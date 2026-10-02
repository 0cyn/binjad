#include "FileChild.hpp"
#include "ToolCall.hpp"
#include "ToolSupport.hpp"

#include "binjad/worker/FileChild.hpp"

#include <debuggerapi.h>
#include <kernelcacheapi.h>
#include <sharedcacheapi.h>

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <limits>
#include <stdexcept>

namespace binjad {
	namespace {
		std::optional<std::string> DescribePluginAddress(BinaryNinja::BinaryView& view, std::uint64_t address)
		{
			if (view.GetTypeName() == "KCView")
			{
				auto controller = KernelCacheAPI::KernelCacheController::GetController(view);
				if (!controller)
					return std::nullopt;
				if (const auto image = controller->GetImageContaining(address))
				{
					if (!controller->IsImageLoaded(*image))
						return "address " + file_process::HexAddress(address) + " is in unloaded KernelCache image '"
							+ image->name + "'; call bn_kernel_cache_image_load for that image, then "
							+ "bn_analysis_update_and_wait";
					return "address " + file_process::HexAddress(address) + " is in loaded KernelCache image '"
						+ image->name + "' but is not an analyzed function start";
				}
				if (view.IsValidOffset(address))
					return "address " + file_process::HexAddress(address)
						+ " is in a loaded KernelCache mapped range but is not an analyzed function start";
				return "address " + file_process::HexAddress(address)
					+ " is not contained in a KernelCache image or loaded mapped range";
			}
			if (view.GetTypeName() == "DSCView")
			{
				auto controller = SharedCacheAPI::SharedCacheController::GetController(view);
				if (!controller)
					return std::nullopt;
				if (const auto image = controller->GetImageContaining(address))
				{
					if (!controller->IsImageLoaded(*image))
						return "address " + file_process::HexAddress(address) + " is in unloaded SharedCache image '"
							+ image->name + "'; call bn_shared_cache_image_load for that image, then "
							+ "bn_analysis_update_and_wait";
					return "address " + file_process::HexAddress(address) + " is in loaded SharedCache image '"
						+ image->name + "' but is not an analyzed function start";
				}
				if (const auto region = controller->GetRegionContaining(address))
				{
					if (!controller->IsRegionLoaded(*region))
						return "address " + file_process::HexAddress(address) + " is in unloaded SharedCache region '"
							+ region->name + "'; call bn_shared_cache_region_load for that region, then "
							+ "bn_analysis_update_and_wait";
					return "address " + file_process::HexAddress(address) + " is in loaded SharedCache region '"
						+ region->name + "' but is not an analyzed function start";
				}
				if (view.IsValidOffset(address))
					return "address " + file_process::HexAddress(address)
						+ " is in a loaded SharedCache mapped range but is not an analyzed function start";
				return "address " + file_process::HexAddress(address)
					+ " is not contained in a SharedCache image, region, or loaded mapped range";
			}
			return std::nullopt;
		}

		std::string MergeLoadOptions(std::string_view base, std::string_view overrides, bool reuseDatabase)
		{
			rapidjson::Document document;
			const auto input = base.empty() ? std::string_view("{}") : base;
			try
			{
				document.Parse(input.data(), input.size());
			}
			catch (const ParseException&)
			{
				throw std::invalid_argument("file load options must be a JSON object");
			}
			if (document.HasParseError() || !document.IsObject())
				throw std::invalid_argument("file load options must be a JSON object");
			rapidjson::Document overrideDocument;
			const auto overrideInput = overrides.empty() ? std::string_view("{}") : overrides;
			try
			{
				overrideDocument.Parse(overrideInput.data(), overrideInput.size());
			}
			catch (const ParseException&)
			{
				throw std::invalid_argument("BinaryView load options must be a JSON object");
			}
			if (overrideDocument.HasParseError() || !overrideDocument.IsObject())
				throw std::invalid_argument("BinaryView load options must be a JSON object");
			for (const auto& member : overrideDocument.GetObject())
			{
				rapidjson::Value name(member.name, document.GetAllocator()),
					value(member.value, document.GetAllocator());
				const auto existing = document.FindMember(name);
				if (existing == document.MemberEnd())
					document.AddMember(std::move(name), std::move(value), document.GetAllocator());
				else
					existing->value = std::move(value);
			}
			if (reuseDatabase)
			{
				constexpr auto key = "analysis.database.suppressReanalysis";
				const auto existing = document.FindMember(key);
				if (existing == document.MemberEnd())
					document.AddMember(rapidjson::StringRef(key), true, document.GetAllocator());
				else if (!existing->value.IsBool())
					throw std::invalid_argument("analysis.database.suppressReanalysis must be a boolean");
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			document.Accept(writer);
			return {buffer.GetString(), buffer.GetSize()};
		}
	}  // namespace

	FileChild::FileChild(std::unique_ptr<ipc::ByteChannel> channel) : channel_(std::move(channel)), runtime_(true) {}
	FileChild::~FileChild()
	{
		try
		{
			Close(true);
		}
		catch (...)
		{}
	}

	int FileChild::Run()
	{
		try
		{
			bool running = true;
			while (running)
			{
				const auto envelope = ipc::ReceiveEnvelope(*channel_);
				if (!envelope.has_command() || envelope.request_id() == 0)
				{
					SendFailure(envelope.request_id(), "expected a command with a nonzero request ID");
					continue;
				}
				Dispatch(envelope, running);
			}
			return EXIT_SUCCESS;
		}
		catch (const std::exception& exception)
		{
			try
			{
				SendEvent(0, ipc::ANALYSIS_STATE_FAILED, exception.what());
			}
			catch (...)
			{}
			return EXIT_FAILURE;
		}
	}

	void FileChild::AddCandidate(const std::string& name, BinaryNinja::Ref<BinaryNinja::BinaryViewType> type)
	{
		if (name.empty() || candidates_.contains(name))
			return;
		std::string schema;
		if (type)
			if (const auto settings = type->GetLoadSettingsForData(data_))
			{
				settings->SetResourceId(name);
				schema = settings->SerializeSchema();
			}
		candidateOrder_.push_back(name);
		candidates_.emplace(name, FileChildCandidate {std::move(type), false, std::move(schema)});
	}

	bool FileChild::HasMappedLoadOptions() const
	{
		rapidjson::Document options;
		options.Parse(loadOptions_.data(), loadOptions_.size());
		if (options.HasParseError() || !options.IsObject())
			return false;
		for (const auto& member : options.GetObject())
		{
			const std::string_view name(member.name.GetString(), member.name.GetStringLength());
			if (name == "loader.platform" || name == "loader.architecture" || name == "loader.imageBase"
				|| name == "loader.entryPoint" || name == "loader.entryPointOffset" || name == "loader.segments"
				|| name == "loader.sections")
				return true;
		}
		return false;
	}

	void FileChild::EnumerateCandidates()
	{
		for (const auto& name : file_->GetExistingViews())
			AddCandidate(name, BinaryNinja::BinaryViewType::GetByName(name));
		AddCandidate(data_->GetTypeName(), BinaryNinja::BinaryViewType::GetByName(data_->GetTypeName()));
		for (const auto& type : BinaryNinja::BinaryViewType::GetViewTypesForData(data_))
			if (type && !type->IsDeprecated())
				AddCandidate(type->GetName(), type);
		if (data_->GetTypeName() == "Raw")
			AddCandidate("Mapped", BinaryNinja::BinaryViewType::GetByName("Mapped"));
		if (candidateOrder_.empty())
			throw std::runtime_error("Binary Ninja found no BinaryView candidates");
		auto recommended = std::find_if(candidateOrder_.begin(), candidateOrder_.end(), [&](const auto& name) {
			return name != "Raw" && name != "Mapped" && candidates_.at(name).type;
		});
		if (databaseBacked_)
		{
			const auto existing = candidates_.find(data_->GetTypeName());
			if (existing != candidates_.end())
				recommended = std::find(candidateOrder_.begin(), candidateOrder_.end(), data_->GetTypeName());
		}
		else if (HasMappedLoadOptions() && candidates_.contains("Mapped"))
			recommended = std::find(candidateOrder_.begin(), candidateOrder_.end(), "Mapped");
		if (recommended == candidateOrder_.end())
			recommended = candidateOrder_.begin();
		candidates_.at(*recommended).recommended = true;
	}

	ipc::Reply FileChild::OpenFile(const ipc::OpenFile& command)
	{
		if (file_)
			throw std::runtime_error("file child already owns an open item");
		if (command.path().empty())
			throw std::invalid_argument("open path must not be empty");
		loadOptions_ = MergeLoadOptions(command.options_json(), {}, false);
		try
		{
			openedPath_ = command.path();
			databaseBacked_ = BNIsDatabase(command.path().c_str());
			reuseDatabase_ = command.reuse_database() && databaseBacked_;
			if (reuseDatabase_)
			{
				if (!BinaryNinja::Settings::Instance()->Contains("analysis.database.suppressReanalysis"))
					throw std::runtime_error("Binary Ninja does not expose BNDB reanalysis suppression");
				loadOptions_ = MergeLoadOptions(loadOptions_, {}, true);
			}
			if (databaseBacked_)
			{
				data_ = BinaryNinja::Load(command.path(), false, loadOptions_);
				if (data_)
					file_ = data_->GetFile();
			}
			else
			{
				BinaryNinja::TransformSession transforms(command.path(), TransformSessionModeFull, loadOptions_);
				if (transforms.Process() && transforms.HasAnyStages() && transforms.HasSinglePath())
				{
					data_ = transforms.GetCurrentView();
					if (data_)
						file_ = data_->GetFile();
				}
				if (!data_)
				{
					file_ = new BinaryNinja::FileMetadata(command.path());
					data_ = BinaryNinja::BinaryData::CreateFromFilename(file_, command.path());
				}
			}
			if (!data_)
				throw std::runtime_error("Binary Ninja could not open the file metadata");
			snapshotApplied_ = !databaseBacked_ || file_->IsSnapshotDataAppliedWithoutError();
			EnumerateCandidates();
		}
		catch (...)
		{
			if (file_)
				file_->Close();
			candidates_.clear();
			candidateOrder_.clear();
			data_ = nullptr;
			file_ = nullptr;
			databaseBacked_ = snapshotApplied_ = reuseDatabase_ = false;
			loadOptions_.clear();
			openedPath_.clear();
			throw;
		}
		ipc::Reply reply;
		reply.set_success(true);
		auto* opened = reply.mutable_file_opened();
		opened->set_database_backed(databaseBacked_);
		opened->set_snapshot_applied(snapshotApplied_);
		for (const auto& name : candidateOrder_)
		{
			auto* candidate = opened->add_candidates();
			candidate->set_view_type(name);
			candidate->set_recommended(candidates_.at(name).recommended);
			candidate->set_created(false);
			candidate->set_load_settings_schema_json(candidates_.at(name).loadSettingsSchemaJson);
		}
		return reply;
	}

	std::string FileChild::ApplyLoadSettings(
		const FileChildCandidate& candidate, const std::string& options, const std::string& explicitOptions)
	{
		if (!candidate.type)
			return {};
		const auto settings = candidate.type->GetLoadSettingsForData(data_);
		if (!settings)
		{
			if (explicitOptions != "{}")
				throw std::invalid_argument(
					"BinaryView type does not accept load options; select Mapped for raw firmware and inspect "
					"bn_binary_view_load_settings");
			return {};
		}
		settings->SetResourceId(candidate.type->GetName());
		rapidjson::Document requested;
		requested.Parse(explicitOptions.data(), explicitOptions.size());
		if (requested.HasParseError() || !requested.IsObject())
			throw std::invalid_argument("BinaryView load options must be a JSON object");
		for (const auto& member : requested.GetObject())
		{
			const std::string name(member.name.GetString(), member.name.GetStringLength());
			if (!settings->Contains(name) && name != "loader.architecture" && name != "loader.entryPoint")
				throw std::invalid_argument("BinaryView load option '" + name + "' is not supported by "
					+ candidate.type->GetName() + "; call bn_binary_view_load_settings for the authoritative schema");
		}
		if (!settings->DeserializeSettings(options, data_, SettingsResourceScope))
			throw std::invalid_argument("Binary Ninja rejected the BinaryView load options");
		data_->SetLoadSettings(candidate.type->GetName(), settings);
		return settings->SerializeSettings(data_, SettingsResourceScope);
	}

	ipc::Reply FileChild::OpenBinaryView(const ipc::OpenBinaryView& command)
	{
		if (!file_ || !data_)
			throw std::runtime_error("no open item exists");
		if (command.view_type().empty())
			throw std::invalid_argument("BinaryView type must not be empty");
		const auto candidate = candidates_.find(command.view_type());
		if (candidate == candidates_.end())
			throw std::runtime_error("BinaryView candidate not found");
		std::shared_ptr<FileChildViewState> state;
		{
			std::lock_guard lock(viewMutex_);
			const auto existing = views_.find(command.view_type());
			if (existing != views_.end())
				state = existing->second;
		}
		if (!state)
		{
			const auto options = MergeLoadOptions(loadOptions_, command.options_json(), reuseDatabase_);
			const auto effective = ApplyLoadSettings(candidate->second, options, command.options_json());
			BinaryNinja::Ref<BinaryNinja::BinaryView> view;
			if (command.view_type() == data_->GetTypeName())
				view = data_;
			else if (databaseBacked_)
				view = file_->GetViewOfType(command.view_type());
			if (!view && candidate->second.type)
			{
				view = candidate->second.type->Create(data_);
				if (view && !view->Init())
					view = nullptr;
			}
			if (!view)
				throw std::runtime_error("Binary Ninja could not materialize the BinaryView");
			state = std::make_shared<FileChildViewState>();
			state->view = view;
			state->effectiveLoadSettingsJson = effective;
			std::lock_guard lock(viewMutex_);
			views_.emplace(command.view_type(), state);
		}
		else if (command.options_json() != "{}")
			throw std::invalid_argument(
				"BinaryView is already materialized; load options cannot be changed. Close the open item, reopen it, "
				"and configure the candidate before materialization");
		ipc::Reply reply;
		reply.set_success(true);
		auto* opened = reply.mutable_binary_view_opened();
		opened->set_view_type(command.view_type());
		if (const auto architecture = state->view->GetDefaultArchitecture())
			opened->set_architecture(architecture->GetName());
		if (const auto platform = state->view->GetDefaultPlatform())
			opened->set_platform(platform->GetName());
		opened->set_effective_load_settings_json(state->effectiveLoadSettingsJson);
		opened->set_start(state->view->GetStart());
		opened->set_end(state->view->GetEnd());
		opened->set_entry_point(state->view->GetEntryPoint());
		opened->set_database_backed(file_->IsBackedByDatabase(command.view_type()));
		opened->set_snapshot_applied(!databaseBacked_ || file_->IsSnapshotDataAppliedWithoutError());
		return reply;
	}

	std::shared_ptr<FileChildViewState> FileChild::View(const std::string& viewType) const
	{
		std::lock_guard lock(viewMutex_);
		const auto view = views_.find(viewType);
		if (view == views_.end())
			throw std::runtime_error("BinaryView is not materialized; call bn_binary_view_open first");
		return view->second;
	}

	BinaryNinja::Ref<BinaryNinja::Function> ResolveFunction(
		const FileChildToolCallContext& context, const rapidjson::Value& arguments)
	{
		const auto& state = context.view;
		if (!arguments.IsObject() || !arguments.HasMember("function") || !arguments["function"].IsString())
			throw std::invalid_argument("function selector must be a string");
		std::uint64_t address = 0;
		std::string error;
		const auto& selector = arguments["function"];
		if (!BinaryNinja::BinaryView::ParseExpression(
				state->view, std::string(selector.GetString(), selector.GetStringLength()), address, 0, error))
			throw std::invalid_argument(error.empty() ? "invalid function selector" : error);
		auto functions = state->view->GetAnalysisFunctionsForAddress(address);
		const bool atAddress = !functions.empty();
		std::optional<std::string> requestedArchitecture;
		if (const auto arch = arguments.FindMember("arch"); arch != arguments.MemberEnd())
		{
			requestedArchitecture.emplace(arch->value.GetString(), arch->value.GetStringLength());
			std::erase_if(functions, [&](const auto& function) {
				const auto architecture = function->GetArchitecture();
				return !architecture || architecture->GetName() != *requestedArchitecture;
			});
		}
		if (functions.empty())
		{
			if (atAddress && requestedArchitecture)
				throw std::invalid_argument("function exists at " + file_process::HexAddress(address)
					+ " but not for requested architecture '" + *requestedArchitecture + "'");
			const auto symbols = state->view->GetSymbols(address, 1);
			if (std::any_of(symbols.begin(), symbols.end(), [&](const auto& symbol) {
					return symbol->GetAddress() == address && symbol->GetType() == FunctionSymbol;
				}))
				throw std::invalid_argument("function not found at " + file_process::HexAddress(address) + "; a FunctionSymbol exists, but symbols do not create functions; call bn_function_create for this BinaryView and address");
			if (const auto description = DescribePluginAddress(*state->view, address))
				throw std::invalid_argument("function not found: " + *description);
			throw std::invalid_argument("function not found at " + file_process::HexAddress(address));
		}
		if (functions.size() != 1)
			throw std::invalid_argument("function selector is ambiguous; specify arch");
		return functions.front();
	}

	BinaryNinja::Ref<BinaryNinja::Type> ParseRequestedType(
		const FileChildToolCallContext& context, const rapidjson::Value& arguments)
	{
		const auto& state = context.view;
		const bool hasDefinition = arguments.HasMember("definition"), hasSource = arguments.HasMember("source");
		if (hasDefinition == hasSource)
			throw std::invalid_argument("exactly one of definition or source is required");
		std::string errors;
		if (hasDefinition)
		{
			const auto& value = arguments["definition"];
			if (!value.IsString() || value.GetStringLength() == 0)
				throw std::invalid_argument("definition must be a non-empty string");
			BinaryNinja::QualifiedNameAndType parsed;
			if (!state->view->ParseTypeString(std::string(value.GetString(), value.GetStringLength()), parsed, errors)
				|| !parsed.type)
				throw std::invalid_argument(errors.empty() ? "invalid type definition" : errors);
			return parsed.type;
		}
		const auto& source = arguments["source"];
		if (!source.IsString() || source.GetStringLength() == 0)
			throw std::invalid_argument("source must be a non-empty string");
		std::vector<std::string> options, includeDirs;
		auto readStrings = [&](const char* name, auto& output) {
			if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
			{
				if (!value->value.IsArray())
					throw std::invalid_argument(std::string(name) + " must be an array of strings");
				for (const auto& item : value->value.GetArray())
				{
					if (!item.IsString())
						throw std::invalid_argument(std::string(name) + " must be an array of strings");
					output.emplace_back(item.GetString(), item.GetStringLength());
				}
			}
		};
		readStrings("options", options);
		readStrings("includeDirs", includeDirs);
		bool importDependencies = true;
		if (const auto value = arguments.FindMember("importDependencies"); value != arguments.MemberEnd())
		{
			if (!value->value.IsBool())
				throw std::invalid_argument("importDependencies must be a boolean");
			importDependencies = value->value.GetBool();
		}
		BinaryNinja::TypeParserResult parsed;
		if (!state->view->ParseTypesFromSource(std::string(source.GetString(), source.GetStringLength()), options,
				includeDirs, parsed, errors, {}, importDependencies))
			throw std::invalid_argument(errors.empty() ? "invalid type source" : errors);
		std::vector<BinaryNinja::ParsedType> candidates;
		candidates.insert(candidates.end(), parsed.types.begin(), parsed.types.end());
		candidates.insert(candidates.end(), parsed.variables.begin(), parsed.variables.end());
		candidates.insert(candidates.end(), parsed.functions.begin(), parsed.functions.end());
		if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
		{
			const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
			std::erase_if(candidates, [&](const auto& candidate) { return candidate.name.GetString() != wanted; });
		}
		if (candidates.empty())
			throw std::invalid_argument("parsed type not found");
		if (candidates.size() != 1)
			throw std::invalid_argument("type source is ambiguous; specify type");
		return candidates.front().type;
	}

	void FileChild::StartAnalysis(const std::string& viewType, std::uint64_t origin)
	{
		const auto state = View(viewType);
		BinaryNinja::Ref<BinaryNinja::BinaryView> view;
		{
			std::lock_guard lock(viewMutex_);
			if (!activeAnalysisView_.empty())
				throw std::runtime_error("analysis is already active for this open item");
			state->analysisActive = true;
			state->abortRequested = false;
			activeAnalysisView_ = viewType;
			view = state->view;
		}
		if (view->AnalysisIsAborted())
		{
			BinaryNinja::WorkflowMachine machine(view);
			if (!machine.Enable())
			{
				std::lock_guard lock(viewMutex_);
				state->analysisActive = false;
				activeAnalysisView_.clear();
				throw std::runtime_error("failed to re-enable the Binary Ninja workflow");
			}
		}
		try
		{
			auto completion = view->AddAnalysisCompletionEvent([this, state, viewType, origin] {
				ipc::AnalysisState result;
				{
					std::lock_guard lock(viewMutex_);
					result = state->abortRequested ? ipc::ANALYSIS_STATE_ABORTED : ipc::ANALYSIS_STATE_COMPLETE;
					state->analysisActive = false;
					if (activeAnalysisView_ == viewType)
						activeAnalysisView_.clear();
				}
				try
				{
					SendEvent(origin, result, {});
				}
				catch (...)
				{}
			});
			if (!completion)
				throw std::runtime_error("failed to register analysis completion event");
			{
				std::lock_guard lock(viewMutex_);
				state->completionEvents.push_back(completion);
			}
			view->UpdateAnalysis();
		}
		catch (...)
		{
			std::lock_guard lock(viewMutex_);
			state->analysisActive = false;
			if (activeAnalysisView_ == viewType)
				activeAnalysisView_.clear();
			throw;
		}
	}

	ipc::Reply FileChild::AnalysisStatus(const std::string& viewType) const
	{
		if (viewType.empty())
			throw std::invalid_argument("BinaryView type must not be empty");
		ipc::Reply reply;
		reply.set_success(true);
		auto* status = reply.mutable_analysis_status();
		status->set_worker_count(BinaryNinja::GetWorkerThreadCount());
		std::shared_ptr<FileChildViewState> state;
		{
			std::lock_guard lock(viewMutex_);
			const auto existing = views_.find(viewType);
			if (existing != views_.end())
				state = existing->second;
		}
		status->set_has_view(static_cast<bool>(state));
		if (!state)
		{
			status->set_state(ipc::ANALYSIS_STATE_IDLE);
			return reply;
		}
		const auto progress = state->view->GetAnalysisProgress();
		status->set_completed(progress.count);
		status->set_total(progress.total);
		bool active;
		{
			std::lock_guard lock(viewMutex_);
			active = state->analysisActive;
		}
		status->set_state(active ?
				ipc::ANALYSIS_STATE_RUNNING :
				state->view->AnalysisIsAborted() ?
				ipc::ANALYSIS_STATE_ABORTED :
				state->view->HasInitialAnalysis() ?
				ipc::ANALYSIS_STATE_COMPLETE :
				ipc::ANALYSIS_STATE_IDLE);
		status->set_modified(file_->IsModified());
		status->set_analysis_changed(file_->IsAnalysisChanged());
		return reply;
	}

	ipc::Reply FileChild::SaveBinaryView(const ipc::SaveBinaryView& command)
	{
		if (activeUndoId_)
			throw std::runtime_error(
				"cannot save while an explicit transaction is active; commit or roll it back first");
		std::shared_ptr<FileChildViewState> state;
		{
			std::lock_guard lock(viewMutex_);
			const auto existing = views_.find(command.view_type());
			if (existing == views_.end())
				throw std::runtime_error("BinaryView is not materialized; call bn_binary_view_open first");
			state = existing->second;
			if (state->analysisActive)
				throw std::runtime_error("cannot save while analysis is active");
		}
		const bool temporaryCopy = command.temporary_copy(), createdDatabase = !databaseBacked_ || temporaryCopy;
		const auto progress = [this](std::size_t completed, std::size_t total) {
			SendProgress(currentRequest_, "save", completed, total);
			return true;
		};
		auto savedPath = openedPath_;
		bool saved;
		if (createdDatabase)
		{
			if (command.destination().empty())
				throw std::invalid_argument("new database save requires a destination");
			savedPath = command.destination();
			saved = state->view->CreateDatabase(savedPath.string(), progress);
		}
		else
		{
			auto snapshotView = file_->GetViewOfType("Raw");
			if (!snapshotView)
				snapshotView = state->view;
			saved = (!file_->IsModified() && !file_->IsAnalysisChanged()) || snapshotView->SaveAutoSnapshot(progress);
		}
		if (!saved)
			throw std::runtime_error("Binary Ninja could not save the analysis database");
		if (createdDatabase && !temporaryCopy)
		{
			openedPath_ = savedPath;
			databaseBacked_ = snapshotApplied_ = true;
		}
		ipc::Reply reply;
		reply.set_success(true);
		auto* result = reply.mutable_binary_view_saved();
		result->set_path(savedPath.string());
		result->set_created_database(createdDatabase);
		return reply;
	}

	void FileChild::Abort(const std::string& viewType)
	{
		const auto state = View(viewType);
		{
			std::lock_guard lock(viewMutex_);
			if (!state->analysisActive || activeAnalysisView_ != viewType)
				throw std::runtime_error("no analysis is active for this BinaryView");
			state->abortRequested = true;
		}
		state->view->AbortAnalysis();
	}

	void FileChild::Close(bool discard)
	{
		if (!file_)
			return;
		if (activeUndoId_)
		{
			if (!discard)
				throw std::runtime_error("file has an active transaction; explicit discard is required");
			file_->RevertUndoActions(*activeUndoId_);
			activeUndoId_.reset();
			activeUndoView_.clear();
		}
		if (!discard && (file_->IsModified() || file_->IsAnalysisChanged()))
			throw std::runtime_error("file has uncommitted state; explicit discard is required");
		diffTools_.Close();
		struct ClosingView
		{
			std::shared_ptr<FileChildViewState> state;
			bool active;
		};
		std::vector<ClosingView> states;
		{
			std::lock_guard lock(viewMutex_);
			for (const auto& [name, state] : views_)
			{
				state->abortRequested = state->analysisActive;
				states.push_back({state, state->analysisActive});
				state->analysisActive = false;
			}
			activeAnalysisView_.clear();
		}
		for (const auto& closing : states)
		{
			if (closing.active)
				closing.state->view->AbortAnalysis();
			for (const auto& event : closing.state->completionEvents)
				if (event)
					event->Cancel();
			if (BinaryNinjaDebuggerAPI::DebuggerController::ControllerExists(closing.state->view))
			{
				auto controller = BinaryNinjaDebuggerAPI::DebuggerController::GetController(closing.state->view);
				if (controller->IsConnected())
					controller->QuitAndWait(5000);
				controller->Destroy();
			}
		}
		{
			std::lock_guard lock(viewMutex_);
			views_.clear();
		}
		file_->Close();
		candidates_.clear();
		candidateOrder_.clear();
		data_ = nullptr;
		file_ = nullptr;
		databaseBacked_ = snapshotApplied_ = reuseDatabase_ = false;
		loadOptions_.clear();
		openedPath_.clear();
	}

	void FileChild::Dispatch(const ipc::Envelope& envelope, bool& running)
	{
		currentRequest_ = envelope.request_id();
		const auto& command = envelope.command();
		try
		{
			ipc::Reply reply;
			std::optional<std::string> analysisView;
			switch (command.action_case())
			{
			case ipc::Command::kOpenFile:
				reply = OpenFile(command.open_file());
				break;
			case ipc::Command::kOpenBinaryView:
				reply = OpenBinaryView(command.open_binary_view());
				if (command.open_binary_view().analyze())
					analysisView = command.open_binary_view().view_type();
				break;
			case ipc::Command::kSaveBinaryView:
				reply = SaveBinaryView(command.save_binary_view());
				break;
			case ipc::Command::kExecuteAnalysisTool:
			{
				const auto& request = command.execute_analysis_tool();
				const auto* tool = FindFileChildToolCall(request.name());
				if (!tool)
					throw std::invalid_argument("analysis tool is not implemented");
				rapidjson::Document arguments;
				arguments.Parse(request.arguments_json().data(), request.arguments_json().size());
				if (arguments.HasParseError() || !arguments.IsObject())
					throw std::invalid_argument("analysis tool arguments must be a JSON object");
				const auto origin = envelope.request_id();
				const FileChildToolCallContext context {
					request,
					arguments,
					View(request.view_type()),
					file_,
					diffTools_,
					activeUndoId_,
					activeUndoView_,
					viewMutex_,
					[this, origin](std::string_view phase, std::size_t completed, std::size_t total) {
						SendProgress(origin, phase, completed, total);
					},
					[this, origin](ipc::AnalysisState state, std::string_view error) {
						SendEvent(origin, state, error);
					},
				};
				reply = tool->Execute(context);
				break;
			}
			case ipc::Command::kCloseFile:
				Close(command.close_file().discard_uncommitted());
				reply.set_success(true);
				break;
			case ipc::Command::kSetWorkerCount:
				if (command.set_worker_count().count() == 0)
					throw std::invalid_argument("worker count must be greater than zero");
				BinaryNinja::SetWorkerThreadCount(command.set_worker_count().count());
				reply.set_success(true);
				break;
			case ipc::Command::kUpdateAnalysis:
				View(command.update_analysis().view_type());
				reply.set_success(true);
				analysisView = command.update_analysis().view_type();
				break;
			case ipc::Command::kGetAnalysisStatus:
				reply = AnalysisStatus(command.get_analysis_status().view_type());
				break;
			case ipc::Command::kAbortAnalysis:
				Abort(command.abort_analysis().view_type());
				reply.set_success(true);
				break;
			case ipc::Command::kShutdown:
				Close(true);
				reply.set_success(true);
				running = false;
				break;
			case ipc::Command::kScanLocalProjects:
			case ipc::Command::kListLocalProjectFiles:
			case ipc::Command::kExportLocalProjectFile:
			case ipc::Command::kCommitLocalProjectFile:
			case ipc::Command::kCreateLocalProject:
			case ipc::Command::kUpdateLocalProject:
			case ipc::Command::kListLocalProjectFolders:
			case ipc::Command::kCreateLocalProjectFolder:
			case ipc::Command::kUpdateLocalProjectFolder:
			case ipc::Command::kDeleteLocalProjectFolder:
			case ipc::Command::kUpdateLocalProjectFile:
			case ipc::Command::kDeleteLocalProjectFile:
			case ipc::Command::kDeleteLocalProject:
			case ipc::Command::kPrepareLocalProjectDownload:
				throw std::invalid_argument("project command is not valid for a file child");
			case ipc::Command::ACTION_NOT_SET:
				throw std::invalid_argument("command has no action");
			}
			SendReply(envelope.request_id(), std::move(reply));
			if (analysisView)
				try
				{
					StartAnalysis(*analysisView, envelope.request_id());
				}
				catch (const std::exception& exception)
				{
					SendEvent(envelope.request_id(), ipc::ANALYSIS_STATE_FAILED, exception.what());
				}
		}
		catch (const std::exception& exception)
		{
			SendFailure(envelope.request_id(), exception.what());
		}
	}

	void FileChild::SendReply(std::uint64_t requestId, ipc::Reply reply)
	{
		ipc::Envelope envelope;
		envelope.set_protocol_version(ipc::kProtocolVersion);
		envelope.set_request_id(requestId);
		*envelope.mutable_reply() = std::move(reply);
		Send(envelope);
	}
	void FileChild::SendFailure(std::uint64_t requestId, std::string_view error)
	{
		ipc::Reply reply;
		reply.set_success(false);
		reply.set_error(error.data(), error.size());
		SendReply(requestId, std::move(reply));
	}
	void FileChild::SendProgress(std::uint64_t origin, std::string_view phase, std::size_t completed, std::size_t total)
	{
		ipc::Envelope envelope;
		envelope.set_protocol_version(ipc::kProtocolVersion);
		envelope.set_request_id(0);
		auto* progress = envelope.mutable_event()->mutable_progress();
		envelope.mutable_event()->set_originating_request_id(origin);
		progress->set_phase(phase.data(), phase.size());
		progress->set_completed(completed);
		progress->set_total(total);
		Send(envelope);
	}
	void FileChild::SendEvent(std::uint64_t origin, ipc::AnalysisState state, std::string_view error)
	{
		ipc::Envelope envelope;
		envelope.set_protocol_version(ipc::kProtocolVersion);
		envelope.set_request_id(0);
		auto* event = envelope.mutable_event();
		event->set_originating_request_id(origin);
		auto* finished = event->mutable_analysis_finished();
		finished->set_state(state);
		if (!error.empty())
			finished->set_error(error.data(), error.size());
		Send(envelope);
	}
	void FileChild::Send(const ipc::Envelope& envelope)
	{
		std::lock_guard lock(sendMutex_);
		ipc::SendEnvelope(*channel_, envelope);
	}

	int RunFileChild(std::unique_ptr<ipc::ByteChannel> channel)
	{
		if (!channel)
			return EXIT_FAILURE;
		try
		{
			FileChild child(std::move(channel));
			return child.Run();
		}
		catch (...)
		{
			return EXIT_FAILURE;
		}
	}
}  // namespace binjad
