#include "../tool_call.hpp"
#include "../tool_schema.hpp"

#include "binjad/overseer/analysis_scheduler.hpp"
#include "binjad/overseer/collaboration_child_manager.hpp"
#include "binjad/overseer/file_child_coordinator.hpp"
#include "binjad/overseer/project_child_coordinator.hpp"
#include "binjad/platform/cpu.hpp"
#include "binjad/platform/paths.hpp"
#include "binjad/session/job_registry.hpp"
#include "binjad/session/open_item_registry.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>

namespace binjad::mcp {
	namespace {
		namespace detail {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			std::string ErrorJson(std::string_view message)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("error");
				writer.String(message.data(), static_cast<rapidjson::SizeType>(message.size()));
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::uint64_t CurrentUnixSeconds()
			{
				return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
					std::chrono::system_clock::now().time_since_epoch())
						.count());
			}

			std::string RequiredString(const rapidjson::Value& arguments, const char* name)
			{
				const auto member = arguments.FindMember(name);
				return {member->value.GetString(), member->value.GetStringLength()};
			}

			std::optional<std::string> OptionalString(const rapidjson::Value& arguments, const char* name)
			{
				const auto member = arguments.FindMember(name);
				if (member == arguments.MemberEnd())
					return std::nullopt;
				return std::string(member->value.GetString(), member->value.GetStringLength());
			}

			bool OptionalBoolean(const rapidjson::Value& arguments, const char* name, bool defaultValue)
			{
				const auto member = arguments.FindMember(name);
				return member == arguments.MemberEnd() ? defaultValue : member->value.GetBool();
			}

			std::string Serialize(const rapidjson::Value& value)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				value.Accept(writer);
				return {buffer.GetString(), buffer.GetSize()};
			}
		}  // namespace detail


#define BINJAD_ANALYSIS_TOOL(Type, Name, Description, Category, DocCategory, Availability, Handler, ...) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, Description, ToolCallCategory::Category, DocCategory, Availability) {} \
		FoundationResult Execute(const ToolCallContext& context) const override { return Handler(context); } \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter& writer) const override \
		{ \
			schema::WriteObject(writer, {__VA_ARGS__}); \
		} \
	}

		namespace session_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			template <typename WriterType>
			void WriteSession(WriterType& writer, const session::AnalysisSessionRecord& record)
			{
				writer.StartObject();
				writer.Key("analysisSession");
				writer.String(record.reference.data(), static_cast<rapidjson::SizeType>(record.reference.size()));
				writer.Key("createdAt");
				writer.Uint64(record.createdAtUnix);
				writer.Key("legacy");
				writer.Bool(record.legacyVersion.has_value());
				writer.Key("transportManaged");
				writer.Bool(record.legacyVersion.has_value());
				writer.Key("retainers");
				writer.Uint64(record.retainers);
				writer.EndObject();
			}

			std::string SessionJson(const session::AnalysisSessionRecord& record)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteSession(writer, record);
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::string SessionsJson(
				const std::vector<session::AnalysisSessionRecord>& sessions, std::size_t offset, std::size_t limit)
			{
				offset = std::min(offset, sessions.size());
				const auto end = offset + std::min(limit, sessions.size() - offset);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("sessions");
				writer.StartArray();
				for (std::size_t index = offset; index < end; ++index)
					WriteSession(writer, sessions[index]);
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(end - offset);
				writer.Key("total");
				writer.Uint64(sessions.size());
				writer.Key("nextOffset");
				writer.Uint64(end);
				writer.Key("truncated");
				writer.Bool(end < sessions.size());
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::string_view FairnessName(FairnessUnit fairness)
			{
				switch (fairness)
				{
				case FairnessUnit::AnalysisSession:
					return "analysis_session";
				case FairnessUnit::BearerToken:
					return "bearer_token";
				case FairnessUnit::File:
					return "file";
				case FairnessUnit::AnalysisJob:
					return "job";
				}
				return {};
			}

			FoundationResult ComputeStatus(const ToolCallContext& context)
			{
				std::size_t logicalCpuCount = 0;
				std::size_t workerBudget = 0;
				std::size_t allocatedWorkers = 0;
				std::size_t activeAnalyses = 0;
				std::size_t queuedAnalyses = 0;
				if (context.scheduler)
				{
					const auto status = context.scheduler->Status();
					logicalCpuCount = status.logicalCpuCount;
					workerBudget = status.workerBudget;
					allocatedWorkers = status.allocatedWorkers;
					activeAnalyses = status.activeAnalyses;
					queuedAnalyses = status.queuedAnalyses;
				}
				else
				{
					const auto capacity = platform::ActiveLogicalCpuCount();
					if (!capacity.logicalCpuCount)
						return ToolCallSuccess(context, detail::ErrorJson(capacity.error), true);
					logicalCpuCount = *capacity.logicalCpuCount;
					workerBudget = std::max<std::size_t>(1, logicalCpuCount * context.config.cpu.percentage / 100);
				}
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("logicalCpuCount");
				writer.Uint64(logicalCpuCount);
				writer.Key("configuredPercentage");
				writer.Uint(context.config.cpu.percentage);
				writer.Key("workerBudget");
				writer.Uint64(workerBudget);
				writer.Key("allocatedWorkers");
				writer.Uint64(allocatedWorkers);
				writer.Key("activeAnalyses");
				writer.Uint64(activeAnalyses);
				writer.Key("queuedAnalyses");
				writer.Uint64(queuedAnalyses);
				writer.Key("fairness");
				const auto fairness = FairnessName(context.config.cpu.fairness);
				writer.String(fairness.data(), static_cast<rapidjson::SizeType>(fairness.size()));
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult CreateSession(const ToolCallContext& context)
			{
				const auto created = context.sessions.Create(context.principal.id, context.unixNow, context.now);
				if (!created.session)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				return ToolCallSuccess(context, SessionJson(*created.session));
			}

			FoundationResult ListSessions(const ToolCallContext& context)
			{
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = context.arguments.FindMember("offset"); member != context.arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = context.arguments.FindMember("limit"); member != context.arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
				return ToolCallSuccess(
					context, SessionsJson(context.sessions.List(context.principal.id, context.now), offset, limit));
			}

			FoundationResult FindSession(const ToolCallContext& context, bool close)
			{
				std::optional<std::string> reference;
				if (const auto member = context.arguments.FindMember("analysisSession");
					member != context.arguments.MemberEnd())
					reference.emplace(member->value.GetString(), member->value.GetStringLength());
				if (!close && (!reference || *reference == "current") && context.currentSession)
					reference = context.currentSession->reference;
				if (!reference)
					return ToolCallInvalidArguments(
						context, "analysisSession is required when no current session exists");
				const auto found = context.sessions.Find(*reference, context.principal.id, context.now, !close);
				if (!found)
					return ToolCallSuccess(context, detail::ErrorJson("session not found"), true);
				if (close)
					context.sessions.Close(*reference, context.principal.id);
				return ToolCallSuccess(context, SessionJson(*found));
			}

			FoundationResult SessionInfo(const ToolCallContext& context)
			{
				return FindSession(context, false);
			}

			FoundationResult SessionClose(const ToolCallContext& context)
			{
				return FindSession(context, true);
			}

			BINJAD_ANALYSIS_TOOL(AnalysisSessionCreateTool, "bn_analysis_session_create", "Create an analysis session.",
				Core, "Sessions and compute", ToolCallAvailability::ModernProtocol, CreateSession);
			BINJAD_ANALYSIS_TOOL(AnalysisSessionCloseTool, "bn_analysis_session_close",
				"Close an owned analysis session.", Core, "Sessions and compute", ToolCallAvailability::ModernProtocol,
				SessionClose, schema::String("analysisSession", true));
			BINJAD_ANALYSIS_TOOL(AnalysisSessionListTool, "bn_analysis_session_list", "List owned analysis sessions.",
				Core, "Sessions and compute", ToolCallAvailability::None, ListSessions,
				schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_ANALYSIS_TOOL(AnalysisSessionInfoTool, "bn_analysis_session_info",
				"Inspect an owned analysis session; omit analysisSession or use current for the request's current "
				"session.",
				Core, "Sessions and compute", ToolCallAvailability::None, SessionInfo,
				schema::String("analysisSession"));
			BINJAD_ANALYSIS_TOOL(ComputeStatusTool, "bn_compute_status",
				"Report daemon analysis capacity and allocation.", Core, "Sessions and compute",
				ToolCallAvailability::None, ComputeStatus);
		}  // namespace session_tools

		namespace job_tools {
			std::string JobJson(const session::JobRecord& job, bool includeResult = false);
		}

		namespace file_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			std::string_view SourceKindName(session::OpenItemSourceKind kind)
			{
				switch (kind)
				{
				case session::OpenItemSourceKind::ArbitraryPath:
					return "path";
				case session::OpenItemSourceKind::LocalProject:
					return "local_project";
				case session::OpenItemSourceKind::CollaborationProject:
					return "collaboration_project";
				}
				return {};
			}

			template <typename WriterType>
			void WriteBinaryView(WriterType& writer, const session::BinaryViewRecord& view)
			{
				writer.StartObject();
				writer.Key("binaryView");
				writer.String(view.reference.data(), static_cast<rapidjson::SizeType>(view.reference.size()));
				writer.Key("openItem");
				writer.String(view.openItem.data(), static_cast<rapidjson::SizeType>(view.openItem.size()));
				writer.Key("analysisSession");
				writer.String(
					view.analysisSession.data(), static_cast<rapidjson::SizeType>(view.analysisSession.size()));
				writer.Key("viewType");
				writer.String(view.viewType.data(), static_cast<rapidjson::SizeType>(view.viewType.size()));
				writer.Key("recommended");
				writer.Bool(view.recommended);
				writer.Key("created");
				writer.Bool(view.created);
				writer.Key("configurable");
				writer.Bool(!view.loadSettingsSchemaJson.empty());
				if (!view.architecture.empty())
				{
					writer.Key("architecture");
					writer.String(view.architecture.data(), static_cast<rapidjson::SizeType>(view.architecture.size()));
				}
				if (!view.platform.empty())
				{
					writer.Key("platform");
					writer.String(view.platform.data(), static_cast<rapidjson::SizeType>(view.platform.size()));
				}
				if (view.created)
				{
					writer.Key("start");
					writer.Uint64(view.start);
					writer.Key("end");
					writer.Uint64(view.end);
					writer.Key("entryPoint");
					writer.Uint64(view.entryPoint);
				}
				writer.EndObject();
			}

			template <typename WriterType>
			void WriteOpenItem(WriterType& writer, const session::OpenItemRecord& item)
			{
				writer.StartObject();
				writer.Key("openItem");
				writer.String(item.reference.data(), static_cast<rapidjson::SizeType>(item.reference.size()));
				writer.Key("analysisSession");
				writer.String(
					item.analysisSession.data(), static_cast<rapidjson::SizeType>(item.analysisSession.size()));
				writer.Key("sourceKind");
				const auto kind = SourceKindName(item.sourceKind);
				writer.String(kind.data(), static_cast<rapidjson::SizeType>(kind.size()));
				writer.Key("source");
				writer.String(item.source.data(), static_cast<rapidjson::SizeType>(item.source.size()));
				if (item.project)
				{
					writer.Key("project");
					writer.String(item.project->data(), static_cast<rapidjson::SizeType>(item.project->size()));
				}
				writer.Key("binaryViews");
				writer.StartArray();
				for (const auto& view : item.binaryViews)
					WriteBinaryView(writer, view);
				writer.EndArray();
				if (std::any_of(item.binaryViews.begin(), item.binaryViews.end(), [](const auto& view) {
						return !view.created;
					}))
				{
					writer.Key("nextAction");
					writer.String(item.source.ends_with(".bndb") ?
							"Call bn_binary_view_open on the recommended:true binaryView with analyze:false to reuse "
							"saved analysis." :
							"Call bn_binary_view_open on the recommended:true binaryView before using BinaryView "
							"tools.");
				}
				writer.EndObject();
			}

			template <typename Record, typename WriteRecord>
			std::string PaginatedJson(std::string_view key, const std::vector<Record>& records, std::size_t offset,
				std::size_t limit, WriteRecord writeRecord)
			{
				offset = std::min(offset, records.size());
				const auto end = offset + std::min(limit, records.size() - offset);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
				writer.StartArray();
				for (std::size_t index = offset; index < end; ++index)
					writeRecord(writer, records[index]);
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(end - offset);
				writer.Key("total");
				writer.Uint64(records.size());
				writer.Key("nextOffset");
				writer.Uint64(end);
				writer.Key("truncated");
				writer.Bool(end < records.size());
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			void Pagination(const rapidjson::Value& arguments, std::size_t& offset, std::size_t& limit)
			{
				if (const auto member = arguments.FindMember("offset"); member != arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = arguments.FindMember("limit"); member != arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
			}

			bool IsSharedCachePrimaryPath(std::string_view path)
			{
				const auto name = std::filesystem::path(path).filename().string();
				return name.starts_with("dyld_shared_cache_") && name.find('.') == std::string::npos;
			}

			bool IsSharedCacheCompanionPath(std::string_view primary, std::string_view candidate)
			{
				const std::filesystem::path primaryPath(primary);
				const std::filesystem::path candidatePath(candidate);
				return candidatePath.parent_path() == primaryPath.parent_path()
					&& candidatePath.filename().string().starts_with(primaryPath.filename().string() + ".");
			}

			FoundationResult OpenItemOpen(const ToolCallContext& context)
			{
				if (!context.currentSession)
					return ToolCallSuccess(context, detail::ErrorJson("analysis session is required"), true);
				if (!context.fileCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("file-child service is unavailable"), true);
				const auto path = detail::RequiredString(context.arguments, "path");
				const auto project = detail::OptionalString(context.arguments, "project");
				const auto optionsMember = context.arguments.FindMember("options");
				const auto options =
					optionsMember == context.arguments.MemberEnd() ? "{}" : detail::Serialize(optionsMember->value);
				const bool reuseDatabase = detail::OptionalBoolean(context.arguments, "reuseDatabase", true);
				overseer::CoordinatorResult<session::OpenItemRecord> opened;
				if (project)
				{
					if (context.config.EffectiveMode() == Mode::Local)
					{
						if (!context.projectCoordinator)
							return ToolCallSuccess(
								context, detail::ErrorJson("local project service is unavailable"), true);
						auto exported = context.projectCoordinator->ExportFile(*project, path);
						if (!exported.value)
							return ToolCallSuccess(context, detail::ErrorJson(exported.error), true);
						if (IsSharedCachePrimaryPath(path))
						{
							const auto files = context.projectCoordinator->ListFiles(*project);
							if (!files.value)
							{
								std::error_code ignored;
								std::filesystem::remove_all(exported.value->workingDirectory, ignored);
								return ToolCallSuccess(context, detail::ErrorJson(files.error), true);
							}
							std::string companionError;
							for (const auto& file : *files.value)
							{
								if (!IsSharedCacheCompanionPath(path, file.path))
									continue;
								auto companion = context.projectCoordinator->ExportFile(*project, file.path);
								if (!companion.value)
								{
									companionError = companion.error;
									break;
								}
								const auto copied = platform::CopyRegularFilePrivate(companion.value->path,
									exported.value->workingDirectory / std::filesystem::path(file.path).filename());
								std::error_code ignored;
								std::filesystem::remove_all(companion.value->workingDirectory, ignored);
								if (!copied.bytesCopied || !copied.error.empty())
								{
									companionError = copied.error;
									break;
								}
							}
							if (!companionError.empty())
							{
								std::error_code ignored;
								std::filesystem::remove_all(exported.value->workingDirectory, ignored);
								return ToolCallSuccess(context,
									detail::ErrorJson("cannot stage SharedCache companions: " + companionError), true);
							}
						}
						opened = context.fileCoordinator->OpenManagedPath(context.principal,
							context.currentSession->reference, exported.value->path, options, reuseDatabase,
							session::OpenItemSourceKind::LocalProject, path, *project);
						std::error_code ignored;
						std::filesystem::remove_all(exported.value->workingDirectory, ignored);
					}
					else
					{
						if (!context.collaborationManager)
							return ToolCallSuccess(
								context, detail::ErrorJson("collaboration project service is unavailable"), true);
						auto downloaded = context.collaborationManager->DownloadFile(context.principal, *project, path);
						if (!downloaded.value)
							return ToolCallSuccess(context, detail::ErrorJson(downloaded.error), true);
						if (IsSharedCachePrimaryPath(path))
						{
							const auto files = context.collaborationManager->ListFiles(context.principal, *project);
							if (!files.value)
							{
								std::error_code ignored;
								std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
								return ToolCallSuccess(context, detail::ErrorJson(files.error), true);
							}
							std::string companionError;
							for (const auto& file : *files.value)
							{
								if (!IsSharedCacheCompanionPath(path, file.path))
									continue;
								auto companion =
									context.collaborationManager->DownloadFile(context.principal, *project, file.path);
								if (!companion.value)
								{
									companionError = companion.error;
									break;
								}
								const auto copied = platform::CopyRegularFilePrivate(companion.value->path,
									downloaded.value->workingDirectory / std::filesystem::path(file.path).filename());
								std::error_code ignored;
								std::filesystem::remove_all(companion.value->workingDirectory, ignored);
								if (!copied.bytesCopied || !copied.error.empty())
								{
									companionError = copied.error;
									break;
								}
							}
							if (!companionError.empty())
							{
								std::error_code ignored;
								std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
								return ToolCallSuccess(context,
									detail::ErrorJson("cannot stage SharedCache companions: " + companionError), true);
							}
						}
						opened = context.fileCoordinator->OpenManagedPath(context.principal,
							context.currentSession->reference, downloaded.value->path, options, reuseDatabase,
							session::OpenItemSourceKind::CollaborationProject, path, *project);
						std::error_code ignored;
						std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
					}
				}
				else
				{
					opened = context.fileCoordinator->OpenArbitraryPath(
						context.principal, context.currentSession->reference, path, options, reuseDatabase);
				}
				if (!opened.value)
					return ToolCallSuccess(context, detail::ErrorJson(opened.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteOpenItem(writer, *opened.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult OpenItemList(const ToolCallContext& context)
			{
				if (!context.openItems)
					return ToolCallSuccess(context, detail::ErrorJson("open-item service is unavailable"), true);
				std::size_t offset = 0;
				std::size_t limit = 50;
				Pagination(context.arguments, offset, limit);
				return ToolCallSuccess(context,
					PaginatedJson("openItems", context.openItems->ListForToken(context.principal.id), offset, limit,
						[](auto& writer, const auto& item) { WriteOpenItem(writer, item); }));
			}

			FoundationResult BinaryViewList(const ToolCallContext& context)
			{
				if (!context.openItems || !context.currentSession)
					return ToolCallSuccess(context, detail::ErrorJson("analysis session is required"), true);
				std::size_t offset = 0;
				std::size_t limit = 50;
				Pagination(context.arguments, offset, limit);
				return ToolCallSuccess(context,
					PaginatedJson("binaryViews",
						context.openItems->ListViews(context.principal.id, context.currentSession->reference), offset,
						limit, [](auto& writer, const auto& view) { WriteBinaryView(writer, view); }));
			}

			FoundationResult BinaryViewLoadSettings(const ToolCallContext& context)
			{
				if (!context.openItems || !context.currentSession)
					return ToolCallSuccess(context, detail::ErrorJson("analysis session is required"), true);
				const auto member = context.arguments.FindMember("binaryView");
				const std::string binaryView(member->value.GetString(), member->value.GetStringLength());
				const auto view =
					context.openItems->FindView(context.principal.id, context.currentSession->reference, binaryView);
				if (!view)
					return ToolCallSuccess(context, detail::ErrorJson("BinaryView not found"), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("binaryView");
				writer.String(view->reference.data(), static_cast<rapidjson::SizeType>(view->reference.size()));
				writer.Key("viewType");
				writer.String(view->viewType.data(), static_cast<rapidjson::SizeType>(view->viewType.size()));
				writer.Key("configurable");
				writer.Bool(!view->loadSettingsSchemaJson.empty());
				if (!view->loadSettingsSchemaJson.empty())
				{
					writer.Key("schema");
					writer.RawValue(view->loadSettingsSchemaJson.data(), view->loadSettingsSchemaJson.size(),
						rapidjson::kObjectType);
				}
				if (!view->effectiveLoadSettingsJson.empty())
				{
					writer.Key("effective");
					writer.RawValue(view->effectiveLoadSettingsJson.data(), view->effectiveLoadSettingsJson.size(),
						rapidjson::kObjectType);
				}
				writer.Key("nextAction");
				if (view->viewType == "Raw")
					writer.String(
						"Raw does not accept loader settings. Select the Mapped candidate for raw firmware, inspect "
						"its schema, and pass fully qualified loader.* settings to bn_binary_view_open.");
				else if (!view->created)
					writer.String(
						"Pass only keys from schema.settings to bn_binary_view_open options. loader.segments and "
						"loader.sections are serialized JSON strings.");
				else
					writer.String(
						"The effective settings and materialized BinaryView metadata reflect the current view.");
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult OpenItemClose(const ToolCallContext& context)
			{
				if (!context.fileCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("file-child service is unavailable"), true);
				const auto openItemMember = context.arguments.FindMember("openItem");
				const std::string openItem(openItemMember->value.GetString(), openItemMember->value.GetStringLength());
				std::string_view save = "prompt";
				if (const auto member = context.arguments.FindMember("save"); member != context.arguments.MemberEnd())
					save = {member->value.GetString(), member->value.GetStringLength()};
				if (save == "save")
					return ToolCallSuccess(context,
						detail::ErrorJson("save an explicit BinaryView with bn_binary_view_save before closing"), true);
				const auto error = context.fileCoordinator->Close(context.principal.id, openItem, save == "discard");
				if (!error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("openItem");
				writer.String(openItem.data(), static_cast<rapidjson::SizeType>(openItem.size()));
				writer.Key("closed");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult BinaryViewOpen(const ToolCallContext& context)
			{
				if (!context.currentSession || !context.fileCoordinator)
					return ToolCallSuccess(
						context, detail::ErrorJson("analysis session and file-child service are required"), true);
				const auto binaryView = detail::RequiredString(context.arguments, "binaryView");
				const auto optionsMember = context.arguments.FindMember("options");
				const auto options =
					optionsMember == context.arguments.MemberEnd() ? "{}" : detail::Serialize(optionsMember->value);
				const bool analyze = detail::OptionalBoolean(context.arguments, "analyze", true);
				const auto scheduledView = context.openItems ?
					context.openItems->FindView(context.principal.id, context.currentSession->reference, binaryView) :
					std::nullopt;
				if (context.scheduler && !scheduledView)
					return ToolCallSuccess(context, detail::ErrorJson("BinaryView not found"), true);
				const auto opened = context.fileCoordinator->OpenBinaryView(context.principal.id,
					context.currentSession->reference, binaryView, options, analyze && !context.scheduler);
				if (!opened.value)
					return ToolCallSuccess(context, detail::ErrorJson(opened.error), true);
				if (analyze && context.scheduler)
				{
					if (!context.jobs
						|| !context.sessions.Retain(
							context.currentSession->reference, context.principal.id, context.now))
						return ToolCallSuccess(
							context, detail::ErrorJson("cannot retain analysis session for scheduled analysis"), true);
					const auto owner = context.principal.id;
					const auto analysisSession = context.currentSession->reference;
					const auto openItem = opened.value->openItem;
					const auto workerError = context.jobs->StartWorker(
						[scheduler = context.scheduler, coordinator = context.fileCoordinator,
							sessions = &context.sessions, owner, analysisSession, binaryView, openItem] {
							std::string scheduleError;
							auto lease = scheduler->Acquire(
								{owner, analysisSession, openItem, {}},
								[coordinator, owner, analysisSession, binaryView](std::size_t workers) {
									(void)coordinator->SetWorkerCount(owner, analysisSession, binaryView, workers);
								},
								scheduleError);
							if (lease)
								(void)coordinator->UpdateAnalysisAndWait(owner, analysisSession, binaryView);
							sessions->Release(analysisSession, owner);
						});
					if (!workerError.empty())
					{
						context.sessions.Release(analysisSession, owner);
						return ToolCallSuccess(context, detail::ErrorJson(workerError), true);
					}
				}
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteBinaryView(writer, *opened.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			std::string SaveResultJson(std::string_view binaryView, std::string_view openItem,
				std::string_view destination, bool createdDatabase, session::OpenItemSourceKind sourceKind)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("binaryView");
				writer.String(binaryView.data(), static_cast<rapidjson::SizeType>(binaryView.size()));
				writer.Key("openItem");
				writer.String(openItem.data(), static_cast<rapidjson::SizeType>(openItem.size()));
				writer.Key("destination");
				writer.String(destination.data(), static_cast<rapidjson::SizeType>(destination.size()));
				writer.Key("createdDatabase");
				writer.Bool(createdDatabase);
				writer.Key("sourceKind");
				const auto kind = SourceKindName(sourceKind);
				writer.String(kind.data(), static_cast<rapidjson::SizeType>(kind.size()));
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::string CollaborationConflictJson(std::string_view conflicts)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("error");
				writer.String("collaboration merge conflicts require resolutions");
				writer.Key("conflicts");
				writer.RawValue(conflicts.data(), conflicts.size(), rapidjson::kObjectType);
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			FoundationResult BinaryViewSave(const ToolCallContext& context)
			{
				if (!context.currentSession || !context.openItems || !context.fileCoordinator || !context.jobs)
					return ToolCallSuccess(context,
						detail::ErrorJson("analysis session, file-child, and job services are required"), true);
				const auto binaryView = detail::RequiredString(context.arguments, "binaryView");
				const auto destination = detail::OptionalString(context.arguments, "destination");
				const auto message = detail::OptionalString(context.arguments, "message");
				const auto resolutionsMember = context.arguments.FindMember("resolutions");
				const auto resolutions = resolutionsMember == context.arguments.MemberEnd() ?
					"{}" :
					detail::Serialize(resolutionsMember->value);
				const auto view =
					context.openItems->FindView(context.principal.id, context.currentSession->reference, binaryView);
				if (!view || !view->created)
					return ToolCallSuccess(
						context, detail::ErrorJson("BinaryView not found or not materialized"), true);
				const auto item = context.openItems->FindOpenItem(context.principal.id, view->openItem);
				if (!item)
					return ToolCallSuccess(context, detail::ErrorJson("open item not found"), true);
				if (item->sourceKind == session::OpenItemSourceKind::CollaborationProject && !message)
					return ToolCallInvalidArguments(context, "message is required for collaboration saves");

				const bool async = context.request.name == "bn_binary_view_save_async";
				const auto owner = context.principal.id;
				const auto analysisSession = context.currentSession->reference;
				const auto created = context.jobs->Create(
					owner, analysisSession, binaryView, "binary_view_save", context.unixNow, context.now);
				if (!created.job)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				const auto job = created.job->reference;
				context.jobs->Start(owner, job, context.unixNow);
				if (!async && context.attached)
					context.attached(job, [jobs = context.jobs, owner, job] { (void)jobs->Cancel(owner, job); });
				context.jobs->ReportProgress(owner, job, "save", 0, 0, "save started", context.unixNow);
				if (!async && context.progress)
				{
					const auto info = context.jobs->Info(owner, job);
					if (info.job)
						context.progress(*info.job);
				}

				const auto workerError = context.jobs->StartWorker(
					[jobs = context.jobs, fileCoordinator = context.fileCoordinator,
						projectCoordinator = context.projectCoordinator, openItems = context.openItems, owner,
						analysisSession, binaryView, item = *item, destination, message, resolutions,
						principal = context.principal, collaborationManager = context.collaborationManager, job,
						progress = async ? Foundation::JobProgressCallback {} : context.progress] {
						const auto cancelled = [&] {
							const auto info = jobs->Info(owner, job);
							return info.job && info.job->cancelRequested;
						};
						if (cancelled())
						{
							jobs->MarkCancelled(
								owner, job, detail::ErrorJson("job cancelled"), detail::CurrentUnixSeconds());
							return;
						}
						const auto saved = fileCoordinator->SaveBinaryView(owner, analysisSession, binaryView, {},
							[jobs, owner, job, progress](const ipc::Progress& update) {
								jobs->ReportProgress(owner, job, update.phase(), update.completed(), update.total(),
									update.message(), detail::CurrentUnixSeconds());
								if (progress)
								{
									const auto info = jobs->Info(owner, job);
									if (info.job)
										progress(*info.job);
								}
							});
						if (!saved.value)
						{
							jobs->Fail(owner, job, detail::ErrorJson(saved.error), detail::CurrentUnixSeconds());
							return;
						}
						const auto discardCreatedDatabase = [&] {
							if (saved.value->created_database())
								fileCoordinator->DiscardUncommittedSavedDatabase(owner, analysisSession, binaryView);
						};
						if (cancelled())
						{
							discardCreatedDatabase();
							jobs->MarkCancelled(owner, job, detail::ErrorJson("job cancelled before commit"),
								detail::CurrentUnixSeconds());
							return;
						}

						std::string committedDestination;
						if (item.sourceKind == session::OpenItemSourceKind::ArbitraryPath)
						{
							const auto target = destination ?
								std::filesystem::absolute(*destination).lexically_normal() :
								saved.value->created_database() ?
								std::filesystem::path(item.source + ".bndb") :
								std::filesystem::path(item.source);
							const auto original = std::filesystem::path(item.source).lexically_normal();
							const auto installed = platform::InstallRegularFileAtomically(
								saved.value->path(), target, !saved.value->created_database() && target == original);
							if (!installed.installed)
							{
								discardCreatedDatabase();
								jobs->Fail(
									owner, job, detail::ErrorJson(installed.error), detail::CurrentUnixSeconds());
								return;
							}
							committedDestination = target.string();
							openItems->UpdateSource(owner, item.reference, session::OpenItemSourceKind::ArbitraryPath,
								committedDestination, {});
						}
						else if (item.sourceKind == session::OpenItemSourceKind::LocalProject)
						{
							if (!item.project || !projectCoordinator)
							{
								discardCreatedDatabase();
								jobs->Fail(owner, job, detail::ErrorJson("local project service is unavailable"),
									detail::CurrentUnixSeconds());
								return;
							}
							const auto target = destination.value_or(
								saved.value->created_database() ? item.source + ".bndb" : item.source);
							const auto committed = projectCoordinator->CommitFile(*item.project, target,
								saved.value->path(), !saved.value->created_database() && target == item.source, false,
								"Saved analysis database");
							if (!committed.value)
							{
								discardCreatedDatabase();
								jobs->Fail(
									owner, job, detail::ErrorJson(committed.error), detail::CurrentUnixSeconds());
								return;
							}
							committedDestination = committed.value->path;
							openItems->UpdateSource(owner, item.reference, session::OpenItemSourceKind::LocalProject,
								committedDestination, item.project);
						}
						else
						{
							if (!item.project || !collaborationManager || !message)
							{
								discardCreatedDatabase();
								jobs->Fail(owner, job,
									detail::ErrorJson("collaboration project service is unavailable"),
									detail::CurrentUnixSeconds());
								return;
							}
							if (destination)
							{
								discardCreatedDatabase();
								jobs->Fail(owner, job, detail::ErrorJson("collaboration Save As is not implemented"),
									detail::CurrentUnixSeconds());
								return;
							}
							const auto synchronized = collaborationManager->SaveDatabase(principal, *item.project,
								item.source, saved.value->path(), saved.value->created_database(), *message,
								resolutions);
							if (!synchronized.value)
							{
								discardCreatedDatabase();
								jobs->Fail(
									owner, job, detail::ErrorJson(synchronized.error), detail::CurrentUnixSeconds());
								return;
							}
							if (!synchronized.value->synchronized)
							{
								jobs->Fail(owner, job, CollaborationConflictJson(synchronized.value->conflictsJson),
									detail::CurrentUnixSeconds());
								return;
							}
							committedDestination = synchronized.value->path;
							openItems->UpdateSource(owner, item.reference,
								session::OpenItemSourceKind::CollaborationProject, committedDestination, item.project);
						}
						if (saved.value->created_database())
						{
							const auto promoted = fileCoordinator->PromoteSavedBinaryView(
								owner, analysisSession, binaryView, saved.value->path());
							if (!promoted.empty())
							{
								jobs->Fail(owner, job, detail::ErrorJson(promoted), detail::CurrentUnixSeconds());
								return;
							}
						}
						jobs->Complete(owner, job,
							SaveResultJson(binaryView, item.reference, committedDestination,
								saved.value->created_database(), item.sourceKind),
							detail::CurrentUnixSeconds());
					});
				if (!workerError.empty())
					context.jobs->Fail(owner, job, detail::ErrorJson(workerError), context.unixNow);
				if (async)
				{
					const auto info = context.jobs->Info(owner, job);
					return info.job ?
						ToolCallSuccess(context, job_tools::JobJson(*info.job)) :
						ToolCallSuccess(context, detail::ErrorJson("job not found"), true);
				}
				const auto waited = context.jobs->WaitForTerminal(owner, job, context.config.jobs.detachAfter);
				if (!waited.job)
					return ToolCallSuccess(context, detail::ErrorJson(waited.error), true);
				if (waited.job->state == session::JobState::Queued || waited.job->state == session::JobState::Running)
					return ToolCallSuccess(context, job_tools::JobJson(*waited.job));
				const auto result = context.jobs->TakeResult(owner, job);
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(
					context, result.job->resultJson, result.job->state != session::JobState::Complete);
			}

			BINJAD_ANALYSIS_TOOL(OpenItemOpenTool, "bn_open_item_open",
				"Discover BinaryView candidates for an authorized path or project file; call bn_binary_view_open "
				"before using a candidate.",
				Core, "Files and views", ToolCallAvailability::None, OpenItemOpen, schema::NonEmptyString("project"),
				schema::String("path", true), schema::Enum("kind", false, {"auto", "file"}),
				schema::Object("options", false,
					"Candidate-specific Binary Ninja load settings. Call bn_binary_view_load_settings first; Raw "
					"accepts "
					"none, while Mapped exposes fully qualified loader.* keys and requires serialized JSON strings for "
					"segments and sections."),
				schema::Boolean("reuseDatabase"));
			BINJAD_ANALYSIS_TOOL(OpenItemListTool, "bn_open_item_list",
				"List open items owned by this bearer token across concurrent analysis sessions; close only items "
				"created by your workflow.",
				Core, "Files and views", ToolCallAvailability::None, OpenItemList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_ANALYSIS_TOOL(OpenItemCloseTool, "bn_open_item_close", "Close an open item.", Core,
				"Files and views", ToolCallAvailability::None, OpenItemClose, schema::String("openItem", true),
				schema::Enum("save", false, {"prompt", "save", "discard"}));
			BINJAD_ANALYSIS_TOOL(BinaryViewListTool, "bn_binary_view_list",
				"List BinaryView candidates in the current analysis session.", Core, "Files and views",
				ToolCallAvailability::None, BinaryViewList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_ANALYSIS_TOOL(BinaryViewLoadSettingsTool, "bn_binary_view_load_settings",
				"Return the authoritative Binary Ninja load-settings schema and effective settings for one BinaryView "
				"candidate.",
				Core, "Files and views", ToolCallAvailability::None, BinaryViewLoadSettings,
				schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(BinaryViewOpenTool, "bn_binary_view_open",
				"Materialize an explicit candidate; inspect load settings first, use Mapped for raw firmware, and use "
				"analyze:false for reused BNDB analysis.",
				Core, "Files and views", ToolCallAvailability::None, BinaryViewOpen, schema::String("binaryView", true),
				schema::Object("options"), schema::Boolean("analyze"));
			BINJAD_ANALYSIS_TOOL(BinaryViewSaveTool, "bn_binary_view_save", "Save and commit an explicit BinaryView.",
				Core, "Files and views", ToolCallAvailability::None, BinaryViewSave, schema::String("binaryView", true),
				schema::NonEmptyString("destination"), schema::NonEmptyString("message"),
				schema::Object("resolutions"));
			BINJAD_ANALYSIS_TOOL(BinaryViewSaveAsyncTool, "bn_binary_view_save_async",
				"Save and commit an explicit BinaryView as an immediately detached job.", Core, "Files and views",
				ToolCallAvailability::None, BinaryViewSave, schema::String("binaryView", true),
				schema::NonEmptyString("destination"), schema::NonEmptyString("message"),
				schema::Object("resolutions"));
		}  // namespace file_tools

		namespace core_analysis_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			std::string AnalysisStatusJson(const ipc::AnalysisStatus& status)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("state");
				switch (status.state())
				{
				case ipc::ANALYSIS_STATE_IDLE:
					writer.String("idle");
					break;
				case ipc::ANALYSIS_STATE_RUNNING:
					writer.String("running");
					break;
				case ipc::ANALYSIS_STATE_COMPLETE:
					writer.String("complete");
					break;
				case ipc::ANALYSIS_STATE_ABORTED:
					writer.String("aborted");
					break;
				case ipc::ANALYSIS_STATE_FAILED:
					writer.String("failed");
					break;
				default:
					writer.String("unspecified");
					break;
				}
				if (status.total() != 0 || status.state() == ipc::ANALYSIS_STATE_RUNNING)
				{
					writer.Key("completed");
					writer.Uint64(status.completed());
					writer.Key("total");
					writer.Uint64(status.total());
				}
				writer.Key("workerCount");
				writer.Uint(status.worker_count());
				writer.Key("hasView");
				writer.Bool(status.has_view());
				writer.Key("modified");
				writer.Bool(status.modified());
				writer.Key("analysisChanged");
				writer.Bool(status.analysis_changed());
				if (status.state() == ipc::ANALYSIS_STATE_RUNNING)
				{
					writer.Key("pollAfterMilliseconds");
					writer.Uint(10000);
					writer.Key("nextAction");
					writer.String(
						"Wait at least 10 seconds before checking again. If analysis_update_and_wait returned a job, "
						"use "
						"bn_job_info and bn_job_result instead of polling analysis status.");
				}
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::string AnalysisFinishedJson(const ipc::AnalysisFinished& finished)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("state");
				switch (finished.state())
				{
				case ipc::ANALYSIS_STATE_COMPLETE:
					writer.String("complete");
					break;
				case ipc::ANALYSIS_STATE_ABORTED:
					writer.String("aborted");
					break;
				case ipc::ANALYSIS_STATE_FAILED:
					writer.String("failed");
					break;
				default:
					writer.String("unspecified");
					break;
				}
				if (!finished.error().empty())
				{
					writer.Key("error");
					writer.String(finished.error().data(), static_cast<rapidjson::SizeType>(finished.error().size()));
				}
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			struct AnalysisTarget
			{
				std::string view;
				std::string openItem;
			};

			std::optional<AnalysisTarget> Target(const ToolCallContext& context, FoundationResult& error)
			{
				if (!context.currentSession || !context.fileCoordinator)
				{
					error = ToolCallSuccess(
						context, detail::ErrorJson("analysis session and file-child service are required"), true);
					return std::nullopt;
				}
				AnalysisTarget target {detail::RequiredString(context.arguments, "binaryView"), {}};
				const auto scheduledView = context.openItems ?
					context.openItems->FindView(context.principal.id, context.currentSession->reference, target.view) :
					std::nullopt;
				if (context.scheduler && !scheduledView)
				{
					error = ToolCallSuccess(context, detail::ErrorJson("BinaryView not found"), true);
					return std::nullopt;
				}
				if (scheduledView)
					target.openItem = scheduledView->openItem;
				return target;
			}

			FoundationResult AnalysisStatus(const ToolCallContext& context)
			{
				FoundationResult error;
				const auto target = Target(context, error);
				if (!target)
					return error;
				const auto status = context.fileCoordinator->AnalysisStatus(
					context.principal.id, context.currentSession->reference, target->view);
				return status.value ?
					ToolCallSuccess(context, AnalysisStatusJson(*status.value)) :
					ToolCallSuccess(context, detail::ErrorJson(status.error), true);
			}

			void RunAnalysisJob(session::JobRegistry* jobs, overseer::FileChildCoordinator* coordinator,
				overseer::AnalysisScheduler* scheduler, std::string owner, std::string analysisSession,
				std::string view, std::string openItem, std::string job, Foundation::JobProgressCallback progress)
			{
				const auto beforeStart = jobs->Info(owner, job);
				if (beforeStart.job && beforeStart.job->cancelRequested)
				{
					jobs->MarkCancelled(owner, job, detail::ErrorJson("job cancelled"), detail::CurrentUnixSeconds());
					return;
				}
				std::optional<overseer::AnalysisScheduler::Lease> lease;
				if (scheduler)
				{
					std::string scheduleError;
					lease = scheduler->Acquire(
						{owner, analysisSession, openItem, job},
						[coordinator, owner, analysisSession, view](std::size_t workers) {
							(void)coordinator->SetWorkerCount(owner, analysisSession, view, workers);
						},
						scheduleError);
					if (!lease)
					{
						jobs->MarkCancelled(owner, job, detail::ErrorJson(scheduleError), detail::CurrentUnixSeconds());
						return;
					}
				}
				const auto afterQueue = jobs->Info(owner, job);
				if (afterQueue.job && afterQueue.job->cancelRequested)
				{
					jobs->MarkCancelled(owner, job, detail::ErrorJson("job cancelled"), detail::CurrentUnixSeconds());
					return;
				}
				const auto finished = coordinator->UpdateAnalysisAndWait(
					owner, analysisSession, view, [jobs, owner, job, progress](const ipc::Progress& update) {
						jobs->ReportProgress(owner, job, update.phase(), update.completed(), update.total(),
							update.message(), detail::CurrentUnixSeconds());
						if (progress)
						{
							const auto info = jobs->Info(owner, job);
							if (info.job)
								progress(*info.job);
						}
					});
				const auto timestamp = detail::CurrentUnixSeconds();
				if (!finished.value)
				{
					const auto info = jobs->Info(owner, job);
					if (info.job && info.job->cancelRequested)
						jobs->MarkCancelled(owner, job, detail::ErrorJson("job cancelled"), timestamp);
					else
						jobs->Fail(owner, job, detail::ErrorJson(finished.error), timestamp);
					return;
				}
				const auto json = AnalysisFinishedJson(*finished.value);
				const auto info = jobs->Info(owner, job);
				if (finished.value->state() == ipc::ANALYSIS_STATE_ABORTED || (info.job && info.job->cancelRequested))
					jobs->MarkCancelled(owner, job, json, timestamp);
				else if (finished.value->state() == ipc::ANALYSIS_STATE_FAILED)
					jobs->Fail(owner, job, json, timestamp);
				else
					jobs->Complete(owner, job, json, timestamp);
			}

			FoundationResult StartAnalysisJob(const ToolCallContext& context, bool detachImmediately)
			{
				FoundationResult error;
				const auto target = Target(context, error);
				if (!target)
					return error;
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				const auto owner = context.principal.id;
				const auto analysisSession = context.currentSession->reference;
				const auto created = context.jobs->Create(owner, analysisSession, target->view, "analysis_update",
					context.unixNow, context.now,
					[coordinator = context.fileCoordinator, scheduler = context.scheduler, owner, analysisSession,
						view = target->view, openItem = target->openItem] {
						if (scheduler && scheduler->CancelQueued(owner, analysisSession, openItem) != 0)
							return std::string {};
						const auto error = coordinator->AbortAnalysis(owner, analysisSession, view);
						return error.find("no analysis is active") != std::string::npos ? std::string {} : error;
					});
				if (!created.job)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				const auto job = created.job->reference;
				context.jobs->Start(owner, job, context.unixNow);
				if (!detachImmediately && context.attached)
					context.attached(job, [jobs = context.jobs, owner, job] { (void)jobs->Cancel(owner, job); });
				context.jobs->ReportProgress(owner, job, "analysis", 0, 0, "analysis started", context.unixNow);
				if (!detachImmediately && context.progress)
				{
					const auto info = context.jobs->Info(owner, job);
					if (info.job)
						context.progress(*info.job);
				}
				const auto workerError = context.jobs->StartWorker(
					[jobs = context.jobs, coordinator = context.fileCoordinator, scheduler = context.scheduler, owner,
						analysisSession, view = target->view, openItem = target->openItem, job,
						progress = detachImmediately ? Foundation::JobProgressCallback {} : context.progress] {
						RunAnalysisJob(
							jobs, coordinator, scheduler, owner, analysisSession, view, openItem, job, progress);
					});
				if (!workerError.empty())
					context.jobs->Fail(owner, job, detail::ErrorJson(workerError), context.unixNow);
				if (detachImmediately)
					return ToolCallSuccess(context, job_tools::JobJson(*created.job));
				const auto waited = context.jobs->WaitForTerminal(owner, job, context.config.jobs.detachAfter);
				if (!waited.job)
					return ToolCallSuccess(context, detail::ErrorJson(waited.error), true);
				if (waited.job->state == session::JobState::Queued || waited.job->state == session::JobState::Running)
					return ToolCallSuccess(context, job_tools::JobJson(*waited.job));
				const auto result = context.jobs->TakeResult(owner, job);
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(
					context, result.job->resultJson, result.job->state != session::JobState::Complete);
			}

			FoundationResult AnalysisUpdateAndWait(const ToolCallContext& context)
			{
				return StartAnalysisJob(context, false);
			}

			FoundationResult AnalysisUpdateAsync(const ToolCallContext& context)
			{
				return StartAnalysisJob(context, true);
			}

			FoundationResult AnalysisUpdate(const ToolCallContext& context)
			{
				FoundationResult result;
				const auto target = Target(context, result);
				if (!target)
					return result;
				std::string error;
				if (context.scheduler)
				{
					if (!context.jobs || target->openItem.empty()
						|| !context.sessions.Retain(
							context.currentSession->reference, context.principal.id, context.now))
						error = "cannot retain analysis session for scheduled analysis";
					else
					{
						const auto owner = context.principal.id;
						const auto analysisSession = context.currentSession->reference;
						error = context.jobs->StartWorker(
							[scheduler = context.scheduler, coordinator = context.fileCoordinator,
								sessions = &context.sessions, owner, analysisSession, view = target->view,
								openItem = target->openItem] {
								std::string scheduleError;
								auto lease = scheduler->Acquire(
									{owner, analysisSession, openItem, {}},
									[coordinator, owner, analysisSession, view](std::size_t workers) {
										(void)coordinator->SetWorkerCount(owner, analysisSession, view, workers);
									},
									scheduleError);
								if (lease)
									(void)coordinator->UpdateAnalysisAndWait(owner, analysisSession, view);
								sessions->Release(analysisSession, owner);
							});
						if (!error.empty())
							context.sessions.Release(analysisSession, owner);
					}
				}
				else
					error = context.fileCoordinator->UpdateAnalysis(
						context.principal.id, context.currentSession->reference, target->view);
				if (!error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("binaryView");
				writer.String(target->view.data(), static_cast<rapidjson::SizeType>(target->view.size()));
				writer.Key("requested");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult AnalysisAbort(const ToolCallContext& context)
			{
				FoundationResult result;
				const auto target = Target(context, result);
				if (!target)
					return result;
				const auto cancelled = context.scheduler && !target->openItem.empty() ?
					context.scheduler->CancelQueued(
						context.principal.id, context.currentSession->reference, target->openItem) :
					0;
				auto error = context.fileCoordinator->AbortAnalysis(
					context.principal.id, context.currentSession->reference, target->view);
				if (cancelled != 0 && error.find("no analysis is active") != std::string::npos)
					error.clear();
				if (!error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("binaryView");
				writer.String(target->view.data(), static_cast<rapidjson::SizeType>(target->view.size()));
				writer.Key("requested");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			BINJAD_ANALYSIS_TOOL(AnalysisStatusTool, "bn_analysis_status",
				"Return analysis status for a materialized explicit BinaryView.", Core, "Files and views",
				ToolCallAvailability::None, AnalysisStatus, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(AnalysisUpdateTool, "bn_analysis_update",
				"Start analysis without waiting; prefer update_and_wait for normal client workflows.", Core,
				"Files and views", ToolCallAvailability::None, AnalysisUpdate, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(AnalysisUpdateAndWaitTool, "bn_analysis_update_and_wait",
				"Preferred analysis operation; waits until the deadline, then returns a job to poll every 10 seconds "
				"and consume with job_result.",
				Core, "Files and views", ToolCallAvailability::None, AnalysisUpdateAndWait,
				schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(AnalysisUpdateAsyncTool, "bn_analysis_update_async",
				"Start analysis for a materialized BinaryView as an immediately detached job.", Core, "Files and views",
				ToolCallAvailability::None, AnalysisUpdateAsync, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(AnalysisAbortTool, "bn_analysis_abort",
				"Abort analysis for a materialized explicit BinaryView.", Core, "Files and views",
				ToolCallAvailability::None, AnalysisAbort, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(FunctionListTool, "bn_function_list",
				"List functions; query first, default 50 rows, then continue with nextOffset.", Core, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address"), schema::String("start"), schema::String("end"), schema::String("query"),
				schema::StringOrInteger("length"), schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 50, "Defaults to 50; use query and continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionInfoTool, "bn_function_info",
				"Return detailed metadata for one analyzed function.", Core, "Functions", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("function", true),
				schema::String("arch"));
			BINJAD_ANALYSIS_TOOL(FunctionDisassemblyTool, "bn_function_disassembly",
				"Render 200 disassembly lines by default; continue with nextOffset.", Core, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionDecompileTool, "bn_function_decompile",
				"Render an exact analyzed function, default 200 lines; language auto-selects Pseudo Objective-C or "
				"Pseudo Rust when applicable; confirm targets with function_list first.",
				Core, "Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("function", true), schema::String("arch"),
				schema::String("language", false,
					"Omit for automatic Pseudo Objective-C on Objective-C methods, Pseudo Rust on Rust symbols, and "
					"Pseudo C otherwise; explicit names are case/separator insensitive."),
				schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 200, "Defaults to 200 rendered lines; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(StringListTool, "bn_string_list",
				"List strings; query first, default 50 rows, then continue with nextOffset.", Core,
				"Memory and strings", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address"), schema::String("start"),
				schema::String("end"), schema::String("query"), schema::StringOrInteger("length"),
				schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 50, "Defaults to 50; use query first and continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(StringAtTool, "bn_string_at", "Return detailed decoded string data at an address.",
				Core, "Memory and strings", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 65536));
			BINJAD_ANALYSIS_TOOL(SymbolListTool, "bn_symbol_list",
				"List symbols; query first, default 50 rows, then continue with nextOffset.", Core,
				"Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address"), schema::String("start"),
				schema::String("end"), schema::String("query"), schema::StringOrInteger("length"),
				schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 50, "Defaults to 50; use query first and continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(SymbolListAtTool, "bn_symbol_list_at",
				"Return full symbol metadata at an exact address.", Core, "Symbols and entries",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(MemoryReadTool, "bn_memory_read", "Read mapped bytes as lowercase hexadecimal.", Core,
				"Memory and strings", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true),
				schema::StringOrInteger("length", true, 0, 65536));
			BINJAD_ANALYSIS_TOOL(DataAtTool, "bn_data_at", "Return compact data context at an address.", Core,
				"Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true));
		}  // namespace core_analysis_tools

		namespace job_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			template <typename WriterType>
			void WriteJob(WriterType& writer, const session::JobRecord& job, bool includeResult)
			{
				writer.StartObject();
				writer.Key("job");
				writer.String(job.reference.data(), static_cast<rapidjson::SizeType>(job.reference.size()));
				writer.Key("operation");
				writer.String(job.operation.data(), static_cast<rapidjson::SizeType>(job.operation.size()));
				writer.Key("state");
				const auto state = session::JobStateName(job.state);
				writer.String(state.data(), static_cast<rapidjson::SizeType>(state.size()));
				writer.Key("createdAt");
				writer.Uint64(job.createdAtUnix);
				writer.Key("updatedAt");
				writer.Uint64(job.updatedAtUnix);
				writer.Key("cancelRequested");
				writer.Bool(job.cancelRequested);
				if (job.analysisSession)
				{
					writer.Key("analysisSession");
					writer.String(
						job.analysisSession->data(), static_cast<rapidjson::SizeType>(job.analysisSession->size()));
				}
				if (job.binaryView)
				{
					writer.Key("binaryView");
					writer.String(job.binaryView->data(), static_cast<rapidjson::SizeType>(job.binaryView->size()));
				}
				if (job.progress)
				{
					writer.Key("progress");
					writer.StartObject();
					writer.Key("sequence");
					writer.Uint64(job.progress->sequence);
					writer.Key("timestamp");
					writer.Uint64(job.progress->timestampUnix);
					writer.Key("phase");
					writer.String(
						job.progress->phase.data(), static_cast<rapidjson::SizeType>(job.progress->phase.size()));
					writer.Key("completed");
					writer.Uint64(job.progress->completed);
					writer.Key("total");
					writer.Uint64(job.progress->total);
					if (!job.progress->message.empty())
					{
						writer.Key("message");
						writer.String(job.progress->message.data(),
							static_cast<rapidjson::SizeType>(job.progress->message.size()));
					}
					writer.EndObject();
				}
				if (job.state == session::JobState::Queued || job.state == session::JobState::Running)
				{
					writer.Key("pollAfterMilliseconds");
					writer.Uint(10000);
					writer.Key("nextAction");
					writer.String(
						"Call bn_job_info no more than every 10 seconds; when terminal, call bn_job_result exactly "
						"once. Avoid polling bn_analysis_status for this operation.");
				}
				else if (!includeResult)
				{
					writer.Key("nextAction");
					writer.String("Call bn_job_result exactly once to retrieve and consume the terminal result.");
				}
				if (includeResult && !job.resultJson.empty())
				{
					writer.Key("result");
					writer.RawValue(job.resultJson.data(), job.resultJson.size(), rapidjson::kObjectType);
				}
				writer.EndObject();
			}

			std::string JobJson(const session::JobRecord& job, bool includeResult)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteJob(writer, job, includeResult);
				return {buffer.GetString(), buffer.GetSize()};
			}

			FoundationResult JobList(const ToolCallContext& context)
			{
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = context.arguments.FindMember("offset"); member != context.arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = context.arguments.FindMember("limit"); member != context.arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
				const auto jobs = context.jobs->List(context.principal.id);
				offset = std::min(offset, jobs.size());
				const auto end = offset + std::min(limit, jobs.size() - offset);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("jobs");
				writer.StartArray();
				for (std::size_t index = offset; index < end; ++index)
					WriteJob(writer, jobs[index], false);
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(end - offset);
				writer.Key("total");
				writer.Uint64(jobs.size());
				writer.Key("nextOffset");
				writer.Uint64(end);
				writer.Key("truncated");
				writer.Bool(end < jobs.size());
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			std::string JobReference(const ToolCallContext& context)
			{
				const auto member = context.arguments.FindMember("job");
				return {member->value.GetString(), member->value.GetStringLength()};
			}

			FoundationResult JobInfo(const ToolCallContext& context)
			{
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				const auto result = context.jobs->Info(context.principal.id, JobReference(context));
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(context, JobJson(*result.job));
			}

			FoundationResult JobResult(const ToolCallContext& context)
			{
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				const auto result = context.jobs->TakeResult(context.principal.id, JobReference(context));
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(context, JobJson(*result.job, true));
			}

			FoundationResult JobCancel(const ToolCallContext& context)
			{
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				const auto job = JobReference(context);
				if (const auto error = context.jobs->Cancel(context.principal.id, job); !error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				const auto result = context.jobs->Info(context.principal.id, job);
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(context, JobJson(*result.job));
			}

			BINJAD_ANALYSIS_TOOL(JobListTool, "bn_job_list", "List detached jobs owned by this bearer token.", Core,
				"Jobs", ToolCallAvailability::None, JobList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_ANALYSIS_TOOL(JobInfoTool, "bn_job_info", "Inspect a detached job.", Core, "Jobs",
				ToolCallAvailability::None, JobInfo, schema::String("job", true));
			BINJAD_ANALYSIS_TOOL(JobResultTool, "bn_job_result", "Retrieve and consume a terminal detached-job result.",
				Core, "Jobs", ToolCallAvailability::None, JobResult, schema::String("job", true));
			BINJAD_ANALYSIS_TOOL(JobCancelTool, "bn_job_cancel", "Request cancellation of a detached job.", Core,
				"Jobs", ToolCallAvailability::None, JobCancel, schema::String("job", true));
		}  // namespace job_tools

		namespace function_tools {
			BINJAD_ANALYSIS_TOOL(FunctionCallersTool, "bn_function_callers",
				"List callsites that call one analyzed function.", FunctionAnalysis, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionCalleesTool, "bn_function_callees",
				"List callees reached from callsites in one analyzed function.", FunctionAnalysis, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionIlTool, "bn_function_il",
				"Render 200 LLIL, MLIL, or HLIL lines by default; continue with nextOffset.", FunctionAnalysis,
				"Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("function", true), schema::String("arch"),
				schema::Enum("level", false, {"llil", "mlil", "hlil"}), schema::Boolean("ssa"),
				schema::Enum("form", false, {"text"}), schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 200, "Defaults to 200 rendered lines; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionStackLayoutTool, "bn_function_stack_layout",
				"List stack variables for one analyzed function.", FunctionAnalysis, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionXrefsFromTool, "bn_function_xrefs_from",
				"List code references originating in one analyzed function.", FunctionAnalysis, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(FunctionXrefsToTool, "bn_function_xrefs_to",
				"List code references into one analyzed function.", FunctionAnalysis, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
		}  // namespace function_tools

		namespace binary_data_tools {
			FoundationResult ExecuteKernelCacheAware(
				const ToolCallContext& context, std::string_view kernelCacheCommand)
			{
				if (context.config.tools.kernelCache && context.openItems && context.currentSession)
				{
					const auto binaryView = detail::RequiredString(context.arguments, "binaryView");
					const auto target = context.openItems->FindView(
						context.principal.id, context.currentSession->reference, binaryView);
					if (target && target->viewType == "KCView")
						return ExecuteForwardedAnalysisTool(context, kernelCacheCommand);
				}
				return ExecuteForwardedAnalysisTool(context);
			}

			FoundationResult ExportList(const ToolCallContext& context)
			{
				return ExecuteKernelCacheAware(context, "bn_kernel_cache_export_list");
			}

			FoundationResult EntryPointList(const ToolCallContext& context)
			{
				return ExecuteKernelCacheAware(context, "bn_kernel_cache_entry_point_list");
			}

			BINJAD_ANALYSIS_TOOL(ImportListTool, "bn_import_list", "List import symbols with compact rows.", BinaryData,
				"Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address"), schema::String("start"),
				schema::String("end"), schema::String("query"), schema::StringOrInteger("length"),
				schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 50, "Defaults to 50; use query first and continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(ExportListTool, "bn_export_list",
				"List exports; enabled KernelCache views use loaded-image cache symbols.", BinaryData,
				"Symbols and entries", ToolCallAvailability::None, ExportList, schema::String("binaryView", true),
				schema::String("address"), schema::String("start"), schema::String("end"), schema::String("query"),
				schema::StringOrInteger("length"), schema::Integer("offset", false, 0),
				schema::Integer(
					"limit", false, 1, 1000, 50, "Defaults to 50; use query first and continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(EntryPointListTool, "bn_entry_point_list",
				"List loader entry functions; KernelCache views include module init/term targets with analyzed state.",
				BinaryData, "Symbols and entries", ToolCallAvailability::None, EntryPointList,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(SectionListTool, "bn_section_list", "List section ranges and semantics.", BinaryData,
				"Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(SegmentListTool, "bn_segment_list", "List full mapped-segment metadata.", BinaryData,
				"Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DataVariableListTool, "bn_data_variable_list",
				"List typed data variables with compact rows.", BinaryData, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address"), schema::String("start"), schema::String("end"),
				schema::StringOrInteger("length"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(RelocationListTool, "bn_relocation_list", "List full relocation metadata.", BinaryData,
				"Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address"), schema::String("start"),
				schema::String("end"), schema::StringOrInteger("length"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DataXrefsFromTool, "bn_data_xrefs_from",
				"List addresses referenced by data values stored at an address or range; code instruction references "
				"are excluded.",
				BinaryData, "Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::StringOrInteger("length"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DataXrefsToTool, "bn_data_xrefs_to",
				"List data locations that reference a target address or range; code instruction references are "
				"excluded.",
				BinaryData, "Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::StringOrInteger("length"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
		}  // namespace binary_data_tools

		namespace search_tools {
			FoundationResult ProjectAnalysisSearch(const ToolCallContext& context)
			{
				if (!context.openItems || !context.fileCoordinator)
					return ToolCallSuccess(
						context, detail::ErrorJson("open-item and file-child services are required"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = context.arguments.FindMember("offset"); member != context.arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = context.arguments.FindMember("limit"); member != context.arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
				struct ProjectMatch
				{
					std::string path;
					std::string binaryView;
					std::string json;
				};
				std::vector<ProjectMatch> matches;
				std::size_t searchedViews = 0;
				bool partial = false;
				for (const auto& item : context.openItems->ListForToken(context.principal.id))
				{
					if (!item.project || *item.project != project)
						continue;
					for (const auto& view : item.binaryViews)
					{
						if (!view.created)
							continue;
						const auto argumentsJson = std::string("{\"query\":")
							+ detail::Serialize(context.arguments["query"]) + ",\"offset\":0,\"limit\":1000}";
						const auto result = context.fileCoordinator->ExecuteAnalysisTool(context.principal.id,
							item.analysisSession, view.reference, context.request.name, argumentsJson);
						if (!result.value)
							continue;
						++searchedViews;
						rapidjson::Document found;
						found.Parse(result.value->data(), result.value->size());
						if (found.HasParseError() || !found.IsObject() || !found.HasMember("matches")
							|| !found["matches"].IsArray())
							continue;
						if (found.HasMember("truncated") && found["truncated"].IsBool() && found["truncated"].GetBool())
							partial = true;
						for (const auto& match : found["matches"].GetArray())
							matches.push_back({item.source, view.reference, detail::Serialize(match)});
					}
				}
				offset = std::min(offset, matches.size());
				const auto finish = offset + std::min(limit, matches.size() - offset);
				rapidjson::StringBuffer buffer;
				rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("matches");
				writer.StartArray();
				for (std::size_t index = offset; index < finish; ++index)
				{
					writer.StartObject();
					writer.Key("path");
					writer.String(matches[index].path.data(), matches[index].path.size());
					writer.Key("binaryView");
					writer.String(matches[index].binaryView.data(), matches[index].binaryView.size());
					writer.Key("match");
					writer.RawValue(matches[index].json.data(), matches[index].json.size(), rapidjson::kObjectType);
					writer.EndObject();
				}
				writer.EndArray();
				writer.Key("searchedViews");
				writer.Uint64(searchedViews);
				writer.Key("coverage");
				writer.String("materialized open BinaryViews from this project");
				writer.Key("partial");
				writer.Bool(partial);
				writer.Key("count");
				writer.Uint64(finish - offset);
				writer.Key("total");
				writer.Uint64(matches.size());
				writer.Key("nextOffset");
				if (finish < matches.size())
					writer.Uint64(finish);
				else
					writer.Null();
				writer.Key("truncated");
				writer.Bool(finish < matches.size());
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			BINJAD_ANALYSIS_TOOL(CommentListTool, "bn_comment_list",
				"List all global address comments with bounded pagination.", Search, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(CommentSearchTool, "bn_comment_search",
				"Search global address comments case-insensitively.", Search, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("query", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(MemorySearchTool, "bn_memory_search",
				"Search mapped bytes with Binary Ninja advanced binary-search syntax.", Search, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("pattern", true), schema::String("start"), schema::String("end"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(InstructionSearchTool, "bn_instruction_search",
				"Search rendered disassembly text across an explicit address range or the whole view.", Search,
				"Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("query", true), schema::String("start"),
				schema::String("end"), schema::Boolean("caseSensitive"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(IlSearchTool, "bn_il_search",
				"Search rendered LLIL, MLIL, or HLIL across analyzed functions.", Search, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("query", true), schema::String("functionQuery"),
				schema::EnumWithDefault("level", false, {"llil", "mlil", "hlil"}, "hlil"), schema::Boolean("ssa"),
				schema::Boolean("caseSensitive"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(ConstantSearchTool, "bn_constant_search",
				"Search globally for rendered uses of one constant or address value.", Search, "Data and references",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("value", true), schema::String("start"), schema::String("end"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(ProjectAnalysisSearchTool, "bn_project_analysis_search",
				"Search functions, symbols, strings, and comments across materialized BinaryViews currently open from "
				"one project.",
				Search, "Data and references", ToolCallAvailability::None, ProjectAnalysisSearch,
				schema::String("project", true), schema::String("query", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 200, 50));
		}  // namespace search_tools

		namespace type_tools {
			BINJAD_ANALYSIS_TOOL(FunctionPrototypeSetTool, "bn_function_prototype_set",
				"Set a parsed user prototype; if needsUpdate, run analysis update before variable rename/readback.",
				Types, "Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("function", true), schema::String("arch"),
				schema::String("prototype", true));
			BINJAD_ANALYSIS_TOOL(CallingConventionSetTool, "bn_calling_convention_set",
				"Set a function's user calling convention.", Types, "Functions", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("function", true),
				schema::String("arch"), schema::String("callingConvention", true));
			BINJAD_ANALYSIS_TOOL(CallingConventionListTool, "bn_calling_convention_list",
				"List calling conventions available to one analyzed function.", Types, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"));
			BINJAD_ANALYSIS_TOOL(VariableListTool, "bn_variable_list", "List variables for one analyzed function.",
				Types, "Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("function", true), schema::String("arch"),
				schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50, "Defaults to 50; continue with nextOffset."));
			BINJAD_ANALYSIS_TOOL(VariableRenameTool, "bn_variable_rename",
				"Rename one variable after prototype edits; follow returned nextAction before readback.", Types,
				"Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("function", true), schema::String("arch"),
				schema::String("variable", true), schema::String("source"), schema::String("newName", true),
				schema::Integer("index", false, 0), schema::Integer("storage"));
			BINJAD_ANALYSIS_TOOL(VariableSetTypeTool, "bn_variable_set_type",
				"Set one variable type; follow returned nextAction before readback.", Types, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"), schema::String("variable", true),
				schema::String("variableSource"), schema::String("definition"), schema::String("source"),
				schema::String("type"), schema::Integer("index", false, 0), schema::Integer("storage"),
				schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeListTool, "bn_type_list", "List named types with compact class rows.", Types,
				"Types", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("query"), schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(TypeInfoTool, "bn_type_info",
				"Return metadata and a complete C declaration for one named type.", Types, "Types",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("type", true));
			BINJAD_ANALYSIS_TOOL(TypeParseTool, "bn_type_parse", "Parse C source without defining types.", Types,
				"Types", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("source", true), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeDefineTool, "bn_type_define", "Parse and define selected named types.", Types,
				"Types", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("source", true), schema::StringArray("types"), schema::StringArray("options"),
				schema::StringArray("includeDirs"), schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeStructCreateTool, "bn_type_struct_create",
				"Parse and define exactly one new struct type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeStructModifyTool, "bn_type_struct_modify",
				"Parse and replace exactly one existing struct type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeUnionCreateTool, "bn_type_union_create",
				"Parse and define exactly one new union type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeUnionModifyTool, "bn_type_union_modify",
				"Parse and replace exactly one existing union type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeEnumCreateTool, "bn_type_enum_create",
				"Parse and define exactly one new enum type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeEnumModifyTool, "bn_type_enum_modify",
				"Parse and replace exactly one existing enum type.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("source", true),
				schema::String("type"), schema::StringArray("options"), schema::StringArray("includeDirs"),
				schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(TypeDeleteTool, "bn_type_delete", "Delete one exact named type.", Types, "Types",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("type", true));
			BINJAD_ANALYSIS_TOOL(TypeRenameTool, "bn_type_rename", "Rename one exact named type.", Types, "Types",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("type", true), schema::String("newType", true));
			BINJAD_ANALYSIS_TOOL(TypeXrefsFromTool, "bn_type_xrefs_from", "List outgoing named-type references.", Types,
				"Types", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("type", true), schema::Boolean("recursive"));
			BINJAD_ANALYSIS_TOOL(TypeXrefsToTool, "bn_type_xrefs_to",
				"List grouped incoming code, data, and type references.", Types, "Types", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("type", true),
				schema::Integer("maxItems", false, 1));
		}  // namespace type_tools

		namespace annotation_tools {
			BINJAD_ANALYSIS_TOOL(CommentGetTool, "bn_comment_get", "Return the comment at an address.", Annotations,
				"Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(CommentSetTool, "bn_comment_set", "Set a non-empty comment at an address.",
				Annotations, "Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::String("text", true));
			BINJAD_ANALYSIS_TOOL(CommentDeleteTool, "bn_comment_delete", "Delete the comment at an address.",
				Annotations, "Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(SymbolDefineTool, "bn_symbol_define",
				"Define a user symbol at an address; FunctionSymbol annotation does not create a function.",
				Annotations, "Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::String("name", true),
				schema::String("namespace"),
				schema::Enum("type", false,
					{"FunctionSymbol", "ImportAddressSymbol", "ImportedFunctionSymbol", "DataSymbol",
						"ImportedDataSymbol", "ExternalSymbol", "LibraryFunctionSymbol", "SymbolicFunctionSymbol",
						"LocalLabelSymbol"}),
				schema::Enum("binding", false, {"NoBinding", "LocalBinding", "GlobalBinding", "WeakBinding"}),
				schema::Integer("ordinal", false, 0));
			BINJAD_ANALYSIS_TOOL(SymbolRenameTool, "bn_symbol_rename", "Rename one exactly selected symbol.",
				Annotations, "Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::String("name"),
				schema::String("type"), schema::String("namespace"), schema::String("newName", true),
				schema::Integer("ordinal", false, 0));
			BINJAD_ANALYSIS_TOOL(SymbolUndefineTool, "bn_symbol_undefine", "Undefine one exactly selected user symbol.",
				Annotations, "Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true), schema::String("name"),
				schema::String("type"), schema::String("namespace"), schema::Integer("ordinal", false, 0));
			BINJAD_ANALYSIS_TOOL(BookmarkCreateTool, "bn_bookmark_create",
				"Create a persistent bookmark at an address.", Annotations, "Other", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("address", true),
				schema::String("note"));
			BINJAD_ANALYSIS_TOOL(BookmarkListTool, "bn_bookmark_list", "List persistent bookmarks with pagination.",
				Annotations, "Other", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("query"), schema::String("type"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(BookmarkDeleteTool, "bn_bookmark_delete",
				"Delete one persistent bookmark by its Binary Ninja tag id.", Annotations, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("id", true));
			BINJAD_ANALYSIS_TOOL(TagCreateTool, "bn_tag_create",
				"Create a persistent user data tag at an address, creating its tag type when needed.", Annotations,
				"Other", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address", true), schema::String("type", true), schema::String("data"),
				schema::String("icon"));
			BINJAD_ANALYSIS_TOOL(TagListTool, "bn_tag_list",
				"List persistent user tags with optional type/data query filters.", Annotations, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("query"), schema::String("type"), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 200, 50));
			BINJAD_ANALYSIS_TOOL(TagDeleteTool, "bn_tag_delete",
				"Delete one persistent user tag by its Binary Ninja tag id.", Annotations, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("id", true));
			BINJAD_ANALYSIS_TOOL(MetadataGetTool, "bn_metadata_get",
				"Read one persistent custom BinaryView metadata value in the binjad.user namespace.", Annotations,
				"Other", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("key", true));
			BINJAD_ANALYSIS_TOOL(MetadataSetTool, "bn_metadata_set",
				"Store one arbitrary JSON custom BinaryView metadata value in the binjad.user namespace.", Annotations,
				"Other", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("key", true), schema::Any("value", true));
			BINJAD_ANALYSIS_TOOL(MetadataDeleteTool, "bn_metadata_delete",
				"Delete one persistent custom BinaryView metadata value in the binjad.user namespace.", Annotations,
				"Other", ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("key", true));
		}  // namespace annotation_tools

		namespace editing_tools {
			BINJAD_ANALYSIS_TOOL(FunctionCreateTool, "bn_function_create",
				"Create a user function at a mapped address; defining a FunctionSymbol alone does not create a "
				"function.",
				BinaryEditing, "Functions", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(FunctionDeleteTool, "bn_function_delete",
				"Remove one exact function as a persistent user analysis override.", BinaryEditing, "Functions",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("function", true), schema::String("arch"));
			BINJAD_ANALYSIS_TOOL(EntryPointAddTool, "bn_entry_point_add",
				"Add an analysis entry point at a mapped address using the BinaryView's default platform.",
				BinaryEditing, "Symbols and entries", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(DataVariableDefineTool, "bn_data_variable_define",
				"Define a typed user data variable; use definition for a direct type, or source plus optional type to "
				"select a parsed declaration.",
				BinaryEditing, "Data and references", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("datavar", true), schema::String("definition"),
				schema::String("source"), schema::String("type"), schema::StringArray("options"),
				schema::StringArray("includeDirs"), schema::Boolean("importDependencies"));
			BINJAD_ANALYSIS_TOOL(DataVariableUndefineTool, "bn_data_variable_undefine",
				"Remove an exact data variable.", BinaryEditing, "Data and references", ToolCallAvailability::None,
				ExecuteForwardedAnalysisTool, schema::String("binaryView", true), schema::String("datavar", true));
			BINJAD_ANALYSIS_TOOL(SectionCreateTool, "bn_section_create", "Create a user-defined section.",
				BinaryEditing, "Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("section", true), schema::String("start", true),
				schema::String("semantics"), schema::String("typeName"), schema::String("linkedSection"),
				schema::String("infoSection"), schema::StringOrInteger("length", true),
				schema::Integer("alignment", false, 1), schema::Integer("entrySize", false, 0),
				schema::Integer("infoData", false, 0));
			BINJAD_ANALYSIS_TOOL(SectionDeleteTool, "bn_section_delete",
				"Delete an exact auto- or user-defined section.", BinaryEditing, "Sections and segments",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("section", true));
			BINJAD_ANALYSIS_TOOL(SectionModifyTool, "bn_section_modify",
				"Modify an exact auto- or user-defined section.", BinaryEditing, "Sections and segments",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("section", true), schema::String("newSection"), schema::String("start"),
				schema::String("semantics"), schema::String("typeName"), schema::String("linkedSection"),
				schema::String("infoSection"), schema::StringOrInteger("length"),
				schema::Integer("alignment", false, 1), schema::Integer("entrySize", false, 0),
				schema::Integer("infoData", false, 0));
			BINJAD_ANALYSIS_TOOL(SegmentCreateTool, "bn_segment_create", "Create a user mapped segment.", BinaryEditing,
				"Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("start", true), schema::String("length", true),
				schema::String("dataOffset", true), schema::String("dataLength", true),
				schema::Integer("flags", true, 0, 15));
			BINJAD_ANALYSIS_TOOL(SegmentModifyTool, "bn_segment_modify", "Replace one exact user mapped segment.",
				BinaryEditing, "Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("start", true), schema::String("length", true),
				schema::String("newStart"), schema::String("newLength"), schema::String("dataOffset", true),
				schema::String("dataLength", true), schema::Integer("flags", true, 0, 15));
			BINJAD_ANALYSIS_TOOL(SegmentDeleteTool, "bn_segment_delete", "Delete one exact user mapped segment.",
				BinaryEditing, "Sections and segments", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("start", true), schema::String("length", true));
			BINJAD_ANALYSIS_TOOL(BinaryViewRebaseTool, "bn_binary_view_rebase",
				"Rebase an explicit BinaryView to a new base address.", BinaryEditing, "Files and views",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address", true));
			BINJAD_ANALYSIS_TOOL(MemoryMapPreviewTool, "bn_memory_map_preview",
				"Preview a segment or rebase operation without mutating the BinaryView.", BinaryEditing,
				"Memory and strings", ToolCallAvailability::None, ExecuteForwardedAnalysisTool,
				schema::String("binaryView", true), schema::String("operation", true), schema::String("start"),
				schema::String("length"), schema::String("newStart"), schema::String("newLength"),
				schema::String("dataOffset"), schema::String("dataLength"), schema::String("address"),
				schema::Integer("flags", false, 0, 15));
			BINJAD_ANALYSIS_TOOL(StringDefineTool, "bn_string_define",
				"Define a typed user string data object at an address.", BinaryEditing, "Memory and strings",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address", true), schema::String("length", true),
				schema::Enum("encoding", true, {"ascii", "utf8", "utf16", "utf32"}));
			BINJAD_ANALYSIS_TOOL(StringUndefineTool, "bn_string_undefine",
				"Undefine a user string data object at an address.", BinaryEditing, "Memory and strings",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true),
				schema::String("address", true));
		}  // namespace editing_tools

		namespace history_tools {
			BINJAD_ANALYSIS_TOOL(TransactionBeginTool, "bn_transaction_begin",
				"Begin one explicit undo transaction for an explicit BinaryView's open item.", History, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(TransactionCommitTool, "bn_transaction_commit",
				"Commit the active transaction for an explicit BinaryView.", History, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(TransactionRollbackTool, "bn_transaction_rollback",
				"Roll back the active transaction for an explicit BinaryView.", History, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(UndoTool, "bn_undo",
				"Undo the last committed mutation for an explicit BinaryView's file.", History, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(RedoTool, "bn_redo",
				"Redo the last undone mutation for an explicit BinaryView's file.", History, "Other",
				ToolCallAvailability::None, ExecuteForwardedAnalysisTool, schema::String("binaryView", true));
		}  // namespace history_tools

		namespace debugger_tools {
			FoundationResult ExecuteDebuggerTool(const ToolCallContext& context)
			{
				return ExecuteForwardedAnalysisTool(context);
			}

			FoundationResult ExecuteDebuggerWait(const ToolCallContext& context)
			{
				if (!context.currentSession || !context.fileCoordinator)
					return ToolCallSuccess(
						context, detail::ErrorJson("analysis session and file-child service are required"), true);
				if (!context.jobs)
					return ToolCallSuccess(context, detail::ErrorJson("job service is unavailable"), true);
				const auto binaryView = detail::RequiredString(context.arguments, "binaryView");
				const auto argumentsJson = detail::Serialize(context.arguments);
				const auto owner = context.principal.id;
				const auto analysisSession = context.currentSession->reference;
				const auto created = context.jobs->Create(
					owner, analysisSession, binaryView, context.request.name, context.unixNow, context.now);
				if (!created.job)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				const auto job = created.job->reference;
				context.jobs->Start(owner, job, context.unixNow);
				if (context.attached)
					context.attached(job, [jobs = context.jobs, owner, job] { (void)jobs->Cancel(owner, job); });
				context.jobs->ReportProgress(
					owner, job, "debugger", 0, 1, "waiting for debugger target", context.unixNow);
				if (context.progress)
				{
					const auto info = context.jobs->Info(owner, job);
					if (info.job)
						context.progress(*info.job);
				}
				const auto workerError = context.jobs->StartWorker(
					[jobs = context.jobs, coordinator = context.fileCoordinator, owner, analysisSession, binaryView,
						name = context.request.name, argumentsJson, job, progress = context.progress] {
						const auto result =
							coordinator->ExecuteAnalysisTool(owner, analysisSession, binaryView, name, argumentsJson);
						const auto current = jobs->Info(owner, job);
						if (current.job && current.job->cancelRequested)
						{
							jobs->MarkCancelled(
								owner, job, detail::ErrorJson("debugger wait cancelled"), detail::CurrentUnixSeconds());
							return;
						}
						if (!result.value)
						{
							jobs->Fail(owner, job, detail::ErrorJson(result.error), detail::CurrentUnixSeconds());
							return;
						}
						jobs->ReportProgress(
							owner, job, "debugger", 1, 1, "debugger target stopped", detail::CurrentUnixSeconds());
						if (progress)
						{
							const auto info = jobs->Info(owner, job);
							if (info.job)
								progress(*info.job);
						}
						jobs->Complete(owner, job, *result.value, detail::CurrentUnixSeconds());
					});
				if (!workerError.empty())
					context.jobs->Fail(owner, job, detail::ErrorJson(workerError), context.unixNow);
				const auto waited = context.jobs->WaitForTerminal(owner, job, context.config.jobs.detachAfter);
				if (!waited.job)
					return ToolCallSuccess(context, detail::ErrorJson(waited.error), true);
				if (waited.job->state == session::JobState::Queued || waited.job->state == session::JobState::Running)
					return ToolCallSuccess(context, job_tools::JobJson(*waited.job));
				const auto result = context.jobs->TakeResult(owner, job);
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(
					context, result.job->resultJson, result.job->state != session::JobState::Complete);
			}

			BINJAD_ANALYSIS_TOOL(DebuggerAdapterListTool, "bn_debugger_adapter_list",
				"List debugger adapters available for an explicit BinaryView.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerStatusTool, "bn_debugger_status",
				"Return debugger state and target configuration.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerConfigureTool, "bn_debugger_configure",
				"Configure the debugger adapter and target.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true), schema::String("adapter"),
				schema::String("executable"), schema::String("inputFile"), schema::String("workingDirectory"),
				schema::String("commandLine"), schema::String("remoteHost"),
				schema::Integer("remotePort", false, 0, 65535), schema::Integer("attachPid"));
			BINJAD_ANALYSIS_TOOL(DebuggerLaunchTool, "bn_debugger_launch",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerConnectTool, "bn_debugger_connect",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerAttachTool, "bn_debugger_attach",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerGoTool, "bn_debugger_go", "Issue an immediate debugger control operation.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerPauseTool, "bn_debugger_pause",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerStepIntoTool, "bn_debugger_step_into",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerStepOverTool, "bn_debugger_step_over",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerStepReturnTool, "bn_debugger_step_return",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerRestartTool, "bn_debugger_restart",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerQuitTool, "bn_debugger_quit", "Issue an immediate debugger control operation.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerDetachTool, "bn_debugger_detach",
				"Issue an immediate debugger control operation.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true));
			BINJAD_ANALYSIS_TOOL(DebuggerLaunchAndWaitTool, "bn_debugger_launch_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerConnectAndWaitTool, "bn_debugger_connect_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerAttachAndWaitTool, "bn_debugger_attach_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerGoAndWaitTool, "bn_debugger_go_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerPauseAndWaitTool, "bn_debugger_pause_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerStepIntoAndWaitTool, "bn_debugger_step_into_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerStepOverAndWaitTool, "bn_debugger_step_over_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerStepReturnAndWaitTool, "bn_debugger_step_return_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerRestartAndWaitTool, "bn_debugger_restart_and_wait",
				"Run a bounded debugger control operation as an attached or detached job.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerWait, schema::String("binaryView", true),
				schema::Integer("timeoutMilliseconds", true, 1, 30000));
			BINJAD_ANALYSIS_TOOL(DebuggerProcessListTool, "bn_debugger_process_list", "List debugger target state.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerThreadListTool, "bn_debugger_thread_list", "List debugger target state.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerRegisterListTool, "bn_debugger_register_list", "List debugger target state.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerModuleListTool, "bn_debugger_module_list", "List debugger target state.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerMemoryRegionListTool, "bn_debugger_memory_region_list",
				"List debugger target state.", Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerBreakpointListTool, "bn_debugger_breakpoint_list",
				"List debugger target state.", Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerFrameListTool, "bn_debugger_frame_list",
				"List stack frames for a target thread.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true), schema::Integer("thread", false, 0),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
			BINJAD_ANALYSIS_TOOL(DebuggerThreadSetTool, "bn_debugger_thread_set",
				"Select the active debugger target thread.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true), schema::Integer("thread", true, 0));
			BINJAD_ANALYSIS_TOOL(DebuggerRegisterSetTool, "bn_debugger_register_set", "Set one target register value.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::String("register", true), schema::String("value", true));
			BINJAD_ANALYSIS_TOOL(DebuggerMemoryReadTool, "bn_debugger_memory_read", "Read target process memory.",
				Debugger, "Debugger", ToolCallAvailability::Admin, ExecuteDebuggerTool,
				schema::String("binaryView", true), schema::String("address", true),
				schema::Integer("length", true, 1, 65536));
			BINJAD_ANALYSIS_TOOL(DebuggerMemoryWriteTool, "bn_debugger_memory_write",
				"Write target process memory from hexadecimal bytes.", Debugger, "Debugger",
				ToolCallAvailability::Admin, ExecuteDebuggerTool, schema::String("binaryView", true),
				schema::String("address", true), schema::String("hex", true));
			BINJAD_ANALYSIS_TOOL(DebuggerBreakpointAddTool, "bn_debugger_breakpoint_add",
				"Add an absolute software breakpoint.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true), schema::NonEmptyString("address", true));
			BINJAD_ANALYSIS_TOOL(DebuggerBreakpointDeleteTool, "bn_debugger_breakpoint_delete",
				"Delete an absolute software breakpoint.", Debugger, "Debugger", ToolCallAvailability::Admin,
				ExecuteDebuggerTool, schema::String("binaryView", true), schema::NonEmptyString("address", true));
		}  // namespace debugger_tools

#undef BINJAD_ANALYSIS_TOOL
	}  // namespace

	FoundationResult ExecuteOpenItemTool(const ToolCallContext& context)
	{
		return file_tools::OpenItemOpen(context);
	}

	void RegisterCoreSessionTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<session_tools::AnalysisSessionCreateTool>());
		tools.emplace_back(std::make_unique<session_tools::AnalysisSessionCloseTool>());
		tools.emplace_back(std::make_unique<session_tools::AnalysisSessionListTool>());
		tools.emplace_back(std::make_unique<session_tools::AnalysisSessionInfoTool>());
		tools.emplace_back(std::make_unique<session_tools::ComputeStatusTool>());
	}

	void RegisterCoreFileTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<file_tools::OpenItemOpenTool>());
		tools.emplace_back(std::make_unique<file_tools::OpenItemListTool>());
		tools.emplace_back(std::make_unique<file_tools::OpenItemCloseTool>());
		tools.emplace_back(std::make_unique<file_tools::BinaryViewListTool>());
		tools.emplace_back(std::make_unique<file_tools::BinaryViewLoadSettingsTool>());
		tools.emplace_back(std::make_unique<file_tools::BinaryViewOpenTool>());
		tools.emplace_back(std::make_unique<file_tools::BinaryViewSaveTool>());
		tools.emplace_back(std::make_unique<file_tools::BinaryViewSaveAsyncTool>());
	}

	void RegisterCoreAnalysisTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<core_analysis_tools::AnalysisStatusTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::AnalysisUpdateTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::AnalysisUpdateAndWaitTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::AnalysisUpdateAsyncTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::AnalysisAbortTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::FunctionListTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::FunctionInfoTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::FunctionDisassemblyTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::FunctionDecompileTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::StringListTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::StringAtTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::SymbolListTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::SymbolListAtTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::MemoryReadTool>());
		tools.emplace_back(std::make_unique<core_analysis_tools::DataAtTool>());
	}

	void RegisterCoreJobTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<job_tools::JobListTool>());
		tools.emplace_back(std::make_unique<job_tools::JobInfoTool>());
		tools.emplace_back(std::make_unique<job_tools::JobResultTool>());
		tools.emplace_back(std::make_unique<job_tools::JobCancelTool>());
	}

	void RegisterFunctionAnalysisTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<function_tools::FunctionCallersTool>());
		tools.emplace_back(std::make_unique<function_tools::FunctionCalleesTool>());
		tools.emplace_back(std::make_unique<function_tools::FunctionIlTool>());
		tools.emplace_back(std::make_unique<function_tools::FunctionStackLayoutTool>());
		tools.emplace_back(std::make_unique<function_tools::FunctionXrefsFromTool>());
		tools.emplace_back(std::make_unique<function_tools::FunctionXrefsToTool>());
	}

	void RegisterBinaryDataTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<binary_data_tools::ImportListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::ExportListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::EntryPointListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::SectionListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::SegmentListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::DataVariableListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::RelocationListTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::DataXrefsFromTool>());
		tools.emplace_back(std::make_unique<binary_data_tools::DataXrefsToTool>());
	}

	void RegisterSearchTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<search_tools::CommentListTool>());
		tools.emplace_back(std::make_unique<search_tools::CommentSearchTool>());
		tools.emplace_back(std::make_unique<search_tools::MemorySearchTool>());
		tools.emplace_back(std::make_unique<search_tools::InstructionSearchTool>());
		tools.emplace_back(std::make_unique<search_tools::IlSearchTool>());
		tools.emplace_back(std::make_unique<search_tools::ConstantSearchTool>());
		tools.emplace_back(std::make_unique<search_tools::ProjectAnalysisSearchTool>());
	}

	void RegisterTypeTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<type_tools::FunctionPrototypeSetTool>());
		tools.emplace_back(std::make_unique<type_tools::CallingConventionSetTool>());
		tools.emplace_back(std::make_unique<type_tools::CallingConventionListTool>());
		tools.emplace_back(std::make_unique<type_tools::VariableListTool>());
		tools.emplace_back(std::make_unique<type_tools::VariableRenameTool>());
		tools.emplace_back(std::make_unique<type_tools::VariableSetTypeTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeListTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeInfoTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeParseTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeDefineTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeStructCreateTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeStructModifyTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeUnionCreateTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeUnionModifyTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeEnumCreateTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeEnumModifyTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeDeleteTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeRenameTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeXrefsFromTool>());
		tools.emplace_back(std::make_unique<type_tools::TypeXrefsToTool>());
	}

	void RegisterAnnotationTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<annotation_tools::CommentGetTool>());
		tools.emplace_back(std::make_unique<annotation_tools::CommentSetTool>());
		tools.emplace_back(std::make_unique<annotation_tools::CommentDeleteTool>());
		tools.emplace_back(std::make_unique<annotation_tools::SymbolDefineTool>());
		tools.emplace_back(std::make_unique<annotation_tools::SymbolRenameTool>());
		tools.emplace_back(std::make_unique<annotation_tools::SymbolUndefineTool>());
		tools.emplace_back(std::make_unique<annotation_tools::BookmarkCreateTool>());
		tools.emplace_back(std::make_unique<annotation_tools::BookmarkListTool>());
		tools.emplace_back(std::make_unique<annotation_tools::BookmarkDeleteTool>());
		tools.emplace_back(std::make_unique<annotation_tools::TagCreateTool>());
		tools.emplace_back(std::make_unique<annotation_tools::TagListTool>());
		tools.emplace_back(std::make_unique<annotation_tools::TagDeleteTool>());
		tools.emplace_back(std::make_unique<annotation_tools::MetadataGetTool>());
		tools.emplace_back(std::make_unique<annotation_tools::MetadataSetTool>());
		tools.emplace_back(std::make_unique<annotation_tools::MetadataDeleteTool>());
	}

	void RegisterBinaryEditingTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<editing_tools::FunctionCreateTool>());
		tools.emplace_back(std::make_unique<editing_tools::FunctionDeleteTool>());
		tools.emplace_back(std::make_unique<editing_tools::EntryPointAddTool>());
		tools.emplace_back(std::make_unique<editing_tools::DataVariableDefineTool>());
		tools.emplace_back(std::make_unique<editing_tools::DataVariableUndefineTool>());
		tools.emplace_back(std::make_unique<editing_tools::SectionCreateTool>());
		tools.emplace_back(std::make_unique<editing_tools::SectionDeleteTool>());
		tools.emplace_back(std::make_unique<editing_tools::SectionModifyTool>());
		tools.emplace_back(std::make_unique<editing_tools::SegmentCreateTool>());
		tools.emplace_back(std::make_unique<editing_tools::SegmentModifyTool>());
		tools.emplace_back(std::make_unique<editing_tools::SegmentDeleteTool>());
		tools.emplace_back(std::make_unique<editing_tools::BinaryViewRebaseTool>());
		tools.emplace_back(std::make_unique<editing_tools::MemoryMapPreviewTool>());
		tools.emplace_back(std::make_unique<editing_tools::StringDefineTool>());
		tools.emplace_back(std::make_unique<editing_tools::StringUndefineTool>());
	}

	void RegisterHistoryTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<history_tools::TransactionBeginTool>());
		tools.emplace_back(std::make_unique<history_tools::TransactionCommitTool>());
		tools.emplace_back(std::make_unique<history_tools::TransactionRollbackTool>());
		tools.emplace_back(std::make_unique<history_tools::UndoTool>());
		tools.emplace_back(std::make_unique<history_tools::RedoTool>());
	}

	void RegisterDebuggerTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerAdapterListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStatusTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerConfigureTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerLaunchTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerConnectTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerAttachTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerGoTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerPauseTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepIntoTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepOverTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepReturnTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerRestartTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerQuitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerDetachTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerLaunchAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerConnectAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerAttachAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerGoAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerPauseAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepIntoAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepOverAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerStepReturnAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerRestartAndWaitTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerProcessListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerThreadListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerRegisterListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerModuleListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerMemoryRegionListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerBreakpointListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerFrameListTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerThreadSetTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerRegisterSetTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerMemoryReadTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerMemoryWriteTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerBreakpointAddTool>());
		tools.emplace_back(std::make_unique<debugger_tools::DebuggerBreakpointDeleteTool>());
	}
}  // namespace binjad::mcp
