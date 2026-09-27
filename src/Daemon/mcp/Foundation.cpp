#include "binjad/mcp/Foundation.hpp"

#include "ToolCall.hpp"

#include "binjad/overseer/FileChildCoordinator.hpp"
#include "binjad/overseer/AnalysisScheduler.hpp"
#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/platform/Cpu.hpp"
#include "binjad/platform/Paths.hpp"
#include "binjad/project/LocalProjectRegistry.hpp"
#include "binjad/session/OpenItemRegistry.hpp"
#include "binjad/session/JobRegistry.hpp"
#include "binjad/upload/UploadRegistry.hpp"

#include <rapidjsonwrapper.h>
#include <binaryninjacore.h>

#include <algorithm>
#include <chrono>
#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string_view>
#include <tuple>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::mcp {
	namespace {
		using rapidjson::Document;
		using rapidjson::StringBuffer;
		using rapidjson::Value;
		using rapidjson::Writer;


		template <typename OutputStream>
		void WriteId(Writer<OutputStream>& writer, const RequestId& id)
		{
			std::visit(
				[&](const auto& value) {
					using T = std::decay_t<decltype(value)>;
					if constexpr (std::is_same_v<T, std::string>)
						writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
					else if constexpr (std::is_same_v<T, std::int64_t>)
						writer.Int64(value);
					else
						writer.Uint64(value);
				},
				id);
		}

		template <typename WriteResult>
		std::string Response(const ValidatedRequest& request, WriteResult writeResult)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("jsonrpc");
			writer.String("2.0");
			writer.Key("id");
			WriteId(writer, *request.id);
			writer.Key("result");
			writer.StartObject();
			if (IsModern(request.version))
			{
				writer.Key("resultType");
				writer.String("complete");
			}
			writeResult(writer);
			writer.EndObject();
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

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

		std::string_view SourceKindName(session::OpenItemSourceKind kind)
		{
			switch (kind)
			{
			case session::OpenItemSourceKind::ArbitraryPath:
				return "path";
			case session::OpenItemSourceKind::LocalProject:
				return "local_project";
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
			writer.String(view.analysisSession.data(), static_cast<rapidjson::SizeType>(view.analysisSession.size()));
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
			writer.String(item.analysisSession.data(), static_cast<rapidjson::SizeType>(item.analysisSession.size()));
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
				if (item.source.ends_with(".bndb"))
					writer.String(
						"Call bn_binary_view_open on the recommended:true binaryView with analyze:false to reuse saved "
						"analysis.");
				else
					writer.String(
						"Call bn_binary_view_open on the recommended:true binaryView before using BinaryView tools.");
			}
			writer.EndObject();
		}


		template <typename Record, typename WriteRecord>
		std::string PaginatedJson(std::string_view key, const std::vector<Record>& records, std::size_t offset,
			std::size_t limit, WriteRecord writeRecord)
		{
			offset = std::min(offset, records.size());
			const auto count = std::min(limit, records.size() - offset);
			const auto end = offset + count;
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
			writer.StartArray();
			for (std::size_t index = offset; index < end; ++index)
				writeRecord(writer, records[index]);
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(count);
			writer.Key("total");
			writer.Uint64(records.size());
			writer.Key("nextOffset");
			if (end < records.size())
				writer.Uint64(end);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(end < records.size());
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		std::string OpenItemsJson(
			const std::vector<session::OpenItemRecord>& records, std::size_t offset, std::size_t limit)
		{
			return PaginatedJson("openItems", records, offset, limit, [](auto& writer, const auto& record) {
				WriteOpenItem(writer, record);
			});
		}


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
				writer.String(job.progress->phase.data(), static_cast<rapidjson::SizeType>(job.progress->phase.size()));
				writer.Key("completed");
				writer.Uint64(job.progress->completed);
				writer.Key("total");
				writer.Uint64(job.progress->total);
				if (!job.progress->message.empty())
				{
					writer.Key("message");
					writer.String(
						job.progress->message.data(), static_cast<rapidjson::SizeType>(job.progress->message.size()));
				}
				writer.EndObject();
			}
			if (job.state == session::JobState::Queued || job.state == session::JobState::Running)
			{
				writer.Key("pollAfterMilliseconds");
				writer.Uint(10000);
				writer.Key("nextAction");
				writer.String(
					"Call bn_job_info no more than every 10 seconds; when terminal, call bn_job_result exactly once. "
					"Avoid polling bn_analysis_status for this operation.");
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


		std::string JobsJson(const std::vector<session::JobRecord>& jobs, std::size_t offset, std::size_t limit)
		{
			return PaginatedJson("jobs", jobs, offset, limit, [](auto& writer, const auto& record) {
				WriteJob(writer, record, false);
			});
		}

		template <typename WriterType>
		void WriteProject(WriterType& writer, const project::LocalProjectRecord& project)
		{
			writer.StartObject();
			writer.Key("project");
			writer.String(project.reference.data(), static_cast<rapidjson::SizeType>(project.reference.size()));
			writer.Key("name");
			writer.String(project.name.data(), static_cast<rapidjson::SizeType>(project.name.size()));
			writer.Key("description");
			writer.String(project.description.data(), static_cast<rapidjson::SizeType>(project.description.size()));
			writer.EndObject();
		}


		std::string ProjectsJson(
			const std::vector<project::LocalProjectRecord>& projects, std::size_t offset, std::size_t limit)
		{
			return PaginatedJson("projects", projects, offset, limit, [](auto& writer, const auto& project) {
				WriteProject(writer, project);
			});
		}

		std::string SessionsJson(
			const std::vector<session::AnalysisSessionRecord>& sessions, std::size_t offset, std::size_t limit)
		{
			const auto end = std::min(sessions.size(), offset + std::min(limit, sessions.size() - offset));
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

		struct ComputeJsonResult
		{
			std::string json;
			std::string error;
		};

		ComputeJsonResult ComputeJson(const Config& config, const overseer::AnalysisScheduler* scheduler = nullptr)
		{
			if (scheduler)
			{
				const auto status = scheduler->Status();
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("logicalCpuCount");
				writer.Uint64(status.logicalCpuCount);
				writer.Key("configuredPercentage");
				writer.Uint(config.cpu.percentage);
				writer.Key("workerBudget");
				writer.Uint64(status.workerBudget);
				writer.Key("allocatedWorkers");
				writer.Uint64(status.allocatedWorkers);
				writer.Key("activeAnalyses");
				writer.Uint64(status.activeAnalyses);
				writer.Key("queuedAnalyses");
				writer.Uint64(status.queuedAnalyses);
				writer.Key("fairness");
				const auto fairness = FairnessName(config.cpu.fairness);
				writer.String(fairness.data(), static_cast<rapidjson::SizeType>(fairness.size()));
				writer.EndObject();
				return {{buffer.GetString(), buffer.GetSize()}, {}};
			}
			const auto capacity = platform::ActiveLogicalCpuCount();
			if (!capacity.logicalCpuCount)
				return {{}, capacity.error};
			const auto budget = std::max<std::size_t>(1, *capacity.logicalCpuCount * config.cpu.percentage / 100);
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("logicalCpuCount");
			writer.Uint64(*capacity.logicalCpuCount);
			writer.Key("configuredPercentage");
			writer.Uint(config.cpu.percentage);
			writer.Key("workerBudget");
			writer.Uint64(budget);
			writer.Key("allocatedWorkers");
			writer.Uint(0);
			writer.Key("activeAnalyses");
			writer.Uint(0);
			writer.Key("queuedAnalyses");
			writer.Uint(0);
			writer.Key("fairness");
			const auto fairness = FairnessName(config.cpu.fairness);
			writer.String(fairness.data(), static_cast<rapidjson::SizeType>(fairness.size()));
			writer.EndObject();
			return {{buffer.GetString(), buffer.GetSize()}, {}};
		}


		template <typename WriterType>
		void WriteServerMeta(WriterType& writer, std::string_view serverVersion)
		{
			writer.Key("_meta");
			writer.StartObject();
			writer.Key("io.modelcontextprotocol/serverInfo");
			writer.StartObject();
			writer.Key("name");
			writer.String("binjad");
			writer.Key("version");
			writer.String(serverVersion.data(), static_cast<rapidjson::SizeType>(serverVersion.size()));
			writer.EndObject();
			writer.EndObject();
		}

		std::string ToolResult(
			const ValidatedRequest& request, std::string_view structured, bool isError, std::string_view serverVersion)
		{
			return Response(request, [&](auto& writer) {
				writer.Key("content");
				writer.StartArray();
				writer.StartObject();
				writer.Key("type");
				writer.String("text");
				writer.Key("text");
				writer.String(structured.data(), static_cast<rapidjson::SizeType>(structured.size()));
				writer.EndObject();
				writer.EndArray();
				writer.Key("structuredContent");
				writer.RawValue(structured.data(), structured.size(), rapidjson::kObjectType);
				writer.Key("isError");
				writer.Bool(isError);
				if (IsModern(request.version))
					WriteServerMeta(writer, serverVersion);
			});
		}

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

		template <typename WriterType>
		void WriteTool(
			WriterType& writer, std::string_view name, std::string_view description, std::string_view inputSchema)
		{
			writer.StartObject();
			writer.Key("name");
			writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
			writer.Key("description");
			writer.String(description.data(), static_cast<rapidjson::SizeType>(description.size()));
			writer.Key("inputSchema");
			writer.RawValue(inputSchema.data(), inputSchema.size(), rapidjson::kObjectType);
			writer.EndObject();
		}

		using ToolPack = ToolCallCategory;

		ToolPack ToolPackFor(std::string_view name)
		{
			const auto* tool = FindToolCall(name);
			return tool ? tool->Category() : ToolPack::Core;
		}

		std::string_view ToolPackName(ToolPack pack)
		{
			return ToolCallCategoryName(pack);
		}


		std::string RegisteredToolsResponse(const ValidatedRequest& request, std::string_view serverVersion,
			bool localProjects, const ToolConfig& tools, bool adminAllowed, bool arbitraryLocalProjects,
			bool projectRegistration)
		{
			const auto available = [&](const ToolCall& tool) {
				if (!ToolCallAdvertised(tool, tools.discoveryMode))
					return false;
				if (!ToolCallCategoryEnabled(tool.Category(), tools))
					return false;
				const auto requirements = tool.Availability();
				if (HasAvailability(requirements, ToolCallAvailability::ModernProtocol) && !IsModern(request.version))
					return false;
				if (HasAvailability(requirements, ToolCallAvailability::LocalMode) && !localProjects)
					return false;
				if (HasAvailability(requirements, ToolCallAvailability::Admin) && !adminAllowed)
					return false;
				if (HasAvailability(requirements, ToolCallAvailability::ArbitraryPaths) && !arbitraryLocalProjects)
					return false;
				if (HasAvailability(requirements, ToolCallAvailability::ProjectRegistration) && !projectRegistration)
					return false;
				return true;
			};

			return Response(request, [&](auto& writer) {
				writer.Key("tools");
				writer.StartArray();
				for (const auto& tool : RegisteredToolCalls())
				{
					if (!available(*tool))
						continue;
					WriteTool(writer, tool->Name(), tool->Description(), tool->InputSchema());
				}
				writer.EndArray();
				if (IsModern(request.version))
					WriteServerMeta(writer, serverVersion);
			});
		}


		std::string ToolsResponse(const ValidatedRequest& request, std::string_view serverVersion, bool localProjects,
			const ToolConfig& tools, bool adminAllowed, bool arbitraryLocalProjects, bool projectRegistration)
		{
			return RegisteredToolsResponse(request, serverVersion, localProjects, tools, adminAllowed,
				arbitraryLocalProjects, projectRegistration);
		}

		std::string ResourcesResponse(
			const ValidatedRequest& request, std::string_view serverVersion, bool localProjects)
		{
			return Response(request, [&](auto& writer) {
				writer.Key("resources");
				writer.StartArray();
				writer.StartObject();
				writer.Key("uri");
				writer.String("binjad://docs");
				writer.Key("name");
				writer.String("Quick start");
				writer.Key("description");
				writer.String("Minimal binjad lifecycle and argument rules.");
				writer.Key("mimeType");
				writer.String("text/markdown");
				writer.EndObject();
				for (const auto& [uri, name, description] :
					{std::tuple {"binjad://compute", "Compute status", "Current analysis capacity and allocation."},
						std::tuple {"binjad://analysis-sessions", "Analysis sessions",
							"Analysis sessions owned by this bearer token."},
						std::tuple {"binjad://open-items", "Open items",
							"Open files and BinaryView candidates owned by this bearer token."},
						std::tuple {"binjad://jobs", "Detached jobs", "Detached jobs owned by this bearer token."}})
				{
					writer.StartObject();
					writer.Key("uri");
					writer.String(uri);
					writer.Key("name");
					writer.String(name);
					writer.Key("description");
					writer.String(description);
					writer.Key("mimeType");
					writer.String("application/json");
					writer.EndObject();
				}
				if (localProjects)
				{
					writer.StartObject();
					writer.Key("uri");
					writer.String("binjad://local-projects");
					writer.Key("name");
					writer.String("Local projects");
					writer.Key("description");
					writer.String("Shared local Binary Ninja project catalog.");
					writer.Key("mimeType");
					writer.String("application/json");
					writer.EndObject();
				}
				writer.EndArray();
				if (IsModern(request.version))
					WriteServerMeta(writer, serverVersion);
			});
		}

		std::string TemplatesResponse(const ValidatedRequest& request, std::string_view serverVersion)
		{
			return Response(request, [&](auto& writer) {
				writer.Key("resourceTemplates");
				writer.StartArray();
				writer.StartObject();
				writer.Key("uriTemplate");
				writer.String("binjad://analysis-sessions/{analysisSession}");
				writer.Key("name");
				writer.String("Analysis session");
				writer.Key("description");
				writer.String("One analysis session owned by this bearer token.");
				writer.Key("mimeType");
				writer.String("application/json");
				writer.EndObject();
				writer.EndArray();
				if (IsModern(request.version))
					WriteServerMeta(writer, serverVersion);
			});
		}

		std::string ResourceResponse(const ValidatedRequest& request, std::string_view text,
			std::string_view serverVersion, std::string_view mimeType = "application/json")
		{
			return Response(request, [&](auto& writer) {
				writer.Key("contents");
				writer.StartArray();
				writer.StartObject();
				writer.Key("uri");
				writer.String(request.uri.data(), static_cast<rapidjson::SizeType>(request.uri.size()));
				writer.Key("mimeType");
				writer.String(mimeType.data(), static_cast<rapidjson::SizeType>(mimeType.size()));
				writer.Key("text");
				writer.String(text.data(), static_cast<rapidjson::SizeType>(text.size()));
				writer.EndObject();
				writer.EndArray();
				if (IsModern(request.version))
					WriteServerMeta(writer, serverVersion);
			});
		}

		const Value* Arguments(const ValidatedRequest& request, Document& params, std::string& error)
		{
			try
			{
				params.Parse(request.paramsJson.data(), request.paramsJson.size());
			}
			catch (const ParseException&)
			{
				error = "validated tool params are unavailable";
				return nullptr;
			}
			if (params.HasParseError() || !params.IsObject())
			{
				error = "validated tool params are unavailable";
				return nullptr;
			}
			const auto arguments = params.FindMember("arguments");
			if (arguments == params.MemberEnd())
			{
				static const Value empty(rapidjson::kObjectType);
				return &empty;
			}
			return &arguments->value;
		}


		// Shared by forwarded file-child tools and documentation serialization.
		std::optional<std::string> RequiredStringArgument(const Value& arguments, const char* name, std::string& error)
		{
			const auto member = arguments.FindMember(name);
			if (member == arguments.MemberEnd() || !member->value.IsString() || member->value.GetStringLength() == 0)
			{
				error = std::string(name) + " must be a non-empty string";
				return std::nullopt;
			}
			return std::string(member->value.GetString(), member->value.GetStringLength());
		}

		std::string SerializeValue(const Value& value)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			value.Accept(writer);
			return {buffer.GetString(), buffer.GetSize()};
		}

		constexpr std::string_view kQuickStartDocs =
			"Tool discovery: when bn_tools is advertised, use categories, list, and describe before calling an omitted "
			"tool through bn_tools with operation=call. Only the minimal setup and lifecycle surface remains direct.\n"
			"Flow: project_list -> file_list -> project_file_open -> binary_view_open(recommended) -> "
			"analysis_update_and_wait -> query/mutate -> binary_view_save(if changed) -> open_item_close.\n"
			"Uploads: bn_upload_get_url returns a one-time PUT capability and explicit authorization requirements; "
			"commit to a project-relative folder path; import-only commits return JSON and successful retries return "
			"the original result; use bn_upload_list/cancel for cleanup. Local administrators should prefer "
			"bn_local_project_file_import_batch for explicit files already on the server, or "
			"bn_local_project_directory_import to preserve a directory tree; resume a partial directory import with "
			"the returned lastCompleted value as startAfter.\n"
			"Project files: project-relative paths are unique and select files together with project; imports accept "
			"an initial description; bn_local_project_file_list returns descriptions; bn_local_project_file_update "
			"sets or replaces one, and an empty description string clears it.\n"
			"Project documents: use bn_project_text_read for line/query pagination over UTF-8 text and Markdown; use "
			"bn_project_json_read with RFC 6901 pointers to page object keys or array indexes without expanding "
			"unrelated subtrees. These tools read project files directly without a BinaryView.\n"
			"Project writes: if a mutation says the project may be open or read-only, ask the user to close that "
			"project in the Binary Ninja GUI, then retry. Failed upload commits remain staged and may be retried with "
			"the same id without re-uploading.\n"
			"Project recovery: bn_local_project_root_list returns private root indexes. "
			"bn_local_project_relocate copies a closed outside-root project beneath one selected root, verifies its "
			"durable ID, retains the old source on disk, and removes the old registration.\n"
			"Headers: bn_binary_header_info summarizes Mach-O, ELF, or PE identity and security fields; use "
			"bn_linked_library_list for dependencies and the format-specific Header Parsing lists for low-level rows.\n"
			"Functions: FunctionSymbol is annotation only; use bn_entry_point_add for an analysis root and "
			"bn_function_create for a persistent user function, then update analysis and save the BinaryView.\n"
			"URLs: bn_url_open_item links owned arbitrary-path provenance. For a local-project item, call "
			"bn_binary_view_save after the latest changes, then call bn_url_project_file with "
			"updated_bndb_has_been_saved:true; its URL opens the committed project backing file, never unsaved child "
			"state. "
			"Use bn_url_remote_file for an absolute http, https, or file URL, and bn_url_navigate for a Binary Ninja "
			"report-relative expression link. These tools percent-encode expr values.\n"
			"Raw firmware: open only discovers candidates; select Mapped rather than Raw, call "
			"bn_binary_view_load_settings, then pass fully qualified loader.platform, loader.imageBase, and "
			"loader.entryPointOffset options to bn_binary_view_open. Thumb vector values have bit zero set, but Mapped "
			"entry/function addresses use the aligned code address. loader.segments and loader.sections are serialized "
			"JSON strings.\n"
			"Rules: every view tool needs binaryView; query first, use small limits, and continue with nextOffset; "
			"async job results are one-shot; direct C types use definition, while source+type selects a parsed "
			"declaration; after function/variable mutation follow nextAction; set prototypes before variable names; "
			"reopen BNDBs with reuseDatabase:true and analyze:false; close only items created by your workflow because "
			"token-wide lists may include concurrent clients; legacy analysis sessions are transport-managed.";

		ValidatedRequest DocumentationRequest(
			ProtocolVersion version, std::uint64_t id, std::string method, std::string uri = {})
		{
			ValidatedRequest request;
			request.version = version;
			request.id = id;
			request.method = std::move(method);
			request.uri = std::move(uri);
			request.paramsJson = "{}";
			return request;
		}

		std::string_view ToolCategory(std::string_view name)
		{
			const auto* tool = FindToolCall(name);
			return tool ? tool->DocumentationCategory() : "Other";
		}

		template <typename WriterType>
		void WriteFailureIds(WriterType& writer, std::string_view name, const Value& schema)
		{
			writer.StartArray();
			writer.String("invalid_arguments");
			writer.String("analysis_session_unavailable");
			const auto properties = schema.FindMember("properties");
			const auto has = [&](const char* property) {
				return properties != schema.MemberEnd() && properties->value.IsObject()
					&& properties->value.HasMember(property);
			};
			if (has("binaryView") || has("primary"))
				writer.String("binary_view_unavailable");
			if (has("openItem"))
				writer.String("open_item_unavailable");
			if (has("project") || name.find("project") != std::string_view::npos)
				writer.String("project_unavailable");
			if (has("job") || name.starts_with("bn_job"))
				writer.String("job_unavailable");
			if (has("function"))
				writer.String("function_unavailable");
			if (has("type"))
				writer.String("type_unavailable");
			if (has("address"))
				writer.String("address_unavailable");
			if (name.starts_with("bn_kernel_cache") || name.starts_with("bn_shared_cache"))
				writer.String("plugin_state");
			if (name.starts_with("bn_debugger"))
				writer.String("debugger_state");
			if (name.starts_with("bn_diff"))
				writer.String("diff_state");
			if (name.find("save") != std::string_view::npos || name.find("upload") != std::string_view::npos
				|| name.find("project") != std::string_view::npos)
				writer.String("persistence_failure");
			writer.String("service_failure");
			writer.EndArray();
		}

		template <typename WriterType>
		void WriteFailureContracts(WriterType& writer)
		{
			writer.StartObject();
			const auto contract = [&](const char* id, const char* when, const char* surface) {
				writer.Key(id);
				writer.StartObject();
				writer.Key("when");
				writer.String(when);
				writer.Key("surface");
				writer.String(surface);
				writer.EndObject();
			};
			contract("invalid_arguments",
				"A required argument is absent, has the wrong type or range, or an unknown argument is supplied.",
				"JSON-RPC -32602; HTTP 400 for modern MCP and HTTP 200 for legacy MCP.");
			contract("analysis_session_unavailable",
				"The analysis session is unknown, expired, belongs to another token, or is not valid for this protocol "
				"flow.",
				"JSON-RPC error, normally session not found; no tool result is produced.");
			contract("binary_view_unavailable",
				"The BinaryView reference is unknown, belongs to another session, is not materialized, or its file "
				"child failed.",
				"Tool result with isError:true and a structured error string.");
			contract("open_item_unavailable",
				"The open-item reference is unknown, belongs to another token/session, is busy, or requires discard "
				"acknowledgement.",
				"Tool result with isError:true and a structured error string.");
			contract("project_unavailable",
				"The project/file/folder is unknown, unauthorized, locked by another Binary Ninja process, read-only, "
				"or unavailable in the active project mode.",
				"Tool result with isError:true; lock failures instruct the caller to ask the user to close the GUI "
				"project and retry.");
			contract("job_unavailable",
				"The job is unknown, owned by another token, not terminal, already consumed, or cannot be cancelled.",
				"Tool result with isError:true and a structured error string.");
			contract("function_unavailable",
				"The function selector is absent or ambiguous, analysis has not created it, or the requested "
				"architecture/view does not contain it.",
				"Tool result with isError:true; FunctionSymbol-only failures direct callers to bn_function_create.");
			contract("type_unavailable",
				"A named type cannot be found, is the wrong class, already exists for a create operation, or C parsing "
				"fails.",
				"Tool result with isError:true and parse or selection details.");
			contract("address_unavailable",
				"The address expression is invalid, unmapped, outside loaded cache content, or unsuitable for the "
				"requested operation.",
				"Tool result with isError:true and contextual load/analyze guidance where available.");
			contract("plugin_state",
				"The optional plugin surface is disabled, unavailable, the view is incompatible, or required cache "
				"content is not loaded.",
				"Unavailable tools are omitted from discovery; runtime state failures are isError:true tool results.");
			contract("debugger_state",
				"The caller is not an admin, debuggercore is unavailable, target configuration is incomplete, or the "
				"target state rejects the operation.",
				"The surface is omitted for non-admins; runtime failures are isError:true tool results or failed "
				"jobs.");
			contract("diff_state",
				"Google BinDiff is unavailable, a secondary is not a valid BNDB, the comparison is running, absent, "
				"cancelled, or belongs to another explicit pair, or a requested match is absent.",
				"Run failures are terminal job results; cached query and mutation failures are isError:true tool "
				"results.");
			contract("persistence_failure",
				"Storage is locked, read-only, collides with an unrelated destination, upload state is invalid, or a "
				"a persistence operation fails.",
				"Tool result or terminal job with structured error/conflict data; documented retryable uploads retain "
				"their staged id.");
			contract("service_failure",
				"A required daemon service/child is unavailable or an unexpected internal operation fails.",
				"JSON-RPC -32603 when no tool result can be formed; otherwise an isError:true tool result or failed "
				"job.");
			writer.EndObject();
		}
	}  // namespace

	FoundationResult ExecuteForwardedAnalysisTool(const ToolCallContext& context)
	{
		return ExecuteForwardedAnalysisTool(context, context.request.name);
	}

	FoundationResult ExecuteForwardedAnalysisTool(const ToolCallContext& context, std::string_view commandName)
	{
		std::string error;
		const auto binaryView = RequiredStringArgument(context.arguments, "binaryView", error);
		if (!binaryView)
			return {true, IsModern(context.request.version) ? 400 : 200, {},
				ProtocolError {-32602, IsModern(context.request.version) ? 400 : 200, error, context.request.id, {}}};
		if (!context.currentSession || !context.fileCoordinator)
			return {true, 200,
				ToolResult(context.request, ErrorJson("analysis session and file-child service are required"), true,
					context.serverVersion),
				{}};

		const auto result = context.fileCoordinator->ExecuteAnalysisTool(context.principal.id,
			context.currentSession->reference, *binaryView, commandName, SerializeValue(context.arguments));
		if (!result.value)
			return {true, 200, ToolResult(context.request, ErrorJson(result.error), true, context.serverVersion), {}};
		return {true, 200, ToolResult(context.request, *result.value, false, context.serverVersion), {}};
	}

	FoundationResult ToolCallSuccess(const ToolCallContext& context, std::string_view structured, bool isError)
	{
		return {true, 200, ToolResult(context.request, structured, isError, context.serverVersion), {}};
	}

	FoundationResult ToolCallInvalidArguments(const ToolCallContext& context, std::string message)
	{
		const auto status = IsModern(context.request.version) ? 400 : 200;
		return {true, status, {}, ProtocolError {-32602, status, std::move(message), context.request.id, {}}};
	}

	Foundation::Foundation(Config config, session::AnalysisSessionRegistry& sessions, std::string serverVersion,
		session::OpenItemRegistry* openItems, overseer::FileChildCoordinator* fileCoordinator,
		session::JobRegistry* jobs, project::LocalProjectRegistry* projects,
		overseer::ProjectChildCoordinator* projectCoordinator, overseer::AnalysisScheduler* scheduler,
		upload::UploadRegistry* uploads) :
		config_(std::move(config)), toolConfig_(config_.tools), sessions_(sessions),
		serverVersion_(std::move(serverVersion)), openItems_(openItems), fileCoordinator_(fileCoordinator), jobs_(jobs),
		projects_(projects), projectCoordinator_(projectCoordinator), scheduler_(scheduler), uploads_(uploads)
	{}

	void Foundation::SetToolConfig(ToolConfig config)
	{
		std::lock_guard lock(toolConfigMutex_);
		toolConfig_ = std::move(config);
	}

	Config Foundation::EffectiveConfig() const
	{
		Config result = config_;
		std::lock_guard lock(toolConfigMutex_);
		result.tools = toolConfig_;
		return result;
	}

	std::string Foundation::ToolDocumentation(ProtocolVersion version, security::TokenRole role) const
	{
		const auto config = EffectiveConfig();
		const auto request = DocumentationRequest(version, 1, "tools/list");
		const auto advertisedPayload = ToolsResponse(request, serverVersion_, true, config.tools,
			role == security::TokenRole::Admin, config.projects.allowArbitraryPaths,
			config.projects.allowProjectRegistration);
		auto capabilityTools = config.tools;
		capabilityTools.discoveryMode = ToolDiscoveryMode::Full;
		const auto currentPayload = ToolsResponse(request, serverVersion_, true, capabilityTools,
			role == security::TokenRole::Admin, config.projects.allowArbitraryPaths,
			config.projects.allowProjectRegistration);
		ToolConfig allTools;
		const auto localPayload = ToolsResponse(request, serverVersion_, true, allTools, true, true, true);
		allTools.discoveryMode = ToolDiscoveryMode::Brokered;
		const auto brokerPayload = ToolsResponse(request, serverVersion_, true, allTools, true, true, true);
		allTools.discoveryMode = ToolDiscoveryMode::Full;
		const auto modernRequest = DocumentationRequest(ProtocolVersion::V2026_07_28, 1, "tools/list");
		const auto modernLocalPayload = ToolsResponse(modernRequest, serverVersion_, true, allTools, true, true, true);

		struct DocumentedTool
		{
			std::string name;
			std::string description;
			std::string schema;
			bool available = false;
		};
		std::vector<DocumentedTool> documentedTools;
		std::unordered_set<std::string> names;
		std::unordered_set<std::string> availableNames;
		std::unordered_set<std::string> advertisedNames;
		const auto collect = [&](const std::string& payload, bool available, bool advertised) {
			Document discovery;
			discovery.Parse(payload.data(), payload.size());
			if (discovery.HasParseError() || !discovery.IsObject() || !discovery.HasMember("result")
				|| !discovery["result"].IsObject() || !discovery["result"].HasMember("tools")
				|| !discovery["result"]["tools"].IsArray())
				return;
			for (const auto& tool : discovery["result"]["tools"].GetArray())
			{
				std::string name(tool["name"].GetString(), tool["name"].GetStringLength());
				if (available)
					availableNames.insert(name);
				if (advertised)
					advertisedNames.insert(name);
				if (!names.insert(name).second)
					continue;
				documentedTools.push_back({std::move(name),
					std::string(tool["description"].GetString(), tool["description"].GetStringLength()),
					SerializeValue(tool["inputSchema"]), available});
			}
		};
		collect(currentPayload, true, false);
		collect(advertisedPayload, config.tools.discoveryMode == ToolDiscoveryMode::Brokered, true);
		collect(localPayload, false, false);
		collect(brokerPayload, false, false);
		collect(modernLocalPayload, false, false);

		const auto unavailableReason = [&](std::string_view name) -> std::string {
			if (name == kToolBrokerName && config.tools.discoveryMode != ToolDiscoveryMode::Brokered)
				return "Requires tools.discovery_mode to be 'brokered'.";
			const auto* tool = FindToolCall(name);
			return tool ?
				tool->UnavailableReason(config, version, role) :
				"Not advertised for the selected protocol, role, mode, or running options.";
		};

		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("protocolVersion");
		const auto protocol = ToString(version);
		writer.String(protocol.data(), static_cast<rapidjson::SizeType>(protocol.size()));
		writer.Key("role");
		writer.String(role == security::TokenRole::Admin ? "admin" : "user");
		writer.Key("mode");
		writer.String("local");
		writer.Key("availableCount");
		writer.Uint64(availableNames.size());
		writer.Key("totalCount");
		writer.Uint64(documentedTools.size());
		writer.Key("failureContracts");
		WriteFailureContracts(writer);
		writer.Key("tools");
		writer.StartArray();
		for (const auto& tool : documentedTools)
		{
			Document schema;
			schema.Parse(tool.schema.data(), tool.schema.size());
			writer.StartObject();
			writer.Key("name");
			writer.String(tool.name.data(), static_cast<rapidjson::SizeType>(tool.name.size()));
			writer.Key("category");
			const auto category = ToolCategory(tool.name);
			writer.String(category.data(), static_cast<rapidjson::SizeType>(category.size()));
			writer.Key("pack");
			const auto pack = ToolPackName(ToolPackFor(tool.name));
			writer.String(pack.data(), static_cast<rapidjson::SizeType>(pack.size()));
			writer.Key("available");
			writer.Bool(availableNames.contains(tool.name));
			writer.Key("advertised");
			writer.Bool(advertisedNames.contains(tool.name));
			if (!availableNames.contains(tool.name))
			{
				writer.Key("availability");
				const auto reason = unavailableReason(tool.name);
				writer.String(reason.data(), static_cast<rapidjson::SizeType>(reason.size()));
			}
			writer.Key("description");
			writer.String(tool.description.data(), static_cast<rapidjson::SizeType>(tool.description.size()));
			writer.Key("inputSchema");
			schema.Accept(writer);
			writer.Key("failureModes");
			WriteFailureIds(writer, tool.name, schema);
			writer.EndObject();
		}
		writer.EndArray();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string Foundation::ContextDocumentation(
		ProtocolVersion version, security::TokenRole role, std::string_view clientName) const
	{
		const auto config = EffectiveConfig();
		const auto admin = role == security::TokenRole::Admin;
		const auto toolsRequest = DocumentationRequest(version, 1, "tools/list");
		const auto resourcesRequest = DocumentationRequest(version, 2, "resources/list");
		const auto templatesRequest = DocumentationRequest(version, 3, "resources/templates/list");
		const auto docsRequest = DocumentationRequest(version, 4, "resources/read", "binjad://docs");
		const auto tools = ToolsResponse(toolsRequest, serverVersion_, true, config.tools, admin,
			config.projects.allowArbitraryPaths, config.projects.allowProjectRegistration);
		const auto resources = ResourcesResponse(resourcesRequest, serverVersion_, true);
		const auto templates = TemplatesResponse(templatesRequest, serverVersion_);
		const auto docs = ResourceResponse(docsRequest, kQuickStartDocs, serverVersion_, "text/markdown");

		Document toolsDocument;
		toolsDocument.Parse(tools.data(), tools.size());
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("protocolVersion");
		const auto protocol = ToString(version);
		writer.String(protocol.data(), static_cast<rapidjson::SizeType>(protocol.size()));
		writer.Key("role");
		writer.String(admin ? "admin" : "user");
		writer.Key("mode");
		writer.String("local");
		writer.Key("runningOptions");
		writer.StartObject();
		writer.Key("toolDiscoveryMode");
		const auto discoveryMode = ToolDiscoveryModeName(config.tools.discoveryMode);
		writer.String(discoveryMode.data(), static_cast<rapidjson::SizeType>(discoveryMode.size()));
		writer.Key("allowArbitraryPaths");
		writer.Bool(config.projects.allowArbitraryPaths);
		writer.Key("allowProjectRegistration");
		writer.Bool(config.projects.allowProjectRegistration);
		writer.Key("tools");
		writer.StartObject();
		writer.Key("coreWorkflow");
		writer.Bool(true);
		writer.Key("projectManagement");
		writer.Bool(config.tools.projectManagement);
		writer.Key("functionAnalysis");
		writer.Bool(config.tools.functionAnalysis);
		writer.Key("binaryData");
		writer.Bool(config.tools.binaryData);
		writer.Key("search");
		writer.Bool(config.tools.search);
		writer.Key("types");
		writer.Bool(config.tools.types);
		writer.Key("annotations");
		writer.Bool(config.tools.annotations);
		writer.Key("binaryEditing");
		writer.Bool(config.tools.binaryEditing);
		writer.Key("history");
		writer.Bool(config.tools.history);
		writer.Key("headerParsing");
		writer.Bool(config.tools.headerParsing);
		writer.Key("urlGeneration");
		writer.Bool(config.tools.urlGeneration);
		writer.Key("diffing");
		writer.Bool(config.tools.diffing);
		writer.Key("kernelCache");
		writer.Bool(config.tools.kernelCache);
		writer.Key("sharedCache");
		writer.Bool(config.tools.sharedCache);
		writer.Key("debugger");
		writer.Bool(config.tools.debugger);
		writer.EndObject();
		writer.EndObject();
		writer.Key("mcpWire");
		writer.StartArray();
		const auto wire = [&](std::string_view method, const std::string& payload) {
			writer.StartObject();
			writer.Key("method");
			writer.String(method.data(), static_cast<rapidjson::SizeType>(method.size()));
			writer.Key("payload");
			writer.String(payload.data(), static_cast<rapidjson::SizeType>(payload.size()));
			writer.EndObject();
		};
		wire("tools/list", tools);
		wire("resources/list", resources);
		wire("resources/templates/list", templates);
		wire("resources/read binjad://docs", docs);
		writer.EndArray();
		writer.Key("openCodeProjection");
		writer.StartObject();
		writer.Key("boundary");
		writer.String(
			"OpenCode controls the final provider-specific model encoding. This projection applies its MCP namespace "
			"convention to the exact current binjad tool definitions; only mcpWire is byte-for-byte server output.");
		writer.Key("clientNamespace");
		writer.String(clientName.data(), static_cast<rapidjson::SizeType>(clientName.size()));
		writer.Key("tools");
		writer.StartArray();
		if (!toolsDocument.HasParseError() && toolsDocument.IsObject() && toolsDocument.HasMember("result")
			&& toolsDocument["result"].IsObject() && toolsDocument["result"].HasMember("tools")
			&& toolsDocument["result"]["tools"].IsArray())
		{
			for (const auto& tool : toolsDocument["result"]["tools"].GetArray())
			{
				const std::string qualified = std::string(clientName) + "_"
					+ std::string(tool["name"].GetString(), tool["name"].GetStringLength());
				writer.StartObject();
				writer.Key("name");
				writer.String(qualified.data(), static_cast<rapidjson::SizeType>(qualified.size()));
				writer.Key("description");
				tool["description"].Accept(writer);
				writer.Key("inputSchema");
				tool["inputSchema"].Accept(writer);
				writer.EndObject();
			}
		}
		writer.EndArray();
		writer.Key("resourceContext");
		writer.String(kQuickStartDocs.data(), static_cast<rapidjson::SizeType>(kQuickStartDocs.size()));
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	FoundationResult Foundation::Handle(const ValidatedRequest& request, const security::TokenRecord& principal,
		const std::optional<session::AnalysisSessionRecord>& currentSession,
		session::AnalysisSessionRegistry::Clock::time_point now, std::uint64_t unixNow, JobProgressCallback progress,
		AttachedJobCallback attached)
	{
		const auto config = EffectiveConfig();
		if (request.method == "tools/list")
			return {true, 200,
				ToolsResponse(request, serverVersion_, true, config.tools, principal.role == security::TokenRole::Admin,
					config.projects.allowArbitraryPaths, config.projects.allowProjectRegistration),
				{}};
		if (request.method == "resources/list")
			return {true, 200, ResourcesResponse(request, serverVersion_, true), {}};
		if (request.method == "resources/templates/list")
			return {true, 200, TemplatesResponse(request, serverVersion_), {}};
		if (request.method == "resources/read")
		{
			if (request.uri == "binjad://docs")
			{
				return {true, 200, ResourceResponse(request, kQuickStartDocs, serverVersion_, "text/markdown"), {}};
			}
			if (request.uri == "binjad://compute")
			{
				const auto compute = ComputeJson(config, scheduler_);
				if (!compute.error.empty())
					return {true, 500, {}, ProtocolError {-32603, 500, compute.error, request.id, {}}};
				return {true, 200, ResourceResponse(request, compute.json, serverVersion_), {}};
			}
			if (request.uri == "binjad://analysis-sessions")
			{
				const auto sessions = sessions_.List(principal.id, now);
				return {true, 200,
					ResourceResponse(request, SessionsJson(sessions, 0, sessions.size()), serverVersion_), {}};
			}
			if (request.uri == "binjad://jobs")
			{
				if (!jobs_)
					return {true, 500, {}, ProtocolError {-32603, 500, "job service is unavailable", request.id, {}}};
				const auto jobs = jobs_->List(principal.id);
				return {true, 200, ResourceResponse(request, JobsJson(jobs, 0, jobs.size()), serverVersion_), {}};
			}
			if (request.uri == "binjad://open-items")
			{
				if (!openItems_)
					return {
						true, 500, {}, ProtocolError {-32603, 500, "open-item service is unavailable", request.id, {}}};
				const auto items = openItems_->ListForToken(principal.id);
				return {
					true, 200, ResourceResponse(request, OpenItemsJson(items, 0, items.size()), serverVersion_), {}};
			}
			if (request.uri == "binjad://local-projects")
			{
				if (!projects_)
					return {true, IsModern(request.version) ? 404 : 200, {},
						ProtocolError {
							-32004, IsModern(request.version) ? 404 : 200, "resource not found", request.id, {}}};
				const auto projects = projects_->List();
				return {true, 200,
					ResourceResponse(request, ProjectsJson(projects, 0, projects.size()), serverVersion_), {}};
			}
			constexpr std::string_view prefix = "binjad://analysis-sessions/";
			if (request.uri.starts_with(prefix))
			{
				const auto found = sessions_.Find(request.uri.substr(prefix.size()), principal.id, now);
				if (!found)
					return {true, 404, {}, ProtocolError {-32001, 404, "session not found", request.id, {}}};
				return {true, 200, ResourceResponse(request, SessionJson(*found), serverVersion_), {}};
			}
			return {true, IsModern(request.version) ? 404 : 200, {},
				ProtocolError {-32002, IsModern(request.version) ? 404 : 200, "resource not found", request.id, {}}};
		}
		if (request.method != "tools/call")
			return {};

		Document params;
		std::string schemaError;
		const auto* arguments = Arguments(request, params, schemaError);
		if (!arguments)
			return {true, 400, {},
				ProtocolError {-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};

		const auto* tool = FindToolCall(request.name);
		if (!tool || !tool->CanExecute(config, request.version, principal.role))
			return {true, IsModern(request.version) ? 404 : 200, {},
				ProtocolError {-32602, IsModern(request.version) ? 404 : 200, "unknown tool", request.id, {}}};
		if (!tool->ValidateArguments(*arguments, schemaError))
			return {true, IsModern(request.version) ? 400 : 200, {},
				ProtocolError {-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
		return tool->Execute({config, sessions_, serverVersion_, openItems_, fileCoordinator_, jobs_, projects_,
			projectCoordinator_, scheduler_, uploads_, request, principal, currentSession, now, unixNow, progress,
			attached, *arguments});
	}
}  // namespace binjad::mcp
