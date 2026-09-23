#include "../tool_call.hpp"
#include "../tool_schema.hpp"

#include "binjad/overseer/collaboration_child_manager.hpp"
#include "binjad/overseer/analysis_scheduler.hpp"
#include "binjad/overseer/file_child_coordinator.hpp"
#include "binjad/overseer/project_child_coordinator.hpp"
#include "binjad/platform/paths.hpp"
#include "binjad/project/collaboration_project_registry.hpp"
#include "binjad/project/local_project_registry.hpp"
#include "binjad/session/job_registry.hpp"
#include "binjad/session/open_item_registry.hpp"
#include "binjad/upload/upload_registry.hpp"

#include <binaryninjacore.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>

namespace binjad::mcp {
	namespace {
		namespace detail {
			using rapidjson::Document;
			using rapidjson::StringBuffer;
			using rapidjson::Value;
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

			std::string RequiredString(const Value& arguments, const char* name)
			{
				const auto member = arguments.FindMember(name);
				return {member->value.GetString(), member->value.GetStringLength()};
			}

			std::optional<std::string> OptionalString(const Value& arguments, const char* name)
			{
				const auto member = arguments.FindMember(name);
				if (member == arguments.MemberEnd() || member->value.IsNull())
					return std::nullopt;
				return std::string(member->value.GetString(), member->value.GetStringLength());
			}

			std::optional<std::optional<std::string>> OptionalNullableString(const Value& arguments, const char* name)
			{
				const auto member = arguments.FindMember(name);
				if (member == arguments.MemberEnd())
					return std::nullopt;
				if (member->value.IsNull())
					return std::optional<std::string> {};
				return std::optional<std::string>(
					std::in_place, member->value.GetString(), member->value.GetStringLength());
			}

			bool OptionalBoolean(const Value& arguments, const char* name, bool defaultValue)
			{
				const auto member = arguments.FindMember(name);
				return member == arguments.MemberEnd() ? defaultValue : member->value.GetBool();
			}

			void Pagination(const Value& arguments, std::size_t& offset, std::size_t& limit)
			{
				if (const auto member = arguments.FindMember("offset"); member != arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = arguments.FindMember("limit"); member != arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
			}

			bool SafeFilenameComponent(std::string_view value)
			{
				if (value.empty() || value == "." || value == ".." || value.find('/') != std::string_view::npos
					|| value.find('\\') != std::string_view::npos)
					return false;
				return std::none_of(value.begin(), value.end(), [](unsigned char character) {
					return std::iscntrl(character) != 0;
				});
			}

			std::optional<std::string> ProjectPath(std::string_view value)
			{
				const std::filesystem::path path(value);
				const auto normalized = path.lexically_normal();
				if (path.is_absolute() || normalized.empty() || normalized == "." || *normalized.begin() == "..")
					return std::nullopt;
				return normalized.generic_string();
			}

		}  // namespace detail


#define BINJAD_PROJECT_TOOL(Type, Name, Description, Category, DocCategory, Availability, Handler, ...) \
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

#define BINJAD_RESTRICTED_PROJECT_TOOL(Type, Name, Description, Category, DocCategory, Availability, Handler, ...) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, Description, ToolCallCategory::Category, DocCategory, Availability) \
		{ \
			AllowRestrictedExecution(); \
		} \
		FoundationResult Execute(const ToolCallContext& context) const override { return Handler(context); } \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter& writer) const override \
		{ \
			schema::WriteObject(writer, {__VA_ARGS__}); \
		} \
	}

		namespace catalog_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			template <typename WriterType>
			void WriteLocalProject(WriterType& writer, const project::LocalProjectRecord& project)
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

			template <typename WriterType>
			void WriteCollaborationProject(WriterType& writer, const project::CollaborationProjectRecord& project)
			{
				writer.StartObject();
				writer.Key("project");
				writer.String(project.reference.data(), static_cast<rapidjson::SizeType>(project.reference.size()));
				writer.Key("name");
				writer.String(project.name.data(), static_cast<rapidjson::SizeType>(project.name.size()));
				writer.Key("description");
				writer.String(project.description.data(), static_cast<rapidjson::SizeType>(project.description.size()));
				writer.Key("createdAt");
				writer.Int64(project.created);
				writer.Key("lastModified");
				writer.Int64(project.lastModified);
				writer.Key("admin");
				writer.Bool(project.admin);
				writer.EndObject();
			}

			template <typename Record, typename WriteRecord>
			std::string PaginatedJson(std::string_view key, const std::vector<Record>& records,
				const rapidjson::Value& arguments, WriteRecord writeRecord)
			{
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = arguments.FindMember("offset"); member != arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = arguments.FindMember("limit"); member != arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
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

			FoundationResult LocalProjectList(const ToolCallContext& context)
			{
				if (!context.projects)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				return ToolCallSuccess(context,
					PaginatedJson("projects", context.projects->List(), context.arguments,
						[](auto& writer, const auto& project) { WriteLocalProject(writer, project); }));
			}

			FoundationResult LocalProjectInfo(const ToolCallContext& context)
			{
				const auto member = context.arguments.FindMember("project");
				const std::string reference(member->value.GetString(), member->value.GetStringLength());
				const auto found = context.projects ? context.projects->Find(reference) : std::nullopt;
				if (!found)
					return ToolCallSuccess(context, detail::ErrorJson("project not found"), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteLocalProject(writer, *found);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult CollaborationProjectList(const ToolCallContext& context)
			{
				if (!context.collaborationManager)
					return ToolCallSuccess(
						context, detail::ErrorJson("collaboration project service is unavailable"), true);
				const auto projects = context.collaborationManager->ListProjects(context.principal);
				if (!projects.value)
					return ToolCallSuccess(context, detail::ErrorJson(projects.error), true);
				return ToolCallSuccess(context,
					PaginatedJson("projects", *projects.value, context.arguments,
						[](auto& writer, const auto& project) { WriteCollaborationProject(writer, project); }));
			}

			FoundationResult CollaborationProjectInfo(const ToolCallContext& context)
			{
				const auto member = context.arguments.FindMember("project");
				const std::string reference(member->value.GetString(), member->value.GetStringLength());
				const auto project = context.collaborationProjects ?
					context.collaborationProjects->Find(context.principal.id, reference) :
					std::nullopt;
				if (!project)
					return ToolCallSuccess(context, detail::ErrorJson("project not found"), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteCollaborationProject(writer, *project);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			template <typename WriterType>
			void WriteLocalProjectFile(WriterType& writer, const project::LocalProjectFileRecord& file)
			{
				writer.StartObject();
				writer.Key("path");
				writer.String(file.path.data(), static_cast<rapidjson::SizeType>(file.path.size()));
				writer.Key("name");
				writer.String(file.name.data(), static_cast<rapidjson::SizeType>(file.name.size()));
				writer.Key("description");
				writer.String(file.description.data(), static_cast<rapidjson::SizeType>(file.description.size()));
				writer.Key("createdAt");
				writer.Int64(file.creationTimestamp);
				if (file.folderPath)
				{
					writer.Key("folder");
					writer.String(file.folderPath->data(), static_cast<rapidjson::SizeType>(file.folderPath->size()));
				}
				writer.EndObject();
			}

			template <typename WriterType>
			void WriteCollaborationFile(WriterType& writer, const project::CollaborationFileRecord& file)
			{
				writer.StartObject();
				writer.Key("path");
				writer.String(file.path.data(), static_cast<rapidjson::SizeType>(file.path.size()));
				writer.Key("name");
				writer.String(file.name.data(), static_cast<rapidjson::SizeType>(file.name.size()));
				writer.Key("description");
				writer.String(file.description.data(), static_cast<rapidjson::SizeType>(file.description.size()));
				writer.Key("size");
				writer.Uint64(file.size);
				writer.Key("type");
				switch (file.type)
				{
				case RawDataFileType:
					writer.String("raw");
					break;
				case BinaryViewAnalysisFileType:
					writer.String("analysis");
					break;
				case TypeArchiveFileType:
					writer.String("type_archive");
					break;
				default:
					writer.String("unknown");
					break;
				}
				writer.EndObject();
			}

			FoundationResult LocalProjectFileList(const ToolCallContext& context)
			{
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto folder = detail::OptionalString(context.arguments, "folder");
				const auto pathPrefix = detail::OptionalString(context.arguments, "pathPrefix");
				const auto query = detail::OptionalString(context.arguments, "query");
				std::string folderInternalId;
				if (folder)
				{
					const auto normalized = detail::ProjectPath(*folder);
					if (!normalized)
						return ToolCallInvalidArguments(
							context, "folder path must be a contained project-relative path");
					const auto found = context.projectCoordinator->FindFolder(project, *normalized);
					if (!found.value)
						return ToolCallSuccess(context, detail::ErrorJson(found.error), true);
					folderInternalId = found.value->internalId;
				}
				std::string normalizedPrefix;
				if (pathPrefix)
				{
					const auto normalized = detail::ProjectPath(*pathPrefix);
					if (!normalized)
						return ToolCallInvalidArguments(
							context, "pathPrefix must be a contained project-relative path");
					normalizedPrefix = *normalized;
				}
				auto files = context.projectCoordinator->ListFiles(project);
				if (!files.value)
					return ToolCallSuccess(context, detail::ErrorJson(files.error), true);
				const auto lower = [](std::string_view value) {
					std::string result(value);
					std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
						return static_cast<char>(std::tolower(character));
					});
					return result;
				};
				const auto loweredQuery = query ? lower(*query) : std::string {};
				std::erase_if(*files.value, [&](const auto& file) {
					if (folder && file.folderInternalId != folderInternalId)
						return true;
					if (!normalizedPrefix.empty() && !std::string_view(file.path).starts_with(normalizedPrefix))
						return true;
					return !loweredQuery.empty()
						&& lower(file.path + "\n" + file.name + "\n" + file.description).find(loweredQuery)
						== std::string::npos;
				});
				return ToolCallSuccess(context,
					PaginatedJson("files", *files.value, context.arguments, [](auto& writer, const auto& file) {
						WriteLocalProjectFile(writer, file);
					}));
			}

			FoundationResult LocalProjectCreate(const ToolCallContext& context)
			{
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto name = detail::RequiredString(context.arguments, "name");
				auto requestedPath = detail::OptionalString(context.arguments, "path");
				const auto description = detail::OptionalString(context.arguments, "description").value_or("");
				if (!requestedPath)
				{
					if (!context.config.projects.defaultRoot)
						return ToolCallSuccess(
							context, detail::ErrorJson("local project creation requires projects.default_root"), true);
					if (!detail::SafeFilenameComponent(name))
						return ToolCallInvalidArguments(
							context, "name cannot be used as a project filename; provide path");
					requestedPath = name + ".bnpr";
				}
				const std::filesystem::path supplied(*requestedPath);
				const auto normalized = supplied.lexically_normal();
				std::filesystem::path destination;
				if (supplied.is_absolute())
				{
					if (context.principal.role != security::TokenRole::Admin)
						return ToolCallSuccess(context,
							detail::ErrorJson("administrator token required for an absolute project path"), true);
					if (!context.config.projects.allowArbitraryPaths)
						return ToolCallSuccess(context, detail::ErrorJson("arbitrary server paths are disabled"), true);
					if (normalized.extension() != ".bnpr")
						return ToolCallInvalidArguments(context, "absolute path must end in .bnpr");
					destination = normalized;
				}
				else
				{
					if (!context.config.projects.defaultRoot || normalized.empty() || normalized == "."
						|| *normalized.begin() == ".." || normalized.extension() != ".bnpr")
						return ToolCallInvalidArguments(
							context, "path must be a contained relative path ending in .bnpr");
					destination = (*context.config.projects.defaultRoot / normalized).lexically_normal();
				}
				const auto created = context.projectCoordinator->CreateProject(destination, name, description);
				if (!created.value)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteLocalProject(writer, *created.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult CollaborationProjectFileList(const ToolCallContext& context)
			{
				if (!context.collaborationManager)
					return ToolCallSuccess(
						context, detail::ErrorJson("collaboration project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto files = context.collaborationManager->ListFiles(context.principal, project);
				if (!files.value)
					return ToolCallSuccess(context, detail::ErrorJson(files.error), true);
				return ToolCallSuccess(context,
					PaginatedJson("files", *files.value, context.arguments, [](auto& writer, const auto& file) {
						WriteCollaborationFile(writer, file);
					}));
			}

			BINJAD_PROJECT_TOOL(LocalProjectListTool, "bn_local_project_list", "List local projects.", Core, "Projects",
				ToolCallAvailability::LocalMode, LocalProjectList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_PROJECT_TOOL(LocalProjectInfoTool, "bn_local_project_info", "Inspect a local project.", Core,
				"Projects", ToolCallAvailability::LocalMode, LocalProjectInfo, schema::String("project", true));
			BINJAD_PROJECT_TOOL(LocalProjectFileListTool, "bn_local_project_file_list",
				"List local project files and their names, descriptions, paths, folders, and timestamps with optional "
				"filters.",
				Core, "Projects", ToolCallAvailability::LocalMode, LocalProjectFileList,
				schema::String("project", true),
				schema::NonEmptyString("folder", false, "Exact project-relative folder path."),
				schema::NonEmptyString("pathPrefix"), schema::NonEmptyString("query"),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
			BINJAD_PROJECT_TOOL(LocalProjectCreateTool, "bn_local_project_create",
				"Create a local project beneath the configured default root, or at an absolute path for an "
				"administrator.",
				Core, "Projects", ToolCallAvailability::LocalMode, LocalProjectCreate, schema::String("name", true),
				schema::NonEmptyString("path"), schema::String("description"));
			BINJAD_PROJECT_TOOL(CollaborationProjectListTool, "bn_collaboration_project_list",
				"Refresh and list collaboration projects.", Core, "Projects", ToolCallAvailability::CollaborationMode,
				CollaborationProjectList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_PROJECT_TOOL(CollaborationProjectInfoTool, "bn_collaboration_project_info",
				"Inspect a collaboration project.", Core, "Projects", ToolCallAvailability::CollaborationMode,
				CollaborationProjectInfo, schema::String("project", true));
			BINJAD_PROJECT_TOOL(CollaborationProjectFileListTool, "bn_collaboration_project_file_list",
				"List files in a collaboration project.", Core, "Projects", ToolCallAvailability::CollaborationMode,
				CollaborationProjectFileList, schema::String("project", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_PROJECT_TOOL(ProjectFileOpenTool, "bn_project_file_open",
				"Discover BinaryView candidates for a project file; call bn_binary_view_open before using a candidate.",
				Core, "Projects", ToolCallAvailability::None, ExecuteOpenItemTool, schema::String("project", true),
				schema::String("path", true), schema::Enum("kind", false, {"auto", "file"}),
				schema::Object("options", false,
					"Candidate-specific Binary Ninja load settings. Call bn_binary_view_load_settings first; Raw "
					"accepts "
					"none, while Mapped exposes fully qualified loader.* keys and requires serialized JSON strings for "
					"segments and sections."),
				schema::Boolean("reuseDatabase"));
		}  // namespace catalog_tools

		namespace management_tools {
			constexpr auto kLocal = ToolCallAvailability::LocalMode;
			constexpr auto kLocalAdminPaths =
				ToolCallAvailability::LocalMode | ToolCallAvailability::Admin | ToolCallAvailability::ArbitraryPaths;

			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			template <typename WriterType>
			void WriteFolder(WriterType& writer, const project::LocalProjectFolderRecord& folder)
			{
				writer.StartObject();
				writer.Key("path");
				writer.String(folder.path.data(), static_cast<rapidjson::SizeType>(folder.path.size()));
				writer.Key("name");
				writer.String(folder.name.data(), static_cast<rapidjson::SizeType>(folder.name.size()));
				writer.Key("description");
				writer.String(folder.description.data(), static_cast<rapidjson::SizeType>(folder.description.size()));
				if (folder.parentPath)
				{
					writer.Key("parent");
					writer.String(
						folder.parentPath->data(), static_cast<rapidjson::SizeType>(folder.parentPath->size()));
				}
				writer.EndObject();
			}

			template <typename Record, typename WriteRecord>
			std::string Paginated(std::string_view key, const std::vector<Record>& records,
				const rapidjson::Value& arguments, WriteRecord writeRecord)
			{
				std::size_t offset = 0;
				std::size_t limit = 50;
				detail::Pagination(arguments, offset, limit);
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

			FoundationResult LocalProjectRegister(const ToolCallContext& context)
			{
				if (context.principal.role != security::TokenRole::Admin)
					return ToolCallSuccess(context, detail::ErrorJson("administrator token required"), true);
				if (!context.config.projects.allowArbitraryPaths)
					return ToolCallSuccess(context, detail::ErrorJson("arbitrary server paths are disabled"), true);
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto registered =
					context.projectCoordinator->RegisterProject(detail::RequiredString(context.arguments, "path"));
				if (!registered.value)
					return ToolCallSuccess(context, detail::ErrorJson(registered.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				catalog_tools::WriteLocalProject(writer, *registered.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			struct ImportRequest
			{
				std::string source;
				std::string name;
				std::string description;
			};

			std::optional<ImportRequest> ParseImport(const rapidjson::Value& value, std::string& error)
			{
				ImportRequest result;
				result.source = detail::RequiredString(value, "source");
				result.name =
					detail::OptionalString(value, "name")
						.value_or(std::filesystem::path(result.source).filename().string());
				result.description = detail::OptionalString(value, "description").value_or("Imported local file");
				if (!detail::SafeFilenameComponent(result.name))
				{
					error = "name must be one safe filename component";
					return std::nullopt;
				}
				return result;
			}

			FoundationResult LocalProjectImport(const ToolCallContext& context, bool batch)
			{
				if (context.principal.role != security::TokenRole::Admin)
					return ToolCallSuccess(context, detail::ErrorJson("administrator token required"), true);
				if (!context.config.projects.allowArbitraryPaths)
					return ToolCallSuccess(context, detail::ErrorJson("arbitrary server paths are disabled"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				if (!context.projectCoordinator || !context.projects || !context.projects->Find(project))
					return ToolCallSuccess(context, detail::ErrorJson("local project not found"), true);
				std::string folderPath;
				if (const auto folder = detail::OptionalString(context.arguments, "folder"))
				{
					const auto normalized = detail::ProjectPath(*folder);
					if (!normalized)
						return ToolCallInvalidArguments(
							context, "folder path must be a contained project-relative path");
					folderPath = *normalized;
				}

				std::vector<ImportRequest> imports;
				if (batch)
				{
					const auto files = context.arguments.FindMember("files");
					imports.reserve(files->value.Size());
					for (rapidjson::SizeType index = 0; index < files->value.Size(); ++index)
					{
						std::string error;
						auto item = ParseImport(files->value[index], error);
						if (!item)
							return ToolCallInvalidArguments(context, "files[" + std::to_string(index) + "]: " + error);
						imports.push_back(std::move(*item));
					}
				}
				else
				{
					std::string error;
					auto item = ParseImport(context.arguments, error);
					if (!item)
						return ToolCallInvalidArguments(context, error);
					imports.push_back(std::move(*item));
				}

				struct Outcome
				{
					ImportRequest request;
					std::string internalId;
					std::string error;
				};
				std::vector<Outcome> outcomes;
				outcomes.reserve(imports.size());
				for (auto& item : imports)
				{
					Outcome outcome {std::move(item), {}, {}};
					const std::filesystem::path source(outcome.request.source);
					std::error_code filesystemError;
					if (!source.is_absolute() || !std::filesystem::is_regular_file(source, filesystemError)
						|| filesystemError)
						outcome.error = "source path does not resolve to a regular file";
					else
					{
						const auto destination = folderPath.empty() ?
							outcome.request.name :
							(std::filesystem::path(folderPath) / outcome.request.name).generic_string();
						const auto committed = context.projectCoordinator->CommitFile(
							project, destination, source, false, true, outcome.request.description);
						if (committed.value)
							outcome.internalId = committed.value->internalId;
						else
							outcome.error = committed.error;
					}
					outcomes.push_back(std::move(outcome));
				}
				const auto refreshed = context.projectCoordinator->ListFiles(project);
				if (!refreshed.value)
					return ToolCallSuccess(context, detail::ErrorJson(refreshed.error), true);
				const auto findFile = [&](std::string_view internalId) -> const project::LocalProjectFileRecord* {
					const auto found = std::find_if(refreshed.value->begin(), refreshed.value->end(),
						[&](const auto& file) { return file.internalId == internalId; });
					return found == refreshed.value->end() ? nullptr : &*found;
				};
				if (!batch)
				{
					if (!outcomes.front().error.empty())
						return ToolCallSuccess(context, detail::ErrorJson(outcomes.front().error), true);
					const auto* file = findFile(outcomes.front().internalId);
					if (!file)
						return ToolCallSuccess(context, detail::ErrorJson("imported project file not found"), true);
					StringBuffer buffer;
					Writer<StringBuffer> writer(buffer);
					catalog_tools::WriteLocalProjectFile(writer, *file);
					return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
				}

				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("items");
				writer.StartArray();
				std::size_t imported = 0;
				for (const auto& outcome : outcomes)
				{
					writer.StartObject();
					writer.Key("source");
					writer.String(
						outcome.request.source.data(), static_cast<rapidjson::SizeType>(outcome.request.source.size()));
					if (outcome.error.empty())
					{
						if (const auto* file = findFile(outcome.internalId))
						{
							writer.Key("file");
							catalog_tools::WriteLocalProjectFile(writer, *file);
							++imported;
						}
						else
						{
							writer.Key("error");
							writer.String("imported project file not found");
						}
					}
					else
					{
						writer.Key("error");
						writer.String(outcome.error.data(), static_cast<rapidjson::SizeType>(outcome.error.size()));
					}
					writer.EndObject();
				}
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(outcomes.size());
				writer.Key("imported");
				writer.Uint64(imported);
				writer.Key("failed");
				writer.Uint64(outcomes.size() - imported);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()}, imported != outcomes.size());
			}

			FoundationResult LocalProjectFileImport(const ToolCallContext& context)
			{
				return LocalProjectImport(context, false);
			}

			FoundationResult LocalProjectFileImportBatch(const ToolCallContext& context)
			{
				return LocalProjectImport(context, true);
			}

			FoundationResult LocalProjectUpdate(const ToolCallContext& context)
			{
				const auto name = detail::OptionalString(context.arguments, "name");
				const auto description = detail::OptionalString(context.arguments, "description");
				if (!name && !description)
					return ToolCallInvalidArguments(context, "name or description is required");
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto updated = context.projectCoordinator->UpdateProject(
					detail::RequiredString(context.arguments, "project"), name, description);
				if (!updated.value)
					return ToolCallSuccess(context, detail::ErrorJson(updated.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				catalog_tools::WriteLocalProject(writer, *updated.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult LocalProjectFolderList(const ToolCallContext& context)
			{
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto folders =
					context.projectCoordinator->ListFolders(detail::RequiredString(context.arguments, "project"));
				if (!folders.value)
					return ToolCallSuccess(context, detail::ErrorJson(folders.error), true);
				return ToolCallSuccess(context,
					Paginated("folders", *folders.value, context.arguments, [](auto& writer, const auto& folder) {
						WriteFolder(writer, folder);
					}));
			}

			FoundationResult LocalProjectFolderCreate(const ToolCallContext& context)
			{
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				std::optional<std::string> parentInternalId;
				if (const auto parent = detail::OptionalString(context.arguments, "parent"))
				{
					const auto normalized = detail::ProjectPath(*parent);
					if (!normalized)
						return ToolCallInvalidArguments(
							context, "folder path must be a contained project-relative path");
					const auto found = context.projectCoordinator->FindFolder(project, *normalized);
					if (!found.value)
						return ToolCallSuccess(context, detail::ErrorJson(found.error), true);
					parentInternalId = found.value->internalId;
				}
				const auto created = context.projectCoordinator->CreateFolder(project,
					parentInternalId ? std::optional<std::string_view>(*parentInternalId) : std::nullopt,
					detail::RequiredString(context.arguments, "name"),
					detail::OptionalString(context.arguments, "description").value_or(""));
				if (!created.value)
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteFolder(writer, *created.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult LocalProjectFolderUpdate(const ToolCallContext& context)
			{
				const auto name = detail::OptionalString(context.arguments, "name");
				const auto description = detail::OptionalString(context.arguments, "description");
				const auto parent = detail::OptionalNullableString(context.arguments, "parent");
				if (!name && !description && !parent)
					return ToolCallInvalidArguments(context, "a folder update is required");
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto path = detail::ProjectPath(detail::RequiredString(context.arguments, "path"));
				if (!path)
					return ToolCallInvalidArguments(context, "folder path must be a contained project-relative path");
				const auto previousResult = context.projectCoordinator->FindFolder(project, *path);
				if (!previousResult.value)
					return ToolCallSuccess(context, detail::ErrorJson(previousResult.error), true);
				std::optional<std::optional<std::string>> parentInternalId;
				if (parent)
				{
					parentInternalId = std::optional<std::string> {};
					if (*parent)
					{
						const auto normalized = detail::ProjectPath(**parent);
						if (!normalized)
							return ToolCallInvalidArguments(
								context, "folder path must be a contained project-relative path");
						const auto found = context.projectCoordinator->FindFolder(project, *normalized);
						if (!found.value)
							return ToolCallSuccess(context, detail::ErrorJson(found.error), true);
						parentInternalId = std::optional<std::string>(found.value->internalId);
					}
				}
				const auto previous = *previousResult.value;
				const auto updated = context.projectCoordinator->UpdateFolder(
					project, previous.internalId, name, description, parentInternalId);
				if (!updated.value)
					return ToolCallSuccess(context, detail::ErrorJson(updated.error), true);
				if (context.openItems && previous.path != updated.value->path)
					context.openItems->UpdateProjectSourcePrefix(previous.project, previous.path, updated.value->path);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				WriteFolder(writer, *updated.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult LocalProjectFolderDelete(const ToolCallContext& context)
			{
				if (!detail::OptionalBoolean(context.arguments, "recursive", false))
					return ToolCallInvalidArguments(context, "recursive must be true");
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto path = detail::ProjectPath(detail::RequiredString(context.arguments, "path"));
				if (!path)
					return ToolCallInvalidArguments(context, "folder path must be a contained project-relative path");
				const auto existing = context.projectCoordinator->FindFolder(project, *path);
				if (!existing.value)
					return ToolCallSuccess(context, detail::ErrorJson(existing.error), true);
				if (context.openItems
					&& context.openItems->HasProjectSourcePrefix(existing.value->project, existing.value->path))
					return ToolCallSuccess(
						context, detail::ErrorJson("project folder contains an open analysis handle"), true);
				if (const auto error =
						context.projectCoordinator->DeleteFolder(project, existing.value->internalId, true);
					!error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("path");
				writer.String(path->data(), static_cast<rapidjson::SizeType>(path->size()));
				writer.Key("deleted");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult LocalProjectFileUpdate(const ToolCallContext& context)
			{
				const auto name = detail::OptionalString(context.arguments, "name");
				const auto description = detail::OptionalString(context.arguments, "description");
				const auto folder = detail::OptionalNullableString(context.arguments, "folder");
				if (!name && !description && !folder)
					return ToolCallInvalidArguments(context, "a file update is required");
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto path = detail::ProjectPath(detail::RequiredString(context.arguments, "path"));
				if (!path)
					return ToolCallInvalidArguments(context, "folder path must be a contained project-relative path");
				const auto previous = context.projects ? context.projects->FindFile(project, *path) : std::nullopt;
				std::optional<std::optional<std::string>> folderInternalId;
				if (folder)
				{
					folderInternalId = std::optional<std::string> {};
					if (*folder)
					{
						if (!previous)
							return ToolCallSuccess(context, detail::ErrorJson("project file not found"), true);
						const auto normalized = detail::ProjectPath(**folder);
						if (!normalized)
							return ToolCallInvalidArguments(
								context, "folder path must be a contained project-relative path");
						const auto found = context.projectCoordinator->FindFolder(previous->project, *normalized);
						if (!found.value)
							return ToolCallSuccess(context, detail::ErrorJson(found.error), true);
						folderInternalId = std::optional<std::string>(found.value->internalId);
					}
				}
				const auto updated =
					context.projectCoordinator->UpdateFile(project, *path, name, description, folderInternalId);
				if (!updated.value)
					return ToolCallSuccess(context, detail::ErrorJson(updated.error), true);
				if (previous && context.openItems && previous->path != updated.value->path)
					context.openItems->UpdateProjectSource(previous->project, previous->path, updated.value->path);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				catalog_tools::WriteLocalProjectFile(writer, *updated.value);
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult LocalProjectFileDelete(const ToolCallContext& context)
			{
				if (!detail::OptionalBoolean(context.arguments, "delete", false))
					return ToolCallInvalidArguments(context, "delete must be true");
				if (!context.projectCoordinator)
					return ToolCallSuccess(context, detail::ErrorJson("local project service is unavailable"), true);
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto path = detail::ProjectPath(detail::RequiredString(context.arguments, "path"));
				if (!path)
					return ToolCallInvalidArguments(context, "folder path must be a contained project-relative path");
				const auto existing = context.projects ? context.projects->FindFile(project, *path) : std::nullopt;
				if (existing && context.openItems
					&& context.openItems->HasProjectSource(existing->project, existing->path))
					return ToolCallSuccess(
						context, detail::ErrorJson("project file has an open analysis handle"), true);
				if (const auto error = context.projectCoordinator->DeleteFile(project, *path, true); !error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("project");
				writer.String(project.data(), static_cast<rapidjson::SizeType>(project.size()));
				writer.Key("path");
				writer.String(path->data(), static_cast<rapidjson::SizeType>(path->size()));
				writer.Key("deleted");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			std::string AsciiLower(std::string_view value)
			{
				std::string result(value);
				std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
					return static_cast<char>(std::tolower(character));
				});
				return result;
			}

			bool ValidUtf8(std::string_view text)
			{
				for (std::size_t offset = 0; offset < text.size();)
				{
					const auto first = static_cast<unsigned char>(text[offset]);
					std::size_t length = 0;
					std::uint32_t codepoint = 0;
					if (first < 0x80)
					{
						length = 1;
						codepoint = first;
					}
					else if ((first & 0xe0) == 0xc0)
					{
						length = 2;
						codepoint = first & 0x1f;
					}
					else if ((first & 0xf0) == 0xe0)
					{
						length = 3;
						codepoint = first & 0x0f;
					}
					else if ((first & 0xf8) == 0xf0)
					{
						length = 4;
						codepoint = first & 0x07;
					}
					else
						return false;
					if (offset + length > text.size())
						return false;
					for (std::size_t index = 1; index < length; ++index)
					{
						const auto next = static_cast<unsigned char>(text[offset + index]);
						if ((next & 0xc0) != 0x80)
							return false;
						codepoint = (codepoint << 6) | (next & 0x3f);
					}
					if ((length == 2 && codepoint < 0x80) || (length == 3 && codepoint < 0x800)
						|| (length == 4 && codepoint < 0x10000) || (codepoint >= 0xd800 && codepoint <= 0xdfff)
						|| codepoint > 0x10ffff)
						return false;
					offset += length;
				}
				return true;
			}

			std::string Utf8Preview(std::string_view text, std::size_t maximum)
			{
				if (text.size() <= maximum)
					return std::string(text);
				std::size_t end = maximum;
				while (end != 0 && (static_cast<unsigned char>(text[end]) & 0xc0) == 0x80)
					--end;
				return std::string(text.substr(0, end));
			}

			std::string ReadText(const std::filesystem::path& path, std::string_view projectPath,
				std::string_view query, std::size_t offset, std::size_t limit, std::string& error)
			{
				std::ifstream input(path, std::ios::binary);
				if (!input)
				{
					error = "cannot read project text file";
					return {};
				}
				struct Line
				{
					std::size_t number;
					std::string value;
					std::size_t length;
					bool truncated;
				};
				std::vector<Line> page;
				std::string line;
				const auto loweredQuery = AsciiLower(query);
				std::size_t lineNumber = 0;
				std::size_t matched = 0;
				while (std::getline(input, line))
				{
					++lineNumber;
					if (!line.empty() && line.back() == '\r')
						line.pop_back();
					if (line.find('\0') != std::string::npos || !ValidUtf8(line))
					{
						error = "project file is not valid UTF-8 text";
						return {};
					}
					if (!loweredQuery.empty() && AsciiLower(line).find(loweredQuery) == std::string::npos)
						continue;
					if (matched >= offset && page.size() < limit)
					{
						constexpr std::size_t kLinePreviewBytes = 2048;
						page.push_back({lineNumber, Utf8Preview(line, kLinePreviewBytes), line.size(),
							line.size() > kLinePreviewBytes});
					}
					++matched;
				}
				if (input.bad())
				{
					error = "cannot read project text file";
					return {};
				}
				const auto end = std::min(matched, offset + page.size());
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("path");
				writer.String(projectPath.data(), static_cast<rapidjson::SizeType>(projectPath.size()));
				if (!query.empty())
				{
					writer.Key("query");
					writer.String(query.data(), static_cast<rapidjson::SizeType>(query.size()));
				}
				writer.Key("lines");
				writer.StartArray();
				for (const auto& item : page)
				{
					writer.StartObject();
					writer.Key("line");
					writer.Uint64(item.number);
					writer.Key("text");
					writer.String(item.value.data(), static_cast<rapidjson::SizeType>(item.value.size()));
					if (item.truncated)
					{
						writer.Key("byteLength");
						writer.Uint64(item.length);
						writer.Key("truncated");
						writer.Bool(true);
					}
					writer.EndObject();
				}
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(page.size());
				writer.Key("total");
				writer.Uint64(matched);
				writer.Key("nextOffset");
				if (end < matched)
					writer.Uint64(end);
				else
					writer.Null();
				writer.Key("truncated");
				writer.Bool(end < matched);
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::optional<std::string> DecodePointerToken(std::string_view encoded)
			{
				std::string result;
				for (std::size_t index = 0; index < encoded.size(); ++index)
				{
					if (encoded[index] != '~')
					{
						result.push_back(encoded[index]);
						continue;
					}
					if (++index >= encoded.size() || (encoded[index] != '0' && encoded[index] != '1'))
						return std::nullopt;
					result.push_back(encoded[index] == '0' ? '~' : '/');
				}
				return result;
			}

			std::string AppendPointer(std::string_view pointer, std::string_view token)
			{
				std::string result(pointer);
				result.push_back('/');
				for (const char character : token)
				{
					if (character == '~')
						result += "~0";
					else if (character == '/')
						result += "~1";
					else
						result.push_back(character);
				}
				return result;
			}

			const rapidjson::Value* ResolvePointer(
				const rapidjson::Value& root, std::string_view pointer, std::string& error)
			{
				if (pointer.empty())
					return &root;
				if (!pointer.starts_with('/'))
				{
					error = "pointer must be empty or an RFC 6901 JSON Pointer beginning with '/'";
					return nullptr;
				}
				const rapidjson::Value* current = &root;
				for (std::size_t start = 1;;)
				{
					const auto slash = pointer.find('/', start);
					const auto encoded =
						pointer.substr(start, slash == std::string_view::npos ? pointer.size() - start : slash - start);
					const auto token = DecodePointerToken(encoded);
					if (!token)
					{
						error = "pointer contains an invalid '~' escape";
						return nullptr;
					}
					if (current->IsObject())
					{
						const auto member = current->FindMember(rapidjson::StringRef(token->data(), token->size()));
						if (member == current->MemberEnd())
						{
							error = "JSON Pointer does not exist";
							return nullptr;
						}
						current = &member->value;
					}
					else if (current->IsArray())
					{
						std::size_t index = 0;
						const auto parsed = std::from_chars(token->data(), token->data() + token->size(), index);
						if (token->empty() || parsed.ec != std::errc {} || parsed.ptr != token->data() + token->size()
							|| index >= current->Size())
						{
							error = "JSON Pointer array index does not exist";
							return nullptr;
						}
						current = &(*current)[static_cast<rapidjson::SizeType>(index)];
					}
					else
					{
						error = "JSON Pointer traverses through a scalar value";
						return nullptr;
					}
					if (slash == std::string_view::npos)
						return current;
					start = slash + 1;
				}
			}

			template <typename WriterType>
			void WriteJsonSummary(WriterType& writer, const rapidjson::Value& value)
			{
				writer.Key("type");
				if (value.IsObject())
				{
					writer.String("object");
					writer.Key("count");
					writer.Uint64(value.MemberCount());
				}
				else if (value.IsArray())
				{
					writer.String("array");
					writer.Key("count");
					writer.Uint64(value.Size());
				}
				else if (value.IsString())
				{
					writer.String("string");
					const std::string_view text(value.GetString(), value.GetStringLength());
					const auto preview = Utf8Preview(text, 4096);
					writer.Key("value");
					writer.String(preview.data(), static_cast<rapidjson::SizeType>(preview.size()));
					if (preview.size() != text.size())
					{
						writer.Key("byteLength");
						writer.Uint64(text.size());
						writer.Key("truncated");
						writer.Bool(true);
					}
				}
				else if (value.IsBool())
				{
					writer.String("boolean");
					writer.Key("value");
					writer.Bool(value.GetBool());
				}
				else if (value.IsNull())
				{
					writer.String("null");
					writer.Key("value");
					writer.Null();
				}
				else
				{
					writer.String("number");
					writer.Key("value");
					value.Accept(writer);
				}
			}

			std::string ReadJson(const std::filesystem::path& path, std::string_view projectPath,
				std::string_view pointer, std::size_t offset, std::size_t limit, std::string& error)
			{
				std::error_code filesystemError;
				const auto size = std::filesystem::file_size(path, filesystemError);
				if (filesystemError)
				{
					error = "cannot inspect project JSON file";
					return {};
				}
				if (size > 64ull * 1024 * 1024)
				{
					error = "project JSON file exceeds the 64 MiB parsing limit";
					return {};
				}
				std::ifstream input(path, std::ios::binary);
				if (!input)
				{
					error = "cannot read project JSON file";
					return {};
				}
				std::string contents((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
				rapidjson::Document document;
				try
				{
					document.Parse<rapidjson::kParseValidateEncodingFlag>(contents.data(), contents.size());
				}
				catch (const ParseException& exception)
				{
					error = "invalid project JSON at byte " + std::to_string(exception.Offset());
					return {};
				}
				if (document.HasParseError())
				{
					error = "invalid project JSON at byte " + std::to_string(document.GetErrorOffset());
					return {};
				}
				const auto selected = ResolvePointer(document, pointer, error);
				if (!selected)
					return {};
				const bool container = selected->IsObject() || selected->IsArray();
				const std::size_t total = selected->IsObject() ?
					selected->MemberCount() :
					selected->IsArray() ?
					selected->Size() :
					1;
				const auto begin = container ? std::min(offset, total) : 0;
				const auto end = container ? std::min(total, begin + limit) : 1;
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("path");
				writer.String(projectPath.data(), static_cast<rapidjson::SizeType>(projectPath.size()));
				writer.Key("pointer");
				writer.String(pointer.data(), static_cast<rapidjson::SizeType>(pointer.size()));
				writer.Key("type");
				writer.String(selected->IsObject() ? "object" : selected->IsArray() ? "array" : "scalar");
				if (selected->IsObject())
				{
					writer.Key("members");
					writer.StartArray();
					std::size_t index = 0;
					for (const auto& member : selected->GetObject())
					{
						if (index >= begin && index < end)
						{
							writer.StartObject();
							writer.Key("key");
							member.name.Accept(writer);
							const auto child =
								AppendPointer(pointer, {member.name.GetString(), member.name.GetStringLength()});
							writer.Key("pointer");
							writer.String(child.data(), static_cast<rapidjson::SizeType>(child.size()));
							WriteJsonSummary(writer, member.value);
							writer.EndObject();
						}
						++index;
					}
					writer.EndArray();
				}
				else if (selected->IsArray())
				{
					writer.Key("items");
					writer.StartArray();
					for (std::size_t index = begin; index < end; ++index)
					{
						writer.StartObject();
						writer.Key("index");
						writer.Uint64(index);
						const auto child = AppendPointer(pointer, std::to_string(index));
						writer.Key("pointer");
						writer.String(child.data(), static_cast<rapidjson::SizeType>(child.size()));
						WriteJsonSummary(writer, (*selected)[static_cast<rapidjson::SizeType>(index)]);
						writer.EndObject();
					}
					writer.EndArray();
				}
				else
				{
					writer.Key("value");
					writer.StartObject();
					WriteJsonSummary(writer, *selected);
					writer.EndObject();
				}
				writer.Key("count");
				writer.Uint64(end - begin);
				writer.Key("total");
				writer.Uint64(total);
				writer.Key("nextOffset");
				if (end < total)
					writer.Uint64(end);
				else
					writer.Null();
				writer.Key("truncated");
				writer.Bool(end < total);
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			class ScopedWorkingDirectory
			{
			public:
				std::filesystem::path path;
				~ScopedWorkingDirectory()
				{
					if (!path.empty())
					{
						std::error_code ignored;
						std::filesystem::remove_all(path, ignored);
					}
				}
			};

			FoundationResult ProjectDocumentRead(const ToolCallContext& context, bool json)
			{
				const auto project = detail::RequiredString(context.arguments, "project");
				const auto path = detail::RequiredString(context.arguments, "path");
				const auto selector =
					detail::OptionalString(context.arguments, json ? "pointer" : "query").value_or("");
				std::size_t offset = 0;
				std::size_t limit = 50;
				detail::Pagination(context.arguments, offset, limit);
				ScopedWorkingDirectory cleanup;
				std::filesystem::path documentPath;
				if (context.config.EffectiveMode() == Mode::Local)
				{
					if (!context.projectCoordinator)
						return ToolCallSuccess(
							context, detail::ErrorJson("local project service is unavailable"), true);
					auto exported = context.projectCoordinator->ExportFile(project, path);
					if (!exported.value)
						return ToolCallSuccess(context, detail::ErrorJson(exported.error), true);
					cleanup.path = exported.value->workingDirectory;
					documentPath = exported.value->path;
				}
				else
				{
					if (!context.collaborationManager)
						return ToolCallSuccess(
							context, detail::ErrorJson("collaboration project service is unavailable"), true);
					auto downloaded = context.collaborationManager->DownloadFile(context.principal, project, path);
					if (!downloaded.value)
						return ToolCallSuccess(context, detail::ErrorJson(downloaded.error), true);
					cleanup.path = downloaded.value->workingDirectory;
					documentPath = downloaded.value->path;
				}
				std::string error;
				const auto output = json ?
					ReadJson(documentPath, path, selector, offset, limit, error) :
					ReadText(documentPath, path, selector, offset, limit, error);
				return error.empty() ?
					ToolCallSuccess(context, output) :
					ToolCallSuccess(context, detail::ErrorJson(error), true);
			}

			FoundationResult ProjectTextRead(const ToolCallContext& context)
			{
				return ProjectDocumentRead(context, false);
			}

			FoundationResult ProjectJsonRead(const ToolCallContext& context)
			{
				return ProjectDocumentRead(context, true);
			}

			BINJAD_RESTRICTED_PROJECT_TOOL(LocalProjectRegisterTool, "bn_local_project_register",
				"Register an existing local .bnpr or .bnpm project by absolute path.", ProjectManagement, "Projects",
				kLocalAdminPaths, LocalProjectRegister, schema::String("path", true));
			BINJAD_RESTRICTED_PROJECT_TOOL(LocalProjectFileImportTool, "bn_local_project_file_import",
				"Import one server-local regular file with optional project-file name and description; administrator "
				"only.",
				ProjectManagement, "Projects", kLocalAdminPaths, LocalProjectFileImport,
				schema::String("project", true), schema::String("source", true),
				schema::NonEmptyString("folder", false, "Project-relative destination folder path."),
				schema::NonEmptyString("name"),
				schema::String("description", false,
					"Initial project-file description; it can later be changed or cleared with "
					"bn_local_project_file_update."));
			BINJAD_RESTRICTED_PROJECT_TOOL(LocalProjectFileImportBatchTool, "bn_local_project_file_import_batch",
				"Import up to 1000 server-local regular files with optional per-file names and descriptions; "
				"administrator only.",
				ProjectManagement, "Projects", kLocalAdminPaths, LocalProjectFileImportBatch,
				schema::String("project", true),
				schema::NonEmptyString("folder", false, "Project-relative destination folder path."),
				schema::ObjectArray("files", true,
					{schema::String("source", true), schema::NonEmptyString("name"),
						schema::String(
							"description", false, "Initial project-file description for this imported file.")},
					1, 1000));
			BINJAD_PROJECT_TOOL(LocalProjectUpdateTool, "bn_local_project_update", "Update local project metadata.",
				ProjectManagement, "Projects", kLocal, LocalProjectUpdate, schema::String("project", true),
				schema::NonEmptyString("name"), schema::String("description"));
			BINJAD_PROJECT_TOOL(LocalProjectFolderListTool, "bn_local_project_folder_list",
				"List folders in a local project.", ProjectManagement, "Projects", kLocal, LocalProjectFolderList,
				schema::String("project", true), schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000));
			BINJAD_PROJECT_TOOL(LocalProjectFolderCreateTool, "bn_local_project_folder_create",
				"Create a local project folder beneath an optional parent path.", ProjectManagement, "Projects", kLocal,
				LocalProjectFolderCreate, schema::String("project", true), schema::NonEmptyString("parent"),
				schema::String("name", true), schema::String("description"));
			BINJAD_PROJECT_TOOL(LocalProjectFolderUpdateTool, "bn_local_project_folder_update",
				"Update or move a local project folder selected by project and path.", ProjectManagement, "Projects",
				kLocal, LocalProjectFolderUpdate, schema::String("project", true), schema::String("path", true),
				schema::NonEmptyString("name"), schema::String("description"), schema::StringOrNull("parent"));
			BINJAD_PROJECT_TOOL(LocalProjectFolderDeleteTool, "bn_local_project_folder_delete",
				"Recursively delete a local project folder selected by project and path.", ProjectManagement,
				"Projects", kLocal, LocalProjectFolderDelete, schema::String("project", true),
				schema::String("path", true), schema::Boolean("recursive", true));
			BINJAD_PROJECT_TOOL(LocalProjectFileUpdateTool, "bn_local_project_file_update",
				"Update a local project file selected by project and path: set, replace, or clear its description, "
				"rename it, or move it to a folder path.",
				ProjectManagement, "Projects", kLocal, LocalProjectFileUpdate, schema::String("project", true),
				schema::String("path", true), schema::NonEmptyString("name"),
				schema::String("description", false,
					"Set or replace the project-file description; pass an empty string to clear it."),
				schema::StringOrNull(
					"folder", false, "Project-relative destination folder path, or null for project root."));
			BINJAD_PROJECT_TOOL(LocalProjectFileDeleteTool, "bn_local_project_file_delete",
				"Delete a local project file selected by project and path.", ProjectManagement, "Projects", kLocal,
				LocalProjectFileDelete, schema::String("project", true), schema::String("path", true),
				schema::Boolean("delete", true));
			BINJAD_PROJECT_TOOL(ProjectTextReadTool, "bn_project_text_read",
				"Read a UTF-8 project file by lines with resumable pagination and an optional case-insensitive line "
				"query.",
				ProjectManagement, "Projects", ToolCallAvailability::None, ProjectTextRead,
				schema::String("project", true), schema::String("path", true),
				schema::String(
					"query", false, "Optional case-insensitive line filter; offsets apply to matching lines."),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
			BINJAD_PROJECT_TOOL(ProjectJsonReadTool, "bn_project_json_read",
				"Navigate a project JSON file by RFC 6901 pointer; paginate object keys or array indexes without "
				"expanding unrelated subtrees.",
				ProjectManagement, "Projects", ToolCallAvailability::None, ProjectJsonRead,
				schema::String("project", true), schema::String("path", true),
				schema::String("pointer", false,
					"RFC 6901 JSON Pointer selecting the value to inspect; omit or use an empty string for the root."),
				schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 200, 50));
		}  // namespace management_tools

		namespace upload_tools {
			using rapidjson::StringBuffer;
			using rapidjson::Writer;

			std::string_view UploadStateName(upload::UploadState state)
			{
				switch (state)
				{
				case upload::UploadState::Ready:
					return "ready";
				case upload::UploadState::Receiving:
					return "receiving";
				case upload::UploadState::Completed:
					return "completed";
				case upload::UploadState::Committing:
					return "committing";
				case upload::UploadState::Committed:
					return "committed";
				}
				return "unknown";
			}

			template <typename WriterType>
			void WriteUpload(WriterType& writer, const upload::UploadRecord& upload)
			{
				writer.StartObject();
				writer.Key("id");
				writer.String(upload.id.data(), static_cast<rapidjson::SizeType>(upload.id.size()));
				writer.Key("analysisSession");
				writer.String(
					upload.analysisSession.data(), static_cast<rapidjson::SizeType>(upload.analysisSession.size()));
				writer.Key("project");
				writer.String(upload.project.data(), static_cast<rapidjson::SizeType>(upload.project.size()));
				writer.Key("filename");
				writer.String(upload.filename.data(), static_cast<rapidjson::SizeType>(upload.filename.size()));
				writer.Key("state");
				const auto state = UploadStateName(upload.state);
				writer.String(state.data(), static_cast<rapidjson::SizeType>(state.size()));
				writer.Key("createdAt");
				writer.Uint64(upload.createdAtUnix);
				writer.Key("expiresAt");
				writer.Uint64(upload.expiresAtUnix);
				writer.Key("size");
				writer.Uint64(upload.size);
				if (!upload.sha256.empty())
				{
					writer.Key("sha256");
					writer.String(upload.sha256.data(), static_cast<rapidjson::SizeType>(upload.sha256.size()));
				}
				writer.EndObject();
			}

			FoundationResult UploadGetUrl(const ToolCallContext& context)
			{
				if (!context.currentSession || !context.uploads)
					return ToolCallSuccess(
						context, detail::ErrorJson("analysis session and upload service are required"), true);
				const auto projectMember = context.arguments.FindMember("project");
				const auto filenameMember = context.arguments.FindMember("filename");
				const std::string project(projectMember->value.GetString(), projectMember->value.GetStringLength());
				const std::string filename(filenameMember->value.GetString(), filenameMember->value.GetStringLength());
				const auto issued = context.uploads->Issue(context.principal.id, context.currentSession->reference,
					project, filename, context.unixNow, context.now);
				if (!issued.upload)
					return ToolCallSuccess(context, detail::ErrorJson(issued.error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("id");
				writer.String(issued.upload->id.data(), static_cast<rapidjson::SizeType>(issued.upload->id.size()));
				writer.Key("url");
				writer.String(issued.url.data(), static_cast<rapidjson::SizeType>(issued.url.size()));
				writer.Key("project");
				writer.String(
					issued.upload->project.data(), static_cast<rapidjson::SizeType>(issued.upload->project.size()));
				writer.Key("filename");
				writer.String(
					issued.upload->filename.data(), static_cast<rapidjson::SizeType>(issued.upload->filename.size()));
				writer.Key("expiresAt");
				writer.Uint64(issued.upload->expiresAtUnix);
				writer.Key("method");
				writer.String("PUT");
				writer.Key("contentType");
				writer.String("application/octet-stream");
				writer.Key("singleUse");
				writer.Bool(true);
				writer.Key("requiresBearerAuthentication");
				writer.Bool(context.config.uploads.requireBearerAuthentication);
				writer.Key("authorization");
				writer.String(context.config.uploads.requireBearerAuthentication ?
						"Bearer token plus URL capability" :
						"URL capability");
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult UploadList(const ToolCallContext& context)
			{
				if (!context.uploads)
					return ToolCallSuccess(context, detail::ErrorJson("upload service is unavailable"), true);
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = context.arguments.FindMember("offset"); member != context.arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = context.arguments.FindMember("limit"); member != context.arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());
				const auto uploads = context.uploads->List(context.principal.id);
				offset = std::min(offset, uploads.size());
				const auto end = offset + std::min(limit, uploads.size() - offset);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("uploads");
				writer.StartArray();
				for (std::size_t index = offset; index < end; ++index)
					WriteUpload(writer, uploads[index]);
				writer.EndArray();
				writer.Key("count");
				writer.Uint64(end - offset);
				writer.Key("total");
				writer.Uint64(uploads.size());
				writer.Key("nextOffset");
				writer.Uint64(end);
				writer.Key("truncated");
				writer.Bool(end < uploads.size());
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult UploadCancel(const ToolCallContext& context)
			{
				if (!context.uploads)
					return ToolCallSuccess(context, detail::ErrorJson("upload service is unavailable"), true);
				const auto member = context.arguments.FindMember("id");
				const std::string id(member->value.GetString(), member->value.GetStringLength());
				if (const auto error = context.uploads->Cancel(context.principal.id, id); !error.empty())
					return ToolCallSuccess(context, detail::ErrorJson(error), true);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("id");
				writer.String(id.data(), static_cast<rapidjson::SizeType>(id.size()));
				writer.Key("cancelled");
				writer.Bool(true);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
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
				switch (item.sourceKind)
				{
				case session::OpenItemSourceKind::ArbitraryPath:
					writer.String("path");
					break;
				case session::OpenItemSourceKind::LocalProject:
					writer.String("local_project");
					break;
				case session::OpenItemSourceKind::CollaborationProject:
					writer.String("collaboration_project");
					break;
				}
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
						writer.String(
							view.architecture.data(), static_cast<rapidjson::SizeType>(view.architecture.size()));
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

			std::string UploadCommittedJson(const upload::UploadRecord& upload,
				const project::LocalProjectFileRecord& file, const std::optional<session::OpenItemRecord>& openItem)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("id");
				writer.String(upload.id.data(), static_cast<rapidjson::SizeType>(upload.id.size()));
				writer.Key("project");
				writer.String(upload.project.data(), static_cast<rapidjson::SizeType>(upload.project.size()));
				writer.Key("path");
				writer.String(file.path.data(), static_cast<rapidjson::SizeType>(file.path.size()));
				writer.Key("size");
				writer.Uint64(upload.size);
				writer.Key("sha256");
				writer.String(upload.sha256.data(), static_cast<rapidjson::SizeType>(upload.sha256.size()));
				if (openItem)
				{
					writer.Key("openItem");
					WriteOpenItem(writer, *openItem);
				}
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			std::string JobJson(const session::JobRecord& job)
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
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
				writer.EndObject();
				return {buffer.GetString(), buffer.GetSize()};
			}

			FoundationResult UploadCommit(const ToolCallContext& context)
			{
				if (!context.currentSession || !context.uploads || !context.jobs
					|| (context.config.EffectiveMode() == Mode::Local && !context.projectCoordinator)
					|| (context.config.EffectiveMode() == Mode::Collaboration && !context.collaborationManager))
					return ToolCallSuccess(context,
						detail::ErrorJson("analysis session, upload, project, and job services are required"), true);
				const auto id = detail::RequiredString(context.arguments, "id");
				auto folder = detail::OptionalString(context.arguments, "folder");
				bool open = detail::OptionalBoolean(context.arguments, "open", false);
				const bool analyze = detail::OptionalBoolean(context.arguments, "analyze", false);
				if (analyze)
					open = true;
				if (const auto committed =
						context.uploads->FindCommitResult(context.principal.id, context.currentSession->reference, id))
					return ToolCallSuccess(context, *committed);
				auto payload = context.uploads->PreparePayload(
					context.principal.id, context.currentSession->reference, id, context.now);
				if (!payload.first)
					return ToolCallSuccess(context, detail::ErrorJson(payload.second), true);
				if (folder)
				{
					const auto normalized = detail::ProjectPath(*folder);
					if (!normalized)
					{
						context.uploads->CommitFailed(context.principal.id, id);
						return ToolCallInvalidArguments(
							context, "folder path must be a contained project-relative path");
					}
					folder = *normalized;
				}
				const auto owner = context.principal.id;
				const auto analysisSession = context.currentSession->reference;
				const auto created =
					context.jobs->Create(owner, analysisSession, {}, "upload_commit", context.unixNow, context.now);
				if (!created.job)
				{
					context.uploads->CommitFailed(owner, id);
					return ToolCallSuccess(context, detail::ErrorJson(created.error), true);
				}
				const auto job = created.job->reference;
				context.jobs->Start(owner, job, context.unixNow);
				if (context.attached)
					context.attached(job, [jobs = context.jobs, owner, job] { (void)jobs->Cancel(owner, job); });
				context.jobs->ReportProgress(owner, job, "commit", 0, 1, "committing upload", context.unixNow);
				if (context.progress)
				{
					const auto info = context.jobs->Info(owner, job);
					if (info.job)
						context.progress(*info.job);
				}
				const auto workerError = context.jobs->StartWorker(
					[jobs = context.jobs, uploads = context.uploads, projectCoordinator = context.projectCoordinator,
						collaborationManager = context.collaborationManager, principal = context.principal,
						collaborationMode = context.config.EffectiveMode() == Mode::Collaboration,
						fileCoordinator = context.fileCoordinator, scheduler = context.scheduler,
						openItems = context.openItems, owner, analysisSession, id, folder = std::move(folder), open,
						analyze, job, progress = context.progress, payload = std::move(*payload.first)]() mutable {
						const auto info = jobs->Info(owner, job);
						if (info.job && info.job->cancelRequested)
						{
							uploads->CommitFailed(owner, id);
							jobs->MarkCancelled(
								owner, job, detail::ErrorJson("job cancelled"), detail::CurrentUnixSeconds());
							return;
						}
						const auto target = folder ?
							(std::filesystem::path(*folder) / payload.upload.filename).generic_string() :
							payload.upload.filename;
						project::LocalProjectFileRecord committedFile;
						session::OpenItemSourceKind sourceKind = session::OpenItemSourceKind::LocalProject;
						std::string commitError;
						if (collaborationMode)
						{
							const auto committed = collaborationManager->UploadFile(principal, payload.upload.project,
								payload.path, folder.value_or(""), payload.upload.filename);
							if (committed.value)
							{
								committedFile.internalId = committed.value->internalId;
								committedFile.path = committed.value->path;
								committedFile.name = committed.value->name;
								committedFile.description = committed.value->description;
							}
							else
								commitError = committed.error;
							sourceKind = session::OpenItemSourceKind::CollaborationProject;
						}
						else
						{
							const auto committed = projectCoordinator->CommitFile(
								payload.upload.project, target, payload.path, false, true, "Uploaded file");
							if (committed.value)
								committedFile = *committed.value;
							else
								commitError = committed.error
									+ "; the completed upload remains staged; retry bn_upload_commit with the same id after "
									  "resolving the project write failure";
						}
						if (!commitError.empty())
						{
							uploads->CommitFailed(owner, id);
							jobs->Fail(owner, job, detail::ErrorJson(commitError), detail::CurrentUnixSeconds());
							return;
						}
						const auto committedJson = UploadCommittedJson(payload.upload, committedFile, {});
						uploads->RecordCommit(owner, id, committedJson, false);
						const auto afterCommit = jobs->Info(owner, job);
						if (afterCommit.job && afterCommit.job->cancelRequested)
						{
							uploads->RecordCommit(owner, id, committedJson);
							jobs->MarkCancelled(owner, job, committedJson, detail::CurrentUnixSeconds());
							return;
						}
						std::optional<session::OpenItemRecord> openedRecord;
						if (open)
						{
							if (!fileCoordinator || !openItems)
							{
								uploads->RecordCommit(owner, id, committedJson);
								jobs->Fail(owner, job, detail::ErrorJson("file-child service is unavailable"),
									detail::CurrentUnixSeconds());
								return;
							}
							const security::TokenRecord workerPrincipal {
								owner, {}, security::TokenRole::Admin, {}, 0, {}};
							auto opened = fileCoordinator->OpenManagedPath(workerPrincipal, analysisSession,
								payload.path, "{}", true, sourceKind, committedFile.path, payload.upload.project);
							if (!opened.value)
							{
								uploads->RecordCommit(owner, id, committedJson);
								jobs->Fail(owner, job, detail::ErrorJson(opened.error), detail::CurrentUnixSeconds());
								return;
							}
							openedRecord = *opened.value;
							if (analyze)
							{
								const auto recommended = std::find_if(opened.value->binaryViews.begin(),
									opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
								if (recommended == opened.value->binaryViews.end())
								{
									fileCoordinator->Close(owner, opened.value->reference, true);
									uploads->RecordCommit(owner, id, committedJson);
									jobs->Fail(owner, job,
										detail::ErrorJson("uploaded file has no recommended BinaryView"),
										detail::CurrentUnixSeconds());
									return;
								}
								auto materialized = fileCoordinator->OpenBinaryView(
									owner, analysisSession, recommended->reference, "{}", false);
								if (!materialized.value)
								{
									fileCoordinator->Close(owner, opened.value->reference, true);
									uploads->RecordCommit(owner, id, committedJson);
									jobs->Fail(owner, job, detail::ErrorJson(materialized.error),
										detail::CurrentUnixSeconds());
									return;
								}
								std::optional<overseer::AnalysisScheduler::Lease> lease;
								if (scheduler)
								{
									std::string scheduleError;
									lease = scheduler->Acquire(
										{owner, analysisSession, opened.value->reference, job},
										[fileCoordinator, owner, analysisSession, view = recommended->reference](
											std::size_t workers) {
											(void)fileCoordinator->SetWorkerCount(
												owner, analysisSession, view, workers);
										},
										scheduleError);
									if (!lease)
									{
										fileCoordinator->Close(owner, opened.value->reference, true);
										uploads->RecordCommit(owner, id, committedJson);
										jobs->MarkCancelled(
											owner, job, detail::ErrorJson(scheduleError), detail::CurrentUnixSeconds());
										return;
									}
								}
								const auto analyzed = fileCoordinator->UpdateAnalysisAndWait(owner, analysisSession,
									recommended->reference, [jobs, owner, job, progress](const ipc::Progress& update) {
										jobs->ReportProgress(owner, job, update.phase(), update.completed(),
											update.total(), update.message(), detail::CurrentUnixSeconds());
										if (progress)
										{
											const auto current = jobs->Info(owner, job);
											if (current.job)
												progress(*current.job);
										}
									});
								if (!analyzed.value || analyzed.value->state() != ipc::ANALYSIS_STATE_COMPLETE)
								{
									fileCoordinator->Close(owner, opened.value->reference, true);
									uploads->RecordCommit(owner, id, committedJson);
									jobs->Fail(owner, job,
										detail::ErrorJson(analyzed.value ? analyzed.value->error() : analyzed.error),
										detail::CurrentUnixSeconds());
									return;
								}
								openedRecord = openItems->FindOpenItem(owner, opened.value->reference);
							}
						}
						const auto resultJson = UploadCommittedJson(payload.upload, committedFile, openedRecord);
						uploads->RecordCommit(owner, id, resultJson);
						jobs->Complete(owner, job, resultJson, detail::CurrentUnixSeconds());
					});
				if (!workerError.empty())
				{
					context.uploads->CommitFailed(owner, id);
					context.jobs->Fail(owner, job, detail::ErrorJson(workerError), context.unixNow);
				}
				const auto waited = context.jobs->WaitForTerminal(owner, job, context.config.jobs.detachAfter);
				if (!waited.job)
					return ToolCallSuccess(context, detail::ErrorJson(waited.error), true);
				if (waited.job->state == session::JobState::Queued || waited.job->state == session::JobState::Running)
					return ToolCallSuccess(context, JobJson(*waited.job));
				const auto result = context.jobs->TakeResult(owner, job);
				if (!result.job)
					return ToolCallSuccess(context, detail::ErrorJson(result.error), true);
				return ToolCallSuccess(
					context, result.job->resultJson, result.job->state != session::JobState::Complete);
			}

			BINJAD_PROJECT_TOOL(UploadGetUrlTool, "bn_upload_get_url",
				"Issue a session-, project-, and filename-bound one-time upload capability with transport "
				"instructions.",
				Core, "Uploads", ToolCallAvailability::None, UploadGetUrl, schema::String("project", true),
				schema::String("filename", true));
			BINJAD_PROJECT_TOOL(UploadCommitTool, "bn_upload_commit",
				"Commit a completed staged upload idempotently to its bound project.", Core, "Uploads",
				ToolCallAvailability::None, UploadCommit, schema::String("id", true),
				schema::NonEmptyString("folder", false, "Project-relative folder path; missing folders are created."),
				schema::Boolean("open"), schema::Boolean("analyze"));
			BINJAD_PROJECT_TOOL(UploadListTool, "bn_upload_list", "List staged uploads owned by this bearer token.",
				Core, "Uploads", ToolCallAvailability::None, UploadList, schema::Integer("offset", false, 0),
				schema::Integer("limit", false, 1, 1000, 50,
					"Return at most 50 items by default; continue with the response nextOffset."));
			BINJAD_PROJECT_TOOL(UploadCancelTool, "bn_upload_cancel", "Cancel and remove an inactive staged upload.",
				Core, "Uploads", ToolCallAvailability::None, UploadCancel, schema::String("id", true));
		}  // namespace upload_tools

#undef BINJAD_PROJECT_TOOL
#undef BINJAD_RESTRICTED_PROJECT_TOOL
	}  // namespace

	void RegisterCoreProjectTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<catalog_tools::LocalProjectListTool>());
		tools.emplace_back(std::make_unique<catalog_tools::LocalProjectInfoTool>());
		tools.emplace_back(std::make_unique<catalog_tools::LocalProjectFileListTool>());
		tools.emplace_back(std::make_unique<catalog_tools::LocalProjectCreateTool>());
		tools.emplace_back(std::make_unique<catalog_tools::CollaborationProjectListTool>());
		tools.emplace_back(std::make_unique<catalog_tools::CollaborationProjectInfoTool>());
		tools.emplace_back(std::make_unique<catalog_tools::CollaborationProjectFileListTool>());
		tools.emplace_back(std::make_unique<catalog_tools::ProjectFileOpenTool>());
	}

	void RegisterProjectManagementTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<management_tools::LocalProjectRegisterTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFileImportTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFileImportBatchTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectUpdateTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFolderListTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFolderCreateTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFolderUpdateTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFolderDeleteTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFileUpdateTool>());
		tools.emplace_back(std::make_unique<management_tools::LocalProjectFileDeleteTool>());
		tools.emplace_back(std::make_unique<management_tools::ProjectTextReadTool>());
		tools.emplace_back(std::make_unique<management_tools::ProjectJsonReadTool>());
	}

	void RegisterCoreUploadTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<upload_tools::UploadGetUrlTool>());
		tools.emplace_back(std::make_unique<upload_tools::UploadCommitTool>());
		tools.emplace_back(std::make_unique<upload_tools::UploadListTool>());
		tools.emplace_back(std::make_unique<upload_tools::UploadCancelTool>());
	}
}  // namespace binjad::mcp
