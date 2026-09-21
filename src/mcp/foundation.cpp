#include "binjad/mcp/foundation.hpp"

#include "binjad/overseer/file_child_coordinator.hpp"
#include "binjad/overseer/analysis_scheduler.hpp"
#include "binjad/overseer/collaboration_child_manager.hpp"
#include "binjad/overseer/project_child_coordinator.hpp"
#include "binjad/platform/cpu.hpp"
#include "binjad/platform/paths.hpp"
#include "binjad/project/local_project_registry.hpp"
#include "binjad/project/collaboration_project_registry.hpp"
#include "binjad/session/open_item_registry.hpp"
#include "binjad/session/job_registry.hpp"
#include "binjad/upload/upload_registry.hpp"

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

namespace binjad::mcp
{
namespace
{
using rapidjson::Document;
using rapidjson::StringBuffer;
using rapidjson::Value;
using rapidjson::Writer;

bool IsSharedCachePrimaryPath(std::string_view path)
{
    const auto name = std::filesystem::path(path).filename().string();
    return name.starts_with("dyld_shared_cache_") && name.find('.') == std::string::npos;
}

bool IsSharedCacheCompanionPath(std::string_view primary, std::string_view candidate)
{
    const std::filesystem::path primaryPath(primary);
    const std::filesystem::path candidatePath(candidate);
    return candidatePath.parent_path() == primaryPath.parent_path() &&
        candidatePath.filename().string().starts_with(
            primaryPath.filename().string() + ".");
}

template <typename OutputStream>
void WriteId(Writer<OutputStream>& writer, const RequestId& id)
{
    std::visit([&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, std::string>)
            writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
        else if constexpr (std::is_same_v<T, std::int64_t>)
            writer.Int64(value);
        else
            writer.Uint64(value);
    }, id);
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
        case session::OpenItemSourceKind::ArbitraryPath: return "path";
        case session::OpenItemSourceKind::LocalProject: return "local_project";
        case session::OpenItemSourceKind::CollaborationProject: return "collaboration_project";
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
    writer.String(view.analysisSession.data(),
        static_cast<rapidjson::SizeType>(view.analysisSession.size()));
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
        writer.String(view.architecture.data(),
            static_cast<rapidjson::SizeType>(view.architecture.size()));
    }
    if (!view.platform.empty())
    {
        writer.Key("platform");
        writer.String(view.platform.data(),
            static_cast<rapidjson::SizeType>(view.platform.size()));
    }
    if (view.created)
    {
        writer.Key("start"); writer.Uint64(view.start);
        writer.Key("end"); writer.Uint64(view.end);
        writer.Key("entryPoint"); writer.Uint64(view.entryPoint);
    }
    writer.EndObject();
}

std::string BinaryViewLoadSettingsJson(const session::BinaryViewRecord& view)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("binaryView"); writer.String(view.reference.data(),
        static_cast<rapidjson::SizeType>(view.reference.size()));
    writer.Key("viewType"); writer.String(view.viewType.data(),
        static_cast<rapidjson::SizeType>(view.viewType.size()));
    writer.Key("configurable"); writer.Bool(!view.loadSettingsSchemaJson.empty());
    if (!view.loadSettingsSchemaJson.empty())
    {
        writer.Key("schema");
        writer.RawValue(view.loadSettingsSchemaJson.data(),
            view.loadSettingsSchemaJson.size(), rapidjson::kObjectType);
    }
    if (!view.effectiveLoadSettingsJson.empty())
    {
        writer.Key("effective");
        writer.RawValue(view.effectiveLoadSettingsJson.data(),
            view.effectiveLoadSettingsJson.size(), rapidjson::kObjectType);
    }
    writer.Key("nextAction");
    if (view.viewType == "Raw")
        writer.String("Raw does not accept loader settings. Select the Mapped candidate for raw firmware, inspect its schema, and pass fully qualified loader.* settings to bn_binary_view_open.");
    else if (!view.created)
        writer.String("Pass only keys from schema.settings to bn_binary_view_open options. loader.segments and loader.sections are serialized JSON strings.");
    else
        writer.String("The effective settings and materialized BinaryView metadata reflect the current view.");
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

template <typename WriterType>
void WriteOpenItem(WriterType& writer, const session::OpenItemRecord& item)
{
    writer.StartObject();
    writer.Key("openItem");
    writer.String(item.reference.data(), static_cast<rapidjson::SizeType>(item.reference.size()));
    writer.Key("analysisSession");
    writer.String(item.analysisSession.data(),
        static_cast<rapidjson::SizeType>(item.analysisSession.size()));
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
    if (std::any_of(item.binaryViews.begin(), item.binaryViews.end(),
            [](const auto& view) { return !view.created; }))
    {
        writer.Key("nextAction");
        if (item.source.ends_with(".bndb"))
            writer.String("Call bn_binary_view_open on the recommended:true binaryView with analyze:false to reuse saved analysis.");
        else
            writer.String("Call bn_binary_view_open on the recommended:true binaryView before using BinaryView tools.");
    }
    writer.EndObject();
}

std::string BinaryViewJson(const session::BinaryViewRecord& view)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteBinaryView(writer, view);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string OpenItemJson(const session::OpenItemRecord& item)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteOpenItem(writer, item);
    return {buffer.GetString(), buffer.GetSize()};
}

template <typename Record, typename WriteRecord>
std::string PaginatedJson(std::string_view key, const std::vector<Record>& records,
    std::size_t offset, std::size_t limit, WriteRecord writeRecord)
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
    if (end < records.size()) writer.Uint64(end); else writer.Null();
    writer.Key("truncated");
    writer.Bool(end < records.size());
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::string OpenItemsJson(const std::vector<session::OpenItemRecord>& records,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("openItems", records, offset, limit,
        [](auto& writer, const auto& record) { WriteOpenItem(writer, record); });
}

std::string BinaryViewsJson(const std::vector<session::BinaryViewRecord>& records,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("binaryViews", records, offset, limit,
        [](auto& writer, const auto& record) { WriteBinaryView(writer, record); });
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
        writer.String(job.analysisSession->data(),
            static_cast<rapidjson::SizeType>(job.analysisSession->size()));
    }
    if (job.binaryView)
    {
        writer.Key("binaryView");
        writer.String(job.binaryView->data(),
            static_cast<rapidjson::SizeType>(job.binaryView->size()));
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
        writer.String(job.progress->phase.data(),
            static_cast<rapidjson::SizeType>(job.progress->phase.size()));
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
        writer.String("Call bn_job_info no more than every 10 seconds; when terminal, call bn_job_result exactly once. Avoid polling bn_analysis_status for this operation.");
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

std::string JobJson(const session::JobRecord& job, bool includeResult = false)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteJob(writer, job, includeResult);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string JobsJson(const std::vector<session::JobRecord>& jobs,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("jobs", jobs, offset, limit,
        [](auto& writer, const auto& record) { WriteJob(writer, record, false); });
}

template <typename WriterType>
void WriteProject(WriterType& writer, const project::LocalProjectRecord& project)
{
    writer.StartObject();
    writer.Key("project");
    writer.String(project.reference.data(),
        static_cast<rapidjson::SizeType>(project.reference.size()));
    writer.Key("name");
    writer.String(project.name.data(), static_cast<rapidjson::SizeType>(project.name.size()));
    writer.Key("description");
    writer.String(project.description.data(),
        static_cast<rapidjson::SizeType>(project.description.size()));
    writer.EndObject();
}

std::string ProjectJson(const project::LocalProjectRecord& project)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteProject(writer, project);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string ProjectsJson(const std::vector<project::LocalProjectRecord>& projects,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("projects", projects, offset, limit,
        [](auto& writer, const auto& project) { WriteProject(writer, project); });
}

template <typename WriterType>
void WriteProjectFile(WriterType& writer, const project::LocalProjectFileRecord& file)
{
    writer.StartObject();
    writer.Key("path");
    writer.String(file.path.data(), static_cast<rapidjson::SizeType>(file.path.size()));
    writer.Key("name");
    writer.String(file.name.data(), static_cast<rapidjson::SizeType>(file.name.size()));
    writer.Key("description");
    writer.String(file.description.data(),
        static_cast<rapidjson::SizeType>(file.description.size()));
    writer.Key("createdAt");
    writer.Int64(file.creationTimestamp);
    if (file.folderPath)
    {
        writer.Key("folder");
        writer.String(file.folderPath->data(),
            static_cast<rapidjson::SizeType>(file.folderPath->size()));
    }
    writer.EndObject();
}

std::string ProjectFileJson(const project::LocalProjectFileRecord& file)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteProjectFile(writer, file);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string ProjectFilesJson(const std::vector<project::LocalProjectFileRecord>& files,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("files", files, offset, limit,
        [](auto& writer, const auto& file) { WriteProjectFile(writer, file); });
}

template <typename WriterType>
void WriteProjectFolder(WriterType& writer,
    const project::LocalProjectFolderRecord& folder)
{
    writer.StartObject();
    writer.Key("path");
    writer.String(folder.path.data(), static_cast<rapidjson::SizeType>(folder.path.size()));
    writer.Key("name");
    writer.String(folder.name.data(), static_cast<rapidjson::SizeType>(folder.name.size()));
    writer.Key("description");
    writer.String(folder.description.data(),
        static_cast<rapidjson::SizeType>(folder.description.size()));
    if (folder.parentPath)
    {
        writer.Key("parent");
        writer.String(folder.parentPath->data(),
            static_cast<rapidjson::SizeType>(folder.parentPath->size()));
    }
    writer.EndObject();
}

std::string ProjectFolderJson(const project::LocalProjectFolderRecord& folder)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    WriteProjectFolder(writer, folder);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string ProjectFoldersJson(
    const std::vector<project::LocalProjectFolderRecord>& folders,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("folders", folders, offset, limit,
        [](auto& writer, const auto& folder) { WriteProjectFolder(writer, folder); });
}

template <typename WriterType>
void WriteCollaborationProject(WriterType& writer,
    const project::CollaborationProjectRecord& project)
{
    writer.StartObject();
    writer.Key("project"); writer.String(project.reference.data(),
        static_cast<rapidjson::SizeType>(project.reference.size()));
    writer.Key("name"); writer.String(project.name.data(),
        static_cast<rapidjson::SizeType>(project.name.size()));
    writer.Key("description"); writer.String(project.description.data(),
        static_cast<rapidjson::SizeType>(project.description.size()));
    writer.Key("createdAt"); writer.Int64(project.created);
    writer.Key("lastModified"); writer.Int64(project.lastModified);
    writer.Key("admin"); writer.Bool(project.admin);
    writer.EndObject();
}

std::string CollaborationProjectJson(
    const project::CollaborationProjectRecord& project)
{
    StringBuffer buffer; Writer<StringBuffer> writer(buffer);
    WriteCollaborationProject(writer, project);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string CollaborationProjectsJson(
    const std::vector<project::CollaborationProjectRecord>& projects,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("projects", projects, offset, limit,
        [](auto& writer, const auto& project) {
            WriteCollaborationProject(writer, project);
        });
}

template <typename WriterType>
void WriteCollaborationFile(WriterType& writer,
    const project::CollaborationFileRecord& file)
{
    writer.StartObject();
    writer.Key("path"); writer.String(file.path.data(),
        static_cast<rapidjson::SizeType>(file.path.size()));
    writer.Key("name"); writer.String(file.name.data(),
        static_cast<rapidjson::SizeType>(file.name.size()));
    writer.Key("description"); writer.String(file.description.data(),
        static_cast<rapidjson::SizeType>(file.description.size()));
    writer.Key("size"); writer.Uint64(file.size);
    writer.Key("type");
    switch (file.type)
    {
        case RawDataFileType: writer.String("raw"); break;
        case BinaryViewAnalysisFileType: writer.String("analysis"); break;
        case TypeArchiveFileType: writer.String("type_archive"); break;
        default: writer.String("unknown"); break;
    }
    writer.EndObject();
}

std::string CollaborationFilesJson(
    const std::vector<project::CollaborationFileRecord>& files,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("files", files, offset, limit,
        [](auto& writer, const auto& file) { WriteCollaborationFile(writer, file); });
}

std::string SessionsJson(const std::vector<session::AnalysisSessionRecord>& sessions,
    std::size_t offset, std::size_t limit)
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
        case FairnessUnit::AnalysisSession: return "analysis_session";
        case FairnessUnit::BearerToken: return "bearer_token";
        case FairnessUnit::File: return "file";
        case FairnessUnit::AnalysisJob: return "job";
    }
    return {};
}

struct ComputeJsonResult
{
    std::string json;
    std::string error;
};

ComputeJsonResult ComputeJson(const Config& config,
    const overseer::AnalysisScheduler* scheduler = nullptr)
{
    if (scheduler)
    {
        const auto status = scheduler->Status();
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("logicalCpuCount"); writer.Uint64(status.logicalCpuCount);
        writer.Key("configuredPercentage"); writer.Uint(config.cpu.percentage);
        writer.Key("workerBudget"); writer.Uint64(status.workerBudget);
        writer.Key("allocatedWorkers"); writer.Uint64(status.allocatedWorkers);
        writer.Key("activeAnalyses"); writer.Uint64(status.activeAnalyses);
        writer.Key("queuedAnalyses"); writer.Uint64(status.queuedAnalyses);
        writer.Key("fairness");
        const auto fairness = FairnessName(config.cpu.fairness);
        writer.String(fairness.data(), static_cast<rapidjson::SizeType>(fairness.size()));
        writer.EndObject();
        return {{buffer.GetString(), buffer.GetSize()}, {}};
    }
    const auto capacity = platform::ActiveLogicalCpuCount();
    if (!capacity.logicalCpuCount)
        return {{}, capacity.error};
    const auto budget = std::max<std::size_t>(1,
        *capacity.logicalCpuCount * config.cpu.percentage / 100);
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

std::uint64_t CurrentUnixSeconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
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

std::string ToolResult(const ValidatedRequest& request, std::string_view structured,
    bool isError, std::string_view serverVersion)
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
void EmptySchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.EndObject();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void SessionTargetSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("analysisSession");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("analysisSession");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void CurrentSessionTargetSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("analysisSession");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.EndObject();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void PaginationSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("offset");
    writer.StartObject();
    writer.Key("type");
    writer.String("integer");
    writer.Key("minimum");
    writer.Uint(0);
    writer.EndObject();
    writer.Key("limit");
    writer.StartObject();
    writer.Key("type");
    writer.String("integer");
    writer.Key("minimum");
    writer.Uint(1);
    writer.Key("maximum");
    writer.Uint(1000);
    writer.Key("default");
    writer.Uint(50);
    writer.Key("description");
    writer.String("Return at most 50 items by default; continue with the response nextOffset.");
    writer.EndObject();
    writer.EndObject();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void OpenItemOpenSchemaImpl(WriterType& writer, bool requireProject)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("project");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("path");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("kind");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.Key("enum");
    writer.StartArray();
    writer.String("auto");
    writer.String("file");
    writer.EndArray();
    writer.EndObject();
    writer.Key("options");
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("description");
    writer.String("Candidate-specific Binary Ninja load settings. Call bn_binary_view_load_settings first; Raw accepts none, while Mapped exposes fully qualified loader.* keys and requires serialized JSON strings for segments and sections.");
    writer.EndObject();
    writer.Key("reuseDatabase");
    writer.StartObject();
    writer.Key("type");
    writer.String("boolean");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    if (requireProject)
        writer.String("project");
    writer.String("path");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void OpenItemOpenSchema(WriterType& writer)
{
    OpenItemOpenSchemaImpl(writer, false);
}

template <typename WriterType>
void ProjectTargetSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("project");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("project");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void ProjectFilesSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("project");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("offset");
    writer.StartObject();
    writer.Key("type");
    writer.String("integer");
    writer.Key("minimum");
    writer.Uint(0);
    writer.EndObject();
    writer.Key("limit");
    writer.StartObject();
    writer.Key("type");
    writer.String("integer");
    writer.Key("minimum");
    writer.Uint(1);
    writer.Key("maximum");
    writer.Uint(1000);
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("project");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void ProjectOpenSchema(WriterType& writer)
{
    OpenItemOpenSchemaImpl(writer, true);
}

template <typename WriterType>
void StringProperty(WriterType& writer, std::string_view name, bool nullable = false)
{
    writer.Key(name.data(), static_cast<rapidjson::SizeType>(name.size()));
    writer.StartObject();
    writer.Key("type");
    if (nullable)
    {
        writer.StartArray();
        writer.String("string");
        writer.String("null");
        writer.EndArray();
    }
    else
        writer.String("string");
    writer.EndObject();
}

template <typename WriterType>
void ProjectFileListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project");
    writer.Key("folder"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Exact project-relative folder path."); writer.EndObject();
    StringProperty(writer, "pathPrefix"); StringProperty(writer, "query");
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        {
            writer.Key("maximum"); writer.Uint(1000);
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("project"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectTextReadSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "path");
    writer.Key("query"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Optional case-insensitive line filter; offsets apply to matching lines."); writer.EndObject();
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200);
    writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("project"); writer.String("path"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectJsonReadSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "path");
    writer.Key("pointer"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("RFC 6901 JSON Pointer selecting the value to inspect; omit or use an empty string for the root."); writer.EndObject();
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200);
    writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("project"); writer.String("path"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectCreateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "name"); StringProperty(writer, "path");
    StringProperty(writer, "description"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("name"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectRegisterSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "path"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("path"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void LocalProjectFileImportSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "source");
    writer.Key("folder"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Project-relative destination folder path."); writer.EndObject();
    StringProperty(writer, "name");
    writer.Key("description"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Initial project-file description; it can later be changed or cleared with bn_local_project_file_update.");
    writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("source"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void LocalProjectFileImportBatchSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project");
    writer.Key("folder"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Project-relative destination folder path."); writer.EndObject();
    writer.Key("files"); writer.StartObject(); writer.Key("type"); writer.String("array");
    writer.Key("minItems"); writer.Uint(1); writer.Key("maxItems"); writer.Uint(1000);
    writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "source");
    StringProperty(writer, "name");
    writer.Key("description"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Initial project-file description for this imported file.");
    writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("source"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
    writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("files"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectUpdateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "name");
    StringProperty(writer, "description"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FolderCreateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "parent");
    StringProperty(writer, "name"); StringProperty(writer, "description"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project"); writer.String("name"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FolderUpdateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "path");
    StringProperty(writer, "name");
    StringProperty(writer, "description"); StringProperty(writer, "parent", true); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("path"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FolderDeleteSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "project");
    StringProperty(writer, "path");
    writer.Key("recursive"); writer.StartObject(); writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("path"); writer.String("recursive"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FileUpdateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "project");
    StringProperty(writer, "path");
    StringProperty(writer, "name");
    writer.Key("description"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Set or replace the project-file description; pass an empty string to clear it.");
    writer.EndObject();
    writer.Key("folder"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("string"); writer.String("null"); writer.EndArray();
    writer.Key("description"); writer.String("Project-relative destination folder path, or null for project root.");
    writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("path"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FileDeleteSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "project");
    StringProperty(writer, "path");
    writer.Key("delete"); writer.StartObject(); writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("project");
    writer.String("path"); writer.String("delete"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void UploadUrlSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "project"); StringProperty(writer, "filename");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("project"); writer.String("filename"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void UploadCommitSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "id");
    writer.Key("folder"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Project-relative folder path; missing folders are created.");
    writer.EndObject();
    for (const auto* name : {"open", "analyze"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type");
        writer.String("boolean"); writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("id"); writer.EndArray(); writer.Key("additionalProperties");
    writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void UploadTargetSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "id"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("id"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView");
    for (const auto* name : {"address", "start", "end", "query"})
        StringProperty(writer, name);
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(name == std::string_view("limit") ? 1 : 0);
        if (name == std::string_view("limit"))
        {
            writer.Key("maximum"); writer.Uint(1000);
            writer.Key("default"); writer.Uint(50);
            writer.Key("description"); writer.String("Defaults to 50; use query and continue with nextOffset.");
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionInfoSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionCallersSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch");
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        {
            writer.Key("maximum"); writer.Uint(1000);
            writer.Key("default"); writer.Uint(50);
            writer.Key("description"); writer.String("Defaults to 50; continue with nextOffset.");
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionDecompileSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch");
    writer.Key("language"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description");
    writer.String("Omit for automatic Pseudo Objective-C on Objective-C methods, Pseudo Rust on Rust symbols, and Pseudo C otherwise; explicit names are case/separator insensitive.");
    writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        {
            writer.Key("maximum"); writer.Uint(1000);
            writer.Key("default"); writer.Uint(200);
            writer.Key("description"); writer.String("Defaults to 200 rendered lines; continue with nextOffset.");
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionILSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch");
    writer.Key("level"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("enum"); writer.StartArray(); writer.String("llil"); writer.String("mlil");
    writer.String("hlil"); writer.EndArray(); writer.EndObject();
    writer.Key("ssa"); writer.StartObject(); writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.Key("form"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("enum"); writer.StartArray(); writer.String("text"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        {
            writer.Key("maximum"); writer.Uint(1000);
            writer.Key("default"); writer.Uint(200);
            writer.Key("description"); writer.String("Defaults to 200 rendered lines; continue with nextOffset.");
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void StringListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView");
    for (const auto* name : {"address", "start", "end", "query"})
        StringProperty(writer, name);
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        {
            writer.Key("maximum"); writer.Uint(1000);
            writer.Key("default"); writer.Uint(50);
            writer.Key("description"); writer.String("Defaults to 50; use query first and continue with nextOffset.");
        }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void StringAtSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        { writer.Key("maximum"); writer.Uint(65536); }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SymbolListAtSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void EntryPointListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView");
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        { writer.Key("maximum"); writer.Uint(1000); }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void MemoryReadSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray();
    writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(65536);
    writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("binaryView");
    writer.String("address"); writer.String("length"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DataVariableListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView");
    for (const auto* name : {"address", "start", "end"})
        StringProperty(writer, name);
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        { writer.Key("maximum"); writer.Uint(1000); }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DataXrefsSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        { writer.Key("maximum"); writer.Uint(1000); }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SearchSchema(WriterType& writer, const char* queryName,
    bool queryRequired, bool range, bool caseSensitive = false)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView");
    if (queryName) StringProperty(writer, queryName);
    if (range) { StringProperty(writer, "start"); StringProperty(writer, "end"); }
    if (caseSensitive)
    {
        writer.Key("caseSensitive"); writer.StartObject(); writer.Key("type");
        writer.String("boolean"); writer.EndObject();
    }
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200);
    writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView");
    if (queryRequired && queryName) writer.String(queryName);
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void CommentListSchema(WriterType& writer) { SearchSchema(writer, nullptr, false, false); }
template <typename WriterType>
void CommentSearchSchema(WriterType& writer) { SearchSchema(writer, "query", true, false); }
template <typename WriterType>
void MemorySearchSchema(WriterType& writer) { SearchSchema(writer, "pattern", true, true); }
template <typename WriterType>
void InstructionSearchSchema(WriterType& writer) { SearchSchema(writer, "query", true, true, true); }
template <typename WriterType>
void ConstantSearchSchema(WriterType& writer) { SearchSchema(writer, "value", true, true); }

template <typename WriterType>
void IlSearchSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "binaryView");
    StringProperty(writer, "query"); StringProperty(writer, "functionQuery");
    writer.Key("level"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("enum"); writer.StartArray(); writer.String("llil"); writer.String("mlil");
    writer.String("hlil"); writer.EndArray(); writer.Key("default"); writer.String("hlil"); writer.EndObject();
    writer.Key("ssa"); writer.StartObject(); writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.Key("caseSensitive"); writer.StartObject(); writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200); writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("query"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void ProjectAnalysisSearchSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "project");
    StringProperty(writer, "query");
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200);
    writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("project"); writer.String("query"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void AnnotationCreateSchema(WriterType& writer, bool tag)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    if (tag) { StringProperty(writer, "type"); StringProperty(writer, "data"); StringProperty(writer, "icon"); }
    else StringProperty(writer, "note");
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("address");
    if (tag) writer.String("type"); writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}
template <typename WriterType> void BookmarkCreateSchema(WriterType& w) { AnnotationCreateSchema(w, false); }
template <typename WriterType> void TagCreateSchema(WriterType& w) { AnnotationCreateSchema(w, true); }
template <typename WriterType>
void AnnotationListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "query"); StringProperty(writer, "type");
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(200); writer.Key("default"); writer.Uint(50); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}
template <typename WriterType>
void AnnotationDeleteSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "id"); writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("id"); writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}
template <typename WriterType>
void MetadataSchema(WriterType& writer, bool value)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "key");
    if (value) { writer.Key("value"); writer.StartObject(); writer.EndObject(); }
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("key");
    if (value) writer.String("value"); writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}
template <typename WriterType> void MetadataGetSchema(WriterType& w) { MetadataSchema(w, false); }
template <typename WriterType> void MetadataSetSchema(WriterType& w) { MetadataSchema(w, true); }

template <typename WriterType>
void CommentSetSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    StringProperty(writer, "text");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.String("text");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void BinaryViewAddressSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SymbolDefineSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    StringProperty(writer, "name"); StringProperty(writer, "namespace");
    writer.Key("type"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("enum"); writer.StartArray();
    for (const auto* value : {"FunctionSymbol", "ImportAddressSymbol", "ImportedFunctionSymbol",
            "DataSymbol", "ImportedDataSymbol", "ExternalSymbol", "LibraryFunctionSymbol",
            "SymbolicFunctionSymbol", "LocalLabelSymbol"})
        writer.String(value);
    writer.EndArray(); writer.EndObject();
    writer.Key("binding"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("enum"); writer.StartArray(); writer.String("NoBinding");
    writer.String("LocalBinding"); writer.String("GlobalBinding"); writer.String("WeakBinding");
    writer.EndArray(); writer.EndObject();
    writer.Key("ordinal"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.String("name");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SymbolRenameSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    StringProperty(writer, "name"); StringProperty(writer, "type");
    StringProperty(writer, "namespace"); StringProperty(writer, "newName");
    writer.Key("ordinal"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.String("newName");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SymbolSelectSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address");
    StringProperty(writer, "name"); StringProperty(writer, "type");
    StringProperty(writer, "namespace");
    writer.Key("ordinal"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void FunctionPrototypeSetSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch"); StringProperty(writer, "prototype");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.String("prototype");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void CallingConventionSetSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "function");
    StringProperty(writer, "arch"); StringProperty(writer, "callingConvention");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.String("callingConvention");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void VariableRenameSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* name : {"binaryView", "function", "arch", "variable", "source", "newName"})
        StringProperty(writer, name);
    writer.Key("index"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("storage"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.String("variable");
    writer.String("newName"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void VariableSetTypeSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* name : {"binaryView", "function", "arch", "variable", "variableSource",
            "definition", "source", "type"})
        StringProperty(writer, name);
    writer.Key("index"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("storage"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.EndObject();
    for (const auto* name : {"options", "includeDirs"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("array");
        writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.EndObject(); writer.EndObject();
    }
    writer.Key("importDependencies"); writer.StartObject(); writer.Key("type");
    writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("function"); writer.String("variable");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeListSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "query");
    for (const auto* name : {"offset", "limit"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "limit" ? 1 : 0);
        if (std::string_view(name) == "limit")
        { writer.Key("maximum"); writer.Uint(1000); }
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeInfoSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "type");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("type"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeRenameSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "type");
    StringProperty(writer, "newType");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("type"); writer.String("newType");
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeXrefsFromSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "type");
    writer.Key("recursive"); writer.StartObject(); writer.Key("type"); writer.String("boolean");
    writer.EndObject(); writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("type"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeXrefsToSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "type");
    writer.Key("maxItems"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("type"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DataVariableDefineSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* name : {"binaryView", "datavar", "definition", "source", "type"})
        StringProperty(writer, name);
    for (const auto* name : {"options", "includeDirs"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("array");
        writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.EndObject(); writer.EndObject();
    }
    writer.Key("importDependencies"); writer.StartObject(); writer.Key("type");
    writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("datavar"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DataVariableUndefineSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "datavar");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("datavar"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SectionCreateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* name : {"binaryView", "section", "start", "semantics", "typeName",
            "linkedSection", "infoSection"})
        StringProperty(writer, name);
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"alignment", "entrySize", "infoData"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "alignment" ? 1 : 0);
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("section"); writer.String("start");
    writer.String("length"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SectionDeleteSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "section");
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("section"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SectionModifySchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* name : {"binaryView", "section", "newSection", "start", "semantics",
            "typeName", "linkedSection", "infoSection"})
        StringProperty(writer, name);
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.StartArray();
    writer.String("integer"); writer.String("string"); writer.EndArray(); writer.EndObject();
    for (const auto* name : {"alignment", "entrySize", "infoData"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(std::string_view(name) == "alignment" ? 1 : 0);
        writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("section"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void SegmentMutationSchema(WriterType& writer, bool modify, bool remove)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); StringProperty(writer, "binaryView");
    StringProperty(writer, "start"); StringProperty(writer, "length");
    if (!remove)
    {
        if (modify) { StringProperty(writer, "newStart"); StringProperty(writer, "newLength"); }
        StringProperty(writer, "dataOffset"); StringProperty(writer, "dataLength");
        writer.Key("flags"); writer.StartObject(); writer.Key("type"); writer.String("integer");
        writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(15); writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView");
    writer.String("start"); writer.String("length");
    if (!remove) { writer.String("dataOffset"); writer.String("dataLength"); writer.String("flags"); }
    writer.EndArray(); writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}
template <typename WriterType> void SegmentCreateSchema(WriterType& w) { SegmentMutationSchema(w, false, false); }
template <typename WriterType> void SegmentModifySchema(WriterType& w) { SegmentMutationSchema(w, true, false); }
template <typename WriterType> void SegmentDeleteSchema(WriterType& w) { SegmentMutationSchema(w, false, true); }

template <typename WriterType>
void RebaseSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address"); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("address"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void MemoryMapPreviewSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "operation");
    for (const auto* field : {"start", "length", "newStart", "newLength", "dataOffset", "dataLength", "address"}) StringProperty(writer, field);
    writer.Key("flags"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(15); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("operation"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void StringDefineSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "address"); StringProperty(writer, "length");
    writer.Key("encoding"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.Key("enum"); writer.StartArray();
    writer.String("ascii"); writer.String("utf8"); writer.String("utf16"); writer.String("utf32"); writer.EndArray(); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("address"); writer.String("length"); writer.String("encoding"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeParseSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "source");
    for (const auto* name : {"options", "includeDirs"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("array");
        writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.EndObject(); writer.EndObject();
    }
    writer.Key("importDependencies"); writer.StartObject(); writer.Key("type");
    writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("source"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeDefineSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "source");
    for (const auto* name : {"types", "options", "includeDirs"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("array");
        writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.EndObject(); writer.EndObject();
    }
    writer.Key("importDependencies"); writer.StartObject(); writer.Key("type");
    writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("source"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void TypeStructCreateSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    StringProperty(writer, "binaryView"); StringProperty(writer, "source");
    StringProperty(writer, "type");
    for (const auto* name : {"options", "includeDirs"})
    {
        writer.Key(name); writer.StartObject(); writer.Key("type"); writer.String("array");
        writer.Key("items"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.EndObject(); writer.EndObject();
    }
    writer.Key("importDependencies"); writer.StartObject(); writer.Key("type");
    writer.String("boolean"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("source"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void OpenItemCloseSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("openItem");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("save");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.Key("enum");
    writer.StartArray();
    writer.String("prompt");
    writer.String("save");
    writer.String("discard");
    writer.EndArray();
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("openItem");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void BinaryViewOpenSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("binaryView");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("options");
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.EndObject();
    writer.Key("analyze");
    writer.StartObject();
    writer.Key("type");
    writer.String("boolean");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("binaryView");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void BinaryViewTargetSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("binaryView");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("binaryView");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void PluginListSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("loaded"); writer.StartObject();
    writer.Key("type"); writer.String("boolean"); writer.EndObject();
    writer.Key("query"); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("offset"); writer.StartObject();
    writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0);
    writer.EndObject();
    writer.Key("limit"); writer.StartObject();
    writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1);
    writer.Key("maximum"); writer.Uint(1000); writer.EndObject();
    writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void PluginQueryListSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("query"); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("offset"); writer.StartObject();
    writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0);
    writer.EndObject();
    writer.Key("limit"); writer.StartObject();
    writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1);
    writer.Key("maximum"); writer.Uint(1000); writer.EndObject();
    writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void PluginNamedSchema(WriterType& writer, const char* property)
{
    writer.StartObject();
    writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key(property); writer.StartObject();
    writer.Key("type"); writer.String("string"); writer.Key("minLength"); writer.Uint(1);
    writer.EndObject();
    writer.EndObject();
    writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String(property); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void DebuggerWaitSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("timeoutMilliseconds"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(30000); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("timeoutMilliseconds"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerConfigureSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* field : {"binaryView", "adapter", "executable", "inputFile",
             "workingDirectory", "commandLine", "remoteHost"})
    {
        writer.Key(field); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    }
    writer.Key("remotePort"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(65535); writer.EndObject();
    writer.Key("attachPid"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerFrameSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("thread"); writer.StartObject(); writer.Key("type"); writer.String("integer");
    writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(1000); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerThreadSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("thread"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("thread"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerMemoryReadSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    writer.Key("binaryView"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("address"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("length"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(65536); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("binaryView"); writer.String("address"); writer.String("length"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerMemoryWriteSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* field : {"binaryView", "address", "hex"})
    {
        writer.Key(field); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("address"); writer.String("hex"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DebuggerRegisterSetSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject();
    for (const auto* field : {"binaryView", "register", "value"})
    {
        writer.Key(field); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    }
    writer.EndObject(); writer.Key("required"); writer.StartArray();
    writer.String("binaryView"); writer.String("register"); writer.String("value"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void BinaryViewSaveSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("binaryView");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("destination");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.Key("message");
    writer.StartObject(); writer.Key("type"); writer.String("string"); writer.EndObject();
    writer.Key("resolutions");
    writer.StartObject(); writer.Key("type"); writer.String("object"); writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("binaryView");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void JobTargetSchema(WriterType& writer)
{
    writer.StartObject();
    writer.Key("type");
    writer.String("object");
    writer.Key("properties");
    writer.StartObject();
    writer.Key("job");
    writer.StartObject();
    writer.Key("type");
    writer.String("string");
    writer.EndObject();
    writer.EndObject();
    writer.Key("required");
    writer.StartArray();
    writer.String("job");
    writer.EndArray();
    writer.Key("additionalProperties");
    writer.Bool(false);
    writer.EndObject();
}

template <typename WriterType>
void DiffPairProperties(WriterType& writer, bool project)
{
    writer.Key("primary"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String("Materialized primary BinaryView to compare and mutate."); writer.EndObject();
    writer.Key("secondary"); writer.StartObject(); writer.Key("type"); writer.String("string");
    writer.Key("description"); writer.String(project
        ? "Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is present. Repeat the run identity exactly."
        : "Materialized secondary BinaryView to save as a temporary read-only BNDB."); writer.EndObject();
    if (project)
    {
        writer.Key("project"); writer.StartObject(); writer.Key("type"); writer.String("string");
        writer.Key("description"); writer.String("Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache."); writer.EndObject();
    }
}

template <typename WriterType>
void DiffRunViewSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, false); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("secondary"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DiffRunProjectSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, true); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("project"); writer.String("secondary"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DiffPairSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, true); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("secondary"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DiffListSchema(WriterType& writer, bool unmatched = false)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, true);
    StringProperty(writer, "query");
    if (!unmatched)
    {
        writer.Key("minSimilarity"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(255); writer.EndObject();
        writer.Key("minConfidence"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(255); writer.EndObject();
    }
    writer.Key("sort"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.Key("enum"); writer.StartArray();
    if (unmatched) { writer.String("address"); writer.String("name"); }
    else for (const auto* value : {"similarity", "confidence", "primaryAddress", "secondaryAddress", "primaryName", "secondaryName"}) writer.String(value);
    writer.EndArray(); writer.EndObject();
    writer.Key("order"); writer.StartObject(); writer.Key("type"); writer.String("string"); writer.Key("enum"); writer.StartArray(); writer.String("ascending"); writer.String("descending"); writer.EndArray(); writer.EndObject();
    writer.Key("offset"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.EndObject();
    writer.Key("limit"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(1); writer.Key("maximum"); writer.Uint(1000); writer.EndObject();
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("secondary"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DiffFunctionSchema(WriterType& writer, bool exact)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, true);
    StringProperty(writer, "primaryFunction"); if (exact) StringProperty(writer, "secondaryFunction");
    writer.EndObject(); writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("secondary"); writer.String("primaryFunction"); if (exact) writer.String("secondaryFunction"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename WriterType>
void DiffBulkPortSchema(WriterType& writer)
{
    writer.StartObject(); writer.Key("type"); writer.String("object");
    writer.Key("properties"); writer.StartObject(); DiffPairProperties(writer, true);
    writer.Key("minSimilarity"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(255); writer.EndObject();
    writer.Key("minConfidence"); writer.StartObject(); writer.Key("type"); writer.String("integer"); writer.Key("minimum"); writer.Uint(0); writer.Key("maximum"); writer.Uint(255); writer.EndObject(); writer.EndObject();
    writer.Key("required"); writer.StartArray(); writer.String("primary"); writer.String("secondary"); writer.EndArray();
    writer.Key("additionalProperties"); writer.Bool(false); writer.EndObject();
}

template <typename Schema>
class ToolDefinition
{
  public:
    ToolDefinition(std::string_view name, std::string_view description, Schema schema)
        : name_(name), description_(description), schema_(std::move(schema))
    {
    }

    template <typename WriterType>
    void Write(WriterType& writer) const
    {
        writer.StartObject();
        writer.Key("name");
        writer.String(name_.data(), static_cast<rapidjson::SizeType>(name_.size()));
        writer.Key("description");
        writer.String(description_.data(),
            static_cast<rapidjson::SizeType>(description_.size()));
        writer.Key("inputSchema");
        schema_(writer);
        writer.EndObject();
    }

  private:
    std::string_view name_;
    std::string_view description_;
    Schema schema_;
};

template <typename WriterType, typename Schema>
void WriteTool(WriterType& writer, std::string_view name,
    std::string_view description, Schema schema)
{
    ToolDefinition(name, description, std::move(schema)).Write(writer);
}

enum class ToolPack
{
    Core,
    ProjectManagement,
    FunctionAnalysis,
    BinaryData,
    Search,
    Types,
    Annotations,
    BinaryEditing,
    History,
    Diffing,
    KernelCache,
    SharedCache,
    Debugger,
};

ToolPack ToolPackFor(std::string_view name)
{
    const auto is = [&](std::initializer_list<std::string_view> names) {
        return std::find(names.begin(), names.end(), name) != names.end();
    };
    if (is({"bn_local_project_register", "bn_local_project_file_import",
            "bn_local_project_file_import_batch", "bn_local_project_update",
            "bn_local_project_folder_list", "bn_local_project_folder_create",
            "bn_local_project_folder_update", "bn_local_project_folder_delete",
            "bn_local_project_file_update", "bn_local_project_file_delete",
            "bn_project_text_read", "bn_project_json_read"}))
        return ToolPack::ProjectManagement;
    if (is({"bn_function_callers", "bn_function_callees", "bn_function_il",
            "bn_function_stack_layout", "bn_function_xrefs_from",
            "bn_function_xrefs_to"}))
        return ToolPack::FunctionAnalysis;
    if (is({"bn_import_list", "bn_export_list", "bn_entry_point_list",
            "bn_section_list", "bn_segment_list", "bn_data_variable_list",
            "bn_relocation_list", "bn_data_xrefs_from", "bn_data_xrefs_to"}))
        return ToolPack::BinaryData;
    if (is({"bn_comment_list", "bn_comment_search", "bn_memory_search",
            "bn_instruction_search", "bn_il_search", "bn_constant_search",
            "bn_project_analysis_search"}))
        return ToolPack::Search;
    if (name.starts_with("bn_type_") ||
        is({"bn_function_prototype_set", "bn_calling_convention_set",
            "bn_calling_convention_list", "bn_variable_list",
            "bn_variable_rename", "bn_variable_set_type"}))
        return ToolPack::Types;
    if (is({"bn_comment_get", "bn_comment_set", "bn_comment_delete",
            "bn_symbol_define", "bn_symbol_rename", "bn_symbol_undefine",
            "bn_bookmark_create", "bn_bookmark_list", "bn_bookmark_delete",
            "bn_tag_create", "bn_tag_list", "bn_tag_delete",
            "bn_metadata_get", "bn_metadata_set", "bn_metadata_delete"}))
        return ToolPack::Annotations;
    if (is({"bn_function_create", "bn_function_delete", "bn_entry_point_add",
            "bn_data_variable_define", "bn_data_variable_undefine",
            "bn_section_create", "bn_section_delete", "bn_section_modify",
            "bn_segment_create", "bn_segment_modify", "bn_segment_delete",
            "bn_binary_view_rebase", "bn_memory_map_preview",
            "bn_string_define", "bn_string_undefine"}))
        return ToolPack::BinaryEditing;
    if (is({"bn_transaction_begin", "bn_transaction_commit",
            "bn_transaction_rollback", "bn_undo", "bn_redo"}))
        return ToolPack::History;
    if (name.starts_with("bn_diff_")) return ToolPack::Diffing;
    if (name.starts_with("bn_kernel_cache_")) return ToolPack::KernelCache;
    if (name.starts_with("bn_shared_cache_")) return ToolPack::SharedCache;
    if (name.starts_with("bn_debugger_")) return ToolPack::Debugger;
    return ToolPack::Core;
}

std::string_view ToolPackName(ToolPack pack)
{
    switch (pack)
    {
        case ToolPack::Core: return "Core Workflow";
        case ToolPack::ProjectManagement: return "Project Management & Documents";
        case ToolPack::FunctionAnalysis: return "Function Analysis";
        case ToolPack::BinaryData: return "Binary Data";
        case ToolPack::Search: return "Search";
        case ToolPack::Types: return "Types & Signatures";
        case ToolPack::Annotations: return "Annotations & Symbols";
        case ToolPack::BinaryEditing: return "Binary Editing";
        case ToolPack::History: return "Transactions & History";
        case ToolPack::Diffing: return "Diffing";
        case ToolPack::KernelCache: return "KernelCache";
        case ToolPack::SharedCache: return "SharedCache";
        case ToolPack::Debugger: return "Debugger";
    }
    return "Core Workflow";
}

bool ToolEnabled(std::string_view name, const ToolConfig& tools)
{
    switch (ToolPackFor(name))
    {
        case ToolPack::Core: return true;
        case ToolPack::ProjectManagement: return tools.projectManagement;
        case ToolPack::FunctionAnalysis: return tools.functionAnalysis;
        case ToolPack::BinaryData: return tools.binaryData;
        case ToolPack::Search: return tools.search;
        case ToolPack::Types: return tools.types;
        case ToolPack::Annotations: return tools.annotations;
        case ToolPack::BinaryEditing: return tools.binaryEditing;
        case ToolPack::History: return tools.history;
        case ToolPack::Diffing: return tools.diffing;
        case ToolPack::KernelCache: return tools.kernelCache;
        case ToolPack::SharedCache: return tools.sharedCache;
        case ToolPack::Debugger: return tools.debugger;
    }
    return true;
}

std::string UnfilteredToolsResponse(const ValidatedRequest& request, std::string_view serverVersion,
    bool localProjects, bool collaborationProjects, const ToolConfig& tools,
    bool adminAllowed, bool arbitraryLocalProjects)
{
    return Response(request, [&](auto& writer) {
        writer.Key("tools");
        writer.StartArray();
        if (IsModern(request.version))
        {
            WriteTool(writer, "bn_analysis_session_create", "Create an analysis session.", EmptySchema<decltype(writer)>);
            WriteTool(writer, "bn_analysis_session_close", "Close an owned analysis session.", SessionTargetSchema<decltype(writer)>);
        }
        WriteTool(writer, "bn_analysis_session_list", "List owned analysis sessions.", PaginationSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_session_info", "Inspect an owned analysis session; omit analysisSession or use current for the request's current session.", CurrentSessionTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_compute_status", "Report daemon analysis capacity and allocation.", EmptySchema<decltype(writer)>);
        WriteTool(writer, "bn_open_item_open", "Discover BinaryView candidates for an authorized path or project file; call bn_binary_view_open before using a candidate.", OpenItemOpenSchema<decltype(writer)>);
        if (localProjects)
        {
            WriteTool(writer, "bn_local_project_list", "List local projects.", PaginationSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_info", "Inspect a local project.", ProjectTargetSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_file_list", "List local project files and their names, descriptions, paths, folders, and timestamps with optional filters.", ProjectFileListSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_create", "Create a local project beneath the configured default root, or at an absolute path for an administrator.", ProjectCreateSchema<decltype(writer)>);
            if (adminAllowed && arbitraryLocalProjects)
            {
                WriteTool(writer, "bn_local_project_register", "Register an existing local .bnpr or .bnpm project by absolute path.", ProjectRegisterSchema<decltype(writer)>);
                WriteTool(writer, "bn_local_project_file_import", "Import one server-local regular file with optional project-file name and description; administrator only.", LocalProjectFileImportSchema<decltype(writer)>);
                WriteTool(writer, "bn_local_project_file_import_batch", "Import up to 1000 server-local regular files with optional per-file names and descriptions; administrator only.", LocalProjectFileImportBatchSchema<decltype(writer)>);
            }
            WriteTool(writer, "bn_local_project_update", "Update local project metadata.", ProjectUpdateSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_folder_list", "List folders in a local project.", ProjectFilesSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_folder_create", "Create a local project folder beneath an optional parent path.", FolderCreateSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_folder_update", "Update or move a local project folder selected by project and path.", FolderUpdateSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_folder_delete", "Recursively delete a local project folder selected by project and path.", FolderDeleteSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_file_update", "Update a local project file selected by project and path: set, replace, or clear its description, rename it, or move it to a folder path.", FileUpdateSchema<decltype(writer)>);
            WriteTool(writer, "bn_local_project_file_delete", "Delete a local project file selected by project and path.", FileDeleteSchema<decltype(writer)>);
            WriteTool(writer, "bn_project_file_open", "Discover BinaryView candidates for a project file; call bn_binary_view_open before using a candidate.", ProjectOpenSchema<decltype(writer)>);
        }
        if (collaborationProjects)
        {
            WriteTool(writer, "bn_collaboration_project_list", "Refresh and list collaboration projects.", PaginationSchema<decltype(writer)>);
            WriteTool(writer, "bn_collaboration_project_info", "Inspect a collaboration project.", ProjectTargetSchema<decltype(writer)>);
            WriteTool(writer, "bn_collaboration_project_file_list", "List files in a collaboration project.", ProjectFilesSchema<decltype(writer)>);
            WriteTool(writer, "bn_project_file_open", "Download a collaboration project file and discover its BinaryView candidates; call bn_binary_view_open before using one.", ProjectOpenSchema<decltype(writer)>);
        }
        WriteTool(writer, "bn_project_text_read", "Read a UTF-8 project file by lines with resumable pagination and an optional case-insensitive line query.", ProjectTextReadSchema<decltype(writer)>);
        WriteTool(writer, "bn_project_json_read", "Navigate a project JSON file by RFC 6901 pointer; paginate object keys or array indexes without expanding unrelated subtrees.", ProjectJsonReadSchema<decltype(writer)>);
        WriteTool(writer, "bn_open_item_list", "List open items owned by this bearer token across concurrent analysis sessions; close only items created by your workflow.", PaginationSchema<decltype(writer)>);
        WriteTool(writer, "bn_open_item_close", "Close an open item.", OpenItemCloseSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_list", "List BinaryView candidates in the current analysis session.", PaginationSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_load_settings", "Return the authoritative Binary Ninja load-settings schema and effective settings for one BinaryView candidate.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_open", "Materialize an explicit candidate; inspect load settings first, use Mapped for raw firmware, and use analyze:false for reused BNDB analysis.", BinaryViewOpenSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_status", "Return analysis status for a materialized explicit BinaryView.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_update", "Start analysis without waiting; prefer update_and_wait for normal client workflows.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_update_and_wait", "Preferred analysis operation; waits until the deadline, then returns a job to poll every 10 seconds and consume with job_result.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_update_async", "Start analysis for a materialized BinaryView as an immediately detached job.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_analysis_abort", "Abort analysis for a materialized explicit BinaryView.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_save", "Save and commit an explicit BinaryView.", BinaryViewSaveSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_save_async", "Save and commit an explicit BinaryView as an immediately detached job.", BinaryViewSaveSchema<decltype(writer)>);
        WriteTool(writer, "bn_upload_get_url", "Issue a session-, project-, and filename-bound one-time upload capability with transport instructions.", UploadUrlSchema<decltype(writer)>);
        WriteTool(writer, "bn_upload_commit", "Commit a completed staged upload idempotently to its bound project.", UploadCommitSchema<decltype(writer)>);
        WriteTool(writer, "bn_upload_list", "List staged uploads owned by this bearer token.", PaginationSchema<decltype(writer)>);
        WriteTool(writer, "bn_upload_cancel", "Cancel and remove an inactive staged upload.", UploadTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_list", "List functions; query first, default 50 rows, then continue with nextOffset.", FunctionListSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_info", "Return detailed metadata for one analyzed function.", FunctionInfoSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_create", "Create a user function at a mapped address; defining a FunctionSymbol alone does not create a function.", BinaryViewAddressSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_delete", "Remove one exact function as a persistent user analysis override.", FunctionInfoSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_callers", "List callsites that call one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_callees", "List callees reached from callsites in one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_disassembly", "Render 200 disassembly lines by default; continue with nextOffset.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_decompile", "Render an exact analyzed function, default 200 lines; language auto-selects Pseudo Objective-C or Pseudo Rust when applicable; confirm targets with function_list first.", FunctionDecompileSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_il", "Render 200 LLIL, MLIL, or HLIL lines by default; continue with nextOffset.", FunctionILSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_stack_layout", "List stack variables for one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_variable_list", "List variables for one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_calling_convention_list", "List calling conventions available to one analyzed function.", FunctionInfoSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_xrefs_from", "List code references originating in one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_xrefs_to", "List code references into one analyzed function.", FunctionCallersSchema<decltype(writer)>);
        WriteTool(writer, "bn_string_list", "List strings; query first, default 50 rows, then continue with nextOffset.", StringListSchema<decltype(writer)>);
        WriteTool(writer, "bn_string_at", "Return detailed decoded string data at an address.", StringAtSchema<decltype(writer)>);
        WriteTool(writer, "bn_symbol_list", "List symbols; query first, default 50 rows, then continue with nextOffset.", StringListSchema<decltype(writer)>);
        WriteTool(writer, "bn_symbol_list_at", "Return full symbol metadata at an exact address.", SymbolListAtSchema<decltype(writer)>);
        WriteTool(writer, "bn_import_list", "List import symbols with compact rows.", StringListSchema<decltype(writer)>);
        WriteTool(writer, "bn_export_list", "List exports; enabled KernelCache views use loaded-image cache symbols.", StringListSchema<decltype(writer)>);
        WriteTool(writer, "bn_entry_point_list", "List loader entry functions; KernelCache views include module init/term targets with analyzed state.", EntryPointListSchema<decltype(writer)>);
        WriteTool(writer, "bn_entry_point_add", "Add an analysis entry point at a mapped address using the BinaryView's default platform.", BinaryViewAddressSchema<decltype(writer)>);
        WriteTool(writer, "bn_section_list", "List section ranges and semantics.", EntryPointListSchema<decltype(writer)>);
        WriteTool(writer, "bn_segment_list", "List full mapped-segment metadata.", EntryPointListSchema<decltype(writer)>);
        WriteTool(writer, "bn_memory_read", "Read mapped bytes as lowercase hexadecimal.", MemoryReadSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_variable_list", "List typed data variables with compact rows.", DataVariableListSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_at", "Return compact data context at an address.", SymbolListAtSchema<decltype(writer)>);
        WriteTool(writer, "bn_relocation_list", "List full relocation metadata.", DataVariableListSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_xrefs_from", "List addresses referenced by data values stored at an address or range; code instruction references are excluded.", DataXrefsSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_xrefs_to", "List data locations that reference a target address or range; code instruction references are excluded.", DataXrefsSchema<decltype(writer)>);
        WriteTool(writer, "bn_comment_get", "Return the comment at an address.", SymbolListAtSchema<decltype(writer)>);
        WriteTool(writer, "bn_comment_list", "List all global address comments with bounded pagination.", CommentListSchema<decltype(writer)>);
        WriteTool(writer, "bn_comment_search", "Search global address comments case-insensitively.", CommentSearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_memory_search", "Search mapped bytes with Binary Ninja advanced binary-search syntax.", MemorySearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_instruction_search", "Search rendered disassembly text across an explicit address range or the whole view.", InstructionSearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_il_search", "Search rendered LLIL, MLIL, or HLIL across analyzed functions.", IlSearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_constant_search", "Search globally for rendered uses of one constant or address value.", ConstantSearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_project_analysis_search", "Search functions, symbols, strings, and comments across materialized BinaryViews currently open from one project.", ProjectAnalysisSearchSchema<decltype(writer)>);
        WriteTool(writer, "bn_comment_set", "Set a non-empty comment at an address.", CommentSetSchema<decltype(writer)>);
        WriteTool(writer, "bn_comment_delete", "Delete the comment at an address.", SymbolListAtSchema<decltype(writer)>);
        WriteTool(writer, "bn_symbol_define", "Define a user symbol at an address; FunctionSymbol annotation does not create a function.", SymbolDefineSchema<decltype(writer)>);
        WriteTool(writer, "bn_symbol_rename", "Rename one exactly selected symbol.", SymbolRenameSchema<decltype(writer)>);
        WriteTool(writer, "bn_symbol_undefine", "Undefine one exactly selected user symbol.", SymbolSelectSchema<decltype(writer)>);
        WriteTool(writer, "bn_function_prototype_set", "Set a parsed user prototype; if needsUpdate, run analysis update before variable rename/readback.", FunctionPrototypeSetSchema<decltype(writer)>);
        WriteTool(writer, "bn_calling_convention_set", "Set a function's user calling convention.", CallingConventionSetSchema<decltype(writer)>);
        WriteTool(writer, "bn_variable_rename", "Rename one variable after prototype edits; follow returned nextAction before readback.", VariableRenameSchema<decltype(writer)>);
        WriteTool(writer, "bn_variable_set_type", "Set one variable type; follow returned nextAction before readback.", VariableSetTypeSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_list", "List named types with compact class rows.", TypeListSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_info", "Return metadata and a complete C declaration for one named type.", TypeInfoSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_parse", "Parse C source without defining types.", TypeParseSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_define", "Parse and define selected named types.", TypeDefineSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_struct_create", "Parse and define exactly one new struct type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_struct_modify", "Parse and replace exactly one existing struct type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_union_create", "Parse and define exactly one new union type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_union_modify", "Parse and replace exactly one existing union type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_enum_create", "Parse and define exactly one new enum type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_enum_modify", "Parse and replace exactly one existing enum type.", TypeStructCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_delete", "Delete one exact named type.", TypeInfoSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_rename", "Rename one exact named type.", TypeRenameSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_xrefs_from", "List outgoing named-type references.", TypeXrefsFromSchema<decltype(writer)>);
        WriteTool(writer, "bn_type_xrefs_to", "List grouped incoming code, data, and type references.", TypeXrefsToSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_variable_define", "Define a typed user data variable; use definition for a direct type, or source plus optional type to select a parsed declaration.", DataVariableDefineSchema<decltype(writer)>);
        WriteTool(writer, "bn_data_variable_undefine", "Remove an exact data variable.", DataVariableUndefineSchema<decltype(writer)>);
        WriteTool(writer, "bn_section_create", "Create a user-defined section.", SectionCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_section_delete", "Delete an exact auto- or user-defined section.", SectionDeleteSchema<decltype(writer)>);
        WriteTool(writer, "bn_section_modify", "Modify an exact auto- or user-defined section.", SectionModifySchema<decltype(writer)>);
        WriteTool(writer, "bn_segment_create", "Create a user mapped segment.", SegmentCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_segment_modify", "Replace one exact user mapped segment.", SegmentModifySchema<decltype(writer)>);
        WriteTool(writer, "bn_segment_delete", "Delete one exact user mapped segment.", SegmentDeleteSchema<decltype(writer)>);
        WriteTool(writer, "bn_binary_view_rebase", "Rebase an explicit BinaryView to a new base address.", RebaseSchema<decltype(writer)>);
        WriteTool(writer, "bn_memory_map_preview", "Preview a segment or rebase operation without mutating the BinaryView.", MemoryMapPreviewSchema<decltype(writer)>);
        WriteTool(writer, "bn_string_define", "Define a typed user string data object at an address.", StringDefineSchema<decltype(writer)>);
        WriteTool(writer, "bn_string_undefine", "Undefine a user string data object at an address.", BinaryViewAddressSchema<decltype(writer)>);
        WriteTool(writer, "bn_transaction_begin", "Begin one explicit undo transaction for an explicit BinaryView's open item.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_transaction_commit", "Commit the active transaction for an explicit BinaryView.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_transaction_rollback", "Roll back the active transaction for an explicit BinaryView.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_undo", "Undo the last committed mutation for an explicit BinaryView's file.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_redo", "Redo the last undone mutation for an explicit BinaryView's file.", BinaryViewTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_bookmark_create", "Create a persistent bookmark at an address.", BookmarkCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_bookmark_list", "List persistent bookmarks with pagination.", AnnotationListSchema<decltype(writer)>);
        WriteTool(writer, "bn_bookmark_delete", "Delete one persistent bookmark by its Binary Ninja tag id.", AnnotationDeleteSchema<decltype(writer)>);
        WriteTool(writer, "bn_tag_create", "Create a persistent user data tag at an address, creating its tag type when needed.", TagCreateSchema<decltype(writer)>);
        WriteTool(writer, "bn_tag_list", "List persistent user tags with optional type/data query filters.", AnnotationListSchema<decltype(writer)>);
        WriteTool(writer, "bn_tag_delete", "Delete one persistent user tag by its Binary Ninja tag id.", AnnotationDeleteSchema<decltype(writer)>);
        WriteTool(writer, "bn_metadata_get", "Read one persistent custom BinaryView metadata value in the binjad.user namespace.", MetadataGetSchema<decltype(writer)>);
        WriteTool(writer, "bn_metadata_set", "Store one arbitrary JSON custom BinaryView metadata value in the binjad.user namespace.", MetadataSetSchema<decltype(writer)>);
        WriteTool(writer, "bn_metadata_delete", "Delete one persistent custom BinaryView metadata value in the binjad.user namespace.", MetadataGetSchema<decltype(writer)>);
        WriteTool(writer, "bn_diff_run_view", "Run a job-backed Google BinDiff comparison after saving an open secondary BinaryView to a temporary BNDB; results target the primary view.", DiffRunViewSchema<decltype(writer)>);
        WriteTool(writer, "bn_diff_run_project", "Run a job-backed Google BinDiff comparison against a project-relative secondary BNDB; results target the primary view.", DiffRunProjectSchema<decltype(writer)>);
        WriteTool(writer, "bn_diff_summary", "Summarize one cached Google BinDiff comparison with matched/unmatched counts plus exact/changed and score aggregates.", DiffPairSchema<decltype(writer)>);
        WriteTool(writer, "bn_diff_match_list", "List cached function matches with query, metric thresholds, deterministic sorting, and pagination.", [](auto& output) { DiffListSchema(output, false); });
        WriteTool(writer, "bn_diff_primary_unmatched_list", "List unmatched primary functions with deterministic sorting and pagination.", [](auto& output) { DiffListSchema(output, true); });
        WriteTool(writer, "bn_diff_secondary_unmatched_list", "List unmatched secondary functions with deterministic sorting and pagination.", [](auto& output) { DiffListSchema(output, true); });
        WriteTool(writer, "bn_diff_function_matches", "List Google BinDiff matches for one primary function.", [](auto& output) { DiffFunctionSchema(output, false); });
        WriteTool(writer, "bn_diff_match_info", "Return one exact primary-to-secondary function match.", [](auto& output) { DiffFunctionSchema(output, true); });
        WriteTool(writer, "bn_diff_port_name_from_secondary", "Explicitly copy one matched secondary function name onto the primary function.", [](auto& output) { DiffFunctionSchema(output, true); });
        WriteTool(writer, "bn_diff_apply_from_secondary", "Explicitly invoke Google BinDiff's native metadata transfer for one exact match, mutating only the primary view.", [](auto& output) { DiffFunctionSchema(output, true); });
        WriteTool(writer, "bn_diff_port_names_from_secondary", "Copy high-confidence secondary names onto auto-named primary functions while preserving existing primary names.", DiffBulkPortSchema<decltype(writer)>);
        if (tools.kernelCache)
        {
            WriteTool(writer, "bn_kernel_cache_image_list", "List KernelCache images; query first, default 50 rows, then continue with nextOffset.", PluginListSchema<decltype(writer)>);
            WriteTool(writer, "bn_kernel_cache_image_info", "Inspect one exact KernelCache image and its dependencies.", [](auto& output) { PluginNamedSchema(output, "image"); });
            WriteTool(writer, "bn_kernel_cache_image_load", "Load one exact KernelCache image into the BinaryView.", [](auto& output) { PluginNamedSchema(output, "image"); });
            WriteTool(writer, "bn_kernel_cache_symbol_list", "List exported KernelCache symbols.", PluginQueryListSchema<decltype(writer)>);
        }
        if (tools.sharedCache)
        {
            WriteTool(writer, "bn_shared_cache_image_list", "List images available in a SharedCache BinaryView.", PluginListSchema<decltype(writer)>);
            WriteTool(writer, "bn_shared_cache_image_info", "Inspect one exact SharedCache image and its dependencies.", [](auto& output) { PluginNamedSchema(output, "image"); });
            WriteTool(writer, "bn_shared_cache_image_load", "Load one exact SharedCache image into the BinaryView.", [](auto& output) { PluginNamedSchema(output, "image"); });
            WriteTool(writer, "bn_shared_cache_region_list", "List SharedCache regions.", PluginListSchema<decltype(writer)>);
            WriteTool(writer, "bn_shared_cache_region_load", "Load one exact SharedCache region into the BinaryView.", [](auto& output) { PluginNamedSchema(output, "region"); });
            WriteTool(writer, "bn_shared_cache_entry_list", "List files comprising a SharedCache.", PluginQueryListSchema<decltype(writer)>);
            WriteTool(writer, "bn_shared_cache_symbol_list", "List exported SharedCache symbols.", PluginQueryListSchema<decltype(writer)>);
        }
        if (tools.debugger && adminAllowed)
        {
            WriteTool(writer, "bn_debugger_adapter_list", "List debugger adapters available for an explicit BinaryView.", BinaryViewTargetSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_status", "Return debugger state and target configuration.", BinaryViewTargetSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_configure", "Configure the debugger adapter and target.", DebuggerConfigureSchema<decltype(writer)>);
            for (const auto* tool : {"bn_debugger_launch", "bn_debugger_connect", "bn_debugger_attach",
                     "bn_debugger_go", "bn_debugger_pause", "bn_debugger_step_into",
                     "bn_debugger_step_over", "bn_debugger_step_return", "bn_debugger_restart",
                     "bn_debugger_quit", "bn_debugger_detach"})
                WriteTool(writer, tool, "Issue an immediate debugger control operation.", BinaryViewTargetSchema<decltype(writer)>);
            for (const auto* tool : {"bn_debugger_launch_and_wait", "bn_debugger_connect_and_wait",
                     "bn_debugger_attach_and_wait", "bn_debugger_go_and_wait",
                     "bn_debugger_pause_and_wait", "bn_debugger_step_into_and_wait",
                     "bn_debugger_step_over_and_wait", "bn_debugger_step_return_and_wait",
                     "bn_debugger_restart_and_wait"})
                WriteTool(writer, tool, "Run a bounded debugger control operation as an attached or detached job.", DebuggerWaitSchema<decltype(writer)>);
            for (const auto* tool : {"bn_debugger_process_list", "bn_debugger_thread_list", "bn_debugger_register_list",
                     "bn_debugger_module_list", "bn_debugger_memory_region_list",
                     "bn_debugger_breakpoint_list"})
                WriteTool(writer, tool, "List debugger target state.", EntryPointListSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_frame_list", "List stack frames for a target thread.", DebuggerFrameSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_thread_set", "Select the active debugger target thread.", DebuggerThreadSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_register_set", "Set one target register value.", DebuggerRegisterSetSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_memory_read", "Read target process memory.", DebuggerMemoryReadSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_memory_write", "Write target process memory from hexadecimal bytes.", DebuggerMemoryWriteSchema<decltype(writer)>);
            WriteTool(writer, "bn_debugger_breakpoint_add", "Add an absolute software breakpoint.", [](auto& output) { PluginNamedSchema(output, "address"); });
            WriteTool(writer, "bn_debugger_breakpoint_delete", "Delete an absolute software breakpoint.", [](auto& output) { PluginNamedSchema(output, "address"); });
        }
        WriteTool(writer, "bn_job_list", "List detached jobs owned by this bearer token.", PaginationSchema<decltype(writer)>);
        WriteTool(writer, "bn_job_info", "Inspect a detached job.", JobTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_job_result", "Retrieve and consume a terminal detached-job result.", JobTargetSchema<decltype(writer)>);
        WriteTool(writer, "bn_job_cancel", "Request cancellation of a detached job.", JobTargetSchema<decltype(writer)>);
        writer.EndArray();
        if (IsModern(request.version))
            WriteServerMeta(writer, serverVersion);
    });
}

std::string ToolsResponse(const ValidatedRequest& request, std::string_view serverVersion,
    bool localProjects, bool collaborationProjects, const ToolConfig& tools,
    bool adminAllowed, bool arbitraryLocalProjects)
{
    auto response = UnfilteredToolsResponse(request, serverVersion, localProjects,
        collaborationProjects, tools, adminAllowed, arbitraryLocalProjects);
    Document document;
    document.Parse(response.data(), response.size());
    if (document.HasParseError() || !document.IsObject() ||
        !document.HasMember("result") || !document["result"].IsObject() ||
        !document["result"].HasMember("tools") || !document["result"]["tools"].IsArray())
        return response;
    auto& advertised = document["result"]["tools"];
    for (auto item = advertised.Begin(); item != advertised.End();)
    {
        const auto& name = (*item)["name"];
        if (ToolEnabled(std::string_view(name.GetString(), name.GetStringLength()), tools))
            ++item;
        else
            item = advertised.Erase(item);
    }
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document.Accept(writer);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string ResourcesResponse(const ValidatedRequest& request, std::string_view serverVersion,
    bool localProjects, bool collaborationProjects)
{
    return Response(request, [&](auto& writer) {
        writer.Key("resources");
        writer.StartArray();
        writer.StartObject();
        writer.Key("uri"); writer.String("binjad://docs");
        writer.Key("name"); writer.String("Quick start");
        writer.Key("description"); writer.String("Minimal binjad lifecycle and argument rules.");
        writer.Key("mimeType"); writer.String("text/markdown");
        writer.EndObject();
        for (const auto& [uri, name, description] : {
            std::tuple{"binjad://compute", "Compute status", "Current analysis capacity and allocation."},
            std::tuple{"binjad://analysis-sessions", "Analysis sessions", "Analysis sessions owned by this bearer token."},
            std::tuple{"binjad://open-items", "Open items", "Open files and BinaryView candidates owned by this bearer token."},
            std::tuple{"binjad://jobs", "Detached jobs", "Detached jobs owned by this bearer token."}})
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
        if (collaborationProjects)
        {
            writer.StartObject();
            writer.Key("uri"); writer.String("binjad://collaboration-projects");
            writer.Key("name"); writer.String("Collaboration projects");
            writer.Key("description"); writer.String("Projects visible to this collaboration identity.");
            writer.Key("mimeType"); writer.String("application/json");
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

std::string ResourceResponse(const ValidatedRequest& request,
    std::string_view text, std::string_view serverVersion,
    std::string_view mimeType = "application/json")
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

bool Only(const Value& object, std::initializer_list<std::string_view> names, std::string& error)
{
    for (const auto& member : object.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (std::find(names.begin(), names.end(), name) == names.end())
        {
            error = "unknown argument '" + std::string(name) + "'";
            return false;
        }
    }
    return true;
}

bool Only(const Value& object, const std::vector<std::string_view>& names, std::string& error)
{
    for (const auto& member : object.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (std::find(names.begin(), names.end(), name) == names.end())
        {
            error = "unknown argument '" + std::string(name) + "'";
            return false;
        }
    }
    return true;
}

std::optional<std::string> SessionArgument(const Value& arguments, std::string& error)
{
    if (!Only(arguments, {"analysisSession"}, error))
        return std::nullopt;
    const auto member = arguments.FindMember("analysisSession");
    if (member == arguments.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() == 0)
    {
        error = "analysisSession must be a non-empty string";
        return std::nullopt;
    }
    return std::string(member->value.GetString(), member->value.GetStringLength());
}

std::optional<std::string> RequiredStringArgument(
    const Value& arguments, const char* name, std::string& error)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() == 0)
    {
        error = std::string(name) + " must be a non-empty string";
        return std::nullopt;
    }
    return std::string(member->value.GetString(), member->value.GetStringLength());
}

bool OptionalStringArgument(const Value& arguments, const char* name,
    bool allowEmpty, std::optional<std::string>& output, std::string& error)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd())
        return true;
    if (!member->value.IsString() ||
        (!allowEmpty && member->value.GetStringLength() == 0))
    {
        error = std::string(name) + (allowEmpty ? " must be a string"
                                                : " must be a non-empty string");
        return false;
    }
    output.emplace(member->value.GetString(), member->value.GetStringLength());
    return true;
}

bool OptionalNullableStringArgument(const Value& arguments, const char* name,
    std::optional<std::optional<std::string>>& output, std::string& error)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd())
        return true;
    if (member->value.IsNull())
    {
        output = std::optional<std::string>{};
        return true;
    }
    if (!member->value.IsString() || member->value.GetStringLength() == 0)
    {
        error = std::string(name) + " must be a non-empty string or null";
        return false;
    }
    output = std::optional<std::string>(std::in_place,
        member->value.GetString(), member->value.GetStringLength());
    return true;
}

bool SafeFilenameComponent(std::string_view value)
{
    if (value.empty() || value == "." || value == ".." ||
        value.find('/') != std::string_view::npos ||
        value.find('\\') != std::string_view::npos)
        return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char character) {
        return std::iscntrl(character) != 0;
    });
}

std::string AsciiLower(std::string_view value)
{
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::optional<std::string> ProjectFolderPath(std::string_view value, std::string& error)
{
    const std::filesystem::path path(value);
    const auto normalized = path.lexically_normal();
    if (path.is_absolute() || normalized.empty() || normalized == "." ||
        *normalized.begin() == "..")
    {
        error = "folder path must be a contained project-relative path";
        return std::nullopt;
    }
    return normalized.generic_string();
}

std::string SerializeValue(const Value& value)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    value.Accept(writer);
    return {buffer.GetString(), buffer.GetSize()};
}

bool ValidUtf8(std::string_view text)
{
    for (std::size_t offset = 0; offset < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[offset]);
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        if (first < 0x80) { length = 1; codepoint = first; }
        else if ((first & 0xe0) == 0xc0) { length = 2; codepoint = first & 0x1f; }
        else if ((first & 0xf0) == 0xe0) { length = 3; codepoint = first & 0x0f; }
        else if ((first & 0xf8) == 0xf0) { length = 4; codepoint = first & 0x07; }
        else return false;
        if (offset + length > text.size()) return false;
        for (std::size_t index = 1; index < length; ++index)
        {
            const auto next = static_cast<unsigned char>(text[offset + index]);
            if ((next & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((length == 2 && codepoint < 0x80) ||
            (length == 3 && codepoint < 0x800) ||
            (length == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return false;
        offset += length;
    }
    return true;
}

std::string Utf8Preview(std::string_view text, std::size_t maximum)
{
    if (text.size() <= maximum) return std::string(text);
    std::size_t end = maximum;
    while (end != 0 &&
        (static_cast<unsigned char>(text[end]) & 0xc0) == 0x80)
        --end;
    return std::string(text.substr(0, end));
}

std::string ProjectTextJson(const std::filesystem::path& path,
    std::string_view projectPath, std::string_view query,
    std::size_t offset, std::size_t limit, std::string& error)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        error = "cannot read project text file";
        return {};
    }
    struct Line { std::size_t number; std::string value; std::size_t length; bool truncated; };
    std::vector<Line> page;
    std::string line;
    const auto loweredQuery = AsciiLower(query);
    std::size_t lineNumber = 0;
    std::size_t matched = 0;
    while (std::getline(input, line))
    {
        ++lineNumber;
        if (!line.empty() && line.back() == '\r') line.pop_back();
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
            page.push_back({lineNumber, Utf8Preview(line, kLinePreviewBytes),
                line.size(), line.size() > kLinePreviewBytes});
        }
        ++matched;
    }
    if (input.bad())
    {
        error = "cannot read project text file";
        return {};
    }
    const auto end = std::min(matched, offset + page.size());
    StringBuffer buffer; Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("path"); writer.String(projectPath.data(),
        static_cast<rapidjson::SizeType>(projectPath.size()));
    if (!query.empty())
    {
        writer.Key("query"); writer.String(query.data(),
            static_cast<rapidjson::SizeType>(query.size()));
    }
    writer.Key("lines"); writer.StartArray();
    for (const auto& item : page)
    {
        writer.StartObject(); writer.Key("line"); writer.Uint64(item.number);
        writer.Key("text"); writer.String(item.value.data(),
            static_cast<rapidjson::SizeType>(item.value.size()));
        if (item.truncated)
        {
            writer.Key("byteLength"); writer.Uint64(item.length);
            writer.Key("truncated"); writer.Bool(true);
        }
        writer.EndObject();
    }
    writer.EndArray(); writer.Key("count"); writer.Uint64(page.size());
    writer.Key("total"); writer.Uint64(matched); writer.Key("nextOffset");
    if (end < matched) writer.Uint64(end); else writer.Null();
    writer.Key("truncated"); writer.Bool(end < matched); writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::optional<std::string> DecodeJsonPointerToken(std::string_view encoded)
{
    std::string result;
    for (std::size_t index = 0; index < encoded.size(); ++index)
    {
        if (encoded[index] != '~') { result.push_back(encoded[index]); continue; }
        if (++index >= encoded.size() || (encoded[index] != '0' && encoded[index] != '1'))
            return std::nullopt;
        result.push_back(encoded[index] == '0' ? '~' : '/');
    }
    return result;
}

std::string AppendJsonPointer(std::string_view pointer, std::string_view token)
{
    std::string result(pointer);
    result.push_back('/');
    for (const char character : token)
    {
        if (character == '~') result += "~0";
        else if (character == '/') result += "~1";
        else result.push_back(character);
    }
    return result;
}

const Value* ResolveJsonPointer(const Value& root, std::string_view pointer, std::string& error)
{
    if (pointer.empty()) return &root;
    if (!pointer.starts_with('/'))
    {
        error = "pointer must be empty or an RFC 6901 JSON Pointer beginning with '/'";
        return nullptr;
    }
    const Value* current = &root;
    for (std::size_t start = 1;;)
    {
        const auto slash = pointer.find('/', start);
        const auto encoded = pointer.substr(start,
            slash == std::string_view::npos ? pointer.size() - start : slash - start);
        const auto token = DecodeJsonPointerToken(encoded);
        if (!token)
        {
            error = "pointer contains an invalid '~' escape";
            return nullptr;
        }
        if (current->IsObject())
        {
            const auto member = current->FindMember(
                rapidjson::StringRef(token->data(), token->size()));
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
            if (token->empty() || parsed.ec != std::errc{} ||
                parsed.ptr != token->data() + token->size() || index >= current->Size())
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
        if (slash == std::string_view::npos) return current;
        start = slash + 1;
    }
}

template <typename WriterType>
void WriteJsonNodeSummary(WriterType& writer, const Value& value)
{
    writer.Key("type");
    if (value.IsObject())
    {
        writer.String("object"); writer.Key("count"); writer.Uint64(value.MemberCount());
    }
    else if (value.IsArray())
    {
        writer.String("array"); writer.Key("count"); writer.Uint64(value.Size());
    }
    else if (value.IsString())
    {
        writer.String("string");
        const std::string_view text(value.GetString(), value.GetStringLength());
        const auto preview = Utf8Preview(text, 4096);
        writer.Key("value"); writer.String(preview.data(),
            static_cast<rapidjson::SizeType>(preview.size()));
        if (preview.size() != text.size())
        {
            writer.Key("byteLength"); writer.Uint64(text.size());
            writer.Key("truncated"); writer.Bool(true);
        }
    }
    else if (value.IsBool())
    {
        writer.String("boolean"); writer.Key("value"); writer.Bool(value.GetBool());
    }
    else if (value.IsNull())
    {
        writer.String("null"); writer.Key("value"); writer.Null();
    }
    else
    {
        writer.String("number"); writer.Key("value"); value.Accept(writer);
    }
}

std::string ProjectJsonJson(const std::filesystem::path& path,
    std::string_view projectPath, std::string_view pointer,
    std::size_t offset, std::size_t limit, std::string& error)
{
    std::error_code filesystemError;
    const auto size = std::filesystem::file_size(path, filesystemError);
    constexpr std::uintmax_t kMaximumJsonBytes = 64ull * 1024 * 1024;
    if (filesystemError) { error = "cannot inspect project JSON file"; return {}; }
    if (size > kMaximumJsonBytes)
    {
        error = "project JSON file exceeds the 64 MiB parsing limit";
        return {};
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) { error = "cannot read project JSON file"; return {}; }
    std::string contents((std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    Document document;
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
    const auto selected = ResolveJsonPointer(document, pointer, error);
    if (!selected) return {};
    const bool container = selected->IsObject() || selected->IsArray();
    const std::size_t total = selected->IsObject() ? selected->MemberCount()
        : selected->IsArray() ? selected->Size() : 1;
    const auto begin = container ? std::min(offset, total) : 0;
    const auto end = container ? std::min(total, begin + limit) : 1;
    StringBuffer buffer; Writer<StringBuffer> writer(buffer);
    writer.StartObject(); writer.Key("path"); writer.String(projectPath.data(),
        static_cast<rapidjson::SizeType>(projectPath.size()));
    writer.Key("pointer"); writer.String(pointer.data(),
        static_cast<rapidjson::SizeType>(pointer.size()));
    writer.Key("type");
    if (selected->IsObject()) writer.String("object");
    else if (selected->IsArray()) writer.String("array");
    else writer.String("scalar");
    if (selected->IsObject())
    {
        writer.Key("members"); writer.StartArray();
        std::size_t index = 0;
        for (const auto& member : selected->GetObject())
        {
            if (index >= begin && index < end)
            {
                writer.StartObject(); writer.Key("key"); member.name.Accept(writer);
                const auto childPointer = AppendJsonPointer(pointer,
                    std::string_view(member.name.GetString(), member.name.GetStringLength()));
                writer.Key("pointer"); writer.String(childPointer.data(),
                    static_cast<rapidjson::SizeType>(childPointer.size()));
                WriteJsonNodeSummary(writer, member.value); writer.EndObject();
            }
            ++index;
        }
        writer.EndArray();
    }
    else if (selected->IsArray())
    {
        writer.Key("items"); writer.StartArray();
        for (std::size_t index = begin; index < end; ++index)
        {
            writer.StartObject(); writer.Key("index"); writer.Uint64(index);
            const auto childPointer = AppendJsonPointer(pointer, std::to_string(index));
            writer.Key("pointer"); writer.String(childPointer.data(),
                static_cast<rapidjson::SizeType>(childPointer.size()));
            WriteJsonNodeSummary(writer,
                (*selected)[static_cast<rapidjson::SizeType>(index)]); writer.EndObject();
        }
        writer.EndArray();
    }
    else
    {
        writer.Key("value"); writer.StartObject();
        WriteJsonNodeSummary(writer, *selected); writer.EndObject();
    }
    writer.Key("count"); writer.Uint64(end - begin); writer.Key("total"); writer.Uint64(total);
    writer.Key("nextOffset"); if (end < total) writer.Uint64(end); else writer.Null();
    writer.Key("truncated"); writer.Bool(end < total); writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

class ScopedWorkingDirectory
{
  public:
    std::filesystem::path path;
    ~ScopedWorkingDirectory()
    {
        if (path.empty()) return;
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};

bool OptionalBooleanArgument(const Value& arguments, const char* name,
    bool defaultValue, bool& output, std::string& error)
{
    const auto member = arguments.FindMember(name);
    if (member == arguments.MemberEnd())
    {
        output = defaultValue;
        return true;
    }
    if (!member->value.IsBool())
    {
        error = std::string(name) + " must be a boolean";
        return false;
    }
    output = member->value.GetBool();
    return true;
}

bool OptionsArgument(const Value& arguments, std::string& output, std::string& error)
{
    const auto member = arguments.FindMember("options");
    if (member == arguments.MemberEnd())
    {
        output = "{}";
        return true;
    }
    if (!member->value.IsObject())
    {
        error = "options must be an object";
        return false;
    }
    output = SerializeValue(member->value);
    return true;
}

std::string AnalysisStatusJson(const ipc::AnalysisStatus& status)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("state");
    switch (status.state())
    {
        case ipc::ANALYSIS_STATE_IDLE: writer.String("idle"); break;
        case ipc::ANALYSIS_STATE_RUNNING: writer.String("running"); break;
        case ipc::ANALYSIS_STATE_COMPLETE: writer.String("complete"); break;
        case ipc::ANALYSIS_STATE_ABORTED: writer.String("aborted"); break;
        case ipc::ANALYSIS_STATE_FAILED: writer.String("failed"); break;
        default: writer.String("unspecified"); break;
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
        writer.String("Wait at least 10 seconds before checking again. If analysis_update_and_wait returned a job, use bn_job_info and bn_job_result instead of polling analysis status.");
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
        case ipc::ANALYSIS_STATE_COMPLETE: writer.String("complete"); break;
        case ipc::ANALYSIS_STATE_ABORTED: writer.String("aborted"); break;
        case ipc::ANALYSIS_STATE_FAILED: writer.String("failed"); break;
        default: writer.String("unspecified"); break;
    }
    if (!finished.error().empty())
    {
        writer.Key("error");
        writer.String(finished.error().data(),
            static_cast<rapidjson::SizeType>(finished.error().size()));
    }
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::string SaveResultJson(std::string_view binaryView, std::string_view openItem,
    std::string_view destination, bool createdDatabase,
    session::OpenItemSourceKind sourceKind)
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

std::string UploadIssuedJson(
    const upload::UploadRecord& upload, std::string_view url, bool requiresBearer)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("id"); writer.String(upload.id.data(),
        static_cast<rapidjson::SizeType>(upload.id.size()));
    writer.Key("url"); writer.String(url.data(), static_cast<rapidjson::SizeType>(url.size()));
    writer.Key("project"); writer.String(upload.project.data(),
        static_cast<rapidjson::SizeType>(upload.project.size()));
    writer.Key("filename"); writer.String(upload.filename.data(),
        static_cast<rapidjson::SizeType>(upload.filename.size()));
    writer.Key("expiresAt"); writer.Uint64(upload.expiresAtUnix);
    writer.Key("method"); writer.String("PUT");
    writer.Key("contentType"); writer.String("application/octet-stream");
    writer.Key("singleUse"); writer.Bool(true);
    writer.Key("requiresBearerAuthentication"); writer.Bool(requiresBearer);
    writer.Key("authorization");
    writer.String(requiresBearer ? "Bearer token plus URL capability" : "URL capability");
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::string_view UploadStateName(upload::UploadState state)
{
    switch (state)
    {
        case upload::UploadState::Ready: return "ready";
        case upload::UploadState::Receiving: return "receiving";
        case upload::UploadState::Completed: return "completed";
        case upload::UploadState::Committing: return "committing";
        case upload::UploadState::Committed: return "committed";
    }
    return "unknown";
}

template <typename WriterType>
void WriteUpload(WriterType& writer, const upload::UploadRecord& upload)
{
    writer.StartObject();
    writer.Key("id"); writer.String(upload.id.data(),
        static_cast<rapidjson::SizeType>(upload.id.size()));
    writer.Key("analysisSession"); writer.String(upload.analysisSession.data(),
        static_cast<rapidjson::SizeType>(upload.analysisSession.size()));
    writer.Key("project"); writer.String(upload.project.data(),
        static_cast<rapidjson::SizeType>(upload.project.size()));
    writer.Key("filename"); writer.String(upload.filename.data(),
        static_cast<rapidjson::SizeType>(upload.filename.size()));
    writer.Key("state");
    const auto state = UploadStateName(upload.state);
    writer.String(state.data(), static_cast<rapidjson::SizeType>(state.size()));
    writer.Key("createdAt"); writer.Uint64(upload.createdAtUnix);
    writer.Key("expiresAt"); writer.Uint64(upload.expiresAtUnix);
    writer.Key("size"); writer.Uint64(upload.size);
    if (!upload.sha256.empty())
    {
        writer.Key("sha256"); writer.String(upload.sha256.data(),
            static_cast<rapidjson::SizeType>(upload.sha256.size()));
    }
    writer.EndObject();
}

std::string UploadsJson(const std::vector<upload::UploadRecord>& uploads,
    std::size_t offset, std::size_t limit)
{
    return PaginatedJson("uploads", uploads, offset, limit,
        [](auto& writer, const auto& upload) { WriteUpload(writer, upload); });
}

std::string UploadCommittedJson(const upload::UploadRecord& upload,
    const project::LocalProjectFileRecord& file,
    const std::optional<session::OpenItemRecord>& openItem)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("id"); writer.String(upload.id.data(),
        static_cast<rapidjson::SizeType>(upload.id.size()));
    writer.Key("project"); writer.String(upload.project.data(),
        static_cast<rapidjson::SizeType>(upload.project.size()));
    writer.Key("path"); writer.String(file.path.data(),
        static_cast<rapidjson::SizeType>(file.path.size()));
    writer.Key("size"); writer.Uint64(upload.size);
    writer.Key("sha256"); writer.String(upload.sha256.data(),
        static_cast<rapidjson::SizeType>(upload.sha256.size()));
    if (openItem)
    {
        writer.Key("openItem");
        WriteOpenItem(writer, *openItem);
    }
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::string CollaborationConflictJson(std::string_view conflicts)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("error"); writer.String("collaboration merge conflicts require resolutions");
    writer.Key("conflicts");
    writer.RawValue(conflicts.data(), conflicts.size(), rapidjson::kObjectType);
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

bool Pagination(const Value& arguments, std::size_t& offset, std::size_t& limit, std::string& error)
{
    if (!Only(arguments, {"offset", "limit"}, error))
        return false;
    if (const auto member = arguments.FindMember("offset"); member != arguments.MemberEnd())
    {
        if (!member->value.IsUint64() || member->value.GetUint64() > std::numeric_limits<std::size_t>::max())
        {
            error = "offset must be a non-negative integer";
            return false;
        }
        offset = static_cast<std::size_t>(member->value.GetUint64());
    }
    if (const auto member = arguments.FindMember("limit"); member != arguments.MemberEnd())
    {
        if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
            member->value.GetUint64() > 1000)
        {
            error = "limit must be an integer from 1 through 1000";
            return false;
        }
        limit = static_cast<std::size_t>(member->value.GetUint64());
    }
    return true;
}

bool BoundedPagination(const Value& arguments, std::size_t maximum,
    std::size_t& offset, std::size_t& limit, std::string& error)
{
    if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
    {
        if (!value->value.IsUint64() || value->value.GetUint64() > std::numeric_limits<std::size_t>::max())
        { error = "offset must be a non-negative integer"; return false; }
        offset = static_cast<std::size_t>(value->value.GetUint64());
    }
    if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
    {
        if (!value->value.IsUint64() || value->value.GetUint64() == 0 || value->value.GetUint64() > maximum)
        { error = "limit must be an integer from 1 through " + std::to_string(maximum); return false; }
        limit = static_cast<std::size_t>(value->value.GetUint64());
    }
    return true;
}

constexpr std::string_view kQuickStartDocs =
    "Flow: project_list -> file_list -> project_file_open -> binary_view_open(recommended) -> analysis_update_and_wait -> query/mutate -> binary_view_save(if changed) -> open_item_close.\n"
    "Uploads: bn_upload_get_url returns a one-time PUT capability and explicit authorization requirements; commit to a project-relative folder path; import-only commits return JSON and successful retries return the original result; use bn_upload_list/cancel for cleanup. Local administrators should prefer bn_local_project_file_import_batch for files already on the server.\n"
    "Project files: project-relative paths are unique and select files together with project; imports accept an initial description; bn_local_project_file_list returns descriptions; bn_local_project_file_update sets or replaces one, and an empty description string clears it.\n"
    "Project documents: use bn_project_text_read for line/query pagination over UTF-8 text and Markdown; use bn_project_json_read with RFC 6901 pointers to page object keys or array indexes without expanding unrelated subtrees. These tools read project files directly without a BinaryView.\n"
    "Project writes: if a mutation says the project may be open or read-only, ask the user to close that project in the Binary Ninja GUI, then retry. Failed upload commits remain staged and may be retried with the same id without re-uploading.\n"
    "Functions: FunctionSymbol is annotation only; use bn_entry_point_add for an analysis root and bn_function_create for a persistent user function, then update analysis and save the BinaryView.\n"
    "Raw firmware: open only discovers candidates; select Mapped rather than Raw, call bn_binary_view_load_settings, then pass fully qualified loader.platform, loader.imageBase, and loader.entryPointOffset options to bn_binary_view_open. Thumb vector values have bit zero set, but Mapped entry/function addresses use the aligned code address. loader.segments and loader.sections are serialized JSON strings.\n"
    "Rules: every view tool needs binaryView; query first, use small limits, and continue with nextOffset; async job results are one-shot; direct C types use definition, while source+type selects a parsed declaration; after function/variable mutation follow nextAction; set prototypes before variable names; reopen BNDBs with reuseDatabase:true and analyze:false; close only items created by your workflow because token-wide lists may include concurrent clients; legacy analysis sessions are transport-managed.";

ValidatedRequest DocumentationRequest(ProtocolVersion version,
    std::uint64_t id, std::string method, std::string uri = {})
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
    if (name.starts_with("bn_analysis_session") || name == "bn_compute_status") return "Sessions and compute";
    if (name.starts_with("bn_local_project") || name.starts_with("bn_collaboration_project") || name == "bn_project_file_open") return "Projects";
    if (name.starts_with("bn_open_item") || name.starts_with("bn_binary_view")) return "Files and views";
    if (name.starts_with("bn_upload")) return "Uploads";
    if (name.starts_with("bn_function") || name.starts_with("bn_variable") || name.starts_with("bn_calling_convention")) return "Functions";
    if (name.starts_with("bn_string") || name.starts_with("bn_memory")) return "Memory and strings";
    if (name.starts_with("bn_symbol") || name.starts_with("bn_import") || name.starts_with("bn_export") || name.starts_with("bn_entry_point")) return "Symbols and entries";
    if (name.starts_with("bn_data") || name.starts_with("bn_relocation") || name.starts_with("bn_comment")) return "Data and references";
    if (name.starts_with("bn_type")) return "Types";
    if (name.starts_with("bn_section") || name.starts_with("bn_segment")) return "Sections and segments";
    if (name.starts_with("bn_diff")) return "Diffing";
    if (name.starts_with("bn_kernel_cache")) return "KernelCache";
    if (name.starts_with("bn_shared_cache")) return "SharedCache";
    if (name.starts_with("bn_debugger")) return "Debugger";
    if (name.starts_with("bn_job")) return "Jobs";
    return "Other";
}

template <typename WriterType>
void WriteFailureIds(WriterType& writer, std::string_view name, const Value& schema)
{
    writer.StartArray();
    writer.String("invalid_arguments");
    writer.String("analysis_session_unavailable");
    const auto properties = schema.FindMember("properties");
    const auto has = [&](const char* property) {
        return properties != schema.MemberEnd() && properties->value.IsObject() &&
            properties->value.HasMember(property);
    };
    if (has("binaryView") || has("primary")) writer.String("binary_view_unavailable");
    if (has("openItem")) writer.String("open_item_unavailable");
    if (has("project") || name.find("project") != std::string_view::npos)
        writer.String("project_unavailable");
    if (has("job") || name.starts_with("bn_job")) writer.String("job_unavailable");
    if (has("function")) writer.String("function_unavailable");
    if (has("type")) writer.String("type_unavailable");
    if (has("address")) writer.String("address_unavailable");
    if (name.starts_with("bn_kernel_cache") || name.starts_with("bn_shared_cache"))
        writer.String("plugin_state");
    if (name.starts_with("bn_debugger")) writer.String("debugger_state");
    if (name.starts_with("bn_diff")) writer.String("diff_state");
    if (name.find("save") != std::string_view::npos ||
        name.find("upload") != std::string_view::npos ||
        name.find("project") != std::string_view::npos)
        writer.String("persistence_failure");
    writer.String("service_failure");
    writer.EndArray();
}

template <typename WriterType>
void WriteFailureContracts(WriterType& writer)
{
    writer.StartObject();
    const auto contract = [&](const char* id, const char* when, const char* surface) {
        writer.Key(id); writer.StartObject();
        writer.Key("when"); writer.String(when);
        writer.Key("surface"); writer.String(surface);
        writer.EndObject();
    };
    contract("invalid_arguments", "A required argument is absent, has the wrong type or range, or an unknown argument is supplied.", "JSON-RPC -32602; HTTP 400 for modern MCP and HTTP 200 for legacy MCP.");
    contract("analysis_session_unavailable", "The analysis session is unknown, expired, belongs to another token, or is not valid for this protocol flow.", "JSON-RPC error, normally session not found; no tool result is produced.");
    contract("binary_view_unavailable", "The BinaryView reference is unknown, belongs to another session, is not materialized, or its file child failed.", "Tool result with isError:true and a structured error string.");
    contract("open_item_unavailable", "The open-item reference is unknown, belongs to another token/session, is busy, or requires discard acknowledgement.", "Tool result with isError:true and a structured error string.");
    contract("project_unavailable", "The project/file/folder is unknown, unauthorized, locked by another Binary Ninja process, read-only, or unavailable in the active project mode.", "Tool result with isError:true; lock failures instruct the caller to ask the user to close the GUI project and retry.");
    contract("job_unavailable", "The job is unknown, owned by another token, not terminal, already consumed, or cannot be cancelled.", "Tool result with isError:true and a structured error string.");
    contract("function_unavailable", "The function selector is absent or ambiguous, analysis has not created it, or the requested architecture/view does not contain it.", "Tool result with isError:true; FunctionSymbol-only failures direct callers to bn_function_create.");
    contract("type_unavailable", "A named type cannot be found, is the wrong class, already exists for a create operation, or C parsing fails.", "Tool result with isError:true and parse or selection details.");
    contract("address_unavailable", "The address expression is invalid, unmapped, outside loaded cache content, or unsuitable for the requested operation.", "Tool result with isError:true and contextual load/analyze guidance where available.");
    contract("plugin_state", "The optional plugin surface is disabled, unavailable, the view is incompatible, or required cache content is not loaded.", "Unavailable tools are omitted from discovery; runtime state failures are isError:true tool results.");
    contract("debugger_state", "The caller is not an admin, debuggercore is unavailable, target configuration is incomplete, or the target state rejects the operation.", "The surface is omitted for non-admins; runtime failures are isError:true tool results or failed jobs.");
    contract("diff_state", "Google BinDiff is unavailable, a secondary is not a valid BNDB, the comparison is running, absent, cancelled, or belongs to another explicit pair, or a requested match is absent.", "Run failures are terminal job results; cached query and mutation failures are isError:true tool results.");
    contract("persistence_failure", "Storage is locked, read-only, collides with an unrelated destination, upload state is invalid, or a collaboration merge needs resolutions.", "Tool result or terminal job with structured error/conflict data; documented retryable uploads retain their staged id.");
    contract("service_failure", "A required daemon service/child is unavailable or an unexpected internal operation fails.", "JSON-RPC -32603 when no tool result can be formed; otherwise an isError:true tool result or failed job.");
    writer.EndObject();
}
}

Foundation::Foundation(Config config, session::AnalysisSessionRegistry& sessions,
    std::string serverVersion, session::OpenItemRegistry* openItems,
    overseer::FileChildCoordinator* fileCoordinator, session::JobRegistry* jobs,
    project::LocalProjectRegistry* projects,
    overseer::ProjectChildCoordinator* projectCoordinator,
    overseer::AnalysisScheduler* scheduler, upload::UploadRegistry* uploads,
    project::CollaborationProjectRegistry* collaborationProjects,
    overseer::CollaborationChildManager* collaborationManager)
    : config_(std::move(config)), sessions_(sessions), serverVersion_(std::move(serverVersion)),
      openItems_(openItems), fileCoordinator_(fileCoordinator), jobs_(jobs),
      projects_(projects), projectCoordinator_(projectCoordinator), scheduler_(scheduler),
      uploads_(uploads), collaborationProjects_(collaborationProjects),
      collaborationManager_(collaborationManager)
{
}

std::string Foundation::ToolDocumentation(ProtocolVersion version,
    security::TokenRole role) const
{
    const auto request = DocumentationRequest(version, 1, "tools/list");
    const auto currentPayload = ToolsResponse(request, serverVersion_,
        config_.EffectiveMode() == Mode::Local,
        config_.EffectiveMode() == Mode::Collaboration, config_.tools,
        role == security::TokenRole::Admin,
        config_.projects.allowArbitraryPaths);
    ToolConfig allTools;
    const auto localPayload = ToolsResponse(request, serverVersion_,
        true, false, allTools, true, true);
    const auto collaborationPayload = ToolsResponse(request, serverVersion_,
        false, true, allTools, true, true);
    const auto modernRequest = DocumentationRequest(
        ProtocolVersion::V2026_07_28, 1, "tools/list");
    const auto modernLocalPayload = ToolsResponse(modernRequest, serverVersion_,
        true, false, allTools, true, true);
    const auto modernCollaborationPayload = ToolsResponse(modernRequest, serverVersion_,
        false, true, allTools, true, true);

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
    const auto collect = [&](const std::string& payload, bool available) {
        Document discovery;
        discovery.Parse(payload.data(), payload.size());
        if (discovery.HasParseError() || !discovery.IsObject() ||
            !discovery.HasMember("result") || !discovery["result"].IsObject() ||
            !discovery["result"].HasMember("tools") ||
            !discovery["result"]["tools"].IsArray())
            return;
        for (const auto& tool : discovery["result"]["tools"].GetArray())
        {
            std::string name(tool["name"].GetString(), tool["name"].GetStringLength());
            if (available)
                availableNames.insert(name);
            if (!names.insert(name).second)
                continue;
            documentedTools.push_back({std::move(name),
                std::string(tool["description"].GetString(),
                    tool["description"].GetStringLength()),
                SerializeValue(tool["inputSchema"]), available});
        }
    };
    collect(currentPayload, true);
    collect(localPayload, false);
    collect(collaborationPayload, false);
    collect(modernLocalPayload, false);
    collect(modernCollaborationPayload, false);

    const auto unavailableReason = [&](std::string_view name) -> std::string {
        if (!ToolEnabled(name, config_.tools))
            return std::string(ToolPackName(ToolPackFor(name))) +
                " tools are disabled in the running configuration.";
        if (!IsModern(version) &&
            (name == "bn_analysis_session_create" || name == "bn_analysis_session_close"))
            return "Requires the modern MCP protocol session model.";
        if (name == "bn_local_project_register" ||
            name == "bn_local_project_file_import" ||
            name == "bn_local_project_file_import_batch")
            return config_.EffectiveMode() != Mode::Local
                ? "Requires local project mode."
                : role != security::TokenRole::Admin
                ? "Requires an admin bearer token."
                : "Requires projects.allow_arbitrary_paths in local mode.";
        if (name.starts_with("bn_local_project"))
            return "Requires local project mode.";
        if (name.starts_with("bn_collaboration_project"))
            return "Requires collaboration project mode.";
        if (name.starts_with("bn_kernel_cache") && !config_.tools.kernelCache)
            return "KernelCache tools are disabled in the running configuration.";
        if (name.starts_with("bn_shared_cache") && !config_.tools.sharedCache)
            return "SharedCache tools are disabled in the running configuration.";
        if (name.starts_with("bn_debugger"))
        {
            if (!config_.tools.debugger)
                return "Debugger tools are disabled in the running configuration.";
            if (role != security::TokenRole::Admin)
                return "Requires an admin bearer token.";
        }
        return "Not advertised for the selected protocol, role, mode, or running options.";
    };

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("protocolVersion");
    const auto protocol = ToString(version);
    writer.String(protocol.data(), static_cast<rapidjson::SizeType>(protocol.size()));
    writer.Key("role"); writer.String(role == security::TokenRole::Admin ? "admin" : "user");
    writer.Key("mode");
    writer.String(config_.EffectiveMode() == Mode::Local ? "local" : "collaboration");
    writer.Key("availableCount"); writer.Uint64(availableNames.size());
    writer.Key("totalCount"); writer.Uint64(documentedTools.size());
    writer.Key("failureContracts"); WriteFailureContracts(writer);
    writer.Key("tools"); writer.StartArray();
    for (const auto& tool : documentedTools)
    {
        Document schema;
        schema.Parse(tool.schema.data(), tool.schema.size());
        writer.StartObject();
        writer.Key("name"); writer.String(tool.name.data(),
            static_cast<rapidjson::SizeType>(tool.name.size()));
        writer.Key("category");
        const auto category = ToolCategory(tool.name);
        writer.String(category.data(), static_cast<rapidjson::SizeType>(category.size()));
        writer.Key("pack");
        const auto pack = ToolPackName(ToolPackFor(tool.name));
        writer.String(pack.data(), static_cast<rapidjson::SizeType>(pack.size()));
        writer.Key("available"); writer.Bool(availableNames.contains(tool.name));
        if (!availableNames.contains(tool.name))
        {
            writer.Key("availability");
            const auto reason = unavailableReason(tool.name);
            writer.String(reason.data(), static_cast<rapidjson::SizeType>(reason.size()));
        }
        writer.Key("description"); writer.String(tool.description.data(),
            static_cast<rapidjson::SizeType>(tool.description.size()));
        writer.Key("inputSchema"); schema.Accept(writer);
        writer.Key("failureModes"); WriteFailureIds(writer, tool.name, schema);
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

std::string Foundation::ContextDocumentation(ProtocolVersion version,
    security::TokenRole role, std::string_view clientName) const
{
    const auto admin = role == security::TokenRole::Admin;
    const auto local = config_.EffectiveMode() == Mode::Local;
    const auto collaboration = config_.EffectiveMode() == Mode::Collaboration;
    const auto toolsRequest = DocumentationRequest(version, 1, "tools/list");
    const auto resourcesRequest = DocumentationRequest(version, 2, "resources/list");
    const auto templatesRequest = DocumentationRequest(version, 3, "resources/templates/list");
    const auto docsRequest = DocumentationRequest(version, 4, "resources/read", "binjad://docs");
    const auto tools = ToolsResponse(toolsRequest, serverVersion_, local, collaboration,
        config_.tools, admin, config_.projects.allowArbitraryPaths);
    const auto resources = ResourcesResponse(
        resourcesRequest, serverVersion_, local, collaboration);
    const auto templates = TemplatesResponse(templatesRequest, serverVersion_);
    const auto docs = ResourceResponse(
        docsRequest, kQuickStartDocs, serverVersion_, "text/markdown");

    Document toolsDocument;
    toolsDocument.Parse(tools.data(), tools.size());
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("protocolVersion");
    const auto protocol = ToString(version);
    writer.String(protocol.data(), static_cast<rapidjson::SizeType>(protocol.size()));
    writer.Key("role"); writer.String(admin ? "admin" : "user");
    writer.Key("mode"); writer.String(local ? "local" : "collaboration");
    writer.Key("runningOptions"); writer.StartObject();
    writer.Key("allowArbitraryPaths"); writer.Bool(config_.projects.allowArbitraryPaths);
    writer.Key("tools"); writer.StartObject();
    writer.Key("coreWorkflow"); writer.Bool(true);
    writer.Key("projectManagement"); writer.Bool(config_.tools.projectManagement);
    writer.Key("functionAnalysis"); writer.Bool(config_.tools.functionAnalysis);
    writer.Key("binaryData"); writer.Bool(config_.tools.binaryData);
    writer.Key("search"); writer.Bool(config_.tools.search);
    writer.Key("types"); writer.Bool(config_.tools.types);
    writer.Key("annotations"); writer.Bool(config_.tools.annotations);
    writer.Key("binaryEditing"); writer.Bool(config_.tools.binaryEditing);
    writer.Key("history"); writer.Bool(config_.tools.history);
    writer.Key("diffing"); writer.Bool(config_.tools.diffing);
    writer.Key("kernelCache"); writer.Bool(config_.tools.kernelCache);
    writer.Key("sharedCache"); writer.Bool(config_.tools.sharedCache);
    writer.Key("debugger"); writer.Bool(config_.tools.debugger);
    writer.EndObject(); writer.EndObject();
    writer.Key("mcpWire"); writer.StartArray();
    const auto wire = [&](std::string_view method, const std::string& payload) {
        writer.StartObject(); writer.Key("method");
        writer.String(method.data(), static_cast<rapidjson::SizeType>(method.size()));
        writer.Key("payload"); writer.String(payload.data(),
            static_cast<rapidjson::SizeType>(payload.size()));
        writer.EndObject();
    };
    wire("tools/list", tools);
    wire("resources/list", resources);
    wire("resources/templates/list", templates);
    wire("resources/read binjad://docs", docs);
    writer.EndArray();
    writer.Key("openCodeProjection"); writer.StartObject();
    writer.Key("boundary");
    writer.String("OpenCode controls the final provider-specific model encoding. This projection applies its MCP namespace convention to the exact current binjad tool definitions; only mcpWire is byte-for-byte server output.");
    writer.Key("clientNamespace"); writer.String(clientName.data(),
        static_cast<rapidjson::SizeType>(clientName.size()));
    writer.Key("tools"); writer.StartArray();
    if (!toolsDocument.HasParseError() && toolsDocument.IsObject() &&
        toolsDocument.HasMember("result") && toolsDocument["result"].IsObject() &&
        toolsDocument["result"].HasMember("tools") &&
        toolsDocument["result"]["tools"].IsArray())
    {
        for (const auto& tool : toolsDocument["result"]["tools"].GetArray())
        {
            const std::string qualified = std::string(clientName) + "_" +
                std::string(tool["name"].GetString(), tool["name"].GetStringLength());
            writer.StartObject();
            writer.Key("name"); writer.String(qualified.data(),
                static_cast<rapidjson::SizeType>(qualified.size()));
            writer.Key("description"); tool["description"].Accept(writer);
            writer.Key("inputSchema"); tool["inputSchema"].Accept(writer);
            writer.EndObject();
        }
    }
    writer.EndArray();
    writer.Key("resourceContext"); writer.String(kQuickStartDocs.data(),
        static_cast<rapidjson::SizeType>(kQuickStartDocs.size()));
    writer.EndObject();
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

FoundationResult Foundation::Handle(const ValidatedRequest& request,
    const security::TokenRecord& principal,
    const std::optional<session::AnalysisSessionRecord>& currentSession,
    session::AnalysisSessionRegistry::Clock::time_point now, std::uint64_t unixNow,
    JobProgressCallback progress, AttachedJobCallback attached)
{
    if (request.method == "tools/list")
        return {true, 200, ToolsResponse(request, serverVersion_,
            config_.EffectiveMode() == Mode::Local,
            config_.EffectiveMode() == Mode::Collaboration, config_.tools,
            principal.role == security::TokenRole::Admin,
            config_.projects.allowArbitraryPaths), {}};
    if (request.method == "resources/list")
        return {true, 200, ResourcesResponse(request, serverVersion_,
            config_.EffectiveMode() == Mode::Local,
            config_.EffectiveMode() == Mode::Collaboration), {}};
    if (request.method == "resources/templates/list")
        return {true, 200, TemplatesResponse(request, serverVersion_), {}};
    if (request.method == "resources/read")
    {
        if (request.uri == "binjad://docs")
        {
            return {true, 200, ResourceResponse(
                request, kQuickStartDocs, serverVersion_, "text/markdown"), {}};
        }
        if (request.uri == "binjad://compute")
        {
            const auto compute = ComputeJson(config_, scheduler_);
            if (!compute.error.empty())
                return {true, 500, {}, ProtocolError{-32603, 500, compute.error, request.id, {}}};
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
                return {true, 500, {}, ProtocolError{-32603, 500,
                    "job service is unavailable", request.id, {}}};
            const auto jobs = jobs_->List(principal.id);
            return {true, 200,
                ResourceResponse(request, JobsJson(jobs, 0, jobs.size()), serverVersion_), {}};
        }
        if (request.uri == "binjad://open-items")
        {
            if (!openItems_)
                return {true, 500, {}, ProtocolError{-32603, 500,
                    "open-item service is unavailable", request.id, {}}};
            const auto items = openItems_->ListForToken(principal.id);
            return {true, 200, ResourceResponse(request,
                OpenItemsJson(items, 0, items.size()), serverVersion_), {}};
        }
        if (request.uri == "binjad://local-projects")
        {
            if (config_.EffectiveMode() != Mode::Local || !projects_)
                return {true, IsModern(request.version) ? 404 : 200, {},
                    ProtocolError{-32004, IsModern(request.version) ? 404 : 200,
                        "resource not found", request.id, {}}};
            const auto projects = projects_->List();
            return {true, 200, ResourceResponse(request,
                ProjectsJson(projects, 0, projects.size()), serverVersion_), {}};
        }
        if (request.uri == "binjad://collaboration-projects")
        {
            if (config_.EffectiveMode() != Mode::Collaboration || !collaborationManager_)
                return {true, IsModern(request.version) ? 404 : 200, {},
                    ProtocolError{-32004, IsModern(request.version) ? 404 : 200,
                        "resource not found", request.id, {}}};
            const auto projects = collaborationManager_->ListProjects(principal);
            if (!projects.value)
                return {true, 200, ResourceResponse(request,
                    ErrorJson(projects.error), serverVersion_), {}};
            return {true, 200, ResourceResponse(request,
                CollaborationProjectsJson(*projects.value, 0, projects.value->size()),
                serverVersion_), {}};
        }
        constexpr std::string_view prefix = "binjad://analysis-sessions/";
        if (request.uri.starts_with(prefix))
        {
            const auto found = sessions_.Find(request.uri.substr(prefix.size()), principal.id, now);
            if (!found)
                return {true, 404, {}, ProtocolError{-32001, 404, "session not found", request.id, {}}};
            return {true, 200, ResourceResponse(request, SessionJson(*found), serverVersion_), {}};
        }
        return {true, IsModern(request.version) ? 404 : 200, {},
            ProtocolError{-32002, IsModern(request.version) ? 404 : 200,
                "resource not found", request.id, {}}};
    }
    if (request.method != "tools/call")
        return {};

    Document params;
    std::string schemaError;
    const auto* arguments = Arguments(request, params, schemaError);
    if (!arguments)
        return {true, 400, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
            schemaError, request.id, {}}};
    if (!ToolEnabled(request.name, config_.tools))
        return {true, IsModern(request.version) ? 404 : 200, {},
            ProtocolError{-32602, IsModern(request.version) ? 404 : 200,
                "unknown tool", request.id, {}}};
    if (request.name == "bn_diff_run" || request.name == "bn_diff_release" ||
        request.name.starts_with("binjad_internal_"))
        return {true, IsModern(request.version) ? 404 : 200, {},
            ProtocolError{-32602, IsModern(request.version) ? 404 : 200,
                "unknown tool", request.id, {}}};
    if (request.name.starts_with("bn_diff_"))
    {
        const bool runView = request.name == "bn_diff_run_view";
        const bool runProject = request.name == "bn_diff_run_project";
        const bool unmatched = request.name == "bn_diff_primary_unmatched_list" ||
            request.name == "bn_diff_secondary_unmatched_list";
        const bool list = request.name == "bn_diff_match_list" || unmatched;
        const bool oneFunction = request.name == "bn_diff_function_matches";
        const bool exactFunction = request.name == "bn_diff_match_info" ||
            request.name == "bn_diff_port_name_from_secondary" ||
            request.name == "bn_diff_apply_from_secondary";
        const bool bulk = request.name == "bn_diff_port_names_from_secondary";
        std::vector<std::string_view> allowed{"primary", "secondary", "project"};
        if (unmatched)
            allowed = {"primary", "secondary", "project", "query", "sort", "order", "offset", "limit"};
        else if (list)
            allowed = {"primary", "secondary", "project", "query", "minSimilarity",
                "minConfidence", "sort", "order", "offset", "limit"};
        else if (oneFunction)
            allowed = {"primary", "secondary", "project", "primaryFunction"};
        else if (exactFunction)
            allowed = {"primary", "secondary", "project", "primaryFunction", "secondaryFunction"};
        else if (bulk)
            allowed = {"primary", "secondary", "project", "minSimilarity", "minConfidence"};
        if (!Only(*arguments, allowed, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto primary = RequiredStringArgument(*arguments, "primary", schemaError);
        const auto secondary = RequiredStringArgument(*arguments, "secondary", schemaError);
        std::optional<std::string> project;
        OptionalStringArgument(*arguments, "project", false, project, schemaError);
        if (runView && project)
            schemaError = "bn_diff_run_view does not accept project";
        if (runProject && !project)
            schemaError = "project is required for bn_diff_run_project";
        if ((oneFunction || exactFunction) &&
            !RequiredStringArgument(*arguments, "primaryFunction", schemaError))
            schemaError = "primaryFunction is required";
        if (exactFunction &&
            !RequiredStringArgument(*arguments, "secondaryFunction", schemaError))
            schemaError = "secondaryFunction is required";
        for (const auto* field : {"minSimilarity", "minConfidence"})
        {
            if (const auto value = arguments->FindMember(field);
                value != arguments->MemberEnd() &&
                (!value->value.IsUint() || value->value.GetUint() > 255))
                schemaError = std::string(field) + " must be an integer from 0 through 255";
        }
        for (const auto* field : {"query", "sort", "order"})
        {
            if (const auto value = arguments->FindMember(field);
                value != arguments->MemberEnd() && !value->value.IsString())
                schemaError = std::string(field) + " must be a string";
        }
        if (const auto value = arguments->FindMember("order"); value != arguments->MemberEnd() &&
            value->value.IsString())
        {
            const std::string_view order(value->value.GetString(), value->value.GetStringLength());
            if (order != "ascending" && order != "descending")
                schemaError = "order must be ascending or descending";
        }
        if (const auto value = arguments->FindMember("sort"); value != arguments->MemberEnd() &&
            value->value.IsString())
        {
            const std::string_view sort(value->value.GetString(), value->value.GetStringLength());
            const bool valid = unmatched
                ? sort == "address" || sort == "name"
                : sort == "similarity" || sort == "confidence" ||
                    sort == "primaryAddress" || sort == "secondaryAddress" ||
                    sort == "primaryName" || sort == "secondaryName";
            if (!valid)
                schemaError = "sort is not valid for this diff listing";
        }
        if (const auto value = arguments->FindMember("offset");
            value != arguments->MemberEnd() && !value->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto value = arguments->FindMember("limit");
            value != arguments->MemberEnd() && (!value->value.IsUint64() ||
                value->value.GetUint64() == 0 || value->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!primary || !secondary || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_ || !openItems_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session, open-item, and file-child services are required"),
                true, serverVersion_), {}};
        const auto primaryView = openItems_->FindView(
            principal.id, currentSession->reference, *primary);
        if (!primaryView || !primaryView->created)
            return {true, 200, ToolResult(request,
                ErrorJson("primary BinaryView is not materialized"), true, serverVersion_), {}};
        const std::string key = project
            ? "primary:" + std::to_string(primary->size()) + ":" + *primary +
                ":project:" + std::to_string(project->size()) + ":" + *project +
                ":secondary:" + *secondary
            : "primary:" + std::to_string(primary->size()) + ":" + *primary +
                ":view:" + *secondary;
        const overseer::DiffSecondary identity{{}, key};

        if (!runView && !runProject)
        {
            const auto result = fileCoordinator_->ExecuteDiffTool(principal.id,
                currentSession->reference, *primary, identity, request.name,
                SerializeValue(*arguments));
            if (!result.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(result.error), true, serverVersion_), {}};
            return {true, 200, ToolResult(request, *result.value, false, serverVersion_), {}};
        }
        if (!jobs_)
            return {true, 200, ToolResult(request,
                ErrorJson("job service is unavailable"), true, serverVersion_), {}};
        if (runView)
        {
            const auto secondaryView = openItems_->FindView(
                principal.id, currentSession->reference, *secondary);
            if (!secondaryView || !secondaryView->created)
                return {true, 200, ToolResult(request,
                    ErrorJson("secondary BinaryView is not materialized"), true, serverVersion_), {}};
        }
        const auto owner = principal.id;
        const auto analysisSession = currentSession->reference;
        const auto openItem = primaryView->openItem;
        const auto primaryReference = *primary;
        const auto secondaryReference = *secondary;
        const auto projectReference = project;
        const auto created = jobs_->Create(owner, analysisSession, primaryReference,
            request.name, unixNow, now,
            [coordinator = fileCoordinator_, scheduler = scheduler_, owner,
                analysisSession, primaryReference, identity, openItem] {
                if (scheduler && scheduler->CancelQueued(owner, analysisSession, openItem) != 0)
                    return std::string{};
                const auto released = coordinator->ExecuteDiffTool(owner, analysisSession,
                    primaryReference, identity, "binjad_internal_diff_release");
                return released.value ? std::string{} : released.error;
            });
        if (!created.job)
            return {true, 200, ToolResult(request,
                ErrorJson(created.error), true, serverVersion_), {}};
        const auto job = created.job->reference;
        jobs_->Start(owner, job, unixNow);
        if (attached)
            attached(job, [jobs = jobs_, owner, job] { (void)jobs->Cancel(owner, job); });
        jobs_->ReportProgress(owner, job, "diff", 0, 1000,
            "staging secondary database", unixNow);
        const auto workerError = jobs_->StartWorker(
            [this, jobs = jobs_, coordinator = fileCoordinator_, scheduler = scheduler_,
                owner, analysisSession, primaryReference, secondaryReference,
                projectReference, identity, openItem, job, principal, progress] {
                const auto cancelled = [&] {
                    const auto info = jobs->Info(owner, job);
                    return info.job && info.job->cancelRequested;
                };
                if (cancelled())
                {
                    jobs->MarkCancelled(owner, job, ErrorJson("job cancelled"), CurrentUnixSeconds());
                    return;
                }
                std::optional<overseer::AnalysisScheduler::Lease> lease;
                if (scheduler)
                {
                    std::string scheduleError;
                    lease = scheduler->Acquire({owner, analysisSession, openItem, job},
                        [coordinator, owner, analysisSession, primaryReference](std::size_t workers) {
                            (void)coordinator->SetWorkerCount(
                                owner, analysisSession, primaryReference, workers);
                        }, scheduleError);
                    if (!lease)
                    {
                        jobs->MarkCancelled(owner, job, ErrorJson(scheduleError), CurrentUnixSeconds());
                        return;
                    }
                }
                overseer::CoordinatorResult<overseer::DiffSecondary> staged;
                if (!projectReference)
                {
                    staged = coordinator->StageDiffView(owner, analysisSession,
                        primaryReference, secondaryReference, identity.key);
                }
                else if (config_.EffectiveMode() == Mode::Local)
                {
                    if (!projectCoordinator_)
                    {
                        jobs->Fail(owner, job, ErrorJson("local project service is unavailable"), CurrentUnixSeconds());
                        return;
                    }
                    auto exported = projectCoordinator_->ExportFile(*projectReference, secondaryReference);
                    if (!exported.value)
                    {
                        jobs->Fail(owner, job, ErrorJson(exported.error), CurrentUnixSeconds());
                        return;
                    }
                    staged = coordinator->StageDiffFile(owner, analysisSession, primaryReference,
                        exported.value->path, identity.key);
                    std::error_code ignored;
                    std::filesystem::remove_all(exported.value->workingDirectory, ignored);
                }
                else
                {
                    if (!collaborationManager_)
                    {
                        jobs->Fail(owner, job, ErrorJson("collaboration project service is unavailable"), CurrentUnixSeconds());
                        return;
                    }
                    auto downloaded = collaborationManager_->DownloadFile(
                        principal, *projectReference, secondaryReference);
                    if (!downloaded.value)
                    {
                        jobs->Fail(owner, job, ErrorJson(downloaded.error), CurrentUnixSeconds());
                        return;
                    }
                    staged = coordinator->StageDiffFile(owner, analysisSession, primaryReference,
                        downloaded.value->path, identity.key);
                    std::error_code ignored;
                    std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
                }
                if (!staged.value)
                {
                    jobs->Fail(owner, job, ErrorJson(staged.error), CurrentUnixSeconds());
                    return;
                }
                if (cancelled())
                {
                    jobs->MarkCancelled(owner, job, ErrorJson("job cancelled"), CurrentUnixSeconds());
                    return;
                }
                const auto finished = coordinator->RunDiffAndWait(owner, analysisSession,
                    primaryReference, *staged.value,
                    [jobs, owner, job, progress](const ipc::Progress& update) {
                        jobs->ReportProgress(owner, job, update.phase(), update.completed(),
                            update.total(), update.message(), CurrentUnixSeconds());
                        if (progress)
                        {
                            const auto info = jobs->Info(owner, job);
                            if (info.job) progress(*info.job);
                        }
                    });
                if (!finished.value || finished.value->state() != ipc::ANALYSIS_STATE_COMPLETE)
                {
                    if (cancelled() || (finished.value &&
                        finished.value->state() == ipc::ANALYSIS_STATE_ABORTED))
                        jobs->MarkCancelled(owner, job, ErrorJson("diff job cancelled"), CurrentUnixSeconds());
                    else
                        jobs->Fail(owner, job, ErrorJson(finished.value ?
                            finished.value->error() : finished.error), CurrentUnixSeconds());
                    return;
                }
                const auto summary = coordinator->ExecuteDiffTool(owner, analysisSession,
                    primaryReference, *staged.value, "bn_diff_summary");
                if (!summary.value)
                    jobs->Fail(owner, job, ErrorJson(summary.error), CurrentUnixSeconds());
                else
                    jobs->Complete(owner, job, *summary.value, CurrentUnixSeconds());
            });
        if (!workerError.empty())
            jobs_->Fail(owner, job, ErrorJson(workerError), unixNow);
        const auto waited = jobs_->WaitForTerminal(owner, job, config_.jobs.detachAfter);
        if (!waited.job)
            return {true, 200, ToolResult(request, ErrorJson(waited.error), true, serverVersion_), {}};
        if (waited.job->state == session::JobState::Queued ||
            waited.job->state == session::JobState::Running)
            return {true, 200, ToolResult(request, JobJson(*waited.job), false, serverVersion_), {}};
        const auto result = jobs_->TakeResult(owner, job);
        if (!result.job)
            return {true, 200, ToolResult(request, ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, result.job->resultJson,
            result.job->state != session::JobState::Complete, serverVersion_), {}};
    }
    if (request.name == "bn_compute_status")
    {
        if (!Only(*arguments, {}, schemaError))
            return {true, 400, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                schemaError, request.id, {}}};
        const auto compute = ComputeJson(config_, scheduler_);
        if (!compute.error.empty())
            return {true, 200, ToolResult(request, ErrorJson(compute.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, compute.json, false, serverVersion_), {}};
    }
    if (request.name == "bn_analysis_session_create")
    {
        if (!IsModern(request.version))
            return {true, 200, {}, ProtocolError{-32602, 200, "unknown tool", request.id, {}}};
        if (!Only(*arguments, {}, schemaError))
            return {true, 400, {}, ProtocolError{-32602, 400, schemaError, request.id, {}}};
        const auto created = sessions_.Create(principal.id, unixNow, now);
        if (!created.session)
            return {true, 200, ToolResult(request, ErrorJson(created.error), true, serverVersion_), {}};
        return {true, 200,
            ToolResult(request, SessionJson(*created.session), false, serverVersion_), {}};
    }
    if (request.name == "bn_analysis_session_list")
    {
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto sessions = sessions_.List(principal.id, now);
        offset = std::min(offset, sessions.size());
        return {true, 200, ToolResult(request,
            SessionsJson(sessions, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_analysis_session_info" ||
        request.name == "bn_analysis_session_close")
    {
        if (request.name == "bn_analysis_session_close" && !IsModern(request.version))
            return {true, 200, {}, ProtocolError{-32602, 200,
                "unknown tool; the transport manages this legacy analysis session",
                request.id, {}}};
        std::optional<std::string> reference;
        if (request.name == "bn_analysis_session_info")
        {
            if (!Only(*arguments, {"analysisSession"}, schemaError))
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        schemaError, request.id, {}}};
            OptionalStringArgument(
                *arguments, "analysisSession", false, reference, schemaError);
            if ((!reference || *reference == "current") && currentSession)
                reference = currentSession->reference;
            else if (!reference)
                schemaError = "analysisSession is required when no current session exists";
        }
        else
            reference = SessionArgument(*arguments, schemaError);
        if (!reference)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto found = sessions_.Find(*reference, principal.id, now,
            request.name != "bn_analysis_session_close");
        if (!found)
            return {true, 200,
                ToolResult(request, ErrorJson("session not found"), true, serverVersion_), {}};
        if (request.name == "bn_analysis_session_close")
            sessions_.Close(*reference, principal.id);
        return {true, 200, ToolResult(request, SessionJson(*found), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_list")
    {
        if (config_.EffectiveMode() != Mode::Local || !projects_)
            return {true, 200, ToolResult(request,
                ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        return {true, 200, ToolResult(request,
            ProjectsJson(projects_->List(), offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_info")
    {
        if (!Only(*arguments, {"project"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        if (!project)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto found = projects_ ? projects_->Find(*project) : std::nullopt;
        if (config_.EffectiveMode() != Mode::Local || !found)
            return {true, 200, ToolResult(request,
                ErrorJson("project not found"), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectJson(*found), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_file_list")
    {
        if (!Only(*arguments,
                {"project", "folder", "pathPrefix", "query", "offset", "limit"},
                schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        std::optional<std::string> folder;
        std::optional<std::string> pathPrefix;
        std::optional<std::string> query;
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!OptionalStringArgument(*arguments, "folder", false, folder, schemaError) ||
            !OptionalStringArgument(*arguments, "pathPrefix", false, pathPrefix, schemaError) ||
            !OptionalStringArgument(*arguments, "query", false, query, schemaError) || !project)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (const auto member = arguments->FindMember("offset"); member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64() ||
                member->value.GetUint64() > std::numeric_limits<std::size_t>::max())
                schemaError = "offset must be a non-negative integer";
            else
                offset = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (schemaError.empty())
        {
            if (const auto member = arguments->FindMember("limit"); member != arguments->MemberEnd())
            {
                if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                    member->value.GetUint64() > 1000)
                    schemaError = "limit must be an integer from 1 through 1000";
                else
                    limit = static_cast<std::size_t>(member->value.GetUint64());
            }
        }
        if (!schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (config_.EffectiveMode() != Mode::Local || !projectCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
        std::string folderInternalId;
        if (folder)
        {
            const auto normalized = ProjectFolderPath(*folder, schemaError);
            if (!normalized)
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        schemaError, request.id, {}}};
            folder = *normalized;
            const auto found = projectCoordinator_->FindFolder(*project, *folder);
            if (!found.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(found.error), true, serverVersion_), {}};
            folderInternalId = found.value->internalId;
        }
        std::string normalizedPrefix;
        if (pathPrefix)
        {
            const std::filesystem::path value(*pathPrefix);
            const auto normalized = value.lexically_normal();
            if (value.is_absolute() || normalized.empty() || normalized == "." ||
                *normalized.begin() == "..")
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        "pathPrefix must be a contained project-relative path", request.id, {}}};
            normalizedPrefix = normalized.generic_string();
        }
        auto files = projectCoordinator_->ListFiles(*project);
        if (!files.value)
            return {true, 200, ToolResult(request,
                ErrorJson(files.error), true, serverVersion_), {}};
        const auto loweredQuery = query ? AsciiLower(*query) : std::string{};
        std::erase_if(*files.value, [&](const auto& file) {
            if (folder && file.folderInternalId != folderInternalId) return true;
            if (!normalizedPrefix.empty() && !std::string_view(file.path).starts_with(normalizedPrefix))
                return true;
            if (!loweredQuery.empty())
            {
                const auto searchable = AsciiLower(file.path + "\n" + file.name + "\n" + file.description);
                if (searchable.find(loweredQuery) == std::string::npos) return true;
            }
            return false;
        });
        return {true, 200, ToolResult(request,
            ProjectFilesJson(*files.value, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_file_import" ||
        request.name == "bn_local_project_file_import_batch")
    {
        const bool batch = request.name == "bn_local_project_file_import_batch";
        if (!Only(*arguments, batch
                ? std::initializer_list<std::string_view>{"project", "folder", "files"}
                : std::initializer_list<std::string_view>{
                    "project", "folder", "source", "name", "description"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        std::optional<std::string> folder;
        if (!OptionalStringArgument(*arguments, "folder", false, folder, schemaError) || !project)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (principal.role != security::TokenRole::Admin)
            return {true, 200, ToolResult(request,
                ErrorJson("administrator token required"), true, serverVersion_), {}};
        if (!config_.projects.allowArbitraryPaths)
            return {true, 200, ToolResult(request,
                ErrorJson("arbitrary server paths are disabled"), true, serverVersion_), {}};
        if (config_.EffectiveMode() != Mode::Local || !projectCoordinator_ || !projects_ ||
            !projects_->Find(*project))
            return {true, 200, ToolResult(request,
                ErrorJson("local project not found"), true, serverVersion_), {}};

        std::string folderPath;
        if (folder)
        {
            const auto normalized = ProjectFolderPath(*folder, schemaError);
            if (!normalized)
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        schemaError, request.id, {}}};
            folderPath = *normalized;
        }

        struct ImportRequest
        {
            std::string source;
            std::string name;
            std::string description;
        };
        struct ImportOutcome
        {
            ImportRequest request;
            std::string internalId;
            std::string error;
        };
        std::vector<ImportRequest> imports;
        const auto parseImport = [&](const Value& value, bool outer, ImportRequest& item,
                                     std::string& error) -> bool {
            if (!value.IsObject() || !Only(value, outer
                    ? std::initializer_list<std::string_view>{
                        "project", "folder", "source", "name", "description"}
                    : std::initializer_list<std::string_view>{
                        "source", "name", "description"}, error))
            {
                if (error.empty()) error = "import item must be an object";
                return false;
            }
            const auto source = RequiredStringArgument(value, "source", error);
            std::optional<std::string> name;
            std::optional<std::string> description;
            if (!OptionalStringArgument(value, "name", false, name, error) ||
                !OptionalStringArgument(value, "description", true, description, error) ||
                !source)
                return false;
            item.source = *source;
            item.name = name.value_or(std::filesystem::path(*source).filename().string());
            item.description = description.value_or("Imported local file");
            if (!SafeFilenameComponent(item.name))
            {
                error = "name must be one safe filename component";
                return false;
            }
            return true;
        };
        if (batch)
        {
            const auto member = arguments->FindMember("files");
            if (member == arguments->MemberEnd() || !member->value.IsArray() ||
                member->value.Empty() || member->value.Size() > 1000)
                schemaError = "files must be an array containing 1 through 1000 imports";
            else
            {
                imports.reserve(member->value.Size());
                for (rapidjson::SizeType index = 0; index < member->value.Size(); ++index)
                {
                    ImportRequest item;
                    std::string error;
                    if (!parseImport(member->value[index], false, item, error))
                    {
                        schemaError = "files[" + std::to_string(index) + "]: " + error;
                        break;
                    }
                    imports.push_back(std::move(item));
                }
            }
        }
        else
        {
            ImportRequest item;
            if (!parseImport(*arguments, true, item, schemaError))
            {}
            else
                imports.push_back(std::move(item));
        }
        if (!schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};

        std::vector<ImportOutcome> outcomes;
        outcomes.reserve(imports.size());
        for (auto& item : imports)
        {
            ImportOutcome outcome{std::move(item), {}, {}};
            const std::filesystem::path source(outcome.request.source);
            std::error_code filesystemError;
            if (!source.is_absolute() ||
                !std::filesystem::is_regular_file(source, filesystemError) || filesystemError)
            {
                outcome.error = "source path does not resolve to a regular file";
            }
            else
            {
                const auto destination = folderPath.empty()
                    ? outcome.request.name
                    : (std::filesystem::path(folderPath) / outcome.request.name).generic_string();
                const auto committed = projectCoordinator_->CommitFile(*project, destination,
                    source, false, true, outcome.request.description);
                if (committed.value)
                    outcome.internalId = committed.value->internalId;
                else
                    outcome.error = committed.error;
            }
            outcomes.push_back(std::move(outcome));
        }
        const auto refreshed = projectCoordinator_->ListFiles(*project);
        if (!refreshed.value)
            return {true, 200, ToolResult(request,
                ErrorJson(refreshed.error), true, serverVersion_), {}};
        const auto findFile = [&](std::string_view internalId)
            -> const project::LocalProjectFileRecord* {
            const auto found = std::find_if(refreshed.value->begin(), refreshed.value->end(),
                [&](const auto& file) { return file.internalId == internalId; });
            return found == refreshed.value->end() ? nullptr : &*found;
        };
        if (!batch)
        {
            if (!outcomes.front().error.empty())
                return {true, 200, ToolResult(request,
                    ErrorJson(outcomes.front().error), true, serverVersion_), {}};
            const auto* file = findFile(outcomes.front().internalId);
            if (!file)
                return {true, 200, ToolResult(request,
                    ErrorJson("imported project file not found"), true, serverVersion_), {}};
            return {true, 200, ToolResult(request,
                ProjectFileJson(*file), false, serverVersion_), {}};
        }
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("items"); writer.StartArray();
        std::size_t imported = 0;
        for (const auto& outcome : outcomes)
        {
            writer.StartObject(); writer.Key("source");
            writer.String(outcome.request.source.data(),
                static_cast<rapidjson::SizeType>(outcome.request.source.size()));
            if (outcome.error.empty())
            {
                if (const auto* file = findFile(outcome.internalId))
                {
                    writer.Key("file"); WriteProjectFile(writer, *file); ++imported;
                }
                else
                {
                    writer.Key("error"); writer.String("imported project file not found");
                }
            }
            else
            {
                writer.Key("error"); writer.String(outcome.error.data(),
                    static_cast<rapidjson::SizeType>(outcome.error.size()));
            }
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("count"); writer.Uint64(outcomes.size());
        writer.Key("imported"); writer.Uint64(imported);
        writer.Key("failed"); writer.Uint64(outcomes.size() - imported);
        writer.EndObject();
        return {true, 200, ToolResult(request,
            {buffer.GetString(), buffer.GetSize()}, imported != outcomes.size(), serverVersion_), {}};
    }
    if (request.name == "bn_local_project_create")
    {
        if (!Only(*arguments, {"name", "path", "description"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto name = RequiredStringArgument(*arguments, "name", schemaError);
        std::optional<std::string> requestedPath;
        std::optional<std::string> description;
        if (!OptionalStringArgument(*arguments, "path", false, requestedPath, schemaError) ||
            !OptionalStringArgument(*arguments, "description", true, description, schemaError) ||
            !name)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (config_.EffectiveMode() != Mode::Local || !projectCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("local project service is unavailable"),
                true, serverVersion_), {}};
        if (!requestedPath)
        {
            if (!config_.projects.defaultRoot)
                return {true, 200, ToolResult(request,
                    ErrorJson("local project creation requires projects.default_root"),
                    true, serverVersion_), {}};
            if (!SafeFilenameComponent(*name))
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        "name cannot be used as a project filename; provide path", request.id, {}}};
            requestedPath = *name + ".bnpr";
        }
        const std::filesystem::path supplied(*requestedPath);
        const auto normalized = supplied.lexically_normal();
        std::filesystem::path destination;
        if (supplied.is_absolute())
        {
            if (principal.role != security::TokenRole::Admin)
                return {true, 200, ToolResult(request,
                    ErrorJson("administrator token required for an absolute project path"),
                    true, serverVersion_), {}};
            if (!config_.projects.allowArbitraryPaths)
                return {true, 200, ToolResult(request,
                    ErrorJson("arbitrary server paths are disabled"), true, serverVersion_), {}};
            if (normalized.extension() != ".bnpr")
                schemaError = "absolute path must end in .bnpr";
            else
                destination = normalized;
        }
        else if (!config_.projects.defaultRoot || normalized.empty() || normalized == "." ||
            *normalized.begin() == ".." || normalized.extension() != ".bnpr")
            schemaError = "path must be a contained relative path ending in .bnpr";
        else
            destination = (*config_.projects.defaultRoot / normalized).lexically_normal();
        if (!schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto created = projectCoordinator_->CreateProject(
            destination, *name, description.value_or(""));
        if (!created.value)
            return {true, 200, ToolResult(request,
                ErrorJson(created.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectJson(*created.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_register")
    {
        if (!Only(*arguments, {"path"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        if (!path)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (principal.role != security::TokenRole::Admin)
            return {true, 200, ToolResult(request,
                ErrorJson("administrator token required"), true, serverVersion_), {}};
        if (!config_.projects.allowArbitraryPaths)
            return {true, 200, ToolResult(request,
                ErrorJson("arbitrary server paths are disabled"), true, serverVersion_), {}};
        if (config_.EffectiveMode() != Mode::Local || !projectCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
        const auto registered = projectCoordinator_->RegisterProject(*path);
        if (!registered.value)
            return {true, 200, ToolResult(request,
                ErrorJson(registered.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectJson(*registered.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_update")
    {
        if (!Only(*arguments, {"project", "name", "description"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        std::optional<std::string> name;
        std::optional<std::string> description;
        if (!OptionalStringArgument(*arguments, "name", false, name, schemaError) ||
            !OptionalStringArgument(*arguments, "description", true, description, schemaError) ||
            !project || (!name && !description))
        {
            if (schemaError.empty())
                schemaError = "name or description is required";
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        }
        if (config_.EffectiveMode() != Mode::Local || !projectCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
        const auto updated = projectCoordinator_->UpdateProject(*project,
            std::move(name), std::move(description));
        if (!updated.value)
            return {true, 200, ToolResult(request,
                ErrorJson(updated.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectJson(*updated.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_folder_list")
    {
        if (!Only(*arguments, {"project", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (const auto member = arguments->FindMember("offset"); member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64()) schemaError = "offset must be a non-negative integer";
            else offset = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (const auto member = arguments->FindMember("limit");
            schemaError.empty() && member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000)
                schemaError = "limit must be an integer from 1 through 1000";
            else limit = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (!project || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto folders = projectCoordinator_
            ? projectCoordinator_->ListFolders(*project)
            : overseer::ProjectCoordinatorResult<std::vector<project::LocalProjectFolderRecord>>{
                  {}, "local project service is unavailable"};
        if (!folders.value)
            return {true, 200, ToolResult(request,
                ErrorJson(folders.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectFoldersJson(*folders.value, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_folder_create")
    {
        if (!Only(*arguments, {"project", "parent", "name", "description"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto name = RequiredStringArgument(*arguments, "name", schemaError);
        std::optional<std::string> parent;
        std::optional<std::string> description;
        if (!OptionalStringArgument(*arguments, "parent", false, parent, schemaError) ||
            !OptionalStringArgument(*arguments, "description", true, description, schemaError) ||
            !project || !name)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        std::optional<std::string> parentInternalId;
        if (parent)
        {
            const auto normalized = ProjectFolderPath(*parent, schemaError);
            if (!normalized)
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        schemaError, request.id, {}}};
            const auto found = projectCoordinator_
                ? projectCoordinator_->FindFolder(*project, *normalized)
                : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                      {}, "local project service is unavailable"};
            if (!found.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(found.error), true, serverVersion_), {}};
            parentInternalId = found.value->internalId;
        }
        const auto created = projectCoordinator_
            ? projectCoordinator_->CreateFolder(*project,
                  parentInternalId ? std::optional<std::string_view>(*parentInternalId) : std::nullopt,
                  *name, description.value_or(""))
            : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                  {}, "local project service is unavailable"};
        if (!created.value)
            return {true, 200, ToolResult(request,
                ErrorJson(created.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            ProjectFolderJson(*created.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_folder_update")
    {
        if (!Only(*arguments,
                {"project", "path", "name", "description", "parent"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        std::optional<std::string> name;
        std::optional<std::string> description;
        std::optional<std::optional<std::string>> parent;
        if (!OptionalStringArgument(*arguments, "name", false, name, schemaError) ||
            !OptionalStringArgument(*arguments, "description", true, description, schemaError) ||
            !OptionalNullableStringArgument(*arguments, "parent", parent, schemaError) ||
            !project || !path || (!name && !description && !parent))
        {
            if (schemaError.empty()) schemaError = "a folder update is required";
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        }
        const auto normalizedPath = ProjectFolderPath(*path, schemaError);
        if (!normalizedPath)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto previousResult = projectCoordinator_
            ? projectCoordinator_->FindFolder(*project, *normalizedPath)
            : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                  {}, "local project service is unavailable"};
        if (!previousResult.value)
            return {true, 200, ToolResult(request,
                ErrorJson(previousResult.error), true, serverVersion_), {}};
        const auto previous = *previousResult.value;
        std::optional<std::optional<std::string>> parentInternalId;
        if (parent)
        {
            parentInternalId = std::optional<std::string>{};
            if (*parent)
            {
                const auto normalizedParent = ProjectFolderPath(**parent, schemaError);
                if (!normalizedParent)
                    return {true, IsModern(request.version) ? 400 : 200, {},
                        ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                            schemaError, request.id, {}}};
                const auto found = projectCoordinator_->FindFolder(*project, *normalizedParent);
                if (!found.value)
                    return {true, 200, ToolResult(request,
                        ErrorJson(found.error), true, serverVersion_), {}};
                parentInternalId = std::optional<std::string>(found.value->internalId);
            }
        }
        const auto updated = projectCoordinator_
            ? projectCoordinator_->UpdateFolder(*project, previous.internalId,
                  std::move(name), std::move(description), std::move(parentInternalId))
            : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                  {}, "local project service is unavailable"};
        if (!updated.value)
            return {true, 200, ToolResult(request,
                ErrorJson(updated.error), true, serverVersion_), {}};
        if (openItems_ && previous.path != updated.value->path)
            openItems_->UpdateProjectSourcePrefix(
                previous.project, previous.path, updated.value->path);
        return {true, 200, ToolResult(request,
            ProjectFolderJson(*updated.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_folder_delete")
    {
        if (!Only(*arguments, {"project", "path", "recursive"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        bool recursive = false;
        if (!project || !path || !OptionalBooleanArgument(*arguments, "recursive", false,
                recursive, schemaError) || !recursive)
        {
            if (schemaError.empty()) schemaError = "recursive must be true";
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        }
        const auto normalizedPath = ProjectFolderPath(*path, schemaError);
        if (!normalizedPath)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto existing = projectCoordinator_
            ? projectCoordinator_->FindFolder(*project, *normalizedPath)
            : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                  {}, "local project service is unavailable"};
        if (!existing.value)
            return {true, 200, ToolResult(request,
                ErrorJson(existing.error), true, serverVersion_), {}};
        if (openItems_ &&
            openItems_->HasProjectSourcePrefix(existing.value->project, existing.value->path))
            return {true, 200, ToolResult(request,
                ErrorJson("project folder contains an open analysis handle"),
                true, serverVersion_), {}};
        const auto error = projectCoordinator_
            ? projectCoordinator_->DeleteFolder(
                  *project, existing.value->internalId, true)
            : "local project service is unavailable";
        if (!error.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            std::string("{\"path\":\"") + *normalizedPath + "\",\"deleted\":true}",
            false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_file_update")
    {
        if (!Only(*arguments,
                {"project", "path", "name", "description", "folder"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        std::optional<std::string> name;
        std::optional<std::string> description;
        std::optional<std::optional<std::string>> folder;
        if (!OptionalStringArgument(*arguments, "name", false, name, schemaError) ||
            !OptionalStringArgument(*arguments, "description", true, description, schemaError) ||
            !OptionalNullableStringArgument(*arguments, "folder", folder, schemaError) ||
            !project || !path || (!name && !description && !folder))
        {
            if (schemaError.empty()) schemaError = "a file update is required";
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        }
        const auto normalizedPath = ProjectFolderPath(*path, schemaError);
        if (!normalizedPath)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto previous = projects_
            ? projects_->FindFile(*project, *normalizedPath) : std::nullopt;
        std::optional<std::optional<std::string>> folderInternalId;
        if (folder)
        {
            folderInternalId = std::optional<std::string>{};
            if (*folder)
            {
                if (!previous)
                    return {true, 200, ToolResult(request,
                        ErrorJson("project file not found"), true, serverVersion_), {}};
                const auto normalizedFolder = ProjectFolderPath(**folder, schemaError);
                if (!normalizedFolder)
                    return {true, IsModern(request.version) ? 400 : 200, {},
                        ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                            schemaError, request.id, {}}};
                const auto found = projectCoordinator_
                    ? projectCoordinator_->FindFolder(previous->project, *normalizedFolder)
                    : overseer::ProjectCoordinatorResult<project::LocalProjectFolderRecord>{
                          {}, "local project service is unavailable"};
                if (!found.value)
                    return {true, 200, ToolResult(request,
                        ErrorJson(found.error), true, serverVersion_), {}};
                folderInternalId = std::optional<std::string>(found.value->internalId);
            }
        }
        const auto updated = projectCoordinator_
            ? projectCoordinator_->UpdateFile(*project, *normalizedPath,
                  std::move(name), std::move(description), std::move(folderInternalId))
            : overseer::ProjectCoordinatorResult<project::LocalProjectFileRecord>{
                  {}, "local project service is unavailable"};
        if (!updated.value)
            return {true, 200, ToolResult(request,
                ErrorJson(updated.error), true, serverVersion_), {}};
        if (previous && openItems_ && previous->path != updated.value->path)
            openItems_->UpdateProjectSource(
                previous->project, previous->path, updated.value->path);
        return {true, 200, ToolResult(request,
            ProjectFileJson(*updated.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_local_project_file_delete")
    {
        if (!Only(*arguments, {"project", "path", "delete"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        bool confirmed = false;
        if (!project || !path || !OptionalBooleanArgument(*arguments, "delete", false,
                confirmed, schemaError) || !confirmed)
        {
            if (schemaError.empty()) schemaError = "delete must be true";
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        }
        const auto normalizedPath = ProjectFolderPath(*path, schemaError);
        if (!normalizedPath)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto existing = projects_
            ? projects_->FindFile(*project, *normalizedPath) : std::nullopt;
        if (existing && openItems_ &&
            openItems_->HasProjectSource(existing->project, existing->path))
            return {true, 200, ToolResult(request,
                ErrorJson("project file has an open analysis handle"), true, serverVersion_), {}};
        const auto error = projectCoordinator_
            ? projectCoordinator_->DeleteFile(*project, *normalizedPath, true)
            : "local project service is unavailable";
        if (!error.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            std::string("{\"project\":\"") + *project + "\",\"path\":\"" +
                *normalizedPath + "\",\"deleted\":true}",
            false, serverVersion_), {}};
    }
    if (request.name == "bn_collaboration_project_list")
    {
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (config_.EffectiveMode() != Mode::Collaboration || !collaborationManager_)
            return {true, 200, ToolResult(request,
                ErrorJson("collaboration project service is unavailable"),
                true, serverVersion_), {}};
        const auto projects = collaborationManager_->ListProjects(principal);
        if (!projects.value)
            return {true, 200, ToolResult(request,
                ErrorJson(projects.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            CollaborationProjectsJson(*projects.value, offset, limit),
            false, serverVersion_), {}};
    }
    if (request.name == "bn_collaboration_project_info")
    {
        if (!Only(*arguments, {"project"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        if (!project)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto found = collaborationProjects_
            ? collaborationProjects_->Find(principal.id, *project) : std::nullopt;
        if (!found)
            return {true, 200, ToolResult(request,
                ErrorJson("project not found"), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            CollaborationProjectJson(*found), false, serverVersion_), {}};
    }
    if (request.name == "bn_collaboration_project_file_list")
    {
        if (!Only(*arguments, {"project", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (const auto member = arguments->FindMember("offset"); member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64()) schemaError = "offset must be a non-negative integer";
            else offset = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (const auto member = arguments->FindMember("limit");
            schemaError.empty() && member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000)
                schemaError = "limit must be an integer from 1 through 1000";
            else limit = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (!project || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!collaborationManager_)
            return {true, 200, ToolResult(request,
                ErrorJson("collaboration project service is unavailable"),
                true, serverVersion_), {}};
        const auto files = collaborationManager_->ListFiles(principal, *project);
        if (!files.value)
            return {true, 200, ToolResult(request,
                ErrorJson(files.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            CollaborationFilesJson(*files.value, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_project_text_read" || request.name == "bn_project_json_read")
    {
        const bool json = request.name == "bn_project_json_read";
        if (!Only(*arguments, json
                ? std::initializer_list<std::string_view>{"project", "path", "pointer", "offset", "limit"}
                : std::initializer_list<std::string_view>{"project", "path", "query", "offset", "limit"},
                schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        std::optional<std::string> selector;
        if (!OptionalStringArgument(*arguments, json ? "pointer" : "query",
                true, selector, schemaError) || !project || !path)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (const auto member = arguments->FindMember("offset"); member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64() ||
                member->value.GetUint64() > std::numeric_limits<std::size_t>::max())
                schemaError = "offset must be a non-negative integer";
            else
                offset = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (const auto member = arguments->FindMember("limit"); member != arguments->MemberEnd())
        {
            if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 200)
                schemaError = "limit must be an integer from 1 through 200";
            else
                limit = static_cast<std::size_t>(member->value.GetUint64());
        }
        if (!schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};

        ScopedWorkingDirectory cleanup;
        std::filesystem::path documentPath;
        if (config_.EffectiveMode() == Mode::Local)
        {
            if (!projectCoordinator_)
                return {true, 200, ToolResult(request,
                    ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
            auto exported = projectCoordinator_->ExportFile(*project, *path);
            if (!exported.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(exported.error), true, serverVersion_), {}};
            cleanup.path = exported.value->workingDirectory;
            documentPath = exported.value->path;
        }
        else
        {
            if (!collaborationManager_)
                return {true, 200, ToolResult(request,
                    ErrorJson("collaboration project service is unavailable"), true, serverVersion_), {}};
            auto downloaded = collaborationManager_->DownloadFile(principal, *project, *path);
            if (!downloaded.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(downloaded.error), true, serverVersion_), {}};
            cleanup.path = downloaded.value->workingDirectory;
            documentPath = downloaded.value->path;
        }
        std::string documentError;
        const auto output = json
            ? ProjectJsonJson(documentPath, *path, selector.value_or(""),
                  offset, limit, documentError)
            : ProjectTextJson(documentPath, *path, selector.value_or(""),
                  offset, limit, documentError);
        if (!documentError.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(documentError), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, output, false, serverVersion_), {}};
    }
    if (request.name == "bn_open_item_list")
    {
        if (!openItems_)
            return {true, 200, ToolResult(request,
                ErrorJson("open-item service is unavailable"), true, serverVersion_), {}};
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto items = openItems_->ListForToken(principal.id);
        return {true, 200, ToolResult(request,
            OpenItemsJson(items, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_binary_view_list")
    {
        if (!openItems_ || !currentSession)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session is required"), true, serverVersion_), {}};
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto views = openItems_->ListViews(principal.id, currentSession->reference);
        return {true, 200, ToolResult(request,
            BinaryViewsJson(views, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_binary_view_load_settings")
    {
        if (!Only(*arguments, {"binaryView"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (!binaryView)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!openItems_ || !currentSession)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session is required"), true, serverVersion_), {}};
        const auto view = openItems_->FindView(
            principal.id, currentSession->reference, *binaryView);
        if (!view)
            return {true, 200, ToolResult(request,
                ErrorJson("BinaryView not found"), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            BinaryViewLoadSettingsJson(*view), false, serverVersion_), {}};
    }
    if (request.name == "bn_open_item_open" || request.name == "bn_project_file_open")
    {
        if (!Only(*arguments, {"project", "path", "kind", "options", "reuseDatabase"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto path = RequiredStringArgument(*arguments, "path", schemaError);
        if (!path)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        std::optional<std::string> project;
        if (const auto member = arguments->FindMember("project"); member != arguments->MemberEnd())
        {
            if (!member->value.IsString() || member->value.GetStringLength() == 0)
                schemaError = "project must be a non-empty string";
            else
                project.emplace(member->value.GetString(), member->value.GetStringLength());
        }
        if (request.name == "bn_project_file_open" && !project)
            schemaError = "project is required";
        if (!schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (const auto kind = arguments->FindMember("kind"); kind != arguments->MemberEnd())
        {
            if (!kind->value.IsString() ||
                (std::string_view(kind->value.GetString(), kind->value.GetStringLength()) != "auto" &&
                    std::string_view(kind->value.GetString(), kind->value.GetStringLength()) != "file"))
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        "kind must be 'auto' or 'file'", request.id, {}}};
        }
        std::string options;
        bool reuseDatabase = true;
        if (!OptionsArgument(*arguments, options, schemaError) ||
            !OptionalBooleanArgument(
                *arguments, "reuseDatabase", true, reuseDatabase, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session is required"), true, serverVersion_), {}};
        if (!fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("file-child service is unavailable"), true, serverVersion_), {}};
        overseer::CoordinatorResult<session::OpenItemRecord> opened;
        if (project)
        {
            if (config_.EffectiveMode() == Mode::Local)
            {
                if (!projectCoordinator_)
                    return {true, 200, ToolResult(request,
                        ErrorJson("local project service is unavailable"), true, serverVersion_), {}};
                auto exported = projectCoordinator_->ExportFile(*project, *path);
                if (!exported.value)
                    return {true, 200, ToolResult(request,
                        ErrorJson(exported.error), true, serverVersion_), {}};
                if (IsSharedCachePrimaryPath(*path))
                {
                    const auto files = projectCoordinator_->ListFiles(*project);
                    if (!files.value)
                    {
                        std::error_code ignored;
                        std::filesystem::remove_all(exported.value->workingDirectory, ignored);
                        return {true, 200, ToolResult(request,
                            ErrorJson(files.error), true, serverVersion_), {}};
                    }
                    std::string companionError;
                    for (const auto& file : *files.value)
                    {
                        if (!IsSharedCacheCompanionPath(*path, file.path))
                            continue;
                        auto companion = projectCoordinator_->ExportFile(*project, file.path);
                        if (!companion.value)
                        {
                            companionError = companion.error;
                            break;
                        }
                        const auto copied = platform::CopyRegularFilePrivate(companion.value->path,
                            exported.value->workingDirectory /
                                std::filesystem::path(file.path).filename());
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
                        return {true, 200, ToolResult(request,
                            ErrorJson("cannot stage SharedCache companions: " + companionError),
                            true, serverVersion_), {}};
                    }
                }
                opened = fileCoordinator_->OpenManagedPath(principal,
                    currentSession->reference, exported.value->path, std::move(options),
                    reuseDatabase, session::OpenItemSourceKind::LocalProject, *path, *project);
                std::error_code ignored;
                std::filesystem::remove_all(exported.value->workingDirectory, ignored);
            }
            else
            {
                if (!collaborationManager_)
                    return {true, 200, ToolResult(request,
                        ErrorJson("collaboration project service is unavailable"),
                        true, serverVersion_), {}};
                auto downloaded = collaborationManager_->DownloadFile(principal, *project, *path);
                if (!downloaded.value)
                    return {true, 200, ToolResult(request,
                        ErrorJson(downloaded.error), true, serverVersion_), {}};
                if (IsSharedCachePrimaryPath(*path))
                {
                    const auto files = collaborationManager_->ListFiles(principal, *project);
                    if (!files.value)
                    {
                        std::error_code ignored;
                        std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
                        return {true, 200, ToolResult(request,
                            ErrorJson(files.error), true, serverVersion_), {}};
                    }
                    std::string companionError;
                    for (const auto& file : *files.value)
                    {
                        if (!IsSharedCacheCompanionPath(*path, file.path))
                            continue;
                        auto companion = collaborationManager_->DownloadFile(
                            principal, *project, file.path);
                        if (!companion.value)
                        {
                            companionError = companion.error;
                            break;
                        }
                        const auto copied = platform::CopyRegularFilePrivate(companion.value->path,
                            downloaded.value->workingDirectory /
                                std::filesystem::path(file.path).filename());
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
                        return {true, 200, ToolResult(request,
                            ErrorJson("cannot stage SharedCache companions: " + companionError),
                            true, serverVersion_), {}};
                    }
                }
                opened = fileCoordinator_->OpenManagedPath(principal,
                    currentSession->reference, downloaded.value->path, std::move(options),
                    reuseDatabase, session::OpenItemSourceKind::CollaborationProject,
                    *path, *project);
                std::error_code ignored;
                std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);
            }
        }
        else
        {
            opened = fileCoordinator_->OpenArbitraryPath(principal,
                currentSession->reference, *path, std::move(options), reuseDatabase);
        }
        if (!opened.value)
            return {true, 200, ToolResult(request,
                ErrorJson(opened.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            OpenItemJson(*opened.value), false, serverVersion_), {}};
    }
    if (request.name == "bn_open_item_close")
    {
        if (!Only(*arguments, {"openItem", "save"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto openItem = RequiredStringArgument(*arguments, "openItem", schemaError);
        if (!openItem)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        std::string_view save = "prompt";
        if (const auto member = arguments->FindMember("save"); member != arguments->MemberEnd())
        {
            if (!member->value.IsString())
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        "save must be 'prompt', 'save', or 'discard'", request.id, {}}};
            save = {member->value.GetString(), member->value.GetStringLength()};
            if (save != "prompt" && save != "save" && save != "discard")
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        "save must be 'prompt', 'save', or 'discard'", request.id, {}}};
        }
        if (save == "save")
            return {true, 200, ToolResult(request,
                ErrorJson("save an explicit BinaryView with bn_binary_view_save before closing"),
                true, serverVersion_), {}};
        if (!fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("file-child service is unavailable"), true, serverVersion_), {}};
        const auto error = fileCoordinator_->Close(
            principal.id, *openItem, save == "discard");
        if (!error.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(error), true, serverVersion_), {}};
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("openItem");
        writer.String(openItem->data(), static_cast<rapidjson::SizeType>(openItem->size()));
        writer.Key("closed");
        writer.Bool(true);
        writer.EndObject();
        return {true, 200, ToolResult(request,
            {buffer.GetString(), buffer.GetSize()}, false, serverVersion_), {}};
    }
    if (request.name == "bn_binary_view_open")
    {
        if (!Only(*arguments, {"binaryView", "options", "analyze"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        std::string options;
        bool analyze = true;
        if (!binaryView || !OptionsArgument(*arguments, options, schemaError) ||
            !OptionalBooleanArgument(*arguments, "analyze", true, analyze, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto scheduledView = openItems_ ? openItems_->FindView(
            principal.id, currentSession->reference, *binaryView) : std::nullopt;
        if (scheduler_ && !scheduledView)
            return {true, 200, ToolResult(request,
                ErrorJson("BinaryView not found"), true, serverVersion_), {}};
        const auto opened = fileCoordinator_->OpenBinaryView(principal.id,
            currentSession->reference, *binaryView, std::move(options),
            analyze && !scheduler_);
        if (!opened.value)
            return {true, 200, ToolResult(request,
                ErrorJson(opened.error), true, serverVersion_), {}};
        if (analyze && scheduler_)
        {
            if (!jobs_ || !sessions_.Retain(
                    currentSession->reference, principal.id, now))
                return {true, 200, ToolResult(request,
                    ErrorJson("cannot retain analysis session for scheduled analysis"),
                    true, serverVersion_), {}};
            const auto owner = principal.id;
            const auto analysisSession = currentSession->reference;
            const auto view = *binaryView;
            const auto openItem = opened.value->openItem;
            const auto workerError = jobs_->StartWorker(
                [scheduler = scheduler_, coordinator = fileCoordinator_,
                    sessions = &sessions_, owner, analysisSession, view, openItem] {
                    std::string scheduleError;
                    auto lease = scheduler->Acquire({owner, analysisSession, openItem, {}},
                        [coordinator, owner, analysisSession, view](std::size_t workers) {
                            (void)coordinator->SetWorkerCount(
                                owner, analysisSession, view, workers);
                        }, scheduleError);
                    if (lease)
                        (void)coordinator->UpdateAnalysisAndWait(
                            owner, analysisSession, view);
                    sessions->Release(analysisSession, owner);
                });
            if (!workerError.empty())
            {
                sessions_.Release(analysisSession, owner);
                return {true, 200, ToolResult(request,
                    ErrorJson(workerError), true, serverVersion_), {}};
            }
        }
        return {true, 200, ToolResult(request,
            BinaryViewJson(*opened.value), false, serverVersion_), {}};
    }
    const bool kernelCacheTool = request.name == "bn_kernel_cache_image_list" ||
        request.name == "bn_kernel_cache_image_info" ||
        request.name == "bn_kernel_cache_image_load" ||
        request.name == "bn_kernel_cache_symbol_list";
    const bool sharedCacheTool = request.name == "bn_shared_cache_image_list" ||
        request.name == "bn_shared_cache_image_info" ||
        request.name == "bn_shared_cache_image_load" ||
        request.name == "bn_shared_cache_region_list" ||
        request.name == "bn_shared_cache_region_load" ||
        request.name == "bn_shared_cache_entry_list" ||
        request.name == "bn_shared_cache_symbol_list";
    if ((kernelCacheTool && config_.tools.kernelCache) ||
        (sharedCacheTool && config_.tools.sharedCache))
    {
        const bool loadedList = request.name == "bn_kernel_cache_image_list" ||
            request.name == "bn_shared_cache_image_list" ||
            request.name == "bn_shared_cache_region_list";
        const bool queryList = request.name == "bn_kernel_cache_symbol_list" ||
            request.name == "bn_shared_cache_entry_list" ||
            request.name == "bn_shared_cache_symbol_list";
        const bool validFields = loadedList
            ? Only(*arguments, {"binaryView", "loaded", "query", "offset", "limit"}, schemaError)
            : queryList
                ? Only(*arguments, {"binaryView", "query", "offset", "limit"}, schemaError)
                : request.name == "bn_shared_cache_region_load"
                    ? Only(*arguments, {"binaryView", "region"}, schemaError)
                    : Only(*arguments, {"binaryView", "image"}, schemaError);
        if (!validFields)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (request.name.ends_with("_image_info") || request.name.ends_with("_image_load"))
            RequiredStringArgument(*arguments, "image", schemaError);
        if (request.name == "bn_shared_cache_region_load")
            RequiredStringArgument(*arguments, "region", schemaError);
        if (loadedList || queryList)
        {
            if (const auto member = arguments->FindMember("loaded");
                member != arguments->MemberEnd() && !member->value.IsBool())
                schemaError = "loaded must be a boolean";
            if (const auto member = arguments->FindMember("query");
                member != arguments->MemberEnd() && !member->value.IsString())
                schemaError = "query must be a string";
            if (const auto member = arguments->FindMember("offset");
                member != arguments->MemberEnd() && !member->value.IsUint64())
                schemaError = "offset must be a non-negative integer";
            if (const auto member = arguments->FindMember("limit");
                member != arguments->MemberEnd() &&
                (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                    member->value.GetUint64() > 1000))
                schemaError = "limit must be an integer from 1 through 1000";
        }
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    const auto debuggerNameIs = [&](std::initializer_list<std::string_view> names) {
        return std::find(names.begin(), names.end(), request.name) != names.end();
    };
    const bool debuggerImmediate = debuggerNameIs({"bn_debugger_launch", "bn_debugger_connect",
        "bn_debugger_attach", "bn_debugger_go", "bn_debugger_pause",
        "bn_debugger_step_into", "bn_debugger_step_over", "bn_debugger_step_return",
        "bn_debugger_restart", "bn_debugger_quit", "bn_debugger_detach"});
    const bool debuggerWait = debuggerNameIs({"bn_debugger_launch_and_wait",
        "bn_debugger_connect_and_wait", "bn_debugger_attach_and_wait",
        "bn_debugger_go_and_wait", "bn_debugger_pause_and_wait",
        "bn_debugger_step_into_and_wait", "bn_debugger_step_over_and_wait",
        "bn_debugger_step_return_and_wait", "bn_debugger_restart_and_wait"});
    const bool debuggerList = debuggerNameIs({"bn_debugger_process_list", "bn_debugger_thread_list",
        "bn_debugger_register_list", "bn_debugger_module_list",
        "bn_debugger_memory_region_list", "bn_debugger_breakpoint_list"});
    const bool debuggerTool = debuggerImmediate || debuggerWait || debuggerList ||
        debuggerNameIs({"bn_debugger_adapter_list", "bn_debugger_status",
            "bn_debugger_configure", "bn_debugger_frame_list", "bn_debugger_thread_set", "bn_debugger_register_set",
            "bn_debugger_memory_read", "bn_debugger_memory_write",
            "bn_debugger_breakpoint_add", "bn_debugger_breakpoint_delete"});
    if (debuggerTool && config_.tools.debugger &&
        principal.role == security::TokenRole::Admin)
    {
        bool validFields = false;
        if (debuggerImmediate || request.name == "bn_debugger_adapter_list" ||
            request.name == "bn_debugger_status")
            validFields = Only(*arguments, {"binaryView"}, schemaError);
        else if (debuggerWait)
            validFields = Only(*arguments,
                {"binaryView", "timeoutMilliseconds"}, schemaError);
        else if (debuggerList)
            validFields = Only(*arguments, {"binaryView", "offset", "limit"}, schemaError);
        else if (request.name == "bn_debugger_configure")
            validFields = Only(*arguments, {"binaryView", "adapter", "executable",
                "inputFile", "workingDirectory", "commandLine", "remoteHost",
                "remotePort", "attachPid"}, schemaError);
        else if (request.name == "bn_debugger_frame_list")
            validFields = Only(*arguments,
                {"binaryView", "thread", "offset", "limit"}, schemaError);
        else if (request.name == "bn_debugger_thread_set")
            validFields = Only(*arguments, {"binaryView", "thread"}, schemaError);
        else if (request.name == "bn_debugger_register_set")
            validFields = Only(*arguments,
                {"binaryView", "register", "value"}, schemaError);
        else if (request.name == "bn_debugger_memory_read")
            validFields = Only(*arguments,
                {"binaryView", "address", "length"}, schemaError);
        else if (request.name == "bn_debugger_memory_write")
            validFields = Only(*arguments,
                {"binaryView", "address", "hex"}, schemaError);
        else
            validFields = Only(*arguments, {"binaryView", "address"}, schemaError);
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (debuggerWait)
        {
            const auto timeout = arguments->FindMember("timeoutMilliseconds");
            if (timeout == arguments->MemberEnd() || !timeout->value.IsUint64() ||
                timeout->value.GetUint64() == 0 || timeout->value.GetUint64() > 30000)
                schemaError = "timeoutMilliseconds must be an integer from 1 through 30000";
        }
        if (debuggerList || request.name == "bn_debugger_frame_list")
        {
            if (const auto member = arguments->FindMember("offset");
                member != arguments->MemberEnd() && !member->value.IsUint64())
                schemaError = "offset must be a non-negative integer";
            if (const auto member = arguments->FindMember("limit");
                member != arguments->MemberEnd() &&
                (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                    member->value.GetUint64() > 1000))
                schemaError = "limit must be an integer from 1 through 1000";
        }
        if (request.name == "bn_debugger_frame_list" || request.name == "bn_debugger_thread_set")
        {
            const auto thread = arguments->FindMember("thread");
            if (thread != arguments->MemberEnd() && !thread->value.IsUint())
                schemaError = "thread must be an unsigned 32-bit integer";
        }
        for (const auto* field : {"adapter", "executable", "inputFile", "workingDirectory",
                 "commandLine", "remoteHost", "register", "value", "address", "hex"})
        {
            if (const auto member = arguments->FindMember(field);
                member != arguments->MemberEnd() && !member->value.IsString())
                schemaError = std::string(field) + " must be a string";
        }
        if (request.name == "bn_debugger_memory_read")
        {
            const auto length = arguments->FindMember("length");
            if (length == arguments->MemberEnd() || !length->value.IsUint64() ||
                length->value.GetUint64() == 0 || length->value.GetUint64() > 65536)
                schemaError = "length must be an integer from 1 through 65536";
        }
        if (request.name == "bn_debugger_configure")
        {
            if (const auto member = arguments->FindMember("remotePort");
                member != arguments->MemberEnd() &&
                (!member->value.IsUint() || member->value.GetUint() > 65535))
                schemaError = "remotePort must be an integer from 0 through 65535";
            if (const auto member = arguments->FindMember("attachPid");
                member != arguments->MemberEnd() && !member->value.IsInt())
                schemaError = "attachPid must be a signed 32-bit integer";
        }
        if (!validFields || !binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};

        const auto argumentsJson = SerializeValue(*arguments);
        if (!debuggerWait)
        {
            const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
                currentSession->reference, *binaryView, request.name, argumentsJson);
            if (!result.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(result.error), true, serverVersion_), {}};
            return {true, 200, ToolResult(request,
                *result.value, false, serverVersion_), {}};
        }

        if (!jobs_)
            return {true, 200, ToolResult(request,
                ErrorJson("job service is unavailable"), true, serverVersion_), {}};
        const auto owner = principal.id;
        const auto analysisSession = currentSession->reference;
        const auto created = jobs_->Create(owner, analysisSession, *binaryView,
            request.name, unixNow, now);
        if (!created.job)
            return {true, 200, ToolResult(request,
                ErrorJson(created.error), true, serverVersion_), {}};
        const auto job = created.job->reference;
        jobs_->Start(owner, job, unixNow);
        if (attached)
        {
            attached(job, [jobs = jobs_, owner, job] {
                (void)jobs->Cancel(owner, job);
            });
        }
        jobs_->ReportProgress(owner, job, "debugger", 0, 1,
            "waiting for debugger target", unixNow);
        if (progress)
        {
            const auto info = jobs_->Info(owner, job);
            if (info.job) progress(*info.job);
        }
        const auto workerError = jobs_->StartWorker(
            [jobs = jobs_, coordinator = fileCoordinator_, owner, analysisSession,
                binaryView = *binaryView, name = request.name,
                argumentsJson, job, progress] {
                const auto result = coordinator->ExecuteAnalysisTool(owner,
                    analysisSession, binaryView, name, argumentsJson);
                const auto current = jobs->Info(owner, job);
                if (current.job && current.job->cancelRequested)
                {
                    jobs->MarkCancelled(owner, job,
                        ErrorJson("debugger wait cancelled"), CurrentUnixSeconds());
                    return;
                }
                if (!result.value)
                {
                    jobs->Fail(owner, job, ErrorJson(result.error), CurrentUnixSeconds());
                    return;
                }
                jobs->ReportProgress(owner, job, "debugger", 1, 1,
                    "debugger target stopped", CurrentUnixSeconds());
                if (progress)
                {
                    const auto info = jobs->Info(owner, job);
                    if (info.job) progress(*info.job);
                }
                jobs->Complete(owner, job, *result.value, CurrentUnixSeconds());
            });
        if (!workerError.empty())
            jobs_->Fail(owner, job, ErrorJson(workerError), unixNow);
        const auto waited = jobs_->WaitForTerminal(owner, job, config_.jobs.detachAfter);
        if (!waited.job)
            return {true, 200, ToolResult(request,
                ErrorJson(waited.error), true, serverVersion_), {}};
        if (waited.job->state == session::JobState::Queued ||
            waited.job->state == session::JobState::Running)
            return {true, 200, ToolResult(request,
                JobJson(*waited.job), false, serverVersion_), {}};
        const auto result = jobs_->TakeResult(owner, job);
        if (!result.job)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, result.job->resultJson,
            result.job->state != session::JobState::Complete, serverVersion_), {}};
    }
    const bool nativeMutation = request.name == "bn_segment_create" ||
        request.name == "bn_segment_modify" || request.name == "bn_segment_delete" ||
        request.name == "bn_binary_view_rebase" || request.name == "bn_memory_map_preview" ||
        request.name == "bn_function_delete" || request.name == "bn_string_define" ||
        request.name == "bn_string_undefine" || request.name == "bn_transaction_begin" ||
        request.name == "bn_transaction_commit" || request.name == "bn_transaction_rollback" ||
        request.name == "bn_undo" || request.name == "bn_redo" ||
        request.name == "bn_bookmark_create" || request.name == "bn_bookmark_list" ||
        request.name == "bn_bookmark_delete" || request.name == "bn_tag_create" ||
        request.name == "bn_tag_list" || request.name == "bn_tag_delete" ||
        request.name == "bn_metadata_get" || request.name == "bn_metadata_set" ||
        request.name == "bn_metadata_delete";
    if (nativeMutation)
    {
        if (!Only(*arguments, {"binaryView", "start", "length", "newStart", "newLength",
                "dataOffset", "dataLength", "flags", "address", "operation", "function", "arch", "encoding",
                "note", "type", "data", "icon", "id", "key", "value", "query", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (!binaryView)
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request, ErrorJson("analysis session and file-child service are required"), true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name, SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request, ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, *result.value, false, serverVersion_), {}};
    }
    const bool perViewSearch = request.name == "bn_comment_list" ||
        request.name == "bn_comment_search" || request.name == "bn_memory_search" ||
        request.name == "bn_instruction_search" || request.name == "bn_il_search" ||
        request.name == "bn_constant_search";
    if (perViewSearch)
    {
        std::vector<std::string_view> allowed{"binaryView", "offset", "limit"};
        if (request.name == "bn_comment_search") allowed = {"binaryView", "query", "offset", "limit"};
        else if (request.name == "bn_memory_search") allowed = {"binaryView", "pattern", "start", "end", "offset", "limit"};
        else if (request.name == "bn_instruction_search") allowed = {"binaryView", "query", "start", "end", "caseSensitive", "offset", "limit"};
        else if (request.name == "bn_il_search") allowed = {"binaryView", "query", "functionQuery", "level", "ssa", "caseSensitive", "offset", "limit"};
        else if (request.name == "bn_constant_search") allowed = {"binaryView", "value", "start", "end", "offset", "limit"};
        if (!Only(*arguments, allowed, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        const char* required = request.name == "bn_comment_search" || request.name == "bn_instruction_search" || request.name == "bn_il_search" ? "query"
            : request.name == "bn_memory_search" ? "pattern"
            : request.name == "bn_constant_search" ? "value" : nullptr;
        if (required && !RequiredStringArgument(*arguments, required, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        if (!binaryView)
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        std::size_t searchOffset = 0, searchLimit = 50;
        if (!BoundedPagination(*arguments, 200, searchOffset, searchLimit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        (void)searchOffset; (void)searchLimit;
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request, ErrorJson("analysis session and file-child service are required"), true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name, SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request, ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_project_analysis_search")
    {
        if (!Only(*arguments, {"project", "query", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto query = RequiredStringArgument(*arguments, "query", schemaError);
        std::size_t offset = 0, limit = 50;
        if (!BoundedPagination(*arguments, 200, offset, limit, schemaError) || !project || !query)
            return {true, IsModern(request.version) ? 400 : 200, {}, ProtocolError{-32602, IsModern(request.version) ? 400 : 200, schemaError, request.id, {}}};
        if (!openItems_ || !fileCoordinator_)
            return {true, 200, ToolResult(request, ErrorJson("open-item and file-child services are required"), true, serverVersion_), {}};
        struct ProjectMatch { std::string path, binaryView, json; };
        std::vector<ProjectMatch> matches;
        std::size_t searchedViews = 0;
        bool partial = false;
        for (const auto& item : openItems_->ListForToken(principal.id))
        {
            if (!item.project || *item.project != *project) continue;
            for (const auto& view : item.binaryViews)
            {
                if (!view.created) continue;
                const auto argumentsJson = std::string("{\"query\":") + SerializeValue((*arguments)["query"]) + ",\"offset\":0,\"limit\":1000}";
                const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
                    item.analysisSession, view.reference, request.name, argumentsJson);
                if (!result.value) continue;
                ++searchedViews;
                Document found; found.Parse(result.value->data(), result.value->size());
                if (found.HasParseError() || !found.IsObject() || !found.HasMember("matches")) continue;
                if (found.HasMember("truncated") && found["truncated"].IsBool() &&
                    found["truncated"].GetBool()) partial = true;
                for (const auto& match : found["matches"].GetArray())
                    matches.push_back({item.source, view.reference, SerializeValue(match)});
            }
        }
        offset = std::min(offset, matches.size());
        const auto finish = offset + std::min(limit, matches.size() - offset);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer); writer.StartObject();
        writer.Key("matches"); writer.StartArray();
        for (std::size_t index = offset; index < finish; ++index)
        {
            writer.StartObject(); writer.Key("path"); writer.String(matches[index].path.data(), matches[index].path.size());
            writer.Key("binaryView"); writer.String(matches[index].binaryView.data(), matches[index].binaryView.size());
            writer.Key("match"); writer.RawValue(matches[index].json.data(), matches[index].json.size(), rapidjson::kObjectType); writer.EndObject();
        }
        writer.EndArray(); writer.Key("searchedViews"); writer.Uint64(searchedViews);
        writer.Key("coverage"); writer.String("materialized open BinaryViews from this project");
        writer.Key("partial"); writer.Bool(partial);
        writer.Key("count"); writer.Uint64(finish - offset); writer.Key("total"); writer.Uint64(matches.size());
        writer.Key("nextOffset"); if (finish < matches.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < matches.size()); writer.EndObject();
        return {true, 200, ToolResult(request, {buffer.GetString(), buffer.GetSize()}, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_list")
    {
        if (!Only(*arguments, {"binaryView", "offset", "limit", "address",
                "start", "end", "length", "query"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(
            *arguments, "binaryView", schemaError);
        for (const auto* name : {"address", "start", "end", "query"})
        {
            if (const auto member = arguments->FindMember(name);
                member != arguments->MemberEnd() && !member->value.IsString())
                schemaError = std::string(name) + " must be a string";
        }
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (const auto member = arguments->FindMember("length");
            member != arguments->MemberEnd() &&
            !member->value.IsUint64() && !member->value.IsString())
            schemaError = "length must be a non-negative integer or expression";
        const bool hasAddress = arguments->HasMember("address");
        const bool hasStart = arguments->HasMember("start");
        const bool hasEnd = arguments->HasMember("end");
        const bool hasLength = arguments->HasMember("length");
        if (hasAddress && (hasStart || hasEnd || hasLength))
            schemaError = "address cannot be combined with range arguments";
        else if (hasEnd && hasLength)
            schemaError = "end and length are mutually exclusive";
        else if ((hasEnd || hasLength) && !hasStart)
            schemaError = "end and length require start";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_string_list" || request.name == "bn_symbol_list" ||
        request.name == "bn_import_list" || request.name == "bn_export_list")
    {
        if (!Only(*arguments, {"binaryView", "offset", "limit", "address",
                "start", "end", "length", "query"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        for (const auto* name : {"address", "start", "end", "query"})
        {
            if (const auto member = arguments->FindMember(name);
                member != arguments->MemberEnd() && !member->value.IsString())
                schemaError = std::string(name) + " must be a string";
        }
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (const auto member = arguments->FindMember("length");
            member != arguments->MemberEnd() &&
            !member->value.IsUint64() && !member->value.IsString())
            schemaError = "length must be a non-negative integer or expression";
        const bool hasAddress = arguments->HasMember("address");
        const bool hasStart = arguments->HasMember("start");
        const bool hasEnd = arguments->HasMember("end");
        const bool hasLength = arguments->HasMember("length");
        if (hasAddress && (hasStart || hasEnd || hasLength))
            schemaError = "address cannot be combined with range arguments";
        else if (hasEnd && hasLength)
            schemaError = "end and length are mutually exclusive";
        else if ((hasEnd || hasLength) && !hasStart)
            schemaError = "end and length require start";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        auto forwardedName = request.name;
        if (request.name == "bn_export_list" && config_.tools.kernelCache && openItems_)
        {
            const auto target = openItems_->FindView(
                principal.id, currentSession->reference, *binaryView);
            if (target && target->viewType == "KCView")
                forwardedName = "bn_kernel_cache_export_list";
        }
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, forwardedName,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_string_at")
    {
        if (!Only(*arguments, {"binaryView", "address", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 65536))
            schemaError = "limit must be an integer from 1 through 65536";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_symbol_list_at" || request.name == "bn_data_at" ||
        request.name == "bn_comment_get" || request.name == "bn_comment_delete")
    {
        if (!Only(*arguments, {"binaryView", "address"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_entry_point_list" || request.name == "bn_section_list" ||
        request.name == "bn_segment_list")
    {
        if (!Only(*arguments, {"binaryView", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        auto forwardedName = request.name;
        if (request.name == "bn_entry_point_list" && config_.tools.kernelCache && openItems_)
        {
            const auto target = openItems_->FindView(
                principal.id, currentSession->reference, *binaryView);
            if (target && target->viewType == "KCView")
                forwardedName = "bn_kernel_cache_entry_point_list";
        }
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, forwardedName,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_memory_read")
    {
        if (!Only(*arguments, {"binaryView", "address", "length"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        const auto length = arguments->FindMember("length");
        if (length == arguments->MemberEnd() ||
            (!length->value.IsUint64() && !length->value.IsString()) ||
            (length->value.IsUint64() && length->value.GetUint64() > 65536) ||
            (length->value.IsString() && length->value.GetStringLength() == 0))
            schemaError = "length must be an integer from 0 through 65536 or a non-empty expression";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_data_variable_list" || request.name == "bn_relocation_list")
    {
        if (!Only(*arguments, {"binaryView", "offset", "limit", "address",
                "start", "end", "length"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        for (const auto* name : {"address", "start", "end"})
        {
            if (const auto member = arguments->FindMember(name);
                member != arguments->MemberEnd() && !member->value.IsString())
                schemaError = std::string(name) + " must be a string";
        }
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (const auto member = arguments->FindMember("length");
            member != arguments->MemberEnd() &&
            !member->value.IsUint64() && !member->value.IsString())
            schemaError = "length must be a non-negative integer or expression";
        const bool hasAddress = arguments->HasMember("address");
        const bool hasStart = arguments->HasMember("start");
        const bool hasEnd = arguments->HasMember("end");
        const bool hasLength = arguments->HasMember("length");
        if (hasAddress && (hasStart || hasEnd || hasLength))
            schemaError = "address cannot be combined with range arguments";
        else if (hasEnd && hasLength)
            schemaError = "end and length are mutually exclusive";
        else if ((hasEnd || hasLength) && !hasStart)
            schemaError = "end and length require start";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_data_xrefs_from" || request.name == "bn_data_xrefs_to")
    {
        if (!Only(*arguments, {"binaryView", "address", "length", "offset", "limit"},
                schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        if (const auto member = arguments->FindMember("length");
            member != arguments->MemberEnd() &&
            !member->value.IsUint64() && !member->value.IsString())
            schemaError = "length must be a non-negative integer or expression";
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_comment_set")
    {
        if (!Only(*arguments, {"binaryView", "address", "text"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        RequiredStringArgument(*arguments, "text", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_create" || request.name == "bn_entry_point_add")
    {
        if (!Only(*arguments, {"binaryView", "address"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_symbol_define")
    {
        if (!Only(*arguments, {"binaryView", "address", "name", "type", "binding",
                "namespace", "ordinal"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        RequiredStringArgument(*arguments, "name", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "type", false, value, schemaError);
        if (const auto member = arguments->FindMember("type");
            member != arguments->MemberEnd() && member->value.IsString())
        {
            const std::string_view type(member->value.GetString(), member->value.GetStringLength());
            if (type != "FunctionSymbol" && type != "ImportAddressSymbol" &&
                type != "ImportedFunctionSymbol" && type != "DataSymbol" &&
                type != "ImportedDataSymbol" && type != "ExternalSymbol" &&
                type != "LibraryFunctionSymbol" && type != "SymbolicFunctionSymbol" &&
                type != "LocalLabelSymbol")
                schemaError = "type is not a supported symbol type";
        }
        OptionalStringArgument(*arguments, "binding", false, value, schemaError);
        if (const auto member = arguments->FindMember("binding");
            member != arguments->MemberEnd() && member->value.IsString())
        {
            const std::string_view binding(
                member->value.GetString(), member->value.GetStringLength());
            if (binding != "NoBinding" && binding != "LocalBinding" &&
                binding != "GlobalBinding" && binding != "WeakBinding")
                schemaError = "binding is not supported";
        }
        OptionalStringArgument(*arguments, "namespace", true, value, schemaError);
        if (const auto ordinal = arguments->FindMember("ordinal");
            ordinal != arguments->MemberEnd() && !ordinal->value.IsUint64())
            schemaError = "ordinal must be a non-negative integer";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_symbol_rename")
    {
        if (!Only(*arguments, {"binaryView", "address", "name", "type", "namespace",
                "ordinal", "newName"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        RequiredStringArgument(*arguments, "newName", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "name", false, value, schemaError);
        OptionalStringArgument(*arguments, "type", false, value, schemaError);
        OptionalStringArgument(*arguments, "namespace", true, value, schemaError);
        if (const auto ordinal = arguments->FindMember("ordinal");
            ordinal != arguments->MemberEnd() && !ordinal->value.IsUint64())
            schemaError = "ordinal must be a non-negative integer";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_symbol_undefine")
    {
        if (!Only(*arguments, {"binaryView", "address", "name", "type", "namespace",
                "ordinal"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "address", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "name", false, value, schemaError);
        OptionalStringArgument(*arguments, "type", false, value, schemaError);
        OptionalStringArgument(*arguments, "namespace", true, value, schemaError);
        if (const auto ordinal = arguments->FindMember("ordinal");
            ordinal != arguments->MemberEnd() && !ordinal->value.IsUint64())
            schemaError = "ordinal must be a non-negative integer";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_prototype_set")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "prototype"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        RequiredStringArgument(*arguments, "prototype", schemaError);
        std::optional<std::string> architecture;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_calling_convention_set")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "callingConvention"},
                schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        RequiredStringArgument(*arguments, "callingConvention", schemaError);
        std::optional<std::string> architecture;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_variable_rename")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "variable", "source",
                "index", "storage", "newName"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        RequiredStringArgument(*arguments, "variable", schemaError);
        RequiredStringArgument(*arguments, "newName", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "arch", false, value, schemaError);
        OptionalStringArgument(*arguments, "source", false, value, schemaError);
        if (const auto index = arguments->FindMember("index");
            index != arguments->MemberEnd() && !index->value.IsUint())
            schemaError = "index must be a non-negative 32-bit integer";
        if (const auto storage = arguments->FindMember("storage");
            storage != arguments->MemberEnd() && !storage->value.IsInt64())
            schemaError = "storage must be a signed integer";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_variable_set_type")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "variable",
                "variableSource", "index", "storage", "definition", "source", "type",
                "options", "includeDirs", "importDependencies"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        RequiredStringArgument(*arguments, "variable", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "arch", false, value, schemaError);
        OptionalStringArgument(*arguments, "variableSource", false, value, schemaError);
        OptionalStringArgument(*arguments, "definition", false, value, schemaError);
        OptionalStringArgument(*arguments, "source", false, value, schemaError);
        OptionalStringArgument(*arguments, "type", false, value, schemaError);
        const bool hasDefinition = arguments->HasMember("definition");
        const bool hasSource = arguments->HasMember("source");
        if (hasDefinition == hasSource)
            schemaError = "exactly one of definition or source is required";
        else if (arguments->HasMember("type") && !hasSource)
            schemaError = "type requires source";
        if (const auto index = arguments->FindMember("index");
            index != arguments->MemberEnd() && !index->value.IsUint())
            schemaError = "index must be a non-negative 32-bit integer";
        if (const auto storage = arguments->FindMember("storage");
            storage != arguments->MemberEnd() && !storage->value.IsInt64())
            schemaError = "storage must be a signed integer";
        for (const auto* name : {"options", "includeDirs"})
        {
            if (const auto member = arguments->FindMember(name); member != arguments->MemberEnd())
            {
                if (!member->value.IsArray()) schemaError = std::string(name) + " must be an array";
                else for (const auto& item : member->value.GetArray())
                    if (!item.IsString()) schemaError = std::string(name) + " must contain strings";
            }
        }
        if (const auto member = arguments->FindMember("importDependencies");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "importDependencies must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_list")
    {
        if (!Only(*arguments, {"binaryView", "query", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        std::optional<std::string> query;
        OptionalStringArgument(*arguments, "query", true, query, schemaError);
        if (const auto offset = arguments->FindMember("offset");
            offset != arguments->MemberEnd() && !offset->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto limit = arguments->FindMember("limit");
            limit != arguments->MemberEnd() && (!limit->value.IsUint64() ||
                limit->value.GetUint64() == 0 || limit->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_info" || request.name == "bn_type_delete")
    {
        if (!Only(*arguments, {"binaryView", "type"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "type", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_rename")
    {
        if (!Only(*arguments, {"binaryView", "type", "newType"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "type", schemaError);
        RequiredStringArgument(*arguments, "newType", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_xrefs_from")
    {
        if (!Only(*arguments, {"binaryView", "type", "recursive"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "type", schemaError);
        if (const auto recursive = arguments->FindMember("recursive");
            recursive != arguments->MemberEnd() && !recursive->value.IsBool())
            schemaError = "recursive must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_xrefs_to")
    {
        if (!Only(*arguments, {"binaryView", "type", "maxItems"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "type", schemaError);
        if (const auto maxItems = arguments->FindMember("maxItems");
            maxItems != arguments->MemberEnd() &&
            (!maxItems->value.IsUint64() || maxItems->value.GetUint64() == 0))
            schemaError = "maxItems must be a positive integer";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_data_variable_define")
    {
        if (!Only(*arguments, {"binaryView", "datavar", "definition", "source", "type",
                "options", "includeDirs", "importDependencies"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "datavar", schemaError);
        std::optional<std::string> value;
        OptionalStringArgument(*arguments, "definition", false, value, schemaError);
        OptionalStringArgument(*arguments, "source", false, value, schemaError);
        OptionalStringArgument(*arguments, "type", false, value, schemaError);
        const bool hasDefinition = arguments->HasMember("definition");
        const bool hasSource = arguments->HasMember("source");
        if (hasDefinition == hasSource)
            schemaError = "exactly one of definition or source is required";
        else if (arguments->HasMember("type") && !hasSource)
            schemaError = "type requires source";
        for (const auto* name : {"options", "includeDirs"})
        {
            if (const auto member = arguments->FindMember(name); member != arguments->MemberEnd())
            {
                if (!member->value.IsArray()) schemaError = std::string(name) + " must be an array";
                else for (const auto& item : member->value.GetArray())
                    if (!item.IsString()) schemaError = std::string(name) + " must contain strings";
            }
        }
        if (const auto member = arguments->FindMember("importDependencies");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "importDependencies must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_data_variable_undefine")
    {
        if (!Only(*arguments, {"binaryView", "datavar"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "datavar", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_section_create")
    {
        if (!Only(*arguments, {"binaryView", "section", "start", "length", "semantics",
                "typeName", "alignment", "entrySize", "linkedSection", "infoSection",
                "infoData"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "section", schemaError);
        RequiredStringArgument(*arguments, "start", schemaError);
        const auto length = arguments->FindMember("length");
        if (length == arguments->MemberEnd() ||
            (!length->value.IsUint64() && !length->value.IsString()))
            schemaError = "length must be a non-negative integer or expression";
        std::optional<std::string> value;
        for (const auto* name : {"semantics", "typeName", "linkedSection", "infoSection"})
            OptionalStringArgument(*arguments, name, true, value, schemaError);
        if (const auto semantics = arguments->FindMember("semantics");
            semantics != arguments->MemberEnd() && semantics->value.IsString())
        {
            const std::string_view text(
                semantics->value.GetString(), semantics->value.GetStringLength());
            if (text != "DefaultSectionSemantics" && text != "ReadOnlyCodeSectionSemantics" &&
                text != "ReadOnlyDataSectionSemantics" &&
                text != "ReadWriteDataSectionSemantics" && text != "ExternalSectionSemantics")
                schemaError = "semantics is not supported";
        }
        for (const auto* name : {"alignment", "entrySize", "infoData"})
        {
            if (const auto member = arguments->FindMember(name);
                member != arguments->MemberEnd() && !member->value.IsUint64())
                schemaError = std::string(name) + " must be a non-negative integer";
        }
        if (const auto alignment = arguments->FindMember("alignment");
            alignment != arguments->MemberEnd() && alignment->value.IsUint64() &&
            alignment->value.GetUint64() == 0)
            schemaError = "alignment must be positive";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_section_delete")
    {
        if (!Only(*arguments, {"binaryView", "section"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "section", schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_section_modify")
    {
        if (!Only(*arguments, {"binaryView", "section", "newSection", "start", "length",
                "semantics", "typeName", "alignment", "entrySize", "linkedSection",
                "infoSection", "infoData"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "section", schemaError);
        std::optional<std::string> value;
        for (const auto* name : {"newSection", "start", "semantics", "typeName",
                "linkedSection", "infoSection"})
            OptionalStringArgument(*arguments, name,
                std::string_view(name) != "newSection", value, schemaError);
        if (const auto length = arguments->FindMember("length");
            length != arguments->MemberEnd() &&
            !length->value.IsUint64() && !length->value.IsString())
            schemaError = "length must be a non-negative integer or expression";
        if (const auto semantics = arguments->FindMember("semantics");
            semantics != arguments->MemberEnd() && semantics->value.IsString())
        {
            const std::string_view text(
                semantics->value.GetString(), semantics->value.GetStringLength());
            if (text != "DefaultSectionSemantics" && text != "ReadOnlyCodeSectionSemantics" &&
                text != "ReadOnlyDataSectionSemantics" &&
                text != "ReadWriteDataSectionSemantics" && text != "ExternalSectionSemantics")
                schemaError = "semantics is not supported";
        }
        for (const auto* name : {"alignment", "entrySize", "infoData"})
        {
            if (const auto member = arguments->FindMember(name);
                member != arguments->MemberEnd() && !member->value.IsUint64())
                schemaError = std::string(name) + " must be a non-negative integer";
        }
        if (const auto alignment = arguments->FindMember("alignment");
            alignment != arguments->MemberEnd() && alignment->value.IsUint64() &&
            alignment->value.GetUint64() == 0)
            schemaError = "alignment must be positive";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_parse")
    {
        if (!Only(*arguments, {"binaryView", "source", "options", "includeDirs",
                "importDependencies"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "source", schemaError);
        for (const auto* name : {"options", "includeDirs"})
        {
            if (const auto member = arguments->FindMember(name); member != arguments->MemberEnd())
            {
                if (!member->value.IsArray()) schemaError = std::string(name) + " must be an array";
                else for (const auto& item : member->value.GetArray())
                    if (!item.IsString()) schemaError = std::string(name) + " must contain strings";
            }
        }
        if (const auto member = arguments->FindMember("importDependencies");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "importDependencies must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_define")
    {
        if (!Only(*arguments, {"binaryView", "source", "types", "options", "includeDirs",
                "importDependencies"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "source", schemaError);
        for (const auto* name : {"types", "options", "includeDirs"})
        {
            if (const auto member = arguments->FindMember(name); member != arguments->MemberEnd())
            {
                if (!member->value.IsArray()) schemaError = std::string(name) + " must be an array";
                else for (const auto& item : member->value.GetArray())
                    if (!item.IsString()) schemaError = std::string(name) + " must contain strings";
            }
        }
        if (const auto member = arguments->FindMember("importDependencies");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "importDependencies must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_type_struct_create" || request.name == "bn_type_struct_modify" ||
        request.name == "bn_type_union_create" || request.name == "bn_type_union_modify" ||
        request.name == "bn_type_enum_create" || request.name == "bn_type_enum_modify")
    {
        if (!Only(*arguments, {"binaryView", "source", "type", "options", "includeDirs",
                "importDependencies"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "source", schemaError);
        std::optional<std::string> type;
        OptionalStringArgument(*arguments, "type", false, type, schemaError);
        for (const auto* name : {"options", "includeDirs"})
        {
            if (const auto member = arguments->FindMember(name); member != arguments->MemberEnd())
            {
                if (!member->value.IsArray()) schemaError = std::string(name) + " must be an array";
                else for (const auto& item : member->value.GetArray())
                    if (!item.IsString()) schemaError = std::string(name) + " must contain strings";
            }
        }
        if (const auto member = arguments->FindMember("importDependencies");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "importDependencies must be a boolean";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_info" || request.name == "bn_calling_convention_list")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        std::optional<std::string> architecture;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_callers" || request.name == "bn_function_callees" ||
        request.name == "bn_function_disassembly" ||
        request.name == "bn_function_stack_layout" || request.name == "bn_variable_list" ||
        request.name == "bn_function_xrefs_from" || request.name == "bn_function_xrefs_to")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "offset", "limit"},
                schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        std::optional<std::string> architecture;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_decompile")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "language",
                "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        std::optional<std::string> architecture;
        std::optional<std::string> language;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        OptionalStringArgument(*arguments, "language", false, language, schemaError);
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_function_il")
    {
        if (!Only(*arguments, {"binaryView", "function", "arch", "level", "ssa",
                "form", "offset", "limit"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        RequiredStringArgument(*arguments, "function", schemaError);
        std::optional<std::string> architecture;
        OptionalStringArgument(*arguments, "arch", false, architecture, schemaError);
        if (const auto member = arguments->FindMember("level"); member != arguments->MemberEnd())
        {
            if (!member->value.IsString())
                schemaError = "level must be llil, mlil, or hlil";
            else
            {
                const std::string_view level(member->value.GetString(), member->value.GetStringLength());
                if (level != "llil" && level != "mlil" && level != "hlil")
                    schemaError = "level must be llil, mlil, or hlil";
            }
        }
        if (const auto member = arguments->FindMember("ssa");
            member != arguments->MemberEnd() && !member->value.IsBool())
            schemaError = "ssa must be a boolean";
        if (const auto member = arguments->FindMember("form"); member != arguments->MemberEnd() &&
            (!member->value.IsString() ||
                std::string_view(member->value.GetString(), member->value.GetStringLength()) != "text"))
            schemaError = "form must be text";
        if (const auto member = arguments->FindMember("offset");
            member != arguments->MemberEnd() && !member->value.IsUint64())
            schemaError = "offset must be a non-negative integer";
        if (const auto member = arguments->FindMember("limit");
            member != arguments->MemberEnd() &&
            (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
                member->value.GetUint64() > 1000))
            schemaError = "limit must be an integer from 1 through 1000";
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto result = fileCoordinator_->ExecuteAnalysisTool(principal.id,
            currentSession->reference, *binaryView, request.name,
            SerializeValue(*arguments));
        if (!result.value)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            *result.value, false, serverVersion_), {}};
    }
    if (request.name == "bn_job_list")
    {
        if (!jobs_)
            return {true, 200, ToolResult(request,
                ErrorJson("job service is unavailable"), true, serverVersion_), {}};
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto jobs = jobs_->List(principal.id);
        return {true, 200, ToolResult(request,
            JobsJson(jobs, offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_job_info" || request.name == "bn_job_result" ||
        request.name == "bn_job_cancel")
    {
        if (!Only(*arguments, {"job"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto job = RequiredStringArgument(*arguments, "job", schemaError);
        if (!job)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!jobs_)
            return {true, 200, ToolResult(request,
                ErrorJson("job service is unavailable"), true, serverVersion_), {}};
        if (request.name == "bn_job_cancel")
        {
            const auto error = jobs_->Cancel(principal.id, *job);
            if (!error.empty())
                return {true, 200, ToolResult(request,
                    ErrorJson(error), true, serverVersion_), {}};
        }
        const auto result = request.name == "bn_job_result"
            ? jobs_->TakeResult(principal.id, *job) : jobs_->Info(principal.id, *job);
        if (!result.job)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            JobJson(*result.job, request.name == "bn_job_result"), false, serverVersion_), {}};
    }
    if (request.name == "bn_upload_get_url")
    {
        if (!Only(*arguments, {"project", "filename"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto project = RequiredStringArgument(*arguments, "project", schemaError);
        const auto filename = RequiredStringArgument(*arguments, "filename", schemaError);
        if (!project || !filename)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !uploads_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and upload service are required"),
                true, serverVersion_), {}};
        const auto issued = uploads_->Issue(principal.id, currentSession->reference,
            *project, *filename, unixNow, now);
        if (!issued.upload)
            return {true, 200, ToolResult(request,
                ErrorJson(issued.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            UploadIssuedJson(*issued.upload, issued.url,
                config_.uploads.requireBearerAuthentication), false, serverVersion_), {}};
    }
    if (request.name == "bn_upload_list")
    {
        std::size_t offset = 0;
        std::size_t limit = 50;
        if (!Pagination(*arguments, offset, limit, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!uploads_)
            return {true, 200, ToolResult(request,
                ErrorJson("upload service is unavailable"), true, serverVersion_), {}};
        return {true, 200, ToolResult(request,
            UploadsJson(uploads_->List(principal.id), offset, limit), false, serverVersion_), {}};
    }
    if (request.name == "bn_upload_cancel")
    {
        if (!Only(*arguments, {"id"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto id = RequiredStringArgument(*arguments, "id", schemaError);
        if (!id)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!uploads_)
            return {true, 200, ToolResult(request,
                ErrorJson("upload service is unavailable"), true, serverVersion_), {}};
        if (const auto error = uploads_->Cancel(principal.id, *id); !error.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(error), true, serverVersion_), {}};
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("id"); writer.String(id->data(),
            static_cast<rapidjson::SizeType>(id->size()));
        writer.Key("cancelled"); writer.Bool(true); writer.EndObject();
        return {true, 200, ToolResult(request,
            {buffer.GetString(), buffer.GetSize()}, false, serverVersion_), {}};
    }
    if (request.name == "bn_upload_commit")
    {
        if (!Only(*arguments, {"id", "folder", "open", "analyze"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto id = RequiredStringArgument(*arguments, "id", schemaError);
        std::optional<std::string> folder;
        bool open = false;
        bool analyze = false;
        if (!OptionalStringArgument(*arguments, "folder", false, folder, schemaError) ||
            !OptionalBooleanArgument(*arguments, "open", false, open, schemaError) ||
            !OptionalBooleanArgument(*arguments, "analyze", false, analyze, schemaError) ||
            !id)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (analyze)
            open = true;
        if (!currentSession || !uploads_ || !jobs_ ||
            (config_.EffectiveMode() == Mode::Local && !projectCoordinator_) ||
            (config_.EffectiveMode() == Mode::Collaboration && !collaborationManager_))
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session, upload, project, and job services are required"),
                true, serverVersion_), {}};
        if (const auto committed = uploads_->FindCommitResult(
                principal.id, currentSession->reference, *id))
            return {true, 200, ToolResult(request,
                *committed, false, serverVersion_), {}};
        auto payload = uploads_->PreparePayload(principal.id,
            currentSession->reference, *id, now);
        if (!payload.first)
            return {true, 200, ToolResult(request,
                ErrorJson(payload.second), true, serverVersion_), {}};
        if (folder)
        {
            const auto normalized = ProjectFolderPath(*folder, schemaError);
            if (!normalized)
            {
                uploads_->CommitFailed(principal.id, *id);
                return {true, IsModern(request.version) ? 400 : 200, {},
                    ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                        schemaError, request.id, {}}};
            }
            folder = *normalized;
        }
        const auto owner = principal.id;
        const auto analysisSession = currentSession->reference;
        const auto created = jobs_->Create(owner, analysisSession, {},
            "upload_commit", unixNow, now);
        if (!created.job)
        {
            uploads_->CommitFailed(owner, *id);
            return {true, 200, ToolResult(request,
                ErrorJson(created.error), true, serverVersion_), {}};
        }
        const auto job = created.job->reference;
        jobs_->Start(owner, job, unixNow);
        if (attached)
            attached(job, [jobs = jobs_, owner, job] {
                (void)jobs->Cancel(owner, job);
            });
        jobs_->ReportProgress(owner, job, "commit", 0, 1, "committing upload", unixNow);
        if (progress)
        {
            const auto info = jobs_->Info(owner, job);
            if (info.job) progress(*info.job);
        }
        const auto workerError = jobs_->StartWorker(
            [jobs = jobs_, uploads = uploads_, projectCoordinator = projectCoordinator_,
                collaborationManager = collaborationManager_, principal,
                collaborationMode = config_.EffectiveMode() == Mode::Collaboration,
                fileCoordinator = fileCoordinator_, scheduler = scheduler_,
                openItems = openItems_, owner, analysisSession, id = *id,
                folder = std::move(folder), open, analyze, job, progress,
                payload = std::move(*payload.first)]() mutable {
                const auto info = jobs->Info(owner, job);
                if (info.job && info.job->cancelRequested)
                {
                    uploads->CommitFailed(owner, id);
                    jobs->MarkCancelled(owner, job,
                        ErrorJson("job cancelled"), CurrentUnixSeconds());
                    return;
                }
                const auto target = folder
                    ? (std::filesystem::path(*folder) / payload.upload.filename).generic_string()
                    : payload.upload.filename;
                project::LocalProjectFileRecord committedFile;
                session::OpenItemSourceKind sourceKind =
                    session::OpenItemSourceKind::LocalProject;
                std::string commitError;
                if (collaborationMode)
                {
                    const auto committed = collaborationManager->UploadFile(principal,
                        payload.upload.project, payload.path,
                        folder.value_or(""), payload.upload.filename);
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
                        payload.upload.project, target,
                        payload.path, false, true, "Uploaded file");
                    if (committed.value)
                        committedFile = *committed.value;
                    else
                        commitError = committed.error +
                            "; the completed upload remains staged; retry bn_upload_commit "
                            "with the same id after resolving the project write failure";
                }
                if (!commitError.empty())
                {
                    uploads->CommitFailed(owner, id);
                    jobs->Fail(owner, job, ErrorJson(commitError), CurrentUnixSeconds());
                    return;
                }
                const auto committedJson = UploadCommittedJson(payload.upload,
                    committedFile, {});
                uploads->RecordCommit(owner, id, committedJson, false);
                const auto afterCommit = jobs->Info(owner, job);
                if (afterCommit.job && afterCommit.job->cancelRequested)
                {
                    uploads->RecordCommit(owner, id, committedJson);
                    jobs->MarkCancelled(owner, job,
                        committedJson, CurrentUnixSeconds());
                    return;
                }
                std::optional<session::OpenItemRecord> openedRecord;
                if (open)
                {
                    if (!fileCoordinator || !openItems)
                    {
                        uploads->RecordCommit(owner, id, committedJson);
                        jobs->Fail(owner, job,
                            ErrorJson("file-child service is unavailable"), CurrentUnixSeconds());
                        return;
                    }
                    const security::TokenRecord principal{owner, {},
                        security::TokenRole::Admin, {}, 0, {}};
                    auto opened = fileCoordinator->OpenManagedPath(principal,
                        analysisSession, payload.path, "{}", true,
                        sourceKind, committedFile.path, payload.upload.project);
                    if (!opened.value)
                    {
                        uploads->RecordCommit(owner, id, committedJson);
                        jobs->Fail(owner, job, ErrorJson(opened.error), CurrentUnixSeconds());
                        return;
                    }
                    openedRecord = *opened.value;
                    if (analyze)
                    {
                        const auto recommended = std::find_if(opened.value->binaryViews.begin(),
                            opened.value->binaryViews.end(), [](const auto& view) {
                                return view.recommended;
                            });
                        if (recommended == opened.value->binaryViews.end())
                        {
                            fileCoordinator->Close(owner, opened.value->reference, true);
                            uploads->RecordCommit(owner, id, committedJson);
                            jobs->Fail(owner, job,
                                ErrorJson("uploaded file has no recommended BinaryView"),
                                CurrentUnixSeconds());
                            return;
                        }
                        auto materialized = fileCoordinator->OpenBinaryView(owner,
                            analysisSession, recommended->reference, "{}", false);
                        if (!materialized.value)
                        {
                            fileCoordinator->Close(owner, opened.value->reference, true);
                            uploads->RecordCommit(owner, id, committedJson);
                            jobs->Fail(owner, job,
                                ErrorJson(materialized.error), CurrentUnixSeconds());
                            return;
                        }
                        std::optional<overseer::AnalysisScheduler::Lease> lease;
                        if (scheduler)
                        {
                            std::string scheduleError;
                            lease = scheduler->Acquire({owner, analysisSession,
                                opened.value->reference, job},
                                [fileCoordinator, owner, analysisSession,
                                    view = recommended->reference](std::size_t workers) {
                                    (void)fileCoordinator->SetWorkerCount(
                                        owner, analysisSession, view, workers);
                                }, scheduleError);
                            if (!lease)
                            {
                                fileCoordinator->Close(owner, opened.value->reference, true);
                                uploads->RecordCommit(owner, id, committedJson);
                                jobs->MarkCancelled(owner, job,
                                    ErrorJson(scheduleError), CurrentUnixSeconds());
                                return;
                            }
                        }
                        const auto analyzed = fileCoordinator->UpdateAnalysisAndWait(owner,
                            analysisSession, recommended->reference,
                            [jobs, owner, job, progress](const ipc::Progress& update) {
                                jobs->ReportProgress(owner, job, update.phase(),
                                    update.completed(), update.total(), update.message(),
                                    CurrentUnixSeconds());
                                if (progress)
                                {
                                    const auto current = jobs->Info(owner, job);
                                    if (current.job) progress(*current.job);
                                }
                            });
                        if (!analyzed.value || analyzed.value->state() != ipc::ANALYSIS_STATE_COMPLETE)
                        {
                            fileCoordinator->Close(owner, opened.value->reference, true);
                            uploads->RecordCommit(owner, id, committedJson);
                            jobs->Fail(owner, job, ErrorJson(analyzed.value
                                ? analyzed.value->error() : analyzed.error), CurrentUnixSeconds());
                            return;
                        }
                        openedRecord = openItems->FindOpenItem(owner, opened.value->reference);
                    }
                }
                const auto resultJson = UploadCommittedJson(
                    payload.upload, committedFile, openedRecord);
                uploads->RecordCommit(owner, id, resultJson);
                jobs->Complete(owner, job, resultJson, CurrentUnixSeconds());
            });
        if (!workerError.empty())
        {
            uploads_->CommitFailed(owner, *id);
            jobs_->Fail(owner, job, ErrorJson(workerError), unixNow);
        }
        const auto waited = jobs_->WaitForTerminal(owner, job, config_.jobs.detachAfter);
        if (!waited.job)
            return {true, 200, ToolResult(request,
                ErrorJson(waited.error), true, serverVersion_), {}};
        if (waited.job->state == session::JobState::Queued ||
            waited.job->state == session::JobState::Running)
            return {true, 200, ToolResult(request,
                JobJson(*waited.job), false, serverVersion_), {}};
        const auto result = jobs_->TakeResult(owner, job);
        if (!result.job)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, result.job->resultJson,
            result.job->state != session::JobState::Complete, serverVersion_), {}};
    }
    if (request.name == "bn_binary_view_save" ||
        request.name == "bn_binary_view_save_async")
    {
        if (!Only(*arguments,
                {"binaryView", "destination", "message", "resolutions"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        std::optional<std::string> destination;
        std::optional<std::string> message;
        std::string resolutions = "{}";
        if (const auto member = arguments->FindMember("destination");
            member != arguments->MemberEnd())
        {
            if (!member->value.IsString() || member->value.GetStringLength() == 0)
                schemaError = "destination must be a non-empty string";
            else
                destination.emplace(member->value.GetString(), member->value.GetStringLength());
        }
        if (!OptionalStringArgument(*arguments, "message", false, message, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (const auto member = arguments->FindMember("resolutions");
            member != arguments->MemberEnd())
        {
            if (!member->value.IsObject())
                schemaError = "resolutions must be an object";
            else
                resolutions = SerializeValue(member->value);
        }
        if (!binaryView || !schemaError.empty())
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !openItems_ || !fileCoordinator_ || !jobs_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session, file-child, and job services are required"),
                true, serverVersion_), {}};
        const auto view = openItems_->FindView(
            principal.id, currentSession->reference, *binaryView);
        if (!view || !view->created)
            return {true, 200, ToolResult(request,
                ErrorJson("BinaryView not found or not materialized"), true, serverVersion_), {}};
        const auto item = openItems_->FindOpenItem(principal.id, view->openItem);
        if (!item)
            return {true, 200, ToolResult(request,
                ErrorJson("open item not found"), true, serverVersion_), {}};
        if (item->sourceKind == session::OpenItemSourceKind::CollaborationProject &&
            !message)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    "message is required for collaboration saves", request.id, {}}};

        const auto owner = principal.id;
        const auto analysisSession = currentSession->reference;
        const auto jobCreated = jobs_->Create(owner, analysisSession, *binaryView,
            "binary_view_save", unixNow, now);
        if (!jobCreated.job)
            return {true, 200, ToolResult(request,
                ErrorJson(jobCreated.error), true, serverVersion_), {}};
        const auto job = jobCreated.job->reference;
        jobs_->Start(owner, job, unixNow);
        if (request.name == "bn_binary_view_save" && attached)
        {
            attached(job, [jobs = jobs_, owner, job] {
                (void)jobs->Cancel(owner, job);
            });
        }
        jobs_->ReportProgress(owner, job, "save", 0, 0, "save started", unixNow);
        if (request.name == "bn_binary_view_save" && progress)
        {
            const auto info = jobs_->Info(owner, job);
            if (info.job)
                progress(*info.job);
        }

        const auto workerError = jobs_->StartWorker(
            [jobs = jobs_, fileCoordinator = fileCoordinator_,
                projectCoordinator = projectCoordinator_, openItems = openItems_, owner,
                analysisSession, binaryView = *binaryView, item = *item,
                requestedDestination = std::move(destination),
                message = std::move(message), resolutions = std::move(resolutions),
                principal, collaborationManager = collaborationManager_, job,
                requestProgress = request.name == "bn_binary_view_save" ? progress
                                                                         : JobProgressCallback{}] {
                const auto cancelled = [&] {
                    const auto info = jobs->Info(owner, job);
                    return info.job && info.job->cancelRequested;
                };
                if (cancelled())
                {
                    jobs->MarkCancelled(owner, job,
                        ErrorJson("job cancelled"), CurrentUnixSeconds());
                    return;
                }
                const auto saved = fileCoordinator->SaveBinaryView(owner,
                    analysisSession, binaryView, {},
                    [jobs, owner, job, requestProgress](const ipc::Progress& update) {
                        jobs->ReportProgress(owner, job, update.phase(), update.completed(),
                            update.total(), update.message(), CurrentUnixSeconds());
                        if (requestProgress)
                        {
                            const auto info = jobs->Info(owner, job);
                            if (info.job)
                                requestProgress(*info.job);
                        }
                    });
                if (!saved.value)
                {
                    jobs->Fail(owner, job, ErrorJson(saved.error), CurrentUnixSeconds());
                    return;
                }
                const auto discardCreatedDatabase = [&] {
                    if (saved.value->created_database())
                        fileCoordinator->DiscardUncommittedSavedDatabase(
                            owner, analysisSession, binaryView);
                };
                if (cancelled())
                {
                    discardCreatedDatabase();
                    jobs->MarkCancelled(owner, job,
                        ErrorJson("job cancelled before commit"), CurrentUnixSeconds());
                    return;
                }

                std::string committedDestination;
                if (item.sourceKind == session::OpenItemSourceKind::ArbitraryPath)
                {
                    std::filesystem::path target;
                    if (requestedDestination)
                        target = std::filesystem::absolute(*requestedDestination).lexically_normal();
                    else if (saved.value->created_database())
                        target = item.source + ".bndb";
                    else
                        target = item.source;
                    const auto original = std::filesystem::path(item.source).lexically_normal();
                    const bool replace = !saved.value->created_database() && target == original;
                    const auto installed = platform::InstallRegularFileAtomically(
                        saved.value->path(), target, replace);
                    if (!installed.installed)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job, ErrorJson(installed.error), CurrentUnixSeconds());
                        return;
                    }
                    committedDestination = target.string();
                    openItems->UpdateSource(owner, item.reference,
                        session::OpenItemSourceKind::ArbitraryPath,
                        committedDestination, {});
                }
                else if (item.sourceKind == session::OpenItemSourceKind::LocalProject)
                {
                    if (!item.project || !projectCoordinator)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job,
                            ErrorJson("local project service is unavailable"),
                            CurrentUnixSeconds());
                        return;
                    }
                    const auto target = requestedDestination.value_or(
                        saved.value->created_database() ? item.source + ".bndb" : item.source);
                    const bool replace = !saved.value->created_database() && target == item.source;
                    const auto committed = projectCoordinator->CommitFile(
                        *item.project, target, saved.value->path(), replace, false,
                        "Saved analysis database");
                    if (!committed.value)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job, ErrorJson(committed.error), CurrentUnixSeconds());
                        return;
                    }
                    committedDestination = committed.value->path;
                    openItems->UpdateSource(owner, item.reference,
                        session::OpenItemSourceKind::LocalProject,
                        committedDestination, item.project);
                }
                else
                {
                    if (!item.project || !collaborationManager || !message)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job,
                            ErrorJson("collaboration project service is unavailable"),
                            CurrentUnixSeconds());
                        return;
                    }
                    if (requestedDestination)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job,
                            ErrorJson("collaboration Save As is not implemented"),
                            CurrentUnixSeconds());
                        return;
                    }
                    const auto synchronized = collaborationManager->SaveDatabase(
                        principal, *item.project, item.source, saved.value->path(),
                        saved.value->created_database(), *message, resolutions);
                    if (!synchronized.value)
                    {
                        discardCreatedDatabase();
                        jobs->Fail(owner, job, ErrorJson(synchronized.error),
                            CurrentUnixSeconds());
                        return;
                    }
                    if (!synchronized.value->synchronized)
                    {
                        jobs->Fail(owner, job,
                            CollaborationConflictJson(synchronized.value->conflictsJson),
                            CurrentUnixSeconds());
                        return;
                    }
                    committedDestination = synchronized.value->path;
                    openItems->UpdateSource(owner, item.reference,
                        session::OpenItemSourceKind::CollaborationProject,
                        committedDestination, item.project);
                }
                if (saved.value->created_database())
                {
                    const auto promoted = fileCoordinator->PromoteSavedBinaryView(
                        owner, analysisSession, binaryView, saved.value->path());
                    if (!promoted.empty())
                    {
                        jobs->Fail(owner, job, ErrorJson(promoted), CurrentUnixSeconds());
                        return;
                    }
                }
                jobs->Complete(owner, job, SaveResultJson(binaryView,
                    item.reference, committedDestination,
                    saved.value->created_database(), item.sourceKind),
                    CurrentUnixSeconds());
            });
        if (!workerError.empty())
            jobs_->Fail(owner, job, ErrorJson(workerError), unixNow);

        if (request.name == "bn_binary_view_save_async")
        {
            const auto info = jobs_->Info(owner, job);
            return {true, 200, ToolResult(request,
                info.job ? JobJson(*info.job) : ErrorJson("job not found"),
                !info.job, serverVersion_), {}};
        }
        const auto waited = jobs_->WaitForTerminal(owner, job, config_.jobs.detachAfter);
        if (!waited.job)
            return {true, 200, ToolResult(request,
                ErrorJson(waited.error), true, serverVersion_), {}};
        if (waited.job->state == session::JobState::Queued ||
            waited.job->state == session::JobState::Running)
            return {true, 200, ToolResult(request,
                JobJson(*waited.job), false, serverVersion_), {}};
        const auto result = jobs_->TakeResult(owner, job);
        if (!result.job)
            return {true, 200, ToolResult(request,
                ErrorJson(result.error), true, serverVersion_), {}};
        return {true, 200, ToolResult(request, result.job->resultJson,
            result.job->state != session::JobState::Complete, serverVersion_), {}};
    }
    if (request.name == "bn_analysis_status" || request.name == "bn_analysis_update" ||
        request.name == "bn_analysis_update_and_wait" ||
        request.name == "bn_analysis_update_async" || request.name == "bn_analysis_abort")
    {
        if (!Only(*arguments, {"binaryView"}, schemaError))
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        const auto binaryView = RequiredStringArgument(*arguments, "binaryView", schemaError);
        if (!binaryView)
            return {true, IsModern(request.version) ? 400 : 200, {},
                ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
                    schemaError, request.id, {}}};
        if (!currentSession || !fileCoordinator_)
            return {true, 200, ToolResult(request,
                ErrorJson("analysis session and file-child service are required"),
                true, serverVersion_), {}};
        const auto scheduledView = openItems_ ? openItems_->FindView(
            principal.id, currentSession->reference, *binaryView) : std::nullopt;
        if (scheduler_ && !scheduledView)
            return {true, 200, ToolResult(request,
                ErrorJson("BinaryView not found"), true, serverVersion_), {}};
        if (request.name == "bn_analysis_status")
        {
            const auto status = fileCoordinator_->AnalysisStatus(
                principal.id, currentSession->reference, *binaryView);
            if (!status.value)
                return {true, 200, ToolResult(request,
                    ErrorJson(status.error), true, serverVersion_), {}};
            return {true, 200, ToolResult(request,
                AnalysisStatusJson(*status.value), false, serverVersion_), {}};
        }
        if (request.name == "bn_analysis_update_and_wait")
        {
            if (!jobs_)
                return {true, 200, ToolResult(request,
                    ErrorJson("job service is unavailable"), true, serverVersion_), {}};
            const auto owner = principal.id;
            const auto analysisSession = currentSession->reference;
            const auto view = *binaryView;
            const auto openItem = scheduledView ? scheduledView->openItem : std::string{};
            const auto created = jobs_->Create(owner, analysisSession, view,
                "analysis_update", unixNow, now,
                [coordinator = fileCoordinator_, scheduler = scheduler_, owner,
                    analysisSession, view, openItem] {
                    if (scheduler && scheduler->CancelQueued(
                        owner, analysisSession, openItem) != 0)
                        return std::string{};
                    const auto error = coordinator->AbortAnalysis(owner, analysisSession, view);
                    return error.find("no analysis is active") != std::string::npos
                        ? std::string{} : error;
                });
            if (!created.job)
                return {true, 200, ToolResult(request,
                    ErrorJson(created.error), true, serverVersion_), {}};
            const auto job = created.job->reference;
            jobs_->Start(owner, job, unixNow);
            if (attached)
            {
                attached(job, [jobs = jobs_, owner, job] {
                    (void)jobs->Cancel(owner, job);
                });
            }
            jobs_->ReportProgress(owner, job, "analysis", 0, 0,
                "analysis started", unixNow);
            if (progress)
            {
                const auto info = jobs_->Info(owner, job);
                if (info.job)
                    progress(*info.job);
            }
            const auto workerError = jobs_->StartWorker(
                [jobs = jobs_, coordinator = fileCoordinator_, scheduler = scheduler_, owner,
                    analysisSession, view, openItem, job, progress] {
                    const auto beforeStart = jobs->Info(owner, job);
                    if (beforeStart.job && beforeStart.job->cancelRequested)
                    {
                        jobs->MarkCancelled(owner, job,
                            ErrorJson("job cancelled"), CurrentUnixSeconds());
                        return;
                    }
                    std::optional<overseer::AnalysisScheduler::Lease> lease;
                    if (scheduler)
                    {
                        std::string scheduleError;
                        lease = scheduler->Acquire({owner, analysisSession, openItem, job},
                            [coordinator, owner, analysisSession, view](std::size_t workers) {
                                (void)coordinator->SetWorkerCount(
                                    owner, analysisSession, view, workers);
                            }, scheduleError);
                        if (!lease)
                        {
                            jobs->MarkCancelled(owner, job,
                                ErrorJson(scheduleError), CurrentUnixSeconds());
                            return;
                        }
                    }
                    const auto afterQueue = jobs->Info(owner, job);
                    if (afterQueue.job && afterQueue.job->cancelRequested)
                    {
                        jobs->MarkCancelled(owner, job,
                            ErrorJson("job cancelled"), CurrentUnixSeconds());
                        return;
                    }
                    const auto finished = coordinator->UpdateAnalysisAndWait(
                        owner, analysisSession, view,
                        [jobs, owner, job, progress](const ipc::Progress& update) {
                            jobs->ReportProgress(owner, job, update.phase(),
                                update.completed(), update.total(), update.message(),
                                CurrentUnixSeconds());
                            if (progress)
                            {
                                const auto info = jobs->Info(owner, job);
                                if (info.job)
                                    progress(*info.job);
                            }
                        });
                    const auto timestamp = CurrentUnixSeconds();
                    if (!finished.value)
                    {
                        const auto info = jobs->Info(owner, job);
                        if (info.job && info.job->cancelRequested)
                            jobs->MarkCancelled(owner, job,
                                ErrorJson("job cancelled"), timestamp);
                        else
                            jobs->Fail(owner, job, ErrorJson(finished.error), timestamp);
                        return;
                    }
                    const auto json = AnalysisFinishedJson(*finished.value);
                    const auto info = jobs->Info(owner, job);
                    if (finished.value->state() == ipc::ANALYSIS_STATE_ABORTED ||
                        (info.job && info.job->cancelRequested))
                        jobs->MarkCancelled(owner, job, json, timestamp);
                    else if (finished.value->state() == ipc::ANALYSIS_STATE_FAILED)
                        jobs->Fail(owner, job, json, timestamp);
                    else
                        jobs->Complete(owner, job, json, timestamp);
                });
            if (!workerError.empty())
                jobs_->Fail(owner, job, ErrorJson(workerError), unixNow);
            const auto waited = jobs_->WaitForTerminal(
                owner, job, config_.jobs.detachAfter);
            if (!waited.job)
                return {true, 200, ToolResult(request,
                    ErrorJson(waited.error), true, serverVersion_), {}};
            if (waited.job->state == session::JobState::Queued ||
                waited.job->state == session::JobState::Running)
                return {true, 200, ToolResult(request,
                    JobJson(*waited.job), false, serverVersion_), {}};
            const auto result = jobs_->TakeResult(owner, job);
            if (!result.job)
                return {true, 200, ToolResult(request,
                    ErrorJson(result.error), true, serverVersion_), {}};
            return {true, 200, ToolResult(request, result.job->resultJson,
                result.job->state != session::JobState::Complete, serverVersion_), {}};
        }
        if (request.name == "bn_analysis_update_async")
        {
            if (!jobs_)
                return {true, 200, ToolResult(request,
                    ErrorJson("job service is unavailable"), true, serverVersion_), {}};
            const auto owner = principal.id;
            const auto analysisSession = currentSession->reference;
            const auto view = *binaryView;
            const auto openItem = scheduledView ? scheduledView->openItem : std::string{};
            const auto created = jobs_->Create(owner, analysisSession, view,
                "analysis_update", unixNow, now,
                [coordinator = fileCoordinator_, scheduler = scheduler_, owner,
                    analysisSession, view, openItem] {
                    if (scheduler && scheduler->CancelQueued(
                        owner, analysisSession, openItem) != 0)
                        return std::string{};
                    const auto error = coordinator->AbortAnalysis(owner, analysisSession, view);
                    return error.find("no analysis is active") != std::string::npos
                        ? std::string{} : error;
                });
            if (!created.job)
                return {true, 200, ToolResult(request,
                    ErrorJson(created.error), true, serverVersion_), {}};
            jobs_->Start(owner, created.job->reference, unixNow);
            const auto workerError = jobs_->StartWorker(
                [jobs = jobs_, coordinator = fileCoordinator_, scheduler = scheduler_, owner,
                    analysisSession, view, openItem, job = created.job->reference] {
                    const auto beforeStart = jobs->Info(owner, job);
                    if (beforeStart.job && beforeStart.job->cancelRequested)
                    {
                        jobs->MarkCancelled(owner, job,
                            ErrorJson("job cancelled"), CurrentUnixSeconds());
                        return;
                    }
                    std::optional<overseer::AnalysisScheduler::Lease> lease;
                    if (scheduler)
                    {
                        std::string scheduleError;
                        lease = scheduler->Acquire({owner, analysisSession, openItem, job},
                            [coordinator, owner, analysisSession, view](std::size_t workers) {
                                (void)coordinator->SetWorkerCount(
                                    owner, analysisSession, view, workers);
                            }, scheduleError);
                        if (!lease)
                        {
                            jobs->MarkCancelled(owner, job,
                                ErrorJson(scheduleError), CurrentUnixSeconds());
                            return;
                        }
                    }
                    const auto afterQueue = jobs->Info(owner, job);
                    if (afterQueue.job && afterQueue.job->cancelRequested)
                    {
                        jobs->MarkCancelled(owner, job,
                            ErrorJson("job cancelled"), CurrentUnixSeconds());
                        return;
                    }
                    const auto finished = coordinator->UpdateAnalysisAndWait(
                        owner, analysisSession, view,
                        [jobs, owner, job](const ipc::Progress& progress) {
                            jobs->ReportProgress(owner, job, progress.phase(),
                                progress.completed(), progress.total(), progress.message(),
                                CurrentUnixSeconds());
                        });
                    const auto timestamp = CurrentUnixSeconds();
                    if (!finished.value)
                    {
                        const auto info = jobs->Info(owner, job);
                        if (info.job && info.job->cancelRequested)
                            jobs->MarkCancelled(owner, job,
                                ErrorJson("job cancelled"), timestamp);
                        else
                            jobs->Fail(owner, job, ErrorJson(finished.error), timestamp);
                        return;
                    }
                    const auto json = AnalysisFinishedJson(*finished.value);
                    const auto info = jobs->Info(owner, job);
                    if (finished.value->state() == ipc::ANALYSIS_STATE_ABORTED ||
                        (info.job && info.job->cancelRequested))
                        jobs->MarkCancelled(owner, job, json, timestamp);
                    else if (finished.value->state() == ipc::ANALYSIS_STATE_FAILED)
                        jobs->Fail(owner, job, json, timestamp);
                    else
                        jobs->Complete(owner, job, json, timestamp);
                });
            if (!workerError.empty())
                jobs_->Fail(owner, created.job->reference,
                    ErrorJson(workerError), unixNow);
            return {true, 200, ToolResult(request,
                JobJson(*created.job), false, serverVersion_), {}};
        }
        std::string error;
        if (request.name == "bn_analysis_update" && scheduler_)
        {
            if (!jobs_ || !scheduledView || !sessions_.Retain(
                    currentSession->reference, principal.id, now))
                error = "cannot retain analysis session for scheduled analysis";
            else
            {
                const auto owner = principal.id;
                const auto analysisSession = currentSession->reference;
                const auto view = *binaryView;
                const auto openItem = scheduledView->openItem;
                error = jobs_->StartWorker(
                    [scheduler = scheduler_, coordinator = fileCoordinator_,
                        sessions = &sessions_, owner, analysisSession, view, openItem] {
                        std::string scheduleError;
                        auto lease = scheduler->Acquire({owner, analysisSession, openItem, {}},
                            [coordinator, owner, analysisSession, view](std::size_t workers) {
                                (void)coordinator->SetWorkerCount(
                                    owner, analysisSession, view, workers);
                            }, scheduleError);
                        if (lease)
                            (void)coordinator->UpdateAnalysisAndWait(
                                owner, analysisSession, view);
                        sessions->Release(analysisSession, owner);
                    });
                if (!error.empty())
                    sessions_.Release(analysisSession, owner);
            }
        }
        else if (request.name == "bn_analysis_update")
        {
            error = fileCoordinator_->UpdateAnalysis(
                principal.id, currentSession->reference, *binaryView);
        }
        else
        {
            const auto cancelled = scheduler_ && scheduledView
                ? scheduler_->CancelQueued(principal.id,
                    currentSession->reference, scheduledView->openItem)
                : 0;
            error = fileCoordinator_->AbortAnalysis(
                principal.id, currentSession->reference, *binaryView);
            if (cancelled != 0 && error.find("no analysis is active") != std::string::npos)
                error.clear();
        }
        if (!error.empty())
            return {true, 200, ToolResult(request,
                ErrorJson(error), true, serverVersion_), {}};
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("binaryView");
        writer.String(binaryView->data(), static_cast<rapidjson::SizeType>(binaryView->size()));
        writer.Key("requested");
        writer.Bool(true);
        writer.EndObject();
        return {true, 200, ToolResult(request,
            {buffer.GetString(), buffer.GetSize()}, false, serverVersion_), {}};
    }
    return {true, IsModern(request.version) ? 400 : 200, {},
        ProtocolError{-32602, IsModern(request.version) ? 400 : 200,
            "unknown tool", request.id, {}}};
}
}
