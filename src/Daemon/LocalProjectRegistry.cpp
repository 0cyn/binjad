#include "binjad/project/LocalProjectRegistry.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace binjad::project
{
namespace
{
constexpr std::string_view kInitialKnownProjects =
    "{\n  \"version\": 1,\n  \"projects\": []\n}\n";

bool ValidKnownProjectPath(const std::filesystem::path& path)
{
    return path.is_absolute() && path == path.lexically_normal() &&
        (path.extension() == ".bnpr" || path.extension() == ".bnpm");
}

std::string ProjectScopedKey(std::string_view project, std::string_view value)
{
    std::string key(project);
    key.push_back('\0');
    key.append(value);
    return key;
}

std::optional<std::vector<std::filesystem::path>> ParseKnownProjects(
    std::string_view contents, std::string& error)
{
    rapidjson::Document document;
    document.Parse(contents.data(), contents.size());
    if (document.HasParseError() || !document.IsObject())
    {
        error = "known project registry must be a JSON object";
        return std::nullopt;
    }
    std::unordered_set<std::string_view> fields;
    for (const auto& member : document.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (name != "version" && name != "projects")
        {
            error = "known project registry contains unknown field '" + std::string(name) + "'";
            return std::nullopt;
        }
        if (!fields.insert(name).second)
        {
            error = "known project registry contains duplicate field '" + std::string(name) + "'";
            return std::nullopt;
        }
    }
    const auto version = document.FindMember("version");
    const auto projects = document.FindMember("projects");
    if (version == document.MemberEnd() || !version->value.IsUint() ||
        version->value.GetUint() != 1)
    {
        error = "known project registry version must be 1";
        return std::nullopt;
    }
    if (projects == document.MemberEnd() || !projects->value.IsArray())
    {
        error = "known project registry projects must be an array";
        return std::nullopt;
    }
    std::vector<std::filesystem::path> result;
    std::set<std::filesystem::path> unique;
    for (rapidjson::SizeType index = 0; index < projects->value.Size(); ++index)
    {
        const auto& value = projects->value[index];
        if (!value.IsString())
        {
            error = "known project registry project paths must be strings";
            return std::nullopt;
        }
        const std::filesystem::path path(
            std::string(value.GetString(), value.GetStringLength()));
        if (!ValidKnownProjectPath(path))
        {
            error = "known project registry paths must be normalized absolute .bnpr or .bnpm paths";
            return std::nullopt;
        }
        if (!unique.insert(path).second)
        {
            error = "known project registry contains a duplicate path";
            return std::nullopt;
        }
        result.push_back(path);
    }
    return result;
}

std::string KnownProjectsJson(const std::vector<std::filesystem::path>& paths)
{
    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("version"); writer.Uint(1);
    writer.Key("projects"); writer.StartArray();
    for (const auto& path : paths)
    {
        const auto value = path.string();
        writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
    }
    writer.EndArray();
    writer.EndObject();
    return std::string(buffer.GetString(), buffer.GetSize()) + '\n';
}
}

KnownProjectStore::KnownProjectStore(
    security::CredentialStore& credentials, std::filesystem::path path)
    : file_(credentials, std::move(path), "projects-integrity")
{
}

std::string KnownProjectStore::Load()
{
    const auto loaded = file_.LoadOrCreate(kInitialKnownProjects, [](std::string_view contents) {
        std::string error;
        const auto paths = ParseKnownProjects(contents, error);
        return paths && paths->empty();
    });
    if (!loaded.contents)
        return loaded.error;
    std::string error;
    auto paths = ParseKnownProjects(*loaded.contents, error);
    if (!paths)
        return error;
    std::lock_guard lock(mutex_);
    paths_ = std::move(*paths);
    return {};
}

std::vector<std::filesystem::path> KnownProjectStore::Paths() const
{
    std::lock_guard lock(mutex_);
    return paths_;
}

std::string KnownProjectStore::Persist(const std::vector<std::filesystem::path>& paths)
{
    if (const auto error = file_.Replace(KnownProjectsJson(paths)); !error.empty())
        return error;
    paths_ = paths;
    return {};
}

std::string KnownProjectStore::Add(const std::filesystem::path& path)
{
    const auto normalized = path.lexically_normal();
    if (!ValidKnownProjectPath(normalized))
        return "known project path must be an absolute .bnpr or .bnpm path";
    std::lock_guard lock(mutex_);
    if (std::find(paths_.begin(), paths_.end(), normalized) != paths_.end())
        return {};
    auto updated = paths_;
    updated.push_back(normalized);
    std::sort(updated.begin(), updated.end());
    return Persist(updated);
}

std::string KnownProjectStore::Remove(const std::filesystem::path& path)
{
    const auto normalized = path.lexically_normal();
    std::lock_guard lock(mutex_);
    auto updated = paths_;
    const auto removed = std::erase(updated, normalized);
    return removed == 0 ? std::string{} : Persist(updated);
}

LocalProjectRegistry::LocalProjectRegistry(reference::FriendlyReferencePool& references)
    : references_(references)
{
}

LocalProjectRegistry::~LocalProjectRegistry()
{
    std::lock_guard lock(mutex_);
    for (const auto& project : projects_)
        references_.Release(project.reference);
}

std::string LocalProjectRegistry::Replace(std::vector<LocalProjectRecord> projects)
{
    std::lock_guard lock(mutex_);
    std::unordered_map<std::string, std::string> existing;
    for (const auto& project : projects_)
        existing.emplace(project.internalId, project.reference);

    std::vector<std::string> acquired;
    for (auto& project : projects)
    {
        if (const auto found = existing.find(project.internalId); found != existing.end())
        {
            project.reference = found->second;
            existing.erase(found);
            continue;
        }
        auto reference = references_.Acquire();
        if (!reference.value)
        {
            for (const auto& value : acquired)
                references_.Release(value);
            return reference.error;
        }
        project.reference = *reference.value;
        acquired.push_back(project.reference);
    }
    for (const auto& [id, reference] : existing)
    {
        for (auto file = files_.begin(); file != files_.end();)
        {
            if (file->second.project == reference)
                file = files_.erase(file);
            else
                ++file;
        }
        for (auto folder = folders_.begin(); folder != folders_.end();)
        {
            if (folder->second.project == reference)
                folder = folders_.erase(folder);
            else
                ++folder;
        }
        references_.Release(reference);
    }
    std::sort(projects.begin(), projects.end(), [](const auto& left, const auto& right) {
        return left.name < right.name ||
            (left.name == right.name && left.reference < right.reference);
    });
    projects_ = std::move(projects);
    return {};
}

std::string LocalProjectRegistry::Upsert(LocalProjectRecord& project)
{
    std::lock_guard lock(mutex_);
    const auto existing = std::find_if(projects_.begin(), projects_.end(),
        [&](const auto& value) { return value.internalId == project.internalId; });
    if (existing != projects_.end())
    {
        project.reference = existing->reference;
        *existing = project;
    }
    else
    {
        auto reference = references_.Acquire();
        if (!reference.value)
            return reference.error;
        project.reference = *reference.value;
        projects_.push_back(project);
    }
    std::sort(projects_.begin(), projects_.end(), [](const auto& left, const auto& right) {
        return left.name < right.name ||
            (left.name == right.name && left.reference < right.reference);
    });
    return {};
}

std::vector<LocalProjectRecord> LocalProjectRegistry::List() const
{
    std::lock_guard lock(mutex_);
    return projects_;
}

std::optional<LocalProjectRecord> LocalProjectRegistry::Find(
    std::string_view reference) const
{
    std::lock_guard lock(mutex_);
    const auto project = std::find_if(projects_.begin(), projects_.end(),
        [&](const auto& value) { return value.reference == reference; });
    return project == projects_.end() ? std::nullopt
                                      : std::optional<LocalProjectRecord>(*project);
}

bool LocalProjectRegistry::RemoveProject(std::string_view reference)
{
    std::lock_guard lock(mutex_);
    const auto project = std::find_if(projects_.begin(), projects_.end(),
        [&](const auto& value) { return value.reference == reference; });
    if (project == projects_.end())
        return false;
    for (auto file = files_.begin(); file != files_.end();)
    {
        if (file->second.project == reference)
            file = files_.erase(file);
        else
            ++file;
    }
    for (auto folder = folders_.begin(); folder != folders_.end();)
    {
        if (folder->second.project == reference)
            folder = folders_.erase(folder);
        else
            ++folder;
    }
    references_.Release(project->reference);
    projects_.erase(project);
    return true;
}

std::string LocalProjectRegistry::AssignFiles(std::string_view project,
    std::vector<LocalProjectFileRecord>& files)
{
    std::lock_guard lock(mutex_);
    std::unordered_set<std::string> paths;
    for (auto& file : files)
    {
        if (file.path.empty() || !paths.insert(file.path).second)
            return "project contains duplicate or empty file path '" + file.path + "'";
        file.project = project;
        file.folderPath.reset();
        if (!file.folderInternalId.empty())
        {
            const auto folder = std::find_if(folders_.begin(), folders_.end(),
                [&](const auto& entry) {
                    return entry.second.project == project &&
                        entry.second.internalId == file.folderInternalId;
                });
            if (folder != folders_.end())
                file.folderPath = folder->second.path;
        }
    }
    for (auto existing = files_.begin(); existing != files_.end();)
    {
        if (existing->second.project == project)
            existing = files_.erase(existing);
        else
            ++existing;
    }
    for (const auto& file : files)
        files_[ProjectScopedKey(project, file.path)] = file;
    return {};
}

std::string LocalProjectRegistry::AssignFolders(std::string_view project,
    std::vector<LocalProjectFolderRecord>& folders)
{
    std::lock_guard lock(mutex_);
    std::unordered_set<std::string> paths;
    std::unordered_map<std::string, std::string> pathsById;
    for (auto& folder : folders)
    {
        if (folder.path.empty() || !paths.insert(folder.path).second)
            return "project contains duplicate or empty folder path '" + folder.path + "'";
        if (folder.internalId.empty() || !pathsById.emplace(folder.internalId, folder.path).second)
            return "project contains duplicate or empty folder identity";
        folder.project = project;
    }
    for (auto existing = folders_.begin(); existing != folders_.end();)
    {
        if (existing->second.project == project)
            existing = folders_.erase(existing);
        else
            ++existing;
    }
    for (auto& folder : folders)
    {
        folder.parentPath.reset();
        if (const auto parent = pathsById.find(folder.parentInternalId);
            parent != pathsById.end())
            folder.parentPath = parent->second;
        folders_[ProjectScopedKey(project, folder.internalId)] = folder;
    }
    return {};
}

std::optional<LocalProjectFileRecord> LocalProjectRegistry::FindFile(
    std::string_view project, std::string_view path) const
{
    std::lock_guard lock(mutex_);
    const auto file = files_.find(ProjectScopedKey(project, path));
    return file == files_.end() ? std::nullopt : std::optional(file->second);
}

std::optional<LocalProjectFolderRecord> LocalProjectRegistry::FindFolderById(
    std::string_view project, std::string_view internalId) const
{
    std::lock_guard lock(mutex_);
    const auto folder = folders_.find(ProjectScopedKey(project, internalId));
    return folder == folders_.end() ? std::nullopt : std::optional(folder->second);
}

void LocalProjectRegistry::RemoveFile(std::string_view project, std::string_view path)
{
    std::lock_guard lock(mutex_);
    files_.erase(ProjectScopedKey(project, path));
}

std::size_t LocalProjectRegistry::Size() const
{
    std::lock_guard lock(mutex_);
    return projects_.size();
}
}
