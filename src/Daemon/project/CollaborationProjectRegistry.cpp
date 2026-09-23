#include "binjad/project/collaboration_project_registry.hpp"

#include <algorithm>
#include <unordered_map>

namespace binjad::project
{
CollaborationProjectRegistry::CollaborationProjectRegistry(
    reference::FriendlyReferencePool& references) : references_(references)
{
}

CollaborationProjectRegistry::~CollaborationProjectRegistry()
{
    std::lock_guard lock(mutex_);
    for (const auto& [reference, project] : projects_)
        references_.Release(reference);
}

std::string CollaborationProjectRegistry::Replace(std::string_view ownerTokenId,
    std::vector<CollaborationProjectRecord>& projects)
{
    std::lock_guard lock(mutex_);
    std::unordered_map<std::string, std::string> existing;
    for (const auto& [reference, project] : projects_)
    {
        if (project.ownerTokenId == ownerTokenId)
            existing.emplace(project.internalId, reference);
    }
    std::vector<std::string> acquired;
    for (auto& project : projects)
    {
        project.ownerTokenId = ownerTokenId;
        if (const auto found = existing.find(project.internalId); found != existing.end())
        {
            project.reference = found->second;
            existing.erase(found);
        }
        else
        {
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
    }
    for (const auto& [id, reference] : existing)
    {
        references_.Release(reference);
        projects_.erase(reference);
    }
    for (const auto& project : projects)
        projects_[project.reference] = project;
    std::erase_if(files_, [&](const auto& file) {
        return file.ownerTokenId == ownerTokenId && !projects_.contains(file.project);
    });
    return {};
}

std::vector<CollaborationProjectRecord> CollaborationProjectRegistry::List(
    std::string_view ownerTokenId) const
{
    std::lock_guard lock(mutex_);
    std::vector<CollaborationProjectRecord> result;
    for (const auto& [reference, project] : projects_)
    {
        if (project.ownerTokenId == ownerTokenId)
            result.push_back(project);
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.name < right.name ||
            (left.name == right.name && left.reference < right.reference);
    });
    return result;
}

std::optional<CollaborationProjectRecord> CollaborationProjectRegistry::Find(
    std::string_view ownerTokenId, std::string_view reference) const
{
    std::lock_guard lock(mutex_);
    const auto project = projects_.find(std::string(reference));
    if (project == projects_.end() || project->second.ownerTokenId != ownerTokenId)
        return std::nullopt;
    return project->second;
}

void CollaborationProjectRegistry::AssignFiles(std::string_view ownerTokenId,
    std::string_view project, std::vector<CollaborationFileRecord> files)
{
    std::lock_guard lock(mutex_);
    std::erase_if(files_, [&](const auto& file) {
        return file.ownerTokenId == ownerTokenId && file.project == project;
    });
    for (auto& file : files)
    {
        file.ownerTokenId = ownerTokenId;
        file.project = project;
        files_.push_back(std::move(file));
    }
}

std::vector<CollaborationFileRecord> CollaborationProjectRegistry::Files(
    std::string_view ownerTokenId, std::string_view project) const
{
    std::lock_guard lock(mutex_);
    std::vector<CollaborationFileRecord> result;
    for (const auto& file : files_)
    {
        if (file.ownerTokenId == ownerTokenId && file.project == project)
            result.push_back(file);
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.path < right.path ||
            (left.path == right.path && left.internalId < right.internalId);
    });
    return result;
}

void CollaborationProjectRegistry::RemoveByToken(std::string_view ownerTokenId)
{
    std::lock_guard lock(mutex_);
    for (auto project = projects_.begin(); project != projects_.end();)
    {
        if (project->second.ownerTokenId == ownerTokenId)
        {
            references_.Release(project->first);
            project = projects_.erase(project);
        }
        else
            ++project;
    }
    std::erase_if(files_, [&](const auto& file) {
        return file.ownerTokenId == ownerTokenId;
    });
}
}
