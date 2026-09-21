#pragma once

#include "binjad/reference/friendly_reference.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binjad::project
{
struct CollaborationProjectRecord
{
    std::string reference;
    std::string ownerTokenId;
    std::string internalId;
    std::string name;
    std::string description;
    std::int64_t created = 0;
    std::int64_t lastModified = 0;
    bool admin = false;
};

struct CollaborationFileRecord
{
    std::string ownerTokenId;
    std::string project;
    std::string internalId;
    std::string path;
    std::string name;
    std::string description;
    std::uint64_t size = 0;
    std::uint32_t type = 0;
};

class CollaborationProjectRegistry
{
  public:
    explicit CollaborationProjectRegistry(reference::FriendlyReferencePool& references);
    ~CollaborationProjectRegistry();

    std::string Replace(std::string_view ownerTokenId,
        std::vector<CollaborationProjectRecord>& projects);
    std::vector<CollaborationProjectRecord> List(std::string_view ownerTokenId) const;
    std::optional<CollaborationProjectRecord> Find(
        std::string_view ownerTokenId, std::string_view reference) const;
    void AssignFiles(std::string_view ownerTokenId, std::string_view project,
        std::vector<CollaborationFileRecord> files);
    std::vector<CollaborationFileRecord> Files(
        std::string_view ownerTokenId, std::string_view project) const;
    void RemoveByToken(std::string_view ownerTokenId);

  private:
    reference::FriendlyReferencePool& references_;
    std::unordered_map<std::string, CollaborationProjectRecord> projects_;
    std::vector<CollaborationFileRecord> files_;
    mutable std::mutex mutex_;
};
}
