#pragma once

#include "binjad/security/CredentialStore.hpp"

#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::security
{
struct IntegrityFileLoadResult
{
    std::optional<std::string> contents;
    bool created = false;
    std::string error;
};

class IntegrityFile
{
  public:
    using EnrollExisting = std::function<bool(std::string_view)>;

    IntegrityFile(CredentialStore& credentials, std::filesystem::path path,
        std::string credentialKey);
    IntegrityFileLoadResult LoadOrCreate(
        std::string_view initialContents, const EnrollExisting& mayEnrollExisting);
    std::string Replace(std::string_view contents);

  private:
    CredentialStore& credentials_;
    std::filesystem::path path_;
    std::string credentialKey_;
    std::optional<std::string> currentDigest_;
    std::mutex mutex_;
};
}
