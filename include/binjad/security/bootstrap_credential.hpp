#pragma once

#include "binjad/security/credential_store.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::security
{
struct BootstrapMintResult
{
    std::optional<std::string> credential;
    std::string error;
};

struct BootstrapAuthorization
{
    bool authorized = false;
    std::string error;
};

class BootstrapCredential
{
  public:
    explicit BootstrapCredential(CredentialStore& credentials);
    std::string Load();
    std::string Refresh();
    BootstrapMintResult Mint();
    BootstrapAuthorization Begin(std::string_view credential);
    std::string Complete(bool success);
    bool Available() const;

  private:
    enum class State
    {
        Unloaded,
        Missing,
        Ready,
        Pending,
    };

    CredentialStore& credentials_;
    State state_ = State::Unloaded;
    std::string digest_;
    mutable std::mutex mutex_;

    std::string ReloadLocked();
};
}
