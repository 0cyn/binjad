#include "binjad/security/bootstrap_credential.hpp"

#include "binjad/security/crypto.hpp"
#include "binjad/security/random.hpp"
#include "binjad/security/token_authenticator.hpp"

#include <algorithm>
#include <utility>

namespace binjad::security
{
namespace
{
constexpr std::string_view kCredentialKey = "bootstrap-admin";

bool IsDigest(std::string_view value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
    });
}

std::string Stored(std::string_view state, std::string_view digest)
{
    return "1\n" + std::string(state) + '\n' + std::string(digest);
}
}

BootstrapCredential::BootstrapCredential(CredentialStore& credentials)
    : credentials_(credentials)
{
}

std::string BootstrapCredential::Load()
{
    std::lock_guard lock(mutex_);
    if (state_ != State::Unloaded)
        return "bootstrap credential is already loaded";
    return ReloadLocked();
}

std::string BootstrapCredential::Refresh()
{
    std::lock_guard lock(mutex_);
    if (state_ == State::Unloaded)
        return "bootstrap credential must be loaded before refresh";
    if (state_ == State::Pending)
        return {};
    return ReloadLocked();
}

std::string BootstrapCredential::ReloadLocked()
{
    const auto stored = credentials_.Read(kCredentialKey);
    if (!stored.error.empty())
        return "cannot read bootstrap credential: " + stored.error;
    if (!stored.value)
    {
        state_ = State::Missing;
        digest_.clear();
        return {};
    }
    constexpr std::string_view readyPrefix = "1\nready\n";
    constexpr std::string_view pendingPrefix = "1\npending\n";
    if (stored.value->starts_with(pendingPrefix) &&
        IsDigest(std::string_view(*stored.value).substr(pendingPrefix.size())))
    {
        if (const auto error = credentials_.Remove(kCredentialKey); !error.empty())
            return "cannot consume interrupted bootstrap credential: " + error;
        state_ = State::Missing;
        return {};
    }
    if (!stored.value->starts_with(readyPrefix))
        return "bootstrap credential record is malformed";
    digest_ = std::string_view(*stored.value).substr(readyPrefix.size());
    if (!IsDigest(digest_))
    {
        digest_.clear();
        return "bootstrap credential record is malformed";
    }
    state_ = State::Ready;
    return {};
}

BootstrapMintResult BootstrapCredential::Mint()
{
    std::lock_guard lock(mutex_);
    if (state_ == State::Unloaded)
        return {{}, "bootstrap credential must be loaded before minting"};
    auto credential = GenerateHex256();
    if (!credential.value)
        return {{}, "cannot generate bootstrap credential: " + credential.error};
    auto digest = Sha256Hex(*credential.value);
    if (const auto error = credentials_.Write(kCredentialKey, Stored("ready", digest)); !error.empty())
        return {{}, "cannot store bootstrap credential: " + error};
    state_ = State::Ready;
    digest_ = std::move(digest);
    return {std::move(credential.value), {}};
}

BootstrapAuthorization BootstrapCredential::Begin(std::string_view credential)
{
    std::lock_guard lock(mutex_);
    if (state_ == State::Unloaded)
        return {false, "bootstrap credential is not loaded"};
    if (state_ != State::Pending)
    {
        if (const auto error = ReloadLocked(); !error.empty())
            return {false, error};
    }
    if (state_ != State::Ready || !TokenAuthenticator::IsTokenSyntax(credential) ||
        !ConstantTimeEqual(Sha256Hex(credential), digest_))
        return {};
    if (const auto error = credentials_.Write(
        kCredentialKey, Stored("pending", digest_)); !error.empty())
        return {false, "cannot reserve bootstrap credential: " + error};
    state_ = State::Pending;
    return {true, {}};
}

std::string BootstrapCredential::Complete(bool success)
{
    std::lock_guard lock(mutex_);
    if (state_ != State::Pending)
        return "bootstrap credential has no pending use";
    const auto stored = credentials_.Read(kCredentialKey);
    if (!stored.error.empty())
        return "cannot read pending bootstrap credential: " + stored.error;
    if (!stored.value || *stored.value != Stored("pending", digest_))
    {
        state_ = State::Missing;
        digest_.clear();
        return ReloadLocked();
    }
    if (success)
    {
        const auto error = credentials_.Remove(kCredentialKey);
        state_ = State::Missing;
        digest_.clear();
        return error.empty() ? std::string{} : "cannot delete consumed bootstrap credential: " + error;
    }
    if (const auto error = credentials_.Write(
        kCredentialKey, Stored("ready", digest_)); !error.empty())
        return "cannot restore bootstrap credential: " + error;
    state_ = State::Ready;
    return {};
}

bool BootstrapCredential::Available() const
{
    std::lock_guard lock(mutex_);
    return state_ == State::Ready;
}
}
