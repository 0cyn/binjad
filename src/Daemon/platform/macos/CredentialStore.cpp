#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/CredentialVault.hpp"

#include "../../security/PlatformCredentialStore.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace binjad::security
{
namespace
{
constexpr std::string_view kService = "me.cynder.binjad";
constexpr std::string_view kVaultAccount = "credential-vault";
constexpr std::string_view kVaultLabel = "binjad";

struct VaultReadResult
{
    std::optional<CredentialVaultValues> values;
    std::string error;
};

std::string StatusMessage(OSStatus status)
{
    CFStringRef message = SecCopyErrorMessageString(status, nullptr);
    if (!message)
        return "Keychain error " + std::to_string(status);
    const auto length = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(message), kCFStringEncodingUTF8) + 1;
    std::string output(static_cast<std::size_t>(length), '\0');
    if (!CFStringGetCString(message, output.data(), length, kCFStringEncodingUTF8))
        output = "Keychain error " + std::to_string(status);
    else
        output.resize(std::char_traits<char>::length(output.c_str()));
    CFRelease(message);
    return output;
}

CFStringRef String(std::string_view value)
{
    return CFStringCreateWithBytes(kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(value.data()), value.size(), kCFStringEncodingUTF8, false);
}

CFMutableDictionaryRef Query(std::string_view service)
{
    auto query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const auto serviceValue = String(service);
    const auto keyValue = String(kVaultAccount);
    if (!query || !serviceValue || !keyValue)
    {
        if (query)
            CFRelease(query);
        if (serviceValue)
            CFRelease(serviceValue);
        if (keyValue)
            CFRelease(keyValue);
        return nullptr;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceValue);
    CFDictionarySetValue(query, kSecAttrAccount, keyValue);
    CFRelease(serviceValue);
    CFRelease(keyValue);
    return query;
}

bool SetLabel(CFMutableDictionaryRef attributes)
{
    const auto label = String(kVaultLabel);
    if (!label)
        return false;
    CFDictionarySetValue(attributes, kSecAttrLabel, label);
    CFRelease(label);
    return true;
}

VaultReadResult ReadVault(std::string_view service)
{
    const auto query = Query(service);
    if (!query)
        return {{}, "cannot allocate Keychain query"};
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = nullptr;
    const auto status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecItemNotFound)
        return {};
    if (status != errSecSuccess)
        return {{}, StatusMessage(status)};
    if (!result || CFGetTypeID(result) != CFDataGetTypeID())
    {
        if (result)
            CFRelease(result);
        return {{}, "Keychain returned an invalid credential vault"};
    }
    const auto data = static_cast<CFDataRef>(result);
    const std::string contents(reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
        static_cast<std::size_t>(CFDataGetLength(data)));
    CFRelease(result);
    auto parsed = ParseCredentialVault(contents);
    if (!parsed.values)
        return {{}, parsed.error};
    return {std::move(parsed.values), {}};
}

std::string DeleteService(std::string_view service)
{
    const auto query = Query(service);
    if (!query)
        return "cannot allocate Keychain query";
    CFDictionaryRemoveValue(query, kSecAttrAccount);
    while (true)
    {
        const auto status = SecItemDelete(query);
        if (status == errSecItemNotFound)
        {
            CFRelease(query);
            return {};
        }
        if (status != errSecSuccess)
        {
            CFRelease(query);
            return StatusMessage(status);
        }
    }
}

class MacCredentialStore final : public CredentialStore
{
  public:
    explicit MacCredentialStore(PlatformCredentialStoreOptions options)
        : service_(options.standardInstallation
                  ? std::string(kService)
                  : std::string(kService) + "." + options.namespaceId),
          legacyService_(options.standardInstallation
                  ? std::string(kService) + "." + std::move(options.namespaceId)
                  : std::string{})
    {
    }

    CredentialReadResult Read(std::string_view key) override
    {
        std::lock_guard lock(mutex_);
        if (const auto error = LoadLocked(); !error.empty())
            return {{}, error};
        const auto value = values_.find(std::string(key));
        return value == values_.end() ? CredentialReadResult{}
                                      : CredentialReadResult{value->second, {}};
    }

    std::string Write(std::string_view key, std::string_view value) override
    {
        std::lock_guard lock(mutex_);
        if (const auto error = LoadLocked(); !error.empty())
            return error;
        auto updated = values_;
        updated[std::string(key)] = std::string(value);
        if (const auto error = PersistLocked(updated); !error.empty())
            return error;
        values_ = std::move(updated);
        return {};
    }

    std::string Remove(std::string_view key) override
    {
        std::lock_guard lock(mutex_);
        if (const auto error = LoadLocked(); !error.empty())
            return error;
        if (!values_.contains(std::string(key)))
            return {};
        auto updated = values_;
        updated.erase(std::string(key));
        if (const auto error = PersistLocked(updated); !error.empty())
            return error;
        values_ = std::move(updated);
        return {};
    }

  private:
    std::string LoadLocked()
    {
        if (loaded_)
            return {};

        auto current = ReadVault(service_);
        if (!current.error.empty())
            return current.error;
        if (current.values)
        {
            values_ = std::move(*current.values);
            if (!legacyService_.empty())
            {
                if (const auto error = DeleteService(legacyService_); !error.empty())
                    return "cannot remove legacy Keychain credentials: " + error;
            }
            loaded_ = true;
            return {};
        }

        if (!legacyService_.empty())
        {
            // Move the former default-config item only after the stable item is durable.
            auto legacy = ReadVault(legacyService_);
            if (!legacy.error.empty())
                return "cannot read legacy Keychain credential vault: " + legacy.error;
            if (legacy.values)
            {
                if (const auto error = PersistServiceLocked(service_, *legacy.values); !error.empty())
                    return "cannot migrate Keychain credential vault: " + error;
                if (const auto error = DeleteService(legacyService_); !error.empty())
                    return "cannot remove legacy Keychain credentials: " + error;
                values_ = std::move(*legacy.values);
                loaded_ = true;
                return {};
            }
        }

        values_.clear();
        loaded_ = true;
        return {};
    }

    std::string PersistLocked(const CredentialVaultValues& values)
    {
        return PersistServiceLocked(service_, values);
    }

    std::string PersistServiceLocked(
        std::string_view service, const CredentialVaultValues& values)
    {
        const auto contents = SerializeCredentialVault(values);
        const auto query = Query(service);
        if (!query)
            return "cannot allocate Keychain query";
        const auto data = CFDataCreate(kCFAllocatorDefault,
            reinterpret_cast<const UInt8*>(contents.data()), contents.size());
        const auto update = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!data || !update)
        {
            if (data)
                CFRelease(data);
            if (update)
                CFRelease(update);
            CFRelease(query);
            return "cannot allocate Keychain credential value";
        }
        CFDictionarySetValue(update, kSecValueData, data);
        if (!SetLabel(update))
        {
            CFRelease(update);
            CFRelease(data);
            CFRelease(query);
            return "cannot allocate Keychain credential label";
        }
        auto status = SecItemUpdate(query, update);
        if (status == errSecItemNotFound)
        {
            CFDictionarySetValue(query, kSecValueData, data);
            if (!SetLabel(query))
            {
                CFRelease(update);
                CFRelease(data);
                CFRelease(query);
                return "cannot allocate Keychain credential label";
            }
            status = SecItemAdd(query, nullptr);
        }
        CFRelease(update);
        CFRelease(data);
        CFRelease(query);
        return status == errSecSuccess ? std::string{} : StatusMessage(status);
    }

    std::string service_;
    std::string legacyService_;
    CredentialVaultValues values_;
    bool loaded_ = false;
    std::mutex mutex_;
};
}

std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(
    PlatformCredentialStoreOptions options)
{
    return std::make_unique<MacCredentialStore>(std::move(options));
}
}
