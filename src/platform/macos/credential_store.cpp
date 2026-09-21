#include "binjad/security/credential_store.hpp"
#include "binjad/security/credential_vault.hpp"

#include "../../security/platform_credential_store.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <memory>
#include <mutex>
#include <string>

namespace binjad::security
{
namespace
{
constexpr std::string_view kVaultAccount = "credential-vault";

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

class MacCredentialStore final : public CredentialStore
{
  public:
    explicit MacCredentialStore(std::string namespaceId)
        : service_("me.cynder.binjad." + std::move(namespaceId))
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
        // Service commands and the daemon are separate processes sharing this vault.
        const auto query = Query(service_);
        if (!query)
            return "cannot allocate Keychain query";
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
        CFTypeRef result = nullptr;
        const auto status = SecItemCopyMatching(query, &result);
        CFRelease(query);
        if (status == errSecItemNotFound)
        {
            values_.clear();
            return {};
        }
        if (status != errSecSuccess)
            return StatusMessage(status);
        if (!result || CFGetTypeID(result) != CFDataGetTypeID())
        {
            if (result)
                CFRelease(result);
            return "Keychain returned an invalid credential vault";
        }
        const auto data = static_cast<CFDataRef>(result);
        const std::string contents(reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
            static_cast<std::size_t>(CFDataGetLength(data)));
        CFRelease(result);
        auto parsed = ParseCredentialVault(contents);
        if (!parsed.values)
            return parsed.error;
        values_ = std::move(*parsed.values);
        return {};
    }

    std::string PersistLocked(const CredentialVaultValues& values)
    {
        const auto contents = SerializeCredentialVault(values);
        const auto query = Query(service_);
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
        auto status = SecItemUpdate(query, update);
        if (status == errSecItemNotFound)
        {
            CFDictionarySetValue(query, kSecValueData, data);
            status = SecItemAdd(query, nullptr);
        }
        CFRelease(update);
        CFRelease(data);
        CFRelease(query);
        return status == errSecSuccess ? std::string{} : StatusMessage(status);
    }

    std::string service_;
    CredentialVaultValues values_;
    std::mutex mutex_;
};
}

std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(std::string_view namespaceId)
{
    return std::make_unique<MacCredentialStore>(std::string(namespaceId));
}
}
