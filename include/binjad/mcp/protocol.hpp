#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace binjad::mcp
{
enum class ProtocolVersion
{
    V2025_03_26,
    V2025_06_18,
    V2025_11_25,
    V2026_07_28,
};

using RequestId = std::variant<std::int64_t, std::uint64_t, std::string>;

struct TransportHeaders
{
    std::optional<std::string> protocolVersion;
    std::optional<std::string> method;
    std::optional<std::string> name;
};

struct SubscriptionFilter
{
    bool toolsListChanged = false;
    bool resourcesListChanged = false;
    std::vector<std::string> resourceSubscriptions;
};

struct ValidatedRequest
{
    ProtocolVersion version;
    std::optional<RequestId> id;
    std::string method;
    std::string name;
    std::string uri;
    std::string cursor;
    std::string analysisSession;
    std::string paramsJson;
    std::optional<SubscriptionFilter> subscription;
    bool notification = false;
};

struct ProtocolError
{
    int code;
    int httpStatus;
    std::string message;
    std::optional<RequestId> id;
    std::string dataJson;
};

struct ValidationResult
{
    std::optional<ValidatedRequest> request;
    std::optional<ProtocolError> error;
};

std::string_view ToString(ProtocolVersion version);
std::optional<ProtocolVersion> ParseProtocolVersion(std::string_view version);
bool IsModern(ProtocolVersion version);
ProtocolVersion NegotiateLegacyVersion(std::string_view requestedVersion);

ValidationResult ValidateRequest(std::string_view body, const TransportHeaders& headers,
    std::optional<ProtocolVersion> establishedLegacyVersion = std::nullopt);

std::string BuildErrorResponse(const ProtocolError& error);
std::string BuildDiscoveryResponse(const RequestId& id, std::string_view serverVersion);
std::string BuildInitializeResponse(
    const RequestId& id, ProtocolVersion version, std::string_view serverVersion);
std::string BuildEmptyResultResponse(
    const RequestId& id, ProtocolVersion version, std::string_view serverVersion);
std::string BuildSubscriptionAcknowledgement(
    const RequestId& id, const SubscriptionFilter& filter);
std::string BuildResourceUpdatedNotification(std::string_view uri);
std::string BuildToolsListChangedNotification();
std::string BuildResourcesListChangedNotification();
std::string EncodeSseEvent(std::string_view json);
std::string EncodeSseKeepAlive();
}
