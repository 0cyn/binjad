#pragma once

#include "binjad/mcp/Protocol.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace binjad::session
{
class SubscriptionRegistry
{
  public:
    using ListenerId = std::uint64_t;
    using NotificationCallback = std::function<void(std::string_view)>;

    void SubscribeLegacy(std::string session, std::string ownerTokenId, std::string uri);
    void UnsubscribeLegacy(std::string_view session, std::string_view ownerTokenId,
        std::string_view uri);
    ListenerId ListenLegacy(std::string session, std::string ownerTokenId,
        NotificationCallback callback);
    ListenerId ListenModern(std::string ownerTokenId, mcp::SubscriptionFilter filter,
        NotificationCallback callback);
    void RemoveListener(ListenerId listener);
    void RemoveSession(std::string_view session);
    void RemoveOwner(std::string_view ownerTokenId);

    void PublishResource(std::string_view ownerTokenId, std::string_view uri) const;
    void PublishToolsListChanged() const;
    void PublishResourcesListChanged() const;

    std::size_t ListenerCount() const;

  private:
    struct LegacySubscriptions
    {
        std::string ownerTokenId;
        std::unordered_set<std::string> uris;
    };

    struct Listener
    {
        std::string ownerTokenId;
        std::string legacySession;
        mcp::SubscriptionFilter filter;
        NotificationCallback callback;
    };

    ListenerId AddListener(Listener listener);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, LegacySubscriptions> legacySubscriptions_;
    std::unordered_map<ListenerId, Listener> listeners_;
    ListenerId nextListener_ = 1;
};
}
