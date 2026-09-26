#include "binjad/session/SubscriptionRegistry.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace binjad::session {
	void SubscriptionRegistry::SubscribeLegacy(std::string session, std::string ownerTokenId, std::string uri)
	{
		std::lock_guard lock(mutex_);
		auto& subscriptions = legacySubscriptions_[session];
		subscriptions.ownerTokenId = std::move(ownerTokenId);
		const auto value = uri;
		subscriptions.uris.insert(std::move(uri));
		for (auto& [id, listener] : listeners_)
		{
			(void)id;
			if (listener.legacySession != session
				|| std::find(listener.filter.resourceSubscriptions.begin(), listener.filter.resourceSubscriptions.end(),
					   value)
					!= listener.filter.resourceSubscriptions.end())
				continue;
			listener.filter.resourceSubscriptions.push_back(value);
		}
	}

	void SubscriptionRegistry::UnsubscribeLegacy(
		std::string_view session, std::string_view ownerTokenId, std::string_view uri)
	{
		std::lock_guard lock(mutex_);
		const auto found = legacySubscriptions_.find(std::string(session));
		if (found == legacySubscriptions_.end() || found->second.ownerTokenId != ownerTokenId)
			return;
		found->second.uris.erase(std::string(uri));
		for (auto& [id, listener] : listeners_)
		{
			(void)id;
			if (listener.legacySession == session)
				std::erase(listener.filter.resourceSubscriptions, uri);
		}
		if (found->second.uris.empty())
			legacySubscriptions_.erase(found);
	}

	SubscriptionRegistry::ListenerId SubscriptionRegistry::ListenLegacy(
		std::string session, std::string ownerTokenId, NotificationCallback callback)
	{
		mcp::SubscriptionFilter filter;
		{
			std::lock_guard lock(mutex_);
			const auto found = legacySubscriptions_.find(session);
			if (found != legacySubscriptions_.end() && found->second.ownerTokenId == ownerTokenId)
				filter.resourceSubscriptions.assign(found->second.uris.begin(), found->second.uris.end());
		}
		filter.toolsListChanged = true;
		filter.resourcesListChanged = true;
		return AddListener({std::move(ownerTokenId), std::move(session), std::move(filter), std::move(callback)});
	}

	SubscriptionRegistry::ListenerId SubscriptionRegistry::ListenModern(
		std::string ownerTokenId, mcp::SubscriptionFilter filter, NotificationCallback callback)
	{
		return AddListener({std::move(ownerTokenId), {}, std::move(filter), std::move(callback)});
	}

	void SubscriptionRegistry::RemoveListener(ListenerId listener)
	{
		std::lock_guard lock(mutex_);
		listeners_.erase(listener);
	}

	void SubscriptionRegistry::RemoveSession(std::string_view session)
	{
		std::lock_guard lock(mutex_);
		legacySubscriptions_.erase(std::string(session));
		std::erase_if(listeners_, [&](const auto& listener) { return listener.second.legacySession == session; });
	}

	void SubscriptionRegistry::RemoveOwner(std::string_view ownerTokenId)
	{
		std::lock_guard lock(mutex_);
		std::erase_if(legacySubscriptions_, [&](const auto& subscriptions) {
			return subscriptions.second.ownerTokenId == ownerTokenId;
		});
		std::erase_if(listeners_, [&](const auto& listener) { return listener.second.ownerTokenId == ownerTokenId; });
	}

	void SubscriptionRegistry::PublishResource(std::string_view ownerTokenId, std::string_view uri) const
	{
		std::vector<NotificationCallback> callbacks;
		{
			std::lock_guard lock(mutex_);
			for (const auto& [id, listener] : listeners_)
			{
				(void)id;
				if (listener.ownerTokenId != ownerTokenId
					|| std::find(listener.filter.resourceSubscriptions.begin(),
						   listener.filter.resourceSubscriptions.end(), uri)
						== listener.filter.resourceSubscriptions.end())
					continue;
				callbacks.push_back(listener.callback);
			}
		}
		const auto notification = mcp::BuildResourceUpdatedNotification(uri);
		for (const auto& callback : callbacks)
			callback(notification);
	}

	void SubscriptionRegistry::PublishToolsListChanged() const
	{
		std::vector<NotificationCallback> callbacks;
		{
			std::lock_guard lock(mutex_);
			for (const auto& [id, listener] : listeners_)
			{
				(void)id;
				if (listener.filter.toolsListChanged)
					callbacks.push_back(listener.callback);
			}
		}
		const auto notification = mcp::BuildToolsListChangedNotification();
		for (const auto& callback : callbacks)
			callback(notification);
	}

	void SubscriptionRegistry::PublishResourcesListChanged() const
	{
		std::vector<NotificationCallback> callbacks;
		{
			std::lock_guard lock(mutex_);
			for (const auto& [id, listener] : listeners_)
			{
				(void)id;
				if (listener.filter.resourcesListChanged)
					callbacks.push_back(listener.callback);
			}
		}
		const auto notification = mcp::BuildResourcesListChangedNotification();
		for (const auto& callback : callbacks)
			callback(notification);
	}

	std::size_t SubscriptionRegistry::ListenerCount() const
	{
		std::lock_guard lock(mutex_);
		return listeners_.size();
	}

	SubscriptionRegistry::ListenerId SubscriptionRegistry::AddListener(Listener listener)
	{
		std::lock_guard lock(mutex_);
		auto id = nextListener_++;
		if (id == 0)
			id = nextListener_++;
		listeners_.emplace(id, std::move(listener));
		return id;
	}
}  // namespace binjad::session
