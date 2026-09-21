#include "binjad/session/subscription_registry.hpp"
#include "binjad/session/open_item_registry.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(SubscriptionRegistryTest, FiltersModernNotificationsByOwnerAndSelection)
{
    binjad::session::SubscriptionRegistry subscriptions;
    std::vector<std::string> first;
    std::vector<std::string> second;
    binjad::mcp::SubscriptionFilter filter;
    filter.toolsListChanged = true;
    filter.resourceSubscriptions = {"binjad://jobs"};
    subscriptions.ListenModern("owner-a", filter,
        [&](std::string_view value) { first.emplace_back(value); });
    subscriptions.ListenModern("owner-b", filter,
        [&](std::string_view value) { second.emplace_back(value); });

    subscriptions.PublishResource("owner-a", "binjad://jobs");
    subscriptions.PublishResource("owner-a", "binjad://compute");
    subscriptions.PublishToolsListChanged();

    ASSERT_EQ(first.size(), 2U);
    EXPECT_NE(first[0].find("notifications/resources/updated"), std::string::npos);
    EXPECT_NE(first[0].find("binjad://jobs"), std::string::npos);
    EXPECT_NE(first[1].find("notifications/tools/list_changed"), std::string::npos);
    ASSERT_EQ(second.size(), 1U);
    EXPECT_NE(second[0].find("notifications/tools/list_changed"), std::string::npos);
}

TEST(SubscriptionRegistryTest, UpdatesActiveLegacyListenerSubscriptions)
{
    binjad::session::SubscriptionRegistry subscriptions;
    std::vector<std::string> observed;
    const auto listener = subscriptions.ListenLegacy("session", "owner",
        [&](std::string_view value) { observed.emplace_back(value); });

    subscriptions.SubscribeLegacy("session", "owner", "binjad://jobs");
    subscriptions.PublishResource("owner", "binjad://jobs");
    subscriptions.UnsubscribeLegacy("session", "owner", "binjad://jobs");
    subscriptions.PublishResource("owner", "binjad://jobs");
    subscriptions.PublishResourcesListChanged();

    ASSERT_EQ(observed.size(), 2U);
    EXPECT_NE(observed[0].find("notifications/resources/updated"), std::string::npos);
    EXPECT_NE(observed[1].find("notifications/resources/list_changed"), std::string::npos);
    subscriptions.RemoveListener(listener);
    EXPECT_EQ(subscriptions.ListenerCount(), 0U);
}

TEST(SubscriptionRegistryTest, RemovesSessionAndOwnerListeners)
{
    binjad::session::SubscriptionRegistry subscriptions;
    subscriptions.ListenLegacy("session-a", "owner-a", [](std::string_view) {});
    subscriptions.ListenModern("owner-a", {}, [](std::string_view) {});
    subscriptions.ListenModern("owner-b", {}, [](std::string_view) {});
    ASSERT_EQ(subscriptions.ListenerCount(), 3U);

    subscriptions.RemoveSession("session-a");
    EXPECT_EQ(subscriptions.ListenerCount(), 2U);
    subscriptions.RemoveOwner("owner-a");
    EXPECT_EQ(subscriptions.ListenerCount(), 1U);
}

TEST(SubscriptionRegistryTest, OpenItemMutationsPublishLiveResourceUpdate)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::session::SubscriptionRegistry subscriptions;
    const auto owner = std::string(64, 'a');
    std::vector<std::string> observed;
    binjad::mcp::SubscriptionFilter filter;
    filter.resourceSubscriptions = {"binjad://open-items"};
    subscriptions.ListenModern(owner, filter,
        [&](std::string_view value) { observed.emplace_back(value); });
    items.SetChangedCallback([&](std::string_view changedOwner) {
        subscriptions.PublishResource(changedOwner, "binjad://open-items");
    });

    ASSERT_TRUE(items.Create(owner, "SessionRef",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Raw", true}}).openItem);
    ASSERT_EQ(observed.size(), 1U);
    EXPECT_NE(observed[0].find("binjad://open-items"), std::string::npos);
}
