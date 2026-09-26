#include "binjad/session/AnalysisSessionRegistry.hpp"

#include <gtest/gtest.h>

#include <chrono>

namespace
{
using namespace std::chrono_literals;
using Clock = binjad::session::AnalysisSessionRegistry::Clock;
}

TEST(AnalysisSessionRegistryTest, CreatesModernAndLegacySessionsInOneReferenceNamespace)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = Clock::time_point(1h);
    const auto modern = sessions.Create(std::string(64, 'a'), 10, now);
    const auto legacy = sessions.Create(std::string(64, 'a'), 11, now,
        binjad::mcp::ProtocolVersion::V2025_03_26);
    ASSERT_TRUE(modern.session.has_value()) << modern.error;
    ASSERT_TRUE(legacy.session.has_value()) << legacy.error;
    EXPECT_NE(modern.session->reference, legacy.session->reference);
    EXPECT_TRUE(binjad::reference::IsFriendlyReference(modern.session->reference));
    EXPECT_FALSE(modern.session->legacyTransportId.has_value());
    ASSERT_TRUE(legacy.session->legacyTransportId.has_value());
    EXPECT_EQ(legacy.session->legacyTransportId->size(), 43U);
    EXPECT_EQ(references.Size(), 2U);
}

TEST(AnalysisSessionRegistryTest, HidesForeignSessionsAndRefreshesAuthorizedLookup)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto start = Clock::time_point(1h);
    const auto created = sessions.Create(std::string(64, 'a'), 10, start);
    ASSERT_TRUE(created.session.has_value());
    EXPECT_FALSE(sessions.Find(created.session->reference, std::string(64, 'b'), start + 1min));
    EXPECT_TRUE(sessions.Find(created.session->reference, std::string(64, 'a'), start + 20min));
    EXPECT_TRUE(sessions.Find(created.session->reference, std::string(64, 'a'), start + 49min));
    EXPECT_FALSE(sessions.Find(created.session->reference, std::string(64, 'a'), start + 80min));
}

TEST(AnalysisSessionRegistryTest, ResolvesLegacyOwnershipWithoutDisclosingForeignMapping)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = Clock::time_point(1h);
    const auto created = sessions.Create(std::string(64, 'a'), 10, now,
        binjad::mcp::ProtocolVersion::V2025_06_18);
    ASSERT_TRUE(created.session && created.session->legacyTransportId);
    EXPECT_FALSE(sessions.FindLegacy(
        *created.session->legacyTransportId, std::string(64, 'b'), now));
    const auto found = sessions.FindLegacy(
        *created.session->legacyTransportId, std::string(64, 'a'), now);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->legacyVersion, binjad::mcp::ProtocolVersion::V2025_06_18);
}

TEST(AnalysisSessionRegistryTest, RetentionDefersSweepUntilJobReleasesSession)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto start = Clock::time_point(1h);
    const auto created = sessions.Create(std::string(64, 'a'), 10, start);
    ASSERT_TRUE(created.session.has_value());
    ASSERT_TRUE(sessions.Retain(created.session->reference, std::string(64, 'a'), start));
    EXPECT_TRUE(sessions.Sweep(start + 1h).empty());
    ASSERT_TRUE(sessions.Release(created.session->reference, std::string(64, 'a')));
    const auto expired = sessions.Sweep(start + 1h);
    ASSERT_EQ(expired.size(), 1U);
    EXPECT_EQ(expired.front().reference, created.session->reference);
    EXPECT_EQ(references.Size(), 0U);
}

TEST(AnalysisSessionRegistryTest, CloseReleasesGlobalReference)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto created = sessions.Create(std::string(64, 'a'), 10, Clock::time_point{});
    ASSERT_TRUE(created.session.has_value());
    EXPECT_TRUE(sessions.Close(created.session->reference, std::string(64, 'a')));
    EXPECT_FALSE(sessions.Close(created.session->reference, std::string(64, 'a')));
    EXPECT_EQ(sessions.Size(), 0U);
    EXPECT_EQ(references.Size(), 0U);
}

TEST(AnalysisSessionRegistryTest, ClosesEverySessionOwnedByRevokedToken)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = Clock::time_point{};
    ASSERT_TRUE(sessions.Create(std::string(64, 'a'), 1, now).session);
    ASSERT_TRUE(sessions.Create(std::string(64, 'a'), 2, now).session);
    ASSERT_TRUE(sessions.Create(std::string(64, 'b'), 3, now).session);
    const auto removed = sessions.CloseByOwner(std::string(64, 'a'));
    EXPECT_EQ(removed.size(), 2U);
    EXPECT_EQ(sessions.Size(), 1U);
    EXPECT_EQ(references.Size(), 1U);
}

TEST(AnalysisSessionRegistryTest, NotifiesDependentStateOnEveryRemovalPath)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    std::vector<std::string> closed;
    sessions.SetClosedCallback(
        [&](const auto& session) { closed.push_back(session.reference); });
    const auto now = Clock::time_point{};
    const auto explicitClose = sessions.Create(std::string(64, 'a'), 1, now);
    const auto expired = sessions.Create(std::string(64, 'a'), 2, now);
    ASSERT_TRUE(explicitClose.session && expired.session);
    ASSERT_TRUE(sessions.Close(explicitClose.session->reference, std::string(64, 'a')));
    sessions.Sweep(now + 31min);
    EXPECT_EQ(closed.size(), 2U);
}
