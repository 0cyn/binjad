#include "binjad/session/OpenItemRegistry.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(OpenItemRegistryTest, AssignsCandidateHandlesBeforeMaterialization)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    const auto created = items.Create(std::string(64, 'a'), "SessionRef",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Raw", false}, {"Mach-O", true}});
    ASSERT_TRUE(created.openItem.has_value()) << created.error;
    EXPECT_TRUE(binjad::reference::IsFriendlyReference(created.openItem->reference));
    ASSERT_EQ(created.openItem->binaryViews.size(), 2U);
    for (const auto& view : created.openItem->binaryViews)
    {
        EXPECT_TRUE(binjad::reference::IsFriendlyReference(view.reference));
        EXPECT_FALSE(view.created);
        EXPECT_EQ(view.openItem, created.openItem->reference);
    }
    EXPECT_EQ(references.Size(), 3U);
}

TEST(OpenItemRegistryTest, ListsItemsTokenWideAndViewsSessionWide)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    ASSERT_TRUE(items.Create(std::string(64, 'a'), "FirstSession",
        binjad::session::OpenItemSourceKind::LocalProject, "first.bin", "ProjectRef",
        {{"Raw", true}}).openItem);
    ASSERT_TRUE(items.Create(std::string(64, 'a'), "SecondSession",
        binjad::session::OpenItemSourceKind::LocalProject, "second.bin", "ProjectRef",
        {{"Raw", true}}).openItem);
    ASSERT_TRUE(items.Create(std::string(64, 'b'), "ForeignSession",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/foreign", {},
        {{"Raw", true}}).openItem);
    EXPECT_EQ(items.ListForToken(std::string(64, 'a')).size(), 2U);
    EXPECT_EQ(items.ListViews(std::string(64, 'a'), "FirstSession").size(), 1U);
    EXPECT_TRUE(items.ListViews(std::string(64, 'b'), "FirstSession").empty());
}

TEST(OpenItemRegistryTest, MaterializesExplicitViewAndHidesForeignReferences)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    const auto created = items.Create(std::string(64, 'a'), "SessionRef",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Raw", true}});
    ASSERT_TRUE(created.openItem);
    const auto& view = created.openItem->binaryViews.front();
    EXPECT_FALSE(items.MarkViewCreated(std::string(64, 'b'), "SessionRef", view.reference));
    const auto materialized = items.MarkViewCreated(
        std::string(64, 'a'), "SessionRef", view.reference);
    ASSERT_TRUE(materialized);
    EXPECT_TRUE(materialized->created);
    EXPECT_TRUE(items.FindView(std::string(64, 'a'), "SessionRef", view.reference));
}

TEST(OpenItemRegistryTest, ClosingSessionReleasesEveryOwnedHandle)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    ASSERT_TRUE(items.Create(std::string(64, 'a'), "SessionRef",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Raw", false}, {"ELF", true}}).openItem);
    ASSERT_TRUE(items.Create(std::string(64, 'a'), "OtherSession",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/other", {},
        {{"Raw", true}}).openItem);
    const auto removed = items.CloseByAnalysisSession("SessionRef");
    EXPECT_EQ(removed.size(), 1U);
    EXPECT_EQ(items.Size(), 1U);
    EXPECT_EQ(references.Size(), 2U);
}

TEST(OpenItemRegistryTest, TracksProjectFileMovesAndOpenDeletionGuards)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    const auto created = items.Create(std::string(64, 'a'), "SessionRef",
        binjad::session::OpenItemSourceKind::LocalProject, "old/file.bin", "ProjectRef",
        {{"Raw", true}});
    ASSERT_TRUE(created.openItem);
    EXPECT_TRUE(items.HasProjectSource("ProjectRef", "old/file.bin"));
    items.UpdateProjectSource("ProjectRef", "old/file.bin", "new/file.bin");
    EXPECT_FALSE(items.HasProjectSource("ProjectRef", "old/file.bin"));
    EXPECT_TRUE(items.HasProjectSource("ProjectRef", "new/file.bin"));
    items.UpdateProjectSourcePrefix("ProjectRef", "new", "moved");
    EXPECT_FALSE(items.HasProjectSourcePrefix("ProjectRef", "new"));
    EXPECT_TRUE(items.HasProjectSourcePrefix("ProjectRef", "moved"));
    const auto updated = items.FindOpenItem(
        std::string(64, 'a'), created.openItem->reference);
    ASSERT_TRUE(updated);
    EXPECT_EQ(updated->source, "moved/file.bin");
}

TEST(OpenItemRegistryTest, ReportsEveryResourceVisibleMutation)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    std::vector<std::string> owners;
    items.SetChangedCallback(
        [&](std::string_view owner) { owners.emplace_back(owner); });
    const auto owner = std::string(64, 'a');
    const auto created = items.Create(owner, "SessionRef",
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Mach-O", true}});
    ASSERT_TRUE(created.openItem);
    ASSERT_TRUE(items.MarkViewCreated(
        owner, "SessionRef", created.openItem->binaryViews.front().reference));
    ASSERT_TRUE(items.UpdateSource(owner, created.openItem->reference,
        binjad::session::OpenItemSourceKind::ArbitraryPath,
        "/tmp/input.bndb", {}));
    ASSERT_TRUE(items.Close(owner, created.openItem->reference));

    EXPECT_EQ(owners, (std::vector<std::string>{owner, owner, owner, owner}));
}
