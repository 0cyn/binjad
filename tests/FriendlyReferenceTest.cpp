#include "binjad/reference/FriendlyReference.hpp"

#include <gtest/gtest.h>

#include <unordered_set>
#include <vector>

TEST(FriendlyReferenceTest, LoadsExactCuratedDictionary)
{
    EXPECT_EQ(binjad::reference::FriendlyWordCount(), 16384U);
}

TEST(FriendlyReferenceTest, AcquiresUniqueFourWordPascalCaseReferences)
{
    binjad::reference::FriendlyReferencePool pool;
    std::vector<std::string> references;
    for (int index = 0; index < 100; ++index)
    {
        const auto acquired = pool.Acquire();
        ASSERT_TRUE(acquired.value.has_value()) << acquired.error;
        EXPECT_TRUE(binjad::reference::IsFriendlyReference(*acquired.value));
        references.push_back(*acquired.value);
    }
    EXPECT_EQ(pool.Size(), references.size());
    EXPECT_TRUE(pool.Release(references.front()));
    EXPECT_FALSE(pool.Release(references.front()));
    EXPECT_EQ(pool.Size(), references.size() - 1);
}

TEST(FriendlyReferenceTest, RejectsMalformedOrUnknownReferences)
{
    EXPECT_FALSE(binjad::reference::IsFriendlyReference("lowercasewordsarenotvalid"));
    EXPECT_FALSE(binjad::reference::IsFriendlyReference("OnlyThreeKnownWords"));
    EXPECT_FALSE(binjad::reference::IsFriendlyReference("MadeUpWordsNeverExistHere"));
}
