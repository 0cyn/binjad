#include "binjad/process/role.hpp"

#include <gtest/gtest.h>

TEST(ProcessRoleTest, SelectsRoleFromArgv0Filename)
{
    EXPECT_EQ(binjad::RoleFromArgv0("/opt/bin/binjad-file-child"),
        binjad::ProcessRole::FileChild);
    EXPECT_EQ(binjad::RoleFromArgv0("binjad-project-child"),
        binjad::ProcessRole::ProjectChild);
    EXPECT_EQ(binjad::RoleFromArgv0("/opt/bin/binjad"),
        binjad::ProcessRole::Overseer);
}
