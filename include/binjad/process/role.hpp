#pragma once

#include <optional>
#include <string_view>

namespace binjad
{
enum class ProcessRole
{
    Overseer,
    FileChild,
    ProjectChild,
};

inline constexpr std::string_view kFileChildArgv0 = "binjad-file-child";
inline constexpr std::string_view kProjectChildArgv0 = "binjad-project-child";

ProcessRole RoleFromArgv0(std::string_view argv0);
std::string_view ChildArgv0(ProcessRole role);
}
