#include "binjad/process/role.hpp"

#include <filesystem>
#include <stdexcept>

namespace binjad
{
ProcessRole RoleFromArgv0(std::string_view argv0)
{
    const auto filename = std::filesystem::path(argv0).filename().string();
    if (filename == kFileChildArgv0)
        return ProcessRole::FileChild;
    if (filename == kProjectChildArgv0)
        return ProcessRole::ProjectChild;
    return ProcessRole::Overseer;
}

std::string_view ChildArgv0(ProcessRole role)
{
    switch (role)
    {
        case ProcessRole::FileChild: return kFileChildArgv0;
        case ProcessRole::ProjectChild: return kProjectChildArgv0;
        case ProcessRole::Overseer: break;
    }
    throw std::invalid_argument("overseer is not a child role");
}
}
