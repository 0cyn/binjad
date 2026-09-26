#pragma once

#include "binjad/ipc/Channel.hpp"

#include <memory>

namespace binjad
{
int RunProjectChild(std::unique_ptr<ipc::ByteChannel> channel);
}
