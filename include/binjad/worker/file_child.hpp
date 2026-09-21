#pragma once

#include "binjad/ipc/channel.hpp"

#include <memory>

namespace binjad
{
int RunFileChild(std::unique_ptr<ipc::ByteChannel> channel);
}
