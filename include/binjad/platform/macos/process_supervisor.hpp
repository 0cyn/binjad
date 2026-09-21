#pragma once

#include "binjad/process/supervisor.hpp"

#include <mach/mach.h>

namespace binjad::platform::macos
{
mach_port_t ExceptionPort(ProcessSupervisor& supervisor);
}
