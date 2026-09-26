#pragma once

#include "binjad/process/Supervisor.hpp"

#include <mach/mach.h>

namespace binjad::platform::macos
{
mach_port_t ExceptionPort(ProcessSupervisor& supervisor);
}
