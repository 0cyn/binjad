#include "binjad/logging.hpp"

#include <os/log.h>

#include <string>

namespace binjad
{
void Log(LogLevel level, std::string_view message)
{
    static os_log_t log = os_log_create("me.cynder.binjad", "daemon");
    os_log_type_t type = OS_LOG_TYPE_DEFAULT;
    switch (level)
    {
        case LogLevel::Debug: type = OS_LOG_TYPE_DEBUG; break;
        case LogLevel::Info: type = OS_LOG_TYPE_INFO; break;
        case LogLevel::Notice: type = OS_LOG_TYPE_DEFAULT; break;
        case LogLevel::Error: type = OS_LOG_TYPE_ERROR; break;
        case LogLevel::Fault: type = OS_LOG_TYPE_FAULT; break;
    }
    const std::string text(message);
    os_log_with_type(log, type, "%{public}s", text.c_str());
}
}
