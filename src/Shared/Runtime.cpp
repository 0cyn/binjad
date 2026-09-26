#include "binjad/binary_ninja/Runtime.hpp"

#include <binaryninjaapi.h>

#include <stdexcept>

namespace binjad
{
BinaryNinjaRuntime::BinaryNinjaRuntime(bool allowUserPlugins)
{
    BinaryNinja::SetBundledPluginDirectory(BinaryNinja::GetBundledPluginDirectory());
    if (!BinaryNinja::InitPlugins(allowUserPlugins))
        throw std::runtime_error("Binary Ninja plugin initialization failed");
    initialized_ = true;
}

BinaryNinjaRuntime::~BinaryNinjaRuntime()
{
    if (initialized_)
        BNShutdown();
}
}
