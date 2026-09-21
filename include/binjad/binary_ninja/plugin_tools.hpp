#pragma once

#include <memory>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace BinaryNinja
{
class BinaryView;
}

namespace binjad::binary_ninja
{
class PluginTools
{
  public:
    PluginTools();
    ~PluginTools();

    PluginTools(const PluginTools&) = delete;
    PluginTools& operator=(const PluginTools&) = delete;

    std::string Execute(std::string_view name, BinaryNinja::BinaryView& view,
        std::string_view argumentsJson);
    std::optional<std::string> DescribeAddress(
        BinaryNinja::BinaryView& view, std::uint64_t address);
    void Close(BinaryNinja::BinaryView& view) noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
