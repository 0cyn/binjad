#pragma once

#include <binaryninjaapi.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <thread>

namespace binjad::binary_ninja
{
class DiffTools
{
  public:
    using ProgressCallback = std::function<void(double)>;
    using CompletionCallback = std::function<void(bool, std::string)>;

    DiffTools() = default;
    DiffTools(const DiffTools&) = delete;
    DiffTools& operator=(const DiffTools&) = delete;
    ~DiffTools();

    std::string Begin(BinaryNinja::Ref<BinaryNinja::BinaryView> primary,
        std::string key, const std::string& secondaryDatabase,
        ProgressCallback progress, CompletionCallback completion);
    std::string Execute(std::string_view name,
        BinaryNinja::Ref<BinaryNinja::BinaryView> primary,
        std::string_view key, std::string_view argumentsJson);
    void Close() noexcept;

  private:
    struct State;
    std::shared_ptr<State> Find(std::string_view key,
        BinaryNinja::BinaryView& primary) const;
    std::string Release(std::string_view key);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<State>> states_;
    std::vector<std::jthread> workers_;
};
}
