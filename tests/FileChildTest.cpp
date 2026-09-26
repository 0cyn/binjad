#include "binjad/ipc/Envelope.hpp"
#include "binjad/worker/FileChild.hpp"

#include <rapidjsonwrapper.h>

#include <gtest/gtest.h>

#include <chrono>
#include <array>
#include <cstdint>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <functional>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace
{
class QueueChannel final : public binjad::ipc::ByteChannel
{
  public:
    QueueChannel(std::deque<std::vector<std::uint8_t>> requests,
        std::shared_ptr<std::vector<std::vector<std::uint8_t>>> responses,
        std::uint64_t waitForAnalysisBeforeRequest = 0) :
        requests_(std::move(requests)), responses_(std::move(responses)),
        waitForAnalysisBeforeRequest_(waitForAnalysisBeforeRequest)
    {}

    void Send(std::span<const std::uint8_t> payload) override
    {
        const auto envelope = binjad::ipc::ParseEnvelope(payload);
        std::lock_guard lock(mutex_);
        responses_->emplace_back(payload.begin(), payload.end());
        if (envelope.has_event() && envelope.event().has_analysis_finished())
        {
            analysisFinished_ = true;
            ready_.notify_all();
        }
    }

    std::vector<std::uint8_t> Receive() override
    {
        if (requests_.empty())
            throw std::runtime_error("test channel has no more requests");
        const auto next = binjad::ipc::ParseEnvelope(requests_.front());
        if (next.request_id() == waitForAnalysisBeforeRequest_)
        {
            std::unique_lock lock(mutex_);
            if (!ready_.wait_for(lock, std::chrono::seconds(30), [&] {
                    return analysisFinished_;
                }))
                throw std::runtime_error("timed out waiting for analysis completion");
        }
        auto request = std::move(requests_.front());
        requests_.pop_front();
        return request;
    }

  private:
    std::deque<std::vector<std::uint8_t>> requests_;
    std::shared_ptr<std::vector<std::vector<std::uint8_t>>> responses_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::uint64_t waitForAnalysisBeforeRequest_ = 0;
    bool analysisFinished_ = false;
};

std::vector<std::uint8_t> Command(
    std::uint64_t requestId, const std::function<void(binjad::ipc::Command&)>& fill)
{
    binjad::ipc::Envelope envelope;
    envelope.set_protocol_version(binjad::ipc::kProtocolVersion);
    envelope.set_request_id(requestId);
    fill(*envelope.mutable_command());
    return binjad::ipc::SerializeEnvelope(envelope);
}
}

TEST(FileChildTest, OpensQueriesClosesAndShutsDown)
{
    const auto database = std::filesystem::temp_directory_path() /
        ("binjad-file-child-save-" + std::to_string(getpid()) + ".bndb");
    std::error_code ignored;
    std::filesystem::remove(database, ignored);
    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(BINJAD_ANALYSIS_FIXTURE);
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Raw");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        command.mutable_get_analysis_status()->set_view_type("Mach-O");
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        command.mutable_get_analysis_status()->set_view_type("Raw");
    }));
    requests.push_back(Command(64, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_set");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_helper","text":"fixture comment"})");
    }));
    requests.push_back(Command(65, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_get");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(6, [&](binjad::ipc::Command& command) {
        auto* save = command.mutable_save_binary_view();
        save->set_view_type("Mach-O");
        save->set_destination(database.string());
    }));
    requests.push_back(Command(7, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(false);
    }));
    requests.push_back(Command(8, [&](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(database.string());
        open->set_options_json("{}");
        open->set_reuse_database(true);
    }));
    requests.push_back(Command(9, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(90, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_get");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(41, [](binjad::ipc::Command& command) {
        command.mutable_update_analysis()->set_view_type("Mach-O");
    }));
    requests.push_back(Command(13, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(R"({"offset":0,"limit":5})");
    }));
    requests.push_back(Command(14, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_info");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(15, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_callers");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":5})");
    }));
    requests.push_back(Command(16, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_callees");
        execute->set_arguments_json(R"({"function":"_main","offset":0,"limit":5})");
    }));
    requests.push_back(Command(17, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_disassembly");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(18, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(89, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","language":"pseudo-c","offset":0,"limit":20})");
    }));
    requests.push_back(Command(19, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_il");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","level":"hlil","ssa":false,"offset":0,"limit":20})");
    }));
    requests.push_back(Command(20, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_stack_layout");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(21, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_variable_list");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(22, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_calling_convention_list");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(23, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_xrefs_from");
        execute->set_arguments_json(R"({"function":"_main","offset":0,"limit":20})");
    }));
    requests.push_back(Command(24, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_xrefs_to");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(25, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_list");
        execute->set_arguments_json(R"({"query":"binjad-analysis-fixture-marker","offset":0,"limit":20})");
    }));
    requests.push_back(Command(26, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list");
        execute->set_arguments_json(R"({"query":"fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(27, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_not_a_tool");
        execute->set_arguments_json("{}");
    }));
    requests.push_back(Command(28, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_info");
        execute->set_arguments_json("{}");
    }));
    requests.push_back(Command(29, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(R"({"length":16})");
    }));
    requests.push_back(Command(30, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json("{}");
    }));
    requests.push_back(Command(31, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_il");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","level":"lifted"})");
    }));
    requests.push_back(Command(32, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(
            R"({"start":"_binjad_fixture_helper","length":18446744073709551615})");
    }));
    requests.push_back(Command(33, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_list");
        execute->set_arguments_json(
            R"({"start":"_binjad_fixture_helper","length":18446744073709551615})");
    }));
    requests.push_back(Command(34, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_list");
        execute->set_arguments_json("[]");
    }));
    requests.push_back(Command(35, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list");
        execute->set_arguments_json("null");
    }));
    requests.push_back(Command(36, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(R"({"query":"fixture_helper","offset":0,"limit":1})");
    }));
    requests.push_back(Command(37, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(R"({"query":"definitely_not_a_function","limit":1})");
    }));
    requests.push_back(Command(38, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list");
        execute->set_arguments_json(R"({"query":"fixture_helper","offset":0,"limit":1})");
    }));
    requests.push_back(Command(39, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper","limit":10})");
    }));
    requests.push_back(Command(40, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list");
        execute->set_arguments_json(R"({"offset":18446744073709551615,"limit":1})");
    }));
    requests.push_back(Command(42, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_message","offset":0,"limit":4})");
    }));
    requests.push_back(Command(43, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_disassembly");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(44, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_helper","offset":0,"limit":20})");
    }));
    requests.push_back(Command(45, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_il");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","level":"llil","ssa":true,"offset":0,"limit":20})");
    }));
    requests.push_back(Command(46, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_list");
        execute->set_arguments_json(R"({"query":"binjad-long-string","limit":1})");
    }));
    requests.push_back(Command(47, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_long_message","offset":128,"limit":32})");
    }));
    requests.push_back(Command(48, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_utf8_message"})");
    }));
    requests.push_back(Command(91, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_list");
        execute->set_arguments_json(R"({"query":"\u00e9-\ud83d\ude00","limit":10})");
    }));
    requests.push_back(Command(49, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","offset":18446744073709551615,"limit":1})");
    }));
    requests.push_back(Command(50, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_il");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","level":"mlil","ssa":false,"offset":0,"limit":1})");
    }));
    requests.push_back(Command(51, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_disassembly");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","offset":0,"limit":1})");
    }));
    requests.push_back(Command(52, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","language":"Not A Language"})");
    }));
    requests.push_back(Command(53, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_long_message","offset":1000,"limit":1})");
    }));
    requests.push_back(Command(54, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_info");
        execute->set_arguments_json(R"({"function":"0xffffffffffffffff"})");
    }));
    requests.push_back(Command(55, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(56, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_import_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(57, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_export_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(58, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_entry_point_list");
        execute->set_arguments_json(R"({"offset":0,"limit":10})");
    }));
    requests.push_back(Command(59, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_section_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(60, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_segment_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(61, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_memory_read");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_helper","length":16})");
    }));
    requests.push_back(Command(62, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_data_variable_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(63, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_data_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(66, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_set");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_helper","text":"updated fixture comment"})");
    }));
    requests.push_back(Command(67, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_get");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(68, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_delete");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(69, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_comment_get");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper"})");
    }));
    requests.push_back(Command(70, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_define");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_sink","name":"fixture_named_data","type":"DataSymbol","binding":"GlobalBinding","namespace":"tests","ordinal":3})");
    }));
    requests.push_back(Command(71, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(72, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_rename");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_sink","name":"fixture_named_data","type":"DataSymbol","namespace":"tests","ordinal":3,"newName":"fixture_renamed_data"})");
    }));
    requests.push_back(Command(73, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(74, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_undefine");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_sink","name":"fixture_renamed_data","type":"DataSymbol","namespace":"tests","ordinal":3})");
    }));
    requests.push_back(Command(75, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_list_at");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(92, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_entry_point_add");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper + 4"})");
    }));
    requests.push_back(Command(93, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_create");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper + 4"})");
    }));
    requests.push_back(Command(101, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_create");
        execute->set_arguments_json(R"({"address":"_binjad_fixture_helper + 4"})");
    }));
    requests.push_back(Command(94, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_helper + 4","limit":10})");
    }));
    requests.push_back(Command(95, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_entry_point_list");
        execute->set_arguments_json(R"({"offset":0,"limit":10})");
    }));
    requests.push_back(Command(102, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_define");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_sink","name":"fixture_function_symbol","type":"FunctionSymbol"})");
    }));
    requests.push_back(Command(103, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_info");
        execute->set_arguments_json(R"({"function":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(104, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_symbol_undefine");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_sink","name":"fixture_function_symbol","type":"FunctionSymbol"})");
    }));
    requests.push_back(Command(76, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_prototype_set");
        execute->set_arguments_json(
            R"json({"function":"_binjad_fixture_helper","prototype":"int32_t fixture(int32_t value)"})json");
    }));
    requests.push_back(Command(77, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_calling_convention_set");
        execute->set_arguments_json(
            R"({"function":"_binjad_fixture_helper","callingConvention":"apple-arm64"})");
    }));
    requests.push_back(Command(78, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_define");
        execute->set_arguments_json(
            R"({"source":"struct fixture_type { int x; unsigned short y; };","types":["fixture_type"]})");
    }));
    requests.push_back(Command(79, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_info");
        execute->set_arguments_json(R"({"type":"fixture_type"})");
    }));
    requests.push_back(Command(80, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_struct_create");
        execute->set_arguments_json(
            R"({"source":"struct fixture_struct { unsigned int value; };","type":"fixture_struct"})");
    }));
    requests.push_back(Command(81, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_struct_modify");
        execute->set_arguments_json(
            R"({"source":"struct fixture_struct { unsigned int value; unsigned int other; };","type":"fixture_struct"})");
    }));
    requests.push_back(Command(82, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_delete");
        execute->set_arguments_json(R"({"type":"fixture_struct"})");
    }));
    requests.push_back(Command(83, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_type_list");
        execute->set_arguments_json(R"({"query":"fixture_struct"})");
    }));
    requests.push_back(Command(84, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_data_variable_define");
        execute->set_arguments_json(
            R"({"datavar":"_binjad_fixture_sink","definition":"uint32_t"})");
    }));
    requests.push_back(Command(85, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_data_variable_undefine");
        execute->set_arguments_json(R"({"datavar":"_binjad_fixture_sink"})");
    }));
    requests.push_back(Command(86, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_section_create");
        execute->set_arguments_json(
            R"({"section":"fixture_custom","start":"_binjad_fixture_helper","length":4,"semantics":"ReadOnlyCodeSectionSemantics","alignment":4})");
    }));
    requests.push_back(Command(88, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_section_modify");
        execute->set_arguments_json(
            R"({"section":"fixture_custom","newSection":"fixture_custom_renamed","length":8})");
    }));
    requests.push_back(Command(87, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_section_delete");
        execute->set_arguments_json(R"({"section":"fixture_custom_renamed"})");
    }));
    requests.push_back(Command(10, [](binjad::ipc::Command& command) {
        command.mutable_save_binary_view()->set_view_type("Mach-O");
    }));
    requests.push_back(Command(11, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(false);
    }));
    requests.push_back(Command(96, [&](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(database.string());
        open->set_options_json("{}");
        open->set_reuse_database(true);
    }));
    requests.push_back(Command(97, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(98, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_function_list");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_helper + 4","limit":10})");
    }));
    requests.push_back(Command(99, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_entry_point_list");
        execute->set_arguments_json(R"({"offset":0,"limit":10})");
    }));
    for (const auto& [id, name, arguments] : std::vector<std::tuple<std::uint64_t, std::string, std::string>>{
             {110, "bn_comment_list", R"({"offset":0,"limit":10})"},
             {111, "bn_comment_search", R"({"query":"fixture comment","offset":0,"limit":10})"},
             {112, "bn_memory_search", R"({"pattern":"62 69 6e 6a 61 64","offset":0,"limit":10})"},
             {113, "bn_instruction_search", R"({"query":"ret","offset":0,"limit":10})"},
             {114, "bn_il_search", R"({"query":"return","level":"hlil","offset":0,"limit":10})"},
             {115, "bn_constant_search", R"({"value":"0","offset":0,"limit":10})"},
             {116, "bn_project_analysis_search", R"({"query":"fixture_helper","offset":0,"limit":10})"}})
    {
        requests.push_back(Command(id, [=](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("Mach-O"); execute->set_name(name);
            execute->set_arguments_json(arguments);
        }));
    }
    requests.push_back(Command(100, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(false);
    }));
    requests.push_back(Command(12, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses, 13);
    ASSERT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);

    bool opened = false;
    bool status = false;
    bool closed = false;
    bool shutdown = false;
    bool createdDatabase = false;
    bool savedSnapshot = false;
    bool listedFunctions = false;
    bool inspectedFunction = false;
    bool listedCallers = false;
    bool listedCallees = false;
    bool renderedDisassembly = false;
    bool renderedDecompilation = false;
    bool renderedDecompilationAlias = false;
    bool restoredDatabaseComment = false;
    bool renderedIL = false;
    bool listedStack = false;
    bool listedVariables = false;
    bool listedCallingConventions = false;
    bool listedXrefsFrom = false;
    bool listedXrefsTo = false;
    bool listedStrings = false;
    bool listedSymbols = false;
    std::size_t rejectedAnalysisTools = 0;
    std::size_t filteredAnalysisTools = 0;
    std::size_t analyzedToolResults = 0;
    std::size_t stringEdgeCases = 0;
    std::size_t renderingPages = 0;
    bool inspectedSymbols = false;
    bool listedImports = false;
    bool listedExports = false;
    bool listedEntryPoints = false;
    bool listedSections = false;
    bool listedSegments = false;
    bool readMemory = false;
    bool listedDataVariables = false;
    bool inspectedData = false;
    std::size_t commentResults = 0;
    std::size_t symbolMutationResults = 0;
    bool setPrototype = false;
    bool setCallingConvention = false;
    std::size_t definedTypeResults = 0;
    std::size_t dataVariableMutations = 0;
    std::size_t sectionMutations = 0;
    bool addedEntryPoint = false;
    bool createdUserFunction = false;
    bool repeatedUserFunction = false;
    bool listedCreatedFunction = false;
    bool listedAddedEntryPoint = false;
    bool restoredUserFunction = false;
    bool restoredEntryPoint = false;
    bool guidedFunctionCreation = false;
    std::size_t searchResults = 0;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (!envelope.has_reply())
            continue;
        if (envelope.request_id() == 103)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find("symbols do not create functions"),
                std::string::npos);
            EXPECT_NE(envelope.reply().error().find("bn_function_create"),
                std::string::npos);
            guidedFunctionCreation = true;
            ++rejectedAnalysisTools;
            continue;
        }
        if ((envelope.request_id() >= 27 && envelope.request_id() <= 35) ||
            envelope.request_id() == 52 || envelope.request_id() == 54)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_FALSE(envelope.reply().error().empty());
            ++rejectedAnalysisTools;
            continue;
        }
        ASSERT_TRUE(envelope.reply().success())
            << "request " << envelope.request_id() << ": " << envelope.reply().error();
        rapidjson::Document analysisResult;
        if (envelope.reply().has_analysis_tool_result())
        {
            const auto& json = envelope.reply().analysis_tool_result().json();
            analysisResult.Parse(json.data(), json.size());
            ASSERT_FALSE(analysisResult.HasParseError()) << "request " << envelope.request_id();
            ASSERT_TRUE(analysisResult.IsObject());
        }
        if (envelope.request_id() == 1)
        {
            opened = envelope.reply().has_file_opened();
            EXPECT_GT(envelope.reply().file_opened().candidates_size(), 0);
        }
        else if (envelope.request_id() == 2)
        {
            EXPECT_TRUE(envelope.reply().has_binary_view_opened());
            EXPECT_EQ(envelope.reply().binary_view_opened().view_type(), "Mach-O");
        }
        else if (envelope.request_id() == 3)
        {
            EXPECT_TRUE(envelope.reply().has_binary_view_opened());
            EXPECT_EQ(envelope.reply().binary_view_opened().view_type(), "Raw");
        }
        else if (envelope.request_id() == 4 || envelope.request_id() == 5)
        {
            status = envelope.reply().has_analysis_status();
            EXPECT_TRUE(envelope.reply().analysis_status().has_view());
        }
        else if (envelope.request_id() == 6)
        {
            ASSERT_TRUE(envelope.reply().has_binary_view_saved());
            createdDatabase = envelope.reply().binary_view_saved().created_database();
        }
        else if (envelope.request_id() == 7 || envelope.request_id() == 11 ||
            envelope.request_id() == 100)
            closed = true;
        else if (envelope.request_id() == 10)
        {
            ASSERT_TRUE(envelope.reply().has_binary_view_saved());
            savedSnapshot = !envelope.reply().binary_view_saved().created_database();
        }
        else if (envelope.request_id() == 13)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            ASSERT_TRUE(analysisResult["functions"].IsArray());
            for (const auto& function : analysisResult["functions"].GetArray())
            {
                EXPECT_EQ(function.MemberCount(), 3U);
                EXPECT_TRUE(function["address"].IsString());
                EXPECT_TRUE(function["name"].IsString());
                EXPECT_TRUE(function["type"].IsString());
            }
            EXPECT_TRUE(analysisResult["count"].IsUint64());
            EXPECT_TRUE(analysisResult["total"].IsUint64());
            listedFunctions = true;
        }
        else if (envelope.request_id() >= 110 && envelope.request_id() <= 116)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            ASSERT_TRUE(analysisResult["matches"].IsArray());
            if (envelope.request_id() == 113 || envelope.request_id() == 116)
                EXPECT_GT(analysisResult["total"].GetUint64(), 0U)
                    << envelope.request_id();
            ++searchResults;
        }
        else if (envelope.request_id() == 14)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"basicBlocks\""),
                std::string::npos);
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"hasUserType\""),
                std::string::npos);
            EXPECT_TRUE(analysisResult["ranges"].IsArray());
            EXPECT_TRUE(analysisResult["basicBlocks"].IsArray());
            EXPECT_GT(analysisResult["basicBlockCount"].GetUint64(), 1U);
            EXPECT_TRUE(analysisResult["hasUserType"].IsBool());
            EXPECT_TRUE(analysisResult["callingConvention"].IsString() ||
                analysisResult["callingConvention"].IsNull());
            inspectedFunction = true;
        }
        else if (envelope.request_id() == 15)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"callers\""),
                std::string::npos);
            EXPECT_GT(analysisResult["total"].GetUint64(), 0U);
            bool foundMain = false;
            for (const auto& caller : analysisResult["callers"].GetArray())
            {
                const std::string_view name(caller["caller"]["name"].GetString(),
                    caller["caller"]["name"].GetStringLength());
                foundMain |= name.find("main") != std::string_view::npos;
            }
            EXPECT_TRUE(foundMain);
            listedCallers = true;
        }
        else if (envelope.request_id() == 16)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"callees\""),
                std::string::npos);
            EXPECT_GT(analysisResult["total"].GetUint64(), 0U);
            bool foundHelper = false;
            for (const auto& callee : analysisResult["callees"].GetArray())
            {
                for (const auto& function : callee["functions"].GetArray())
                {
                    const std::string_view name(
                        function["name"].GetString(), function["name"].GetStringLength());
                    foundHelper |= name.find("binjad_fixture_helper") != std::string_view::npos;
                }
            }
            EXPECT_TRUE(foundHelper);
            listedCallees = true;
        }
        else if (envelope.request_id() == 17)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("binjad_fixture_helper"),
                std::string::npos);
            renderedDisassembly = true;
        }
        else if (envelope.request_id() == 18)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"Pseudo C\""),
                std::string::npos);
            EXPECT_TRUE(analysisResult["text"].IsString());
            EXPECT_TRUE(analysisResult["needsUpdate"].IsBool());
            renderedDecompilation = true;
        }
        else if (envelope.request_id() == 89)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_EQ(std::string(analysisResult["language"].GetString()), "Pseudo C");
            EXPECT_TRUE(analysisResult["text"].IsString());
            renderedDecompilationAlias = true;
        }
        else if (envelope.request_id() == 90)
        {
            EXPECT_EQ(std::string(analysisResult["text"].GetString()), "fixture comment");
            restoredDatabaseComment = true;
        }
        else if (envelope.request_id() == 19)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"level\":\"hlil\""),
                std::string::npos);
            EXPECT_FALSE(analysisResult["ssa"].GetBool());
            EXPECT_TRUE(analysisResult["text"].IsString());
            renderedIL = true;
        }
        else if (envelope.request_id() == 20)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"variables\""),
                std::string::npos);
            for (const auto& variable : analysisResult["variables"].GetArray())
            {
                EXPECT_EQ(variable.MemberCount(), 3U);
                EXPECT_TRUE(variable["offset"].IsInt64());
            }
            listedStack = true;
        }
        else if (envelope.request_id() == 21)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"variables\""),
                std::string::npos);
            for (const auto& variable : analysisResult["variables"].GetArray())
            {
                EXPECT_EQ(variable.MemberCount(), 5U);
                EXPECT_TRUE(variable["index"].IsUint());
                EXPECT_TRUE(variable["storage"].IsInt64());
            }
            listedVariables = true;
        }
        else if (envelope.request_id() == 22)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find(
                "\"callingConventions\""), std::string::npos);
            EXPECT_TRUE(analysisResult["callingConventions"].IsArray());
            listedCallingConventions = true;
        }
        else if (envelope.request_id() == 23)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"references\""),
                std::string::npos);
            EXPECT_GT(analysisResult["total"].GetUint64(), 0U);
            bool foundHelper = false;
            for (const auto& reference : analysisResult["references"].GetArray())
            {
                for (const auto& function : reference["functions"].GetArray())
                {
                    const std::string_view name(
                        function["name"].GetString(), function["name"].GetStringLength());
                    foundHelper |= name.find("binjad_fixture_helper") != std::string_view::npos;
                }
            }
            EXPECT_TRUE(foundHelper);
            listedXrefsFrom = true;
        }
        else if (envelope.request_id() == 24)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"references\""),
                std::string::npos);
            EXPECT_GT(analysisResult["total"].GetUint64(), 0U);
            bool foundMain = false;
            for (const auto& reference : analysisResult["references"].GetArray())
            {
                if (reference["function"].IsNull())
                    continue;
                const auto& function = reference["function"];
                const std::string_view name(
                    function["name"].GetString(), function["name"].GetStringLength());
                foundMain |= name.find("main") != std::string_view::npos;
            }
            EXPECT_TRUE(foundMain);
            listedXrefsTo = true;
        }
        else if (envelope.request_id() == 25)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"strings\""),
                std::string::npos);
            for (const auto& string : analysisResult["strings"].GetArray())
            {
                EXPECT_TRUE(string.HasMember("address"));
                EXPECT_NE(string.HasMember("value"), string.HasMember("bytes"));
                if (string.HasMember("truncated"))
                {
                    EXPECT_TRUE(string["truncated"].GetBool());
                    EXPECT_TRUE(string.HasMember("length"));
                }
            }
            ASSERT_FALSE(analysisResult["strings"].Empty());
            EXPECT_EQ(std::string(analysisResult["strings"][0]["value"].GetString()),
                "binjad-analysis-fixture-marker");
            listedStrings = true;
        }
        else if (envelope.request_id() == 26)
        {
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"symbols\""),
                std::string::npos);
            for (const auto& symbol : analysisResult["symbols"].GetArray())
            {
                EXPECT_EQ(symbol.MemberCount(), 3U);
                EXPECT_TRUE(symbol["address"].IsString());
                EXPECT_TRUE(symbol["name"].IsString());
                EXPECT_TRUE(symbol["type"].IsString());
            }
            EXPECT_FALSE(analysisResult["symbols"].Empty());
            listedSymbols = true;
        }
        else if (envelope.request_id() == 36)
        {
            ASSERT_EQ(analysisResult["functions"].Size(), 1U);
            EXPECT_NE(std::string(analysisResult["functions"][0]["name"].GetString()).find(
                "binjad_fixture_helper"), std::string::npos);
            EXPECT_EQ(analysisResult["count"].GetUint64(), 1U);
            ++filteredAnalysisTools;
        }
        else if (envelope.request_id() == 37)
        {
            EXPECT_TRUE(analysisResult["functions"].Empty());
            EXPECT_EQ(analysisResult["total"].GetUint64(), 0U);
            EXPECT_TRUE(analysisResult["nextOffset"].IsNull());
            EXPECT_FALSE(analysisResult["truncated"].GetBool());
            ++filteredAnalysisTools;
        }
        else if (envelope.request_id() == 38)
        {
            ASSERT_EQ(analysisResult["symbols"].Size(), 1U);
            EXPECT_NE(std::string(analysisResult["symbols"][0]["name"].GetString()).find(
                "binjad_fixture_helper"), std::string::npos);
            ++filteredAnalysisTools;
        }
        else if (envelope.request_id() == 39)
        {
            ASSERT_FALSE(analysisResult["symbols"].Empty());
            const std::string address = analysisResult["symbols"][0]["address"].GetString();
            for (const auto& symbol : analysisResult["symbols"].GetArray())
                EXPECT_EQ(std::string(symbol["address"].GetString()), address);
            ++filteredAnalysisTools;
        }
        else if (envelope.request_id() == 40)
        {
            EXPECT_TRUE(analysisResult["symbols"].Empty());
            EXPECT_EQ(analysisResult["count"].GetUint64(), 0U);
            EXPECT_TRUE(analysisResult["nextOffset"].IsNull());
            ++filteredAnalysisTools;
        }
        else if (envelope.request_id() == 41)
        {
            EXPECT_TRUE(envelope.reply().success());
        }
        else if (envelope.request_id() == 42)
        {
            EXPECT_EQ(std::string(analysisResult["encoding"].GetString()), "ascii");
            EXPECT_EQ(std::string(analysisResult["value"].GetString()), "binj");
            EXPECT_EQ(analysisResult["byteLength"].GetUint64(), 30U);
            EXPECT_EQ(analysisResult["characterLength"].GetUint64(), 30U);
            EXPECT_EQ(analysisResult["nextOffset"].GetUint64(), 4U);
            EXPECT_TRUE(analysisResult["truncated"].GetBool());
            ++analyzedToolResults;
        }
        else if (envelope.request_id() == 43)
        {
            const std::string_view text(
                analysisResult["text"].GetString(), analysisResult["text"].GetStringLength());
            EXPECT_NE(text.find("0x"), std::string_view::npos);
            EXPECT_GT(analysisResult["total"].GetUint64(), 1U);
            ++analyzedToolResults;
        }
        else if (envelope.request_id() == 44)
        {
            const std::string_view text(
                analysisResult["text"].GetString(), analysisResult["text"].GetStringLength());
            EXPECT_NE(text.find("binjad_fixture_helper"), std::string_view::npos)
                << envelope.reply().analysis_tool_result().json();
            EXPECT_GT(analysisResult["total"].GetUint64(), 1U);
            ++analyzedToolResults;
        }
        else if (envelope.request_id() == 45)
        {
            EXPECT_EQ(std::string(analysisResult["level"].GetString()), "llil");
            EXPECT_TRUE(analysisResult["ssa"].GetBool());
            EXPECT_GT(analysisResult["total"].GetUint64(), 1U);
            const std::string_view text(
                analysisResult["text"].GetString(), analysisResult["text"].GetStringLength());
            EXPECT_NE(text.find('#'), std::string_view::npos);
            ++analyzedToolResults;
        }
        else if (envelope.request_id() == 46)
        {
            ASSERT_EQ(analysisResult["strings"].Size(), 1U);
            const auto& string = analysisResult["strings"][0];
            EXPECT_EQ(string["value"].GetStringLength(), 128U);
            EXPECT_EQ(string["length"].GetUint64(), 147U);
            EXPECT_TRUE(string["truncated"].GetBool());
            ++stringEdgeCases;
        }
        else if (envelope.request_id() == 47)
        {
            EXPECT_EQ(analysisResult["offset"].GetUint64(), 128U);
            EXPECT_EQ(analysisResult["count"].GetUint64(), 19U);
            EXPECT_EQ(analysisResult["characterLength"].GetUint64(), 147U);
            EXPECT_EQ(analysisResult["value"].GetStringLength(), 19U);
            EXPECT_TRUE(analysisResult["nextOffset"].IsNull());
            EXPECT_FALSE(analysisResult["truncated"].GetBool());
            ++stringEdgeCases;
        }
        else if (envelope.request_id() == 48)
        {
            EXPECT_EQ(std::string(analysisResult["encoding"].GetString()), "utf-8");
            EXPECT_EQ(analysisResult["byteLength"].GetUint64(), 19U);
            EXPECT_EQ(analysisResult["characterLength"].GetUint64(), 15U);
            EXPECT_EQ(std::string(analysisResult["value"].GetString(),
                analysisResult["value"].GetStringLength()),
                "binjad-utf8-\xc3\xa9-\xf0\x9f\x98\x80");
            ++stringEdgeCases;
        }
        else if (envelope.request_id() == 91)
        {
            ASSERT_EQ(analysisResult["strings"].Size(), 1U);
            EXPECT_EQ(std::string(analysisResult["strings"][0]["value"].GetString(),
                analysisResult["strings"][0]["value"].GetStringLength()),
                "binjad-utf8-\xc3\xa9-\xf0\x9f\x98\x80");
            ++stringEdgeCases;
        }
        else if (envelope.request_id() == 49)
        {
            EXPECT_EQ(std::string(analysisResult["text"].GetString()), "");
            EXPECT_EQ(analysisResult["count"].GetUint64(), 0U);
            EXPECT_TRUE(analysisResult["nextOffset"].IsNull());
            EXPECT_FALSE(analysisResult["truncated"].GetBool());
            ++renderingPages;
        }
        else if (envelope.request_id() == 50 || envelope.request_id() == 51)
        {
            EXPECT_EQ(analysisResult["count"].GetUint64(), 1U);
            EXPECT_GT(analysisResult["total"].GetUint64(), 1U);
            EXPECT_EQ(analysisResult["nextOffset"].GetUint64(), 1U);
            EXPECT_TRUE(analysisResult["truncated"].GetBool());
            ++renderingPages;
        }
        else if (envelope.request_id() == 53)
        {
            EXPECT_EQ(analysisResult["offset"].GetUint64(), 147U);
            EXPECT_EQ(analysisResult["count"].GetUint64(), 0U);
            EXPECT_EQ(std::string(analysisResult["value"].GetString()), "");
            EXPECT_TRUE(analysisResult["nextOffset"].IsNull());
            EXPECT_FALSE(analysisResult["truncated"].GetBool());
            ++stringEdgeCases;
        }
        else if (envelope.request_id() == 55)
        {
            ASSERT_FALSE(analysisResult["symbols"].Empty());
            const auto& symbol = analysisResult["symbols"][0];
            EXPECT_EQ(symbol.MemberCount(), 9U);
            EXPECT_NE(std::string(symbol["fullName"].GetString()).find(
                "binjad_fixture_helper"), std::string::npos);
            EXPECT_EQ(std::string(symbol["type"].GetString()), "FunctionSymbol");
            EXPECT_TRUE(symbol["namespace"].IsArray());
            EXPECT_TRUE(symbol["binding"].IsString());
            EXPECT_TRUE(symbol["autoDefined"].IsBool());
            inspectedSymbols = true;
        }
        else if (envelope.request_id() == 56)
        {
            for (const auto& symbol : analysisResult["symbols"].GetArray())
            {
                const std::string_view type(
                    symbol["type"].GetString(), symbol["type"].GetStringLength());
                EXPECT_TRUE(type == "ImportAddressSymbol" ||
                    type == "ImportedFunctionSymbol" || type == "ImportedDataSymbol");
            }
            listedImports = true;
        }
        else if (envelope.request_id() == 57)
        {
            for (const auto& symbol : analysisResult["symbols"].GetArray())
            {
                const std::string_view type(
                    symbol["type"].GetString(), symbol["type"].GetStringLength());
                EXPECT_TRUE(type == "FunctionSymbol" || type == "DataSymbol");
            }
            listedExports = true;
        }
        else if (envelope.request_id() == 58)
        {
            ASSERT_FALSE(analysisResult["entryPoints"].Empty());
            for (const auto& entry : analysisResult["entryPoints"].GetArray())
            {
                EXPECT_EQ(entry.MemberCount(), 2U);
                EXPECT_TRUE(entry["address"].IsString());
                EXPECT_TRUE(entry["name"].IsString());
            }
            listedEntryPoints = true;
        }
        else if (envelope.request_id() == 59)
        {
            ASSERT_FALSE(analysisResult["sections"].Empty());
            for (const auto& section : analysisResult["sections"].GetArray())
            {
                EXPECT_EQ(section.MemberCount(), 4U);
                EXPECT_TRUE(section["name"].IsString());
                EXPECT_TRUE(section["start"].IsString());
                EXPECT_TRUE(section["end"].IsString());
                EXPECT_TRUE(section["semantics"].IsString());
            }
            listedSections = true;
        }
        else if (envelope.request_id() == 60)
        {
            ASSERT_FALSE(analysisResult["segments"].Empty());
            for (const auto& segment : analysisResult["segments"].GetArray())
            {
                EXPECT_EQ(segment.MemberCount(), 16U);
                EXPECT_TRUE(segment["flags"].IsArray());
                EXPECT_TRUE(segment["readable"].IsBool());
                EXPECT_TRUE(segment["writable"].IsBool());
                EXPECT_TRUE(segment["executable"].IsBool());
                EXPECT_TRUE(segment["autoDefined"].IsBool());
            }
            listedSegments = true;
        }
        else if (envelope.request_id() == 61)
        {
            EXPECT_EQ(analysisResult["bytesRead"].GetUint64(), 16U);
            EXPECT_EQ(analysisResult["hex"].GetStringLength(), 32U);
            readMemory = true;
        }
        else if (envelope.request_id() == 62)
        {
            ASSERT_FALSE(analysisResult["dataVariables"].Empty());
            for (const auto& variable : analysisResult["dataVariables"].GetArray())
            {
                EXPECT_EQ(variable.MemberCount(), 2U);
                EXPECT_TRUE(variable["address"].IsString());
                EXPECT_TRUE(variable["type"].IsString());
            }
            listedDataVariables = true;
        }
        else if (envelope.request_id() == 63)
        {
            EXPECT_TRUE(analysisResult["dataVariable"].IsObject());
            EXPECT_TRUE(analysisResult["exactDataVariable"].GetBool());
            EXPECT_TRUE(analysisResult["memory"]["hex"].IsString());
            EXPECT_TRUE(analysisResult["symbols"].IsArray());
            EXPECT_TRUE(analysisResult["functions"].IsArray());
            inspectedData = true;
        }
        else if (envelope.request_id() == 64)
        {
            EXPECT_TRUE(analysisResult["updated"].GetBool());
            EXPECT_EQ(std::string(analysisResult["text"].GetString()), "fixture comment");
            ++commentResults;
        }
        else if (envelope.request_id() == 65)
        {
            EXPECT_EQ(std::string(analysisResult["text"].GetString()), "fixture comment");
            ++commentResults;
        }
        else if (envelope.request_id() == 66)
        {
            EXPECT_TRUE(analysisResult["updated"].GetBool());
            EXPECT_EQ(std::string(analysisResult["text"].GetString()),
                "updated fixture comment");
            ++commentResults;
        }
        else if (envelope.request_id() == 67)
        {
            EXPECT_EQ(std::string(analysisResult["text"].GetString()),
                "updated fixture comment");
            ++commentResults;
        }
        else if (envelope.request_id() == 68)
        {
            EXPECT_TRUE(analysisResult["deleted"].GetBool());
            ++commentResults;
        }
        else if (envelope.request_id() == 69)
        {
            EXPECT_EQ(std::string(analysisResult["text"].GetString()), "");
            ++commentResults;
        }
        else if (envelope.request_id() == 70)
        {
            const auto& symbol = analysisResult["symbol"];
            EXPECT_EQ(std::string(symbol["fullName"].GetString()), "fixture_named_data");
            EXPECT_EQ(std::string(symbol["binding"].GetString()), "GlobalBinding");
            EXPECT_EQ(symbol["ordinal"].GetUint64(), 3U);
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 71)
        {
            bool found = false;
            for (const auto& symbol : analysisResult["symbols"].GetArray())
                found |= std::string_view(symbol["fullName"].GetString()) == "fixture_named_data";
            EXPECT_TRUE(found);
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 72)
        {
            EXPECT_EQ(std::string(analysisResult["symbol"]["fullName"].GetString()),
                "fixture_renamed_data");
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 73)
        {
            bool found = false;
            for (const auto& symbol : analysisResult["symbols"].GetArray())
                found |= std::string_view(symbol["fullName"].GetString()) == "fixture_renamed_data";
            EXPECT_TRUE(found);
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 74)
        {
            EXPECT_TRUE(analysisResult["deleted"].GetBool());
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 75)
        {
            bool found = false;
            for (const auto& symbol : analysisResult["symbols"].GetArray())
                found |= std::string_view(symbol["fullName"].GetString()) == "fixture_renamed_data";
            EXPECT_FALSE(found);
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 102)
        {
            EXPECT_EQ(std::string(analysisResult["symbol"]["type"].GetString()),
                "FunctionSymbol");
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 104)
        {
            EXPECT_TRUE(analysisResult["deleted"].GetBool());
            ++symbolMutationResults;
        }
        else if (envelope.request_id() == 76)
        {
            EXPECT_TRUE(analysisResult["hasUserType"].GetBool());
            const std::string_view type(
                analysisResult["type"].GetString(), analysisResult["type"].GetStringLength());
            EXPECT_NE(type.find("int32_t"), std::string_view::npos);
            setPrototype = true;
        }
        else if (envelope.request_id() == 77)
        {
            EXPECT_EQ(std::string(analysisResult["callingConvention"].GetString()), "apple-arm64");
            setCallingConvention = true;
        }
        else if (envelope.request_id() == 78)
        {
            ASSERT_EQ(analysisResult["types"].Size(), 1U);
            EXPECT_EQ(std::string(analysisResult["types"][0]["name"].GetString()),
                "fixture_type");
            EXPECT_FALSE(analysisResult["types"][0]["autoDefined"].GetBool());
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 79)
        {
            EXPECT_EQ(std::string(analysisResult["name"].GetString()), "fixture_type");
            const std::string_view definition(
                analysisResult["definition"].GetString(),
                analysisResult["definition"].GetStringLength());
            EXPECT_NE(definition.find("fixture_type"), std::string_view::npos);
            EXPECT_NE(definition.find(" x"), std::string_view::npos);
            EXPECT_EQ(definition.find("BN_TYPE_PARSER"), std::string_view::npos);
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 80)
        {
            EXPECT_EQ(std::string(analysisResult["name"].GetString()), "fixture_struct");
            EXPECT_EQ(std::string(analysisResult["class"].GetString()),
                "StructureTypeClass");
            EXPECT_NE(std::string_view(analysisResult["definition"].GetString()).find("value"),
                std::string_view::npos);
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 81)
        {
            EXPECT_EQ(std::string(analysisResult["name"].GetString()), "fixture_struct");
            EXPECT_GE(analysisResult["width"].GetUint64(), 8U);
            EXPECT_NE(std::string_view(analysisResult["definition"].GetString()).find("other"),
                std::string_view::npos);
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 82)
        {
            EXPECT_TRUE(analysisResult["deleted"].GetBool());
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 83)
        {
            EXPECT_TRUE(analysisResult["types"].Empty());
            ++definedTypeResults;
        }
        else if (envelope.request_id() == 84)
        {
            EXPECT_TRUE(analysisResult["exactDataVariable"].GetBool());
            EXPECT_EQ(std::string(analysisResult["dataVariable"]["type"].GetString()),
                "uint32_t");
            EXPECT_FALSE(analysisResult["dataVariable"]["autoDiscovered"].GetBool());
            ++dataVariableMutations;
        }
        else if (envelope.request_id() == 85)
        {
            ASSERT_TRUE(analysisResult["dataVariable"].IsObject());
            EXPECT_TRUE(analysisResult["exactDataVariable"].GetBool());
            EXPECT_TRUE(analysisResult["dataVariable"]["autoDiscovered"].GetBool());
            ++dataVariableMutations;
        }
        else if (envelope.request_id() == 86)
        {
            EXPECT_EQ(std::string(analysisResult["section"]["name"].GetString()),
                "fixture_custom");
            EXPECT_EQ(std::string(analysisResult["section"]["semantics"].GetString()),
                "ReadOnlyCodeSectionSemantics");
            ++sectionMutations;
        }
        else if (envelope.request_id() == 87)
        {
            EXPECT_TRUE(analysisResult["deleted"].GetBool());
            ++sectionMutations;
        }
        else if (envelope.request_id() == 88)
        {
            EXPECT_EQ(std::string(analysisResult["section"]["name"].GetString()),
                "fixture_custom_renamed");
            ++sectionMutations;
        }
        else if (envelope.request_id() == 92)
        {
            EXPECT_TRUE(analysisResult["added"].GetBool());
            EXPECT_NE(std::string(analysisResult["nextAction"].GetString()).find(
                "bn_analysis_update_and_wait"), std::string::npos);
            addedEntryPoint = true;
        }
        else if (envelope.request_id() == 93)
        {
            EXPECT_TRUE(analysisResult["created"].GetBool());
            EXPECT_FALSE(analysisResult["autoDiscovered"].GetBool());
            EXPECT_NE(std::string(analysisResult["nextAction"].GetString()).find(
                "bn_binary_view_save"), std::string::npos);
            createdUserFunction = true;
        }
        else if (envelope.request_id() == 94)
        {
            EXPECT_EQ(analysisResult["total"].GetUint64(), 1U);
            listedCreatedFunction = true;
        }
        else if (envelope.request_id() == 101)
        {
            EXPECT_FALSE(analysisResult["created"].GetBool());
            repeatedUserFunction = true;
        }
        else if (envelope.request_id() == 95)
        {
            EXPECT_GE(analysisResult["total"].GetUint64(), 1U);
            listedAddedEntryPoint = true;
        }
        else if (envelope.request_id() == 96)
        {
            EXPECT_TRUE(envelope.reply().has_file_opened());
            EXPECT_TRUE(envelope.reply().file_opened().database_backed());
        }
        else if (envelope.request_id() == 97)
        {
            EXPECT_TRUE(envelope.reply().has_binary_view_opened());
            EXPECT_TRUE(envelope.reply().binary_view_opened().database_backed());
        }
        else if (envelope.request_id() == 98)
        {
            EXPECT_EQ(analysisResult["total"].GetUint64(), 1U);
            restoredUserFunction = true;
        }
        else if (envelope.request_id() == 99)
        {
            EXPECT_GE(analysisResult["total"].GetUint64(), 1U);
            restoredEntryPoint = true;
        }
        else if (envelope.request_id() == 12)
            shutdown = true;
    }
    EXPECT_TRUE(opened);
    EXPECT_TRUE(status);
    EXPECT_TRUE(closed);
    EXPECT_TRUE(shutdown);
    EXPECT_TRUE(createdDatabase);
    EXPECT_TRUE(savedSnapshot);
    EXPECT_TRUE(listedFunctions);
    EXPECT_TRUE(inspectedFunction);
    EXPECT_TRUE(listedCallers);
    EXPECT_TRUE(listedCallees);
    EXPECT_TRUE(renderedDisassembly);
    EXPECT_TRUE(renderedDecompilation);
    EXPECT_TRUE(renderedDecompilationAlias);
    EXPECT_TRUE(restoredDatabaseComment);
    EXPECT_TRUE(renderedIL);
    EXPECT_TRUE(listedStack);
    EXPECT_TRUE(listedVariables);
    EXPECT_TRUE(listedCallingConventions);
    EXPECT_TRUE(listedXrefsFrom);
    EXPECT_TRUE(listedXrefsTo);
    EXPECT_TRUE(listedStrings);
    EXPECT_TRUE(listedSymbols);
    EXPECT_EQ(rejectedAnalysisTools, 12U);
    EXPECT_EQ(filteredAnalysisTools, 5U);
    EXPECT_EQ(analyzedToolResults, 4U);
    EXPECT_EQ(stringEdgeCases, 5U);
    EXPECT_EQ(renderingPages, 3U);
    EXPECT_TRUE(inspectedSymbols);
    EXPECT_TRUE(listedImports);
    EXPECT_TRUE(listedExports);
    EXPECT_TRUE(listedEntryPoints);
    EXPECT_TRUE(listedSections);
    EXPECT_TRUE(listedSegments);
    EXPECT_TRUE(readMemory);
    EXPECT_TRUE(listedDataVariables);
    EXPECT_TRUE(inspectedData);
    EXPECT_EQ(commentResults, 6U);
    EXPECT_EQ(symbolMutationResults, 8U);
    EXPECT_TRUE(setPrototype);
    EXPECT_TRUE(setCallingConvention);
    EXPECT_EQ(definedTypeResults, 6U);
    EXPECT_EQ(dataVariableMutations, 2U);
    EXPECT_EQ(sectionMutations, 3U);
    EXPECT_TRUE(addedEntryPoint);
    EXPECT_TRUE(createdUserFunction);
    EXPECT_TRUE(repeatedUserFunction);
    EXPECT_TRUE(listedCreatedFunction);
    EXPECT_TRUE(listedAddedEntryPoint);
    EXPECT_TRUE(restoredUserFunction);
    EXPECT_TRUE(restoredEntryPoint);
    EXPECT_TRUE(guidedFunctionCreation);
    EXPECT_EQ(searchResults, 7U);
    EXPECT_TRUE(std::filesystem::is_regular_file(database));
    std::filesystem::remove(database, ignored);
}

TEST(FileChildTest, ParsesMachOHeadersAndLinkedLibraries)
{
    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(BINJAD_ANALYSIS_FIXTURE);
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_binary_header_info");
        execute->set_arguments_json("{}");
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_linked_library_list");
        execute->set_arguments_json(R"({"offset":0,"limit":100})");
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_macho_load_command_list");
        execute->set_arguments_json(R"({"query":"segment","offset":0,"limit":100})");
    }));
    requests.push_back(Command(6, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(7, [](binjad::ipc::Command& command) { command.mutable_shutdown(); }));

    const auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    EXPECT_EQ(binjad::RunFileChild(std::make_unique<QueueChannel>(std::move(requests), responses)), EXIT_SUCCESS);

    std::size_t parsed = 0;
    for (const auto& payload : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(payload);
        if (envelope.request_id() < 3 || envelope.request_id() > 5)
            continue;
        ASSERT_TRUE(envelope.has_reply());
        ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
        ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
        rapidjson::Document result;
        const auto& json = envelope.reply().analysis_tool_result().json();
        result.Parse(json.data(), json.size());
        ASSERT_FALSE(result.HasParseError()) << json;
        if (envelope.request_id() == 3)
        {
            EXPECT_STREQ(result["format"].GetString(), "Mach-O");
            EXPECT_TRUE(result["header"].HasMember("loadCommandCount"));
            EXPECT_TRUE(result["header"].HasMember("uuid"));
        }
        else if (envelope.request_id() == 4)
        {
            EXPECT_TRUE(result["libraries"].IsArray());
            EXPECT_GE(result["total"].GetUint64(), 1U);
        }
        else
        {
            EXPECT_TRUE(result["loadCommands"].IsArray());
            EXPECT_GE(result["total"].GetUint64(), 1U);
        }
        ++parsed;
    }
    EXPECT_EQ(parsed, 3U);
}

namespace
{
    void ExerciseHeaderFixture(const std::filesystem::path& fixture, std::string_view viewType,
        std::initializer_list<std::pair<std::string_view, std::string_view>> tools)
    {
        std::deque<std::vector<std::uint8_t>> requests;
        requests.push_back(Command(1, [&](binjad::ipc::Command& command) {
            auto* open = command.mutable_open_file();
            open->set_path(fixture.string());
            open->set_options_json("{}");
        }));
        requests.push_back(Command(2, [&](binjad::ipc::Command& command) {
            auto* open = command.mutable_open_binary_view();
            open->set_view_type(std::string(viewType));
            open->set_options_json("{}");
            open->set_analyze(false);
        }));
        std::uint64_t requestId = 3;
        for (const auto& [tool, key] : tools)
        {
            (void)key;
            requests.push_back(Command(requestId++, [&, tool](binjad::ipc::Command& command) {
                auto* execute = command.mutable_execute_analysis_tool();
                execute->set_view_type(std::string(viewType));
                execute->set_name(std::string(tool));
                execute->set_arguments_json(R"({"offset":0,"limit":100})");
            }));
        }
        requests.push_back(Command(requestId++, [](binjad::ipc::Command& command) {
            command.mutable_close_file()->set_discard_uncommitted(true);
        }));
        requests.push_back(Command(requestId, [](binjad::ipc::Command& command) { command.mutable_shutdown(); }));

        const auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
        EXPECT_EQ(binjad::RunFileChild(std::make_unique<QueueChannel>(std::move(requests), responses)), EXIT_SUCCESS);

        std::size_t parsed = 0;
        for (const auto& payload : *responses)
        {
            const auto envelope = binjad::ipc::ParseEnvelope(payload);
            if (envelope.request_id() < 3 || envelope.request_id() >= 3 + tools.size())
                continue;
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            rapidjson::Document result;
            const auto& json = envelope.reply().analysis_tool_result().json();
            result.Parse(json.data(), json.size());
            ASSERT_FALSE(result.HasParseError()) << json;
            const auto& expected = *(tools.begin() + (envelope.request_id() - 3));
            if (expected.first == "bn_binary_header_info")
            {
                EXPECT_EQ(std::string_view(result["format"].GetString()), viewType);
                EXPECT_TRUE(result["header"].IsObject());
            }
            else
            {
                EXPECT_TRUE(result[expected.second.data()].IsArray()) << json;
                EXPECT_GE(result["total"].GetUint64(), 1U) << json;
            }
            ++parsed;
        }
        EXPECT_EQ(parsed, tools.size());
    }
}

TEST(FileChildTest, ParsesElfHeadersAndLinkedLibraries)
{
    const auto sourceDirectory = std::filesystem::path(__FILE__).parent_path().parent_path();
    ExerciseHeaderFixture(sourceDirectory /
            "vendor/debugger/test/binaries/Linux-x86_64/helloworld",
        "ELF", {{"bn_binary_header_info", ""}, {"bn_linked_library_list", "libraries"},
                   {"bn_elf_program_header_list", "programHeaders"},
                   {"bn_elf_dynamic_entry_list", "dynamicEntries"}});
}

TEST(FileChildTest, ParsesPeHeadersAndLinkedLibraries)
{
    const auto sourceDirectory = std::filesystem::path(__FILE__).parent_path().parent_path();
    ExerciseHeaderFixture(sourceDirectory /
            "vendor/debugger/test/binaries/Windows-x86_64/helloworld.exe",
        "PE", {{"bn_binary_header_info", ""}, {"bn_linked_library_list", "libraries"},
                  {"bn_pe_data_directory_list", "dataDirectories"}});
}

TEST(FileChildTest, MapsRawFirmwareWithAuthoritativeLoaderSettings)
{
    const auto firmware = std::filesystem::temp_directory_path() /
        ("binjad-mapped-cortex-m-" + std::to_string(getpid()) + ".bin");
    {
        const std::array<std::uint8_t, 12> bytes{
            0x00, 0x10, 0x00, 0x20,
            0x09, 0x00, 0x00, 0x00,
            0x00, 0xb5, 0x00, 0xbd};
        std::ofstream output(firmware, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(output);
        output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        ASSERT_TRUE(output);
    }

    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [&](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(firmware.string());
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Raw");
        open->set_options_json(R"({"architecture":"thumb2"})");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mapped");
        open->set_options_json(R"({"architecture":"thumb2"})");
        open->set_analyze(false);
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mapped");
        open->set_options_json(
            R"({"loader.platform":"thumb2","loader.imageBase":0,"loader.entryPointOffset":8})");
        open->set_analyze(false);
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mapped");
        execute->set_name("bn_entry_point_add");
        execute->set_arguments_json(R"({"address":"0x8"})");
    }));
    for (const auto& [id, name, arguments] : std::vector<std::tuple<std::uint64_t, std::string, std::string>>{
             {20, "bn_transaction_begin", "{}"},
             {21, "bn_comment_set", R"({"address":"0x8","text":"rolled back"})"},
             {22, "bn_transaction_rollback", "{}"},
             {23, "bn_comment_get", R"({"address":"0x8"})"},
             {24, "bn_transaction_begin", "{}"},
             {25, "bn_comment_set", R"({"address":"0x8","text":"committed"})"},
             {26, "bn_transaction_commit", "{}"},
             {27, "bn_undo", "{}"},
             {28, "bn_comment_get", R"({"address":"0x8"})"},
             {29, "bn_redo", "{}"},
             {30, "bn_comment_get", R"({"address":"0x8"})"}})
    {
        requests.push_back(Command(id, [=](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("Mapped"); execute->set_name(name);
            execute->set_arguments_json(arguments);
        }));
    }
    for (const auto& [id, name, arguments] : std::vector<std::tuple<std::uint64_t, std::string, std::string>>{
             {40, "bn_bookmark_create", R"({"address":"0x8","note":"entry bookmark"})"},
             {41, "bn_bookmark_list", R"({"offset":0,"limit":10})"},
             {42, "bn_tag_create", R"({"address":"0x8","type":"Review","data":"inspect entry","icon":"R"})"},
             {43, "bn_tag_list", R"({"type":"Review","offset":0,"limit":10})"},
             {44, "bn_metadata_set", R"({"key":"review","value":{"status":"open","count":2}})"},
             {45, "bn_metadata_get", R"({"key":"review"})"},
             {46, "bn_metadata_delete", R"({"key":"review"})"}})
    {
        requests.push_back(Command(id, [=](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("Mapped"); execute->set_name(name);
            execute->set_arguments_json(arguments);
        }));
    }
    for (const auto& [id, name, arguments] : std::vector<std::tuple<std::uint64_t, std::string, std::string>>{
             {6, "bn_segment_create", R"({"start":"0x100","length":"0x10","dataOffset":"0","dataLength":"0","flags":3})"},
             {7, "bn_memory_map_preview", R"({"operation":"modify","start":"0x100","length":"0x10","newStart":"0x110","newLength":"0x20","dataOffset":"0","dataLength":"0","flags":3})"},
             {8, "bn_segment_modify", R"({"start":"0x100","length":"0x10","newStart":"0x110","newLength":"0x20","dataOffset":"0","dataLength":"0","flags":3})"},
             {9, "bn_segment_delete", R"({"start":"0x110","length":"0x20"})"},
             {10, "bn_string_define", R"({"address":"0x8","length":"4","encoding":"ascii"})"},
             {11, "bn_string_undefine", R"({"address":"0x8"})"},
             {12, "bn_function_create", R"({"address":"0x8"})"},
             {13, "bn_function_delete", R"({"function":"0x8"})"},
             {14, "bn_binary_view_rebase", R"({"address":"0x1000"})"}})
    {
        requests.push_back(Command(id, [=](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("Mapped"); execute->set_name(name);
            execute->set_arguments_json(arguments);
        }));
    }
    requests.push_back(Command(31, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(32, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses);
    EXPECT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);
    bool sawMapped = false;
    std::size_t nativeMutations = 0;
    std::size_t transactionResults = 0;
    std::size_t annotationResults = 0;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (!envelope.has_reply())
            continue;
        if (envelope.request_id() == 1)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            for (const auto& candidate : envelope.reply().file_opened().candidates())
            {
                if (candidate.view_type() != "Mapped")
                    continue;
                sawMapped = true;
                EXPECT_FALSE(candidate.recommended());
                EXPECT_NE(candidate.load_settings_schema_json().find("loader.platform"),
                    std::string::npos);
                EXPECT_NE(candidate.load_settings_schema_json().find("loader.entryPointOffset"),
                    std::string::npos);
            }
        }
        else if (envelope.request_id() == 2)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find("select Mapped"), std::string::npos);
        }
        else if (envelope.request_id() == 3)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find("not supported by Mapped"),
                std::string::npos);
            EXPECT_NE(envelope.reply().error().find("bn_binary_view_load_settings"),
                std::string::npos);
        }
        else if (envelope.request_id() == 4)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            const auto& opened = envelope.reply().binary_view_opened();
            EXPECT_EQ(opened.view_type(), "Mapped");
            EXPECT_EQ(opened.architecture(), "thumb2");
            EXPECT_EQ(opened.platform(), "thumb2");
            EXPECT_EQ(opened.start(), 0U);
            EXPECT_GE(opened.end(), 12U);
            EXPECT_EQ(opened.entry_point(), 8U);
            EXPECT_NE(opened.effective_load_settings_json().find("loader.platform"),
                std::string::npos);
        }
        else if (envelope.request_id() == 5)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            EXPECT_TRUE(envelope.reply().has_analysis_tool_result());
        }
        else if (envelope.request_id() >= 6 && envelope.request_id() <= 14)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.request_id() << ": " << envelope.reply().error();
            EXPECT_TRUE(envelope.reply().has_analysis_tool_result());
            ++nativeMutations;
        }
        else if (envelope.request_id() >= 20 && envelope.request_id() <= 30)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.request_id() << ": " << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            rapidjson::Document analysisResult;
            const auto& json = envelope.reply().analysis_tool_result().json();
            analysisResult.Parse(json.data(), json.size());
            ASSERT_FALSE(analysisResult.HasParseError());
            if (envelope.request_id() == 23 || envelope.request_id() == 28)
                EXPECT_STREQ(analysisResult["text"].GetString(), "");
            if (envelope.request_id() == 30)
                EXPECT_STREQ(analysisResult["text"].GetString(), "committed");
            ++transactionResults;
        }
        else if (envelope.request_id() >= 40 && envelope.request_id() <= 46)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.request_id() << ": " << envelope.reply().error();
            rapidjson::Document result; const auto& json = envelope.reply().analysis_tool_result().json();
            result.Parse(json.data(), json.size()); ASSERT_FALSE(result.HasParseError());
            if (envelope.request_id() == 41) EXPECT_EQ(result["total"].GetUint64(), 1U);
            if (envelope.request_id() == 43) EXPECT_EQ(result["total"].GetUint64(), 1U);
            if (envelope.request_id() == 45) EXPECT_STREQ(result["value"]["status"].GetString(), "open");
            ++annotationResults;
        }
    }
    EXPECT_TRUE(sawMapped);
    EXPECT_EQ(nativeMutations, 9U);
    EXPECT_EQ(transactionResults, 11U);
    EXPECT_EQ(annotationResults, 7U);
    std::error_code ignored;
    std::filesystem::remove(firmware, ignored);
}

TEST(FileChildTest, LoadsDebuggerPluginApiForExplicitView)
{
    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(BINJAD_DEBUGGER_FIXTURE);
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_adapter_list");
        execute->set_arguments_json(R"({"binaryView":"test"})");
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_status");
        execute->set_arguments_json(R"({"binaryView":"test"})");
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_configure");
        execute->set_arguments_json(std::string(R"({"binaryView":"test","executable":")") +
            BINJAD_DEBUGGER_FIXTURE + "\"}");
    }));
    requests.push_back(Command(6, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_launch");
        execute->set_arguments_json(R"({"binaryView":"test"})");
    }));
    requests.push_back(Command(7, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_pause_and_wait");
        execute->set_arguments_json(
            R"({"binaryView":"test","timeoutMilliseconds":10000})");
    }));
    requests.push_back(Command(8, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_thread_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(9, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_register_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(10, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_module_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(11, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_memory_region_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(12, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_debugger_quit");
        execute->set_arguments_json(R"({"binaryView":"test"})");
    }));
    requests.push_back(Command(14, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_kernel_cache_image_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":3})");
    }));
    requests.push_back(Command(13, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses);
    EXPECT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);

    bool adaptersSeen = false;
    bool statusSeen = false;
    bool launchSeen = false;
    std::size_t targetStateReplies = 0;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (!envelope.has_reply()) continue;
        if (envelope.request_id() == 3)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("LLDB"),
                std::string::npos);
            adaptersSeen = true;
        }
        else if (envelope.request_id() == 4)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"connected\":false"),
                std::string::npos);
            statusSeen = true;
        }
        else if (envelope.request_id() == 6)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_NE(envelope.reply().analysis_tool_result().json().find("\"accepted\":true"),
                std::string::npos);
        }
        else if (envelope.request_id() == 7)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            EXPECT_EQ(envelope.reply().analysis_tool_result().json().find("Timed"),
                std::string::npos) << envelope.reply().analysis_tool_result().json();
            launchSeen = true;
        }
        else if (envelope.request_id() >= 8 && envelope.request_id() <= 11)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
            rapidjson::Document document;
            const auto& json = envelope.reply().analysis_tool_result().json();
            document.Parse(json.data(), json.size());
            ASSERT_FALSE(document.HasParseError());
            ASSERT_TRUE(document.HasMember("items"));
            EXPECT_GT(document["total"].GetUint64(), 0U) << json;
            ++targetStateReplies;
        }
        else if (envelope.request_id() == 14)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find("not a KernelCache view"),
                std::string::npos);
        }
    }
    EXPECT_TRUE(adaptersSeen);
    EXPECT_TRUE(statusSeen);
    EXPECT_TRUE(launchSeen);
    EXPECT_EQ(targetStateReplies, 4U);
}

TEST(FileChildTest, ReadsShortNullTerminatedStringAtExplicitAddress)
{
    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(BINJAD_ANALYSIS_FIXTURE);
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O");
        execute->set_name("bn_string_at");
        execute->set_arguments_json(
            R"({"address":"_binjad_fixture_short_message"})");
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses);
    EXPECT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);

    bool found = false;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (!envelope.has_reply() || envelope.request_id() != 3)
            continue;
        ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
        const auto& json = envelope.reply().analysis_tool_result().json();
        rapidjson::Document document;
        document.Parse(json.data(), json.size());
        ASSERT_FALSE(document.HasParseError());
        EXPECT_EQ(std::string(document["value"].GetString()), "udf");
        EXPECT_TRUE(document["inferred"].GetBool());
        found = true;
    }
    EXPECT_TRUE(found);
}

TEST(FileChildTest, ExercisesSharedCachePluginApiWhenFixtureProvided)
{
    const auto* fixture = std::getenv("BINJAD_TEST_SHARED_CACHE");
    if (!fixture || !*fixture)
        GTEST_SKIP() << "BINJAD_TEST_SHARED_CACHE is not configured";

    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [fixture](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(fixture);
        open->set_options_json(R"({"loader.dsc.autoLoadPattern":"^$"})");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("DSCView");
        open->set_options_json(R"({"loader.dsc.autoLoadPattern":"^$"})");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_image_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":3})");
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_image_info");
        execute->set_arguments_json(
            R"({"binaryView":"test","image":"/usr/lib/system/libsystem_c.dylib"})");
    }));
    requests.push_back(Command(5, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_region_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":3})");
    }));
    requests.push_back(Command(6, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_entry_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":3})");
    }));
    requests.push_back(Command(40, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(R"({"function":"0x180715000","limit":10})");
    }));
    requests.push_back(Command(7, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_image_load");
        execute->set_arguments_json(
            R"({"binaryView":"test","image":"/usr/lib/system/libsystem_c.dylib"})");
    }));
    requests.push_back(Command(41, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(R"({"function":"0x180715000","limit":10})");
    }));
    requests.push_back(Command(8, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_shared_cache_symbol_list");
        execute->set_arguments_json(
            R"({"binaryView":"test","query":"_malloc","offset":0,"limit":3})");
    }));
    requests.push_back(Command(50, [](binjad::ipc::Command& command) {
        command.mutable_update_analysis()->set_view_type("DSCView");
    }));
    requests.push_back(Command(51, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("DSCView");
        execute->set_name("bn_string_list");
        execute->set_arguments_json(
            R"({"binaryView":"test","query":"malloc","offset":0,"limit":3})");
    }));
    requests.push_back(Command(9, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(10, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses);
    EXPECT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);

    std::size_t pluginReplies = 0;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (envelope.has_reply() && envelope.request_id() == 40)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find(
                "unloaded SharedCache image '/usr/lib/system/libsystem_c.dylib'"),
                std::string::npos) << envelope.reply().error();
        }
        if (envelope.has_reply() && envelope.request_id() == 41)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find(
                "loaded SharedCache image '/usr/lib/system/libsystem_c.dylib' but is not an analyzed function start"),
                std::string::npos) << envelope.reply().error();
        }
        if (envelope.has_reply() && envelope.request_id() == 51)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            const auto& json = envelope.reply().analysis_tool_result().json();
            rapidjson::Document document;
            document.Parse(json.data(), json.size());
            ASSERT_FALSE(document.HasParseError());
            EXPECT_FALSE(document["available"].GetBool());
            EXPECT_EQ(std::string(document["state"].GetString()), "analysis_running");
            EXPECT_EQ(document["retryAfterMilliseconds"].GetUint(), 10000U);
        }
        if (!envelope.has_reply() || envelope.request_id() < 3 || envelope.request_id() > 8)
            continue;
        ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
        ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
        const auto& json = envelope.reply().analysis_tool_result().json();
        EXPECT_FALSE(json.empty());
        if (envelope.request_id() == 7)
            EXPECT_NE(json.find("bn_analysis_update_and_wait"), std::string::npos);
        ++pluginReplies;
    }
    EXPECT_EQ(pluginReplies, 6U);
}

TEST(FileChildTest, ExercisesKernelCachePluginApiWhenFixtureProvided)
{
    const auto* fixture = std::getenv("BINJAD_TEST_KERNEL_CACHE");
    if (!fixture || !*fixture)
        GTEST_SKIP() << "BINJAD_TEST_KERNEL_CACHE is not configured";
    const auto* configuredImage = std::getenv("BINJAD_TEST_KERNEL_CACHE_IMAGE");
    const std::string image = configuredImage && *configuredImage
        ? configuredImage : "com.apple.filesystems.udf";

    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [fixture](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(fixture);
        open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("KCView");
        open->set_options_json("{}");
        open->set_analyze(false);
    }));
    requests.push_back(Command(3, [image](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_image_list");
        execute->set_arguments_json(std::string(
            R"({"binaryView":"test","query":")") + image +
            R"(","offset":0,"limit":10})");
    }));
    requests.push_back(Command(4, [image](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_image_info");
        execute->set_arguments_json(std::string(
            R"({"binaryView":"test","image":")") + image + "\"}");
    }));
    requests.push_back(Command(42, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_function_decompile");
        execute->set_arguments_json(R"({"function":"0x1","limit":10})");
    }));
    if (image == "com.apple.filesystems.udf")
    {
        requests.push_back(Command(40, [](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("KCView");
            execute->set_name("bn_function_decompile");
            execute->set_arguments_json(
                R"({"function":"0xfffffe0007da21c0","limit":10})");
        }));
    }
    requests.push_back(Command(5, [image](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_image_load");
        execute->set_arguments_json(std::string(
            R"({"binaryView":"test","image":")") + image + "\"}");
    }));
    if (image == "com.apple.filesystems.udf")
    {
        requests.push_back(Command(41, [](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("KCView");
            execute->set_name("bn_function_decompile");
            execute->set_arguments_json(
                R"({"function":"0xfffffe0007da21c0","limit":10})");
        }));
    }
    requests.push_back(Command(6, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_symbol_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(7, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_entry_point_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(8, [](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("KCView");
        execute->set_name("bn_kernel_cache_export_list");
        execute->set_arguments_json(R"({"binaryView":"test","offset":0,"limit":10})");
    }));
    requests.push_back(Command(9, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(10, [](binjad::ipc::Command& command) {
        command.mutable_shutdown();
    }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    auto channel = std::make_unique<QueueChannel>(std::move(requests), responses);
    EXPECT_EQ(binjad::RunFileChild(std::move(channel)), EXIT_SUCCESS);

    std::size_t pluginReplies = 0;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (!envelope.has_reply())
            continue;
        if (envelope.request_id() == 1)
        {
            ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
            bool kernelView = false;
            for (const auto& candidate : envelope.reply().file_opened().candidates())
                kernelView |= candidate.view_type() == "KCView";
            EXPECT_TRUE(kernelView);
        }
        if (envelope.request_id() == 40)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find(
                "unloaded KernelCache image 'com.apple.filesystems.udf'"), std::string::npos)
                << envelope.reply().error();
        }
        if (envelope.request_id() == 42)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find(
                "is not contained in a KernelCache image or loaded mapped range"),
                std::string::npos) << envelope.reply().error();
        }
        if (envelope.request_id() == 41)
        {
            EXPECT_FALSE(envelope.reply().success());
            EXPECT_NE(envelope.reply().error().find(
                "loaded KernelCache image 'com.apple.filesystems.udf' but is not an analyzed function start"),
                std::string::npos) << envelope.reply().error();
        }
        if (envelope.request_id() < 3 || envelope.request_id() > 8)
            continue;
        ASSERT_TRUE(envelope.reply().success()) << envelope.reply().error();
        ASSERT_TRUE(envelope.reply().has_analysis_tool_result());
        const auto& json = envelope.reply().analysis_tool_result().json();
        EXPECT_FALSE(json.empty());
        if (envelope.request_id() == 5)
            EXPECT_NE(json.find("bn_analysis_update_and_wait"), std::string::npos);
        if (envelope.request_id() == 7 ||
            (envelope.request_id() == 8 && image == "com.apple.filesystems.udf"))
        {
            rapidjson::Document document;
            document.Parse(json.data(), json.size());
            ASSERT_FALSE(document.HasParseError());
            EXPECT_GT(document["total"].GetUint64(), 0U) << json;
        }
        ++pluginReplies;
    }
    EXPECT_EQ(pluginReplies, 6U);
}

TEST(FileChildTest, RunsAndQueriesGoogleBinDiffAgainstSecondaryDatabase)
{
    const auto database = std::filesystem::temp_directory_path() /
        ("binjad-diff-secondary-" + std::to_string(getpid()) + ".bndb");
    const auto stagedDatabase = std::filesystem::temp_directory_path() /
        ("binjad-diff-staged-" + std::to_string(getpid()) + ".bndb");
    std::error_code ignored;
    std::filesystem::remove(database, ignored);
    std::filesystem::remove(stagedDatabase, ignored);

    std::deque<std::vector<std::uint8_t>> requests;
    requests.push_back(Command(1, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(BINJAD_ANALYSIS_FIXTURE); open->set_options_json("{}");
    }));
    requests.push_back(Command(2, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O"); open->set_options_json("{}"); open->set_analyze(false);
    }));
    requests.push_back(Command(3, [&](binjad::ipc::Command& command) {
        auto* save = command.mutable_save_binary_view();
        save->set_view_type("Mach-O"); save->set_destination(database.string());
    }));
    requests.push_back(Command(4, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(5, [&](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_file();
        open->set_path(database.string()); open->set_options_json("{}"); open->set_reuse_database(true);
    }));
    requests.push_back(Command(6, [](binjad::ipc::Command& command) {
        auto* open = command.mutable_open_binary_view();
        open->set_view_type("Mach-O"); open->set_options_json("{}"); open->set_analyze(false);
    }));
    requests.push_back(Command(7, [&](binjad::ipc::Command& command) {
        auto* save = command.mutable_save_binary_view();
        save->set_view_type("Mach-O"); save->set_destination(stagedDatabase.string());
        save->set_temporary_copy(true);
    }));
    requests.push_back(Command(8, [&](binjad::ipc::Command& command) {
        auto* execute = command.mutable_execute_analysis_tool();
        execute->set_view_type("Mach-O"); execute->set_name("bn_diff_run");
        execute->set_arguments_json("{}"); execute->set_secondary_path(stagedDatabase.string());
        execute->set_diff_key("test-secondary");
    }));
    for (const auto& [id, name, arguments] : std::vector<std::tuple<std::uint64_t, std::string, std::string>>{
             {9, "bn_diff_summary", "{}"},
             {10, "bn_diff_match_list", R"({"sort":"similarity","order":"ascending","limit":10})"},
             {11, "bn_diff_function_matches", R"({"primaryFunction":"_binjad_fixture_helper"})"},
             {12, "bn_diff_match_info", R"({"primaryFunction":"_binjad_fixture_helper","secondaryFunction":"_binjad_fixture_helper"})"},
             {13, "bn_diff_port_name_from_secondary", R"({"primaryFunction":"_binjad_fixture_helper","secondaryFunction":"_binjad_fixture_helper"})"},
             {14, "bn_diff_apply_from_secondary", R"({"primaryFunction":"_binjad_fixture_helper","secondaryFunction":"_binjad_fixture_helper"})"},
             {15, "bn_diff_port_names_from_secondary", R"({"minSimilarity":255,"minConfidence":0})"},
             {16, "binjad_internal_diff_release", "{}"}})
    {
        requests.push_back(Command(id, [=](binjad::ipc::Command& command) {
            auto* execute = command.mutable_execute_analysis_tool();
            execute->set_view_type("Mach-O"); execute->set_name(name);
            execute->set_arguments_json(arguments); execute->set_diff_key("test-secondary");
        }));
    }
    requests.push_back(Command(17, [](binjad::ipc::Command& command) {
        command.mutable_close_file()->set_discard_uncommitted(true);
    }));
    requests.push_back(Command(18, [](binjad::ipc::Command& command) { command.mutable_shutdown(); }));

    auto responses = std::make_shared<std::vector<std::vector<std::uint8_t>>>();
    const auto exitCode = binjad::RunFileChild(std::make_unique<QueueChannel>(
        std::move(requests), responses, 9));
    std::unordered_map<std::uint64_t, std::string> results;
    std::string failures;
    bool completed = false;
    for (const auto& bytes : *responses)
    {
        const auto envelope = binjad::ipc::ParseEnvelope(bytes);
        if (envelope.has_event() && envelope.event().has_analysis_finished() &&
            envelope.event().originating_request_id() == 8)
            completed = envelope.event().analysis_finished().state() ==
                binjad::ipc::ANALYSIS_STATE_COMPLETE;
        if (envelope.has_reply() && envelope.reply().success() &&
            envelope.reply().has_analysis_tool_result())
            results.emplace(envelope.request_id(), envelope.reply().analysis_tool_result().json());
        if (envelope.has_reply() && !envelope.reply().success())
            failures += std::to_string(envelope.request_id()) + ": " +
                envelope.reply().error() + "\n";
    }
    ASSERT_EQ(exitCode, EXIT_SUCCESS) << failures;
    EXPECT_TRUE(completed);
    EXPECT_NE(results[9].find(R"("provider":"Google BinDiff")"), std::string::npos);
    EXPECT_NE(results[9].find(R"("changedMatches":0)"), std::string::npos);
    EXPECT_NE(results[9].find(R"("similarity":{"minimum":255)"), std::string::npos);
    EXPECT_NE(results[10].find(R"("similarity":255)"), std::string::npos);
    EXPECT_NE(results[11].find("_binjad_fixture_helper"), std::string::npos);
    EXPECT_NE(results[12].find(R"("confidence":)"), std::string::npos);
    EXPECT_NE(results[13].find(R"("applied":true)"), std::string::npos);
    EXPECT_NE(results[14].find(R"("applied":true)"), std::string::npos);
    EXPECT_NE(results[15].find(R"("preserved":)"), std::string::npos);
    EXPECT_EQ(results[16], R"({"released":true})");
    std::filesystem::remove(database, ignored);
    std::filesystem::remove(stagedDatabase, ignored);
}
