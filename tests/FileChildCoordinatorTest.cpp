#include "binjad/ipc/envelope.hpp"
#include "binjad/mcp/foundation.hpp"
#include "binjad/overseer/file_child_coordinator.hpp"
#include "binjad/session/job_registry.hpp"

#include <rapidjsonwrapper.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace
{
class ScriptChannel final : public binjad::ipc::ByteChannel
{
  public:
    explicit ScriptChannel(bool kernelCache = false) : kernelCache_(kernelCache) {}

    void DropNextReply()
    {
        std::lock_guard lock(mutex_);
        dropNextReply_ = true;
        droppedRequest_ = false;
    }

    bool WaitForDroppedRequest(std::chrono::milliseconds timeout)
    {
        std::unique_lock lock(mutex_);
        return ready_.wait_for(lock, timeout, [&] { return droppedRequest_; });
    }

    void SetUpdateDelay(std::chrono::milliseconds delay)
    {
        std::lock_guard lock(mutex_);
        updateDelay_ = delay;
    }

    void SetStalledAnalysis(bool stalled, bool abortStops = true)
    {
        std::lock_guard lock(mutex_);
        stalledAnalysis_ = stalled;
        abortStopsAnalysis_ = abortStops;
    }

    bool WaitForAnalysisRunning(std::chrono::milliseconds timeout)
    {
        std::unique_lock lock(mutex_);
        return ready_.wait_for(lock, timeout, [&] {
            return analysisState_ == binjad::ipc::ANALYSIS_STATE_RUNNING;
        });
    }

    std::size_t AnalysisCommandCount()
    {
        std::lock_guard lock(mutex_);
        return analysisCommandCount_;
    }

    std::string LastOpenOptions()
    {
        std::lock_guard lock(mutex_);
        return lastOpenOptions_;
    }

    std::string LastAnalysisTool()
    {
        std::lock_guard lock(mutex_);
        return lastAnalysisTool_;
    }

    void PushEvent(const binjad::ipc::Event& event)
    {
        binjad::ipc::Envelope envelope;
        envelope.set_protocol_version(binjad::ipc::kProtocolVersion);
        envelope.set_request_id(0);
        *envelope.mutable_event() = event;
        {
            std::lock_guard lock(mutex_);
            responses_.push_back(binjad::ipc::SerializeEnvelope(envelope));
        }
        ready_.notify_one();
    }

    void Send(std::span<const std::uint8_t> payload) override
    {
        const auto request = binjad::ipc::ParseEnvelope(payload);
        bool stalledAnalysis = false;
        std::uint64_t abortedRequest = 0;
        {
            std::lock_guard lock(mutex_);
            if (dropNextReply_)
            {
                dropNextReply_ = false;
                droppedRequest_ = true;
                ready_.notify_all();
                return;
            }
        }
        binjad::ipc::Envelope response;
        response.set_protocol_version(binjad::ipc::kProtocolVersion);
        response.set_request_id(request.request_id());
        auto* reply = response.mutable_reply();
        reply->set_success(true);
        const auto& command = request.command();
        if (command.has_open_file())
        {
            {
                std::lock_guard lock(mutex_);
                lastOpenOptions_ = command.open_file().options_json();
            }
            auto* opened = reply->mutable_file_opened();
            auto* raw = opened->add_candidates();
            raw->set_view_type("Raw");
            auto* executable = opened->add_candidates();
            executable->set_view_type(kernelCache_ ? "KCView" : "Mach-O");
            executable->set_recommended(true);
        }
        else if (command.has_open_binary_view())
        {
            createdViews_.insert(command.open_binary_view().view_type());
            reply->mutable_binary_view_opened()->set_view_type(
                command.open_binary_view().view_type());
        }
        else if (command.has_get_analysis_status())
        {
            auto* status = reply->mutable_analysis_status();
            status->set_has_view(
                createdViews_.contains(command.get_analysis_status().view_type()));
            std::lock_guard lock(mutex_);
            status->set_state(analysisState_);
        }
        else if (command.has_abort_analysis())
        {
            std::lock_guard lock(mutex_);
            if (abortStopsAnalysis_ && analysisState_ == binjad::ipc::ANALYSIS_STATE_RUNNING)
            {
                analysisState_ = binjad::ipc::ANALYSIS_STATE_ABORTED;
                abortedRequest = activeAnalysisRequest_;
            }
        }
        else if (command.has_update_analysis())
        {
            std::lock_guard lock(mutex_);
            analysisState_ = binjad::ipc::ANALYSIS_STATE_RUNNING;
            activeAnalysisRequest_ = request.request_id();
            stalledAnalysis = stalledAnalysis_;
            ready_.notify_all();
        }
        else if (command.has_execute_analysis_tool())
        {
            {
                std::lock_guard lock(mutex_);
                ++analysisCommandCount_;
                lastAnalysisTool_ = command.execute_analysis_tool().name();
            }
            if (command.execute_analysis_tool().name() == "bn_function_info")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","name":"entry","hasUserType":true,"callingConvention":"cdecl","basicBlockCount":1})");
            else if (command.execute_analysis_tool().name() == "bn_function_callers")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"callers":[{"callsite":"0x1200","caller":{"address":"0x1100","name":"caller"}}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_callees")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"callees":[{"callsite":"0x1004","target":"0x2000","functions":[{"address":"0x2000","name":"callee"}]}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_disassembly")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"text":"0x1000  ret","count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_decompile")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"language":"Pseudo C","text":"int32_t entry() { return 0; }","needsUpdate":false,"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_il")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"level":"mlil","ssa":true,"text":"0x1000  return 0","needsUpdate":false,"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_stack_layout")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"variables":[{"offset":-4,"name":"var_4","type":"int32_t"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_variable_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"variables":[{"name":"arg1","type":"int32_t","source":"register","index":0,"storage":0}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_calling_convention_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"current":"cdecl","callingConventions":["cdecl","linux-syscall"]})");
            else if (command.execute_analysis_tool().name() == "bn_function_xrefs_from")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"references":[{"source":"0x1004","target":"0x2000","functions":[{"address":"0x2000","name":"target"}]}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_function_xrefs_to")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"references":[{"source":"0x2004","function":{"address":"0x2000","name":"source"}}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_string_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"strings":[{"address":"0x3000","value":"message"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_string_at")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x3000","encoding":"ascii","byteLength":7,"characterLength":7,"value":"message","offset":0,"count":7,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_symbol_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbols":[{"address":"0x1000","name":"entry","type":"FunctionSymbol"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_symbol_list_at")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbols":[{"address":"0x1000","type":"FunctionSymbol","shortName":"entry","fullName":"entry","rawName":"entry","namespace":["BNINTERNALNAMESPACE"],"ordinal":0,"binding":"NoBinding","autoDefined":false}],"count":1})");
            else if (command.execute_analysis_tool().name() == "bn_import_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbols":[{"address":"0x4000","name":"imported","type":"ImportAddressSymbol"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_export_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbols":[{"address":"0x1000","name":"exported","type":"FunctionSymbol"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_entry_point_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"entryPoints":[{"address":"0x1000","name":"entry"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_entry_point_add")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","platform":"linux-armv7","added":true,"functionPresent":false,"nextAction":"Call bn_function_create at this address, then bn_analysis_update_and_wait and bn_binary_view_save."})");
            else if (command.execute_analysis_tool().name() == "bn_function_create")
                reply->mutable_analysis_tool_result()->set_json(
                    R"json({"address":"0x1000","name":"sub_1000","architecture":"armv7","platform":"linux-armv7","type":"void()","created":true,"autoDiscovered":false,"needsUpdate":true,"nextAction":"Call bn_analysis_update_and_wait, then bn_binary_view_save to persist the user function."})json");
            else if (command.execute_analysis_tool().name() == "bn_section_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"sections":[{"name":".text","start":"0x1000","end":"0x2000","semantics":"ReadOnlyCodeSectionSemantics"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_segment_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"segments":[{"segment":"0x1000","start":"0x1000","end":"0x2000","length":4096,"dataOffset":"0x0","dataLength":4096,"dataEnd":"0x2000","flags":["SegmentReadable","SegmentExecutable"],"readable":true,"writable":false,"executable":true,"containsData":false,"containsCode":true,"denyWrite":false,"denyExecute":false,"autoDefined":true}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_memory_read")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","bytesRead":4,"hex":"01020304"})");
            else if (command.execute_analysis_tool().name() == "bn_data_variable_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"dataVariables":[{"address":"0x3000","type":"int32_t"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_data_at")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x3000","dataVariable":{"type":"int32_t","formatted":"0x1","confidence":255,"autoDiscovered":true},"exactDataVariable":true,"memory":{"bytesRead":4,"hex":"01000000"},"comment":"","symbols":[],"functions":[]})");
            else if (command.execute_analysis_tool().name() == "bn_relocation_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"relocations":[{"address":"0x5000","target":"0x6000","architecture":"arm64","symbol":"0x6000","symbolName":"target","type":1,"nativeType":2,"external":true}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_data_xrefs_from")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"references":[{"target":"0x3000","dataVariable":{"address":"0x3000","type":"int32_t"}}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_data_xrefs_to")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"references":[{"source":"0x4000","dataVariable":{"address":"0x4000","type":"int32_t*"}}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_comment_get")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","text":"reviewed"})");
            else if (command.execute_analysis_tool().name() == "bn_comment_set")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","text":"reviewed","updated":true})");
            else if (command.execute_analysis_tool().name() == "bn_comment_delete")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x1000","deleted":true})");
            else if (command.execute_analysis_tool().name() == "bn_symbol_define")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbol":{"address":"0x3000","type":"DataSymbol","shortName":"named","fullName":"named","rawName":"named","namespace":["custom"],"ordinal":3,"binding":"GlobalBinding","autoDefined":false}})");
            else if (command.execute_analysis_tool().name() == "bn_symbol_rename")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"symbol":{"address":"0x3000","type":"DataSymbol","shortName":"renamed","fullName":"renamed","rawName":"renamed","namespace":["custom"],"ordinal":3,"binding":"GlobalBinding","autoDefined":false}})");
            else if (command.execute_analysis_tool().name() == "bn_symbol_undefine")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x3000","deleted":true})");
            else if (command.execute_analysis_tool().name() == "bn_function_prototype_set")
                reply->mutable_analysis_tool_result()->set_json(
                    R"json({"address":"0x1000","name":"entry","type":"int32_t(int32_t value)","hasUserType":true,"callingConvention":"cdecl","needsUpdate":true,"nextAction":"Call bn_analysis_update_and_wait before readback or dependent variable mutations.","basicBlocks":[]})json");
            else if (command.execute_analysis_tool().name() == "bn_calling_convention_set")
                reply->mutable_analysis_tool_result()->set_json(
                    R"json({"address":"0x1000","name":"entry","type":"int32_t()","hasUserType":true,"callingConvention":"cdecl","basicBlocks":[]})json");
            else if (command.execute_analysis_tool().name() == "bn_variable_rename")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"variable":{"name":"packet","type":"int32_t","source":"stack","index":0,"storage":-8},"needsUpdate":true,"nextAction":"Call bn_analysis_update_and_wait before readback."})");
            else if (command.execute_analysis_tool().name() == "bn_variable_set_type")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"variable":{"name":"packet","type":"uint32_t","source":"stack","index":0,"storage":-8},"needsUpdate":true,"nextAction":"Call bn_analysis_update_and_wait before readback."})");
            else if (command.execute_analysis_tool().name() == "bn_type_list")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"types":[{"name":"packet_header","class":"StructureTypeClass"}],"count":1,"total":1,"nextOffset":null,"truncated":false})");
            else if (command.execute_analysis_tool().name() == "bn_type_info")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_header","id":"type-id","class":"StructureTypeClass","width":8,"alignment":4,"autoDefined":false,"definition":"struct packet_header { int32_t x; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_parse")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"success":true,"errors":"","types":[{"name":"packet_header","class":"StructureTypeClass","definition":"struct packet_header { int32_t x; };"}],"variables":[],"functions":[]})");
            else if (command.execute_analysis_tool().name() == "bn_type_define")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"types":[{"name":"packet_header","id":"type-id","class":"StructureTypeClass","width":4,"alignment":4,"autoDefined":false,"definition":"struct packet_header { int32_t x; };"}]})");
            else if (command.execute_analysis_tool().name() == "bn_type_struct_create")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_header","id":"type-id","class":"StructureTypeClass","width":4,"alignment":4,"autoDefined":false,"definition":"struct packet_header { int32_t x; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_struct_modify")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_header","id":"type-id","class":"StructureTypeClass","width":8,"alignment":4,"autoDefined":false,"definition":"struct packet_header { int32_t x; int32_t y; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_union_create")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_value","id":"type-id","class":"StructureTypeClass","width":4,"alignment":4,"autoDefined":false,"definition":"union packet_value { int32_t i; float f; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_union_modify")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_value","id":"type-id","class":"StructureTypeClass","width":8,"alignment":8,"autoDefined":false,"definition":"union packet_value { int64_t i; double f; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_enum_create")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_kind","id":"type-id","class":"EnumerationTypeClass","width":4,"alignment":4,"autoDefined":false,"definition":"enum packet_kind { PACKET_A = 1, PACKET_B = 2 };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_enum_modify")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"packet_kind","id":"type-id","class":"EnumerationTypeClass","width":4,"alignment":4,"autoDefined":false,"definition":"enum packet_kind { PACKET_A = 1, PACKET_B = 2, PACKET_C = 3 };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_delete")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"type":"packet_header","deleted":true})");
            else if (command.execute_analysis_tool().name() == "bn_type_rename")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"name":"network::packet_header","id":"type-id","class":"StructureTypeClass","width":8,"alignment":4,"autoDefined":false,"definition":"struct packet_header { int32_t x; int32_t y; };"})");
            else if (command.execute_analysis_tool().name() == "bn_type_xrefs_from")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"type":"packet_header","references":[{"name":"socket_address","class":"StructureTypeClass"}],"recursive":false})");
            else if (command.execute_analysis_tool().name() == "bn_type_xrefs_to")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"type":"packet_header","code":[{"address":"0x1000","function":"parse_packet","arch":"arm64"}],"data":[{"address":"0x3000","type":"struct packet_header"}],"types":[{"name":"packet_container","class":"StructureTypeClass"}]})");
            else if (command.execute_analysis_tool().name() == "bn_data_variable_define")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x3000","dataVariable":{"type":"uint32_t","formatted":"0x1","confidence":255,"autoDiscovered":false},"exactDataVariable":true,"memory":{"bytesRead":4,"hex":"01000000"},"comment":"","symbols":[],"functions":[]})");
            else if (command.execute_analysis_tool().name() == "bn_data_variable_undefine")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"address":"0x3000","dataVariable":null,"exactDataVariable":false,"memory":{"bytesRead":4,"hex":"01000000"},"comment":"","symbols":[],"functions":[]})");
            else if (command.execute_analysis_tool().name() == "bn_section_create")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"section":{"name":".custom","start":"0x4000","end":"0x4100","semantics":"ReadWriteDataSectionSemantics"}})");
            else if (command.execute_analysis_tool().name() == "bn_section_delete")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"section":".custom","deleted":true})");
            else if (command.execute_analysis_tool().name() == "bn_section_modify")
                reply->mutable_analysis_tool_result()->set_json(
                    R"({"section":{"name":".renamed","start":"0x4000","end":"0x4200","semantics":"ReadWriteDataSectionSemantics"}})");
            else
                reply->mutable_analysis_tool_result()->set_json(
                    R"json({"functions":[{"address":"0x1000","name":"entry","type":"int32_t()"}],"count":1,"total":1,"nextOffset":null,"truncated":false})json");
        }
        {
            std::lock_guard lock(mutex_);
            responses_.push_back(binjad::ipc::SerializeEnvelope(response));
        }
        ready_.notify_one();
        if (abortedRequest != 0)
        {
            binjad::ipc::Event event;
            event.set_originating_request_id(abortedRequest);
            event.mutable_analysis_finished()->set_state(
                binjad::ipc::ANALYSIS_STATE_ABORTED);
            PushEvent(event);
        }
        if (command.has_update_analysis())
        {
            if (stalledAnalysis)
                return;
            std::chrono::milliseconds delay;
            {
                std::lock_guard lock(mutex_);
                delay = updateDelay_;
            }
            std::this_thread::sleep_for(delay);
            binjad::ipc::Event progress;
            progress.set_originating_request_id(request.request_id());
            progress.mutable_progress()->set_phase("analysis");
            progress.mutable_progress()->set_completed(1);
            progress.mutable_progress()->set_total(2);
            progress.mutable_progress()->set_message("working");
            PushEvent(progress);
            binjad::ipc::Event event;
            event.set_originating_request_id(request.request_id());
            event.mutable_analysis_finished()->set_state(
                binjad::ipc::ANALYSIS_STATE_COMPLETE);
            {
                std::lock_guard lock(mutex_);
                analysisState_ = binjad::ipc::ANALYSIS_STATE_COMPLETE;
            }
            PushEvent(event);
        }
    }

    std::vector<std::uint8_t> Receive() override
    {
        std::unique_lock lock(mutex_);
        ready_.wait(lock, [&] { return closed_ || !responses_.empty(); });
        if (responses_.empty())
            throw binjad::ipc::ChannelError("scripted channel closed");
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

    void Close() override
    {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        ready_.notify_all();
    }

  private:
    std::deque<std::vector<std::uint8_t>> responses_;
    std::mutex mutex_;
    std::condition_variable ready_;
    bool closed_ = false;
    bool dropNextReply_ = false;
    bool droppedRequest_ = false;
    std::chrono::milliseconds updateDelay_{};
    binjad::ipc::AnalysisState analysisState_ = binjad::ipc::ANALYSIS_STATE_IDLE;
    std::uint64_t activeAnalysisRequest_ = 0;
    bool stalledAnalysis_ = false;
    bool abortStopsAnalysis_ = true;
    std::unordered_set<std::string> createdViews_;
    std::size_t analysisCommandCount_ = 0;
    std::string lastOpenOptions_;
    std::string lastAnalysisTool_;
    bool kernelCache_ = false;
};

class FakeSupervisor final : public binjad::ProcessSupervisor
{
  public:
    binjad::ProcessId Spawn(
        const std::filesystem::path& executable, binjad::ProcessRole role) override
    {
        ++spawned;
        lastExecutable = executable;
        lastRole = role;
        return static_cast<binjad::ProcessId>(6 + spawned);
    }
    void Terminate(binjad::ProcessId) override { ++terminated; }
    void SetExitCallback(ExitCallback callback) override { exitCallback = std::move(callback); }
    void PublishExit(const binjad::ChildExit& exit)
    {
        if (exitCallback)
            exitCallback(exit);
    }

    int spawned = 0;
    int terminated = 0;
    std::filesystem::path lastExecutable;
    binjad::ProcessRole lastRole = binjad::ProcessRole::Overseer;
    ExitCallback exitCallback;
};

class FakeAcceptor final : public binjad::ChildChannelAcceptor
{
  public:
    std::unique_ptr<binjad::ipc::ByteChannel> Accept(
        binjad::ProcessId process, binjad::ProcessRole role) override
    {
        acceptedProcess = process;
        acceptedRole = role;
        auto result = std::make_unique<ScriptChannel>(kernelCache);
        channel = result.get();
        return result;
    }

    binjad::ProcessId acceptedProcess = 0;
    binjad::ProcessRole acceptedRole = binjad::ProcessRole::Overseer;
    ScriptChannel* channel = nullptr;
    bool kernelCache = false;
};

#if !defined(_WIN32)
class TemporaryDirectory
{
  public:
    TemporaryDirectory()
        : path(std::filesystem::temp_directory_path() /
            ("binjad-file-coordinator-" + std::to_string(::getpid())))
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        std::filesystem::create_directories(path);
    }
    ~TemporaryDirectory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

binjad::mcp::ValidatedRequest ToolRequest(std::string name, std::string arguments)
{
    binjad::mcp::ValidatedRequest request;
    request.version = binjad::mcp::ProtocolVersion::V2026_07_28;
    request.id = std::uint64_t{1};
    request.method = "tools/call";
    request.name = std::move(name);
    request.paramsJson = "{\"arguments\":" + std::move(arguments) + '}';
    return request;
}

rapidjson::Document ParseResponse(const std::string& response)
{
    rapidjson::Document document;
    document.Parse(response.data(), response.size());
    return document;
}

void ExpectStructuredContentMirrored(const binjad::mcp::FoundationResult& response)
{
    auto document = ParseResponse(response.body);
    ASSERT_FALSE(document.HasParseError());
    const auto& result = document["result"];
    ASSERT_TRUE(result["structuredContent"].IsObject());
    ASSERT_TRUE(result["content"].IsArray());
    ASSERT_EQ(result["content"].Size(), 1U);
    const auto& text = result["content"][0]["text"];
    ASSERT_TRUE(text.IsString());
    rapidjson::Document mirrored;
    mirrored.Parse(text.GetString(), text.GetStringLength());
    ASSERT_FALSE(mirrored.HasParseError());
    EXPECT_EQ(mirrored, result["structuredContent"]);
}
#endif
}

#if !defined(_WIN32)
TEST(FileChildCoordinatorTest, CopiesOpensMaterializesQueriesAndCloses)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    std::promise<std::string> eventCompletion;
    auto eventResult = eventCompletion.get_future();
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items,
        [&](std::string_view openItem, const auto&) {
            eventCompletion.set_value(std::string(openItem));
        });
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};

    const auto opened = coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", source, "{}", false);
    ASSERT_TRUE(opened.value.has_value()) << opened.error;
    ASSERT_EQ(opened.value->binaryViews.size(), 2U);
    EXPECT_EQ(supervisor.spawned, 1);
    EXPECT_EQ(acceptor.acceptedProcess, 7U);
    binjad::ipc::Event event;
    event.set_originating_request_id(42);
    event.mutable_progress()->set_phase("analysis");
    ASSERT_NE(acceptor.channel, nullptr);
    acceptor.channel->PushEvent(event);
    ASSERT_EQ(eventResult.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(eventResult.get(), opened.value->reference);
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());

    const auto view = coordinator.OpenBinaryView(
        principal.id, "AnalysisSession", recommended->reference, "{}", true);
    ASSERT_TRUE(view.value.has_value()) << view.error;
    EXPECT_TRUE(view.value->created);
    const auto status = coordinator.AnalysisStatus(
        principal.id, "AnalysisSession", recommended->reference);
    ASSERT_TRUE(status.value.has_value()) << status.error;
    EXPECT_TRUE(status.value->has_view());
    const auto analysisCommands = acceptor.channel->AnalysisCommandCount();
    const auto foreign = coordinator.ExecuteAnalysisTool(std::string(64, 'f'),
        "AnalysisSession", recommended->reference, "bn_function_list", "{}");
    EXPECT_FALSE(foreign.value);
    const auto wrongSession = coordinator.ExecuteAnalysisTool(principal.id,
        "WrongSession", recommended->reference, "bn_function_list", "{}");
    EXPECT_FALSE(wrongSession.value);
    EXPECT_EQ(acceptor.channel->AnalysisCommandCount(), analysisCommands);
    const auto finished = coordinator.UpdateAnalysisAndWait(
        principal.id, "AnalysisSession", recommended->reference);
    ASSERT_TRUE(finished.value) << finished.error;
    EXPECT_EQ(finished.value->state(), binjad::ipc::ANALYSIS_STATE_COMPLETE);
    EXPECT_TRUE(coordinator.Close(principal.id, opened.value->reference, true).empty());
    EXPECT_EQ(coordinator.Size(), 0U);
    EXPECT_EQ(items.Size(), 0U);
    EXPECT_EQ(supervisor.terminated, 0);
}

TEST(FileChildCoordinatorTest, InjectsAuthorizedSharedCachePrimaryWithoutOverridingCaller)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "dyld_shared_cache_arm64e";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "dyld cache fixture";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};

    const auto opened = coordinator.OpenArbitraryPath(principal, "AnalysisSession",
        source, R"({"loader.dsc.autoLoadPattern":"^$"})", false);
    ASSERT_TRUE(opened.value.has_value()) << opened.error;
    rapidjson::Document injected;
    const auto options = acceptor.channel->LastOpenOptions();
    injected.Parse(options.data(), options.size());
    ASSERT_FALSE(injected.HasParseError());
    ASSERT_TRUE(injected.HasMember("loader.dsc.primaryFilePath"));
    EXPECT_EQ(std::string(injected["loader.dsc.primaryFilePath"].GetString()),
        std::filesystem::canonical(source).string());
    EXPECT_EQ(std::string(injected["loader.dsc.autoLoadPattern"].GetString()), "^$");
    EXPECT_TRUE(coordinator.Close(principal.id, opened.value->reference, true).empty());

    const auto overridden = coordinator.OpenArbitraryPath(principal, "AnalysisSession",
        source, R"({"loader.dsc.primaryFilePath":"/chosen/cache"})", false);
    ASSERT_TRUE(overridden.value.has_value()) << overridden.error;
    rapidjson::Document preserved;
    const auto overriddenOptions = acceptor.channel->LastOpenOptions();
    preserved.Parse(overriddenOptions.data(), overriddenOptions.size());
    ASSERT_FALSE(preserved.HasParseError());
    EXPECT_EQ(std::string(preserved["loader.dsc.primaryFilePath"].GetString()),
        "/chosen/cache");
    EXPECT_TRUE(coordinator.Close(principal.id, overridden.value->reference, true).empty());
}

TEST(FileChildCoordinatorTest, CooperativelyAbortsActiveAnalysisWithinGracePeriod)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    config.jobs.cancellationGrace = std::chrono::seconds(1);
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto opened = coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", source, "{}", false);
    ASSERT_TRUE(opened.value) << opened.error;
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());
    ASSERT_TRUE(coordinator.OpenBinaryView(principal.id, "AnalysisSession",
        recommended->reference, "{}", false).value);
    acceptor.channel->SetStalledAnalysis(true, true);

    auto analysis = std::async(std::launch::async, [&] {
        return coordinator.UpdateAnalysisAndWait(
            principal.id, "AnalysisSession", recommended->reference);
    });
    ASSERT_TRUE(acceptor.channel->WaitForAnalysisRunning(std::chrono::seconds(1)));
    EXPECT_TRUE(coordinator.AbortAnalysis(
        principal.id, "AnalysisSession", recommended->reference).empty());
    ASSERT_EQ(analysis.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto finished = analysis.get();
    ASSERT_TRUE(finished.value) << finished.error;
    EXPECT_EQ(finished.value->state(), binjad::ipc::ANALYSIS_STATE_ABORTED);
    EXPECT_EQ(supervisor.terminated, 0);
}

TEST(FileChildCoordinatorTest, ForcesAndLazilyRecoversUnresponsiveAnalysis)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    config.jobs.cancellationGrace = std::chrono::seconds::zero();
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto opened = coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", source, "{}", false);
    ASSERT_TRUE(opened.value) << opened.error;
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());
    ASSERT_TRUE(coordinator.OpenBinaryView(principal.id, "AnalysisSession",
        recommended->reference, "{}", false).value);
    acceptor.channel->SetStalledAnalysis(true, false);

    auto analysis = std::async(std::launch::async, [&] {
        return coordinator.UpdateAnalysisAndWait(
            principal.id, "AnalysisSession", recommended->reference);
    });
    ASSERT_TRUE(acceptor.channel->WaitForAnalysisRunning(std::chrono::seconds(1)));
    EXPECT_TRUE(coordinator.AbortAnalysis(
        principal.id, "AnalysisSession", recommended->reference).empty());
    ASSERT_EQ(analysis.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_FALSE(analysis.get().value);
    EXPECT_GE(supervisor.terminated, 1);

    const auto recovered = coordinator.AnalysisStatus(
        principal.id, "AnalysisSession", recommended->reference);
    ASSERT_TRUE(recovered.value) << recovered.error;
    EXPECT_TRUE(recovered.value->has_view());
    EXPECT_EQ(supervisor.spawned, 2);
}

TEST(FileChildCoordinatorTest, RejectsDisabledAndNonAdminArbitraryPathsBeforeSpawn)
{
    TemporaryDirectory temporary;
    binjad::Config config;
    config.projects.allowArbitraryPaths = false;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    binjad::security::TokenRecord principal;
    principal.role = binjad::security::TokenRole::Admin;
    EXPECT_FALSE(coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", temporary.path / "missing").value);
    EXPECT_EQ(supervisor.spawned, 0);
}

TEST(FileChildCoordinatorTest, RoutesGenericKernelCacheEntryAndExportTools)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "kernelcache";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "kernel cache fixture";
    }
    binjad::Config config;
    config.tools.kernelCache = true;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    acceptor.kernelCache = true;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    binjad::mcp::Foundation foundation(
        config, sessions, "0.1.0", &items, &coordinator);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto current = sessions.Create(principal.id, 1,
        binjad::session::AnalysisSessionRegistry::Clock::time_point{});
    ASSERT_TRUE(current.session);
    const auto opened = coordinator.OpenArbitraryPath(principal,
        current.session->reference, source, "{}", false);
    ASSERT_TRUE(opened.value) << opened.error;
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());
    ASSERT_EQ(recommended->viewType, "KCView");
    ASSERT_TRUE(coordinator.OpenBinaryView(principal.id, current.session->reference,
        recommended->reference, "{}", false).value);

    const auto exports = foundation.Handle(ToolRequest("bn_export_list",
        "{\"binaryView\":\"" + recommended->reference + "\",\"limit\":5}"),
        principal, current.session, {}, 1);
    EXPECT_FALSE(exports.error.has_value());
    EXPECT_EQ(acceptor.channel->LastAnalysisTool(), "bn_kernel_cache_export_list");
    const auto entries = foundation.Handle(ToolRequest("bn_entry_point_list",
        "{\"binaryView\":\"" + recommended->reference + "\",\"limit\":5}"),
        principal, current.session, {}, 1);
    EXPECT_FALSE(entries.error.has_value());
    EXPECT_EQ(acceptor.channel->LastAnalysisTool(), "bn_kernel_cache_entry_point_list");
    EXPECT_TRUE(coordinator.Close(principal.id, opened.value->reference, true).empty());
}

TEST(FileChildCoordinatorTest, FoundationToolsDriveExplicitOpenAndViewFlow)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    config.jobs.cancellationGrace = std::chrono::seconds::zero();
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    binjad::session::JobRegistry jobs(references, sessions);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    binjad::mcp::Foundation foundation(
        config, sessions, "0.1.0", &items, &coordinator, &jobs);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto current = sessions.Create(principal.id, 1,
        binjad::session::AnalysisSessionRegistry::Clock::time_point{});
    ASSERT_TRUE(current.session);

    const auto currentInfo = foundation.Handle(ToolRequest("bn_analysis_session_info", "{}"),
        principal, current.session, {}, 1);
    EXPECT_NE(currentInfo.body.find(current.session->reference), std::string::npos);

    const auto opened = foundation.Handle(ToolRequest("bn_open_item_open",
        std::string("{\"path\":\"") + source.string() + "\",\"reuseDatabase\":false}"),
        principal, current.session, {}, 1);
    ASSERT_FALSE(opened.error.has_value());
    auto openedJson = ParseResponse(opened.body);
    ASSERT_FALSE(openedJson.HasParseError());
    const auto& structured = openedJson["result"]["structuredContent"];
    ASSERT_TRUE(structured.HasMember("nextAction"));
    EXPECT_NE(std::string_view(structured["nextAction"].GetString()).find(
        "bn_binary_view_open"), std::string_view::npos);
    const std::string openItem = structured["openItem"].GetString();
    std::string binaryView;
    for (const auto& candidate : structured["binaryViews"].GetArray())
    {
        if (candidate["recommended"].GetBool())
            binaryView = candidate["binaryView"].GetString();
    }
    ASSERT_FALSE(binaryView.empty());

    const auto materialized = foundation.Handle(ToolRequest("bn_binary_view_open",
        "{\"binaryView\":\"" + binaryView + "\",\"analyze\":false}"),
        principal, current.session, {}, 1);
    EXPECT_NE(materialized.body.find(R"("created":true)"), std::string::npos);
    const auto status = foundation.Handle(ToolRequest("bn_analysis_status",
        "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(status.body.find(R"("hasView":true)"), std::string::npos);
    const std::string diffPair = "{\"primary\":\"" + binaryView +
        "\",\"secondary\":\"" + binaryView + "\"";
    for (const auto& [name, fields] : std::vector<std::pair<std::string, std::string>>{
             {"bn_diff_summary", ""},
             {"bn_diff_match_list", R"(,"query":"entry","minSimilarity":1,"minConfidence":2,"sort":"similarity","order":"ascending","offset":0,"limit":10)"},
             {"bn_diff_primary_unmatched_list", R"(,"query":"entry","sort":"name","order":"descending","offset":0,"limit":10)"},
             {"bn_diff_secondary_unmatched_list", R"(,"sort":"address","order":"ascending","offset":0,"limit":10)"},
             {"bn_diff_function_matches", R"(,"primaryFunction":"0x1000")"},
             {"bn_diff_match_info", R"(,"primaryFunction":"0x1000","secondaryFunction":"0x1000")"},
             {"bn_diff_port_name_from_secondary", R"(,"primaryFunction":"0x1000","secondaryFunction":"0x1000")"},
             {"bn_diff_apply_from_secondary", R"(,"primaryFunction":"0x1000","secondaryFunction":"0x1000")"},
             {"bn_diff_port_names_from_secondary", R"(,"minSimilarity":200,"minConfidence":150)"}})
    {
        const auto response = foundation.Handle(ToolRequest(name, diffPair + fields + '}'),
            principal, current.session, {}, 1);
        EXPECT_FALSE(response.error.has_value()) << name << ": " <<
            (response.error ? response.error->message : std::string{});
        EXPECT_EQ(acceptor.channel->LastAnalysisTool(), name);
    }
    const auto functions = foundation.Handle(ToolRequest("bn_function_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(functions.body.find(R"("name":"entry")"), std::string::npos);
    const auto functionInfo = foundation.Handle(ToolRequest("bn_function_info",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(functionInfo.body.find(R"("basicBlockCount":1)"), std::string::npos);
    EXPECT_NE(functionInfo.body.find(R"("callingConvention":"cdecl")"), std::string::npos);
    const auto callers = foundation.Handle(ToolRequest("bn_function_callers",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(callers.body.find(R"("callsite":"0x1200")"), std::string::npos);
    const auto callees = foundation.Handle(ToolRequest("bn_function_callees",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(callees.body.find(R"("name":"callee")"), std::string::npos);
    const auto disassembly = foundation.Handle(ToolRequest("bn_function_disassembly",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(disassembly.body.find(R"(0x1000  ret)"), std::string::npos);
    const auto decompile = foundation.Handle(ToolRequest("bn_function_decompile",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(decompile.body.find(R"("language":"Pseudo C")"), std::string::npos);
    const auto il = foundation.Handle(ToolRequest("bn_function_il",
        "{\"binaryView\":\"" + binaryView +
            "\",\"function\":\"0x1000\",\"level\":\"mlil\",\"ssa\":true}"),
        principal, current.session, {}, 1);
    EXPECT_NE(il.body.find(R"("level":"mlil")"), std::string::npos);
    const auto stack = foundation.Handle(ToolRequest("bn_function_stack_layout",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(stack.body.find(R"("name":"var_4")"), std::string::npos);
    const auto variables = foundation.Handle(ToolRequest("bn_variable_list",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(variables.body.find(R"("source":"register")"), std::string::npos);
    const auto conventions = foundation.Handle(ToolRequest("bn_calling_convention_list",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(conventions.body.find(R"("current":"cdecl")"), std::string::npos);
    const auto xrefsFrom = foundation.Handle(ToolRequest("bn_function_xrefs_from",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(xrefsFrom.body.find(R"("target":"0x2000")"), std::string::npos);
    const auto xrefsTo = foundation.Handle(ToolRequest("bn_function_xrefs_to",
        "{\"binaryView\":\"" + binaryView + "\",\"function\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(xrefsTo.body.find(R"("source":"0x2004")"), std::string::npos);
    const auto strings = foundation.Handle(ToolRequest("bn_string_list",
        "{\"binaryView\":\"" + binaryView + "\",\"query\":\"message\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(strings.body.find(R"("value":"message")"), std::string::npos);
    const auto stringAt = foundation.Handle(ToolRequest("bn_string_at",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x3000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(stringAt.body.find(R"("encoding":"ascii")"), std::string::npos);
    const auto symbols = foundation.Handle(ToolRequest("bn_symbol_list",
        "{\"binaryView\":\"" + binaryView + "\",\"query\":\"entry\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(symbols.body.find(R"("type":"FunctionSymbol")"), std::string::npos);
    const auto symbolsAt = foundation.Handle(ToolRequest("bn_symbol_list_at",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(symbolsAt.body.find(R"("binding":"NoBinding")"), std::string::npos);
    const auto imports = foundation.Handle(ToolRequest("bn_import_list",
        "{\"binaryView\":\"" + binaryView + "\",\"query\":\"imported\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(imports.body.find(R"("type":"ImportAddressSymbol")"), std::string::npos);
    const auto exports = foundation.Handle(ToolRequest("bn_export_list",
        "{\"binaryView\":\"" + binaryView + "\",\"query\":\"exported\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(exports.body.find(R"("type":"FunctionSymbol")"), std::string::npos);
    const auto entryPoints = foundation.Handle(ToolRequest("bn_entry_point_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(entryPoints.body.find(R"("name":"entry")"), std::string::npos);
    const auto sections = foundation.Handle(ToolRequest("bn_section_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(sections.body.find("ReadOnlyCodeSectionSemantics"), std::string::npos);
    const auto segments = foundation.Handle(ToolRequest("bn_segment_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(segments.body.find(R"("containsCode":true)"), std::string::npos);
    const auto memory = foundation.Handle(ToolRequest("bn_memory_read",
        "{\"binaryView\":\"" + binaryView +
            "\",\"address\":\"0x1000\",\"length\":4}"),
        principal, current.session, {}, 1);
    EXPECT_NE(memory.body.find(R"("hex":"01020304")"), std::string::npos);
    const auto dataVariables = foundation.Handle(ToolRequest("bn_data_variable_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(dataVariables.body.find(R"("type":"int32_t")"), std::string::npos);
    const auto dataAt = foundation.Handle(ToolRequest("bn_data_at",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x3000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(dataAt.body.find(R"("exactDataVariable":true)"), std::string::npos);
    const auto relocations = foundation.Handle(ToolRequest("bn_relocation_list",
        "{\"binaryView\":\"" + binaryView + "\",\"limit\":10}"),
        principal, current.session, {}, 1);
    EXPECT_NE(relocations.body.find(R"("nativeType":2)"), std::string::npos);
    const auto dataXrefs = foundation.Handle(ToolRequest("bn_data_xrefs_from",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x2000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(dataXrefs.body.find(R"("target":"0x3000")"), std::string::npos);
    const auto dataXrefsTo = foundation.Handle(ToolRequest("bn_data_xrefs_to",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x3000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(dataXrefsTo.body.find(R"("source":"0x4000")"), std::string::npos);
    const auto comment = foundation.Handle(ToolRequest("bn_comment_get",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(comment.body.find(R"("text":"reviewed")"), std::string::npos);
    const auto setComment = foundation.Handle(ToolRequest("bn_comment_set",
        "{\"binaryView\":\"" + binaryView +
            "\",\"address\":\"0x1000\",\"text\":\"reviewed\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(setComment.body.find(R"("updated":true)"), std::string::npos);
    const auto deleteComment = foundation.Handle(ToolRequest("bn_comment_delete",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(deleteComment.body.find(R"("deleted":true)"), std::string::npos);
    const auto addEntry = foundation.Handle(ToolRequest("bn_entry_point_add",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(addEntry.body.find(R"("added":true)"), std::string::npos);
    EXPECT_NE(addEntry.body.find("bn_function_create"), std::string::npos);
    const auto createFunction = foundation.Handle(ToolRequest("bn_function_create",
        "{\"binaryView\":\"" + binaryView + "\",\"address\":\"0x1000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createFunction.body.find(R"("created":true)"), std::string::npos);
    EXPECT_NE(createFunction.body.find("bn_binary_view_save"), std::string::npos);
    const auto defineSymbol = foundation.Handle(ToolRequest("bn_symbol_define",
        "{\"binaryView\":\"" + binaryView +
            "\",\"address\":\"0x3000\",\"name\":\"named\",\"type\":\"DataSymbol\",\"binding\":\"GlobalBinding\",\"namespace\":\"custom\",\"ordinal\":3}"),
        principal, current.session, {}, 1);
    EXPECT_NE(defineSymbol.body.find(R"("binding":"GlobalBinding")"), std::string::npos);
    const auto renameSymbol = foundation.Handle(ToolRequest("bn_symbol_rename",
        "{\"binaryView\":\"" + binaryView +
            "\",\"address\":\"0x3000\",\"name\":\"named\",\"newName\":\"renamed\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(renameSymbol.body.find(R"("fullName":"renamed")"), std::string::npos);
    const auto undefineSymbol = foundation.Handle(ToolRequest("bn_symbol_undefine",
        "{\"binaryView\":\"" + binaryView +
            "\",\"address\":\"0x3000\",\"name\":\"renamed\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(undefineSymbol.body.find(R"("deleted":true)"), std::string::npos);
    const auto setPrototype = foundation.Handle(ToolRequest("bn_function_prototype_set",
        "{\"binaryView\":\"" + binaryView +
            "\",\"function\":\"0x1000\",\"prototype\":\"int32_t entry(int32_t value)\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(setPrototype.body.find(R"("hasUserType":true)"), std::string::npos);
    EXPECT_NE(setPrototype.body.find("bn_analysis_update_and_wait"), std::string::npos);
    const auto setConvention = foundation.Handle(ToolRequest("bn_calling_convention_set",
        "{\"binaryView\":\"" + binaryView +
            "\",\"function\":\"0x1000\",\"callingConvention\":\"cdecl\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(setConvention.body.find(R"("callingConvention":"cdecl")"), std::string::npos);
    const auto renameVariable = foundation.Handle(ToolRequest("bn_variable_rename",
        "{\"binaryView\":\"" + binaryView +
            "\",\"function\":\"0x1000\",\"variable\":\"var_8\",\"source\":\"stack\",\"index\":0,\"storage\":-8,\"newName\":\"packet\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(renameVariable.body.find(R"("name":"packet")"), std::string::npos);
    EXPECT_NE(renameVariable.body.find("bn_analysis_update_and_wait"), std::string::npos);
    const auto setVariableType = foundation.Handle(ToolRequest("bn_variable_set_type",
        "{\"binaryView\":\"" + binaryView +
            "\",\"function\":\"0x1000\",\"variable\":\"packet\",\"variableSource\":\"stack\",\"index\":0,\"storage\":-8,\"definition\":\"uint32_t\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(setVariableType.body.find(R"("type":"uint32_t")"), std::string::npos);
    EXPECT_NE(setVariableType.body.find("bn_analysis_update_and_wait"), std::string::npos);
    const auto types = foundation.Handle(ToolRequest("bn_type_list",
        "{\"binaryView\":\"" + binaryView + "\",\"query\":\"packet\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(types.body.find(R"("class":"StructureTypeClass")"), std::string::npos);
    const auto typeInfo = foundation.Handle(ToolRequest("bn_type_info",
        "{\"binaryView\":\"" + binaryView + "\",\"type\":\"packet_header\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(typeInfo.body.find("struct packet_header"), std::string::npos);
    const auto parsedTypes = foundation.Handle(ToolRequest("bn_type_parse",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"struct packet_header { int x; };\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(parsedTypes.body.find(R"("success":true)"), std::string::npos);
    const auto definedTypes = foundation.Handle(ToolRequest("bn_type_define",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"struct packet_header { int x; };\",\"types\":[\"packet_header\"]}"),
        principal, current.session, {}, 1);
    EXPECT_NE(definedTypes.body.find(R"("autoDefined":false)"), std::string::npos);
    const auto createdStruct = foundation.Handle(ToolRequest("bn_type_struct_create",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"struct packet_header { int x; };\",\"type\":\"packet_header\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createdStruct.body.find(R"("class":"StructureTypeClass")"), std::string::npos);
    const auto modifiedStruct = foundation.Handle(ToolRequest("bn_type_struct_modify",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"struct packet_header { int x; int y; };\",\"type\":\"packet_header\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(modifiedStruct.body.find(R"("width":8)"), std::string::npos);
    const auto createdUnion = foundation.Handle(ToolRequest("bn_type_union_create",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"union packet_value { int i; float f; };\",\"type\":\"packet_value\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createdUnion.body.find("union packet_value"), std::string::npos);
    const auto modifiedUnion = foundation.Handle(ToolRequest("bn_type_union_modify",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"union packet_value { long long i; double f; };\",\"type\":\"packet_value\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(modifiedUnion.body.find(R"("width":8)"), std::string::npos);
    const auto createdEnum = foundation.Handle(ToolRequest("bn_type_enum_create",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"enum packet_kind { PACKET_A = 1, PACKET_B = 2 };\",\"type\":\"packet_kind\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createdEnum.body.find("PACKET_B"), std::string::npos);
    const auto modifiedEnum = foundation.Handle(ToolRequest("bn_type_enum_modify",
        "{\"binaryView\":\"" + binaryView +
            "\",\"source\":\"enum packet_kind { PACKET_A = 1, PACKET_B = 2, PACKET_C = 3 };\",\"type\":\"packet_kind\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(modifiedEnum.body.find("PACKET_C"), std::string::npos);
    const auto deletedType = foundation.Handle(ToolRequest("bn_type_delete",
        "{\"binaryView\":\"" + binaryView + "\",\"type\":\"packet_header\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(deletedType.body.find(R"("deleted":true)"), std::string::npos);
    const auto renamedType = foundation.Handle(ToolRequest("bn_type_rename",
        "{\"binaryView\":\"" + binaryView +
            "\",\"type\":\"packet_header\",\"newType\":\"network::packet_header\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(renamedType.body.find("network::packet_header"), std::string::npos);
    const auto typeXrefs = foundation.Handle(ToolRequest("bn_type_xrefs_from",
        "{\"binaryView\":\"" + binaryView +
            "\",\"type\":\"packet_header\",\"recursive\":false}"),
        principal, current.session, {}, 1);
    EXPECT_NE(typeXrefs.body.find("socket_address"), std::string::npos);
    const auto incomingTypeXrefs = foundation.Handle(ToolRequest("bn_type_xrefs_to",
        "{\"binaryView\":\"" + binaryView +
            "\",\"type\":\"packet_header\",\"maxItems\":100}"),
        principal, current.session, {}, 1);
    EXPECT_NE(incomingTypeXrefs.body.find("packet_container"), std::string::npos);
    const auto defineDataVariable = foundation.Handle(ToolRequest("bn_data_variable_define",
        "{\"binaryView\":\"" + binaryView +
            "\",\"datavar\":\"0x3000\",\"definition\":\"uint32_t\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(defineDataVariable.body.find(R"("type":"uint32_t")"), std::string::npos);
    const auto undefineDataVariable = foundation.Handle(ToolRequest("bn_data_variable_undefine",
        "{\"binaryView\":\"" + binaryView + "\",\"datavar\":\"0x3000\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(undefineDataVariable.body.find(R"("dataVariable":null)"), std::string::npos);
    const auto createSection = foundation.Handle(ToolRequest("bn_section_create",
        "{\"binaryView\":\"" + binaryView +
            "\",\"section\":\".custom\",\"start\":\"0x4000\",\"length\":256,\"semantics\":\"ReadWriteDataSectionSemantics\",\"alignment\":16}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createSection.body.find(R"("name":".custom")"), std::string::npos);
    const auto deleteSection = foundation.Handle(ToolRequest("bn_section_delete",
        "{\"binaryView\":\"" + binaryView + "\",\"section\":\".custom\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(deleteSection.body.find(R"("deleted":true)"), std::string::npos);
    const auto modifySection = foundation.Handle(ToolRequest("bn_section_modify",
        "{\"binaryView\":\"" + binaryView +
            "\",\"section\":\".custom\",\"newSection\":\".renamed\",\"length\":512}"),
        principal, current.session, {}, 1);
    EXPECT_NE(modifySection.body.find(R"("name":".renamed")"), std::string::npos);
    for (const auto* response : {&functions, &functionInfo, &callers, &callees,
            &disassembly, &decompile, &il, &stack, &variables, &conventions,
            &xrefsFrom, &xrefsTo, &strings, &stringAt, &symbols, &symbolsAt, &imports,
            &exports, &entryPoints, &sections, &segments, &memory, &dataVariables, &dataAt,
            &relocations, &dataXrefs, &dataXrefsTo, &comment, &setComment, &deleteComment,
            &defineSymbol, &renameSymbol, &undefineSymbol, &setPrototype, &setConvention,
            &renameVariable, &setVariableType, &types, &typeInfo, &parsedTypes, &definedTypes,
            &createdStruct, &modifiedStruct, &createdUnion, &modifiedUnion, &createdEnum,
            &modifiedEnum, &deletedType, &renamedType, &typeXrefs, &incomingTypeXrefs,
            &defineDataVariable, &undefineDataVariable, &createSection, &deleteSection,
            &modifySection})
        ExpectStructuredContentMirrored(*response);
    const auto commandCount = acceptor.channel->AnalysisCommandCount();
    const auto expectInvalid = [&](std::string name, std::string arguments) {
        const auto response = foundation.Handle(ToolRequest(
            std::move(name), std::move(arguments)), principal, current.session, {}, 1);
        ASSERT_TRUE(response.error.has_value());
        EXPECT_EQ(response.error->code, -32602);
        EXPECT_EQ(response.error->httpStatus, 400);
    };
    expectInvalid("bn_function_list", "{\"binaryView\":\"" + binaryView +
        "\",\"address\":\"0x1000\",\"start\":\"0x1000\"}");
    expectInvalid("bn_function_list", "{\"binaryView\":\"" + binaryView +
        "\",\"limit\":0}");
    expectInvalid("bn_function_info", "{\"binaryView\":\"" + binaryView +
        "\",\"function\":\"0x1000\",\"arch\":\"\"}");
    expectInvalid("bn_function_decompile", "{\"binaryView\":\"" + binaryView +
        "\",\"function\":\"0x1000\",\"language\":\"\"}");
    expectInvalid("bn_function_il", "{\"binaryView\":\"" + binaryView +
        "\",\"function\":\"0x1000\",\"level\":\"lifted\"}");
    expectInvalid("bn_function_il", "{\"binaryView\":\"" + binaryView +
        "\",\"function\":\"0x1000\",\"form\":\"tokens\"}");
    expectInvalid("bn_function_callers", "{\"binaryView\":\"" + binaryView +
        "\",\"function\":\"0x1000\",\"offset\":-1}");
    expectInvalid("bn_string_list", "{\"binaryView\":\"" + binaryView +
        "\",\"previewBytes\":64}");
    expectInvalid("bn_string_list", "{\"binaryView\":\"" + binaryView +
        "\",\"end\":\"0x4000\"}");
    expectInvalid("bn_string_at", "{\"binaryView\":\"" + binaryView + "\"}");
    expectInvalid("bn_string_at", "{\"binaryView\":\"" + binaryView +
        "\",\"address\":\"0x3000\",\"limit\":65537}");
    expectInvalid("bn_symbol_list", "{\"binaryView\":\"" + binaryView +
        "\",\"length\":16}");
    expectInvalid("bn_symbol_list_at", "{\"binaryView\":\"" + binaryView + "\"}");
    EXPECT_EQ(acceptor.channel->AnalysisCommandCount(), commandCount);
    const auto waited = foundation.Handle(ToolRequest("bn_analysis_update_and_wait",
        "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(waited.body.find(R"("state":"complete")"), std::string::npos);

    auto immediateDetachConfig = config;
    immediateDetachConfig.jobs.detachAfter = std::chrono::seconds::zero();
    binjad::mcp::Foundation immediateDetach(immediateDetachConfig,
        sessions, "0.1.0", &items, &coordinator, &jobs);
    acceptor.channel->SetUpdateDelay(std::chrono::milliseconds(20));
    std::string attachedJob;
    std::vector<binjad::session::JobRecord> progress;
    std::mutex progressMutex;
    const auto automaticallyDetached = immediateDetach.Handle(
        ToolRequest("bn_analysis_update_and_wait",
            "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1,
        [&](const auto& record) {
            std::lock_guard lock(progressMutex);
            progress.push_back(record);
        },
        [&](std::string_view job, auto) { attachedJob = job; });
    EXPECT_NE(automaticallyDetached.body.find(R"("state":"running")"),
        std::string::npos);
    EXPECT_FALSE(attachedJob.empty());
    {
        std::lock_guard lock(progressMutex);
        ASSERT_FALSE(progress.empty());
        EXPECT_EQ(progress.front().reference, attachedJob);
    }
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        const auto info = jobs.Info(principal.id, attachedJob);
        ASSERT_TRUE(info.job);
        if (info.job->state == binjad::session::JobState::Complete)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto automaticResult = immediateDetach.Handle(ToolRequest("bn_job_result",
        "{\"job\":\"" + attachedJob + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(automaticResult.body.find(R"("state":"complete")"), std::string::npos);
    acceptor.channel->SetUpdateDelay({});

    const auto detached = foundation.Handle(ToolRequest("bn_analysis_update_async",
        "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    auto detachedJson = ParseResponse(detached.body);
    ASSERT_FALSE(detachedJson.HasParseError());
    const std::string job = detachedJson["result"]["structuredContent"]["job"].GetString();
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        const auto info = jobs.Info(principal.id, job);
        if (info.job && info.job->state != binjad::session::JobState::Queued &&
            info.job->state != binjad::session::JobState::Running)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto jobInfo = jobs.Info(principal.id, job);
    ASSERT_TRUE(jobInfo.job && jobInfo.job->progress);
    EXPECT_EQ(jobInfo.job->progress->phase, "analysis");
    EXPECT_EQ(jobInfo.job->progress->message, "working");
    const auto result = foundation.Handle(ToolRequest("bn_job_result",
        "{\"job\":\"" + job + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(result.body.find(R"("state":"complete")"), std::string::npos);
    EXPECT_EQ(jobs.Size(), 0U);

    auto cancellationConfig = config;
    cancellationConfig.jobs.cancellationGrace = std::chrono::seconds::zero();
    binjad::mcp::Foundation cancellationFoundation(cancellationConfig,
        sessions, "0.1.0", &items, &coordinator, &jobs);
    acceptor.channel->SetStalledAnalysis(true, false);
    const auto cancellable = cancellationFoundation.Handle(
        ToolRequest("bn_analysis_update_async",
            "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    auto cancellableJson = ParseResponse(cancellable.body);
    ASSERT_FALSE(cancellableJson.HasParseError());
    const std::string cancellableJob =
        cancellableJson["result"]["structuredContent"]["job"].GetString();
    ASSERT_TRUE(acceptor.channel->WaitForAnalysisRunning(std::chrono::seconds(1)));
    const auto cancelled = cancellationFoundation.Handle(ToolRequest("bn_job_cancel",
        "{\"job\":\"" + cancellableJob + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(cancelled.body.find(R"("cancelRequested":true)"), std::string::npos);
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        const auto info = jobs.Info(principal.id, cancellableJob);
        if (info.job && info.job->state == binjad::session::JobState::Cancelled)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto cancelledInfo = jobs.Info(principal.id, cancellableJob);
    ASSERT_TRUE(cancelledInfo.job);
    EXPECT_EQ(cancelledInfo.job->state, binjad::session::JobState::Cancelled);
    const auto cancelledResult = cancellationFoundation.Handle(
        ToolRequest("bn_job_result", "{\"job\":\"" + cancellableJob + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(cancelledResult.body.find("job cancelled"), std::string::npos);
    const auto recoveredStatus = cancellationFoundation.Handle(
        ToolRequest("bn_analysis_status",
            "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(recoveredStatus.body.find(R"("hasView":true)"), std::string::npos);

    const auto closed = foundation.Handle(ToolRequest("bn_open_item_close",
        "{\"openItem\":\"" + openItem + "\",\"save\":\"discard\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(closed.body.find(R"("closed":true)"), std::string::npos);
    EXPECT_EQ(coordinator.Size(), 0U);
}

TEST(FileChildCoordinatorTest, IdleCrashReopensViewsAndReportsOneRetryError)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto opened = coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", source, "{}", false);
    ASSERT_TRUE(opened.value);
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());
    ASSERT_TRUE(coordinator.OpenBinaryView(
        principal.id, "AnalysisSession", recommended->reference, "{}", false).value);

    binjad::ChildExit exit;
    exit.processId = 7;
    exit.role = binjad::ProcessRole::FileChild;
    exit.signal = 9;
    supervisor.PublishExit(exit);
    const auto firstStatus = coordinator.AnalysisStatus(
        principal.id, "AnalysisSession", recommended->reference);
    EXPECT_FALSE(firstStatus.value);
    EXPECT_NE(firstStatus.error.find("reopened, retry"), std::string::npos);
    EXPECT_EQ(supervisor.spawned, 2);
    EXPECT_EQ(acceptor.acceptedProcess, 8U);
    const auto secondStatus = coordinator.AnalysisStatus(
        principal.id, "AnalysisSession", recommended->reference);
    ASSERT_TRUE(secondStatus.value) << secondStatus.error;
    EXPECT_TRUE(secondStatus.value->has_view());
    const auto functions = coordinator.ExecuteAnalysisTool(principal.id,
        "AnalysisSession", recommended->reference, "bn_function_list", "{}");
    ASSERT_TRUE(functions.value) << functions.error;
    EXPECT_NE(functions.value->find(R"("functions")"), std::string::npos);
    EXPECT_TRUE(coordinator.Close(principal.id, opened.value->reference, true).empty());
}

TEST(FileChildCoordinatorTest, InFlightCrashFailsRequestThenRecoversTransparently)
{
    TemporaryDirectory temporary;
    const auto source = temporary.path / "input.bin";
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "test input";
    }
    binjad::Config config;
    config.storage.spoolPath = temporary.path / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry items(references);
    binjad::overseer::FileChildCoordinator coordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, items);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto opened = coordinator.OpenArbitraryPath(
        principal, "AnalysisSession", source, "{}", false);
    ASSERT_TRUE(opened.value);
    const auto recommended = std::find_if(opened.value->binaryViews.begin(),
        opened.value->binaryViews.end(), [](const auto& view) { return view.recommended; });
    ASSERT_NE(recommended, opened.value->binaryViews.end());
    ASSERT_TRUE(coordinator.OpenBinaryView(
        principal.id, "AnalysisSession", recommended->reference, "{}", false).value);

    ASSERT_NE(acceptor.channel, nullptr);
    acceptor.channel->DropNextReply();
    auto interrupted = std::async(std::launch::async, [&] {
        return coordinator.AnalysisStatus(
            principal.id, "AnalysisSession", recommended->reference);
    });
    ASSERT_TRUE(acceptor.channel->WaitForDroppedRequest(std::chrono::seconds(1)));
    binjad::ChildExit exit;
    exit.processId = 7;
    exit.role = binjad::ProcessRole::FileChild;
    exit.signal = 9;
    supervisor.PublishExit(exit);
    const auto failed = interrupted.get();
    EXPECT_FALSE(failed.value);
    EXPECT_NE(failed.error.find("signal 9"), std::string::npos);

    const auto recovered = coordinator.AnalysisStatus(
        principal.id, "AnalysisSession", recommended->reference);
    ASSERT_TRUE(recovered.value) << recovered.error;
    EXPECT_TRUE(recovered.value->has_view());
    EXPECT_EQ(supervisor.spawned, 2);
    EXPECT_TRUE(coordinator.Close(principal.id, opened.value->reference, true).empty());
}
#endif
