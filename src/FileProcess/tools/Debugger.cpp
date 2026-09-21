#include "../PluginToolSupport.hpp"
#include "../ToolCall.hpp"

#include <debuggerapi.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace binjad {
	using namespace BinaryNinjaDebuggerAPI;
	using namespace file_process::plugin;

	namespace {
		std::uint64_t Address(BinaryNinja::BinaryView& view, const rapidjson::Value& arguments, const char* field)
		{
			const auto expression = RequiredString(arguments, field);
			rapidjson::Value value;
			value.SetString(expression.data(), static_cast<rapidjson::SizeType>(expression.size()));
			return ParseExpression(view, value, field);
		}

		std::uint64_t Timeout(const rapidjson::Value& arguments)
		{
			const auto timeout = arguments.FindMember("timeoutMilliseconds");
			if (timeout == arguments.MemberEnd() || !timeout->value.IsUint64() || timeout->value.GetUint64() == 0
				|| timeout->value.GetUint64() > 30000)
				throw std::invalid_argument("timeoutMilliseconds must be an integer from 1 through 30000");
			return timeout->value.GetUint64();
		}

		ipc::Reply AcceptedReply(bool accepted)
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("accepted");
			writer.Bool(accepted);
			writer.EndObject();
			return JsonReply(buffer);
		}

		ipc::Reply StopReply(DebugStopReason reason)
		{
			const auto name = DebuggerController::GetDebugStopReasonString(reason);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("stopReason");
			writer.Int(reason);
			writer.Key("stopReasonName");
			writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
			writer.EndObject();
			return JsonReply(buffer);
		}

#define BINJAD_FILE_CHILD_TOOL(Type, Name) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& context) const override; \
	}; \
	ipc::Reply Type::Execute(const FileChildToolCallContext& context) const

		BINJAD_FILE_CHILD_TOOL(DebuggerAdapterListTool, "bn_debugger_adapter_list")
		{
			RequireOnly(context.arguments, {"binaryView"});
			const auto adapters = DebugAdapterType::GetAvailableAdapters(context.view->view);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("adapters");
			writer.StartArray();
			for (const auto& adapter : adapters)
				writer.String(adapter.data(), static_cast<rapidjson::SizeType>(adapter.size()));
			writer.EndArray();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStatusTool, "bn_debugger_status")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			const auto adapter = controller->GetAdapterType();
			const auto reason = controller->StopReason();
			const auto reasonName = DebuggerController::GetDebugStopReasonString(reason);
			const auto executable = controller->GetExecutablePath();
			const auto input = controller->GetInputFile();
			const auto working = controller->GetWorkingDirectory();
			const auto commandLine = controller->GetCommandLineArguments();
			const auto host = controller->GetRemoteHost();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("adapter");
			writer.String(adapter.data(), static_cast<rapidjson::SizeType>(adapter.size()));
			writer.Key("connected");
			writer.Bool(controller->IsConnected());
			writer.Key("running");
			writer.Bool(controller->IsRunning());
			writer.Key("connectionStatus");
			writer.Int(controller->GetConnectionStatus());
			writer.Key("targetStatus");
			writer.Int(controller->GetTargetStatus());
			writer.Key("stopReason");
			writer.Int(reason);
			writer.Key("stopReasonName");
			writer.String(reasonName.data(), static_cast<rapidjson::SizeType>(reasonName.size()));
			writer.Key("pid");
			writer.Uint(controller->GetActivePID());
			writer.Key("instructionPointer");
			WriteAddress(writer, controller->IP());
			writer.Key("stackPointer");
			WriteAddress(writer, controller->StackPointer());
			writer.Key("configuration");
			writer.StartObject();
			writer.Key("executable");
			writer.String(executable.data(), static_cast<rapidjson::SizeType>(executable.size()));
			writer.Key("inputFile");
			writer.String(input.data(), static_cast<rapidjson::SizeType>(input.size()));
			writer.Key("workingDirectory");
			writer.String(working.data(), static_cast<rapidjson::SizeType>(working.size()));
			writer.Key("commandLine");
			writer.String(commandLine.data(), static_cast<rapidjson::SizeType>(commandLine.size()));
			writer.Key("remoteHost");
			writer.String(host.data(), static_cast<rapidjson::SizeType>(host.size()));
			writer.Key("remotePort");
			writer.Uint(controller->GetRemotePort());
			writer.Key("attachPid");
			writer.Int(controller->GetPIDAttach());
			writer.EndObject();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerConfigureTool, "bn_debugger_configure")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments,
				{"binaryView", "adapter", "executable", "inputFile", "workingDirectory", "commandLine", "remoteHost",
					"remotePort", "attachPid"});
			const auto setString = [&](const char* field, auto setter) {
				const auto member = context.arguments.FindMember(field);
				if (member == context.arguments.MemberEnd())
					return;
				if (!member->value.IsString())
					throw std::invalid_argument(std::string(field) + " must be a string");
				(controller.GetPtr()->*setter)(std::string(member->value.GetString(), member->value.GetStringLength()));
			};
			setString("adapter", &DebuggerController::SetAdapterType);
			setString("executable", &DebuggerController::SetExecutablePath);
			setString("inputFile", &DebuggerController::SetInputFile);
			setString("workingDirectory", &DebuggerController::SetWorkingDirectory);
			setString("commandLine", &DebuggerController::SetCommandLineArguments);
			setString("remoteHost", &DebuggerController::SetRemoteHost);
			if (const auto member = context.arguments.FindMember("remotePort"); member != context.arguments.MemberEnd())
			{
				if (!member->value.IsUint() || member->value.GetUint() > 65535)
					throw std::invalid_argument("remotePort must be an integer from 0 through 65535");
				controller->SetRemotePort(member->value.GetUint());
			}
			if (const auto member = context.arguments.FindMember("attachPid"); member != context.arguments.MemberEnd())
			{
				if (!member->value.IsInt())
					throw std::invalid_argument("attachPid must be a signed 32-bit integer");
				controller->SetPIDAttach(member->value.GetInt());
			}
			const auto adapter = controller->GetAdapterType();
			const auto reason = controller->StopReason();
			const auto reasonName = DebuggerController::GetDebugStopReasonString(reason);
			const auto executable = controller->GetExecutablePath();
			const auto input = controller->GetInputFile();
			const auto working = controller->GetWorkingDirectory();
			const auto commandLine = controller->GetCommandLineArguments();
			const auto host = controller->GetRemoteHost();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("adapter");
			writer.String(adapter.data(), static_cast<rapidjson::SizeType>(adapter.size()));
			writer.Key("connected");
			writer.Bool(controller->IsConnected());
			writer.Key("running");
			writer.Bool(controller->IsRunning());
			writer.Key("connectionStatus");
			writer.Int(controller->GetConnectionStatus());
			writer.Key("targetStatus");
			writer.Int(controller->GetTargetStatus());
			writer.Key("stopReason");
			writer.Int(reason);
			writer.Key("stopReasonName");
			writer.String(reasonName.data(), static_cast<rapidjson::SizeType>(reasonName.size()));
			writer.Key("pid");
			writer.Uint(controller->GetActivePID());
			writer.Key("instructionPointer");
			WriteAddress(writer, controller->IP());
			writer.Key("stackPointer");
			WriteAddress(writer, controller->StackPointer());
			writer.Key("configuration");
			writer.StartObject();
			writer.Key("executable");
			writer.String(executable.data(), static_cast<rapidjson::SizeType>(executable.size()));
			writer.Key("inputFile");
			writer.String(input.data(), static_cast<rapidjson::SizeType>(input.size()));
			writer.Key("workingDirectory");
			writer.String(working.data(), static_cast<rapidjson::SizeType>(working.size()));
			writer.Key("commandLine");
			writer.String(commandLine.data(), static_cast<rapidjson::SizeType>(commandLine.size()));
			writer.Key("remoteHost");
			writer.String(host.data(), static_cast<rapidjson::SizeType>(host.size()));
			writer.Key("remotePort");
			writer.Uint(controller->GetRemotePort());
			writer.Key("attachPid");
			writer.Int(controller->GetPIDAttach());
			writer.EndObject();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerLaunchTool, "bn_debugger_launch")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->Launch());
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerConnectTool, "bn_debugger_connect")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->Connect());
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerAttachTool, "bn_debugger_attach")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->Attach());
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerGoTool, "bn_debugger_go")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->Go());
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerPauseTool, "bn_debugger_pause")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			controller->Pause();
			return AcceptedReply(true);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepIntoTool, "bn_debugger_step_into")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->StepInto(NormalFunctionGraph));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepOverTool, "bn_debugger_step_over")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->StepOver(NormalFunctionGraph));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepReturnTool, "bn_debugger_step_return")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			return AcceptedReply(controller->StepReturn());
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerRestartTool, "bn_debugger_restart")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			controller->Restart();
			return AcceptedReply(true);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerQuitTool, "bn_debugger_quit")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			controller->Quit();
			return AcceptedReply(true);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerDetachTool, "bn_debugger_detach")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView"});
			controller->Detach();
			return AcceptedReply(true);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerLaunchAndWaitTool, "bn_debugger_launch_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->LaunchAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerConnectAndWaitTool, "bn_debugger_connect_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->ConnectAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerAttachAndWaitTool, "bn_debugger_attach_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->AttachAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerGoAndWaitTool, "bn_debugger_go_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->GoAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerPauseAndWaitTool, "bn_debugger_pause_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->PauseAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepIntoAndWaitTool, "bn_debugger_step_into_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->StepIntoAndWait(NormalFunctionGraph, Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepOverAndWaitTool, "bn_debugger_step_over_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->StepOverAndWait(NormalFunctionGraph, Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerStepReturnAndWaitTool, "bn_debugger_step_return_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->StepReturnAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerRestartAndWaitTool, "bn_debugger_restart_and_wait")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "timeoutMilliseconds"});
			return StopReply(controller->RestartAndWait(Timeout(context.arguments)));
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerProcessListTool, "bn_debugger_process_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto processes = controller->GetProcessList();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, processes, offset, limit, [](auto& output, const auto& process) {
				output.StartObject();
				output.Key("pid");
				output.Uint(process.m_pid);
				output.Key("name");
				output.String(
					process.m_processName.data(), static_cast<rapidjson::SizeType>(process.m_processName.size()));
				output.Key("commandLine");
				output.String(
					process.m_commandLine.data(), static_cast<rapidjson::SizeType>(process.m_commandLine.size()));
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerThreadListTool, "bn_debugger_thread_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto threads = controller->GetThreads();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, threads, offset, limit, [](auto& output, const auto& thread) {
				output.StartObject();
				output.Key("id");
				output.Uint(thread.m_tid);
				output.Key("instructionPointer");
				WriteAddress(output, thread.m_rip);
				output.Key("frozen");
				output.Bool(thread.m_isFrozen);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerRegisterListTool, "bn_debugger_register_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto registers = controller->GetRegisters();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, registers, offset, limit, [](auto& output, const auto& reg) {
				const auto value = "0x" + intx::to_string(reg.m_value, 16);
				output.StartObject();
				output.Key("name");
				output.String(reg.m_name.data(), static_cast<rapidjson::SizeType>(reg.m_name.size()));
				output.Key("width");
				output.Uint64(reg.m_width);
				output.Key("index");
				output.Uint64(reg.m_registerIndex);
				output.Key("value");
				output.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
				output.Key("hint");
				output.String(reg.m_hint.data(), static_cast<rapidjson::SizeType>(reg.m_hint.size()));
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerModuleListTool, "bn_debugger_module_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto modules = controller->GetModules();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, modules, offset, limit, [](auto& output, const auto& module) {
				output.StartObject();
				output.Key("name");
				output.String(module.m_name.data(), static_cast<rapidjson::SizeType>(module.m_name.size()));
				output.Key("shortName");
				output.String(module.m_short_name.data(), static_cast<rapidjson::SizeType>(module.m_short_name.size()));
				output.Key("address");
				WriteAddress(output, module.m_address);
				output.Key("size");
				output.Uint64(module.m_size);
				output.Key("loaded");
				output.Bool(module.m_loaded);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerMemoryRegionListTool, "bn_debugger_memory_region_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto regions = controller->GetMemoryMap();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, regions, offset, limit, [](auto& output, const auto& region) {
				output.StartObject();
				output.Key("name");
				output.String(region.m_name.data(), static_cast<rapidjson::SizeType>(region.m_name.size()));
				output.Key("start");
				WriteAddress(output, region.m_start);
				output.Key("size");
				output.Uint64(region.m_size);
				output.Key("read");
				output.Bool(region.m_read);
				output.Key("write");
				output.Bool(region.m_write);
				output.Key("execute");
				output.Bool(region.m_execute);
				output.Key("shared");
				output.Bool(region.m_shared);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerBreakpointListTool, "bn_debugger_breakpoint_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto points = controller->GetBreakpoints();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, points, offset, limit, [](auto& output, const auto& point) {
				output.StartObject();
				output.Key("address");
				WriteAddress(output, point.address);
				output.Key("module");
				output.String(point.module.data(), static_cast<rapidjson::SizeType>(point.module.size()));
				output.Key("offset");
				WriteAddress(output, point.offset);
				output.Key("enabled");
				output.Bool(point.enabled);
				output.Key("condition");
				output.String(point.condition.data(), static_cast<rapidjson::SizeType>(point.condition.size()));
				output.Key("type");
				output.Int(point.type);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerFrameListTool, "bn_debugger_frame_list")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "thread", "offset", "limit"});
			const auto thread = context.arguments.FindMember("thread");
			if (thread != context.arguments.MemberEnd() && !thread->value.IsUint())
				throw std::invalid_argument("thread must be an unsigned 32-bit integer");
			const auto threadId =
				thread == context.arguments.MemberEnd() ? controller->GetActiveThread().m_tid : thread->value.GetUint();
			const auto [offset, limit] = Pagination(context.arguments);
			const auto frames = controller->GetFramesOfThread(threadId);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, frames, offset, limit, [](auto& output, const auto& frame) {
				output.StartObject();
				output.Key("index");
				output.Uint64(frame.m_index);
				output.Key("pc");
				WriteAddress(output, frame.m_pc);
				output.Key("sp");
				WriteAddress(output, frame.m_sp);
				output.Key("fp");
				WriteAddress(output, frame.m_fp);
				output.Key("function");
				output.String(
					frame.m_functionName.data(), static_cast<rapidjson::SizeType>(frame.m_functionName.size()));
				output.Key("functionStart");
				WriteAddress(output, frame.m_functionStart);
				output.Key("module");
				output.String(frame.m_module.data(), static_cast<rapidjson::SizeType>(frame.m_module.size()));
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerThreadSetTool, "bn_debugger_thread_set")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "thread"});
			const auto member = context.arguments.FindMember("thread");
			if (member == context.arguments.MemberEnd() || !member->value.IsUint())
				throw std::invalid_argument("thread must be an unsigned 32-bit integer");
			const auto threads = controller->GetThreads();
			const auto found = std::find_if(threads.begin(), threads.end(), [&](const auto& thread) {
				return thread.m_tid == member->value.GetUint();
			});
			if (found == threads.end())
				throw std::invalid_argument("debugger thread not found");
			controller->SetActiveThread(*found);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("thread");
			writer.Uint(found->m_tid);
			writer.Key("instructionPointer");
			WriteAddress(writer, found->m_rip);
			writer.Key("active");
			writer.Bool(true);
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerRegisterSetTool, "bn_debugger_register_set")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "register", "value"});
			const auto name = RequiredString(context.arguments, "register");
			const auto value = Address(*context.view->view, context.arguments, "value");
			if (!controller->SetRegisterValue(name, intx::uint512(value)))
				throw std::runtime_error("debugger register update failed");
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("register");
			writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
			writer.Key("updated");
			writer.Bool(true);
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerMemoryReadTool, "bn_debugger_memory_read")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "address", "length"});
			const auto address = Address(*context.view->view, context.arguments, "address");
			const auto length = context.arguments.FindMember("length");
			if (length == context.arguments.MemberEnd() || !length->value.IsUint64() || length->value.GetUint64() == 0
				|| length->value.GetUint64() > 65536)
				throw std::invalid_argument("length must be an integer from 1 through 65536");
			const auto data = controller->ReadMemory(address, static_cast<std::size_t>(length->value.GetUint64()));
			const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
			std::string hex;
			hex.reserve(data.GetLength() * 2);
			constexpr char digits[] = "0123456789abcdef";
			for (std::size_t index = 0; index < data.GetLength(); ++index)
			{
				hex.push_back(digits[bytes[index] >> 4]);
				hex.push_back(digits[bytes[index] & 0xf]);
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			WriteAddress(writer, address);
			writer.Key("requested");
			writer.Uint64(length->value.GetUint64());
			writer.Key("read");
			writer.Uint64(data.GetLength());
			writer.Key("hex");
			writer.String(hex.data(), static_cast<rapidjson::SizeType>(hex.size()));
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerMemoryWriteTool, "bn_debugger_memory_write")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "address", "hex"});
			const auto address = Address(*context.view->view, context.arguments, "address");
			const auto hex = RequiredString(context.arguments, "hex");
			if (hex.size() % 2 != 0 || hex.size() > 131072)
				throw std::invalid_argument("hex must contain an even number of at most 131072 hexadecimal characters");
			std::vector<std::uint8_t> bytes;
			bytes.reserve(hex.size() / 2);
			const auto nibble = [](char value) -> int {
				if (value >= '0' && value <= '9')
					return value - '0';
				if (value >= 'a' && value <= 'f')
					return value - 'a' + 10;
				if (value >= 'A' && value <= 'F')
					return value - 'A' + 10;
				return -1;
			};
			for (std::size_t index = 0; index < hex.size(); index += 2)
			{
				const auto high = nibble(hex[index]);
				const auto low = nibble(hex[index + 1]);
				if (high < 0 || low < 0)
					throw std::invalid_argument("hex contains a non-hexadecimal character");
				bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
			}
			BinaryNinja::DataBuffer data(bytes.data(), bytes.size());
			if (!controller->WriteMemory(address, data))
				throw std::runtime_error("debugger memory write failed");
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			WriteAddress(writer, address);
			writer.Key("written");
			writer.Uint64(bytes.size());
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerBreakpointAddTool, "bn_debugger_breakpoint_add")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "address"});
			const auto address = Address(*context.view->view, context.arguments, "address");
			controller->AddBreakpoint(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			WriteAddress(writer, address);
			writer.Key("added");
			writer.Bool(true);
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_FILE_CHILD_TOOL(DebuggerBreakpointDeleteTool, "bn_debugger_breakpoint_delete")
		{
			auto controller = DebuggerController::GetController(context.view->view);
			if (!controller)
				throw std::runtime_error("Debugger controller is unavailable");
			RequireOnly(context.arguments, {"binaryView", "address"});
			const auto address = Address(*context.view->view, context.arguments, "address");
			controller->DeleteBreakpoint(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			WriteAddress(writer, address);
			writer.Key("deleted");
			writer.Bool(true);
			writer.EndObject();
			return JsonReply(buffer);
		};

#undef BINJAD_FILE_CHILD_TOOL
	}  // namespace

	void RegisterDebuggerToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<DebuggerAdapterListTool>());
		tools.emplace_back(std::make_unique<DebuggerStatusTool>());
		tools.emplace_back(std::make_unique<DebuggerConfigureTool>());
		tools.emplace_back(std::make_unique<DebuggerLaunchTool>());
		tools.emplace_back(std::make_unique<DebuggerConnectTool>());
		tools.emplace_back(std::make_unique<DebuggerAttachTool>());
		tools.emplace_back(std::make_unique<DebuggerGoTool>());
		tools.emplace_back(std::make_unique<DebuggerPauseTool>());
		tools.emplace_back(std::make_unique<DebuggerStepIntoTool>());
		tools.emplace_back(std::make_unique<DebuggerStepOverTool>());
		tools.emplace_back(std::make_unique<DebuggerStepReturnTool>());
		tools.emplace_back(std::make_unique<DebuggerRestartTool>());
		tools.emplace_back(std::make_unique<DebuggerQuitTool>());
		tools.emplace_back(std::make_unique<DebuggerDetachTool>());
		tools.emplace_back(std::make_unique<DebuggerLaunchAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerConnectAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerAttachAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerGoAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerPauseAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerStepIntoAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerStepOverAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerStepReturnAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerRestartAndWaitTool>());
		tools.emplace_back(std::make_unique<DebuggerProcessListTool>());
		tools.emplace_back(std::make_unique<DebuggerThreadListTool>());
		tools.emplace_back(std::make_unique<DebuggerRegisterListTool>());
		tools.emplace_back(std::make_unique<DebuggerModuleListTool>());
		tools.emplace_back(std::make_unique<DebuggerMemoryRegionListTool>());
		tools.emplace_back(std::make_unique<DebuggerBreakpointListTool>());
		tools.emplace_back(std::make_unique<DebuggerFrameListTool>());
		tools.emplace_back(std::make_unique<DebuggerThreadSetTool>());
		tools.emplace_back(std::make_unique<DebuggerRegisterSetTool>());
		tools.emplace_back(std::make_unique<DebuggerMemoryReadTool>());
		tools.emplace_back(std::make_unique<DebuggerMemoryWriteTool>());
		tools.emplace_back(std::make_unique<DebuggerBreakpointAddTool>());
		tools.emplace_back(std::make_unique<DebuggerBreakpointDeleteTool>());
	}
}  // namespace binjad
