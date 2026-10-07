#include "../FileChild.hpp"
#include "../ToolCall.hpp"
#include "../ToolSupport.hpp"

#include "binjad/binary_ninja/Language.hpp"
#include "binjad/binary_ninja/StringCodec.hpp"

#include <highlevelilinstruction.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace binjad {
	using binary_ninja::DecodeString;
	using binary_ninja::HexBytes;
	using binary_ninja::SliceString;
	using binary_ninja::StringEncodingName;
	using namespace file_process;

	namespace {
#define BINJAD_ANALYSIS_TOOL(Type, Name) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& command) const override; \
	}; \
	ipc::Reply Type::Execute(const FileChildToolCallContext& command) const

		BINJAD_ANALYSIS_TOOL(FunctionListTool, "bn_function_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("function-list arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			auto parseExpression = [&](const rapidjson::Value& value) {
				if (!value.IsString())
					throw std::invalid_argument("address expression must be a string");
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
				address = parseExpression(value->value);
			if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
				start = parseExpression(value->value);
			if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
				end = parseExpression(value->value);
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
			{
				std::uint64_t length = 0;
				if (value->value.IsUint64())
					length = value->value.GetUint64();
				else
					length = parseExpression(value->value);
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("function range length is invalid");
				end = *start + length;
			}
			std::string query;
			if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
				query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));

			auto functions = state->view->GetAnalysisFunctionList();
			std::erase_if(functions, [&](const auto& function) {
				const auto functionAddress = function->GetStart();
				if (address && functionAddress != *address)
					return true;
				if (start && functionAddress < *start)
					return true;
				if (end && functionAddress >= *end)
					return true;
				if (!query.empty())
				{
					const auto symbol = function->GetSymbol();
					if (!symbol)
						return true;
					return Lower(symbol->GetShortName()).find(query) == std::string::npos
						&& Lower(symbol->GetFullName()).find(query) == std::string::npos
						&& Lower(symbol->GetRawName()).find(query) == std::string::npos;
				}
				return false;
			});
			std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
				if (left->GetStart() != right->GetStart())
					return left->GetStart() < right->GetStart();
				const auto leftArch = left->GetArchitecture();
				const auto rightArch = right->GetArchitecture();
				const auto leftName = leftArch ? leftArch->GetName() : std::string {};
				const auto rightName = rightArch ? rightArch->GetName() : std::string {};
				if (leftName != rightName)
					return leftName < rightName;
				const auto leftSymbol = left->GetSymbol();
				const auto rightSymbol = right->GetSymbol();
				return (leftSymbol ? leftSymbol->GetRawName() : std::string {})
					< (rightSymbol ? rightSymbol->GetRawName() : std::string {});
			});
			offset = std::min(offset, functions.size());
			const auto finish = offset + std::min(limit, functions.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("functions");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& function = functions[index];
				const auto symbol = function->GetSymbol();
				const auto platform = function->GetPlatform();
				const auto type = function->GetType();
				const auto addressText = HexAddress(function->GetStart());
				writer.StartObject();
				writer.Key("address");
				writer.String(addressText.data(), addressText.size());
				writer.Key("name");
				const auto name = symbol ? symbol->GetShortName() : addressText;
				writer.String(name.data(), name.size());
				writer.Key("type");
				const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
				writer.String(typeText.data(), typeText.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(functions.size());
			writer.Key("nextOffset");
			if (finish < functions.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < functions.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionInfoTool, "bn_function_info")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			const auto symbol = function->GetSymbol();
			const auto architecture = function->GetArchitecture();
			const auto platform = function->GetPlatform();
			const auto type = function->GetType();
			const auto callingConvention = function->GetCallingConvention().GetValue();
			const auto addressText = HexAddress(function->GetStart());
			const auto name = symbol ? symbol->GetShortName() : addressText;
			const auto architectureName = architecture ? architecture->GetName() : std::string {};
			const auto platformName = platform ? platform->GetName() : std::string {};
			const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
			const auto blocks = function->GetBasicBlocks();
			const auto ranges = function->GetAddressRanges();

			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("name");
			writer.String(name.data(), name.size());
			writer.Key("start");
			writer.String(addressText.data(), addressText.size());
			writer.Key("lowestAddress");
			const auto lowestAddress = HexAddress(function->GetLowestAddress());
			writer.String(lowestAddress.data(), lowestAddress.size());
			writer.Key("highestAddress");
			const auto highestAddress = HexAddress(function->GetHighestAddress());
			writer.String(highestAddress.data(), highestAddress.size());
			writer.Key("architecture");
			writer.String(architectureName.data(), architectureName.size());
			writer.Key("platform");
			writer.String(platformName.data(), platformName.size());
			writer.Key("type");
			writer.String(typeText.data(), typeText.size());
			writer.Key("hasUserType");
			writer.Bool(function->HasUserType());
			writer.Key("callingConvention");
			if (callingConvention)
			{
				const auto callingConventionName = callingConvention->GetName();
				writer.String(callingConventionName.data(), callingConventionName.size());
			}
			else
				writer.Null();
			writer.Key("exported");
			writer.Bool(function->IsExported());
			writer.Key("autoDiscovered");
			writer.Bool(function->WasAutomaticallyDiscovered());
			writer.Key("hasUserAnnotations");
			writer.Bool(function->HasUserAnnotations());
			const bool needsUpdate = function->NeedsUpdate();
			writer.Key("needsUpdate");
			writer.Bool(needsUpdate);
			if (needsUpdate)
			{
				writer.Key("nextAction");
				writer.String("Call bn_analysis_update_and_wait before readback or dependent variable mutations.");
			}
			writer.Key("analysisSkipped");
			writer.Bool(function->IsAnalysisSkipped());
			writer.Key("analysisSkipReason");
			writer.String(AnalysisSkipReasonName(function->GetAnalysisSkipReason()));
			writer.Key("basicBlockCount");
			writer.Uint64(blocks.size());
			writer.Key("ranges");
			writer.StartArray();
			for (const auto& range : ranges)
			{
				const auto start = HexAddress(range.start);
				const auto end = HexAddress(range.end);
				writer.StartObject();
				writer.Key("start");
				writer.String(start.data(), start.size());
				writer.Key("end");
				writer.String(end.data(), end.size());
				writer.Key("length");
				writer.Uint64(range.end - range.start);
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("basicBlocks");
			writer.StartArray();
			for (std::size_t index = 0; index < blocks.size(); ++index)
			{
				const auto start = HexAddress(blocks[index]->GetStart());
				const auto end = HexAddress(blocks[index]->GetEnd());
				writer.StartObject();
				writer.Key("index");
				writer.Uint64(index);
				writer.Key("start");
				writer.String(start.data(), start.size());
				writer.Key("end");
				writer.String(end.data(), end.size());
				writer.Key("length");
				writer.Uint64(blocks[index]->GetEnd() - blocks[index]->GetStart());
				writer.Key("incoming");
				writer.Uint64(blocks[index]->GetIncomingEdges().size());
				writer.Key("outgoing");
				writer.Uint64(blocks[index]->GetOutgoingEdges().size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionCallersTool, "bn_function_callers")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto callers = state->view->GetCallers(function->GetStart());
			std::sort(callers.begin(), callers.end(), [](const auto& left, const auto& right) {
				if (left.addr != right.addr)
					return left.addr < right.addr;
				const auto leftStart = left.func ? left.func->GetStart() : 0;
				const auto rightStart = right.func ? right.func->GetStart() : 0;
				return leftStart < rightStart;
			});
			offset = std::min(offset, callers.size());
			const auto finish = offset + std::min(limit, callers.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("callers");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& caller = callers[index];
				const auto callerAddress = caller.func ? caller.func->GetStart() : caller.addr;
				const auto callerAddressText = HexAddress(callerAddress);
				const auto callsite = HexAddress(caller.addr);
				const auto symbol = caller.func ? caller.func->GetSymbol() : nullptr;
				const auto name = symbol ? symbol->GetShortName() : callerAddressText;
				writer.StartObject();
				writer.Key("callsite");
				writer.String(callsite.data(), callsite.size());
				writer.Key("caller");
				writer.StartObject();
				writer.Key("address");
				writer.String(callerAddressText.data(), callerAddressText.size());
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.EndObject();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(callers.size());
			writer.Key("nextOffset");
			if (finish < callers.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < callers.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionCalleesTool, "bn_function_callees")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			struct Callee
			{
				std::uint64_t callsite;
				std::uint64_t target;
			};
			std::vector<Callee> callees;
			for (const auto& callsite : function->GetCallSites())
			{
				for (const auto target : state->view->GetCallees(callsite))
					callees.push_back({callsite.addr, target});
			}
			std::sort(callees.begin(), callees.end(), [](const auto& left, const auto& right) {
				return std::tie(left.callsite, left.target) < std::tie(right.callsite, right.target);
			});
			offset = std::min(offset, callees.size());
			const auto finish = offset + std::min(limit, callees.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("callees");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto callsite = HexAddress(callees[index].callsite);
				const auto target = HexAddress(callees[index].target);
				writer.StartObject();
				writer.Key("callsite");
				writer.String(callsite.data(), callsite.size());
				writer.Key("target");
				writer.String(target.data(), target.size());
				writer.Key("functions");
				writer.StartArray();
				for (const auto& targetFunction : state->view->GetAnalysisFunctionsForAddress(callees[index].target))
				{
					const auto functionAddress = HexAddress(targetFunction->GetStart());
					const auto symbol = targetFunction->GetSymbol();
					const auto name = symbol ? symbol->GetShortName() : functionAddress;
					writer.StartObject();
					writer.Key("address");
					writer.String(functionAddress.data(), functionAddress.size());
					writer.Key("name");
					writer.String(name.data(), name.size());
					writer.EndObject();
				}
				writer.EndArray();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(callees.size());
			writer.Key("nextOffset");
			if (finish < callees.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < callees.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionDisassemblyTool, "bn_function_disassembly")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultRenderLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());

			const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
			settings->SetOption(ShowAddress, false);
			settings->SetOption(ShowOpcode, false);
			std::vector<std::string> lines;
			for (const auto& line : function->GetTypeTokens(settings))
				lines.push_back("  " + TokenText(line.tokens));
			if (!lines.empty())
				lines.emplace_back();
			auto blocks = function->GetBasicBlocks();
			std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) {
				return left->GetStart() < right->GetStart();
			});
			bool firstBlock = true;
			for (const auto& block : blocks)
			{
				if (!firstBlock)
					lines.emplace_back();
				firstBlock = false;
				for (const auto& line : block->GetDisassemblyText(settings))
					lines.push_back(HexAddress(line.addr) + "  " + TokenText(line.tokens));
			}
			while (!lines.empty() && lines.back().empty())
				lines.pop_back();
			offset = std::min(offset, lines.size());
			const auto finish = offset + std::min(limit, lines.size() - offset);
			std::string text;
			for (auto index = offset; index < finish; ++index)
			{
				if (index != offset)
					text += '\n';
				text += lines[index];
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("text");
			writer.String(text.data(), text.size());
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(lines.size());
			writer.Key("nextOffset");
			if (finish < lines.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < lines.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionDecompileTool, "bn_function_decompile")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			const auto languageArgument = arguments.FindMember("language");
			const bool explicitLanguage = languageArgument != arguments.MemberEnd();
			std::string languageName = "Pseudo C";
			std::string languageReason = "default";
			if (explicitLanguage)
			{
				const auto& value = languageArgument->value;
				languageName.assign(value.GetString(), value.GetStringLength());
				languageReason = "requested";
			}
			else if (const auto symbol = function->GetSymbol())
			{
				const auto preference =
					binary_ninja::PreferredLanguageForSymbol(symbol->GetShortName(), symbol->GetRawName());
				languageName = preference.name;
				languageReason = preference.reason;
			}
			std::size_t offset = 0;
			std::size_t limit = kDefaultRenderLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());

			const auto findRepresentation = [&](std::string requested, std::string& resolvedName) {
				auto result = function->GetLanguageRepresentation(requested);
				if (result)
				{
					resolvedName = std::move(requested);
					return result;
				}
				const auto normalized = NormalizedName(requested);
				for (const auto& type : BinaryNinja::LanguageRepresentationFunctionType::GetTypes())
				{
					if (!type || !type->IsValid(state->view) || NormalizedName(type->GetName()) != normalized)
						continue;
					if (result)
						throw std::invalid_argument("language representation name is ambiguous: " + requested);
					resolvedName = type->GetName();
					result = function->GetLanguageRepresentation(resolvedName);
				}
				return result;
			};
			std::string resolvedLanguage;
			auto representation = findRepresentation(languageName, resolvedLanguage);
			if (!representation && !explicitLanguage && languageName != "Pseudo C")
			{
				languageName = "Pseudo C";
				languageReason = "fallback";
				representation = findRepresentation(languageName, resolvedLanguage);
			}
			if (!representation)
			{
				bool analysisActive = false;
				{
					std::lock_guard lock(command.viewMutex);
					analysisActive = state->analysisActive;
				}
				throw std::invalid_argument("language representation is unavailable: " + languageName
					+ (analysisActive ? "; analysis is running, so wait for its job to finish before retrying" :
										"; use bn_function_il with level hlil as a fallback"));
			}
			languageName = std::move(resolvedLanguage);
			const auto highLevelIL = representation->GetHighLevelILFunction();
			if (!highLevelIL)
				throw std::runtime_error("high-level IL is unavailable for the function");
			const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
			settings->SetOption(ShowAddress, false);
			settings->SetOption(ShowOpcode, false);
			settings->SetOption(ShowTypeCasts, true);
			settings->SetOption(IndentHLILBody, true);
			std::vector<std::string> lines;
			for (const auto& line : function->GetTypeTokens(settings))
				lines.push_back("  " + TokenText(line.tokens));
			if (!lines.empty())
				lines.emplace_back();
			for (const auto& line : representation->GetLinearLines(highLevelIL->GetRootExpr(), settings))
				lines.push_back(TokenText(line.tokens));
			while (!lines.empty() && lines.back().empty())
				lines.pop_back();
			offset = std::min(offset, lines.size());
			const auto finish = offset + std::min(limit, lines.size() - offset);
			std::string text;
			for (auto index = offset; index < finish; ++index)
			{
				if (index != offset)
					text += '\n';
				text += lines[index];
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("language");
			writer.String(languageName.data(), languageName.size());
			if (!explicitLanguage)
			{
				writer.Key("languageSelection");
				writer.String(languageReason.data(), languageReason.size());
			}
			writer.Key("text");
			writer.String(text.data(), text.size());
			writer.Key("needsUpdate");
			writer.Bool(function->NeedsUpdate());
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(lines.size());
			writer.Key("nextOffset");
			if (finish < lines.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < lines.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionIlTool, "bn_function_il")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::string level = "hlil";
			if (const auto value = arguments.FindMember("level"); value != arguments.MemberEnd())
				level.assign(value->value.GetString(), value->value.GetStringLength());
			bool ssa = false;
			if (const auto value = arguments.FindMember("ssa"); value != arguments.MemberEnd())
				ssa = value->value.GetBool();
			std::size_t offset = 0;
			std::size_t limit = kDefaultRenderLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());

			std::vector<BinaryNinja::Ref<BinaryNinja::BasicBlock>> blocks;
			if (level == "llil")
			{
				auto il = function->GetLowLevelIL();
				if (!il)
					throw std::runtime_error("low-level IL is unavailable for the function");
				if (ssa)
					il = il->GetSSAForm();
				blocks = il->GetBasicBlocks();
			}
			else if (level == "mlil")
			{
				auto il = function->GetMediumLevelIL();
				if (!il)
					throw std::runtime_error("medium-level IL is unavailable for the function");
				if (ssa)
					il = il->GetSSAForm();
				blocks = il->GetBasicBlocks();
			}
			else if (level == "hlil")
			{
				auto il = function->GetHighLevelIL();
				if (!il)
					throw std::runtime_error("high-level IL is unavailable for the function");
				if (ssa)
					il = il->GetSSAForm();
				blocks = il->GetBasicBlocks();
			}
			else
				throw std::invalid_argument("level must be llil, mlil, or hlil");

			const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
			settings->SetOption(ShowAddress, false);
			settings->SetOption(ShowOpcode, false);
			settings->SetOption(ShowTypeCasts, true);
			std::vector<std::string> lines;
			for (const auto& line : function->GetTypeTokens(settings))
				lines.push_back("  " + TokenText(line.tokens));
			if (!lines.empty())
				lines.emplace_back();
			std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) {
				return left->GetStart() < right->GetStart();
			});
			bool firstBlock = true;
			for (const auto& block : blocks)
			{
				if (!firstBlock)
					lines.emplace_back();
				firstBlock = false;
				for (const auto& line : block->GetDisassemblyText(settings))
					lines.push_back(HexAddress(line.addr) + "  " + TokenText(line.tokens));
			}
			while (!lines.empty() && lines.back().empty())
				lines.pop_back();
			offset = std::min(offset, lines.size());
			const auto finish = offset + std::min(limit, lines.size() - offset);
			std::string text;
			for (auto index = offset; index < finish; ++index)
			{
				if (index != offset)
					text += '\n';
				text += lines[index];
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("level");
			writer.String(level.data(), level.size());
			writer.Key("ssa");
			writer.Bool(ssa);
			writer.Key("text");
			writer.String(text.data(), text.size());
			writer.Key("needsUpdate");
			writer.Bool(function->NeedsUpdate());
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(lines.size());
			writer.Key("nextOffset");
			if (finish < lines.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < lines.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionStackLayoutTool, "bn_function_stack_layout")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			struct StackVariable
			{
				std::int64_t frameOffset;
				BinaryNinja::VariableNameAndType variable;
			};
			std::vector<StackVariable> variables;
			for (const auto& [frameOffset, entries] : function->GetStackLayout())
			{
				for (const auto& entry : entries)
					variables.push_back({frameOffset, entry});
			}
			offset = std::min(offset, variables.size());
			const auto finish = offset + std::min(limit, variables.size() - offset);
			const auto platform = function->GetPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("variables");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& entry = variables[index];
				const auto type = entry.variable.type.GetValue();
				const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
				writer.StartObject();
				writer.Key("offset");
				writer.Int64(entry.frameOffset);
				writer.Key("name");
				writer.String(entry.variable.name.data(), entry.variable.name.size());
				writer.Key("type");
				writer.String(typeText.data(), typeText.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(variables.size());
			writer.Key("nextOffset");
			if (finish < variables.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < variables.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(VariableListTool, "bn_variable_list")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			const auto variableMap = function->GetVariables();
			std::vector<BinaryNinja::VariableNameAndType> variables;
			variables.reserve(variableMap.size());
			for (const auto& entry : variableMap)
				variables.push_back(entry.second);
			offset = std::min(offset, variables.size());
			const auto finish = offset + std::min(limit, variables.size() - offset);
			const auto platform = function->GetPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("variables");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& entry = variables[index];
				const auto type = entry.type.GetValue();
				const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
				writer.StartObject();
				writer.Key("name");
				writer.String(entry.name.data(), entry.name.size());
				writer.Key("type");
				writer.String(typeText.data(), typeText.size());
				writer.Key("source");
				writer.String(VariableSourceName(entry.var.type));
				writer.Key("index");
				writer.Uint(entry.var.index);
				writer.Key("storage");
				writer.Int64(entry.var.storage);
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(variables.size());
			writer.Key("nextOffset");
			if (finish < variables.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < variables.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(CallingConventionListTool, "bn_calling_convention_list")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			const auto platform = function->GetPlatform();
			if (!platform)
				throw std::runtime_error("function has no platform");
			const auto current = function->GetCallingConvention().GetValue();
			std::vector<std::string> names;
			for (const auto& convention : platform->GetCallingConventions())
			{
				if (convention)
					names.push_back(convention->GetName());
			}
			std::sort(names.begin(), names.end());
			names.erase(std::unique(names.begin(), names.end()), names.end());
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("current");
			if (current)
			{
				const auto currentName = current->GetName();
				writer.String(currentName.data(), currentName.size());
			}
			else
				writer.Null();
			writer.Key("callingConventions");
			writer.StartArray();
			for (const auto& name : names)
				writer.String(name.data(), name.size());
			writer.EndArray();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionXrefsFromTool, "bn_function_xrefs_from")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			struct Reference
			{
				std::uint64_t source;
				std::uint64_t target;
			};
			std::vector<Reference> references;
			for (const auto& block : function->GetBasicBlocks())
			{
				const auto architecture = block->GetArchitecture();
				if (!architecture)
					continue;
				for (auto source = block->GetStart(); source < block->GetEnd();)
				{
					BinaryNinja::ReferenceSource referenceSource;
					referenceSource.func = function;
					referenceSource.arch = architecture;
					referenceSource.addr = source;
					for (const auto target : state->view->GetCodeReferencesFrom(referenceSource))
						references.push_back({source, target});
					const auto length = state->view->GetInstructionLength(architecture, source);
					if (length == 0 || length > block->GetEnd() - source)
						break;
					source += length;
				}
			}
			std::sort(references.begin(), references.end(), [](const auto& left, const auto& right) {
				return std::tie(left.source, left.target) < std::tie(right.source, right.target);
			});
			references.erase(
				std::unique(references.begin(), references.end(),
					[](const auto& left, const auto& right) {
						return left.source == right.source && left.target == right.target;
					}),
				references.end());
			offset = std::min(offset, references.size());
			const auto finish = offset + std::min(limit, references.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("references");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto source = HexAddress(references[index].source);
				const auto target = HexAddress(references[index].target);
				writer.StartObject();
				writer.Key("source");
				writer.String(source.data(), source.size());
				writer.Key("target");
				writer.String(target.data(), target.size());
				writer.Key("functions");
				writer.StartArray();
				for (const auto& targetFunction :
					state->view->GetAnalysisFunctionsContainingAddress(references[index].target))
				{
					const auto functionAddress = HexAddress(targetFunction->GetStart());
					const auto symbol = targetFunction->GetSymbol();
					const auto name = symbol ? symbol->GetShortName() : functionAddress;
					writer.StartObject();
					writer.Key("address");
					writer.String(functionAddress.data(), functionAddress.size());
					writer.Key("name");
					writer.String(name.data(), name.size());
					writer.EndObject();
				}
				writer.EndArray();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(references.size());
			writer.Key("nextOffset");
			if (finish < references.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < references.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionXrefsToTool, "bn_function_xrefs_to")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			const auto function = ResolveFunction(command, arguments);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			std::vector<BinaryNinja::ReferenceSource> references;
			for (const auto& range : function->GetAddressRanges())
			{
				auto rangeReferences = state->view->GetCodeReferences(range.start, range.end - range.start);
				references.insert(references.end(), rangeReferences.begin(), rangeReferences.end());
			}
			std::sort(references.begin(), references.end(), [](const auto& left, const auto& right) {
				if (left.addr != right.addr)
					return left.addr < right.addr;
				const auto leftStart = left.func ? left.func->GetStart() : 0;
				const auto rightStart = right.func ? right.func->GetStart() : 0;
				return leftStart < rightStart;
			});
			references.erase(
				std::unique(references.begin(), references.end(),
					[](const auto& left, const auto& right) {
						const auto leftStart = left.func ? left.func->GetStart() : 0;
						const auto rightStart = right.func ? right.func->GetStart() : 0;
						return left.addr == right.addr && leftStart == rightStart;
					}),
				references.end());
			offset = std::min(offset, references.size());
			const auto finish = offset + std::min(limit, references.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("references");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& reference = references[index];
				const auto source = HexAddress(reference.addr);
				writer.StartObject();
				writer.Key("source");
				writer.String(source.data(), source.size());
				writer.Key("function");
				if (reference.func)
				{
					const auto functionAddress = HexAddress(reference.func->GetStart());
					const auto symbol = reference.func->GetSymbol();
					const auto name = symbol ? symbol->GetShortName() : functionAddress;
					writer.StartObject();
					writer.Key("address");
					writer.String(functionAddress.data(), functionAddress.size());
					writer.Key("name");
					writer.String(name.data(), name.size());
					writer.EndObject();
				}
				else
					writer.Null();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(references.size());
			writer.Key("nextOffset");
			if (finish < references.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < references.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(StringListTool, "bn_string_list")
		{
			const auto& state = command.view;
			const bool sharedCacheView = state->view->GetTypeName() == "DSCView";
			{
				std::lock_guard lock(command.viewMutex);
				if (state->analysisActive && sharedCacheView)
				{
					rapidjson::StringBuffer buffer;
					rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
					writer.StartObject();
					writer.Key("available");
					writer.Bool(false);
					writer.Key("state");
					writer.String("analysis_running");
					writer.Key("retryAfterMilliseconds");
					writer.Uint(10000);
					writer.Key("nextAction");
					writer.String(
						"Wait for SharedCache analysis to finish before listing strings. If analysis_update_and_wait "
						"returned a job, poll bn_job_info no more than every 10 seconds and call bn_job_result when "
						"terminal.");
					writer.EndObject();
					ipc::Reply reply;
					reply.set_success(true);
					reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
					return reply;
				}
			}
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("string-list arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
				address = parseExpression(value->value);
			if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
				start = parseExpression(value->value);
			if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
				end = parseExpression(value->value);
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
			{
				std::uint64_t length =
					value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("string range length is invalid");
				end = *start + length;
			}
			std::string query;
			if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
				query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));

			auto strings = state->view->GetStrings();
			std::erase_if(strings, [&](const auto& string) {
				if (address && string.start != *address)
					return true;
				if (start && string.start < *start)
					return true;
				if (end && string.start >= *end)
					return true;
				if (!query.empty())
				{
					const auto detected = ReadDetectedString(state->view, string.type, string.start, string.length);
					const auto preview =
						DecodeString(detected.type, detected.bytes, std::numeric_limits<std::size_t>::max());
					return Lower(preview.text).find(query) == std::string::npos;
				}
				return false;
			});
			std::sort(strings.begin(), strings.end(), [](const auto& left, const auto& right) {
				if (left.start != right.start)
					return left.start < right.start;
				return left.type < right.type;
			});
			offset = std::min(offset, strings.size());
			const auto finish = offset + std::min(limit, strings.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("strings");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& string = strings[index];
				const auto detected = ReadDetectedString(state->view, string.type, string.start, string.length);
				const auto preview = DecodeString(detected.type, detected.bytes);
				const auto addressText = HexAddress(string.start);
				writer.StartObject();
				writer.Key("address");
				writer.String(addressText.data(), addressText.size());
				writer.Key(preview.decoded ? "value" : "bytes");
				writer.String(preview.text.data(), preview.text.size());
				if (preview.truncated)
				{
					writer.Key("length");
					writer.Uint64(preview.length);
					writer.Key("truncated");
					writer.Bool(true);
				}
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(strings.size());
			writer.Key("nextOffset");
			if (finish < strings.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < strings.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(StringAtTool, "bn_string_at")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("string address must be a string");
			const auto& addressValue = arguments["address"];
			std::uint64_t address = 0;
			std::string parseError;
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid string address" : parseError);
			BNStringReference reference {};
			const bool detectedByAnalysis = state->view->GetStringAtAddress(address, reference);
			std::size_t offset = 0;
			std::size_t limit = 4096;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto detected = detectedByAnalysis ?
				std::optional<DetectedStringData>(
					ReadDetectedString(state->view, reference.type, reference.start, reference.length)) :
				ReadNullTerminatedString(state->view, address);
			if (!detected)
				throw std::invalid_argument(
					"string not found and no valid NUL-terminated UTF-8 string exists at address");
			const std::span<const std::uint8_t> bytes(detected->bytes);
			const auto decoded = DecodeString(detected->type, bytes, std::numeric_limits<std::size_t>::max());
			const auto chunk = SliceString(decoded, bytes, offset, limit);
			const auto addressText = HexAddress(detectedByAnalysis ? reference.start : address);
			const auto encoding = StringEncodingName(detected->type);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("encoding");
			if (encoding)
				writer.String(encoding);
			else
				writer.Null();
			writer.Key("byteLength");
			writer.Uint64(detected->bytes.size());
			writer.Key("characterLength");
			if (decoded.decoded)
				writer.Uint64(chunk.total);
			else
				writer.Null();
			writer.Key(decoded.decoded ? "value" : "bytes");
			writer.String(chunk.text.data(), chunk.text.size());
			writer.Key("offset");
			writer.Uint64(chunk.offset);
			writer.Key("count");
			writer.Uint64(chunk.count);
			writer.Key("nextOffset");
			if (chunk.nextOffset)
				writer.Uint64(*chunk.nextOffset);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(chunk.truncated);
			if (!detectedByAnalysis)
			{
				writer.Key("inferred");
				writer.Bool(true);
			}
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SymbolListTool, "bn_symbol_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("symbol-list arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
				address = parseExpression(value->value);
			if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
				start = parseExpression(value->value);
			if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
				end = parseExpression(value->value);
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
			{
				std::uint64_t length =
					value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("symbol range length is invalid");
				end = *start + length;
			}
			std::string query;
			if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
				query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));
			auto symbols = state->view->GetSymbols();
			std::erase_if(symbols, [&](const auto& symbol) {
				if (command.name() == "bn_import_list" && symbol->GetType() != ImportAddressSymbol
					&& symbol->GetType() != ImportedFunctionSymbol && symbol->GetType() != ImportedDataSymbol)
					return true;
				if (command.name() == "bn_export_list")
				{
					const bool exportedType = symbol->GetType() == FunctionSymbol || symbol->GetType() == DataSymbol;
					const bool exportedBinding =
						symbol->GetBinding() == GlobalBinding || symbol->GetBinding() == WeakBinding;
					if (!exportedType || !exportedBinding)
						return true;
				}
				if (address && symbol->GetAddress() != *address)
					return true;
				if (start && symbol->GetAddress() < *start)
					return true;
				if (end && symbol->GetAddress() >= *end)
					return true;
				return !query.empty() && Lower(symbol->GetShortName()).find(query) == std::string::npos
					&& Lower(symbol->GetFullName()).find(query) == std::string::npos
					&& Lower(symbol->GetRawName()).find(query) == std::string::npos;
			});
			std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
				if (left->GetAddress() != right->GetAddress())
					return left->GetAddress() < right->GetAddress();
				if (left->GetType() != right->GetType())
					return left->GetType() < right->GetType();
				return left->GetFullName() < right->GetFullName();
			});
			offset = std::min(offset, symbols.size());
			const auto finish = offset + std::min(limit, symbols.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("symbols");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& symbol = symbols[index];
				const auto addressText = HexAddress(symbol->GetAddress());
				const auto name = symbol->GetFullName();
				writer.StartObject();
				writer.Key("address");
				writer.String(addressText.data(), addressText.size());
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("type");
				writer.String(SymbolTypeName(symbol->GetType()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(symbols.size());
			writer.Key("nextOffset");
			if (finish < symbols.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < symbols.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(ImportListTool, "bn_import_list")
		{
			return SymbolListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(ExportListTool, "bn_export_list")
		{
			return SymbolListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(SymbolListAtTool, "bn_symbol_list_at")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("symbol address must be a string");
			const auto& addressValue = arguments["address"];
			std::uint64_t address = 0;
			std::string parseError;
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
			auto symbols = state->view->GetSymbols(address, 1);
			std::erase_if(symbols, [&](const auto& symbol) { return symbol->GetAddress() != address; });
			std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
				if (left->GetType() != right->GetType())
					return left->GetType() < right->GetType();
				return left->GetFullName() < right->GetFullName();
			});
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("symbols");
			writer.StartArray();
			for (const auto& symbol : symbols)
			{
				const auto addressText = HexAddress(symbol->GetAddress());
				const auto shortName = symbol->GetShortName();
				const auto fullName = symbol->GetFullName();
				const auto rawName = symbol->GetRawName();
				const auto nameSpace = symbol->GetNameSpace();
				writer.StartObject();
				writer.Key("address");
				writer.String(addressText.data(), addressText.size());
				writer.Key("type");
				writer.String(SymbolTypeName(symbol->GetType()));
				writer.Key("shortName");
				writer.String(shortName.data(), shortName.size());
				writer.Key("fullName");
				writer.String(fullName.data(), fullName.size());
				writer.Key("rawName");
				writer.String(rawName.data(), rawName.size());
				writer.Key("namespace");
				writer.StartArray();
				for (const auto& component : nameSpace)
					writer.String(component.data(), component.size());
				writer.EndArray();
				writer.Key("ordinal");
				writer.Uint64(symbol->GetOrdinal());
				writer.Key("binding");
				writer.String(SymbolBindingName(symbol->GetBinding()));
				writer.Key("autoDefined");
				writer.Bool(symbol->IsAutoDefined());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(symbols.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(EntryPointListTool, "bn_entry_point_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("entry-point arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto functions = state->view->GetAllEntryFunctions();
			std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
				return left->GetStart() < right->GetStart();
			});
			offset = std::min(offset, functions.size());
			const auto finish = offset + std::min(limit, functions.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("entryPoints");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& function = functions[index];
				const auto address = HexAddress(function->GetStart());
				const auto symbol = function->GetSymbol();
				const auto name = symbol ? symbol->GetShortName() : address;
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), address.size());
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(functions.size());
			writer.Key("nextOffset");
			if (finish < functions.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < functions.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(EntryPointAddTool, "bn_entry_point_add")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("entry-point address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& value = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(
					state->view, std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid entry-point address" : parseError);
			if (!state->view->IsValidOffset(address))
				throw std::invalid_argument("entry-point address is not mapped");
			const auto platform = state->view->GetDefaultPlatform();
			if (!platform)
				throw std::runtime_error(
					"BinaryView has no default platform. For raw firmware, close the open item, reopen it, select the "
					"Mapped candidate, inspect bn_binary_view_load_settings, and set loader.platform before "
					"materialization");
			const auto entries = state->view->GetAllEntryFunctions();
			const bool existing = std::any_of(entries.begin(), entries.end(), [&](const auto& function) {
				return function->GetStart() == address;
			});
			if (!existing)
				state->view->AddEntryPointForAnalysis(platform.GetPtr(), address);
			const auto functions = state->view->GetAnalysisFunctionList();
			const bool functionPresent = std::any_of(functions.begin(), functions.end(), [&](const auto& function) {
				return function->GetStart() == address;
			});
			const auto addressText = HexAddress(address);
			const auto platformName = platform->GetName();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("platform");
			writer.String(platformName.data(), platformName.size());
			writer.Key("added");
			writer.Bool(!existing);
			writer.Key("functionPresent");
			writer.Bool(functionPresent);
			writer.Key("nextAction");
			writer.String(functionPresent ?
					"Call bn_analysis_update_and_wait, then bn_binary_view_save to persist changes." :
					"Call bn_function_create at this address, then bn_analysis_update_and_wait and "
					"bn_binary_view_save.");
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionCreateTool, "bn_function_create")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("function address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& value = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(
					state->view, std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid function address" : parseError);
			if (!state->view->IsValidOffset(address))
				throw std::invalid_argument("function address is not mapped");
			const auto platform = state->view->GetDefaultPlatform();
			if (!platform)
				throw std::runtime_error(
					"BinaryView has no default platform. For raw firmware, close the open item, reopen it, select the "
					"Mapped candidate, inspect bn_binary_view_load_settings, and set loader.platform before "
					"materialization");
			auto functions = state->view->GetAnalysisFunctionList();
			auto existing = std::find_if(functions.begin(), functions.end(), [&](const auto& function) {
				return function->GetStart() == address && function->GetPlatform().GetPtr() == platform.GetPtr();
			});
			const auto tracked = state->userFunctions.find(address);
			const bool created = existing == functions.end() && tracked == state->userFunctions.end();
			BinaryNinja::Ref<BinaryNinja::Function> function;
			if (existing != functions.end())
				function = *existing;
			else if (tracked != state->userFunctions.end())
				function = tracked->second;
			else
			{
				function = state->view->CreateUserFunction(platform.GetPtr(), address);
				if (function)
					state->userFunctions.emplace(address, function);
			}
			if (!function)
				throw std::runtime_error("Binary Ninja could not create the user function");
			const auto symbol = function->GetSymbol();
			const auto architecture = function->GetArchitecture();
			const auto type = function->GetType();
			const auto addressText = HexAddress(function->GetStart());
			const auto name = symbol ? symbol->GetShortName() : addressText;
			const auto architectureName = architecture ? architecture->GetName() : std::string {};
			const auto platformName = platform->GetName();
			const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("name");
			writer.String(name.data(), name.size());
			writer.Key("architecture");
			writer.String(architectureName.data(), architectureName.size());
			writer.Key("platform");
			writer.String(platformName.data(), platformName.size());
			writer.Key("type");
			writer.String(typeText.data(), typeText.size());
			writer.Key("created");
			writer.Bool(created);
			writer.Key("autoDiscovered");
			writer.Bool(function->WasAutomaticallyDiscovered());
			writer.Key("needsUpdate");
			writer.Bool(function->NeedsUpdate());
			writer.Key("nextAction");
			writer.String("Call bn_analysis_update_and_wait, then bn_binary_view_save to persist the user function.");
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SectionListTool, "bn_section_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("section-list arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto sections = state->view->GetSections();
			std::sort(sections.begin(), sections.end(), [](const auto& left, const auto& right) {
				if (left->GetStart() != right->GetStart())
					return left->GetStart() < right->GetStart();
				return left->GetName() < right->GetName();
			});
			offset = std::min(offset, sections.size());
			const auto finish = offset + std::min(limit, sections.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("sections");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& section = sections[index];
				const auto name = section->GetName();
				const auto start = HexAddress(section->GetStart());
				const auto end = HexAddress(section->GetEnd());
				writer.StartObject();
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("start");
				writer.String(start.data(), start.size());
				writer.Key("end");
				writer.String(end.data(), end.size());
				writer.Key("semantics");
				writer.String(SectionSemanticsName(section->GetSemantics()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(sections.size());
			writer.Key("nextOffset");
			if (finish < sections.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < sections.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SegmentListTool, "bn_segment_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("segment-list arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto segments = state->view->GetSegments();
			std::sort(segments.begin(), segments.end(), [](const auto& left, const auto& right) {
				return left->GetStart() < right->GetStart();
			});
			offset = std::min(offset, segments.size());
			const auto finish = offset + std::min(limit, segments.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("segments");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& segment = segments[index];
				const auto flags = segment->GetFlags();
				const auto start = HexAddress(segment->GetStart());
				const auto end = HexAddress(segment->GetEnd());
				const auto dataOffset = HexAddress(segment->GetDataOffset());
				const auto dataEnd = HexAddress(segment->GetDataEnd());
				writer.StartObject();
				writer.Key("segment");
				writer.String(start.data(), start.size());
				writer.Key("start");
				writer.String(start.data(), start.size());
				writer.Key("end");
				writer.String(end.data(), end.size());
				writer.Key("length");
				writer.Uint64(segment->GetLength());
				writer.Key("dataOffset");
				writer.String(dataOffset.data(), dataOffset.size());
				writer.Key("dataLength");
				writer.Uint64(segment->GetDataLength());
				writer.Key("dataEnd");
				writer.String(dataEnd.data(), dataEnd.size());
				writer.Key("flags");
				writer.Uint(flags);
				writer.Key("flagNames");
				writer.StartArray();
				for (const auto name : SegmentFlagNames(flags))
					writer.String(name.data(), name.size());
				writer.EndArray();
				writer.Key("readable");
				writer.Bool((flags & SegmentReadable) != 0);
				writer.Key("writable");
				writer.Bool((flags & SegmentWritable) != 0);
				writer.Key("executable");
				writer.Bool((flags & SegmentExecutable) != 0);
				writer.Key("containsData");
				writer.Bool((flags & SegmentContainsData) != 0);
				writer.Key("containsCode");
				writer.Bool((flags & SegmentContainsCode) != 0);
				writer.Key("denyWrite");
				writer.Bool((flags & SegmentDenyWrite) != 0);
				writer.Key("denyExecute");
				writer.Bool((flags & SegmentDenyExecute) != 0);
				writer.Key("autoDefined");
				writer.Bool(segment->IsAutoDefined());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(segments.size());
			writer.Key("nextOffset");
			if (finish < segments.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < segments.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(MemoryReadTool, "bn_memory_read")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString()
				|| !arguments.HasMember("length"))
				throw std::invalid_argument("memory address and length are required");
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid memory expression" : error);
				return result;
			};
			const auto address = parseExpression(arguments["address"]);
			const auto& lengthValue = arguments["length"];
			if (!lengthValue.IsUint64() && !lengthValue.IsString())
				throw std::invalid_argument("memory length must be an integer or expression");
			const auto length = lengthValue.IsUint64() ? lengthValue.GetUint64() : parseExpression(lengthValue);
			if (length > 65536)
				throw std::invalid_argument("memory read length exceeds 65536 bytes");
			const auto data = state->view->ReadBuffer(address, static_cast<std::size_t>(length));
			const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
			const auto hex = HexBytes({bytes, data.GetLength()});
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("bytesRead");
			writer.Uint64(data.GetLength());
			writer.Key("hex");
			writer.String(hex.data(), hex.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(DataVariableListTool, "bn_data_variable_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("data-variable arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
				address = parseExpression(value->value);
			if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
				start = parseExpression(value->value);
			if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
				end = parseExpression(value->value);
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
			{
				const auto length = value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("data-variable range length is invalid");
				end = *start + length;
			}
			std::vector<BinaryNinja::DataVariable> variables;
			for (const auto& [variableAddress, variable] : state->view->GetDataVariables())
			{
				if (address && variableAddress != *address)
					continue;
				if (start && variableAddress < *start)
					continue;
				if (end && variableAddress >= *end)
					continue;
				variables.push_back(variable);
			}
			offset = std::min(offset, variables.size());
			const auto finish = offset + std::min(limit, variables.size() - offset);
			const auto platform = state->view->GetDefaultPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("dataVariables");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& variable = variables[index];
				const auto type = variable.type.GetValue();
				const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
				const auto addressText = HexAddress(variable.address);
				writer.StartObject();
				writer.Key("address");
				writer.String(addressText.data(), addressText.size());
				writer.Key("type");
				writer.String(typeText.data(), typeText.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(variables.size());
			writer.Key("nextOffset");
			if (finish < variables.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < variables.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(DataAtTool, "bn_data_at")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("data address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid data address" : parseError);

			BinaryNinja::DataVariable dataVariable;
			bool hasDataVariable = state->view->GetDataVariableAtAddress(address, dataVariable);
			bool exactDataVariable = hasDataVariable;
			if (!hasDataVariable)
			{
				const auto variables = state->view->GetDataVariables();
				auto candidate = variables.upper_bound(address);
				if (candidate != variables.begin())
				{
					--candidate;
					const auto type = candidate->second.type.GetValue();
					if (type && address - candidate->first < type->GetWidth())
					{
						dataVariable = candidate->second;
						hasDataVariable = true;
					}
				}
			}
			std::string formatted;
			if (hasDataVariable)
			{
				const auto type = dataVariable.type.GetValue();
				if (type)
				{
					std::vector<BinaryNinja::InstructionTextToken> prefix;
					std::vector<std::pair<BinaryNinja::Type*, std::size_t>> context;
					const auto lines = BinaryNinja::DataRendererContainer::RenderLinesForData(
						state->view, dataVariable.address, type, prefix, 80, context);
					for (std::size_t index = 0; index < lines.size(); ++index)
					{
						if (index != 0)
							formatted += '\n';
						formatted += TokenText(lines[index].tokens);
					}
				}
			}
			const auto data = state->view->ReadBuffer(address, 32);
			const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
			const auto hex = HexBytes({bytes, data.GetLength()});
			const auto addressText = HexAddress(address);
			const auto platform = state->view->GetDefaultPlatform();
			const auto symbols = state->view->GetSymbols(address, 1);
			const auto functions = state->view->GetAnalysisFunctionsContainingAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("dataVariable");
			if (hasDataVariable)
			{
				const auto type = dataVariable.type.GetValue();
				const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
				writer.StartObject();
				writer.Key("type");
				writer.String(typeText.data(), typeText.size());
				writer.Key("formatted");
				writer.String(formatted.data(), formatted.size());
				writer.Key("confidence");
				writer.Uint(dataVariable.type.GetConfidence());
				writer.Key("autoDiscovered");
				writer.Bool(dataVariable.autoDiscovered);
				writer.EndObject();
			}
			else
				writer.Null();
			writer.Key("exactDataVariable");
			writer.Bool(exactDataVariable);
			writer.Key("memory");
			writer.StartObject();
			writer.Key("bytesRead");
			writer.Uint64(data.GetLength());
			writer.Key("hex");
			writer.String(hex.data(), hex.size());
			writer.EndObject();
			const auto comment = state->view->GetCommentForAddress(address);
			writer.Key("comment");
			writer.String(comment.data(), comment.size());
			writer.Key("symbols");
			writer.StartArray();
			for (const auto& symbol : symbols)
			{
				if (symbol->GetAddress() != address)
					continue;
				const auto name = symbol->GetFullName();
				writer.StartObject();
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("type");
				writer.String(SymbolTypeName(symbol->GetType()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("functions");
			writer.StartArray();
			for (const auto& function : functions)
			{
				const auto functionAddress = HexAddress(function->GetStart());
				const auto symbol = function->GetSymbol();
				const auto name = symbol ? symbol->GetShortName() : functionAddress;
				writer.StartObject();
				writer.Key("address");
				writer.String(functionAddress.data(), functionAddress.size());
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(RelocationListTool, "bn_relocation_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("relocation arguments must be an object");
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
				address = parseExpression(value->value);
			if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
				start = parseExpression(value->value);
			if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
				end = parseExpression(value->value);
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
			{
				const auto length = value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("relocation range length is invalid");
				end = *start + length;
			}
			if (start && end && *end < *start)
				throw std::invalid_argument("relocation range end must not precede start");
			std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
			if (address)
				ranges = state->view->GetRelocationRangesAtAddress(*address);
			else if (start && end)
				ranges = state->view->GetRelocationRangesInRange(*start, static_cast<std::size_t>(*end - *start));
			else
				ranges = state->view->GetRelocationRanges();
			std::vector<BinaryNinja::Ref<BinaryNinja::Relocation>> relocations;
			for (const auto& [rangeStart, rangeEnd] : ranges)
			{
				if (rangeEnd <= rangeStart)
					continue;
				for (const auto& relocation : state->view->GetRelocationsAt(rangeStart))
				{
					if (address && relocation->GetAddress() != *address)
						continue;
					if (start && relocation->GetAddress() < *start)
						continue;
					if (end && relocation->GetAddress() >= *end)
						continue;
					relocations.push_back(relocation);
				}
			}
			std::sort(relocations.begin(), relocations.end(), [](const auto& left, const auto& right) {
				if (left->GetAddress() != right->GetAddress())
					return left->GetAddress() < right->GetAddress();
				return left->GetTarget() < right->GetTarget();
			});
			relocations.erase(
				std::unique(relocations.begin(), relocations.end(),
					[](const auto& left, const auto& right) {
						return left->GetAddress() == right->GetAddress() && left->GetTarget() == right->GetTarget();
					}),
				relocations.end());
			offset = std::min(offset, relocations.size());
			const auto finish = offset + std::min(limit, relocations.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("relocations");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto& relocation = relocations[index];
				const auto info = relocation->GetInfo();
				const auto relocationAddress = HexAddress(relocation->GetAddress());
				const auto target = HexAddress(relocation->GetTarget());
				const auto architecture = relocation->GetArchitecture();
				const auto architectureName = architecture ? architecture->GetName() : std::string {};
				const auto symbol = relocation->GetSymbol();
				writer.StartObject();
				writer.Key("address");
				writer.String(relocationAddress.data(), relocationAddress.size());
				writer.Key("target");
				writer.String(target.data(), target.size());
				writer.Key("architecture");
				writer.String(architectureName.data(), architectureName.size());
				writer.Key("symbol");
				if (symbol)
				{
					const auto symbolAddress = HexAddress(symbol->GetAddress());
					writer.String(symbolAddress.data(), symbolAddress.size());
				}
				else
					writer.Null();
				writer.Key("symbolName");
				if (symbol)
				{
					const auto symbolName = symbol->GetFullName();
					writer.String(symbolName.data(), symbolName.size());
				}
				else
					writer.Null();
				writer.Key("type");
				writer.Uint(info.type);
				writer.Key("nativeType");
				writer.Uint64(info.nativeType);
				writer.Key("external");
				writer.Bool(info.external);
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(relocations.size());
			writer.Key("nextOffset");
			if (finish < relocations.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < relocations.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(DataXrefsFromTool, "bn_data_xrefs_from")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("data reference address must be a string");
			auto parseExpression = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid data reference expression" : error);
				return result;
			};
			const auto address = parseExpression(arguments["address"]);
			std::optional<std::uint64_t> length;
			if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
				length = value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
			std::size_t offset = 0;
			std::size_t limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			const bool incoming = command.name() == "bn_data_xrefs_to";
			auto references = incoming ?
				(length ? state->view->GetDataReferences(address, *length) : state->view->GetDataReferences(address)) :
				(length ? state->view->GetDataReferencesFrom(address, *length) :
						  state->view->GetDataReferencesFrom(address));
			std::sort(references.begin(), references.end());
			references.erase(std::unique(references.begin(), references.end()), references.end());
			offset = std::min(offset, references.size());
			const auto finish = offset + std::min(limit, references.size() - offset);
			const auto platform = state->view->GetDefaultPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("references");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				const auto reference = HexAddress(references[index]);
				BinaryNinja::DataVariable variable;
				writer.StartObject();
				writer.Key(incoming ? "source" : "target");
				writer.String(reference.data(), reference.size());
				writer.Key("dataVariable");
				if (state->view->GetDataVariableAtAddress(references[index], variable))
				{
					const auto type = variable.type.GetValue();
					const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
					writer.StartObject();
					writer.Key("address");
					writer.String(reference.data(), reference.size());
					writer.Key("type");
					writer.String(typeText.data(), typeText.size());
					writer.EndObject();
				}
				else
					writer.Null();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(references.size());
			writer.Key("nextOffset");
			if (finish < references.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < references.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(DataXrefsToTool, "bn_data_xrefs_to")
		{
			return DataXrefsFromTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(CommentListTool, "bn_comment_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("search arguments must be an object");
			std::size_t offset = 0, limit = 50;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = static_cast<std::size_t>(value->value.GetUint64());
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = static_cast<std::size_t>(value->value.GetUint64());
			bool caseSensitive = false;
			if (const auto value = arguments.FindMember("caseSensitive"); value != arguments.MemberEnd())
				caseSensitive = value->value.GetBool();
			auto stringArgument = [&](const char* name, bool required = true) {
				const auto value = arguments.FindMember(name);
				if (value == arguments.MemberEnd())
				{
					if (required)
						throw std::invalid_argument(std::string(name) + " is required");
					return std::string {};
				}
				if (!value->value.IsString())
					throw std::invalid_argument(std::string(name) + " must be a string");
				return std::string(value->value.GetString(), value->value.GetStringLength());
			};
			auto parseAddress = [&](const char* name, std::uint64_t fallback) {
				const auto value = arguments.FindMember(name);
				if (value == arguments.MemberEnd())
					return fallback;
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(state->view,
						std::string(value->value.GetString(), value->value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
				return result;
			};
			const auto start = parseAddress("start", state->view->GetStart());
			const auto end = parseAddress("end", state->view->GetEnd());
			if (end < start)
				throw std::invalid_argument("end must not precede start");
			struct Match
			{
				std::uint64_t address;
				std::string kind;
				std::string text;
				std::string function;
				std::string level {};
			};
			std::vector<Match> matches;
			std::string searchMode;
			std::string constantLevel;
			bool constantAnalysisComplete = false;
			const auto name = command.name();
			if (name == "bn_comment_list" || name == "bn_comment_search")
			{
				const auto query = name == "bn_comment_search" ? Lower(stringArgument("query")) : std::string {};
				for (const auto address : state->view->GetCommentedAddresses())
				{
					const auto comment = state->view->GetCommentForAddress(address);
					if (query.empty() || Lower(comment).find(query) != std::string::npos)
						matches.push_back({address, "comment", comment, {}});
				}
			}
			else if (name == "bn_memory_search")
			{
				const auto pattern = stringArgument("pattern");
				if (pattern.empty())
					throw std::invalid_argument("pattern must not be empty");
				if (end == start)
					throw std::invalid_argument("end must be greater than start");
				auto booleanArgument = [&](const char* argument, bool fallback) {
					const auto value = arguments.FindMember(argument);
					if (value == arguments.MemberEnd())
						return fallback;
					if (!value->value.IsBool())
						throw std::invalid_argument(std::string(argument) + " must be a boolean");
					return value->value.GetBool();
				};
				const auto raw = booleanArgument("raw", false);
				const auto searchCaseSensitive = booleanArgument("caseSensitive", false);
				const auto overlap = booleanArgument("overlap", false);
				std::uint64_t alignment = 1;
				if (const auto value = arguments.FindMember("alignment"); value != arguments.MemberEnd())
				{
					if (!value->value.IsUint64())
						throw std::invalid_argument("alignment must be a positive integer");
					alignment = value->value.GetUint64();
				}
				if (alignment == 0 || (alignment & (alignment - 1)) != 0)
					throw std::invalid_argument("alignment must be a positive power of two");

				rapidjson::StringBuffer searchBuffer;
				rapidjson::Writer<rapidjson::StringBuffer> searchWriter(searchBuffer);
				searchWriter.StartObject();
				searchWriter.Key("pattern");
				searchWriter.String(pattern.data(), pattern.size());
				searchWriter.Key("start");
				searchWriter.Uint64(start);
				searchWriter.Key("end");
				searchWriter.Uint64(end == std::numeric_limits<std::uint64_t>::max() ? end : end - 1);
				searchWriter.Key("raw");
				searchWriter.Bool(raw);
				searchWriter.Key("ignoreCase");
				searchWriter.Bool(!searchCaseSensitive);
				searchWriter.Key("overlap");
				searchWriter.Bool(overlap);
				searchWriter.Key("align");
				searchWriter.Uint64(alignment);
				searchWriter.EndObject();
				const std::string searchQuery(searchBuffer.GetString(), searchBuffer.GetSize());
				searchMode = state->view->DetectSearchMode(searchQuery);
				const auto searched = state->view->Search(
					searchQuery, [](std::size_t, std::size_t) { return true; },
					[&](std::uint64_t address, const BinaryNinja::DataBuffer& match) {
						if (address < start || address >= end)
							return true;
						const auto* bytes = static_cast<const std::uint8_t*>(match.GetData());
						matches.push_back({address, "memory", HexBytes({bytes, match.GetLength()}), {}});
						return true;
					});
				if (!searched)
					throw std::runtime_error("Binary Ninja memory search failed");
			}
			else if (name == "bn_instruction_search")
			{
				const auto query = stringArgument("query");
				const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
				const auto flags = caseSensitive ? FindCaseSensitive : FindCaseInsensitive;
				state->view->FindAllText(
					start, end, query, settings, flags, NormalFunctionGraph,
					[](std::size_t, std::size_t) { return true; },
					[&](std::uint64_t address, const std::string&, const BinaryNinja::LinearDisassemblyLine& line) {
						matches.push_back({address, "instruction", TokenText(line.contents.tokens), {}});
						return true;
					});
			}
			else if (name == "bn_constant_search")
			{
				const auto expression = stringArgument("value");
				std::uint64_t constant = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(state->view, expression, constant, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid constant expression" : error);
				if (end == start)
					throw std::invalid_argument("end must be greater than start");
				constantLevel = stringArgument("level", false);
				if (constantLevel.empty())
					constantLevel = "llil";
				if (constantLevel != "all" && constantLevel != "disassembly" && constantLevel != "llil"
					&& constantLevel != "mlil" && constantLevel != "hlil")
					throw std::invalid_argument("level must be all, disassembly, llil, mlil, or hlil");
				constantAnalysisComplete = state->view->HasInitialAnalysis()
					&& state->view->GetAnalysisState() == IdleState && !state->view->AnalysisIsAborted();
				if ((constantLevel == "all" || constantLevel == "mlil" || constantLevel == "hlil")
					&& !constantAnalysisComplete)
					throw std::runtime_error(
						"complete analysis is required for this constant-search level; call "
						"bn_analysis_update_and_wait");
				const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
				auto containsConstant = [&](const std::vector<BinaryNinja::InstructionTextToken>& tokens) {
					return std::any_of(tokens.begin(), tokens.end(), [&](const auto& token) {
						return BinaryNinja::DisassemblyTextRenderer::IsIntegerToken(token.type)
							&& token.value == constant;
					});
				};
				auto addBlocks =
					[&](const BinaryNinja::Ref<BinaryNinja::Function>& function, std::string_view level,
						const std::vector<BinaryNinja::Ref<BinaryNinja::BasicBlock>>& blocks) {
						const auto functionName = function->GetSymbol()->GetFullName();
						for (const auto& block : blocks)
							for (const auto& line : block->GetDisassemblyText(settings))
								if (line.addr >= start && line.addr < end && containsConstant(line.tokens))
									matches.push_back({line.addr, "constant", TokenText(line.tokens), functionName,
										std::string(level)});
					};
				auto addLevel = [&](const BinaryNinja::Ref<BinaryNinja::Function>& function, std::string_view level) {
					if (level == "disassembly")
						addBlocks(function, level, function->GetBasicBlocks());
					else if (level == "llil")
					{
						if (const auto il = function->GetLowLevelILIfAvailable())
							addBlocks(function, level, il->GetBasicBlocks());
					}
					else if (level == "mlil")
					{
						if (const auto il = function->GetMediumLevelILIfAvailable())
							addBlocks(function, level, il->GetBasicBlocks());
					}
					else if (level == "hlil")
					{
						if (const auto il = function->GetHighLevelILIfAvailable())
							addBlocks(function, level, il->GetBasicBlocks());
					}
				};
				for (const auto& function : state->view->GetAnalysisFunctionList())
				{
					if (constantLevel == "all")
					{
						addLevel(function, "hlil");
						addLevel(function, "mlil");
						addLevel(function, "llil");
						addLevel(function, "disassembly");
					}
					else
						addLevel(function, constantLevel);
				}
				std::set<std::uint64_t> seenAddresses;
				matches.erase(
					std::remove_if(matches.begin(), matches.end(),
						[&](const auto& match) { return !seenAddresses.insert(match.address).second; }),
					matches.end());
			}
			else if (name == "bn_il_search")
			{
				auto query = stringArgument("query");
				if (!caseSensitive)
					query = Lower(query);
				auto functionQuery = Lower(stringArgument("functionQuery", false));
				const auto level = stringArgument("level", false).empty() ? "hlil" : stringArgument("level");
				bool ssa = false;
				if (const auto value = arguments.FindMember("ssa"); value != arguments.MemberEnd())
					ssa = value->value.GetBool();
				const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
				for (const auto& function : state->view->GetAnalysisFunctionList())
				{
					if (!functionQuery.empty()
						&& Lower(function->GetSymbol()->GetFullName()).find(functionQuery) == std::string::npos)
						continue;
					std::vector<BinaryNinja::Ref<BinaryNinja::BasicBlock>> blocks;
					if (level == "llil")
					{
						auto il = function->GetLowLevelILIfAvailable();
						if (!il)
							continue;
						if (ssa)
							il = il->GetSSAForm();
						blocks = il->GetBasicBlocks();
					}
					else if (level == "mlil")
					{
						auto il = function->GetMediumLevelILIfAvailable();
						if (!il)
							continue;
						if (ssa)
							il = il->GetSSAForm();
						blocks = il->GetBasicBlocks();
					}
					else if (level == "hlil")
					{
						auto il = function->GetHighLevelILIfAvailable();
						if (!il)
							continue;
						if (ssa)
							il = il->GetSSAForm();
						blocks = il->GetBasicBlocks();
					}
					else
						throw std::invalid_argument("level must be llil, mlil, or hlil");
					for (const auto& block : blocks)
						for (const auto& line : block->GetDisassemblyText(settings))
						{
							const auto text = TokenText(line.tokens);
							const auto comparable = caseSensitive ? text : Lower(text);
							if (comparable.find(query) != std::string::npos)
								matches.push_back({line.addr, level, text, function->GetSymbol()->GetFullName()});
						}
				}
			}
			else if (name == "bn_project_analysis_search")
			{
				const auto query = Lower(stringArgument("query"));
				for (const auto& function : state->view->GetAnalysisFunctionList())
				{
					const auto text = function->GetSymbol()->GetFullName();
					if (Lower(text).find(query) != std::string::npos)
						matches.push_back({function->GetStart(), "function", text, text});
				}
				for (const auto& symbol : state->view->GetSymbols())
					if (Lower(symbol->GetFullName()).find(query) != std::string::npos)
						matches.push_back({symbol->GetAddress(), "symbol", symbol->GetFullName(), {}});
				for (const auto& string : state->view->GetStrings())
				{
					const auto detected = ReadDetectedString(state->view, string.type, string.start, string.length);
					const auto preview = DecodeString(detected.type, detected.bytes, 128);
					if (Lower(preview.text).find(query) != std::string::npos)
						matches.push_back({string.start, "string", preview.text, {}});
				}
				for (const auto address : state->view->GetCommentedAddresses())
				{
					const auto text = state->view->GetCommentForAddress(address);
					if (Lower(text).find(query) != std::string::npos)
						matches.push_back({address, "comment", text, {}});
				}
			}
			else
				throw std::invalid_argument("unknown search tool");
			std::sort(matches.begin(), matches.end(), [](const auto& left, const auto& right) {
				if (left.address != right.address)
					return left.address < right.address;
				if (left.kind != right.kind)
					return left.kind < right.kind;
				return left.text < right.text;
			});
			offset = std::min(offset, matches.size());
			const auto finish = offset + std::min(limit, matches.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			if (!searchMode.empty())
			{
				writer.Key("searchMode");
				writer.String(searchMode.data(), searchMode.size());
			}
			if (!constantLevel.empty())
			{
				writer.Key("level");
				writer.String(constantLevel.data(), constantLevel.size());
				writer.Key("analysisComplete");
				writer.Bool(constantAnalysisComplete);
				writer.Key("partial");
				writer.Bool(!constantAnalysisComplete);
			}
			writer.Key("matches");
			writer.StartArray();
			for (std::size_t index = offset; index < finish; ++index)
			{
				const auto& match = matches[index];
				writer.StartObject();
				writer.Key("address");
				const auto address = HexAddress(match.address);
				writer.String(address.data(), address.size());
				writer.Key("kind");
				writer.String(match.kind.data(), match.kind.size());
				writer.Key("text");
				writer.String(match.text.data(), match.text.size());
				if (!match.level.empty())
				{
					writer.Key("level");
					writer.String(match.level.data(), match.level.size());
				}
				if (!match.function.empty())
				{
					writer.Key("function");
					writer.String(match.function.data(), match.function.size());
				}
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(matches.size());
			writer.Key("nextOffset");
			if (finish < matches.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < matches.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(CommentSearchTool, "bn_comment_search")
		{
			return CommentListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(MemorySearchTool, "bn_memory_search")
		{
			return CommentListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(InstructionSearchTool, "bn_instruction_search")
		{
			return CommentListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(IlSearchTool, "bn_il_search")
		{
			return CommentListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(ConstantSearchTool, "bn_constant_search")
		{
			return CommentListTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(ProjectAnalysisSearchTool, "bn_project_analysis_search")
		{
			return CommentListTool().Execute(command);
		};

#undef BINJAD_ANALYSIS_TOOL
	}  // namespace

	void RegisterAnalysisToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<FunctionListTool>());
		tools.emplace_back(std::make_unique<FunctionInfoTool>());
		tools.emplace_back(std::make_unique<FunctionCallersTool>());
		tools.emplace_back(std::make_unique<FunctionCalleesTool>());
		tools.emplace_back(std::make_unique<FunctionDisassemblyTool>());
		tools.emplace_back(std::make_unique<FunctionDecompileTool>());
		tools.emplace_back(std::make_unique<FunctionIlTool>());
		tools.emplace_back(std::make_unique<FunctionStackLayoutTool>());
		tools.emplace_back(std::make_unique<VariableListTool>());
		tools.emplace_back(std::make_unique<CallingConventionListTool>());
		tools.emplace_back(std::make_unique<FunctionXrefsFromTool>());
		tools.emplace_back(std::make_unique<FunctionXrefsToTool>());
		tools.emplace_back(std::make_unique<StringListTool>());
		tools.emplace_back(std::make_unique<StringAtTool>());
		tools.emplace_back(std::make_unique<SymbolListTool>());
		tools.emplace_back(std::make_unique<ImportListTool>());
		tools.emplace_back(std::make_unique<ExportListTool>());
		tools.emplace_back(std::make_unique<SymbolListAtTool>());
		tools.emplace_back(std::make_unique<EntryPointListTool>());
		tools.emplace_back(std::make_unique<EntryPointAddTool>());
		tools.emplace_back(std::make_unique<FunctionCreateTool>());
		tools.emplace_back(std::make_unique<SectionListTool>());
		tools.emplace_back(std::make_unique<SegmentListTool>());
		tools.emplace_back(std::make_unique<MemoryReadTool>());
		tools.emplace_back(std::make_unique<DataVariableListTool>());
		tools.emplace_back(std::make_unique<DataAtTool>());
		tools.emplace_back(std::make_unique<RelocationListTool>());
		tools.emplace_back(std::make_unique<DataXrefsFromTool>());
		tools.emplace_back(std::make_unique<DataXrefsToTool>());
		tools.emplace_back(std::make_unique<CommentListTool>());
		tools.emplace_back(std::make_unique<CommentSearchTool>());
		tools.emplace_back(std::make_unique<MemorySearchTool>());
		tools.emplace_back(std::make_unique<InstructionSearchTool>());
		tools.emplace_back(std::make_unique<IlSearchTool>());
		tools.emplace_back(std::make_unique<ConstantSearchTool>());
		tools.emplace_back(std::make_unique<ProjectAnalysisSearchTool>());
	}
}  // namespace binjad
