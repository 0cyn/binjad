#include "../ToolCall.hpp"
#include "../ToolSupport.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <set>

namespace binjad {
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

		BINJAD_ANALYSIS_TOOL(CommentGetTool, "bn_comment_get")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("comment address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& value = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(
					state->view, std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid comment address" : parseError);
			const auto comment = state->view->GetCommentForAddress(address);
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("text");
			writer.String(comment.data(), comment.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(CommentSetTool, "bn_comment_set")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString()
				|| !arguments.HasMember("text") || !arguments["text"].IsString()
				|| arguments["text"].GetStringLength() == 0)
				throw std::invalid_argument("comment address and non-empty text are required");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid comment address" : parseError);
			const std::string text(arguments["text"].GetString(), arguments["text"].GetStringLength());
			state->view->SetCommentForAddress(address, text);
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("text");
			writer.String(text.data(), text.size());
			writer.Key("updated");
			writer.Bool(true);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(CommentDeleteTool, "bn_comment_delete")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("comment address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid comment address" : parseError);
			state->view->SetCommentForAddress(address, "");
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("deleted");
			writer.Bool(true);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SymbolDefineTool, "bn_symbol_define")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString()
				|| !arguments.HasMember("name") || !arguments["name"].IsString()
				|| arguments["name"].GetStringLength() == 0)
				throw std::invalid_argument("symbol address and non-empty name are required");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
			const std::string name(arguments["name"].GetString(), arguments["name"].GetStringLength());
			auto type = DataSymbol;
			auto binding = NoBinding;
			std::string nameSpace;
			std::uint64_t ordinal = 0;
			if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd())
				type = ParseSymbolType({value->value.GetString(), value->value.GetStringLength()});
			if (const auto value = arguments.FindMember("binding"); value != arguments.MemberEnd())
				binding = ParseSymbolBinding({value->value.GetString(), value->value.GetStringLength()});
			if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
				nameSpace.assign(value->value.GetString(), value->value.GetStringLength());
			if (const auto value = arguments.FindMember("ordinal"); value != arguments.MemberEnd())
				ordinal = value->value.GetUint64();
			const BinaryNinja::NameSpace symbolNameSpace = nameSpace.empty() ?
				BinaryNinja::NameSpace(DEFAULT_INTERNAL_NAMESPACE) :
				BinaryNinja::NameSpace(nameSpace);
			BinaryNinja::Ref<BinaryNinja::Symbol> symbol =
				new BinaryNinja::Symbol(type, name, address, binding, symbolNameSpace, ordinal);
			state->view->DefineUserSymbol(symbol);
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("symbol");
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("type");
			writer.String(SymbolTypeName(type));
			writer.Key("shortName");
			writer.String(name.data(), name.size());
			writer.Key("fullName");
			writer.String(name.data(), name.size());
			writer.Key("rawName");
			writer.String(name.data(), name.size());
			writer.Key("namespace");
			writer.StartArray();
			for (const auto& component : symbolNameSpace)
				writer.String(component.data(), component.size());
			writer.EndArray();
			writer.Key("ordinal");
			writer.Uint64(ordinal);
			writer.Key("binding");
			writer.String(SymbolBindingName(binding));
			writer.Key("autoDefined");
			writer.Bool(false);
			writer.EndObject();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SymbolRenameTool, "bn_symbol_rename")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString()
				|| !arguments.HasMember("newName") || !arguments["newName"].IsString()
				|| arguments["newName"].GetStringLength() == 0)
				throw std::invalid_argument("symbol address and non-empty newName are required");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
			auto symbols = state->view->GetSymbols(address, 1);
			std::erase_if(symbols, [&](const auto& symbol) {
				if (symbol->GetAddress() != address)
					return true;
				if (const auto value = arguments.FindMember("name"); value != arguments.MemberEnd())
				{
					const std::string wanted(value->value.GetString(), value->value.GetStringLength());
					if (symbol->GetShortName() != wanted && symbol->GetFullName() != wanted
						&& symbol->GetRawName() != wanted)
						return true;
				}
				if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd()
					&& symbol->GetType() != ParseSymbolType({value->value.GetString(), value->value.GetStringLength()}))
					return true;
				if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
				{
					std::string wanted(value->value.GetString(), value->value.GetStringLength());
					if (wanted.empty())
						wanted = DEFAULT_INTERNAL_NAMESPACE;
					if (symbol->GetNameSpace().GetString() != wanted)
						return true;
				}
				if (const auto value = arguments.FindMember("ordinal");
					value != arguments.MemberEnd() && symbol->GetOrdinal() != value->value.GetUint64())
					return true;
				return false;
			});
			if (symbols.empty())
				throw std::invalid_argument("symbol not found");
			if (symbols.size() != 1)
				throw std::invalid_argument("symbol selector is ambiguous");
			const auto& current = symbols.front();
			const std::string newName(arguments["newName"].GetString(), arguments["newName"].GetStringLength());
			const auto nameSpace = current->GetNameSpace();
			BinaryNinja::Ref<BinaryNinja::Symbol> replacement = new BinaryNinja::Symbol(
				current->GetType(), newName, address, current->GetBinding(), nameSpace, current->GetOrdinal());
			state->view->DefineUserSymbol(replacement);
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("symbol");
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("type");
			writer.String(SymbolTypeName(current->GetType()));
			writer.Key("shortName");
			writer.String(newName.data(), newName.size());
			writer.Key("fullName");
			writer.String(newName.data(), newName.size());
			writer.Key("rawName");
			writer.String(newName.data(), newName.size());
			writer.Key("namespace");
			writer.StartArray();
			for (const auto& component : nameSpace)
				writer.String(component.data(), component.size());
			writer.EndArray();
			writer.Key("ordinal");
			writer.Uint64(current->GetOrdinal());
			writer.Key("binding");
			writer.String(SymbolBindingName(current->GetBinding()));
			writer.Key("autoDefined");
			writer.Bool(false);
			writer.EndObject();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SymbolUndefineTool, "bn_symbol_undefine")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("address") || !arguments["address"].IsString())
				throw std::invalid_argument("symbol address must be a string");
			std::uint64_t address = 0;
			std::string parseError;
			const auto& addressValue = arguments["address"];
			if (!BinaryNinja::BinaryView::ParseExpression(state->view,
					std::string(addressValue.GetString(), addressValue.GetStringLength()), address, 0, parseError))
				throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
			auto symbols = state->view->GetSymbols(address, 1);
			std::erase_if(symbols, [&](const auto& symbol) {
				if (symbol->GetAddress() != address || symbol->IsAutoDefined())
					return true;
				if (const auto value = arguments.FindMember("name"); value != arguments.MemberEnd())
				{
					const std::string wanted(value->value.GetString(), value->value.GetStringLength());
					if (symbol->GetShortName() != wanted && symbol->GetFullName() != wanted
						&& symbol->GetRawName() != wanted)
						return true;
				}
				if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd()
					&& symbol->GetType() != ParseSymbolType({value->value.GetString(), value->value.GetStringLength()}))
					return true;
				if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
				{
					std::string wanted(value->value.GetString(), value->value.GetStringLength());
					if (wanted.empty())
						wanted = DEFAULT_INTERNAL_NAMESPACE;
					if (symbol->GetNameSpace().GetString() != wanted)
						return true;
				}
				if (const auto value = arguments.FindMember("ordinal");
					value != arguments.MemberEnd() && symbol->GetOrdinal() != value->value.GetUint64())
					return true;
				return false;
			});
			if (symbols.empty())
				throw std::invalid_argument("user symbol not found");
			if (symbols.size() != 1)
				throw std::invalid_argument("symbol selector is ambiguous");
			state->view->UndefineUserSymbol(symbols.front());
			const auto addressText = HexAddress(address);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("address");
			writer.String(addressText.data(), addressText.size());
			writer.Key("deleted");
			writer.Bool(true);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(FunctionPrototypeSetTool, "bn_function_prototype_set")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("prototype") || !arguments["prototype"].IsString()
				|| arguments["prototype"].GetStringLength() == 0)
				throw std::invalid_argument("prototype must be a non-empty string");
			const auto function = ResolveFunction(command, arguments);
			const std::string prototype(arguments["prototype"].GetString(), arguments["prototype"].GetStringLength());
			BinaryNinja::QualifiedNameAndType parsed;
			std::string errors;
			if (!state->view->ParseTypeString(prototype, parsed, errors) || !parsed.type)
				throw std::invalid_argument(errors.empty() ? "invalid function prototype" : errors);
			if (parsed.type->GetClass() != FunctionTypeClass)
				throw std::invalid_argument("prototype must describe a function type");
			function->SetUserType(parsed.type);
			return FindFileChildToolCall("bn_function_info")->Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(CallingConventionSetTool, "bn_calling_convention_set")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("callingConvention")
				|| !arguments["callingConvention"].IsString() || arguments["callingConvention"].GetStringLength() == 0)
				throw std::invalid_argument("callingConvention must be a non-empty string");
			const auto function = ResolveFunction(command, arguments);
			const auto platform = function->GetPlatform();
			if (!platform)
				throw std::runtime_error("function has no platform");
			const std::string name(
				arguments["callingConvention"].GetString(), arguments["callingConvention"].GetStringLength());
			BinaryNinja::Ref<BinaryNinja::CallingConvention> selected;
			for (const auto& convention : platform->GetCallingConventions())
			{
				if (convention && convention->GetName() == name)
				{
					selected = convention;
					break;
				}
			}
			if (!selected)
				throw std::invalid_argument("calling convention is not available for the function platform");
			function->SetCallingConvention(
				BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::CallingConvention>>(selected, 255));
			return FindFileChildToolCall("bn_function_info")->Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(VariableRenameTool, "bn_variable_rename")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("variable") || !arguments["variable"].IsString()
				|| !arguments.HasMember("newName") || !arguments["newName"].IsString()
				|| arguments["newName"].GetStringLength() == 0)
				throw std::invalid_argument("variable and non-empty newName are required");
			const auto function = ResolveFunction(command, arguments);
			const std::string variableName(arguments["variable"].GetString(), arguments["variable"].GetStringLength());
			std::vector<BinaryNinja::VariableNameAndType> matches;
			for (const auto& entry : function->GetVariables())
			{
				const auto& variable = entry.second;
				if (variable.name != variableName)
					continue;
				if (const auto value = arguments.FindMember("source"); value != arguments.MemberEnd()
					&& variable.var.type
						!= ParseVariableSource({value->value.GetString(), value->value.GetStringLength()}))
					continue;
				if (const auto value = arguments.FindMember("index");
					value != arguments.MemberEnd() && variable.var.index != value->value.GetUint())
					continue;
				if (const auto value = arguments.FindMember("storage");
					value != arguments.MemberEnd() && variable.var.storage != value->value.GetInt64())
					continue;
				matches.push_back(variable);
			}
			if (matches.empty())
				throw std::invalid_argument("variable not found");
			if (matches.size() != 1)
				throw std::invalid_argument("variable selector is ambiguous");
			const std::string newName(arguments["newName"].GetString(), arguments["newName"].GetStringLength());
			const auto& variable = matches.front();
			function->CreateUserVariable(variable.var, variable.type, newName);
			const auto type = variable.type.GetValue();
			const auto platform = function->GetPlatform();
			const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string {};
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("variable");
			writer.StartObject();
			writer.Key("name");
			writer.String(newName.data(), newName.size());
			writer.Key("type");
			writer.String(typeText.data(), typeText.size());
			writer.Key("source");
			writer.String(VariableSourceName(variable.var.type));
			writer.Key("index");
			writer.Uint(variable.var.index);
			writer.Key("storage");
			writer.Int64(variable.var.storage);
			writer.EndObject();
			writer.Key("needsUpdate");
			writer.Bool(true);
			writer.Key("nextAction");
			writer.String("Call bn_analysis_update_and_wait before readback.");
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(VariableSetTypeTool, "bn_variable_set_type")
		{
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("variable") || !arguments["variable"].IsString())
				throw std::invalid_argument("variable must be a string");
			const auto function = ResolveFunction(command, arguments);
			const std::string variableName(arguments["variable"].GetString(), arguments["variable"].GetStringLength());
			std::vector<BinaryNinja::VariableNameAndType> matches;
			for (const auto& entry : function->GetVariables())
			{
				const auto& variable = entry.second;
				if (variable.name != variableName)
					continue;
				if (const auto value = arguments.FindMember("variableSource"); value != arguments.MemberEnd()
					&& variable.var.type
						!= ParseVariableSource({value->value.GetString(), value->value.GetStringLength()}))
					continue;
				if (const auto value = arguments.FindMember("index");
					value != arguments.MemberEnd() && variable.var.index != value->value.GetUint())
					continue;
				if (const auto value = arguments.FindMember("storage");
					value != arguments.MemberEnd() && variable.var.storage != value->value.GetInt64())
					continue;
				matches.push_back(variable);
			}
			if (matches.empty())
				throw std::invalid_argument("variable not found");
			if (matches.size() != 1)
				throw std::invalid_argument("variable selector is ambiguous");
			const auto parsedType = ParseRequestedType(command, arguments);
			const auto& variable = matches.front();
			const BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>> userType(parsedType, 255);
			function->CreateUserVariable(variable.var, userType, variable.name);
			const auto platform = function->GetPlatform();
			const auto typeText = parsedType->GetString(platform.GetPtr());
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("variable");
			writer.StartObject();
			writer.Key("name");
			writer.String(variable.name.data(), variable.name.size());
			writer.Key("type");
			writer.String(typeText.data(), typeText.size());
			writer.Key("source");
			writer.String(VariableSourceName(variable.var.type));
			writer.Key("index");
			writer.Uint(variable.var.index);
			writer.Key("storage");
			writer.Int64(variable.var.storage);
			writer.EndObject();
			writer.Key("needsUpdate");
			writer.Bool(true);
			writer.Key("nextAction");
			writer.String("Call bn_analysis_update_and_wait before readback.");
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeListTool, "bn_type_list")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject())
				throw std::invalid_argument("type-list arguments must be an object");
			std::size_t offset = 0, limit = kDefaultListLimit;
			if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
				offset = value->value.GetUint64();
			if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
				limit = value->value.GetUint64();
			std::string query;
			if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
				query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));
			std::vector<std::pair<std::string, BinaryNinja::Ref<BinaryNinja::Type>>> types;
			for (const auto& [name, type] : state->view->GetTypes())
			{
				const auto text = name.GetString();
				if (query.empty() || Lower(text).find(query) != std::string::npos)
					types.emplace_back(text, type);
			}
			offset = std::min(offset, types.size());
			const auto finish = offset + std::min(limit, types.size() - offset);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("types");
			writer.StartArray();
			for (auto index = offset; index < finish; ++index)
			{
				writer.StartObject();
				writer.Key("name");
				writer.String(types[index].first.data(), types[index].first.size());
				writer.Key("class");
				writer.String(TypeClassName(types[index].second->GetClass()));
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(finish - offset);
			writer.Key("total");
			writer.Uint64(types.size());
			writer.Key("nextOffset");
			if (finish < types.size())
				writer.Uint64(finish);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(finish < types.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeInfoTool, "bn_type_info")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("type") || !arguments["type"].IsString()
				|| arguments["type"].GetStringLength() == 0)
				throw std::invalid_argument("type must be a non-empty string");
			const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
			BinaryNinja::QualifiedName selectedName;
			BinaryNinja::Ref<BinaryNinja::Type> selectedType;
			for (const auto& [name, type] : state->view->GetTypes())
				if (name.GetString() == requested)
				{
					if (selectedType)
						throw std::invalid_argument("type name is ambiguous");
					selectedName = name;
					selectedType = type;
				}
			if (!selectedType)
				throw std::invalid_argument("type not found");
			const auto definition = RenderTypeDefinition(state->view, selectedName, selectedType);
			const auto typeId = state->view->GetTypeId(selectedName);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("name");
			writer.String(requested.data(), requested.size());
			writer.Key("id");
			writer.String(typeId.data(), typeId.size());
			writer.Key("class");
			writer.String(TypeClassName(selectedType->GetClass()));
			writer.Key("width");
			writer.Uint64(selectedType->GetWidth());
			writer.Key("alignment");
			writer.Uint64(selectedType->GetAlignment());
			writer.Key("autoDefined");
			writer.Bool(state->view->IsTypeAutoDefined(selectedName));
			writer.Key("definition");
			writer.String(definition.data(), definition.size());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeParseTool, "bn_type_parse")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("source") || !arguments["source"].IsString()
				|| arguments["source"].GetStringLength() == 0)
				throw std::invalid_argument("source must be a non-empty string");
			std::vector<std::string> options, includeDirs;
			auto readStrings = [&](const char* name, auto& output) {
				if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
				{
					if (!value->value.IsArray())
						throw std::invalid_argument(std::string(name) + " must be an array of strings");
					for (const auto& item : value->value.GetArray())
					{
						if (!item.IsString())
							throw std::invalid_argument(std::string(name) + " must be an array of strings");
						output.emplace_back(item.GetString(), item.GetStringLength());
					}
				}
			};
			readStrings("options", options);
			readStrings("includeDirs", includeDirs);
			bool importDependencies = true;
			if (const auto value = arguments.FindMember("importDependencies"); value != arguments.MemberEnd())
				importDependencies = value->value.GetBool();
			BinaryNinja::TypeParserResult parsed;
			std::string errors;
			const bool success = state->view->ParseTypesFromSource(
				std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()), options,
				includeDirs, parsed, errors, {}, importDependencies);
			const auto printer = BinaryNinja::TypePrinter::GetDefault();
			const auto platform = state->view->GetDefaultPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("success");
			writer.Bool(success);
			writer.Key("errors");
			writer.String(errors.data(), errors.size());
			auto writeTypes = [&](const char* key, const auto& values, bool fullDefinition) {
				writer.Key(key);
				writer.StartArray();
				for (const auto& value : values)
				{
					const auto name = value.name.GetString();
					const auto definition = fullDefinition ?
						RenderTypeDefinition(state->view, value.name, value.type) :
						printer->GetTypeString(value.type, platform, value.name) + ";";
					writer.StartObject();
					writer.Key("name");
					writer.String(name.data(), name.size());
					if (fullDefinition)
					{
						writer.Key("class");
						writer.String(TypeClassName(value.type->GetClass()));
					}
					writer.Key("definition");
					writer.String(definition.data(), definition.size());
					writer.EndObject();
				}
				writer.EndArray();
			};
			writeTypes("types", parsed.types, true);
			writeTypes("variables", parsed.variables, false);
			writeTypes("functions", parsed.functions, false);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeDefineTool, "bn_type_define")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("source") || !arguments["source"].IsString()
				|| arguments["source"].GetStringLength() == 0)
				throw std::invalid_argument("source must be a non-empty string");
			std::vector<std::string> options, includeDirs;
			auto readStrings = [&](const char* name, auto& output) {
				if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
				{
					if (!value->value.IsArray())
						throw std::invalid_argument(std::string(name) + " must be an array of strings");
					for (const auto& item : value->value.GetArray())
					{
						if (!item.IsString())
							throw std::invalid_argument(std::string(name) + " must be an array of strings");
						output.emplace_back(item.GetString(), item.GetStringLength());
					}
				}
			};
			readStrings("options", options);
			readStrings("includeDirs", includeDirs);
			bool importDependencies = true;
			if (const auto value = arguments.FindMember("importDependencies"); value != arguments.MemberEnd())
				importDependencies = value->value.GetBool();
			BinaryNinja::TypeParserResult parsed;
			std::string errors;
			if (!state->view->ParseTypesFromSource(
					std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()), options,
					includeDirs, parsed, errors, {}, importDependencies))
				throw std::invalid_argument(errors.empty() ? "invalid type source" : errors);
			std::vector<BinaryNinja::ParsedType> selected = parsed.types;
			if (const auto requested = arguments.FindMember("types"); requested != arguments.MemberEnd())
			{
				std::set<std::string> names;
				for (const auto& item : requested->value.GetArray())
					names.emplace(item.GetString(), item.GetStringLength());
				std::erase_if(selected, [&](const auto& type) { return !names.contains(type.name.GetString()); });
				for (const auto& name : names)
					if (std::none_of(selected.begin(), selected.end(), [&](const auto& type) {
							return type.name.GetString() == name;
						}))
						throw std::invalid_argument("parsed type not found: " + name);
			}
			if (selected.empty())
				throw std::invalid_argument("source contains no selected named types");
			state->view->DefineUserTypes(selected);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("types");
			writer.StartArray();
			for (const auto& parsedType : selected)
			{
				const auto name = parsedType.name.GetString();
				const auto stored = state->view->GetTypeByName(parsedType.name);
				const auto typeId = state->view->GetTypeId(parsedType.name);
				const auto definition = RenderTypeDefinition(state->view, parsedType.name, stored);
				writer.StartObject();
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("id");
				writer.String(typeId.data(), typeId.size());
				writer.Key("class");
				writer.String(TypeClassName(stored->GetClass()));
				writer.Key("width");
				writer.Uint64(stored->GetWidth());
				writer.Key("alignment");
				writer.Uint64(stored->GetAlignment());
				writer.Key("autoDefined");
				writer.Bool(state->view->IsTypeAutoDefined(parsedType.name));
				writer.Key("definition");
				writer.String(definition.data(), definition.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeStructCreateTool, "bn_type_struct_create")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("source") || !arguments["source"].IsString()
				|| arguments["source"].GetStringLength() == 0)
				throw std::invalid_argument("source must be a non-empty string");
			std::vector<std::string> options, includeDirs;
			auto readStrings = [&](const char* name, auto& output) {
				if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
					for (const auto& item : value->value.GetArray())
						output.emplace_back(item.GetString(), item.GetStringLength());
			};
			readStrings("options", options);
			readStrings("includeDirs", includeDirs);
			bool importDependencies = true;
			if (const auto value = arguments.FindMember("importDependencies"); value != arguments.MemberEnd())
				importDependencies = value->value.GetBool();
			BinaryNinja::TypeParserResult parsed;
			std::string errors;
			if (!state->view->ParseTypesFromSource(
					std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()), options,
					includeDirs, parsed, errors, {}, importDependencies))
				throw std::invalid_argument(errors.empty() ? "invalid struct source" : errors);
			auto candidates = parsed.types;
			if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
			{
				const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
				std::erase_if(candidates, [&](const auto& candidate) { return candidate.name.GetString() != wanted; });
			}
			const bool unionType = command.name() == "bn_type_union_create" || command.name() == "bn_type_union_modify";
			const auto expectedVariant = unionType ? UnionStructureType : StructStructureType;
			std::erase_if(candidates, [&](const auto& candidate) {
				if (!candidate.type || candidate.type->GetClass() != StructureTypeClass)
					return true;
				const auto structure = candidate.type->GetStructure();
				return !structure || structure->GetStructureType() != expectedVariant;
			});
			if (candidates.empty())
				throw std::invalid_argument(
					unionType ? "matching union definition not found" : "matching struct definition not found");
			if (candidates.size() != 1)
				throw std::invalid_argument(
					unionType ? "union source is ambiguous; specify type" : "struct source is ambiguous; specify type");
			const auto& selected = candidates.front();
			const auto existing = state->view->GetTypeByName(selected.name);
			const bool modify = command.name() == "bn_type_struct_modify" || command.name() == "bn_type_union_modify";
			if (!modify && existing)
				throw std::invalid_argument("type already exists");
			if (modify && !existing)
				throw std::invalid_argument("type does not exist");
			if (modify
				&& (existing->GetClass() != StructureTypeClass || !existing->GetStructure()
					|| existing->GetStructure()->GetStructureType() != expectedVariant))
				throw std::invalid_argument(
					unionType ? "existing type is not a union" : "existing type is not a struct");
			state->view->DefineUserType(selected.name, selected.type);
			rapidjson::StringBuffer argumentsBuffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
			const auto name = selected.name.GetString();
			writer.StartObject();
			writer.Key("type");
			writer.String(name.data(), name.size());
			writer.EndObject();
			ipc::ExecuteAnalysisTool infoCommand = command;
			infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
			rapidjson::Document infoArguments;
			infoArguments.Parse(infoCommand.arguments_json().data(), infoCommand.arguments_json().size());
			const FileChildToolCallContext infoContext {infoCommand, infoArguments, command.view, command.file,
				command.diffTools, command.activeUndoId, command.activeUndoView, command.viewMutex, command.progress,
				command.finished};
			return TypeInfoTool().Execute(infoContext);
		};

		BINJAD_ANALYSIS_TOOL(TypeStructModifyTool, "bn_type_struct_modify")
		{
			return TypeStructCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TypeUnionCreateTool, "bn_type_union_create")
		{
			return TypeStructCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TypeUnionModifyTool, "bn_type_union_modify")
		{
			return TypeStructCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TypeEnumCreateTool, "bn_type_enum_create")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("source") || !arguments["source"].IsString()
				|| arguments["source"].GetStringLength() == 0)
				throw std::invalid_argument("source must be a non-empty string");
			std::vector<std::string> options, includeDirs;
			auto readStrings = [&](const char* name, auto& output) {
				if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
					for (const auto& item : value->value.GetArray())
						output.emplace_back(item.GetString(), item.GetStringLength());
			};
			readStrings("options", options);
			readStrings("includeDirs", includeDirs);
			bool importDependencies = true;
			if (const auto value = arguments.FindMember("importDependencies"); value != arguments.MemberEnd())
				importDependencies = value->value.GetBool();
			BinaryNinja::TypeParserResult parsed;
			std::string errors;
			if (!state->view->ParseTypesFromSource(
					std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()), options,
					includeDirs, parsed, errors, {}, importDependencies))
				throw std::invalid_argument(errors.empty() ? "invalid enum source" : errors);
			auto candidates = parsed.types;
			if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
			{
				const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
				std::erase_if(candidates, [&](const auto& candidate) { return candidate.name.GetString() != wanted; });
			}
			std::erase_if(candidates, [](const auto& candidate) {
				return !candidate.type || candidate.type->GetClass() != EnumerationTypeClass;
			});
			if (candidates.empty())
				throw std::invalid_argument("matching enum definition not found");
			if (candidates.size() != 1)
				throw std::invalid_argument("enum source is ambiguous; specify type");
			const auto& selected = candidates.front();
			const auto existing = state->view->GetTypeByName(selected.name);
			const bool modify = command.name() == "bn_type_enum_modify";
			if (!modify && existing)
				throw std::invalid_argument("type already exists");
			if (modify && !existing)
				throw std::invalid_argument("type does not exist");
			if (modify && existing->GetClass() != EnumerationTypeClass)
				throw std::invalid_argument("existing type is not an enum");
			state->view->DefineUserType(selected.name, selected.type);
			rapidjson::StringBuffer argumentsBuffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
			const auto name = selected.name.GetString();
			writer.StartObject();
			writer.Key("type");
			writer.String(name.data(), name.size());
			writer.EndObject();
			ipc::ExecuteAnalysisTool infoCommand = command;
			infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
			rapidjson::Document infoArguments;
			infoArguments.Parse(infoCommand.arguments_json().data(), infoCommand.arguments_json().size());
			const FileChildToolCallContext infoContext {infoCommand, infoArguments, command.view, command.file,
				command.diffTools, command.activeUndoId, command.activeUndoView, command.viewMutex, command.progress,
				command.finished};
			return TypeInfoTool().Execute(infoContext);
		};

		BINJAD_ANALYSIS_TOOL(TypeEnumModifyTool, "bn_type_enum_modify")
		{
			return TypeEnumCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TypeDeleteTool, "bn_type_delete")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("type") || !arguments["type"].IsString()
				|| arguments["type"].GetStringLength() == 0)
				throw std::invalid_argument("type must be a non-empty string");
			const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
			std::optional<BinaryNinja::QualifiedName> selected;
			for (const auto& [name, type] : state->view->GetTypes())
				if (name.GetString() == requested)
				{
					if (selected)
						throw std::invalid_argument("type name is ambiguous");
					selected = name;
				}
			if (!selected)
				throw std::invalid_argument("type not found");
			if (state->view->IsTypeAutoDefined(*selected))
				state->view->UndefineType(state->view->GetTypeId(*selected));
			else
				state->view->UndefineUserType(*selected);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("type");
			writer.String(requested.data(), requested.size());
			writer.Key("deleted");
			writer.Bool(true);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeRenameTool, "bn_type_rename")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("type") || !arguments["type"].IsString()
				|| !arguments.HasMember("newType") || !arguments["newType"].IsString()
				|| arguments["newType"].GetStringLength() == 0)
				throw std::invalid_argument("type and non-empty newType are required");
			const std::string current(arguments["type"].GetString(), arguments["type"].GetStringLength());
			const std::string replacement(arguments["newType"].GetString(), arguments["newType"].GetStringLength());
			std::optional<BinaryNinja::QualifiedName> currentName;
			for (const auto& [name, type] : state->view->GetTypes())
			{
				if (name.GetString() == current)
					currentName = name;
				if (name.GetString() == replacement && name.GetString() != current)
					throw std::invalid_argument("destination type already exists");
			}
			if (!currentName)
				throw std::invalid_argument("type not found");
			state->view->RenameType(*currentName, QualifiedNameFromString(replacement));
			rapidjson::StringBuffer argumentsBuffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
			writer.StartObject();
			writer.Key("type");
			writer.String(replacement.data(), replacement.size());
			writer.EndObject();
			ipc::ExecuteAnalysisTool infoCommand = command;
			infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
			rapidjson::Document infoArguments;
			infoArguments.Parse(infoCommand.arguments_json().data(), infoCommand.arguments_json().size());
			const FileChildToolCallContext infoContext {infoCommand, infoArguments, command.view, command.file,
				command.diffTools, command.activeUndoId, command.activeUndoView, command.viewMutex, command.progress,
				command.finished};
			return TypeInfoTool().Execute(infoContext);
		};

		BINJAD_ANALYSIS_TOOL(TypeXrefsFromTool, "bn_type_xrefs_from")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("type") || !arguments["type"].IsString())
				throw std::invalid_argument("type must be a string");
			const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
			std::optional<BinaryNinja::QualifiedName> selected;
			for (const auto& [name, type] : state->view->GetTypes())
				if (name.GetString() == requested)
					selected = name;
			if (!selected)
				throw std::invalid_argument("type not found");
			bool recursive = false;
			if (const auto value = arguments.FindMember("recursive"); value != arguments.MemberEnd())
				recursive = value->value.GetBool();
			const auto references = recursive ?
				state->view->GetOutgoingRecursiveTypeReferences(*selected) :
				state->view->GetOutgoingDirectTypeReferences(*selected);
			std::vector<std::string> names;
			for (const auto& reference : references)
				names.push_back(reference.GetString());
			std::sort(names.begin(), names.end());
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("type");
			writer.String(requested.data(), requested.size());
			writer.Key("references");
			writer.StartArray();
			for (const auto& name : names)
			{
				const auto type = state->view->GetTypeByName(QualifiedNameFromString(name));
				writer.StartObject();
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("class");
				if (type)
					writer.String(TypeClassName(type->GetClass()));
				else
					writer.Null();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("recursive");
			writer.Bool(recursive);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TypeXrefsToTool, "bn_type_xrefs_to")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("type") || !arguments["type"].IsString())
				throw std::invalid_argument("type must be a string");
			const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
			std::optional<BinaryNinja::QualifiedName> selected;
			for (const auto& [name, type] : state->view->GetTypes())
				if (name.GetString() == requested)
					selected = name;
			if (!selected)
				throw std::invalid_argument("type not found");
			std::optional<std::size_t> maxItems;
			if (const auto value = arguments.FindMember("maxItems"); value != arguments.MemberEnd())
				maxItems = value->value.GetUint64();
			auto references = state->view->GetAllReferencesForType(*selected, maxItems);
			std::sort(references.codeRefs.begin(), references.codeRefs.end(), [](const auto& a, const auto& b) {
				return a.addr < b.addr;
			});
			std::sort(references.dataRefs.begin(), references.dataRefs.end());
			std::sort(references.typeRefs.begin(), references.typeRefs.end(), [](const auto& a, const auto& b) {
				return a.name.GetString() < b.name.GetString();
			});
			const auto platform = state->view->GetDefaultPlatform();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("type");
			writer.String(requested.data(), requested.size());
			writer.Key("code");
			writer.StartArray();
			for (const auto& reference : references.codeRefs)
			{
				const auto address = HexAddress(reference.addr);
				const auto symbol = reference.func ? reference.func->GetSymbol() : nullptr;
				const auto function = symbol ? symbol->GetShortName() : std::string {};
				const auto arch = reference.arch ? reference.arch->GetName() : std::string {};
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), address.size());
				writer.Key("function");
				writer.String(function.data(), function.size());
				writer.Key("arch");
				writer.String(arch.data(), arch.size());
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("data");
			writer.StartArray();
			for (const auto reference : references.dataRefs)
			{
				const auto address = HexAddress(reference);
				BinaryNinja::DataVariable variable;
				writer.StartObject();
				writer.Key("address");
				writer.String(address.data(), address.size());
				writer.Key("type");
				if (state->view->GetDataVariableAtAddress(reference, variable) && variable.type.GetValue())
				{
					const auto text = variable.type.GetValue()->GetString(platform.GetPtr());
					writer.String(text.data(), text.size());
				}
				else
					writer.Null();
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("types");
			writer.StartArray();
			for (const auto& reference : references.typeRefs)
			{
				const auto name = reference.name.GetString();
				const auto type = state->view->GetTypeByName(reference.name);
				writer.StartObject();
				writer.Key("name");
				writer.String(name.data(), name.size());
				writer.Key("class");
				if (type)
					writer.String(TypeClassName(type->GetClass()));
				else
					writer.Null();
				writer.EndObject();
			}
			writer.EndArray();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(DataVariableDefineTool, "bn_data_variable_define")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("datavar") || !arguments["datavar"].IsString())
				throw std::invalid_argument("datavar must be a string");
			std::uint64_t address = 0;
			std::string error;
			const auto& value = arguments["datavar"];
			if (!BinaryNinja::BinaryView::ParseExpression(
					state->view, std::string(value.GetString(), value.GetStringLength()), address, 0, error))
				throw std::invalid_argument(error.empty() ? "invalid data-variable address" : error);
			const auto type = ParseRequestedType(command, arguments);
			state->view->DefineUserDataVariable(
				address, BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>(type, 255));
			rapidjson::StringBuffer json;
			rapidjson::Writer<rapidjson::StringBuffer> writer(json);
			const auto text = HexAddress(address);
			writer.StartObject();
			writer.Key("address");
			writer.String(text.data(), text.size());
			writer.EndObject();
			ipc::ExecuteAnalysisTool dataCommand = command;
			dataCommand.set_arguments_json(json.GetString(), json.GetSize());
			rapidjson::Document dataArguments;
			dataArguments.Parse(dataCommand.arguments_json().data(), dataCommand.arguments_json().size());
			const FileChildToolCallContext dataContext {dataCommand, dataArguments, command.view, command.file,
				command.diffTools, command.activeUndoId, command.activeUndoView, command.viewMutex, command.progress,
				command.finished};
			return FindFileChildToolCall("bn_data_at")->Execute(dataContext);
		};

		BINJAD_ANALYSIS_TOOL(DataVariableUndefineTool, "bn_data_variable_undefine")
		{
			const auto& state = command.view;
			rapidjson::Document arguments;
			arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!arguments.IsObject() || !arguments.HasMember("datavar") || !arguments["datavar"].IsString())
				throw std::invalid_argument("datavar must be a string");
			std::uint64_t address = 0;
			std::string error;
			const auto& value = arguments["datavar"];
			if (!BinaryNinja::BinaryView::ParseExpression(
					state->view, std::string(value.GetString(), value.GetStringLength()), address, 0, error))
				throw std::invalid_argument(error.empty() ? "invalid data-variable address" : error);
			BinaryNinja::DataVariable variable;
			if (!state->view->GetDataVariableAtAddress(address, variable))
				throw std::invalid_argument("data variable not found");
			if (variable.autoDiscovered)
				state->view->UndefineDataVariable(address, true);
			else
				state->view->UndefineUserDataVariable(address);
			rapidjson::StringBuffer json;
			rapidjson::Writer<rapidjson::StringBuffer> writer(json);
			const auto text = HexAddress(address);
			writer.StartObject();
			writer.Key("address");
			writer.String(text.data(), text.size());
			writer.EndObject();
			ipc::ExecuteAnalysisTool dataCommand = command;
			dataCommand.set_arguments_json(json.GetString(), json.GetSize());
			rapidjson::Document dataArguments;
			dataArguments.Parse(dataCommand.arguments_json().data(), dataCommand.arguments_json().size());
			const FileChildToolCallContext dataContext {dataCommand, dataArguments, command.view, command.file,
				command.diffTools, command.activeUndoId, command.activeUndoView, command.viewMutex, command.progress,
				command.finished};
			return FindFileChildToolCall("bn_data_at")->Execute(dataContext);
		};

		BINJAD_ANALYSIS_TOOL(SectionCreateTool, "bn_section_create")
		{
			const auto& state = command.view;
			rapidjson::Document a;
			a.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!a.IsObject() || !a.HasMember("section") || !a["section"].IsString()
				|| a["section"].GetStringLength() == 0 || !a.HasMember("start") || !a["start"].IsString()
				|| !a.HasMember("length"))
				throw std::invalid_argument("section, start, and length are required");
			const std::string name(a["section"].GetString(), a["section"].GetStringLength());
			if (state->view->GetSectionByName(name))
				throw std::invalid_argument("section already exists");
			auto parse = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid section expression" : error);
				return result;
			};
			const auto start = parse(a["start"]);
			const auto length = a["length"].IsUint64() ? a["length"].GetUint64() : parse(a["length"]);
			if (length > std::numeric_limits<std::uint64_t>::max() - start)
				throw std::invalid_argument("section range overflows");
			auto semantics = DefaultSectionSemantics;
			std::string typeName, linkedSection, infoSection;
			std::uint64_t alignment = 1, entrySize = 0, infoData = 0;
			if (const auto v = a.FindMember("semantics"); v != a.MemberEnd())
				semantics = ParseSectionSemantics({v->value.GetString(), v->value.GetStringLength()});
			if (const auto v = a.FindMember("typeName"); v != a.MemberEnd())
				typeName.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("alignment"); v != a.MemberEnd())
				alignment = v->value.GetUint64();
			if (const auto v = a.FindMember("entrySize"); v != a.MemberEnd())
				entrySize = v->value.GetUint64();
			if (const auto v = a.FindMember("linkedSection"); v != a.MemberEnd())
				linkedSection.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("infoSection"); v != a.MemberEnd())
				infoSection.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("infoData"); v != a.MemberEnd())
				infoData = v->value.GetUint64();
			state->view->AddUserSection(
				name, start, length, semantics, typeName, alignment, entrySize, linkedSection, infoSection, infoData);
			const auto startText = HexAddress(start), endText = HexAddress(start + length);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("section");
			writer.StartObject();
			writer.Key("name");
			writer.String(name.data(), name.size());
			writer.Key("start");
			writer.String(startText.data(), startText.size());
			writer.Key("end");
			writer.String(endText.data(), endText.size());
			writer.Key("semantics");
			writer.String(SectionSemanticsName(semantics));
			writer.EndObject();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SectionDeleteTool, "bn_section_delete")
		{
			const auto& state = command.view;
			rapidjson::Document a;
			a.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!a.IsObject() || !a.HasMember("section") || !a["section"].IsString()
				|| a["section"].GetStringLength() == 0)
				throw std::invalid_argument("section must be a non-empty string");
			const std::string name(a["section"].GetString(), a["section"].GetStringLength());
			const auto section = state->view->GetSectionByName(name);
			if (!section)
				throw std::invalid_argument("section not found");
			if (section->AutoDefined())
				state->view->RemoveAutoSection(name);
			else
				state->view->RemoveUserSection(name);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("section");
			writer.String(name.data(), name.size());
			writer.Key("deleted");
			writer.Bool(true);
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SectionModifyTool, "bn_section_modify")
		{
			const auto& state = command.view;
			rapidjson::Document a;
			a.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!a.IsObject() || !a.HasMember("section") || !a["section"].IsString()
				|| a["section"].GetStringLength() == 0)
				throw std::invalid_argument("section must be a non-empty string");
			const std::string current(a["section"].GetString(), a["section"].GetStringLength());
			const auto section = state->view->GetSectionByName(current);
			if (!section)
				throw std::invalid_argument("section not found");
			auto parse = [&](const rapidjson::Value& value) {
				std::uint64_t result = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(value.GetString(), value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid section expression" : error);
				return result;
			};
			auto name = current;
			auto start = section->GetStart();
			auto length = section->GetLength();
			auto semantics = section->GetSemantics();
			auto typeName = section->GetType();
			auto alignment = section->GetAlignment();
			auto entrySize = section->GetEntrySize();
			auto linked = section->GetLinkedSection();
			auto info = section->GetInfoSection();
			auto infoData = section->GetInfoData();
			if (const auto v = a.FindMember("newSection"); v != a.MemberEnd())
				name.assign(v->value.GetString(), v->value.GetStringLength());
			if (name != current && state->view->GetSectionByName(name))
				throw std::invalid_argument("destination section already exists");
			if (const auto v = a.FindMember("start"); v != a.MemberEnd())
				start = parse(v->value);
			if (const auto v = a.FindMember("length"); v != a.MemberEnd())
				length = v->value.IsUint64() ? v->value.GetUint64() : parse(v->value);
			if (length > std::numeric_limits<std::uint64_t>::max() - start)
				throw std::invalid_argument("section range overflows");
			if (const auto v = a.FindMember("semantics"); v != a.MemberEnd())
				semantics = ParseSectionSemantics({v->value.GetString(), v->value.GetStringLength()});
			if (const auto v = a.FindMember("typeName"); v != a.MemberEnd())
				typeName.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("alignment"); v != a.MemberEnd())
				alignment = v->value.GetUint64();
			if (const auto v = a.FindMember("entrySize"); v != a.MemberEnd())
				entrySize = v->value.GetUint64();
			if (const auto v = a.FindMember("linkedSection"); v != a.MemberEnd())
				linked.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("infoSection"); v != a.MemberEnd())
				info.assign(v->value.GetString(), v->value.GetStringLength());
			if (const auto v = a.FindMember("infoData"); v != a.MemberEnd())
				infoData = v->value.GetUint64();
			const bool automatic = section->AutoDefined();
			if (automatic)
				state->view->RemoveAutoSection(current);
			else
				state->view->RemoveUserSection(current);
			if (automatic)
				state->view->AddAutoSection(
					name, start, length, semantics, typeName, alignment, entrySize, linked, info, infoData);
			else
				state->view->AddUserSection(
					name, start, length, semantics, typeName, alignment, entrySize, linked, info, infoData);
			const auto startText = HexAddress(start), endText = HexAddress(start + length);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("section");
			writer.StartObject();
			writer.Key("name");
			writer.String(name.data(), name.size());
			writer.Key("start");
			writer.String(startText.data(), startText.size());
			writer.Key("end");
			writer.String(endText.data(), endText.size());
			writer.Key("semantics");
			writer.String(SectionSemanticsName(semantics));
			writer.EndObject();
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SegmentCreateTool, "bn_segment_create")
		{
			const auto& state = command.view;
			rapidjson::Document a;
			a.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!a.IsObject())
				throw std::invalid_argument("mutation arguments must be an object");
			auto parse = [&](const char* key, bool required = true, std::uint64_t fallback = 0) {
				const auto v = a.FindMember(key);
				if (v == a.MemberEnd())
				{
					if (required)
						throw std::invalid_argument(std::string(key) + " is required");
					return fallback;
				}
				std::uint64_t result = 0;
				std::string error;
				if (!v->value.IsString()
					|| !BinaryNinja::BinaryView::ParseExpression(
						state->view, std::string(v->value.GetString(), v->value.GetStringLength()), result, 0, error))
					throw std::invalid_argument(error.empty() ? std::string("invalid ") + key : error);
				return result;
			};
			auto exactSegment = [&](std::uint64_t start, std::uint64_t length) {
				for (const auto& segment : state->view->GetSegments())
					if (segment->GetStart() == start && segment->GetLength() == length && !segment->IsAutoDefined())
						return segment;
				return BinaryNinja::Ref<BinaryNinja::Segment>();
			};
			const auto name = command.name();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("operation");
			writer.String(name.data(), name.size());
			if (name == "bn_function_delete")
			{
				const auto function = ResolveFunction(command, a);
				const auto address = function->GetStart();
				state->view->RemoveUserFunction(function);
				const auto text = HexAddress(address);
				writer.Key("address");
				writer.String(text.data(), text.size());
				writer.Key("deleted");
				writer.Bool(true);
			}
			else if (name == "bn_string_define")
			{
				const auto address = parse("address"), length = parse("length");
				if (length == 0 || !state->view->IsValidOffset(address)
					|| !state->view->IsValidOffset(address + length - 1))
					throw std::invalid_argument("string range must be non-empty and mapped");
				const std::string encoding(a["encoding"].GetString(), a["encoding"].GetStringLength());
				const std::size_t width = encoding == "utf16" ? 2 : encoding == "utf32" ? 4 : 1;
				if (length % width != 0)
					throw std::invalid_argument("string length is not aligned to its encoding width");
				auto element = width == 1 ?
					BinaryNinja::Type::IntegerType(1, true, "char") :
					BinaryNinja::Type::WideCharType(width);
				state->view->DefineUserDataVariable(address, BinaryNinja::Type::ArrayType(element, length / width));
				const auto text = HexAddress(address);
				writer.Key("address");
				writer.String(text.data(), text.size());
				writer.Key("length");
				writer.Uint64(length);
				writer.Key("encoding");
				writer.String(encoding.data(), encoding.size());
			}
			else if (name == "bn_string_undefine")
			{
				const auto address = parse("address");
				state->view->UndefineUserDataVariable(address);
				const auto text = HexAddress(address);
				writer.Key("address");
				writer.String(text.data(), text.size());
				writer.Key("undefined");
				writer.Bool(true);
			}
			else if (name == "bn_binary_view_rebase")
			{
				const auto address = parse("address");
				if (!command.file->Rebase(state->view.GetPtr(), address))
					throw std::runtime_error("Binary Ninja rejected the rebase");
				const auto text = HexAddress(address);
				writer.Key("address");
				writer.String(text.data(), text.size());
				writer.Key("rebased");
				writer.Bool(true);
			}
			else
			{
				const auto operation = name == "bn_memory_map_preview" ?
					std::string(a["operation"].GetString(), a["operation"].GetStringLength()) :
					name;
				const bool
					remove = operation == "delete" || operation == "bn_segment_delete",
					modify = operation == "modify" || operation == "bn_segment_modify",
					create = operation == "create" || operation == "bn_segment_create", rebase = operation == "rebase";
				if (!remove && !modify && !create && !rebase)
					throw std::invalid_argument("operation must be create, modify, delete, or rebase");
				if (name == "bn_memory_map_preview")
				{
					writer.Key("valid");
					writer.Bool(true);
					writer.Key("mutated");
					writer.Bool(false);
					if (rebase)
					{
						const auto address = parse("address");
						const auto text = HexAddress(address);
						writer.Key("address");
						writer.String(text.data(), text.size());
					}
					else
					{
						const auto start = parse("start"), length = parse("length");
						writer.Key("existingUserSegment");
						writer.Bool(static_cast<bool>(exactSegment(start, length)));
					}
				}
				else
				{
					const auto start = parse("start"), length = parse("length");
					if (length == 0)
						throw std::invalid_argument("segment length must be nonzero");
					if ((remove || modify) && !exactSegment(start, length))
						throw std::invalid_argument("exact user segment not found");
					if (remove || modify)
						state->view->RemoveUserSegment(start, length);
					std::uint64_t resultStart = start, resultLength = length;
					if (!remove)
					{
						if (modify)
						{
							resultStart = parse("newStart", false, start);
							resultLength = parse("newLength", false, length);
						}
						const auto dataOffset = parse("dataOffset"), dataLength = parse("dataLength");
						if (resultLength == 0 || dataLength > resultLength)
							throw std::invalid_argument("segment lengths are invalid");
						const auto flags = a["flags"].GetUint();
						state->view->AddUserSegment(resultStart, resultLength, dataOffset, dataLength, flags);
						writer.Key("flags");
						writer.Uint(flags);
					}
					const auto text = HexAddress(resultStart);
					writer.Key("start");
					writer.String(text.data(), text.size());
					writer.Key("length");
					writer.Uint64(resultLength);
					writer.Key("deleted");
					writer.Bool(remove);
				}
			}
			writer.Key("nextAction");
			writer.String(
				"Run bn_analysis_update_and_wait when analysis semantics changed, then bn_binary_view_save to persist "
				"the "
				"mutation.");
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(SegmentModifyTool, "bn_segment_modify")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(SegmentDeleteTool, "bn_segment_delete")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(BinaryViewRebaseTool, "bn_binary_view_rebase")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(MemoryMapPreviewTool, "bn_memory_map_preview")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(FunctionDeleteTool, "bn_function_delete")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(StringDefineTool, "bn_string_define")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(StringUndefineTool, "bn_string_undefine")
		{
			return SegmentCreateTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TransactionBeginTool, "bn_transaction_begin")
		{
			const auto& state = command.view;
			const auto name = command.name();
			if (name == "bn_transaction_begin")
			{
				if (command.activeUndoId)
					throw std::runtime_error("an explicit transaction is already active for this open item");
				command.activeUndoId = state->view->BeginUndoActions(false);
				if (command.activeUndoId->empty())
				{
					command.activeUndoId.reset();
					throw std::runtime_error("Binary Ninja did not create an undo transaction");
				}
				command.activeUndoView = command.view_type();
			}
			else if (name == "bn_transaction_commit" || name == "bn_transaction_rollback")
			{
				if (!command.activeUndoId || command.activeUndoView != command.view_type())
					throw std::runtime_error("no active transaction exists for this BinaryView");
				if (name == "bn_transaction_commit")
					state->view->CommitUndoActions(*command.activeUndoId);
				else
					state->view->RevertUndoActions(*command.activeUndoId);
				command.activeUndoId.reset();
				command.activeUndoView.clear();
			}
			else
			{
				if (command.activeUndoId)
					throw std::runtime_error("commit or roll back the active transaction before undo or redo");
				const bool undo = name == "bn_undo";
				if (undo ? !state->view->CanUndo() : !state->view->CanRedo())
					throw std::runtime_error(undo ? "nothing is available to undo" : "nothing is available to redo");
				if (!(undo ? state->view->Undo() : state->view->Redo()))
					throw std::runtime_error(undo ? "undo failed" : "redo failed");
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("operation");
			writer.String(name.data(), name.size());
			writer.Key("active");
			writer.Bool(command.activeUndoId.has_value());
			if (command.activeUndoId)
			{
				writer.Key("coreTransactionId");
				writer.String(command.activeUndoId->data(), command.activeUndoId->size());
			}
			writer.Key("canUndo");
			writer.Bool(state->view->CanUndo());
			writer.Key("canRedo");
			writer.Bool(state->view->CanRedo());
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(TransactionCommitTool, "bn_transaction_commit")
		{
			return TransactionBeginTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(TransactionRollbackTool, "bn_transaction_rollback")
		{
			return TransactionBeginTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(UndoTool, "bn_undo")
		{
			return TransactionBeginTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(RedoTool, "bn_redo")
		{
			return TransactionBeginTool().Execute(command);
		};

		BINJAD_ANALYSIS_TOOL(BookmarkCreateTool, "bn_bookmark_create")
		{
			const auto& state = command.view;
			rapidjson::Document a;
			a.Parse(command.arguments_json().data(), command.arguments_json().size());
			if (!a.IsObject())
				throw std::invalid_argument("annotation arguments must be an object");
			auto stringArg = [&](const char* key, bool required = true) {
				const auto value = a.FindMember(key);
				if (value == a.MemberEnd())
				{
					if (required)
						throw std::invalid_argument(std::string(key) + " is required");
					return std::string {};
				}
				if (!value->value.IsString())
					throw std::invalid_argument(std::string(key) + " must be a string");
				return std::string(value->value.GetString(), value->value.GetStringLength());
			};
			auto addressArg = [&] {
				const auto expression = stringArg("address");
				std::uint64_t address = 0;
				std::string error;
				if (!BinaryNinja::BinaryView::ParseExpression(state->view, expression, address, 0, error))
					throw std::invalid_argument(error.empty() ? "invalid address" : error);
				if (!state->view->IsValidOffset(address))
					throw std::invalid_argument("address is not mapped");
				return address;
			};
			std::function<BinaryNinja::Ref<BinaryNinja::Metadata>(const rapidjson::Value&)> metadata =
				[&](const rapidjson::Value& value) -> BinaryNinja::Ref<BinaryNinja::Metadata> {
				if (value.IsNull())
					throw std::invalid_argument("Binary Ninja metadata cannot represent JSON null");
				if (value.IsBool())
					return new BinaryNinja::Metadata(value.GetBool());
				if (value.IsUint64())
					return new BinaryNinja::Metadata(value.GetUint64());
				if (value.IsInt64())
					return new BinaryNinja::Metadata(value.GetInt64());
				if (value.IsNumber())
					return new BinaryNinja::Metadata(value.GetDouble());
				if (value.IsString())
					return new BinaryNinja::Metadata(std::string(value.GetString(), value.GetStringLength()));
				if (value.IsArray())
				{
					std::vector<BinaryNinja::Ref<BinaryNinja::Metadata>> values;
					for (const auto& item : value.GetArray())
						values.push_back(metadata(item));
					return new BinaryNinja::Metadata(values);
				}
				std::map<std::string, BinaryNinja::Ref<BinaryNinja::Metadata>> values;
				for (const auto& item : value.GetObject())
					values.emplace(
						std::string(item.name.GetString(), item.name.GetStringLength()), metadata(item.value));
				return new BinaryNinja::Metadata(values);
			};
			const auto name = command.name();
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			if (name.starts_with("bn_metadata_"))
			{
				const auto key = stringArg("key");
				if (key.empty() || key.size() > 256)
					throw std::invalid_argument("key must contain 1 through 256 bytes");
				const auto namespaced = "binjad.user." + key;
				writer.Key("key");
				writer.String(key.data(), key.size());
				if (name == "bn_metadata_set")
				{
					state->view->StoreMetadata(namespaced, metadata(a["value"]));
					writer.Key("value");
					a["value"].Accept(writer);
				}
				else if (name == "bn_metadata_delete")
				{
					state->view->RemoveMetadata(namespaced);
					writer.Key("deleted");
					writer.Bool(true);
				}
				else
				{
					const auto value = state->view->QueryMetadata(namespaced);
					if (!value)
						throw std::invalid_argument("custom metadata key not found");
					const auto json = value->GetJsonString();
					rapidjson::Document parsed;
					parsed.Parse(json.data(), json.size());
					if (parsed.HasParseError())
						throw std::runtime_error("stored metadata is not valid JSON");
					writer.Key("value");
					parsed.Accept(writer);
				}
			}
			else
			{
				const bool bookmark = name.starts_with("bn_bookmark_");
				std::vector<BinaryNinja::Ref<BinaryNinja::TagType>> types;
				for (const auto& type : state->view->GetTagTypes())
					if (type->GetType() == (bookmark ? BookmarksTagType : UserTagType))
						types.push_back(type);
				if (name.ends_with("_create"))
				{
					const auto address = addressArg();
					const auto typeName = bookmark ? std::string("Bookmarks") : stringArg("type");
					auto type = state->view->GetTagType(typeName, bookmark ? BookmarksTagType : UserTagType);
					if (!type)
					{
						type = new BinaryNinja::TagType(state->view.GetPtr(), typeName,
							bookmark ? "B" : stringArg("icon", false), true, bookmark ? BookmarksTagType : UserTagType);
						state->view->AddTagType(type);
					}
					const auto data = bookmark ? stringArg("note", false) : stringArg("data", false);
					const auto tag = state->view->CreateUserDataTag(address, type, data, false);
					const auto id = tag->GetId(), text = HexAddress(address);
					writer.Key("id");
					writer.String(id.data(), id.size());
					writer.Key("address");
					writer.String(text.data(), text.size());
					writer.Key("type");
					writer.String(typeName.data(), typeName.size());
					writer.Key(bookmark ? "note" : "data");
					writer.String(data.data(), data.size());
				}
				else if (name.ends_with("_delete"))
				{
					const auto id = stringArg("id");
					bool removed = false;
					for (const auto& type : types)
						for (const auto& ref : state->view->GetAllTagReferencesOfType(type))
							if (!ref.autoDefined && ref.tag->GetId() == id && ref.refType == DataTagReference)
							{
								state->view->RemoveUserDataTag(ref.addr, ref.tag);
								removed = true;
							}
					if (!removed)
						throw std::invalid_argument(bookmark ? "bookmark not found" : "tag not found");
					writer.Key("id");
					writer.String(id.data(), id.size());
					writer.Key("deleted");
					writer.Bool(true);
				}
				else
				{
					const auto query = Lower(stringArg("query", false)), filter = stringArg("type", false);
					std::size_t
						offset = a.HasMember("offset") ? a["offset"].GetUint64() : 0,
						limit = a.HasMember("limit") ? a["limit"].GetUint64() : 50;
					std::vector<BinaryNinja::TagReference> refs;
					for (const auto& type : types)
						if (filter.empty() || type->GetName() == filter)
							for (const auto& ref : state->view->GetAllTagReferencesOfType(type))
								if (!ref.autoDefined
									&& (query.empty() || Lower(ref.tag->GetData()).find(query) != std::string::npos))
									refs.push_back(ref);
					std::sort(refs.begin(), refs.end(), [](const auto& x, const auto& y) {
						return x.addr < y.addr || (x.addr == y.addr && x.tag->GetId() < y.tag->GetId());
					});
					offset = std::min(offset, refs.size());
					const auto end = offset + std::min(limit, refs.size() - offset);
					writer.Key(bookmark ? "bookmarks" : "tags");
					writer.StartArray();
					for (std::size_t i = offset; i < end; ++i)
					{
						const auto& ref = refs[i];
						const auto id = ref.tag->GetId(), text = HexAddress(ref.addr),
								   type = ref.tag->GetType()->GetName(), data = ref.tag->GetData();
						writer.StartObject();
						writer.Key("id");
						writer.String(id.data(), id.size());
						writer.Key("address");
						writer.String(text.data(), text.size());
						writer.Key("type");
						writer.String(type.data(), type.size());
						writer.Key(bookmark ? "note" : "data");
						writer.String(data.data(), data.size());
						writer.EndObject();
					}
					writer.EndArray();
					writer.Key("count");
					writer.Uint64(end - offset);
					writer.Key("total");
					writer.Uint64(refs.size());
					writer.Key("nextOffset");
					if (end < refs.size())
						writer.Uint64(end);
					else
						writer.Null();
					writer.Key("truncated");
					writer.Bool(end < refs.size());
				}
			}
			writer.EndObject();
			ipc::Reply reply;
			reply.set_success(true);
			reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
			return reply;
		};

		BINJAD_ANALYSIS_TOOL(BookmarkListTool, "bn_bookmark_list")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(BookmarkDeleteTool, "bn_bookmark_delete")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(TagCreateTool, "bn_tag_create")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(TagListTool, "bn_tag_list")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(TagDeleteTool, "bn_tag_delete")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(MetadataGetTool, "bn_metadata_get")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(MetadataSetTool, "bn_metadata_set")
		{
			return BookmarkCreateTool().Execute(command);
		};
		BINJAD_ANALYSIS_TOOL(MetadataDeleteTool, "bn_metadata_delete")
		{
			return BookmarkCreateTool().Execute(command);
		};

#undef BINJAD_ANALYSIS_TOOL
	}  // namespace

	void RegisterAnalysisMutationToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<CommentGetTool>());
		tools.emplace_back(std::make_unique<CommentSetTool>());
		tools.emplace_back(std::make_unique<CommentDeleteTool>());
		tools.emplace_back(std::make_unique<SymbolDefineTool>());
		tools.emplace_back(std::make_unique<SymbolRenameTool>());
		tools.emplace_back(std::make_unique<SymbolUndefineTool>());
		tools.emplace_back(std::make_unique<FunctionPrototypeSetTool>());
		tools.emplace_back(std::make_unique<CallingConventionSetTool>());
		tools.emplace_back(std::make_unique<VariableRenameTool>());
		tools.emplace_back(std::make_unique<VariableSetTypeTool>());
		tools.emplace_back(std::make_unique<TypeListTool>());
		tools.emplace_back(std::make_unique<TypeInfoTool>());
		tools.emplace_back(std::make_unique<TypeParseTool>());
		tools.emplace_back(std::make_unique<TypeDefineTool>());
		tools.emplace_back(std::make_unique<TypeStructCreateTool>());
		tools.emplace_back(std::make_unique<TypeStructModifyTool>());
		tools.emplace_back(std::make_unique<TypeUnionCreateTool>());
		tools.emplace_back(std::make_unique<TypeUnionModifyTool>());
		tools.emplace_back(std::make_unique<TypeEnumCreateTool>());
		tools.emplace_back(std::make_unique<TypeEnumModifyTool>());
		tools.emplace_back(std::make_unique<TypeDeleteTool>());
		tools.emplace_back(std::make_unique<TypeRenameTool>());
		tools.emplace_back(std::make_unique<TypeXrefsFromTool>());
		tools.emplace_back(std::make_unique<TypeXrefsToTool>());
		tools.emplace_back(std::make_unique<DataVariableDefineTool>());
		tools.emplace_back(std::make_unique<DataVariableUndefineTool>());
		tools.emplace_back(std::make_unique<SectionCreateTool>());
		tools.emplace_back(std::make_unique<SectionDeleteTool>());
		tools.emplace_back(std::make_unique<SectionModifyTool>());
		tools.emplace_back(std::make_unique<SegmentCreateTool>());
		tools.emplace_back(std::make_unique<SegmentModifyTool>());
		tools.emplace_back(std::make_unique<SegmentDeleteTool>());
		tools.emplace_back(std::make_unique<BinaryViewRebaseTool>());
		tools.emplace_back(std::make_unique<MemoryMapPreviewTool>());
		tools.emplace_back(std::make_unique<FunctionDeleteTool>());
		tools.emplace_back(std::make_unique<StringDefineTool>());
		tools.emplace_back(std::make_unique<StringUndefineTool>());
		tools.emplace_back(std::make_unique<TransactionBeginTool>());
		tools.emplace_back(std::make_unique<TransactionCommitTool>());
		tools.emplace_back(std::make_unique<TransactionRollbackTool>());
		tools.emplace_back(std::make_unique<UndoTool>());
		tools.emplace_back(std::make_unique<RedoTool>());
		tools.emplace_back(std::make_unique<BookmarkCreateTool>());
		tools.emplace_back(std::make_unique<BookmarkListTool>());
		tools.emplace_back(std::make_unique<BookmarkDeleteTool>());
		tools.emplace_back(std::make_unique<TagCreateTool>());
		tools.emplace_back(std::make_unique<TagListTool>());
		tools.emplace_back(std::make_unique<TagDeleteTool>());
		tools.emplace_back(std::make_unique<MetadataGetTool>());
		tools.emplace_back(std::make_unique<MetadataSetTool>());
		tools.emplace_back(std::make_unique<MetadataDeleteTool>());
	}
}  // namespace binjad
