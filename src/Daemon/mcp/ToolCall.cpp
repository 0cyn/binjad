#include "ToolCall.hpp"

#include <stdexcept>
#include <unordered_map>

namespace binjad::mcp {
	ToolCall::ToolCall(std::string_view name, std::string_view description, ToolCallCategory category,
		std::string_view documentationCategory, ToolCallAvailability availability) :
		name_(name), description_(description), category_(category), documentationCategory_(documentationCategory),
		availability_(availability)
	{}

	std::string_view ToolCall::InputSchema() const
	{
		std::call_once(inputSchemaOnce_, [this] {
			rapidjson::StringBuffer buffer;
			ToolCallSchemaWriter writer(buffer);
			WriteInputSchema(writer);
			inputSchema_.assign(buffer.GetString(), buffer.GetSize());
		});
		return inputSchema_;
	}

	bool ToolCall::IsAvailable(const Config& config, ProtocolVersion version, security::TokenRole role) const
	{
		if (!ToolCallCategoryEnabled(category_, config.tools))
			return false;
		if (HasAvailability(availability_, ToolCallAvailability::ModernProtocol) && !IsModern(version))
			return false;
		if (HasAvailability(availability_, ToolCallAvailability::Admin) && role != security::TokenRole::Admin)
			return false;
		if (HasAvailability(availability_, ToolCallAvailability::ArbitraryPaths)
			&& !config.projects.allowArbitraryPaths)
			return false;
		if (HasAvailability(availability_, ToolCallAvailability::ProjectRegistration)
			&& !config.projects.allowProjectRegistration)
			return false;
		return true;
	}

	bool ToolCall::CanExecute(const Config& config, ProtocolVersion version, security::TokenRole role) const
	{
		if (IsAvailable(config, version, role))
			return true;
		return allowRestrictedExecution_ && ToolCallCategoryEnabled(category_, config.tools)
			&& (!HasAvailability(availability_, ToolCallAvailability::ModernProtocol) || IsModern(version));
	}

	bool ToolCall::ValidateArguments(const rapidjson::Value& arguments, std::string& error) const
	{
		rapidjson::Document schemaJson;
		const auto inputSchema = InputSchema();
		schemaJson.Parse(inputSchema.data(), inputSchema.size());
		if (schemaJson.HasParseError())
		{
			error = "registered tool schema is invalid";
			return false;
		}
		rapidjson::SchemaDocument schema(schemaJson);
		rapidjson::SchemaValidator validator(schema);
		if (!arguments.Accept(validator))
		{
			rapidjson::StringBuffer pointer;
			validator.GetInvalidDocumentPointer().StringifyUriFragment(pointer);
			error = "arguments do not match input schema";
			if (pointer.GetSize() != 0)
				error += " at " + std::string(pointer.GetString(), pointer.GetSize());
			return false;
		}

		const auto properties = schemaJson.FindMember("properties");
		const auto schemaHas = [&](const char* name) {
			return properties != schemaJson.MemberEnd() && properties->value.IsObject()
				&& properties->value.HasMember(name);
		};
		for (const auto* name : {"arch", "language"})
		{
			if (!schemaHas(name))
				continue;
			const auto member = arguments.FindMember(name);
			if (member != arguments.MemberEnd() && member->value.IsString() && member->value.GetStringLength() == 0)
			{
				error = std::string(name) + " must be a non-empty string";
				return false;
			}
		}

		if (schemaHas("address") && schemaHas("start") && schemaHas("end") && schemaHas("length"))
		{
			const bool hasAddress = arguments.HasMember("address");
			const bool hasStart = arguments.HasMember("start");
			const bool hasEnd = arguments.HasMember("end");
			const bool hasLength = arguments.HasMember("length");
			if (hasAddress && (hasStart || hasEnd || hasLength))
				error = "address cannot be combined with range arguments";
			else if (hasEnd && hasLength)
				error = "end and length are mutually exclusive";
			else if ((hasEnd || hasLength) && !hasStart)
				error = "end and length require start";
			if (!error.empty())
				return false;
		}
		return true;
	}

	std::string ToolCall::UnavailableReason(
		const Config& config, ProtocolVersion version, security::TokenRole role) const
	{
		if (!ToolCallCategoryEnabled(category_, config.tools))
			return std::string(ToolCallCategoryName(category_)) + " tools are disabled in the running configuration.";
		if (HasAvailability(availability_, ToolCallAvailability::ModernProtocol) && !IsModern(version))
			return "Requires the modern MCP protocol session model.";
		if (HasAvailability(availability_, ToolCallAvailability::Admin) && role != security::TokenRole::Admin)
			return "Requires an admin bearer token.";
		if (HasAvailability(availability_, ToolCallAvailability::ArbitraryPaths)
			&& !config.projects.allowArbitraryPaths)
			return "Requires projects.allow_arbitrary_paths in local mode.";
		if (HasAvailability(availability_, ToolCallAvailability::ProjectRegistration)
			&& !config.projects.allowProjectRegistration)
			return "Requires projects.allow_project_registration in local mode.";
		return "Not advertised for the selected protocol, role, mode, or running options.";
	}

	std::string_view ToolCallCategoryName(ToolCallCategory category)
	{
		switch (category)
		{
		case ToolCallCategory::Core:
			return "Core Workflow";
		case ToolCallCategory::ProjectManagement:
			return "Project Management & Documents";
		case ToolCallCategory::FunctionAnalysis:
			return "Function Analysis";
		case ToolCallCategory::BinaryData:
			return "Binary Data";
		case ToolCallCategory::Search:
			return "Search";
		case ToolCallCategory::Types:
			return "Types & Signatures";
		case ToolCallCategory::Annotations:
			return "Annotations & Symbols";
		case ToolCallCategory::BinaryEditing:
			return "Binary Editing";
		case ToolCallCategory::History:
			return "Transactions & History";
		case ToolCallCategory::HeaderParsing:
			return "Header Parsing";
		case ToolCallCategory::UrlGeneration:
			return "URL Generation";
		case ToolCallCategory::Diffing:
			return "Diffing";
		case ToolCallCategory::KernelCache:
			return "KernelCache";
		case ToolCallCategory::SharedCache:
			return "SharedCache";
		case ToolCallCategory::Debugger:
			return "Debugger";
		}
		return "Core Workflow";
	}

	std::string_view ToolCallCategoryId(ToolCallCategory category)
	{
		switch (category)
		{
		case ToolCallCategory::Core:
			return "core";
		case ToolCallCategory::ProjectManagement:
			return "project_management";
		case ToolCallCategory::FunctionAnalysis:
			return "function_analysis";
		case ToolCallCategory::BinaryData:
			return "binary_data";
		case ToolCallCategory::Search:
			return "search";
		case ToolCallCategory::Types:
			return "types";
		case ToolCallCategory::Annotations:
			return "annotations";
		case ToolCallCategory::BinaryEditing:
			return "binary_editing";
		case ToolCallCategory::History:
			return "history";
		case ToolCallCategory::HeaderParsing:
			return "header_parsing";
		case ToolCallCategory::UrlGeneration:
			return "url_generation";
		case ToolCallCategory::Diffing:
			return "diffing";
		case ToolCallCategory::KernelCache:
			return "kernel_cache";
		case ToolCallCategory::SharedCache:
			return "shared_cache";
		case ToolCallCategory::Debugger:
			return "debugger";
		}
		return "core";
	}

	bool ToolCallCategoryEnabled(ToolCallCategory category, const ToolConfig& config)
	{
		switch (category)
		{
		case ToolCallCategory::Core:
			return true;
		case ToolCallCategory::ProjectManagement:
			return config.projectManagement;
		case ToolCallCategory::FunctionAnalysis:
			return config.functionAnalysis;
		case ToolCallCategory::BinaryData:
			return config.binaryData;
		case ToolCallCategory::Search:
			return config.search;
		case ToolCallCategory::Types:
			return config.types;
		case ToolCallCategory::Annotations:
			return config.annotations;
		case ToolCallCategory::BinaryEditing:
			return config.binaryEditing;
		case ToolCallCategory::History:
			return config.history;
		case ToolCallCategory::HeaderParsing:
			return config.headerParsing;
		case ToolCallCategory::UrlGeneration:
			return config.urlGeneration;
		case ToolCallCategory::Diffing:
			return config.diffing;
		case ToolCallCategory::KernelCache:
			return config.kernelCache;
		case ToolCallCategory::SharedCache:
			return config.sharedCache;
		case ToolCallCategory::Debugger:
			return config.debugger;
		}
		return false;
	}

	bool ToolCallAdvertised(const ToolCall& tool, ToolDiscoveryMode mode)
	{
		if (mode == ToolDiscoveryMode::Full)
			return tool.Name() != kToolBrokerName;
		const auto name = tool.Name();
		return name == kToolBrokerName || name == "bn_analysis_session_create" || name == "bn_analysis_session_close"
			|| name == "bn_open_item_open" || name == "bn_open_item_close" || name == "bn_binary_view_open";
	}

	namespace {
		struct ToolCallRegistry
		{
			std::vector<std::unique_ptr<ToolCall>> tools;
			std::unordered_map<std::string_view, const ToolCall*> byName;
		};

		const ToolCallRegistry& Registry()
		{
			static const auto registry = [] {
				ToolCallRegistry result;
				RegisterToolBroker(result.tools);
				RegisterCoreSessionTools(result.tools);
				RegisterCoreProjectTools(result.tools);
				RegisterProjectManagementTools(result.tools);
				RegisterCoreFileTools(result.tools);
				RegisterCoreAnalysisTools(result.tools);
				RegisterCoreUploadTools(result.tools);
				RegisterCoreJobTools(result.tools);
				RegisterFunctionAnalysisTools(result.tools);
				RegisterBinaryDataTools(result.tools);
				RegisterSearchTools(result.tools);
				RegisterTypeTools(result.tools);
				RegisterAnnotationTools(result.tools);
				RegisterBinaryEditingTools(result.tools);
				RegisterHistoryTools(result.tools);
				RegisterHeaderParsingTools(result.tools);
				RegisterUrlGenerationTools(result.tools);
				RegisterDiffingTools(result.tools);
				RegisterKernelCacheTools(result.tools);
				RegisterSharedCacheTools(result.tools);
				RegisterDebuggerTools(result.tools);

				result.byName.reserve(result.tools.size());
				for (const auto& tool : result.tools)
				{
					(void)tool->InputSchema();
					if (!result.byName.emplace(tool->Name(), tool.get()).second)
						throw std::logic_error("duplicate MCP tool registration");
				}
				return result;
			}();
			return registry;
		}
	}  // namespace

	const std::vector<std::unique_ptr<ToolCall>>& RegisteredToolCalls()
	{
		return Registry().tools;
	}

	const ToolCall* FindToolCall(std::string_view name)
	{
		const auto found = Registry().byName.find(name);
		return found == Registry().byName.end() ? nullptr : found->second;
	}
}  // namespace binjad::mcp
