#include "ToolCall.hpp"

#include "ModelFacingDocs.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <unordered_map>

namespace binjad::mcp {
	ToolCall::ToolCall(std::string_view name, ToolCallCategory category, ToolCallAvailability availability) :
		name_(name), description_(docs::Tool(name).description), category_(category),
		documentationCategory_(docs::Tool(name).category), availability_(availability)
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
			return std::string(ToolCallCategoryName(category_)) + std::string(docs::Availability("disabled_suffix"));
		if (HasAvailability(availability_, ToolCallAvailability::ModernProtocol) && !IsModern(version))
			return std::string(docs::Availability("modern_protocol"));
		if (HasAvailability(availability_, ToolCallAvailability::Admin) && role != security::TokenRole::Admin)
			return std::string(docs::Availability("admin"));
		if (HasAvailability(availability_, ToolCallAvailability::ArbitraryPaths)
			&& !config.projects.allowArbitraryPaths)
			return std::string(docs::Availability("arbitrary_paths"));
		if (HasAvailability(availability_, ToolCallAvailability::ProjectRegistration)
			&& !config.projects.allowProjectRegistration)
			return std::string(docs::Availability("project_registration"));
		return std::string(docs::Availability("not_advertised"));
	}

	std::string_view ToolCallCategoryName(ToolCallCategory category)
	{
		return docs::Category(ToolCallCategoryId(category)).name;
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
		static constexpr std::array<std::string_view, 15> brokeredTools {
			kToolBrokerName,
			"bn_analysis_session_create",
			"bn_analysis_session_close",
			"bn_local_project_list",
			"bn_local_project_file_list",
			"bn_open_item_open",
			"bn_open_item_close",
			"bn_binary_view_open",
			"bn_analysis_status",
			"bn_analysis_update_and_wait",
			"bn_binary_view_save",
			"bn_job_list",
			"bn_job_info",
			"bn_job_result",
			"bn_job_cancel",
		};
		return std::find(brokeredTools.begin(), brokeredTools.end(), tool.Name()) != brokeredTools.end();
	}

	namespace {
		const rapidjson::Value* ObjectMember(const rapidjson::Value& object, std::string_view name)
		{
			if (!object.IsObject())
				return nullptr;
			for (auto member = object.MemberBegin(); member != object.MemberEnd(); ++member)
				if (std::string_view(member->name.GetString(), member->name.GetStringLength()) == name)
					return &member->value;
			return nullptr;
		}

		const rapidjson::Value* SchemaProperty(const rapidjson::Document& schema, std::string_view path)
		{
			const auto separator = path.find('.');
			const auto outerName = path.substr(0, separator);
			const auto* properties = ObjectMember(schema, "properties");
			if (!properties)
				return nullptr;
			const auto* outer = ObjectMember(*properties, outerName);
			if (!outer || separator == std::string_view::npos)
				return outer;

			const auto* items = ObjectMember(*outer, "items");
			if (!items)
				return nullptr;
			const auto* itemProperties = ObjectMember(*items, "properties");
			if (!itemProperties)
				return nullptr;
			const auto innerName = path.substr(separator + 1);
			return ObjectMember(*itemProperties, innerName);
		}

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
					const auto inputSchema = tool->InputSchema();
					if (!result.byName.emplace(tool->Name(), tool.get()).second)
						throw std::logic_error("duplicate MCP tool registration");

					rapidjson::Document schema;
					schema.Parse(inputSchema.data(), inputSchema.size());
					if (schema.HasParseError() || !schema.IsObject())
						throw std::logic_error("invalid schema for documented MCP tool: " + std::string(tool->Name()));
					for (const auto& [argument, description] : docs::Tool(tool->Name()).arguments)
					{
						const auto* property = SchemaProperty(schema, argument);
						if (!property)
							throw std::logic_error("model-facing documentation references an unknown argument: "
								+ std::string(tool->Name()) + "." + std::string(argument));
						const auto* documented = ObjectMember(*property, "description");
						if (!documented || !documented->IsString()
							|| std::string_view(documented->GetString(), documented->GetStringLength()) != description)
							throw std::logic_error("model-facing argument documentation was not applied: "
								+ std::string(tool->Name()) + "." + std::string(argument));
					}
				}
				for (const auto& [name, documentation] : docs::Tools())
				{
					(void)documentation;
					if (!result.byName.contains(name))
						throw std::logic_error(
							"model-facing documentation references an unregistered tool: " + std::string(name));
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
