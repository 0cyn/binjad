#include "../ToolCall.hpp"
#include "../ToolSchema.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace binjad::mcp {
	namespace {
		using rapidjson::StringBuffer;
		using rapidjson::Value;
		using rapidjson::Writer;

		constexpr std::array kCategories {
			ToolCallCategory::Core,
			ToolCallCategory::ProjectManagement,
			ToolCallCategory::FunctionAnalysis,
			ToolCallCategory::BinaryData,
			ToolCallCategory::Search,
			ToolCallCategory::Types,
			ToolCallCategory::Annotations,
			ToolCallCategory::BinaryEditing,
			ToolCallCategory::History,
			ToolCallCategory::HeaderParsing,
			ToolCallCategory::UrlGeneration,
			ToolCallCategory::Diffing,
			ToolCallCategory::KernelCache,
			ToolCallCategory::SharedCache,
			ToolCallCategory::Debugger,
		};

		std::string_view CategoryDescription(ToolCallCategory category)
		{
			return docs::Category(ToolCallCategoryId(category)).description;
		}

		std::optional<ToolCallCategory> ParseCategory(std::string_view id)
		{
			for (const auto category : kCategories)
				if (ToolCallCategoryId(category) == id)
					return category;
			return std::nullopt;
		}

		bool ContainsInsensitive(std::string_view value, std::string_view query)
		{
			if (query.empty())
				return true;
			return std::search(value.begin(), value.end(), query.begin(), query.end(), [](char left, char right) {
				return std::tolower(static_cast<unsigned char>(left))
					== std::tolower(static_cast<unsigned char>(right));
			}) != value.end();
		}

		bool Available(const ToolCall& tool, const ToolCallContext& context)
		{
			return tool.Name() != kToolBrokerName
				&& tool.IsAvailable(context.config, context.request.version, context.principal.role);
		}

		std::optional<std::string> StringArgument(const Value& arguments, const char* name)
		{
			const auto member = arguments.FindMember(name);
			if (member == arguments.MemberEnd())
				return std::nullopt;
			return std::string(member->value.GetString(), member->value.GetStringLength());
		}

		class ToolBroker final : public ToolCall
		{
		public:
			ToolBroker() : ToolCall(kToolBrokerName, ToolCallCategory::Core) {}

			FoundationResult Execute(const ToolCallContext& context) const override
			{
				if (context.config.tools.discoveryMode != ToolDiscoveryMode::Brokered)
					return ToolCallInvalidArguments(context, "bn_tools requires brokered discovery mode");
				const auto operation = StringArgument(context.arguments, "operation");
				if (!operation)
					return ToolCallInvalidArguments(context, "operation is required");
				if (*operation == "categories")
					return Categories(context);
				if (*operation == "list")
					return List(context);
				if (*operation == "describe")
					return Describe(context);
				if (*operation == "call")
					return Call(context);
				return ToolCallInvalidArguments(context, "unsupported broker operation");
			}

		private:
			void WriteInputSchema(ToolCallSchemaWriter& writer) const override
			{
				schema::WriteObject(writer, kToolBrokerName,
					{schema::Enum("operation", true, {"categories", "list", "describe", "call"},
						 "Choose category discovery, compact tool listing, exact schema lookup, or invocation."),
						schema::Enum("category", false,
							{"core", "project_management", "function_analysis", "binary_data", "search", "types",
								"annotations", "binary_editing", "history", "header_parsing", "url_generation",
								"diffing", "kernel_cache", "shared_cache", "debugger"},
							"Required by list."),
						schema::NonEmptyString("query", false, "Optional case-insensitive name or description filter."),
						schema::NonEmptyString("name", false, "Required by describe and call."),
						schema::Object("arguments", false, "Arguments for the selected tool when operation is call."),
						schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000, 50)});
			}

			FoundationResult Categories(const ToolCallContext& context) const
			{
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("categories");
				writer.StartArray();
				for (const auto category : kCategories)
				{
					std::size_t count = 0;
					for (const auto& tool : RegisteredToolCalls())
						if (tool->Category() == category && Available(*tool, context))
							++count;
					writer.StartObject();
					writer.Key("id");
					const auto id = ToolCallCategoryId(category);
					writer.String(id.data(), static_cast<rapidjson::SizeType>(id.size()));
					writer.Key("name");
					const auto name = ToolCallCategoryName(category);
					writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
					writer.Key("description");
					const auto description = CategoryDescription(category);
					writer.String(description.data(), static_cast<rapidjson::SizeType>(description.size()));
					writer.Key("enabled");
					writer.Bool(ToolCallCategoryEnabled(category, context.config.tools));
					writer.Key("toolCount");
					writer.Uint64(count);
					writer.EndObject();
				}
				writer.EndArray();
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult List(const ToolCallContext& context) const
			{
				const auto categoryName = StringArgument(context.arguments, "category");
				const auto category = categoryName ? ParseCategory(*categoryName) : std::nullopt;
				if (!category)
					return ToolCallInvalidArguments(context, "list requires a valid category");
				const auto query = StringArgument(context.arguments, "query").value_or("");
				std::size_t offset = 0;
				std::size_t limit = 50;
				if (const auto member = context.arguments.FindMember("offset"); member != context.arguments.MemberEnd())
					offset = static_cast<std::size_t>(member->value.GetUint64());
				if (const auto member = context.arguments.FindMember("limit"); member != context.arguments.MemberEnd())
					limit = static_cast<std::size_t>(member->value.GetUint64());

				std::vector<const ToolCall*> matches;
				for (const auto& tool : RegisteredToolCalls())
				{
					if (tool->Category() != *category || !Available(*tool, context))
						continue;
					if (!ContainsInsensitive(tool->Name(), query) && !ContainsInsensitive(tool->Description(), query))
						continue;
					matches.push_back(tool.get());
				}
				const auto begin = std::min(offset, matches.size());
				const auto end = std::min(matches.size(), begin + limit);
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("category");
				writer.String(categoryName->data(), static_cast<rapidjson::SizeType>(categoryName->size()));
				writer.Key("tools");
				writer.StartArray();
				for (auto index = begin; index < end; ++index)
				{
					const auto& tool = *matches[index];
					writer.StartObject();
					writer.Key("name");
					writer.String(tool.Name().data(), static_cast<rapidjson::SizeType>(tool.Name().size()));
					writer.Key("description");
					writer.String(
						tool.Description().data(), static_cast<rapidjson::SizeType>(tool.Description().size()));
					writer.Key("direct");
					writer.Bool(ToolCallAdvertised(tool, ToolDiscoveryMode::Brokered));
					writer.EndObject();
				}
				writer.EndArray();
				writer.Key("offset");
				writer.Uint64(begin);
				writer.Key("limit");
				writer.Uint64(limit);
				writer.Key("total");
				writer.Uint64(matches.size());
				if (end < matches.size())
				{
					writer.Key("nextOffset");
					writer.Uint64(end);
				}
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult Describe(const ToolCallContext& context) const
			{
				const auto name = StringArgument(context.arguments, "name");
				const auto* tool = name ? FindToolCall(*name) : nullptr;
				if (!tool || !Available(*tool, context))
					return ToolCallInvalidArguments(context, "describe requires an available tool name");
				StringBuffer buffer;
				Writer<StringBuffer> writer(buffer);
				writer.StartObject();
				writer.Key("name");
				writer.String(tool->Name().data(), static_cast<rapidjson::SizeType>(tool->Name().size()));
				writer.Key("category");
				const auto category = ToolCallCategoryId(tool->Category());
				writer.String(category.data(), static_cast<rapidjson::SizeType>(category.size()));
				writer.Key("description");
				writer.String(tool->Description().data(), static_cast<rapidjson::SizeType>(tool->Description().size()));
				writer.Key("inputSchema");
				const auto schema = tool->InputSchema();
				writer.RawValue(schema.data(), schema.size(), rapidjson::kObjectType);
				writer.EndObject();
				return ToolCallSuccess(context, {buffer.GetString(), buffer.GetSize()});
			}

			FoundationResult Call(const ToolCallContext& context) const
			{
				const auto name = StringArgument(context.arguments, "name");
				const auto* tool = name ? FindToolCall(*name) : nullptr;
				if (!tool || tool->Name() == kToolBrokerName
					|| !tool->CanExecute(context.config, context.request.version, context.principal.role))
					return ToolCallInvalidArguments(context, "call requires an available non-broker tool name");

				const Value emptyArguments(rapidjson::kObjectType);
				const auto member = context.arguments.FindMember("arguments");
				const auto& arguments = member == context.arguments.MemberEnd() ? emptyArguments : member->value;
				std::string error;
				if (!tool->ValidateArguments(arguments, error))
					return ToolCallInvalidArguments(context, std::string(tool->Name()) + ": " + error);

				auto request = context.request;
				request.name = *name;
				auto result = tool->Execute({context.config, context.sessions, context.serverVersion, context.openItems,
					context.fileCoordinator, context.jobs, context.projects, context.projectCoordinator,
					context.scheduler, context.uploads, context.downloads, request, context.principal,
					context.currentSession, context.now, context.unixNow, context.progress, context.attached,
					arguments});
				result.invokedTool = *name;
				return result;
			}
		};
	}  // namespace

	void RegisterToolBroker(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<ToolBroker>());
	}
}  // namespace binjad::mcp
