#include "../ToolCall.hpp"
#include "../ToolSchema.hpp"

#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/session/OpenItemRegistry.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>

namespace binjad::mcp {
	namespace {
		bool IsUnreserved(unsigned char value)
		{
			return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
				|| value == '-' || value == '.' || value == '_' || value == '~';
		}

		std::string PercentEncode(std::string_view value, bool path)
		{
			constexpr char hex[] = "0123456789ABCDEF";
			std::string encoded;
			encoded.reserve(value.size());
			for (const auto raw : value)
			{
				const auto byte = static_cast<unsigned char>(raw);
				if (IsUnreserved(byte) || (path && (byte == '/' || byte == ':')))
				{
					encoded.push_back(static_cast<char>(byte));
					continue;
				}
				encoded.push_back('%');
				encoded.push_back(hex[byte >> 4]);
				encoded.push_back(hex[byte & 0xf]);
			}
			return encoded;
		}

		std::string LocalPathUrl(std::string path)
		{
			for (auto& value : path)
				if (value == '\\')
					value = '/';
			const auto encoded = PercentEncode(path, true);
			if (path.starts_with("//"))
				return "binaryninja:" + encoded;
			if (path.starts_with("/"))
				return "binaryninja://" + encoded;
			return "binaryninja:///" + encoded;
		}

		bool IsHexDigit(char value)
		{
			return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
		}

		bool ValidRemoteUrl(std::string_view url, std::string& error)
		{
			for (std::size_t index = 0; index < url.size(); ++index)
			{
				const auto value = static_cast<unsigned char>(url[index]);
				if (value <= 0x20 || value == 0x7f)
				{
					error = "url must not contain raw whitespace or control characters";
					return false;
				}
				if (value == '%'
					&& (index + 2 >= url.size() || !IsHexDigit(url[index + 1]) || !IsHexDigit(url[index + 2])))
				{
					error = "url contains an invalid percent escape";
					return false;
				}
				if (value == '%')
					index += 2;
			}

			const auto schemeEnd = url.find(':');
			if (schemeEnd == std::string_view::npos)
			{
				error = "url must be an absolute http, https, or file URL";
				return false;
			}
			std::string scheme(url.substr(0, schemeEnd));
			for (auto& value : scheme)
				value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
			if (scheme != "http" && scheme != "https" && scheme != "file")
			{
				error = "url scheme must be http, https, or file";
				return false;
			}
			const auto remainder = url.substr(schemeEnd + 1);
			if (!remainder.starts_with("//") || remainder.size() == 2 || remainder[2] == '?' || remainder[2] == '#')
			{
				error = "url must use an absolute hierarchical form";
				return false;
			}
			if (scheme != "file")
			{
				const auto authorityEnd = remainder.find_first_of("/?#", 2);
				if (authorityEnd == 2)
				{
					error = "http and https URLs must include a host";
					return false;
				}
			}
			return true;
		}

		bool HasExpressionParameter(std::string_view url)
		{
			const auto query = url.find('?');
			const auto fragment = url.find('#');
			if (query == std::string_view::npos || (fragment != std::string_view::npos && query > fragment))
				return false;
			auto remaining = url.substr(
				query + 1, fragment == std::string_view::npos ? std::string_view::npos : fragment - query - 1);
			while (!remaining.empty())
			{
				const auto separator = remaining.find('&');
				const auto parameter = remaining.substr(0, separator);
				if (parameter.substr(0, parameter.find('=')) == "expr")
					return true;
				if (separator == std::string_view::npos)
					break;
				remaining.remove_prefix(separator + 1);
			}
			return false;
		}

		std::string WithExpression(std::string url, std::string_view expression)
		{
			if (expression.empty())
				return url;
			const auto fragment = url.find('#');
			const auto insertion = fragment == std::string::npos ? url.size() : fragment;
			const auto query = url.find('?');
			char separator = '?';
			if (query != std::string::npos && query < insertion)
				separator = insertion != 0 && (url[insertion - 1] == '?' || url[insertion - 1] == '&') ? '\0' : '&';
			std::string parameter;
			if (separator != '\0')
				parameter.push_back(separator);
			parameter += "expr=" + PercentEncode(expression, false);
			url.insert(insertion, parameter);
			return url;
		}

		std::string ErrorJson(std::string_view message)
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("error");
			writer.String(message.data(), static_cast<rapidjson::SizeType>(message.size()));
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		std::string UrlJson(std::string_view url, std::string_view sourceKind, std::string_view expression,
			std::string_view openItem = {}, std::string_view project = {}, std::string_view projectPath = {})
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("url");
			writer.String(url.data(), static_cast<rapidjson::SizeType>(url.size()));
			writer.Key("sourceKind");
			writer.String(sourceKind.data(), static_cast<rapidjson::SizeType>(sourceKind.size()));
			if (!openItem.empty())
			{
				writer.Key("openItem");
				writer.String(openItem.data(), static_cast<rapidjson::SizeType>(openItem.size()));
			}
			if (!project.empty())
			{
				writer.Key("project");
				writer.String(project.data(), static_cast<rapidjson::SizeType>(project.size()));
				writer.Key("path");
				writer.String(projectPath.data(), static_cast<rapidjson::SizeType>(projectPath.size()));
			}
			if (!expression.empty())
			{
				writer.Key("expr");
				writer.String(expression.data(), static_cast<rapidjson::SizeType>(expression.size()));
			}
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		std::string StringArgument(const rapidjson::Value& arguments, const char* name)
		{
			const auto member = arguments.FindMember(name);
			return member == arguments.MemberEnd() ?
				std::string {} :
				std::string(member->value.GetString(), member->value.GetStringLength());
		}

		bool IsBndbPath(std::string_view path)
		{
			auto extension = std::filesystem::path(path).extension().string();
			std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
				return static_cast<char>(std::tolower(value));
			});
			return extension == ".bndb";
		}

		class OpenItemUrlTool final : public ToolCall
		{
		public:
			OpenItemUrlTool() : ToolCall("bn_url_open_item", ToolCallCategory::UrlGeneration) {}

			FoundationResult Execute(const ToolCallContext& context) const override
			{
				if (!context.openItems)
					return ToolCallSuccess(context, ErrorJson("open-item service is unavailable"), true);
				const auto reference = StringArgument(context.arguments, "openItem");
				const auto item = context.openItems->FindOpenItem(context.principal.id, reference);
				if (!item)
					return ToolCallSuccess(context, ErrorJson("open item not found"), true);
				if (item->sourceKind != session::OpenItemSourceKind::ArbitraryPath)
					return ToolCallSuccess(
						context, ErrorJson("open item is project-backed; use bn_url_project_file instead"), true);
				if (!std::filesystem::path(item->source).is_absolute())
					return ToolCallSuccess(context, ErrorJson("open item source is not an absolute path"), true);
				const auto expression = StringArgument(context.arguments, "expr");
				return ToolCallSuccess(context,
					UrlJson(
						WithExpression(LocalPathUrl(item->source), expression), "path", expression, item->reference));
			}

		private:
			void WriteInputSchema(ToolCallSchemaWriter& writer) const override
			{
				schema::WriteObject(writer, "bn_url_open_item",
					{schema::String("openItem", true,
						 "Owned arbitrary-path open-item reference. Use bn_url_project_file for local-project items."),
						schema::NonEmptyString("expr", false,
							"Optional Binary Ninja navigation expression, such as a function, section, or address.")});
			}
		};

		class ProjectFileUrlTool final : public ToolCall
		{
		public:
			ProjectFileUrlTool() :
				ToolCall("bn_url_project_file", ToolCallCategory::UrlGeneration, ToolCallAvailability::LocalMode)
			{}

			FoundationResult Execute(const ToolCallContext& context) const override
			{
				if (!context.openItems || !context.projectCoordinator)
					return ToolCallSuccess(
						context, ErrorJson("open-item or local-project service is unavailable"), true);
				const auto reference = StringArgument(context.arguments, "openItem");
				const auto item = context.openItems->FindOpenItem(context.principal.id, reference);
				if (!item)
					return ToolCallSuccess(context, ErrorJson("open item not found"), true);
				if (item->sourceKind != session::OpenItemSourceKind::LocalProject || !item->project)
					return ToolCallSuccess(context,
						ErrorJson("open item is not backed by a local project; use bn_url_open_item instead"), true);
				if (!IsBndbPath(item->source))
					return ToolCallSuccess(context,
						ErrorJson("project open item does not target a saved BNDB; call bn_binary_view_save first"),
						true);

				const auto files = context.projectCoordinator->ListFiles(*item->project);
				if (!files.value)
					return ToolCallSuccess(context, ErrorJson(files.error), true);
				const auto file = std::find_if(files.value->begin(), files.value->end(), [&](const auto& candidate) {
					return candidate.path == item->source;
				});
				if (file == files.value->end())
					return ToolCallSuccess(context, ErrorJson("project file not found"), true);
				if (!file->backingPath.is_absolute())
					return ToolCallSuccess(context, ErrorJson("project file has no absolute backing path"), true);

				const auto expression = StringArgument(context.arguments, "expr");
				return ToolCallSuccess(context,
					UrlJson(WithExpression(LocalPathUrl(file->backingPath.string()), expression), "local_project",
						expression, item->reference, *item->project, item->source));
			}

		private:
			void WriteInputSchema(ToolCallSchemaWriter& writer) const override
			{
				writer.StartObject();
				writer.Key("type");
				writer.String("object");
				writer.Key("properties");
				writer.StartObject();
				writer.Key("openItem");
				writer.StartObject();
				writer.Key("type");
				writer.String("string");
				writer.Key("minLength");
				writer.Uint(1);
				writer.Key("description");
				const auto openItemDescription = docs::ToolArgument("bn_url_project_file", "openItem");
				writer.String(openItemDescription.data(), static_cast<rapidjson::SizeType>(openItemDescription.size()));
				writer.EndObject();
				writer.Key("updated_bndb_has_been_saved");
				writer.StartObject();
				writer.Key("type");
				writer.String("boolean");
				writer.Key("enum");
				writer.StartArray();
				writer.Bool(true);
				writer.EndArray();
				writer.Key("description");
				const auto acknowledgementDescription =
					docs::ToolArgument("bn_url_project_file", "updated_bndb_has_been_saved");
				writer.String(acknowledgementDescription.data(),
					static_cast<rapidjson::SizeType>(acknowledgementDescription.size()));
				writer.EndObject();
				writer.Key("expr");
				writer.StartObject();
				writer.Key("type");
				writer.String("string");
				writer.Key("minLength");
				writer.Uint(1);
				writer.Key("description");
				const auto expressionDescription = docs::ToolArgument("bn_url_project_file", "expr");
				writer.String(
					expressionDescription.data(), static_cast<rapidjson::SizeType>(expressionDescription.size()));
				writer.EndObject();
				writer.EndObject();
				writer.Key("required");
				writer.StartArray();
				writer.String("openItem");
				writer.String("updated_bndb_has_been_saved");
				writer.EndArray();
				writer.Key("additionalProperties");
				writer.Bool(false);
				writer.EndObject();
			}
		};

		class RemoteFileUrlTool final : public ToolCall
		{
		public:
			RemoteFileUrlTool() : ToolCall("bn_url_remote_file", ToolCallCategory::UrlGeneration) {}

			FoundationResult Execute(const ToolCallContext& context) const override
			{
				const auto source = StringArgument(context.arguments, "url");
				std::string error;
				if (!ValidRemoteUrl(source, error))
					return ToolCallSuccess(context, ErrorJson(error), true);
				const auto expression = StringArgument(context.arguments, "expr");
				if (!expression.empty() && HasExpressionParameter(source))
					return ToolCallSuccess(context, ErrorJson("url already contains an expr query parameter"), true);
				return ToolCallSuccess(
					context, UrlJson(WithExpression("binaryninja:" + source, expression), "remote", expression));
			}

		private:
			void WriteInputSchema(ToolCallSchemaWriter& writer) const override
			{
				schema::WriteObject(writer, "bn_url_remote_file",
					{schema::String("url", true,
						 "Absolute http, https, or file URL in standard hierarchical form; do not encode the scheme or "
						 ":// separators."),
						schema::NonEmptyString("expr", false,
							"Optional Binary Ninja navigation expression, such as a function, section, or address.")});
			}
		};
	}  // namespace

	void RegisterUrlGenerationTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<OpenItemUrlTool>());
		tools.emplace_back(std::make_unique<ProjectFileUrlTool>());
		tools.emplace_back(std::make_unique<RemoteFileUrlTool>());
	}
}  // namespace binjad::mcp
