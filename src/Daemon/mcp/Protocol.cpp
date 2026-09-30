#include "binjad/mcp/Protocol.hpp"

#include "ModelFacingDocs.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <type_traits>
#include <utility>

namespace binjad::mcp {
	namespace {
		using rapidjson::Document;
		using rapidjson::StringBuffer;
		using rapidjson::Value;
		using rapidjson::Writer;

		constexpr std::array kSupportedVersions {
			ProtocolVersion::V2026_07_28,
			ProtocolVersion::V2025_11_25,
			ProtocolVersion::V2025_06_18,
			ProtocolVersion::V2025_03_26,
		};

		ProtocolError Error(int code, int status, std::string message, std::optional<RequestId> id = std::nullopt,
			std::string dataJson = {})
		{
			return {code, status, std::move(message), std::move(id), std::move(dataJson)};
		}

		bool ParseRequestId(const Value& value, RequestId& result)
		{
			if (value.IsString())
			{
				result = std::string(value.GetString(), value.GetStringLength());
				return true;
			}
			if (value.IsInt64())
			{
				result = value.GetInt64();
				return true;
			}
			if (value.IsUint64())
			{
				result = value.GetUint64();
				return true;
			}
			return false;
		}

		template <typename OutputStream>
		void WriteRequestId(Writer<OutputStream>& writer, const RequestId& id)
		{
			std::visit(
				[&](const auto& value) {
					using T = std::decay_t<decltype(value)>;
					if constexpr (std::is_same_v<T, std::string>)
						writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
					else if constexpr (std::is_same_v<T, std::int64_t>)
						writer.Int64(value);
					else
						writer.Uint64(value);
				},
				id);
		}

		std::string Serialize(const Value& value)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			value.Accept(writer);
			return {buffer.GetString(), buffer.GetSize()};
		}

		bool IsRequestMethod(std::string_view method)
		{
			return method != "notifications/initialized" && method != "notifications/cancelled";
		}

		const Value* Params(const Value& root, bool required, std::string& error)
		{
			const auto member = root.FindMember("params");
			if (member == root.MemberEnd())
			{
				if (required)
					error = "params is required";
				return nullptr;
			}
			if (!member->value.IsObject())
			{
				error = "params must be an object";
				return nullptr;
			}
			return &member->value;
		}

		bool OptionalString(const Value& object, const char* name, std::string& destination, std::string& error)
		{
			const auto member = object.FindMember(name);
			if (member == object.MemberEnd())
				return true;
			if (!member->value.IsString())
			{
				error = std::string(name) + " must be a string";
				return false;
			}
			destination.assign(member->value.GetString(), member->value.GetStringLength());
			return true;
		}

		bool RequiredString(const Value& object, const char* name, std::string& destination, std::string& error)
		{
			const auto member = object.FindMember(name);
			if (member == object.MemberEnd() || !member->value.IsString() || member->value.GetStringLength() == 0)
			{
				error = std::string(name) + " must be a non-empty string";
				return false;
			}
			destination.assign(member->value.GetString(), member->value.GetStringLength());
			return true;
		}

		bool ValidatePagination(const Value* params, ValidatedRequest& request, std::string& error)
		{
			return !params || OptionalString(*params, "cursor", request.cursor, error);
		}

		bool ValidateSubscriptionFilter(const Value& params, ValidatedRequest& request, std::string& error)
		{
			const auto notifications = params.FindMember("notifications");
			if (notifications == params.MemberEnd() || !notifications->value.IsObject())
			{
				error = "notifications must be an object";
				return false;
			}

			SubscriptionFilter filter;
			const std::pair<const char*, bool*> supportedBooleans[] = {
				{"toolsListChanged", &filter.toolsListChanged},
				{"resourcesListChanged", &filter.resourcesListChanged},
			};
			for (const auto& [name, output] : supportedBooleans)
			{
				const auto member = notifications->value.FindMember(name);
				if (member == notifications->value.MemberEnd())
					continue;
				if (!member->value.IsBool())
				{
					error = std::string("notifications.") + name + " must be a boolean";
					return false;
				}
				*output = member->value.GetBool();
			}
			if (const auto prompts = notifications->value.FindMember("promptsListChanged");
				prompts != notifications->value.MemberEnd() && !prompts->value.IsBool())
			{
				error = "notifications.promptsListChanged must be a boolean";
				return false;
			}

			const auto resources = notifications->value.FindMember("resourceSubscriptions");
			if (resources != notifications->value.MemberEnd())
			{
				if (!resources->value.IsArray())
				{
					error = "notifications.resourceSubscriptions must be an array";
					return false;
				}
				for (const auto& value : resources->value.GetArray())
				{
					if (!value.IsString() || value.GetStringLength() == 0)
					{
						error = "notifications.resourceSubscriptions must contain non-empty strings";
						return false;
					}
					filter.resourceSubscriptions.emplace_back(value.GetString(), value.GetStringLength());
				}
			}
			request.subscription = std::move(filter);
			return true;
		}

		bool ValidateMethod(const Value& root, ValidatedRequest& request, std::string& error)
		{
			const bool modern = IsModern(request.version);
			const bool paramsRequired = modern || request.method == "initialize" || request.method == "tools/call"
				|| request.method == "resources/read" || request.method == "resources/subscribe"
				|| request.method == "resources/unsubscribe" || request.method == "subscriptions/listen"
				|| request.method == "notifications/cancelled";
			const auto* params = Params(root, paramsRequired, error);
			if (!error.empty())
				return false;
			if (params)
				request.paramsJson = Serialize(*params);

			if (request.method == "server/discover")
				return modern;
			if (request.method == "ping")
				return !modern;
			if (request.method == "tools/list" || request.method == "resources/list"
				|| request.method == "resources/templates/list")
				return ValidatePagination(params, request, error);
			if (request.method == "tools/call")
			{
				if (!RequiredString(*params, "name", request.name, error))
					return false;
				const auto arguments = params->FindMember("arguments");
				if (arguments != params->MemberEnd() && !arguments->value.IsObject())
				{
					error = "arguments must be an object";
					return false;
				}
				return true;
			}
			if (request.method == "resources/read" || request.method == "resources/subscribe"
				|| request.method == "resources/unsubscribe")
			{
				if (modern && request.method != "resources/read")
					return false;
				return RequiredString(*params, "uri", request.uri, error);
			}
			if (request.method == "subscriptions/listen")
				return modern && ValidateSubscriptionFilter(*params, request, error);
			if (request.method == "notifications/initialized")
				return !modern;
			if (request.method == "notifications/cancelled")
			{
				if (modern)
					return false;
				const auto requestId = params->FindMember("requestId");
				RequestId ignored;
				if (requestId == params->MemberEnd() || !ParseRequestId(requestId->value, ignored))
				{
					error = "requestId must be a string or integer";
					return false;
				}
				const auto reason = params->FindMember("reason");
				if (reason != params->MemberEnd() && !reason->value.IsString())
				{
					error = "reason must be a string";
					return false;
				}
				return true;
			}
			return false;
		}

		bool ValidateImplementation(const Value& value, std::string& error)
		{
			if (!value.IsObject())
			{
				error = "clientInfo must be an object";
				return false;
			}
			std::string ignored;
			return RequiredString(value, "name", ignored, error) && RequiredString(value, "version", ignored, error);
		}

		bool ValidateInitialize(const Value& root, std::string& requestedVersion, std::string& error)
		{
			const auto* params = Params(root, true, error);
			if (!params)
				return false;
			if (!RequiredString(*params, "protocolVersion", requestedVersion, error))
				return false;
			const auto capabilities = params->FindMember("capabilities");
			if (capabilities == params->MemberEnd() || !capabilities->value.IsObject())
			{
				error = "capabilities must be an object";
				return false;
			}
			const auto clientInfo = params->FindMember("clientInfo");
			if (clientInfo == params->MemberEnd())
			{
				error = "clientInfo is required";
				return false;
			}
			return ValidateImplementation(clientInfo->value, error);
		}

		std::optional<std::string> DecodeBase64(std::string_view encoded)
		{
			static constexpr std::string_view alphabet =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
			if (encoded.empty() || encoded.size() % 4 != 0)
				return std::nullopt;
			std::string result;
			result.reserve(encoded.size() / 4 * 3);
			for (std::size_t offset = 0; offset < encoded.size(); offset += 4)
			{
				std::uint32_t value = 0;
				int padding = 0;
				for (std::size_t index = 0; index < 4; ++index)
				{
					const char character = encoded[offset + index];
					if (character == '=')
					{
						if (index < 2 || offset + 4 != encoded.size())
							return std::nullopt;
						++padding;
						value <<= 6;
						continue;
					}
					if (padding != 0)
						return std::nullopt;
					const auto position = alphabet.find(character);
					if (position == std::string_view::npos)
						return std::nullopt;
					value = (value << 6) | static_cast<std::uint32_t>(position);
				}
				result.push_back(static_cast<char>((value >> 16) & 0xff));
				if (padding < 2)
					result.push_back(static_cast<char>((value >> 8) & 0xff));
				if (padding < 1)
					result.push_back(static_cast<char>(value & 0xff));
			}
			return result;
		}

		std::optional<std::string> DecodeHeader(std::string_view value)
		{
			constexpr std::string_view prefix = "=?base64?";
			constexpr std::string_view suffix = "?=";
			if (value.starts_with(prefix) && value.ends_with(suffix))
				return DecodeBase64(value.substr(prefix.size(), value.size() - prefix.size() - suffix.size()));
			if (value.empty() || std::isspace(static_cast<unsigned char>(value.front()))
				|| std::isspace(static_cast<unsigned char>(value.back())))
				return std::nullopt;
			for (const char character : value)
			{
				const auto byte = static_cast<unsigned char>(character);
				if (byte < 0x20 || byte > 0x7e)
					return std::nullopt;
			}
			return std::string(value);
		}

		std::string UnsupportedVersionData(std::string_view requested)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("supported");
			writer.StartArray();
			for (const auto version : kSupportedVersions)
				writer.String(ToString(version).data(), static_cast<rapidjson::SizeType>(ToString(version).size()));
			writer.EndArray();
			writer.Key("requested");
			writer.String(requested.data(), static_cast<rapidjson::SizeType>(requested.size()));
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		std::optional<ProtocolError> ValidateModernMetadata(
			const Value& root, const TransportHeaders& headers, ValidatedRequest& request)
		{
			if (!headers.protocolVersion || *headers.protocolVersion != ToString(request.version))
				return Error(-32020, 400, "MCP-Protocol-Version header is missing or mismatched", request.id);
			if (!headers.method || *headers.method != request.method)
				return Error(-32020, 400, "Mcp-Method header is missing or mismatched", request.id);

			std::string paramsError;
			const auto* params = Params(root, true, paramsError);
			if (!params)
				return Error(-32602, 400, paramsError, request.id);
			const auto meta = params->FindMember("_meta");
			if (meta == params->MemberEnd() || !meta->value.IsObject())
				return Error(-32602, 400, "params._meta must be an object", request.id);
			const auto version = meta->value.FindMember("io.modelcontextprotocol/protocolVersion");
			if (version == meta->value.MemberEnd() || !version->value.IsString()
				|| std::string_view(version->value.GetString(), version->value.GetStringLength())
					!= ToString(request.version))
				return Error(-32602, 400, "params._meta protocol version is missing or mismatched", request.id);
			const auto capabilities = meta->value.FindMember("io.modelcontextprotocol/clientCapabilities");
			if (capabilities == meta->value.MemberEnd() || !capabilities->value.IsObject())
				return Error(-32602, 400, "params._meta client capabilities must be an object", request.id);
			if (const auto clientInfo = meta->value.FindMember("io.modelcontextprotocol/clientInfo");
				clientInfo != meta->value.MemberEnd())
			{
				std::string error;
				if (!ValidateImplementation(clientInfo->value, error))
					return Error(-32602, 400, error, request.id);
			}
			if (const auto analysisSession = meta->value.FindMember("me.cynder.binjad/analysisSession");
				analysisSession != meta->value.MemberEnd())
			{
				if (!analysisSession->value.IsString() || analysisSession->value.GetStringLength() == 0)
					return Error(-32602, 400, "params._meta analysis session must be a non-empty string", request.id);
				request.analysisSession.assign(
					analysisSession->value.GetString(), analysisSession->value.GetStringLength());
			}

			const bool needsName = request.method == "tools/call" || request.method == "resources/read";
			if (needsName)
			{
				if (!headers.name)
					return Error(-32020, 400, "Mcp-Name header is required", request.id);
				const auto decoded = DecodeHeader(*headers.name);
				const auto& expected = request.method == "tools/call" ? request.name : request.uri;
				if (!decoded || *decoded != expected)
					return Error(-32020, 400, "Mcp-Name header is invalid or mismatched", request.id);
			}
			return std::nullopt;
		}

		template <typename OutputStream>
		void WriteCapabilities(Writer<OutputStream>& writer)
		{
			writer.StartObject();
			writer.Key("tools");
			writer.StartObject();
			writer.Key("listChanged");
			writer.Bool(true);
			writer.EndObject();
			writer.Key("resources");
			writer.StartObject();
			writer.Key("subscribe");
			writer.Bool(true);
			writer.Key("listChanged");
			writer.Bool(true);
			writer.EndObject();
			writer.EndObject();
		}

		template <typename OutputStream>
		void WriteServerInfo(Writer<OutputStream>& writer, std::string_view serverVersion)
		{
			writer.StartObject();
			writer.Key("name");
			writer.String("binjad");
			writer.Key("version");
			writer.String(serverVersion.data(), static_cast<rapidjson::SizeType>(serverVersion.size()));
			writer.EndObject();
		}

		template <typename OutputStream>
		void WriteSubscriptionFilter(Writer<OutputStream>& writer, const SubscriptionFilter& filter)
		{
			writer.StartObject();
			if (filter.toolsListChanged)
			{
				writer.Key("toolsListChanged");
				writer.Bool(true);
			}
			if (filter.resourcesListChanged)
			{
				writer.Key("resourcesListChanged");
				writer.Bool(true);
			}
			if (!filter.resourceSubscriptions.empty())
			{
				writer.Key("resourceSubscriptions");
				writer.StartArray();
				for (const auto& uri : filter.resourceSubscriptions)
					writer.String(uri.data(), static_cast<rapidjson::SizeType>(uri.size()));
				writer.EndArray();
			}
			writer.EndObject();
		}
	}  // namespace

	std::string_view ToString(ProtocolVersion version)
	{
		switch (version)
		{
		case ProtocolVersion::V2025_03_26:
			return "2025-03-26";
		case ProtocolVersion::V2025_06_18:
			return "2025-06-18";
		case ProtocolVersion::V2025_11_25:
			return "2025-11-25";
		case ProtocolVersion::V2026_07_28:
			return "2026-07-28";
		}
		return {};
	}

	std::optional<ProtocolVersion> ParseProtocolVersion(std::string_view version)
	{
		for (const auto candidate : kSupportedVersions)
		{
			if (ToString(candidate) == version)
				return candidate;
		}
		return std::nullopt;
	}

	bool IsModern(ProtocolVersion version)
	{
		return version == ProtocolVersion::V2026_07_28;
	}

	ProtocolVersion NegotiateLegacyVersion(std::string_view requestedVersion)
	{
		const auto version = ParseProtocolVersion(requestedVersion);
		if (version && !IsModern(*version))
			return *version;
		return ProtocolVersion::V2025_03_26;
	}

	ValidationResult ValidateRequest(
		std::string_view body, const TransportHeaders& headers, std::optional<ProtocolVersion> establishedLegacyVersion)
	{
		Document document;
		try
		{
			document.Parse(body.data(), body.size());
		}
		catch (const ParseException& exception)
		{
			return {{},
				Error(-32700, 400,
					std::string("parse error at byte ") + std::to_string(exception.Offset()) + ": "
						+ rapidjson::GetParseError_En(exception.Code()))};
		}
		if (document.HasParseError())
		{
			return {{},
				Error(-32700, 400,
					std::string("parse error at byte ") + std::to_string(document.GetErrorOffset()) + ": "
						+ rapidjson::GetParseError_En(document.GetParseError()))};
		}
		if (!document.IsObject())
			return {{}, Error(-32600, 400, "request must be a JSON object")};

		std::optional<RequestId> id;
		if (const auto idMember = document.FindMember("id"); idMember != document.MemberEnd())
		{
			RequestId parsed;
			if (!ParseRequestId(idMember->value, parsed))
				return {{}, Error(-32600, 400, "id must be a string or integer")};
			id = std::move(parsed);
		}
		const auto jsonrpc = document.FindMember("jsonrpc");
		if (jsonrpc == document.MemberEnd() || !jsonrpc->value.IsString()
			|| std::string_view(jsonrpc->value.GetString(), jsonrpc->value.GetStringLength()) != "2.0")
			return {{}, Error(-32600, 400, "jsonrpc must be '2.0'", id)};
		const auto methodMember = document.FindMember("method");
		if (methodMember == document.MemberEnd() || !methodMember->value.IsString()
			|| methodMember->value.GetStringLength() == 0)
			return {{}, Error(-32600, 400, "method must be a non-empty string", id)};
		const std::string method(methodMember->value.GetString(), methodMember->value.GetStringLength());

		if (method == "initialize")
		{
			if (!id)
				return {{}, Error(-32600, 400, "initialize requires an id")};
			std::string requestedVersion;
			std::string schemaError;
			if (!ValidateInitialize(document, requestedVersion, schemaError))
				return {{}, Error(-32602, 200, schemaError, id)};
			const auto selected = NegotiateLegacyVersion(requestedVersion);
			return {ValidatedRequest {
						selected, id, method, {}, {}, {}, {}, Serialize(document["params"]), std::nullopt, false},
				{}};
		}

		std::optional<ProtocolVersion> version;
		if (headers.protocolVersion)
		{
			version = ParseProtocolVersion(*headers.protocolVersion);
			if (!version)
			{
				return {{},
					Error(-32022, 400, "unsupported protocol version", id,
						UnsupportedVersionData(*headers.protocolVersion))};
			}
		}
		else if (establishedLegacyVersion)
		{
			version = establishedLegacyVersion;
		}
		else
		{
			return {{}, Error(-32600, 400, "MCP-Protocol-Version header or legacy session is required", id)};
		}

		if (establishedLegacyVersion)
		{
			if (IsModern(*establishedLegacyVersion))
				return {{}, Error(-32600, 400, "legacy session cannot use a modern protocol version", id)};
			if (version != establishedLegacyVersion)
				return {{}, Error(-32600, 400, "protocol version does not match the legacy session", id)};
		}
		if (!IsModern(*version) && *version != ProtocolVersion::V2025_03_26 && !headers.protocolVersion)
			return {{}, Error(-32600, 400, "MCP-Protocol-Version header is required for this legacy version", id)};

		const bool notification = !IsRequestMethod(method);
		if (notification == id.has_value())
			return {{},
				Error(-32600, IsModern(*version) ? 400 : 200,
					notification ? "notification must not include an id" : "request requires an id", id)};

		ValidatedRequest request {*version, id, method, {}, {}, {}, {}, {}, std::nullopt, notification};
		std::string schemaError;
		const bool knownMethod = ValidateMethod(document, request, schemaError);
		if (!knownMethod)
		{
			if (!schemaError.empty())
				return {{}, Error(-32602, IsModern(*version) ? 400 : 200, schemaError, id)};
			return {{}, Error(-32601, IsModern(*version) ? 404 : 200, "method not found", id)};
		}

		if (IsModern(*version))
		{
			if (const auto metadataError = ValidateModernMetadata(document, headers, request))
				return {{}, *metadataError};
		}
		return {std::move(request), {}};
	}

	std::string BuildErrorResponse(const ProtocolError& error)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		if (error.id)
		{
			writer.Key("id");
			WriteRequestId(writer, *error.id);
		}
		writer.Key("error");
		writer.StartObject();
		writer.Key("code");
		writer.Int(error.code);
		writer.Key("message");
		writer.String(error.message.data(), static_cast<rapidjson::SizeType>(error.message.size()));
		if (!error.dataJson.empty())
		{
			writer.Key("data");
			writer.RawValue(error.dataJson.data(), error.dataJson.size(), rapidjson::kObjectType);
		}
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildDiscoveryResponse(const RequestId& id, std::string_view serverVersion)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		writer.Key("id");
		WriteRequestId(writer, id);
		writer.Key("result");
		writer.StartObject();
		writer.Key("resultType");
		writer.String("complete");
		writer.Key("supportedVersions");
		writer.StartArray();
		for (const auto version : kSupportedVersions)
			writer.String(ToString(version).data(), static_cast<rapidjson::SizeType>(ToString(version).size()));
		writer.EndArray();
		writer.Key("capabilities");
		WriteCapabilities(writer);
		writer.Key("ttlMs");
		writer.Uint64(60000);
		writer.Key("cacheScope");
		writer.String("private");
		writer.Key("instructions");
		const auto instructions = docs::ModernDiscoveryInstructions();
		writer.String(instructions.data(), static_cast<rapidjson::SizeType>(instructions.size()));
		writer.Key("_meta");
		writer.StartObject();
		writer.Key("io.modelcontextprotocol/serverInfo");
		WriteServerInfo(writer, serverVersion);
		writer.EndObject();
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildInitializeResponse(const RequestId& id, ProtocolVersion version, std::string_view serverVersion)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		writer.Key("id");
		WriteRequestId(writer, id);
		writer.Key("result");
		writer.StartObject();
		writer.Key("protocolVersion");
		writer.String(ToString(version).data(), static_cast<rapidjson::SizeType>(ToString(version).size()));
		writer.Key("capabilities");
		WriteCapabilities(writer);
		writer.Key("serverInfo");
		WriteServerInfo(writer, serverVersion);
		writer.Key("instructions");
		const auto instructions = docs::LegacyInitializationInstructions();
		writer.String(instructions.data(), static_cast<rapidjson::SizeType>(instructions.size()));
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildEmptyResultResponse(const RequestId& id, ProtocolVersion version, std::string_view serverVersion)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		writer.Key("id");
		WriteRequestId(writer, id);
		writer.Key("result");
		writer.StartObject();
		if (IsModern(version))
		{
			writer.Key("resultType");
			writer.String("complete");
			writer.Key("_meta");
			writer.StartObject();
			writer.Key("io.modelcontextprotocol/serverInfo");
			WriteServerInfo(writer, serverVersion);
			writer.EndObject();
		}
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildSubscriptionAcknowledgement(const RequestId& id, const SubscriptionFilter& filter)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		writer.Key("method");
		writer.String("notifications/subscriptions/acknowledged");
		writer.Key("params");
		writer.StartObject();
		writer.Key("_meta");
		writer.StartObject();
		writer.Key("io.modelcontextprotocol/subscriptionId");
		WriteRequestId(writer, id);
		writer.EndObject();
		writer.Key("notifications");
		WriteSubscriptionFilter(writer, filter);
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildResourceUpdatedNotification(std::string_view uri)
	{
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("jsonrpc");
		writer.String("2.0");
		writer.Key("method");
		writer.String("notifications/resources/updated");
		writer.Key("params");
		writer.StartObject();
		writer.Key("uri");
		writer.String(uri.data(), static_cast<rapidjson::SizeType>(uri.size()));
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	std::string BuildToolsListChangedNotification()
	{
		return R"({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})";
	}

	std::string BuildResourcesListChangedNotification()
	{
		return R"({"jsonrpc":"2.0","method":"notifications/resources/list_changed"})";
	}

	std::string EncodeSseEvent(std::string_view json)
	{
		std::string output;
		std::size_t start = 0;
		while (start <= json.size())
		{
			const auto end = json.find('\n', start);
			output += "data: ";
			output.append(json.substr(start, end - start));
			output += "\r\n";
			if (end == std::string_view::npos)
				break;
			start = end + 1;
		}
		output += "\r\n";
		return output;
	}

	std::string EncodeSseKeepAlive()
	{
		return ":\r\n\r\n";
	}
}  // namespace binjad::mcp
