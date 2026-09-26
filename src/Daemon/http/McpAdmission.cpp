#include "binjad/http/McpAdmission.hpp"

#include <algorithm>
#include <cctype>

namespace binjad::http {
	namespace {
		void AddCorsHeaders(ImmediateResponse& response, std::string_view origin)
		{
			response.headers.emplace_back("Access-Control-Allow-Origin", origin);
			response.headers.emplace_back("Vary", "Origin");
		}

		ImmediateResponse OriginRejected()
		{
			return {403, "application/json", "{\"error\":\"forbidden_origin\"}\n", {}};
		}

		ImmediateResponse Unauthorized()
		{
			return {401, "application/json", "{\"error\":\"unauthorized\"}\n", {{"WWW-Authenticate", "Bearer"}}};
		}

		ImmediateResponse PayloadTooLarge()
		{
			return {413, "application/json", "{\"error\":\"payload_too_large\"}\n", {}};
		}

		ImmediateResponse MethodNotAllowed()
		{
			return {405, "application/json", "{\"error\":\"method_not_allowed\"}\n",
				{{"Allow", "POST, GET, DELETE, OPTIONS"}}};
		}

		ImmediateResponse Preflight(std::string_view origin)
		{
			ImmediateResponse response {204, {}, {},
				{
					{"Access-Control-Allow-Methods", "POST, GET, DELETE"},
					{"Access-Control-Allow-Headers",
						"Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name, "
						"Last-Event-ID"},
					{"Access-Control-Max-Age", "600"},
				}};
			AddCorsHeaders(response, origin);
			return response;
		}

		bool EqualAsciiCaseInsensitive(std::string_view left, std::string_view right)
		{
			if (left.size() != right.size())
				return false;
			for (std::size_t index = 0; index < left.size(); ++index)
			{
				if (std::tolower(static_cast<unsigned char>(left[index]))
					!= std::tolower(static_cast<unsigned char>(right[index])))
					return false;
			}
			return true;
		}
	}  // namespace

	McpAdmissionPolicy::McpAdmissionPolicy(HttpConfig config, const security::TokenAuthenticator& authenticator) :
		config_(std::move(config)), authenticator_(authenticator)
	{}

	McpAdmissionResult McpAdmissionPolicy::Evaluate(const McpRequestHead& request, std::uint64_t now) const
	{
		const auto reject = [&](ImmediateResponse response) {
			if (request.origin)
				AddCorsHeaders(response, *request.origin);
			return McpAdmissionResult {{}, std::move(response), request.origin};
		};
		if (request.origin && !IsAllowedOrigin(*request.origin))
			return {{}, OriginRejected(), {}};
		if (request.method == Method::Options)
		{
			if (!request.origin)
				return {{}, OriginRejected(), {}};
			return {{}, Preflight(*request.origin), request.origin};
		}

		if (!request.authorization)
			return reject(Unauthorized());
		const auto token = BearerToken(*request.authorization);
		if (!token)
			return reject(Unauthorized());
		auto principal = authenticator_.Authenticate(*token, now);
		if (!principal)
			return reject(Unauthorized());
		if (request.contentLength && *request.contentLength > config_.mcpMaxBodyBytes)
			return reject(PayloadTooLarge());
		if (request.method != Method::Post && request.method != Method::Get && request.method != Method::Delete)
			return reject(MethodNotAllowed());
		return {std::move(principal), {}, request.origin};
	}

	bool McpAdmissionPolicy::IsAllowedOrigin(std::string_view origin) const
	{
		return std::find(config_.allowedOrigins.begin(), config_.allowedOrigins.end(), origin)
			!= config_.allowedOrigins.end();
	}

	std::optional<std::string_view> McpAdmissionPolicy::BearerToken(std::string_view authorization)
	{
		const auto separator = authorization.find(' ');
		if (separator == std::string_view::npos || separator == 0 || separator + 1 == authorization.size())
			return std::nullopt;
		if (!EqualAsciiCaseInsensitive(authorization.substr(0, separator), "Bearer"))
			return std::nullopt;
		const auto token = authorization.substr(separator + 1);
		if (token.find_first_of(" \t\r\n") != std::string_view::npos)
			return std::nullopt;
		return token;
	}

	ImmediateResponse HealthResponse()
	{
		return {200, "application/json", "{\"status\":\"ok\"}", {{"Cache-Control", "no-store"}}};
	}
}  // namespace binjad::http
