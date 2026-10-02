#include "binjad/http/DownloadRoutes.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>

namespace binjad::http {
	namespace {
		std::optional<std::string> Header(const drogon::HttpRequestPtr& request, std::string_view name)
		{
			const auto found = request->headers().find(std::string(name));
			return found == request->headers().end() ? std::nullopt : std::optional(found->second);
		}

		std::string EscapeRegex(std::string_view value)
		{
			constexpr std::string_view special = R"(\.^$|()[]{}*+?)";
			std::string escaped;
			for (const char character : value)
			{
				if (special.find(character) != std::string_view::npos)
					escaped.push_back('\\');
				escaped.push_back(character);
			}
			return escaped;
		}

		std::optional<std::string> Capability(std::string_view path)
		{
			const auto prefix = binjad::kDownloadPath;
			if (!path.starts_with(prefix) || path.size() != prefix.size() + 65 || path[prefix.size()] != '/')
				return std::nullopt;
			const auto value = path.substr(prefix.size() + 1);
			if (!std::all_of(value.begin(), value.end(), [](unsigned char character) {
					return std::isdigit(character) != 0 || (character >= 'a' && character <= 'f');
				}))
				return std::nullopt;
			return std::string(value);
		}

		drogon::HttpResponsePtr ErrorResponse(
			int status, std::string_view body, const std::optional<std::string>& origin)
		{
			auto response = drogon::HttpResponse::newHttpResponse();
			response->setStatusCode(static_cast<drogon::HttpStatusCode>(status));
			response->setContentTypeString("application/json");
			response->setBody(std::string(body));
			response->addHeader("Cache-Control", "no-store");
			if (origin)
			{
				response->addHeader("Access-Control-Allow-Origin", *origin);
				response->addHeader("Vary", "Origin");
			}
			return response;
		}

		void AddCommonHeaders(const drogon::HttpResponsePtr& response, const std::optional<std::string>& origin)
		{
			response->addHeader("Cache-Control", "no-store");
			response->addHeader("X-Content-Type-Options", "nosniff");
			if (origin)
			{
				response->addHeader("Access-Control-Allow-Origin", *origin);
				response->addHeader("Vary", "Origin");
			}
		}
	}  // namespace

	DownloadRoutes::DownloadRoutes(download::DownloadRegistry& downloads) : downloads_(downloads) {}

	void DownloadRoutes::Register(drogon::HttpAppFramework& app)
	{
		auto self = shared_from_this();
		app.registerHandlerViaRegex("^" + EscapeRegex(binjad::kDownloadPath) + "/[0-9a-f]{64}$",
			[self](const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr&& stream,
				DrogonResponseCallback&& callback) { self->Handle(request, std::move(stream), std::move(callback)); },
			{drogon::Get, drogon::Options});
	}

	void DownloadRoutes::Handle(
		const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
	{
		if (stream)
			stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
		const auto origin = Header(request, "origin");
		if (request->method() == drogon::Options)
		{
			auto response = ErrorResponse(204, {}, origin);
			response->addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
			callback(response);
			return;
		}
		const auto capability = Capability(request->path());
		const auto download =
			capability ? downloads_.Claim(*capability, download::DownloadRegistry::Clock::now()) : std::nullopt;
		if (!download)
		{
			callback(ErrorResponse(404, "{\"error\":\"download_not_found\"}", origin));
			return;
		}

		auto response = drogon::HttpResponse::newFileResponse(download->artifactPath.string(), download->attachmentName,
			drogon::CT_CUSTOM, download->contentType, request);
		AddCommonHeaders(response, origin);
		callback(response);
	}

	std::shared_ptr<DownloadRoutes> RegisterDownloadRoutes(
		drogon::HttpAppFramework& app, download::DownloadRegistry& downloads)
	{
		auto routes = std::make_shared<DownloadRoutes>(downloads);
		routes->Register(app);
		return routes;
	}
}  // namespace binjad::http
