#include "binjad/http/PortalRoutes.hpp"

#include "binjad/http/DrogonRoutes.hpp"

#include <charconv>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace binjad::http
{
namespace
{
Method ToMethod(drogon::HttpMethod method)
{
    switch (method)
    {
        case drogon::Get: return Method::Get;
        case drogon::Post: return Method::Post;
        case drogon::Put: return Method::Put;
        case drogon::Patch: return Method::Patch;
        case drogon::Delete: return Method::Delete;
        case drogon::Options: return Method::Options;
        default: return Method::Other;
    }
}

std::optional<std::string> Header(
    const drogon::HttpRequestPtr& request, std::string_view lowercaseName)
{
    const auto header = request->headers().find(std::string(lowercaseName));
    return header == request->headers().end() ? std::nullopt : std::optional(header->second);
}

std::optional<std::uint64_t> ContentLength(const drogon::HttpRequestPtr& request)
{
    const auto header = Header(request, "content-length");
    if (!header)
        return std::nullopt;
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(header->data(), header->data() + header->size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == header->data() + header->size()
        ? std::optional(value) : std::nullopt;
}

drogon::HttpResponsePtr Response(const ImmediateResponse& response)
{
    auto output = drogon::HttpResponse::newHttpResponse();
    output->setStatusCode(static_cast<drogon::HttpStatusCode>(response.status));
    if (!response.contentType.empty())
        output->setContentTypeString(response.contentType);
    output->setBody(response.body);
    for (const auto& [name, value] : response.headers)
        output->addHeader(name, value);
    return output;
}

ImmediateResponse PayloadTooLarge()
{
    return {413, "application/json", "{\"error\":\"payload_too_large\"}",
        {{"Cache-Control", "no-store"}}};
}

std::string EscapeRegex(std::string_view value)
{
    constexpr std::string_view special = R"(\.^$|()[]{}*+?)";
    std::string escaped;
    escaped.reserve(value.size() * 2);
    for (const char character : value)
    {
        if (special.find(character) != std::string_view::npos)
            escaped.push_back('\\');
        escaped.push_back(character);
    }
    return escaped;
}

struct PortalStreamState
{
    portal::ApiRequest request;
    std::shared_ptr<portal::Api> api;
    DrogonResponseCallback callback;
    bool oversized = false;
};

void Dispatch(std::shared_ptr<PortalStreamState> state)
{
    try
    {
        std::thread([state = std::move(state)] {
            drogon::HttpResponsePtr response;
            try
            {
                response = Response(state->api->Handle(state->request));
            }
            catch (...)
            {
                response = Response({500, "application/json", "{\"error\":\"internal_error\"}",
                    {{"Cache-Control", "no-store"}}});
            }
            state->callback(response);
        }).detach();
    }
    catch (...)
    {
        state->callback(Response({503, "application/json", "{\"error\":\"service_unavailable\"}",
            {{"Cache-Control", "no-store"}}}));
    }
}
}

PortalRoutes::PortalRoutes(Config config, std::shared_ptr<portal::Api> api)
    : config_(std::move(config)), api_(std::move(api))
{
    if (!api_)
        throw std::invalid_argument("portal API must not be null");
}

void PortalRoutes::Register(drogon::HttpAppFramework& app)
{
    auto self = shared_from_this();
    app.registerHandler(config_.http.portalPath,
        [self](const drogon::HttpRequestPtr& request,
            drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
            self->HandlePage(request, std::move(stream), std::move(callback));
        }, {drogon::Get});
    for (const auto* asset : {"app.css", "app.js", "binjad.png"})
    {
        app.registerHandler(config_.http.portalPath + "/" + asset,
            [self](const drogon::HttpRequestPtr& request,
                drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
                self->HandleAsset(request, std::move(stream), std::move(callback));
            }, {drogon::Get});
    }
    app.registerHandlerViaRegex("^" + EscapeRegex(config_.http.portalPath) + "/api(?:/.*)?$",
        [self](const drogon::HttpRequestPtr& request,
            drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
            self->HandleApi(request, std::move(stream), std::move(callback));
        }, {drogon::Get, drogon::Post, drogon::Put, drogon::Patch, drogon::Delete});
}

void PortalRoutes::HandlePage(const drogon::HttpRequestPtr&,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    if (stream)
        stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
    callback(Response(api_->Page()));
}

void PortalRoutes::HandleAsset(const drogon::HttpRequestPtr& request,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    if (stream)
        stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
    const auto separator = request->path().find_last_of('/');
    const auto name = separator == std::string::npos
        ? std::string_view{} : std::string_view(request->path()).substr(separator + 1);
    callback(Response(api_->Asset(name)));
}

void PortalRoutes::HandleApi(const drogon::HttpRequestPtr& request,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    if (const auto length = ContentLength(request);
        length && *length > portal::Api::kMaxBodyBytes)
    {
        if (stream)
            stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        callback(Response(PayloadTooLarge()));
        return;
    }
    auto state = std::make_shared<PortalStreamState>(PortalStreamState{
        {ToMethod(request->method()), request->path(), Header(request, "origin"),
            Header(request, "authorization"), {}},
        api_, std::move(callback), false});
    if (!stream)
    {
        state->request.body.assign(request->body());
        Dispatch(std::move(state));
        return;
    }
    stream->setStreamReader(drogon::RequestStreamReader::newReader(
        [state](const char* data, std::size_t length) {
            if (state->oversized)
                return;
            if (length > portal::Api::kMaxBodyBytes - state->request.body.size())
            {
                state->oversized = true;
                state->request.body.clear();
                return;
            }
            state->request.body.append(data, length);
        },
        [state = std::move(state)](std::exception_ptr error) mutable {
            if (error)
            {
                state->callback(Response({400, "application/json", "{\"error\":\"bad_request\"}",
                    {{"Cache-Control", "no-store"}}}));
                return;
            }
            if (state->oversized)
            {
                state->callback(Response(PayloadTooLarge()));
                return;
            }
            Dispatch(std::move(state));
        }));
}

std::shared_ptr<PortalRoutes> RegisterPortalRoutes(
    drogon::HttpAppFramework& app, Config config, std::shared_ptr<portal::Api> api)
{
    auto routes = std::make_shared<PortalRoutes>(std::move(config), std::move(api));
    routes->Register(app);
    return routes;
}
}
