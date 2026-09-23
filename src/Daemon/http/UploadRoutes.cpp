#include "binjad/http/upload_routes.hpp"

#include "binjad/platform/paths.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <optional>
#include <string>
#include <utility>

namespace binjad::http
{
std::string ConfigureDrogonUploadStorage(
    drogon::HttpAppFramework& app, const Config& config)
{
    const auto path = config.storage.spoolPath / "drogon-uploads";
    if (const auto error = platform::CreatePrivateDirectory(path); !error.empty())
        return error;
    app.setUploadPath(path.string());
    return {};
}

namespace
{
std::optional<std::string> Header(
    const drogon::HttpRequestPtr& request, std::string_view name)
{
    const auto found = request->headers().find(std::string(name));
    return found == request->headers().end() ? std::nullopt
                                             : std::optional(found->second);
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

std::uint64_t UnixSeconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

drogon::HttpResponsePtr Response(int status, std::string body,
    const std::optional<std::string>& origin = {})
{
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(static_cast<drogon::HttpStatusCode>(status));
    response->setContentTypeString("application/json");
    response->setBody(std::move(body));
    response->addHeader("Cache-Control", "no-store");
    if (origin)
    {
        response->addHeader("Access-Control-Allow-Origin", *origin);
        response->addHeader("Vary", "Origin");
    }
    return response;
}

std::optional<std::string> Bearer(const drogon::HttpRequestPtr& request)
{
    const auto authorization = Header(request, "authorization");
    constexpr std::string_view prefix = "Bearer ";
    if (!authorization || !std::string_view(*authorization).starts_with(prefix))
        return std::nullopt;
    return authorization->substr(prefix.size());
}

std::optional<std::string> Capability(
    std::string_view path, std::string_view prefix)
{
    if (!path.starts_with(prefix) || path.size() != prefix.size() + 65 ||
        path[prefix.size()] != '/')
        return std::nullopt;
    const auto value = path.substr(prefix.size() + 1);
    if (!std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isdigit(character) || (character >= 'a' && character <= 'f');
        }))
        return std::nullopt;
    return std::string(value);
}

std::optional<std::string> MultipartBoundary(std::string_view contentType)
{
    constexpr std::string_view prefix = "multipart/form-data";
    if (!contentType.starts_with(prefix))
        return std::nullopt;
    const auto marker = contentType.find("boundary=");
    if (marker == std::string_view::npos)
        return std::nullopt;
    auto boundary = contentType.substr(marker + 9);
    if (const auto separator = boundary.find(';'); separator != std::string_view::npos)
        boundary = boundary.substr(0, separator);
    while (!boundary.empty() && boundary.front() == ' ')
        boundary.remove_prefix(1);
    if (boundary.size() >= 2 && boundary.front() == '"' && boundary.back() == '"')
        boundary = boundary.substr(1, boundary.size() - 2);
    if (boundary.empty() || boundary.size() > 200 ||
        std::any_of(boundary.begin(), boundary.end(), [](unsigned char value) {
            return value < 0x21 || value > 0x7e;
        }))
        return std::nullopt;
    return std::string(boundary);
}

class MultipartStream
{
  public:
    MultipartStream(std::string boundary, upload::UploadTransfer& transfer)
        : opening_("--" + boundary + "\r\n"),
          delimiter_("\r\n--" + std::move(boundary)), transfer_(transfer)
    {
    }

    bool Write(std::string_view data, std::string& error)
    {
        if (complete_)
        {
            if (!data.empty())
                error = "multipart data follows the closing boundary";
            return error.empty();
        }
        pending_.append(data);
        if (!headersRead_)
        {
            const auto end = pending_.find("\r\n\r\n");
            if (end == std::string::npos)
            {
                if (pending_.size() > 64 * 1024)
                    error = "multipart headers are too large";
                return error.empty();
            }
            if (!pending_.starts_with(opening_))
            {
                error = "invalid multipart opening boundary";
                return false;
            }
            const auto headers = std::string_view(pending_).substr(opening_.size(),
                end - opening_.size());
            if (headers.find("Content-Disposition:") == std::string_view::npos &&
                headers.find("content-disposition:") == std::string_view::npos)
            {
                error = "multipart file part lacks Content-Disposition";
                return false;
            }
            pending_.erase(0, end + 4);
            headersRead_ = true;
        }
        const auto delimiter = pending_.find(delimiter_);
        if (delimiter != std::string::npos)
        {
            if (!transfer_.Write(std::string_view(pending_).substr(0, delimiter), error))
                return false;
            const auto suffix = std::string_view(pending_).substr(delimiter + delimiter_.size());
            if (suffix == "--")
                return true;
            if (!suffix.starts_with("--\r\n") || suffix.size() != 4)
            {
                error = "multipart body contains more than one file part";
                return false;
            }
            complete_ = true;
            pending_.clear();
            return true;
        }
        if (pending_.size() > delimiter_.size() + 4)
        {
            const auto emit = pending_.size() - delimiter_.size() - 4;
            if (!transfer_.Write(std::string_view(pending_).substr(0, emit), error))
                return false;
            pending_.erase(0, emit);
        }
        return true;
    }

    bool Finish(std::string& error)
    {
        if (!complete_)
        {
            const auto delimiter = pending_.find(delimiter_);
            if (delimiter != std::string::npos &&
                std::string_view(pending_).substr(delimiter + delimiter_.size()) == "--")
            {
                if (!transfer_.Write(std::string_view(pending_).substr(0, delimiter), error))
                    return false;
                complete_ = true;
                pending_.clear();
            }
        }
        if (!headersRead_ || !complete_)
        {
            error = "incomplete multipart upload";
            return false;
        }
        return true;
    }

  private:
    std::string opening_;
    std::string delimiter_;
    upload::UploadTransfer& transfer_;
    std::string pending_;
    bool headersRead_ = false;
    bool complete_ = false;
};

struct StreamState
{
    std::unique_ptr<upload::UploadTransfer> transfer;
    std::unique_ptr<MultipartStream> multipart;
    DrogonResponseCallback callback;
    std::optional<std::string> origin;
    std::string error;
};

void Finish(const std::shared_ptr<StreamState>& state, std::exception_ptr exception)
{
    if (exception && state->error.empty())
        state->error = "upload stream failed";
    if (state->error.empty() && state->multipart && !state->multipart->Finish(state->error))
    {}
    std::optional<upload::UploadRecord> completed;
    if (state->error.empty())
        completed = state->transfer->Finish(state->error);
    if (!completed)
    {
        state->transfer->Abort();
        state->callback(Response(state->error == "upload exceeds configured maximum" ? 413 : 400,
            "{\"error\":\"upload_failed\"}", state->origin));
        return;
    }
    state->callback(Response(201, "{\"id\":\"" + completed->id +
        "\",\"size\":" + std::to_string(completed->size) +
        ",\"sha256\":\"" + completed->sha256 + "\"}", state->origin));
}
}

UploadRoutes::UploadRoutes(Config config,
    const security::TokenAuthenticator& authenticator, upload::UploadRegistry& uploads)
    : config_(std::move(config)), authenticator_(authenticator), uploads_(uploads)
{
}

void UploadRoutes::Register(drogon::HttpAppFramework& app)
{
    auto self = shared_from_this();
    app.registerHandlerViaRegex("^" + EscapeRegex(config_.http.uploadPath) + "/[0-9a-f]{64}$",
        [self](const drogon::HttpRequestPtr& request,
            drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
            self->Handle(request, std::move(stream), std::move(callback));
        }, {drogon::Put, drogon::Post, drogon::Options});
}

void UploadRoutes::Handle(const drogon::HttpRequestPtr& request,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    const auto origin = Header(request, "origin");
    if (origin && std::find(config_.http.allowedOrigins.begin(),
            config_.http.allowedOrigins.end(), *origin) == config_.http.allowedOrigins.end())
    {
        if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        callback(Response(403, "{\"error\":\"forbidden_origin\"}"));
        return;
    }
    if (request->method() == drogon::Options)
    {
        if (!origin)
        {
            if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
            callback(Response(403, "{\"error\":\"forbidden_origin\"}"));
            return;
        }
        if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        auto response = Response(204, {}, origin);
        response->addHeader("Access-Control-Allow-Methods", "PUT, POST, OPTIONS");
        response->addHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        callback(response);
        return;
    }
    const auto capability = Capability(request->path(), config_.http.uploadPath);
    if (!capability)
    {
        if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        callback(Response(404, "{\"error\":\"upload_not_found\"}", origin));
        return;
    }
    std::optional<security::TokenRecord> principal;
    if (config_.uploads.requireBearerAuthentication)
    {
        const auto token = Bearer(request);
        principal = token ? authenticator_.Authenticate(*token, UnixSeconds()) : std::nullopt;
        if (!principal)
        {
            if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
            auto response = Response(401, "{\"error\":\"unauthorized\"}", origin);
            response->addHeader("WWW-Authenticate", "Bearer");
            callback(response);
            return;
        }
    }
    if (request->method() == drogon::Put)
    {
        if (const auto length = Header(request, "content-length"); length)
        {
            std::uint64_t value = 0;
            const auto parsed = std::from_chars(
                length->data(), length->data() + length->size(), value);
            if (parsed.ec != std::errc{} || parsed.ptr != length->data() + length->size() ||
                value > config_.uploads.maxBytes)
            {
                if (stream)
                    stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
                callback(Response(413, "{\"error\":\"payload_too_large\"}", origin));
                return;
            }
        }
    }
    auto [transfer, error] = principal
        ? uploads_.Begin(*capability, principal->id,
              session::AnalysisSessionRegistry::Clock::now())
        : uploads_.Begin(*capability, session::AnalysisSessionRegistry::Clock::now());
    if (!transfer)
    {
        if (stream) stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        callback(Response(404, "{\"error\":\"upload_not_found\"}", origin));
        return;
    }
    auto state = std::make_shared<StreamState>();
    state->transfer = std::move(transfer);
    state->callback = std::move(callback);
    state->origin = origin;
    const auto contentType = Header(request, "content-type").value_or("");
    if (request->method() == drogon::Post)
    {
        const auto boundary = MultipartBoundary(contentType);
        if (!boundary)
        {
            state->transfer->Abort();
            state->callback(Response(400, "{\"error\":\"invalid_multipart\"}", origin));
            return;
        }
        state->multipart = std::make_unique<MultipartStream>(*boundary, *state->transfer);
    }
    auto write = [state](const char* data, std::size_t length) {
        if (!state->error.empty()) return;
        const std::string_view value(data, length);
        if (state->multipart)
            state->multipart->Write(value, state->error);
        else
            state->transfer->Write(value, state->error);
    };
    if (!stream)
    {
        write(request->body().data(), request->body().size());
        Finish(state, {});
        return;
    }
    stream->setStreamReader(drogon::RequestStreamReader::newReader(
        std::move(write), [state](std::exception_ptr exception) { Finish(state, exception); }));
}

std::shared_ptr<UploadRoutes> RegisterUploadRoutes(drogon::HttpAppFramework& app,
    Config config, const security::TokenAuthenticator& authenticator,
    upload::UploadRegistry& uploads)
{
    auto routes = std::make_shared<UploadRoutes>(
        std::move(config), authenticator, uploads);
    routes->Register(app);
    return routes;
}
}
