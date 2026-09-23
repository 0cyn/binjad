#include "binjad/http/drogon_routes.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cctype>
#include <chrono>
#include <exception>
#include <limits>
#include <memory>
#include <stdexcept>
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
    if (header == request->headers().end())
        return std::nullopt;
    return header->second;
}

std::optional<std::uint64_t> ContentLength(const drogon::HttpRequestPtr& request)
{
    const auto header = Header(request, "content-length");
    if (!header)
        return std::nullopt;
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(header->data(), header->data() + header->size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != header->data() + header->size())
        return std::nullopt;
    return value;
}

std::uint64_t UnixSeconds()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

drogon::HttpResponsePtr DrogonResponse(const ImmediateResponse& response)
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
    return {413, "application/json", "{\"error\":\"payload_too_large\"}\n", {}};
}

ImmediateResponse BadRequest()
{
    return {400, "application/json", "{\"error\":\"bad_request\"}\n", {}};
}

ImmediateResponse InternalError()
{
    return {500, "application/json", "{\"error\":\"internal_error\"}\n", {}};
}

bool AcceptsEventStream(std::string_view accept)
{
    std::string lowercase(accept);
    std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(),
        [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return lowercase.find("text/event-stream") != std::string::npos;
}

bool IsSseOperation(const AdmittedMcpRequest& request)
{
    if (!AcceptsEventStream(request.accept))
        return false;
    if (request.method == Method::Get)
        return true;
    if (request.method != Method::Post)
        return false;
    rapidjson::Document document;
    try
    {
        document.Parse(request.body.data(), request.body.size());
    }
    catch (const ParseException&)
    {
        return false;
    }
    if (document.HasParseError() || !document.IsObject())
        return false;
    const auto method = document.FindMember("method");
    const auto params = document.FindMember("params");
    if (method == document.MemberEnd() || !method->value.IsString())
        return false;
    const std::string_view methodName(method->value.GetString(), method->value.GetStringLength());
    if (methodName == "subscriptions/listen")
        return true;
    if (methodName != "tools/call" || params == document.MemberEnd() || !params->value.IsObject())
        return false;
    const auto name = params->value.FindMember("name");
    if (name == params->value.MemberEnd() || !name->value.IsString())
        return false;
    const std::string_view tool(name->value.GetString(), name->value.GetStringLength());
    if (tool == "bn_upload_commit")
    {
        const auto arguments = params->value.FindMember("arguments");
        if (arguments == params->value.MemberEnd() || !arguments->value.IsObject())
            return false;
        for (const auto* field : {"open", "analyze"})
        {
            const auto value = arguments->value.FindMember(field);
            if (value != arguments->value.MemberEnd() && value->value.IsBool() &&
                value->value.GetBool())
                return true;
        }
        return false;
    }
    return tool == "bn_analysis_update_and_wait" || tool == "bn_binary_view_save";
}

std::string ProgressNotification(const session::JobRecord& job)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("jsonrpc");
    writer.String("2.0");
    writer.Key("method");
    writer.String("notifications/progress");
    writer.Key("params");
    writer.StartObject();
    writer.Key("progressToken");
    writer.String(job.reference.data(), static_cast<rapidjson::SizeType>(job.reference.size()));
    const auto& progress = *job.progress;
    writer.Key("progress");
    writer.Uint64(progress.completed);
    writer.Key("total");
    writer.Uint64(progress.total);
    writer.Key("job");
    writer.String(job.reference.data(), static_cast<rapidjson::SizeType>(job.reference.size()));
    writer.Key("phase");
    writer.String(progress.phase.data(), static_cast<rapidjson::SizeType>(progress.phase.size()));
    writer.Key("completed");
    writer.Uint64(progress.completed);
    writer.Key("sequence");
    writer.Uint64(progress.sequence);
    writer.Key("timestamp");
    writer.Uint64(progress.timestampUnix);
    if (!progress.message.empty())
    {
        writer.Key("message");
        writer.String(progress.message.data(),
            static_cast<rapidjson::SizeType>(progress.message.size()));
    }
    writer.EndObject();
    writer.EndObject();
    return mcp::EncodeSseEvent({buffer.GetString(), buffer.GetSize()});
}

void ApplyCors(const drogon::HttpResponsePtr& response, const std::optional<std::string>& origin)
{
    if (!response || !origin)
        return;
    response->addHeader("Access-Control-Allow-Origin", *origin);
    response->addHeader("Vary", "Origin");
}

AdmittedMcpRequest BuildRequest(const drogon::HttpRequestPtr& request,
    const McpAdmissionResult& admission, Method method)
{
    AdmittedMcpRequest output;
    output.method = method;
    output.principal = *admission.principal;
    output.transportHeaders.protocolVersion = Header(request, "mcp-protocol-version");
    output.transportHeaders.method = Header(request, "mcp-method");
    output.transportHeaders.name = Header(request, "mcp-name");
    output.sessionId = Header(request, "mcp-session-id");
    output.lastEventId = Header(request, "last-event-id");
    output.accept = request->getHeader("accept");
    return output;
}

struct StreamState
{
    AdmittedMcpRequest request;
    McpRequestHandler handler;
    DrogonResponseCallback callback;
    std::optional<std::string> origin;
    std::uint64_t maximum = 0;
    bool oversized = false;
    std::weak_ptr<trantor::TcpConnection> connection;
    std::function<void(const trantor::TcpConnectionPtr&,
        const std::shared_ptr<AttachedSseState>&)> trackConnection;
    std::function<void(const trantor::TcpConnection*,
        const AttachedSseState*)> forgetConnection;
};

}

class AttachedSseState final : public std::enable_shared_from_this<AttachedSseState>
{
  public:
    using FinishedCallback = std::function<void(const AttachedSseState*)>;

    explicit AttachedSseState(FinishedCallback finished)
        : finishedCallback_(std::move(finished))
    {
    }

    ~AttachedSseState()
    {
        Finish({});
    }

    void Start(drogon::ResponseStreamPtr stream)
    {
        std::lock_guard lock(mutex_);
        stream_ = std::shared_ptr<drogon::ResponseStream>(std::move(stream));
    }

    void Attach(std::function<void()> cancel)
    {
        std::function<void()> cancelNow;
        {
            std::lock_guard lock(mutex_);
            if (finished_)
                return;
            cancel_ = std::move(cancel);
            if (disconnected_)
                cancelNow = cancel_;
        }
        if (cancelNow)
            cancelNow();
    }

    void Progress(const session::JobRecord& job)
    {
        if (!job.progress)
            return;
        Send(ProgressNotification(job));
    }

    void Notification(std::string_view json)
    {
        Send(mcp::EncodeSseEvent(json));
    }

    void Complete(std::string_view json)
    {
        std::shared_ptr<drogon::ResponseStream> stream;
        FinishedCallback finished;
        {
            std::lock_guard lock(mutex_);
            if (finished_)
                return;
            finished_ = true;
            stream = std::move(stream_);
            finished = std::move(finishedCallback_);
            cancel_ = {};
        }
        if (stream)
        {
            if (!json.empty())
                stream->send(mcp::EncodeSseEvent(json));
            stream->close();
        }
        if (finished)
            finished(this);
    }

    void Disconnect()
    {
        std::function<void()> cancel;
        {
            std::lock_guard lock(mutex_);
            if (finished_ || disconnected_)
                return;
            disconnected_ = true;
            cancel = cancel_;
        }
        if (cancel)
            cancel();
    }

  private:
    void Send(std::string data)
    {
        std::shared_ptr<drogon::ResponseStream> stream;
        {
            std::lock_guard lock(mutex_);
            if (finished_)
                return;
            stream = stream_;
        }
        if (stream && !stream->send(data))
            Disconnect();
    }

    void Finish(std::string_view json)
    {
        Complete(json);
    }

    std::mutex mutex_;
    std::shared_ptr<drogon::ResponseStream> stream_;
    std::function<void()> cancel_;
    FinishedCallback finishedCallback_;
    bool disconnected_ = false;
    bool finished_ = false;
};

namespace
{

void DispatchJson(std::shared_ptr<StreamState> state)
{
    try
    {
        std::thread([state] {
            auto completed = std::make_shared<std::atomic_bool>(false);
            auto callback = [origin = state->origin,
                                callback = std::move(state->callback), completed](
                                const drogon::HttpResponsePtr& response) mutable {
                if (completed->exchange(true))
                    return;
                if (!response)
                {
                    callback(DrogonResponse(InternalError()));
                    return;
                }
                ApplyCors(response, origin);
                callback(response);
            };
            try
            {
                state->handler(std::move(state->request), callback);
            }
            catch (...)
            {
                callback(DrogonResponse(InternalError()));
            }
        }).detach();
    }
    catch (...)
    {
        auto response = DrogonResponse({503, "application/json",
            "{\"error\":\"service_unavailable\"}\n", {}});
        ApplyCors(response, state->origin);
        state->callback(response);
    }
}

void Dispatch(std::shared_ptr<StreamState> state)
{
    if (!IsSseOperation(state->request))
    {
        DispatchJson(std::move(state));
        return;
    }
    try
    {
        const auto connection = state->connection.lock();
        auto attached = std::make_shared<AttachedSseState>(
            [connection = connection.get(), forget = state->forgetConnection](
                const AttachedSseState* stream) {
                if (connection && forget)
                    forget(connection, stream);
            });
        if (connection && state->trackConnection)
            state->trackConnection(connection, attached);
        state->request.progress = [weak = std::weak_ptr(attached)](
                                      const session::JobRecord& job) {
            if (const auto stream = weak.lock())
                stream->Progress(job);
        };
        state->request.attachedJob = [weak = std::weak_ptr(attached)](
                                         std::string_view, std::function<void()> cancel) {
            if (const auto stream = weak.lock())
                stream->Attach(std::move(cancel));
        };
        state->request.notification = [attached](std::string_view json) {
            attached->Notification(json);
        };
        state->request.attachedSubscription = [weak = std::weak_ptr(attached)](
                                                  std::function<void()> cancel) {
            if (const auto stream = weak.lock())
                stream->Attach(std::move(cancel));
        };
        auto response = drogon::HttpResponse::newAsyncStreamResponse(
            [state, attached](drogon::ResponseStreamPtr stream) mutable {
                attached->Start(std::move(stream));
                try
                {
                    std::thread([state = std::move(state), attached]() mutable {
                        auto completed = std::make_shared<std::atomic_bool>(false);
                        auto callback = [attached, completed](
                                            const drogon::HttpResponsePtr& result) {
                            if (completed->exchange(true))
                                return;
                            attached->Complete(result ? result->body()
                                                      : InternalError().body);
                        };
                        try
                        {
                            state->handler(std::move(state->request), callback);
                        }
                        catch (...)
                        {
                            callback(DrogonResponse(InternalError()));
                        }
                    }).detach();
                }
                catch (...)
                {
                    attached->Complete(InternalError().body);
                }
            });
        response->setContentTypeString("text/event-stream");
        response->addHeader("Cache-Control", "no-store");
        response->addHeader("X-Accel-Buffering", "no");
        ApplyCors(response, state->origin);
        state->callback(response);
    }
    catch (...)
    {
        auto response = DrogonResponse({503, "application/json",
            "{\"error\":\"service_unavailable\"}\n", {}});
        ApplyCors(response, state->origin);
        state->callback(response);
    }
}
}

DrogonRoutes::DrogonRoutes(Config config,
    const security::TokenAuthenticator& authenticator, McpRequestHandler handler)
    : config_(std::move(config)), admission_(config_.http, authenticator),
      handler_(std::move(handler))
{
    if (!handler_)
        throw std::invalid_argument("MCP request handler must not be empty");
}

void DrogonRoutes::Register(drogon::HttpAppFramework& app)
{
    app.enableRequestStream();
    app.setIdleConnectionTimeout(0);
    const auto maximumBody = std::max(config_.uploads.maxBytes, config_.http.mcpMaxBodyBytes);
    app.setClientMaxBodySize(static_cast<std::size_t>(std::min<std::uint64_t>(
        maximumBody, std::numeric_limits<std::size_t>::max())));
    for (const auto& address : config_.listener.addresses)
        app.addListener(address, config_.listener.port);

    auto self = shared_from_this();
    app.setConnectionCallback([weak = std::weak_ptr<DrogonRoutes>(self)](
                                  const trantor::TcpConnectionPtr& connection) {
        if (const auto routes = weak.lock())
            routes->ConnectionChanged(connection);
    });
    app.registerHandler(config_.http.healthPath,
        [self](const drogon::HttpRequestPtr& request,
            drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
            self->HandleHealth(request, std::move(stream), std::move(callback));
        }, {drogon::Get});
    app.registerHandler(config_.http.mcpPath,
        [self](const drogon::HttpRequestPtr& request,
            drogon::RequestStreamPtr&& stream, DrogonResponseCallback&& callback) {
            self->HandleMcp(request, std::move(stream), std::move(callback));
        }, {drogon::Get, drogon::Post, drogon::Delete, drogon::Options});
}

void DrogonRoutes::HandleHealth(const drogon::HttpRequestPtr&,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    if (stream)
        stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
    callback(DrogonResponse(HealthResponse()));
}

void DrogonRoutes::HandleMcp(const drogon::HttpRequestPtr& request,
    drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const
{
    const auto method = ToMethod(request->method());
    const auto origin = Header(request, "origin");
    const auto admission = admission_.Evaluate(
        {method, origin, Header(request, "authorization"), ContentLength(request)}, UnixSeconds());
    if (admission.response)
    {
        if (stream)
            stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        callback(DrogonResponse(*admission.response));
        return;
    }

    auto state = std::make_shared<StreamState>(StreamState{
        BuildRequest(request, admission, method), handler_, std::move(callback),
        admission.allowedOrigin, config_.http.mcpMaxBodyBytes, false,
        request->getConnectionPtr(),
        [weak = weak_from_this()](const trantor::TcpConnectionPtr& connection,
            const std::shared_ptr<AttachedSseState>& attached) {
            if (const auto routes = weak.lock())
                routes->TrackConnection(connection, attached);
        },
        [weak = weak_from_this()](const trantor::TcpConnection* connection,
            const AttachedSseState* attached) {
            if (const auto routes = weak.lock())
                routes->ForgetConnection(connection, attached);
        }});
    if (method != Method::Post)
    {
        if (stream)
            stream->setStreamReader(drogon::RequestStreamReader::newNullReader());
        Dispatch(std::move(state));
        return;
    }
    if (!stream)
    {
        if (request->body().size() > state->maximum)
        {
            auto response = DrogonResponse(PayloadTooLarge());
            ApplyCors(response, state->origin);
            state->callback(response);
        }
        else
        {
            state->request.body.assign(request->body());
            Dispatch(std::move(state));
        }
        return;
    }

    stream->setStreamReader(drogon::RequestStreamReader::newReader(
        [state](const char* data, std::size_t length) {
            if (state->oversized)
                return;
            if (length > state->maximum - state->request.body.size())
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
                auto response = DrogonResponse(BadRequest());
                ApplyCors(response, state->origin);
                state->callback(response);
                return;
            }
            if (state->oversized)
            {
                auto response = DrogonResponse(PayloadTooLarge());
                ApplyCors(response, state->origin);
                state->callback(response);
                return;
            }
            Dispatch(std::move(state));
        }));
}

void DrogonRoutes::TrackConnection(const trantor::TcpConnectionPtr& connection,
    const std::shared_ptr<AttachedSseState>& stream) const
{
    if (!connection)
        return;
    std::lock_guard lock(connectionsMutex_);
    connections_[connection.get()].push_back(stream);
}

void DrogonRoutes::ForgetConnection(const trantor::TcpConnection* connection,
    const AttachedSseState* stream) const
{
    std::lock_guard lock(connectionsMutex_);
    const auto entry = connections_.find(connection);
    if (entry == connections_.end())
        return;
    auto& streams = entry->second;
    std::erase_if(streams, [stream](const auto& weak) {
        const auto current = weak.lock();
        return !current || current.get() == stream;
    });
    if (streams.empty())
        connections_.erase(entry);
}

void DrogonRoutes::ConnectionChanged(
    const trantor::TcpConnectionPtr& connection) const
{
    if (!connection || !connection->disconnected())
        return;
    std::vector<std::shared_ptr<AttachedSseState>> streams;
    {
        std::lock_guard lock(connectionsMutex_);
        const auto entry = connections_.find(connection.get());
        if (entry == connections_.end())
            return;
        for (const auto& weak : entry->second)
        {
            if (auto stream = weak.lock())
                streams.push_back(std::move(stream));
        }
        connections_.erase(entry);
    }
    for (const auto& stream : streams)
        stream->Disconnect();
}

std::shared_ptr<DrogonRoutes> RegisterDrogonRoutes(drogon::HttpAppFramework& app,
    Config config, const security::TokenAuthenticator& authenticator, McpRequestHandler handler)
{
    auto routes = std::make_shared<DrogonRoutes>(
        std::move(config), authenticator, std::move(handler));
    routes->Register(app);
    return routes;
}
}
