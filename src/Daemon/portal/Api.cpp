#include "binjad/portal/api.hpp"

#include "binjad/platform/paths.hpp"
#include "binjad/version.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::portal
{
namespace
{
using rapidjson::Document;
using rapidjson::StringBuffer;
using rapidjson::Value;
using rapidjson::Writer;

http::ImmediateResponse Json(int status, std::string body)
{
    return {status, "application/json", std::move(body), {{"Cache-Control", "no-store"}}};
}

http::ImmediateResponse Error(int status, std::string_view message)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("error");
    writer.String(message.data(), static_cast<rapidjson::SizeType>(message.size()));
    writer.EndObject();
    return Json(status, {buffer.GetString(), buffer.GetSize()});
}

http::ImmediateResponse Unauthorized()
{
    auto response = Error(401, "unauthorized");
    response.headers.emplace_back(
        "WWW-Authenticate", "Basic realm=\"binjad portal\", charset=\"UTF-8\"");
    return response;
}

std::optional<std::string> DecodeBase64(std::string_view encoded)
{
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (encoded.empty() || encoded.size() % 4 != 0)
        return std::nullopt;
    std::string output;
    output.reserve(encoded.size() / 4 * 3);
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
            const auto digit = alphabet.find(character);
            if (digit == std::string_view::npos)
                return std::nullopt;
            value = (value << 6) | static_cast<std::uint32_t>(digit);
        }
        output.push_back(static_cast<char>((value >> 16) & 0xff));
        if (padding < 2)
            output.push_back(static_cast<char>((value >> 8) & 0xff));
        if (padding < 1)
            output.push_back(static_cast<char>(value & 0xff));
    }
    return output;
}

std::optional<std::pair<std::string, std::string>> BasicCredentials(
    const std::optional<std::string>& authorization)
{
    if (!authorization || authorization->size() < 7)
        return std::nullopt;
    const auto scheme = std::string_view(*authorization).substr(0, 5);
    if (!std::equal(scheme.begin(), scheme.end(), "Basic", [](char left, char right) {
        return std::tolower(static_cast<unsigned char>(left)) ==
            std::tolower(static_cast<unsigned char>(right));
    }) || (*authorization)[5] != ' ')
        return std::nullopt;
    const auto decoded = DecodeBase64(std::string_view(*authorization).substr(6));
    if (!decoded)
        return std::nullopt;
    const auto separator = decoded->find(':');
    if (separator == std::string::npos || separator == 0)
        return std::nullopt;
    return std::pair(decoded->substr(0, separator), decoded->substr(separator + 1));
}

std::optional<std::string_view> BearerCredential(
    const std::optional<std::string>& authorization)
{
    if (!authorization || authorization->size() < 8 || (*authorization)[6] != ' ')
        return std::nullopt;
    const auto scheme = std::string_view(*authorization).substr(0, 6);
    if (!std::equal(scheme.begin(), scheme.end(), "Bearer", [](char left, char right) {
        return std::tolower(static_cast<unsigned char>(left)) ==
            std::tolower(static_cast<unsigned char>(right));
    }))
        return std::nullopt;
    const auto token = std::string_view(*authorization).substr(7);
    return token.empty() || token.find_first_of(" \t\r\n") != std::string_view::npos
        ? std::nullopt : std::optional(token);
}

std::optional<Document> ParseObject(std::string_view json, std::string& error)
{
    Document document;
    try
    {
        document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
    }
    catch (const ParseException& exception)
    {
        error = std::string("invalid JSON at byte ") +
            std::to_string(exception.Offset()) + ": " +
            rapidjson::GetParseError_En(exception.Code());
        return std::nullopt;
    }
    if (document.HasParseError())
    {
        error = std::string("invalid JSON at byte ") +
            std::to_string(document.GetErrorOffset()) + ": " +
            rapidjson::GetParseError_En(document.GetParseError());
        return std::nullopt;
    }
    if (!document.IsObject())
    {
        error = "request body must be a JSON object";
        return std::nullopt;
    }
    return document;
}

bool OnlyFields(const Value& object, std::initializer_list<std::string_view> fields,
    std::string& error)
{
    std::unordered_set<std::string_view> seen;
    for (const auto& member : object.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (std::find(fields.begin(), fields.end(), name) == fields.end())
        {
            error = "unknown field '" + std::string(name) + "'";
            return false;
        }
        if (!seen.insert(name).second)
        {
            error = "duplicate field '" + std::string(name) + "'";
            return false;
        }
    }
    return true;
}

bool StringField(const Value& object, const char* name, std::string& output,
    bool required, std::string& error)
{
    const auto member = object.FindMember(name);
    if (member == object.MemberEnd())
    {
        if (required)
            error = std::string(name) + " is required";
        return !required;
    }
    if (!member->value.IsString())
    {
        error = std::string(name) + " must be a string";
        return false;
    }
    output.assign(member->value.GetString(), member->value.GetStringLength());
    return true;
}

std::optional<security::PortalRole> PortalRole(std::string_view role)
{
    if (role == "portal-admin")
        return security::PortalRole::Admin;
    if (role == "self-service")
        return security::PortalRole::SelfService;
    return std::nullopt;
}

std::optional<security::TokenRole> TokenRole(std::string_view role)
{
    if (role == "admin")
        return security::TokenRole::Admin;
    if (role == "user")
        return security::TokenRole::User;
    return std::nullopt;
}

template <typename WriteValue>
std::string JsonResult(WriteValue writeValue)
{
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("result");
    writeValue(writer);
    writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}

template <typename WriterType>
void WriteAccount(WriterType& writer, const security::AccountRecord& account)
{
    writer.StartObject();
    writer.Key("id");
    writer.String(account.id.data(), static_cast<rapidjson::SizeType>(account.id.size()));
    writer.Key("username");
    writer.String(account.username.data(), static_cast<rapidjson::SizeType>(account.username.size()));
    writer.Key("role");
    writer.String(account.role == security::PortalRole::Admin ? "portal-admin" : "self-service");
    writer.Key("created_at");
    writer.Uint64(account.createdAt);
    if (account.collaborationUsername)
    {
        writer.Key("collaboration_username");
        writer.String(account.collaborationUsername->data(),
            static_cast<rapidjson::SizeType>(account.collaborationUsername->size()));
    }
    writer.Key("deleted_at");
    writer.Uint64(account.deletedAt.value_or(0));
    writer.EndObject();
}

template <typename WriterType>
void WriteToken(WriterType& writer, const security::TokenRecord& token)
{
    writer.StartObject();
    writer.Key("id");
    writer.String(token.id.data(), static_cast<rapidjson::SizeType>(token.id.size()));
    writer.Key("role");
    writer.String(token.role == security::TokenRole::Admin ? "admin" : "user");
    if (!token.label.empty())
    {
        writer.Key("label");
        writer.String(token.label.data(), static_cast<rapidjson::SizeType>(token.label.size()));
    }
    writer.Key("created_at");
    writer.Uint64(token.createdAt);
    writer.Key("expires_at");
    writer.Uint64(token.expiresAt.value_or(0));
    writer.EndObject();
}

std::string_view SegmentAfter(std::string_view path, std::string_view prefix)
{
    return path.starts_with(prefix) ? path.substr(prefix.size()) : std::string_view{};
}

std::string NormalizeJson(std::string_view json)
{
    std::string error;
    const auto document = ParseObject(json, error);
    if (!document)
        return {};
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document->Accept(writer);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string_view ModeName(Mode mode)
{
    switch (mode)
    {
        case Mode::Auto: return "auto";
        case Mode::Local: return "local";
        case Mode::Collaboration: return "collaboration";
    }
    return "auto";
}

template <typename WriterType>
void WriteProject(WriterType& writer, const ProjectSummary& project)
{
    writer.StartObject();
    writer.Key("project");
    writer.String(project.reference.data(),
        static_cast<rapidjson::SizeType>(project.reference.size()));
    writer.Key("name");
    writer.String(project.name.data(), static_cast<rapidjson::SizeType>(project.name.size()));
    writer.Key("description");
    writer.String(project.description.data(),
        static_cast<rapidjson::SizeType>(project.description.size()));
    writer.EndObject();
}
}

Api::Api(Config config, Service& service, std::filesystem::path configPath)
    : config_(std::move(config)), service_(service), apiPath_(config_.http.portalPath + "/api"),
      configPath_(std::move(configPath))
{
    if (!configPath_.empty())
    {
        const auto current = platform::ReadPrivateFile(configPath_);
        if (current.contents)
            activeConfiguration_ = NormalizeJson(*current.contents);
    }
    if (activeConfiguration_.empty())
        activeConfiguration_ = NormalizeJson(DefaultConfigJson());
}

void Api::SetProjectDeleteCallback(ProjectDelete callback)
{
    projectDelete_ = std::move(callback);
}

void Api::SetProjectListCallback(ProjectList callback)
{
    projectList_ = std::move(callback);
}

void Api::SetRuntimeStatusProvider(RuntimeStatusProvider callback)
{
    runtimeStatus_ = std::move(callback);
}

void Api::SetMcpDocumentationProviders(
    McpContextProvider context, McpToolsProvider tools)
{
    mcpContext_ = std::move(context);
    mcpTools_ = std::move(tools);
}

http::ImmediateResponse Api::Handle(const ApiRequest& request)
{
    if (!AllowedOrigin(request.origin))
        return Error(403, "forbidden_origin");
    if (request.body.size() > kMaxBodyBytes)
        return Error(413, "payload_too_large");
    if (request.path == apiPath_ + "/bootstrap" && request.method == http::Method::Get)
    {
        const auto available = service_.BootstrapAvailable();
        if (!available.value)
            return Error(500, available.error);
        return Json(200, JsonResult([&](auto& writer) { writer.Bool(*available.value); }));
    }
    if (request.path == apiPath_ + "/bootstrap" && request.method == http::Method::Post)
    {
        std::string error;
        const auto body = ParseObject(request.body, error);
        if (!body || !OnlyFields(*body, {"credential", "username", "password"}, error))
            return Error(400, error);
        std::string credential;
        std::string username;
        std::string password;
        if (!StringField(*body, "credential", credential, true, error) ||
            !StringField(*body, "username", username, true, error) ||
            !StringField(*body, "password", password, true, error))
            return Error(400, error);
        const auto created = service_.CreateBootstrapAdministrator(
            credential, std::move(username), std::move(password));
        if (!created.value)
            return Error(created.error == "invalid bootstrap credential" ? 401 : 400, created.error);
        return Json(201, JsonResult([&](auto& writer) { WriteAccount(writer, *created.value); }));
    }

    http::ImmediateResponse authenticationError;
    const auto actor = Authenticate(request, authenticationError);
    if (!actor)
        return authenticationError;

    if (request.path == apiPath_ + "/status" && request.method == http::Method::Get)
    {
        const auto status = runtimeStatus_ ? runtimeStatus_() : RuntimeStatus{};
        bool restartRequired = false;
        {
            std::lock_guard lock(configurationMutex_);
            restartRequired = restartRequired_;
        }
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartObject();
            writer.Key("version"); writer.String(BINJAD_VERSION);
            writer.Key("mode"); writer.String(ModeName(config_.EffectiveMode()).data());
            writer.Key("configured_mode"); writer.String(ModeName(config_.mode).data());
            writer.Key("restart_required"); writer.Bool(restartRequired);
            writer.Key("actor"); WriteAccount(writer, *actor);
            writer.Key("runtime"); writer.StartObject();
            writer.Key("analysis_sessions"); writer.Uint64(status.analysisSessions);
            writer.Key("open_items"); writer.Uint64(status.openItems);
            writer.Key("jobs"); writer.Uint64(status.jobs);
            writer.Key("projects"); writer.Uint64(status.projects);
            writer.Key("logical_cpu_count"); writer.Uint64(status.logicalCpuCount);
            writer.Key("worker_budget"); writer.Uint64(status.workerBudget);
            writer.Key("allocated_workers"); writer.Uint64(status.allocatedWorkers);
            writer.Key("active_analyses"); writer.Uint64(status.activeAnalyses);
            writer.Key("queued_analyses"); writer.Uint64(status.queuedAnalyses);
            writer.EndObject();
            writer.EndObject();
        }));
    }

    if ((request.path == apiPath_ + "/mcp/context" ||
        request.path == apiPath_ + "/mcp/tools") && request.method == http::Method::Post)
    {
        if (actor->role != security::PortalRole::Admin)
            return Error(403, "portal administrator required");
        std::string error;
        const auto body = ParseObject(request.body, error);
        const bool context = request.path == apiPath_ + "/mcp/context";
        if (!body || !OnlyFields(*body,
            context ? std::initializer_list<std::string_view>{"protocol", "role", "client"}
                    : std::initializer_list<std::string_view>{"protocol", "role"}, error))
            return Error(400, error);
        std::string protocolName;
        std::string roleName;
        if (!StringField(*body, "protocol", protocolName, true, error) ||
            !StringField(*body, "role", roleName, true, error))
            return Error(400, error);
        const auto protocol = mcp::ParseProtocolVersion(protocolName);
        if (!protocol)
            return Error(400, "protocol must be a supported MCP protocol version");
        const auto role = TokenRole(roleName);
        if (!role)
            return Error(400, "role must be 'admin' or 'user'");
        std::string result;
        if (context)
        {
            std::string client = "binjad";
            if (!StringField(*body, "client", client, false, error))
                return Error(400, error);
            if (client.empty() || client.size() > 64 ||
                !std::all_of(client.begin(), client.end(), [](unsigned char character) {
                    return std::isalnum(character) != 0 || character == '_' || character == '-';
                }))
                return Error(400, "client must contain 1 through 64 ASCII letters, digits, '_' or '-'");
            if (!mcpContext_)
                return Error(503, "MCP context documentation is unavailable");
            result = mcpContext_(*protocol, *role, client);
        }
        else
        {
            if (!mcpTools_)
                return Error(503, "MCP tool documentation is unavailable");
            result = mcpTools_(*protocol, *role);
        }
        Document documented;
        documented.Parse(result.data(), result.size());
        if (documented.HasParseError() || !documented.IsObject())
            return Error(500, "MCP documentation provider returned invalid JSON");
        return Json(200, JsonResult([&](auto& writer) { documented.Accept(writer); }));
    }

    if (request.path == apiPath_ + "/config" && request.method == http::Method::Get)
    {
        if (actor->role != security::PortalRole::Admin)
            return Error(403, "portal administrator required");
        std::lock_guard lock(configurationMutex_);
        std::string configured = activeConfiguration_;
        if (!configPath_.empty())
        {
            const auto current = platform::ReadPrivateFile(configPath_);
            if (!current.error.empty())
                return Error(500, current.error);
            if (current.contents)
                configured = NormalizeJson(*current.contents);
        }
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartObject();
            writer.Key("configuration");
            writer.RawValue(configured.data(), configured.size(), rapidjson::kObjectType);
            writer.Key("restart_required"); writer.Bool(restartRequired_);
            writer.EndObject();
        }));
    }
    if (request.path == apiPath_ + "/config" && request.method == http::Method::Put)
    {
        if (actor->role != security::PortalRole::Admin)
            return Error(403, "portal administrator required");
        if (configPath_.empty())
            return Error(503, "configuration persistence is unavailable");
        const auto parsed = ParseConfig(request.body, configPath_);
        if (!parsed.config)
        {
            return Json(400, JsonResult([&](auto& writer) {
                writer.StartObject();
                writer.Key("valid"); writer.Bool(false);
                writer.Key("errors"); writer.StartArray();
                for (const auto& item : parsed.errors)
                {
                    writer.StartObject();
                    writer.Key("path"); writer.String(item.path.data(),
                        static_cast<rapidjson::SizeType>(item.path.size()));
                    writer.Key("message"); writer.String(item.message.data(),
                        static_cast<rapidjson::SizeType>(item.message.size()));
                    writer.EndObject();
                }
                writer.EndArray();
                writer.EndObject();
            }));
        }
        const auto normalized = NormalizeJson(request.body);
        if (normalized.empty())
            return Error(400, "invalid configuration JSON");
        const auto persisted = platform::ReplacePrivateFile(configPath_, request.body + "\n");
        if (!persisted.installed)
            return Error(500, persisted.error);
        bool restartRequired = false;
        {
            std::lock_guard lock(configurationMutex_);
            restartRequired_ = normalized != activeConfiguration_;
            restartRequired = restartRequired_;
        }
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartObject();
            writer.Key("valid"); writer.Bool(true);
            writer.Key("restart_required"); writer.Bool(restartRequired);
            writer.Key("effective_mode");
            writer.String(ModeName(parsed.config->EffectiveMode()).data());
            writer.EndObject();
        }));
    }

    if (request.path == apiPath_ + "/projects" && request.method == http::Method::Get)
    {
        if (actor->role != security::PortalRole::Admin)
            return Error(403, "portal administrator required");
        auto projects = projectList_ ? projectList_() : std::vector<ProjectSummary>{};
        std::sort(projects.begin(), projects.end(), [](const auto& left, const auto& right) {
            return left.name < right.name ||
                (left.name == right.name && left.reference < right.reference);
        });
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartArray();
            for (const auto& project : projects) WriteProject(writer, project);
            writer.EndArray();
        }));
    }

    if (request.path == apiPath_ + "/accounts" && request.method == http::Method::Get)
    {
        auto accounts = service_.ListAccounts(*actor);
        if (!accounts.value)
            return Error(403, accounts.error);
        std::sort(accounts.value->begin(), accounts.value->end(), [](const auto& left, const auto& right) {
            return left.username < right.username ||
                (left.username == right.username && left.id < right.id);
        });
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartArray();
            for (const auto& account : *accounts.value)
                WriteAccount(writer, account);
            writer.EndArray();
        }));
    }
    if (request.path == apiPath_ + "/accounts" && request.method == http::Method::Post)
    {
        std::string error;
        const auto body = ParseObject(request.body, error);
        if (!body || !OnlyFields(*body, {"username", "password", "role"}, error))
            return Error(400, error);
        std::string username;
        std::string password;
        std::string role;
        if (!StringField(*body, "username", username, true, error) ||
            !StringField(*body, "password", password, true, error) ||
            !StringField(*body, "role", role, true, error))
            return Error(400, error);
        const auto parsedRole = PortalRole(role);
        if (!parsedRole)
            return Error(400, "role must be 'portal-admin' or 'self-service'");
        const auto created = service_.CreateAccount(
            *actor, std::move(username), std::move(password), *parsedRole);
        if (!created.value)
            return Error(created.error == "portal administrator required" ? 403 : 400, created.error);
        return Json(201, JsonResult([&](auto& writer) { WriteAccount(writer, *created.value); }));
    }

    const auto accountsPrefix = apiPath_ + "/accounts/";
    if (request.path.starts_with(accountsPrefix))
    {
        const auto suffix = SegmentAfter(request.path, accountsPrefix);
        const auto slash = suffix.find('/');
        const auto accountId = suffix.substr(0, slash);
        if (slash != std::string_view::npos && suffix.substr(slash) == "/collaboration" &&
            request.method == http::Method::Put)
        {
            std::string error;
            const auto body = ParseObject(request.body, error);
            if (!body || !OnlyFields(*body, {"username", "access_token"}, error))
                return Error(400, error);
            std::string username;
            std::string accessToken;
            if (!StringField(*body, "username", username, true, error) ||
                !StringField(*body, "access_token", accessToken, true, error))
                return Error(400, error);
            const auto updated = service_.SetCollaborationBinding(
                *actor, accountId, std::move(username), std::move(accessToken));
            if (!updated.value)
                return Error(updated.error == "account not found" ? 404 : 400, updated.error);
            return Json(200, JsonResult([&](auto& writer) { WriteAccount(writer, *updated.value); }));
        }
        if (slash == std::string_view::npos && request.method == http::Method::Get)
        {
            const auto accounts = service_.ListAccounts(*actor);
            if (!accounts.value)
                return Error(403, accounts.error);
            const auto found = std::find_if(accounts.value->begin(), accounts.value->end(),
                [&](const auto& account) { return account.id == accountId; });
            if (found == accounts.value->end())
                return Error(404, "account not found");
            return Json(200, JsonResult([&](auto& writer) { WriteAccount(writer, *found); }));
        }
        if (slash == std::string_view::npos && request.method == http::Method::Patch)
        {
            std::string error;
            const auto body = ParseObject(request.body, error);
            if (!body || !OnlyFields(*body, {"role", "password"}, error))
                return Error(400, error);
            security::AccountUpdateRequest update;
            std::string role;
            if (!StringField(*body, "role", role, false, error))
                return Error(400, error);
            if (body->HasMember("role"))
            {
                update.role = PortalRole(role);
                if (!update.role)
                    return Error(400, "role must be 'portal-admin' or 'self-service'");
            }
            std::string password;
            if (!StringField(*body, "password", password, false, error))
                return Error(400, error);
            if (body->HasMember("password"))
                update.password = std::move(password);
            const auto updated = service_.UpdateAccount(*actor, accountId, update);
            if (!updated.value)
                return Error(updated.error == "account not found" ? 404 :
                    updated.error.find("administrator required") != std::string::npos ? 403 : 400,
                    updated.error);
            return Json(200, JsonResult([&](auto& writer) { WriteAccount(writer, *updated.value); }));
        }
        if (slash == std::string_view::npos && request.method == http::Method::Delete)
        {
            std::string error;
            const auto body = ParseObject(request.body, error);
            if (!body || !OnlyFields(*body, {"tokens"}, error))
                return Error(400, error);
            std::string disposition;
            if (!StringField(*body, "tokens", disposition, true, error))
                return Error(400, error);
            if (disposition != "revoke" && disposition != "retain")
                return Error(400, "tokens must be 'revoke' or 'retain'");
            const auto deleted = service_.DeleteAccount(
                *actor, accountId, disposition == "revoke");
            if (!deleted.value)
                return Error(deleted.error == "portal administrator required" ? 403 : 400, deleted.error);
            return Json(200, JsonResult([&](auto& writer) {
                writer.StartObject();
                writer.Key("deleted");
                writer.Bool(deleted.value->deleted);
                writer.Key("revoked_tokens");
                writer.Uint64(deleted.value->revokedTokens);
                writer.EndObject();
            }));
        }
    }

    const auto projectsPrefix = apiPath_ + "/projects/";
    if (request.path.starts_with(projectsPrefix) && request.method == http::Method::Delete)
    {
        const auto project = SegmentAfter(request.path, projectsPrefix);
        if (project.empty() || project.find('/') != std::string_view::npos)
            return Error(404, "project not found");
        if (actor->role != security::PortalRole::Admin)
            return Error(403, "portal administrator required");
        std::string error;
        const auto body = ParseObject(request.body, error);
        if (!body || !OnlyFields(*body, {"delete"}, error))
            return Error(400, error);
        const auto confirmed = body->FindMember("delete");
        if (confirmed == body->MemberEnd() || !confirmed->value.IsBool() ||
            !confirmed->value.GetBool())
            return Error(400, "delete must be true");
        if (config_.EffectiveMode() != Mode::Local || !projectDelete_)
            return Error(400, "local project deletion is unavailable");
        const auto deleted = projectDelete_(project);
        if (!deleted.value)
        {
            const auto status = deleted.error == "project not found" ? 404 :
                deleted.error == "project has open analysis handles" ? 409 : 400;
            return Error(status, deleted.error);
        }
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartObject();
            writer.Key("project");
            writer.String(project.data(), static_cast<rapidjson::SizeType>(project.size()));
            writer.Key("deleted");
            writer.Bool(*deleted.value);
            writer.EndObject();
        }));
    }

    if (request.path == apiPath_ + "/tokens" && request.method == http::Method::Get)
    {
        const auto tokens = service_.ListTokens(*actor);
        if (!tokens.value)
            return Error(400, tokens.error);
        return Json(200, JsonResult([&](auto& writer) {
            writer.StartArray();
            for (const auto& token : *tokens.value)
                WriteToken(writer, token);
            writer.EndArray();
        }));
    }
    if (request.path == apiPath_ + "/tokens" && request.method == http::Method::Post)
    {
        std::string error;
        const auto body = ParseObject(request.body, error);
        if (!body || !OnlyFields(*body, {"label", "role", "ttl_seconds"}, error))
            return Error(400, error);
        TokenRequest tokenRequest;
        std::string label;
        if (!StringField(*body, "label", label, false, error))
            return Error(400, error);
        if (body->HasMember("label"))
            tokenRequest.label = std::move(label);
        std::string role;
        if (!StringField(*body, "role", role, false, error))
            return Error(400, error);
        if (body->HasMember("role"))
        {
            tokenRequest.role = TokenRole(role);
            if (!tokenRequest.role)
                return Error(400, "role must be 'admin' or 'user'");
        }
        if (const auto ttl = body->FindMember("ttl_seconds"); ttl != body->MemberEnd())
        {
            if (!ttl->value.IsUint64())
                return Error(400, "ttl_seconds must be an unsigned integer");
            tokenRequest.ttlSeconds = ttl->value.GetUint64();
        }
        const auto issued = service_.IssueToken(*actor, tokenRequest);
        if (!issued.value || !issued.value->token || !issued.value->record)
            return Error(issued.error == "portal administrator required to issue an admin token" ? 403 : 400,
                issued.error);
        return Json(201, JsonResult([&](auto& writer) {
            writer.StartObject();
            writer.Key("token");
            writer.String(issued.value->token->data(),
                static_cast<rapidjson::SizeType>(issued.value->token->size()));
            writer.Key("metadata");
            WriteToken(writer, *issued.value->record);
            writer.EndObject();
        }));
    }
    const auto tokensPrefix = apiPath_ + "/tokens/";
    if (request.path.starts_with(tokensPrefix) && request.method == http::Method::Delete)
    {
        const auto tokenId = SegmentAfter(request.path, tokensPrefix);
        if (tokenId.find('/') != std::string_view::npos)
            return Error(404, "not found");
        const auto revoked = service_.RevokeToken(*actor, tokenId);
        if (!revoked.value || !*revoked.value)
            return revoked.error.empty() ? Error(404, "token not found") : Error(400, revoked.error);
        return {204, {}, {}, {{"Cache-Control", "no-store"}}};
    }
    return Error(404, "not found");
}

http::ImmediateResponse Api::Page() const
{
    auto response = Asset("index.html");
    constexpr std::string_view marker = "{{PORTAL_PATH}}";
    for (auto position = response.body.find(marker); position != std::string::npos;
        position = response.body.find(marker, position + config_.http.portalPath.size()))
        response.body.replace(position, marker.size(), config_.http.portalPath);
    response.headers.emplace_back("Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'");
    return response;
}

http::ImmediateResponse Api::Asset(std::string_view name) const
{
    if (name != "index.html" && name != "app.css" && name != "app.js" &&
        name != "binjad.png")
        return Error(404, "not found");
    const std::filesystem::path candidates[]{
        std::filesystem::path(BINJAD_PORTAL_INSTALL_DIR) / name,
        std::filesystem::path(BINJAD_PORTAL_SOURCE_DIR) / name,
    };
    for (const auto& path : candidates)
    {
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            continue;
        const std::string contents{
            std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
        const auto contentType = name == "index.html" ? "text/html; charset=utf-8" :
            name == "app.css" ? "text/css; charset=utf-8" :
            name == "app.js" ? "text/javascript; charset=utf-8" :
                               "image/png";
        return {200, contentType, contents, {{"Cache-Control", "no-store"}}};
    }
    return Error(500, "portal asset is unavailable");
}

std::optional<security::AccountRecord> Api::Authenticate(
    const ApiRequest& request, http::ImmediateResponse& error) const
{
    if (config_.http.veryDangerousUnauthenticatedPortal)
    {
        const auto administrator = service_.UnauthenticatedAdministrator();
        if (administrator.value)
            return administrator.value;
        error = Unauthorized();
        return std::nullopt;
    }
    if (const auto bearer = BearerCredential(request.authorization))
    {
        const auto authenticated = service_.AuthenticateAdminBearer(*bearer);
        if (authenticated.value)
            return authenticated.value;
        error = Unauthorized();
        return std::nullopt;
    }
    const auto credentials = BasicCredentials(request.authorization);
    if (!credentials)
    {
        error = Unauthorized();
        return std::nullopt;
    }
    const auto authenticated = service_.Authenticate(credentials->first, credentials->second);
    if (authenticated.result != security::PasswordVerification::Match || !authenticated.account)
    {
        error = authenticated.result == security::PasswordVerification::Error
            ? Error(500, "authentication backend failure") : Unauthorized();
        return std::nullopt;
    }
    return authenticated.account;
}

bool Api::AllowedOrigin(const std::optional<std::string>& origin) const
{
    return !origin || std::find(config_.http.allowedOrigins.begin(),
        config_.http.allowedOrigins.end(), *origin) != config_.http.allowedOrigins.end();
}
}
