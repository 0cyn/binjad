#include "binjad/Config.hpp"
#include "binjad/security/CredentialStore.hpp"

#include <rapidjsonwrapper.h>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

extern char** environ;

namespace {
using namespace std::chrono_literals;

struct CommandResult
{
    int status = 255;
    std::string output;
};

CommandResult RunCommand(const std::vector<std::string>& arguments, bool capture = false)
{
    int pipeDescriptors[2]{-1, -1};
    posix_spawn_file_actions_t actions = nullptr;
    if (capture)
    {
        if (pipe(pipeDescriptors) != 0 || posix_spawn_file_actions_init(&actions) != 0)
            return {};
        posix_spawn_file_actions_adddup2(&actions, pipeDescriptors[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, pipeDescriptors[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, pipeDescriptors[0]);
        posix_spawn_file_actions_addclose(&actions, pipeDescriptors[1]);
    }
    std::vector<char*> values;
    values.reserve(arguments.size() + 1);
    for (const auto& argument : arguments)
        values.push_back(const_cast<char*>(argument.c_str()));
    values.push_back(nullptr);
    pid_t process = 0;
    const auto spawned =
        posix_spawn(&process, arguments.front().c_str(), capture ? &actions : nullptr, nullptr, values.data(), environ);
    if (capture)
    {
        posix_spawn_file_actions_destroy(&actions);
        close(pipeDescriptors[1]);
    }
    if (spawned != 0)
    {
        if (capture)
            close(pipeDescriptors[0]);
        return {spawned, {}};
    }
    CommandResult result;
    if (capture)
    {
        char buffer[4096];
        ssize_t length = 0;
        while ((length = read(pipeDescriptors[0], buffer, sizeof(buffer))) > 0)
            result.output.append(buffer, static_cast<std::size_t>(length));
        close(pipeDescriptors[0]);
    }
    int status = 0;
    while (waitpid(process, &status, 0) < 0 && errno == EINTR)
    {}
    result.status = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255);
    return result;
}

std::uint16_t AvailablePort()
{
    const auto socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (socketDescriptor < 0)
        return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(socketDescriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
    {
        close(socketDescriptor);
        return 0;
    }
    socklen_t size = sizeof(address);
    if (getsockname(socketDescriptor, reinterpret_cast<sockaddr*>(&address), &size) != 0)
    {
        close(socketDescriptor);
        return 0;
    }
    close(socketDescriptor);
    return ntohs(address.sin_port);
}

std::string XmlEscape(std::string_view value)
{
    std::string result;
    for (const char character : value)
    {
        switch (character)
        {
            case '&':
                result += "&amp;";
                break;
            case '<':
                result += "&lt;";
                break;
            case '>':
                result += "&gt;";
                break;
            case '\"':
                result += "&quot;";
                break;
            case '\'':
                result += "&apos;";
                break;
            default:
                result += character;
                break;
        }
    }
    return result;
}

std::string Base64(std::string_view value)
{
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    for (std::size_t offset = 0; offset < value.size(); offset += 3)
    {
        std::uint32_t bytes = static_cast<unsigned char>(value[offset]) << 16;
        if (offset + 1 < value.size())
            bytes |= static_cast<unsigned char>(value[offset + 1]) << 8;
        if (offset + 2 < value.size())
            bytes |= static_cast<unsigned char>(value[offset + 2]);
        output.push_back(alphabet[(bytes >> 18) & 0x3f]);
        output.push_back(alphabet[(bytes >> 12) & 0x3f]);
        output.push_back(offset + 1 < value.size() ? alphabet[(bytes >> 6) & 0x3f] : '=');
        output.push_back(offset + 2 < value.size() ? alphabet[bytes & 0x3f] : '=');
    }
    return output;
}

struct HttpResult
{
    int status = 0;
    std::string body;
};

HttpResult Http(
    std::string_view method, std::string_view url, const std::vector<std::string>& headers = {},
    std::string_view body = {}, const std::filesystem::path& responseHeaders = {})
{
    std::vector<std::string> arguments{
        "/usr/bin/curl", "--silent",          "--show-error", "--max-time",    "180",
        "--request",     std::string(method), "--write-out",  "\n%{http_code}"};
    if (!responseHeaders.empty())
    {
        arguments.emplace_back("--dump-header");
        arguments.push_back(responseHeaders.string());
    }
    for (const auto& header : headers)
    {
        arguments.emplace_back("--header");
        arguments.push_back(header);
    }
    if (!body.empty())
    {
        arguments.emplace_back("--data-binary");
        arguments.emplace_back(body);
    }
    arguments.emplace_back(url);
    const auto command = RunCommand(arguments, true);
    if (command.status != 0)
        return {-command.status, command.output};
    const auto separator = command.output.rfind('\n');
    if (separator == std::string::npos)
        return {};
    HttpResult result;
    result.body = command.output.substr(0, separator);
    const auto status = command.output.substr(separator + 1);
    if (status.size() == 3)
        result.status = std::stoi(status);
    return result;
}

std::string Header(const std::filesystem::path& path, std::string_view name)
{
    std::ifstream stream(path);
    std::string line;
    std::string expected(name);
    std::transform(expected.begin(), expected.end(), expected.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    while (std::getline(stream, line))
    {
        const auto separator = line.find(':');
        if (separator == std::string::npos)
            continue;
        auto key = line.substr(0, separator);
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        if (key != expected)
            continue;
        auto value = line.substr(separator + 1);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
            value.erase(value.begin());
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
            value.pop_back();
        return value;
    }
    return {};
}

rapidjson::Document Parse(std::string_view json)
{
    rapidjson::Document document;
    document.Parse(json.data(), json.size());
    return document;
}

class LaunchdRegistration
{
  public:
    LaunchdRegistration(std::string domain, std::string label) : target_(std::move(domain) + "/" + std::move(label)) {}
    ~LaunchdRegistration()
    {
        if (loaded_)
            (void)RunCommand({"/bin/launchctl", "bootout", target_}, true);
    }
    void SetLoaded() { loaded_ = true; }

  private:
    std::string target_;
    bool loaded_ = false;
};

class CredentialCleanup
{
  public:
    explicit CredentialCleanup(const std::filesystem::path& configPath) :
        service_("me.cynder.binjad." + binjad::security::CredentialNamespace(configPath))
    {}
    ~CredentialCleanup()
    {
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            if (RunCommand({"/usr/bin/security", "delete-generic-password", "-s", service_}, true).status != 0)
                break;
        }
    }

  private:
    std::string service_;
};

std::string ToolBody(int id, std::string_view name, std::string_view arguments)
{
    return "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) + ",\"method\":\"tools/call\",\"params\":{\"name\":\""
        + std::string(name) + "\",\"arguments\":" + std::string(arguments) + "}}";
}
}  // namespace

TEST(MachLaunchdIntegrationTest, RunsOverseerAndRealFileChild)
{
    const auto label = "me.cynder.binjad.integration." + std::to_string(getpid());
    const auto temporary = std::filesystem::temp_directory_path() / label;
    std::error_code ignored;
    std::filesystem::remove_all(temporary, ignored);
    ASSERT_TRUE(std::filesystem::create_directories(temporary));
    struct FileCleanup
    {
        std::filesystem::path path;
        ~FileCleanup()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } fileCleanup{temporary};

    const auto configPath = temporary / "config.json";
    const auto projectRoot = temporary / "projects";
    const auto fixture = RunCommand({BINJAD_TEST_PROJECT_FIXTURE_PATH, projectRoot.string()}, true);
    ASSERT_EQ(fixture.status, 0) << fixture.output;
    const auto created = binjad::LoadOrCreateConfig(configPath);
    ASSERT_TRUE(created.config) << created.errors.front().message;
    const auto port = AvailablePort();
    ASSERT_NE(port, 0);
    rapidjson::Document config;
    {
        std::ifstream stream(configPath, std::ios::binary);
        const std::string json(std::istreambuf_iterator<char>(stream), {});
        config.Parse(json.data(), json.size());
    }
    ASSERT_TRUE(config.IsObject());
    config["listener"]["port"].SetUint(port);
    config["listener"]["addresses"].Clear();
    config["listener"]["addresses"].PushBack(
        rapidjson::Value("127.0.0.1", config.GetAllocator()), config.GetAllocator());
    config["projects"]["roots"].Clear();
    config["projects"]["roots"].PushBack(
        rapidjson::Value(projectRoot.string().c_str(), config.GetAllocator()), config.GetAllocator());
    config["projects"]["default_root"].SetString(projectRoot.string().c_str(), config.GetAllocator());
    {
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        config.Accept(writer);
        std::ofstream stream(configPath, std::ios::binary | std::ios::trunc);
        stream.write(buffer.GetString(), static_cast<std::streamsize>(buffer.GetSize()));
    }
    CredentialCleanup credentialCleanup(configPath);

    const auto plistPath = temporary / "agent.plist";
    {
        std::ofstream plist(plistPath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(plist);
        plist
            << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
               "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            << "<plist version=\"1.0\"><dict>\n"
            << "<key>Label</key><string>" << label << "</string>\n"
            << "<key>ProgramArguments</key><array>"
            << "<string>" << XmlEscape(BINJAD_TEST_DAEMON_PATH) << "</string>"
            << "<string>--config</string><string>" << XmlEscape(configPath.string()) << "</string>"
            << "</array>\n"
            << "<key>MachServices</key><dict><key>me.cynder.binjad</key><true/></dict>\n"
            << "<key>RunAtLoad</key><true/>\n"
            << "<key>ProcessType</key><string>Background</string>\n"
            << "</dict></plist>\n";
    }

    const auto domain = "gui/" + std::to_string(getuid());
    LaunchdRegistration registration(domain, label);
    if (RunCommand({"/bin/launchctl", "bootstrap", domain, plistPath.string()}, true).status != 0)
        GTEST_SKIP() << "launchctl could not bootstrap the integration LaunchAgent";
    registration.SetLoaded();

    const auto baseUrl = "http://127.0.0.1:" + std::to_string(port);
    bool ready = false;
    for (int attempt = 0; attempt < 1800; ++attempt)
    {
        const auto health = Http("GET", baseUrl + "/healthz");
        if (health.status == 200 && health.body == R"({"status":"ok"})")
        {
            ready = true;
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
    ASSERT_TRUE(ready) << "overseer did not become ready";

    const auto setup = Http(
        "POST", baseUrl + "/portal/api/setup", {"Content-Type: application/json"},
        R"({"username":"Admin","password":"ninebytes"})");
    ASSERT_EQ(setup.status, 201) << setup.body;
    const auto basic = "Authorization: Basic " + Base64("Admin:ninebytes");
    const auto issued = Http(
        "POST", baseUrl + "/portal/api/token", {"Content-Type: application/json", basic}, R"({"ttl_seconds":300})");
    ASSERT_EQ(issued.status, 201) << issued.body;
    auto issuedJson = Parse(issued.body);
    ASSERT_FALSE(issuedJson.HasParseError());
    ASSERT_TRUE(issuedJson["result"]["token"].IsString());
    const std::string token = issuedJson["result"]["token"].GetString();
    const auto bearer = "Authorization: Bearer " + token;

    const auto responseHeaders = temporary / "initialize.headers";
    const auto initialized = Http(
        "POST", baseUrl + "/mcp", {"Content-Type: application/json", bearer},
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}})",
        responseHeaders);
    ASSERT_EQ(initialized.status, 200) << initialized.body;
    const auto session = Header(responseHeaders, "mcp-session-id");
    ASSERT_EQ(session.size(), 43U);
    const std::vector<std::string> mcpHeaders{
        "Content-Type: application/json", bearer, "MCP-Protocol-Version: 2025-06-18", "Mcp-Session-Id: " + session};

    const auto projects = Http("POST", baseUrl + "/mcp", mcpHeaders, ToolBody(2, "bn_local_project_list", "{}"));
    ASSERT_EQ(projects.status, 200) << projects.body;
    EXPECT_EQ(projects.body.find(projectRoot.string()), std::string::npos);
    auto projectsJson = Parse(projects.body);
    ASSERT_TRUE(projectsJson.IsObject()) << projects.body;
    ASSERT_TRUE(projectsJson.HasMember("result")) << projects.body;
    ASSERT_TRUE(projectsJson["result"].HasMember("structuredContent")) << projects.body;
    ASSERT_TRUE(projectsJson["result"]["structuredContent"].HasMember("projects")) << projects.body;
    ASSERT_TRUE(projectsJson["result"]["structuredContent"]["projects"].IsArray()) << projects.body;
    ASSERT_FALSE(projectsJson["result"]["structuredContent"]["projects"].Empty()) << projects.body;
    const std::string project = projectsJson["result"]["structuredContent"]["projects"][0]["project"].GetString();
    const auto files = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(3, "bn_local_project_file_list", "{\"project\":\"" + project + "\"}"));
    ASSERT_EQ(files.status, 200) << files.body;
    auto filesJson = Parse(files.body);
    ASSERT_TRUE(filesJson.IsObject()) << files.body;
    ASSERT_TRUE(filesJson.HasMember("result")) << files.body;
    ASSERT_TRUE(filesJson["result"].HasMember("structuredContent")) << files.body;
    ASSERT_TRUE(filesJson["result"]["structuredContent"].HasMember("files")) << files.body;
    ASSERT_TRUE(filesJson["result"]["structuredContent"]["files"].IsArray()) << files.body;
    ASSERT_FALSE(filesJson["result"]["structuredContent"]["files"].Empty()) << files.body;
    const std::string filePath = filesJson["result"]["structuredContent"]["files"][0]["path"].GetString();
    const auto uploadUrl = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(40, "bn_upload_get_url", "{\"project\":\"" + project + "\",\"filename\":\"uploaded.bin\"}"));
    ASSERT_EQ(uploadUrl.status, 200) << uploadUrl.body;
    auto uploadJson = Parse(uploadUrl.body);
    const auto& uploadContent = uploadJson["result"]["structuredContent"];
    ASSERT_TRUE(uploadContent.HasMember("requiresBearerAuthentication"));
    EXPECT_FALSE(uploadContent["requiresBearerAuthentication"].GetBool());
    EXPECT_STREQ(uploadContent["method"].GetString(), "PUT");
    const std::string uploadId = uploadContent["id"].GetString();
    const std::string uploadUrlValue = uploadContent["url"].GetString();
    const auto transferred =
        Http("PUT", uploadUrlValue, {"Content-Type: application/octet-stream"}, "uploaded payload");
    ASSERT_EQ(transferred.status, 201) << transferred.body;
    const auto committedUpload = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(41, "bn_upload_commit", "{\"id\":\"" + uploadId + "\",\"folder\":\"incoming\"}"));
    ASSERT_EQ(committedUpload.status, 200) << committedUpload.body;
    EXPECT_NE(committedUpload.body.find("incoming/uploaded.bin"), std::string::npos) << committedUpload.body;
    const auto repeatedUploadCommit =
        Http("POST", baseUrl + "/mcp", mcpHeaders, ToolBody(44, "bn_upload_commit", "{\"id\":\"" + uploadId + "\"}"));
    ASSERT_EQ(repeatedUploadCommit.status, 200) << repeatedUploadCommit.body;
    EXPECT_NE(repeatedUploadCommit.body.find("incoming/uploaded.bin"), std::string::npos) << repeatedUploadCommit.body;
    const auto listedUploads = Http("POST", baseUrl + "/mcp", mcpHeaders, ToolBody(45, "bn_upload_list", "{}"));
    ASSERT_EQ(listedUploads.status, 200) << listedUploads.body;
    EXPECT_NE(listedUploads.body.find(R"("state":"committed")"), std::string::npos);
    const auto cancelledUpload =
        Http("POST", baseUrl + "/mcp", mcpHeaders, ToolBody(46, "bn_upload_cancel", "{\"id\":\"" + uploadId + "\"}"));
    ASSERT_EQ(cancelledUpload.status, 200) << cancelledUpload.body;
    EXPECT_NE(cancelledUpload.body.find(R"("cancelled":true)"), std::string::npos);
    const auto createdProject =
        Http("POST", baseUrl + "/mcp", mcpHeaders, ToolBody(4, "bn_local_project_create", R"({"name":"Created"})"));
    ASSERT_EQ(createdProject.status, 200) << createdProject.body;
    EXPECT_NE(createdProject.body.find("Created"), std::string::npos);
    auto createdProjectJson = Parse(createdProject.body);
    const std::string createdProjectReference =
        createdProjectJson["result"]["structuredContent"]["project"].GetString();
    const auto updatedProject = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(5, "bn_local_project_update", "{\"project\":\"" + project + "\",\"description\":\"Updated\"}"));
    ASSERT_EQ(updatedProject.status, 200) << updatedProject.body;
    const auto createdFolder = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(6, "bn_local_project_folder_create", "{\"project\":\"" + project + "\",\"name\":\"Folder\"}"));
    ASSERT_EQ(createdFolder.status, 200) << createdFolder.body;
    auto folderJson = Parse(createdFolder.body);
    const std::string folder = folderJson["result"]["structuredContent"]["path"].GetString();
    const auto importedBatch = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(
            42, "bn_local_project_file_import_batch",
            "{\"project\":\"" + project + "\",\"folder\":\"" + folder
                + "\",\"files\":[{\"source\":\"/usr/bin/false\","
                  "\"name\":\"imported-false\"},{\"source\":\"/usr/bin/true\","
                  "\"name\":\"imported-true\"}]}"));
    ASSERT_EQ(importedBatch.status, 200) << importedBatch.body;
    EXPECT_NE(importedBatch.body.find(R"("imported":2)"), std::string::npos) << importedBatch.body;
    const auto filteredImports = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(43, "bn_local_project_file_list",
                 "{\"project\":\"" + project + "\",\"folder\":\"" + folder + "\",\"query\":\"imported-true\"}"));
    ASSERT_EQ(filteredImports.status, 200) << filteredImports.body;
    EXPECT_NE(filteredImports.body.find(R"("total":1)"), std::string::npos) << filteredImports.body;
    const auto updatedFolder = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(7, "bn_local_project_folder_update",
                 "{\"project\":\"" + project + "\",\"path\":\"" + folder + "\",\"name\":\"Renamed\"}"));
    ASSERT_EQ(updatedFolder.status, 200) << updatedFolder.body;
    const auto updatedFile = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(8, "bn_local_project_file_update",
                 "{\"project\":\"" + project + "\",\"path\":\"" + filePath + "\",\"folder\":\"Renamed\"}"));
    ASSERT_EQ(updatedFile.status, 200) << updatedFile.body;
    auto updatedFileJson = Parse(updatedFile.body);
    const std::string projectPath = updatedFileJson["result"]["structuredContent"]["path"].GetString();

    const auto opened = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(9, "bn_project_file_open",
                 "{\"project\":\"" + project + "\",\"path\":\"" + projectPath + "\",\"reuseDatabase\":false}"));
    ASSERT_EQ(opened.status, 200) << opened.body;
    auto openedJson = Parse(opened.body);
    ASSERT_FALSE(openedJson.HasParseError());
    ASSERT_TRUE(openedJson.IsObject()) << opened.body;
    ASSERT_TRUE(openedJson.HasMember("result")) << opened.body;
    ASSERT_TRUE(openedJson["result"].HasMember("structuredContent")) << opened.body;
    const auto& openedContent = openedJson["result"]["structuredContent"];
    ASSERT_TRUE(openedContent.HasMember("openItem")) << opened.body;
    ASSERT_TRUE(openedContent["openItem"].IsString());
    ASSERT_TRUE(openedContent.HasMember("nextAction"));
    EXPECT_NE(
        std::string_view(openedContent["nextAction"].GetString()).find("bn_binary_view_open"), std::string_view::npos);
    const std::string openItem = openedContent["openItem"].GetString();
    ASSERT_GE(openedContent["binaryViews"].Size(), 2U);
    std::string binaryView;
    for (const auto& candidate : openedContent["binaryViews"].GetArray())
    {
        if (candidate["recommended"].GetBool())
            binaryView = candidate["binaryView"].GetString();
    }
    ASSERT_FALSE(binaryView.empty());

    const auto materialized = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(10, "bn_binary_view_open", "{\"binaryView\":\"" + binaryView + "\",\"analyze\":false}"));
    ASSERT_EQ(materialized.status, 200) << materialized.body;
    EXPECT_NE(materialized.body.find(R"("created":true)"), std::string::npos);
    const auto analyzed = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(11, "bn_analysis_update_and_wait", "{\"binaryView\":\"" + binaryView + "\"}"));
    ASSERT_EQ(analyzed.status, 200) << analyzed.body;
    EXPECT_NE(analyzed.body.find(R"("state":"complete")"), std::string::npos) << analyzed.body;
    const auto status = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(12, "bn_analysis_status", "{\"binaryView\":\"" + binaryView + "\"}"));
    ASSERT_EQ(status.status, 200) << status.body;
    EXPECT_NE(status.body.find(R"("hasView":true)"), std::string::npos);
    EXPECT_NE(status.body.find(R"("state":"complete")"), std::string::npos);
    const auto functions = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(60, "bn_function_list", "{\"binaryView\":\"" + binaryView + "\",\"limit\":5}"));
    ASSERT_EQ(functions.status, 200) << functions.body;
    auto functionsJson = Parse(functions.body);
    const auto& functionRows = functionsJson["result"]["structuredContent"]["functions"];
    ASSERT_FALSE(functionRows.Empty()) << functions.body;
    EXPECT_EQ(functionRows[0].MemberCount(), 3U);
    const std::string function = functionRows[0]["address"].GetString();
    const auto functionInfo = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(61, "bn_function_info", "{\"binaryView\":\"" + binaryView + "\",\"function\":\"" + function + "\"}"));
    ASSERT_EQ(functionInfo.status, 200) << functionInfo.body;
    EXPECT_NE(functionInfo.body.find(R"("basicBlocks")"), std::string::npos);
    const auto decompiled = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(62, "bn_function_decompile",
                 "{\"binaryView\":\"" + binaryView + "\",\"function\":\"" + function + "\",\"limit\":10}"));
    ASSERT_EQ(decompiled.status, 200) << decompiled.body;
    EXPECT_NE(decompiled.body.find(R"("language":"Pseudo C")"), std::string::npos);
    const auto il = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(
            63, "bn_function_il",
            "{\"binaryView\":\"" + binaryView + "\",\"function\":\"" + function
                + "\",\"level\":\"hlil\",\"ssa\":true,\"limit\":10}"));
    ASSERT_EQ(il.status, 200) << il.body;
    EXPECT_NE(il.body.find(R"("level":"hlil")"), std::string::npos);
    const auto strings = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(64, "bn_string_list", "{\"binaryView\":\"" + binaryView + "\",\"limit\":5}"));
    ASSERT_EQ(strings.status, 200) << strings.body;
    EXPECT_NE(strings.body.find(R"("strings")"), std::string::npos);
    const auto symbols = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(65, "bn_symbol_list", "{\"binaryView\":\"" + binaryView + "\",\"limit\":5}"));
    ASSERT_EQ(symbols.status, 200) << symbols.body;
    EXPECT_NE(symbols.body.find(R"("symbols")"), std::string::npos);
    const auto saved = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(13, "bn_binary_view_save", "{\"binaryView\":\"" + binaryView + "\"}"));
    ASSERT_EQ(saved.status, 200) << saved.body;
    EXPECT_NE(saved.body.find(R"("createdDatabase":true)"), std::string::npos) << saved.body;
    const auto committedFiles = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(14, "bn_local_project_file_list", "{\"project\":\"" + project + "\"}"));
    ASSERT_EQ(committedFiles.status, 200) << committedFiles.body;
    EXPECT_NE(committedFiles.body.find("true.bndb"), std::string::npos) << committedFiles.body;
    const auto closed = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(15, "bn_open_item_close", "{\"openItem\":\"" + openItem + "\",\"save\":\"prompt\"}"));
    ASSERT_EQ(closed.status, 200) << closed.body;
    EXPECT_NE(closed.body.find(R"("closed":true)"), std::string::npos);
    const auto deletedFile = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(16, "bn_local_project_file_delete",
                 "{\"project\":\"" + project + "\",\"path\":\"" + projectPath + "\",\"delete\":true}"));
    ASSERT_EQ(deletedFile.status, 200) << deletedFile.body;
    const auto deletedFolder = Http(
        "POST", baseUrl + "/mcp", mcpHeaders,
        ToolBody(17, "bn_local_project_folder_delete",
                 "{\"project\":\"" + project + "\",\"path\":\"Renamed\",\"recursive\":true}"));
    ASSERT_EQ(deletedFolder.status, 200) << deletedFolder.body;
    const auto deletedProject = Http(
        "DELETE", baseUrl + "/portal/api/projects/" + createdProjectReference,
        {"Content-Type: application/json", basic}, R"({"delete":true})");
    ASSERT_EQ(deletedProject.status, 200) << deletedProject.body;
    EXPECT_NE(deletedProject.body.find(R"("deleted":true)"), std::string::npos);
}
