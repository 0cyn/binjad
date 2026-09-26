#include "binjad/mcp/Foundation.hpp"
#include "binjad/session/OpenItemRegistry.hpp"
#include "binjad/session/JobRegistry.hpp"

#include <rapidjsonwrapper.h>

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <unordered_set>

namespace
{
using namespace std::chrono_literals;

binjad::mcp::ValidatedRequest Request(
    binjad::mcp::ProtocolVersion version, std::string method, std::string name = {},
    std::string uri = {}, std::string params = "{}")
{
    binjad::mcp::ValidatedRequest request;
    request.version = version;
    request.id = std::uint64_t{1};
    request.method = std::move(method);
    request.name = std::move(name);
    request.uri = std::move(uri);
    request.paramsJson = std::move(params);
    return request;
}

binjad::security::TokenRecord Principal()
{
    return {std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
}

binjad::security::TokenRecord UserPrincipal()
{
    auto principal = Principal();
    principal.role = binjad::security::TokenRole::User;
    return principal;
}

std::string StructuredSession(const std::string& response)
{
    rapidjson::Document document;
    document.Parse(response.data(), response.size());
    if (document.HasParseError() || !document.IsObject())
        return {};
    const auto& value = document["result"]["structuredContent"]["analysisSession"];
    return value.IsString() ? std::string(value.GetString(), value.GetStringLength()) : std::string{};
}


const rapidjson::Value* FindTool(const rapidjson::Document& document, std::string_view name)
{
    for (const auto& tool : document["result"]["tools"].GetArray())
    {
        if (std::string_view(tool["name"].GetString(), tool["name"].GetStringLength()) == name)
            return &tool;
    }
    return nullptr;
}
}

TEST(McpFoundationTest, ListsRevisionAppropriateSessionTools)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto modern = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    ASSERT_TRUE(modern.handled);
    EXPECT_NE(modern.body.find("bn_analysis_session_create"), std::string::npos);
    EXPECT_NE(modern.body.find("bn_compute_status"), std::string::npos);
    EXPECT_EQ(modern.body.find("bn_local_project_register"), std::string::npos);
    EXPECT_NE(modern.body.find("bn_local_project_file_import_batch"), std::string::npos);
    EXPECT_NE(modern.body.find("bn_local_project_directory_import"), std::string::npos);
    EXPECT_NE(modern.body.find("bn_local_project_relocate"), std::string::npos);
    const auto user = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        UserPrincipal(), {}, 1);
    EXPECT_EQ(user.body.find("bn_local_project_register"), std::string::npos);
    EXPECT_EQ(user.body.find("bn_local_project_file_import_batch"), std::string::npos);
    const auto legacy = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2025_03_26, "tools/list"),
        Principal(), {}, 1);
    EXPECT_EQ(legacy.body.find("bn_analysis_session_create"), std::string::npos);
    EXPECT_EQ(legacy.body.find("bn_analysis_session_close"), std::string::npos);
    EXPECT_NE(legacy.body.find("bn_analysis_session_list"), std::string::npos);
    rapidjson::Document modernDocument;
    modernDocument.Parse(modern.body.data(), modern.body.size());
    ASSERT_FALSE(modernDocument.HasParseError());
    const auto* sessionInfo = FindTool(modernDocument, "bn_analysis_session_info");
    ASSERT_NE(sessionInfo, nullptr);
    EXPECT_FALSE((*sessionInfo)["inputSchema"].HasMember("required"));
}

TEST(McpFoundationTest, AdvertisesOnlyEnabledToolPacks)
{
    binjad::Config config;
    config.tools.kernelCache = false;
    config.tools.sharedCache = false;
    config.tools.debugger = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation disabled(config, sessions, "0.1.0");
    const auto disabledResponse = disabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    EXPECT_EQ(disabledResponse.body.find("bn_kernel_cache_image_list"), std::string::npos);
    EXPECT_EQ(disabledResponse.body.find("bn_shared_cache_image_list"), std::string::npos);
    EXPECT_EQ(disabledResponse.body.find("bn_debugger_status"), std::string::npos);

    config.tools.kernelCache = true;
    config.tools.sharedCache = true;
    config.tools.debugger = true;
    binjad::mcp::Foundation enabled(config, sessions, "0.1.0");
    const auto enabledResponse = enabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    EXPECT_NE(enabledResponse.body.find("bn_kernel_cache_image_list"), std::string::npos);
    EXPECT_NE(enabledResponse.body.find("bn_shared_cache_region_load"), std::string::npos);
    EXPECT_NE(enabledResponse.body.find("bn_debugger_status"), std::string::npos);
    const auto userResponse = enabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        UserPrincipal(), {}, 1);
    EXPECT_EQ(userResponse.body.find("bn_debugger_status"), std::string::npos);
    EXPECT_NE(userResponse.body.find("bn_kernel_cache_image_list"), std::string::npos);
}

TEST(McpFoundationTest, DisabledExtendedPackKeepsCoreWorkflowAndRejectsDirectCalls)
{
    binjad::Config config;
    config.tools.functionAnalysis = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto principal = Principal();
    const auto listed = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        principal, {}, 1);
    EXPECT_NE(listed.body.find("bn_function_info"), std::string::npos);
    EXPECT_NE(listed.body.find("bn_function_decompile"), std::string::npos);
    EXPECT_NE(listed.body.find("bn_variable_list"), std::string::npos);
    EXPECT_EQ(listed.body.find("bn_function_il"), std::string::npos);
    EXPECT_EQ(listed.body.find("bn_function_callers"), std::string::npos);

    const auto called = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_function_il", {},
        R"({"arguments":{"binaryView":"view","function":"main"}})"),
        principal, {}, 1);
    ASSERT_TRUE(called.error.has_value());
    EXPECT_EQ(called.error->message, "unknown tool");
}

TEST(McpFoundationTest, ToolPacksCanBeReconfiguredWhileRunning)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");

    const auto enabled = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    EXPECT_NE(enabled.body.find("bn_function_il"), std::string::npos);

    auto tools = config.tools;
    tools.functionAnalysis = false;
    foundation.SetToolConfig(tools);
    const auto disabled = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    EXPECT_EQ(disabled.body.find("bn_function_il"), std::string::npos);
    EXPECT_EQ(foundation.ContextDocumentation(binjad::mcp::ProtocolVersion::V2026_07_28,
                  binjad::security::TokenRole::Admin, "binjad")
                  .find("bn_function_il"),
        std::string::npos);
}

TEST(McpFoundationTest, CoreWorkflowIsCompleteAndContainsNoExtendedTools)
{
    binjad::Config config;
    config.tools.projectManagement = false;
    config.tools.functionAnalysis = false;
    config.tools.binaryData = false;
    config.tools.search = false;
    config.tools.types = false;
    config.tools.annotations = false;
    config.tools.binaryEditing = false;
    config.tools.history = false;
    config.tools.headerParsing = false;
    config.tools.urlGeneration = false;
    config.tools.diffing = false;
    config.tools.kernelCache = false;
    config.tools.sharedCache = false;
    config.tools.debugger = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto response = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    rapidjson::Document document;
    document.Parse(response.body.data(), response.body.size());
    ASSERT_FALSE(document.HasParseError());

    const std::unordered_set<std::string_view> expected{
        "bn_analysis_session_create", "bn_analysis_session_close",
        "bn_analysis_session_list", "bn_analysis_session_info", "bn_compute_status",
        "bn_open_item_open", "bn_local_project_list", "bn_local_project_info",
        "bn_local_project_file_list", "bn_local_project_create", "bn_project_file_open",
        "bn_open_item_list", "bn_open_item_close", "bn_binary_view_list",
        "bn_binary_view_load_settings", "bn_binary_view_open", "bn_analysis_status",
        "bn_analysis_update", "bn_analysis_update_and_wait", "bn_analysis_update_async",
        "bn_analysis_abort", "bn_binary_view_save", "bn_binary_view_save_async",
        "bn_upload_get_url", "bn_upload_commit", "bn_upload_list", "bn_upload_cancel",
        "bn_function_list", "bn_function_info", "bn_function_disassembly",
        "bn_function_decompile", "bn_string_list", "bn_string_at", "bn_symbol_list",
        "bn_symbol_list_at", "bn_memory_read", "bn_data_at", "bn_job_list",
        "bn_job_info", "bn_job_result", "bn_job_cancel"};
    const auto& advertised = document["result"]["tools"];
    ASSERT_EQ(advertised.Size(), expected.size());
    for (const auto& tool : advertised.GetArray())
        EXPECT_TRUE(expected.contains(std::string_view(tool["name"].GetString(),
            tool["name"].GetStringLength()))) << tool["name"].GetString();
}

TEST(McpFoundationTest, GatesHeaderParsingAndOutsideRootProjectRegistration)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation defaults(config, sessions, "0.1.0");
    const auto principal = Principal();
    const auto listed = defaults.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), principal, {}, 1);
    for (const auto* name : {"bn_binary_header_info", "bn_linked_library_list",
             "bn_macho_load_command_list", "bn_elf_program_header_list",
             "bn_elf_dynamic_entry_list", "bn_pe_data_directory_list"})
        EXPECT_NE(listed.body.find(name), std::string::npos) << name;
    EXPECT_EQ(listed.body.find("bn_local_project_register"), std::string::npos);
    const auto disabledRegistration = defaults.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_local_project_register", {},
        R"({"arguments":{"path":"/tmp/Outside.bnpr"}})"), principal, {}, 1);
    EXPECT_NE(disabledRegistration.body.find("outside-root project registration is disabled"), std::string::npos);

    config.tools.headerParsing = false;
    config.projects.allowProjectRegistration = true;
    binjad::mcp::Foundation configured(config, sessions, "0.1.0");
    const auto configuredList = configured.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), principal, {}, 1);
    EXPECT_EQ(configuredList.body.find("bn_binary_header_info"), std::string::npos);
    EXPECT_NE(configuredList.body.find("bn_local_project_register"), std::string::npos);
}

TEST(McpFoundationTest, GatesDiffingPackAndAdvertisesStrictPairSchemas)
{
    binjad::Config config;
    config.tools.diffing = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation disabled(config, sessions, "0.1.0");
    const auto hidden = disabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), Principal(), {}, 1);
    EXPECT_EQ(hidden.body.find("bn_diff_match_list"), std::string::npos);

    config.tools.diffing = true;
    binjad::mcp::Foundation enabled(config, sessions, "0.1.0");
    const auto listed = enabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), Principal(), {}, 1);
    rapidjson::Document document;
    document.Parse(listed.body.data(), listed.body.size());
    ASSERT_FALSE(document.HasParseError());
    for (const auto* name : {"bn_diff_run_view", "bn_diff_run_project", "bn_diff_summary",
             "bn_diff_match_list", "bn_diff_primary_unmatched_list",
             "bn_diff_secondary_unmatched_list", "bn_diff_function_matches",
             "bn_diff_match_info", "bn_diff_port_name_from_secondary",
             "bn_diff_apply_from_secondary", "bn_diff_port_names_from_secondary",
             })
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    EXPECT_EQ(FindTool(document, "bn_diff_release"), nullptr);
    const auto removed = enabled.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_diff_release", {},
        R"({"arguments":{"primary":"primary","secondary":"secondary"}})"),
        Principal(), {}, 1);
    ASSERT_TRUE(removed.error.has_value());
    EXPECT_EQ(removed.error->message, "unknown tool");
    const auto* runProject = FindTool(document, "bn_diff_run_project");
    ASSERT_NE(runProject, nullptr);
    EXPECT_EQ((*runProject)["inputSchema"]["required"].Size(), 3U);
}

TEST(McpFoundationTest, GeneratesDocumentedBinaryNinjaUrls)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::OpenItemRegistry openItems(references);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0", &openItems);
    const auto principal = Principal();
    const auto current = sessions.Create(principal.id, 1,
        binjad::session::AnalysisSessionRegistry::Clock::time_point{});
    ASSERT_TRUE(current.session);
    const auto pathItem = openItems.Create(principal.id, current.session->reference,
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/My file#one.bndb", {}, {{"Raw", true}});
    ASSERT_TRUE(pathItem.openItem);
    const auto projectItem = openItems.Create(principal.id, current.session->reference,
        binjad::session::OpenItemSourceKind::LocalProject, "folder/input.bndb", "ProjectRef", {{"Raw", true}});
    ASSERT_TRUE(projectItem.openItem);

    const auto listed = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), principal, {}, 1);
    rapidjson::Document discovery;
    discovery.Parse(listed.body.data(), listed.body.size());
    ASSERT_FALSE(discovery.HasParseError());
    for (const auto* name : {"bn_url_open_item", "bn_url_project_file", "bn_url_remote_file", "bn_url_navigate"})
        ASSERT_NE(FindTool(discovery, name), nullptr) << name;
    const auto* projectTool = FindTool(discovery, "bn_url_project_file");
    ASSERT_NE(projectTool, nullptr);
    ASSERT_TRUE((*projectTool)["inputSchema"]["required"].IsArray());
    EXPECT_EQ((*projectTool)["inputSchema"]["required"].Size(), 2U);
    const auto& savedProperty = (*projectTool)["inputSchema"]["properties"]["updated_bndb_has_been_saved"];
    ASSERT_TRUE(savedProperty["enum"].IsArray());
    ASSERT_EQ(savedProperty["enum"].Size(), 1U);
    EXPECT_TRUE(savedProperty["enum"][0].GetBool());

    const auto local = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_open_item", {},
        std::string(R"({"arguments":{"openItem":")") + pathItem.openItem->reference
            + R"(","expr":"main + 0x10"}})"),
        principal, current.session, {}, 1);
    EXPECT_FALSE(local.error.has_value());
    EXPECT_NE(local.body.find("binaryninja:///tmp/My%20file%23one.bndb?expr=main%20%2B%200x10"),
        std::string::npos);
    EXPECT_NE(local.body.find(R"("confirmationRequired":true)"), std::string::npos);

    const auto remote = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_remote_file", {},
        R"({"arguments":{"url":"https://example.com/a%20b?token=x#part","expr":".text+6b"}})"),
        principal, current.session, {}, 1);
    EXPECT_FALSE(remote.error.has_value());
    EXPECT_NE(remote.body.find(
        "binaryninja:https://example.com/a%20b?token=x&expr=.text%2B6b#part"), std::string::npos);

    const auto navigate = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_navigate", {},
        R"({"arguments":{"expr":"[.data + 400]"}})"),
        principal, current.session, {}, 1);
    EXPECT_FALSE(navigate.error.has_value());
    EXPECT_NE(navigate.body.find("binaryninja://?expr=%5B.data%20%2B%20400%5D"), std::string::npos);
    EXPECT_NE(navigate.body.find(R"("confirmationRequired":false)"), std::string::npos);

    const auto project = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_open_item", {},
        std::string(R"({"arguments":{"openItem":")") + projectItem.openItem->reference + R"("}})"),
        principal, current.session, {}, 1);
    EXPECT_NE(project.body.find("use bn_url_project_file instead"), std::string::npos);
    EXPECT_NE(project.body.find(R"("isError":true)"), std::string::npos);

    const auto falseAcknowledgement = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_project_file", {},
        std::string(R"({"arguments":{"openItem":")") + projectItem.openItem->reference
            + R"(","updated_bndb_has_been_saved":false}})"),
        principal, current.session, {}, 1);
    ASSERT_TRUE(falseAcknowledgement.error.has_value());
    EXPECT_EQ(falseAcknowledgement.error->code, -32602);

    auto otherPrincipal = UserPrincipal();
    otherPrincipal.id = std::string(64, 'c');
    const auto unauthorized = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_open_item", {},
        std::string(R"({"arguments":{"openItem":")") + pathItem.openItem->reference + R"("}})"),
        otherPrincipal, current.session, {}, 1);
    EXPECT_NE(unauthorized.body.find("open item not found"), std::string::npos);
    EXPECT_NE(unauthorized.body.find(R"("isError":true)"), std::string::npos);

    const auto invalidRemote = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_remote_file", {},
        R"({"arguments":{"url":"ssh://example.com/input"}})"),
        principal, current.session, {}, 1);
    EXPECT_NE(invalidRemote.body.find("url scheme must be http, https, or file"), std::string::npos);
    EXPECT_NE(invalidRemote.body.find(R"("isError":true)"), std::string::npos);
}

TEST(McpFoundationTest, GatesUrlGenerationPack)
{
    binjad::Config config;
    config.tools.urlGeneration = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto principal = Principal();
    const auto listed = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"), principal, {}, 1);
    EXPECT_EQ(listed.body.find("bn_url_navigate"), std::string::npos);
    const auto called = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_url_navigate", {},
        R"({"arguments":{"expr":"main"}})"), principal, {}, 1);
    ASSERT_TRUE(called.error.has_value());
    EXPECT_EQ(called.error->message, "unknown tool");
}

TEST(McpFoundationTest, ActiveJobsAdvertiseBoundedPollingAndResultConsumption)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    binjad::mcp::Foundation foundation(
        config, sessions, "0.1.0", nullptr, nullptr, &jobs);
    const auto principal = Principal();
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point{};
    const auto current = sessions.Create(principal.id, 1, now);
    ASSERT_TRUE(current.session);
    const auto created = jobs.Create(principal.id, current.session->reference, {},
        "analysis_update", 1, now);
    ASSERT_TRUE(created.job);
    ASSERT_TRUE(jobs.Start(principal.id, created.job->reference, 1));

    const auto info = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", "bn_job_info", {},
        "{\"arguments\":{\"job\":\"" + created.job->reference + "\"}}"),
        principal, current.session, now, 1);
    EXPECT_NE(info.body.find(R"("pollAfterMilliseconds":10000)"), std::string::npos);
    EXPECT_NE(info.body.find("bn_job_result exactly once"), std::string::npos);
    EXPECT_NE(info.body.find("Avoid polling bn_analysis_status"), std::string::npos);
}


TEST(McpFoundationTest, AdvertisesStrictAnalysisToolSchemas)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto response = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        Principal(), {}, 1);
    rapidjson::Document document;
    document.Parse(response.body.data(), response.body.size());
    ASSERT_FALSE(document.HasParseError());
    ASSERT_TRUE(document["result"]["tools"].IsArray());

    std::unordered_set<std::string> names;
    for (const auto& tool : document["result"]["tools"].GetArray())
        EXPECT_TRUE(names.emplace(tool["name"].GetString()).second);
    for (const auto* name : {"bn_function_list", "bn_function_info", "bn_function_create",
            "bn_function_callers", "bn_function_callees", "bn_function_disassembly",
            "bn_function_decompile", "bn_function_il", "bn_function_stack_layout",
            "bn_variable_list", "bn_calling_convention_list", "bn_function_xrefs_from",
            "bn_function_xrefs_to", "bn_string_list", "bn_string_at", "bn_symbol_list",
            "bn_symbol_list_at", "bn_import_list", "bn_export_list",
            "bn_entry_point_list", "bn_entry_point_add", "bn_section_list", "bn_segment_list", "bn_memory_read",
            "bn_data_variable_list", "bn_data_at", "bn_relocation_list",
            "bn_data_xrefs_from", "bn_data_xrefs_to", "bn_comment_get", "bn_comment_set",
            "bn_comment_delete", "bn_symbol_define", "bn_symbol_rename",
            "bn_symbol_undefine", "bn_function_prototype_set", "bn_calling_convention_set",
            "bn_variable_rename", "bn_variable_set_type", "bn_type_list", "bn_type_info",
            "bn_type_parse", "bn_type_define", "bn_type_struct_create",
            "bn_type_struct_modify", "bn_type_union_create", "bn_type_union_modify",
            "bn_type_enum_create", "bn_type_enum_modify", "bn_type_delete", "bn_type_rename",
            "bn_type_xrefs_from", "bn_type_xrefs_to", "bn_data_variable_define",
            "bn_data_variable_undefine", "bn_section_create", "bn_section_delete",
            "bn_section_modify", "bn_binary_header_info", "bn_linked_library_list",
            "bn_macho_load_command_list", "bn_elf_program_header_list",
            "bn_elf_dynamic_entry_list", "bn_pe_data_directory_list",
            "bn_local_project_root_list", "bn_local_project_directory_import",
            "bn_local_project_relocate"})
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_function_basic_blocks", "bn_function_complexity",
            "bn_function_prototype_get", "bn_function_search"})
        EXPECT_EQ(FindTool(document, name), nullptr) << name;

    const auto* il = FindTool(document, "bn_function_il");
    ASSERT_NE(il, nullptr);
    const auto& levels = (*il)["inputSchema"]["properties"]["level"]["enum"];
    ASSERT_TRUE(levels.IsArray());
    EXPECT_EQ(levels.Size(), 3U);
    EXPECT_EQ(std::string(levels[0].GetString()), "llil");
    EXPECT_EQ(std::string(levels[1].GetString()), "mlil");
    EXPECT_EQ(std::string(levels[2].GetString()), "hlil");

    const auto* strings = FindTool(document, "bn_string_list");
    ASSERT_NE(strings, nullptr);
    const auto& stringProperties = (*strings)["inputSchema"]["properties"];
    EXPECT_FALSE(stringProperties.HasMember("previewBytes"));
    EXPECT_TRUE(stringProperties.HasMember("query"));
    const auto& stringRequired = (*strings)["inputSchema"]["required"];
    ASSERT_EQ(stringRequired.Size(), 1U);
    EXPECT_EQ(std::string(stringRequired[0].GetString()), "binaryView");
    const auto* stringAt = FindTool(document, "bn_string_at");
    ASSERT_NE(stringAt, nullptr);
    const auto& stringAtRequired = (*stringAt)["inputSchema"]["required"];
    ASSERT_EQ(stringAtRequired.Size(), 2U);
    EXPECT_EQ(std::string(stringAtRequired[0].GetString()), "binaryView");
    EXPECT_EQ(std::string(stringAtRequired[1].GetString()), "address");
    EXPECT_EQ((*stringAt)["inputSchema"]["properties"]["limit"]["maximum"].GetUint(),
        65536U);

    const auto* functionInfo = FindTool(document, "bn_function_info");
    ASSERT_NE(functionInfo, nullptr);
    const auto& functionRequired = (*functionInfo)["inputSchema"]["required"];
    ASSERT_EQ(functionRequired.Size(), 2U);
    EXPECT_EQ(std::string(functionRequired[0].GetString()), "binaryView");
    EXPECT_EQ(std::string(functionRequired[1].GetString()), "function");
    for (const auto* name : {"bn_function_create", "bn_entry_point_add"})
    {
        const auto* tool = FindTool(document, name);
        ASSERT_NE(tool, nullptr);
        const auto& required = (*tool)["inputSchema"]["required"];
        ASSERT_EQ(required.Size(), 2U);
        EXPECT_EQ(std::string(required[0].GetString()), "binaryView");
        EXPECT_EQ(std::string(required[1].GetString()), "address");
    }
    const auto* fileUpdate = FindTool(document, "bn_local_project_file_update");
    ASSERT_NE(fileUpdate, nullptr);
    EXPECT_NE(std::string_view((*fileUpdate)["description"].GetString()).find("clear"),
        std::string_view::npos);
    EXPECT_NE(std::string_view((*fileUpdate)["inputSchema"]["properties"]
        ["description"]["description"].GetString()).find("empty string"),
        std::string_view::npos);
    EXPECT_FALSE((*fileUpdate)["inputSchema"]["properties"].HasMember("file"));
    const auto& fileUpdateRequired = (*fileUpdate)["inputSchema"]["required"];
    ASSERT_EQ(fileUpdateRequired.Size(), 2U);
    EXPECT_EQ(std::string_view(fileUpdateRequired[0].GetString()), "project");
    EXPECT_EQ(std::string_view(fileUpdateRequired[1].GetString()), "path");
    const auto* textRead = FindTool(document, "bn_project_text_read");
    const auto* jsonRead = FindTool(document, "bn_project_json_read");
    ASSERT_NE(textRead, nullptr);
    ASSERT_NE(jsonRead, nullptr);
    EXPECT_EQ((*textRead)["inputSchema"]["properties"]["limit"]["maximum"].GetUint(),
        200U);
    EXPECT_TRUE((*textRead)["inputSchema"]["properties"].HasMember("query"));
    EXPECT_TRUE((*jsonRead)["inputSchema"]["properties"].HasMember("pointer"));
    for (const auto* name : {"bn_comment_list", "bn_comment_search", "bn_memory_search",
             "bn_instruction_search", "bn_il_search", "bn_constant_search",
             "bn_project_analysis_search"})
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_segment_create", "bn_segment_modify", "bn_segment_delete",
             "bn_binary_view_rebase", "bn_memory_map_preview", "bn_function_delete",
             "bn_string_define", "bn_string_undefine"})
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_transaction_begin", "bn_transaction_commit",
             "bn_transaction_rollback", "bn_undo", "bn_redo"})
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_bookmark_create", "bn_bookmark_list",
             "bn_bookmark_delete", "bn_tag_create", "bn_tag_list", "bn_tag_delete",
             "bn_metadata_get", "bn_metadata_set", "bn_metadata_delete"})
        EXPECT_NE(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_symbol_import", "bn_symbol_export"})
        EXPECT_EQ(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_snapshot_create", "bn_snapshot_restore",
             "bn_snapshot_list", "bn_snapshot_diff"})
        EXPECT_EQ(FindTool(document, name), nullptr) << name;
    for (const auto* name : {"bn_entry_point_delete", "bn_relocation_define",
             "bn_relocation_modify", "bn_relocation_delete"})
        EXPECT_EQ(FindTool(document, name), nullptr) << name;
}

TEST(McpFoundationTest, ContextDocumentationEmbedsExactDiscoveryPayload)
{
    binjad::Config config;
    config.tools.kernelCache = true;
    config.tools.debugger = true;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto expected = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/list"),
        UserPrincipal(), {}, 1);
    const auto context = foundation.ContextDocumentation(
        binjad::mcp::ProtocolVersion::V2026_07_28,
        binjad::security::TokenRole::User, "binjad");
    rapidjson::Document document;
    document.Parse(context.data(), context.size());
    ASSERT_FALSE(document.HasParseError());
    ASSERT_TRUE(document["mcpWire"].IsArray());
    const rapidjson::Value* tools = nullptr;
    for (const auto& item : document["mcpWire"].GetArray())
    {
        if (std::string_view(item["method"].GetString()) == "tools/list")
            tools = &item;
    }
    ASSERT_NE(tools, nullptr);
    EXPECT_EQ(std::string((*tools)["payload"].GetString(),
                  (*tools)["payload"].GetStringLength()), expected.body);
    const auto& projected = document["openCodeProjection"]["tools"];
    ASSERT_TRUE(projected.IsArray());
    EXPECT_NE(projected.Size(), 0U);
    for (const auto& tool : projected.GetArray())
        EXPECT_TRUE(std::string_view(tool["name"].GetString()).starts_with("binjad_bn_"));
    EXPECT_EQ(context.find("bn_debugger_status"), std::string::npos);
    EXPECT_NE(context.find("bn_kernel_cache_image_list"), std::string::npos);
}

TEST(McpFoundationTest, ToolDocumentationUsesAdvertisedDefinitionsAndFailureContracts)
{
    binjad::Config config;
    config.tools.debugger = false;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto documentation = foundation.ToolDocumentation(
        binjad::mcp::ProtocolVersion::V2026_07_28,
        binjad::security::TokenRole::Admin);
    rapidjson::Document document;
    document.Parse(documentation.data(), documentation.size());
    ASSERT_FALSE(document.HasParseError());
    ASSERT_TRUE(document["failureContracts"].HasMember("invalid_arguments"));
    ASSERT_TRUE(document["failureContracts"].HasMember("service_failure"));
    ASSERT_TRUE(document["tools"].IsArray());
    ASSERT_NE(document["tools"].Size(), 0U);
    EXPECT_GT(document["totalCount"].GetUint64(), document["availableCount"].GetUint64());
    bool foundDisabledDebugger = false;
    for (const auto& tool : document["tools"].GetArray())
    {
        EXPECT_TRUE(tool["name"].IsString());
        EXPECT_TRUE(tool["pack"].IsString());
        EXPECT_TRUE(tool["description"].IsString());
        EXPECT_TRUE(tool["inputSchema"].IsObject());
        EXPECT_TRUE(tool["failureModes"].IsArray());
        EXPECT_GE(tool["failureModes"].Size(), 3U);
        for (const auto& failure : tool["failureModes"].GetArray())
            EXPECT_TRUE(document["failureContracts"].HasMember(failure.GetString()));
        if (std::string_view(tool["name"].GetString()) == "bn_debugger_status")
        {
            foundDisabledDebugger = true;
            EXPECT_FALSE(tool["available"].GetBool());
            EXPECT_NE(std::string_view(tool["availability"].GetString()).find("disabled"),
                std::string_view::npos);
        }
    }
    EXPECT_TRUE(foundDisabledDebugger);
}


TEST(McpFoundationTest, RejectsMissingAnalysisToolTargets)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto principal = Principal();
    const auto current = sessions.Create(principal.id, 1,
        binjad::session::AnalysisSessionRegistry::Clock::time_point{});
    ASSERT_TRUE(current.session);
    for (const auto* name : {"bn_function_list", "bn_function_info", "bn_function_create",
            "bn_function_callers", "bn_function_callees", "bn_function_disassembly",
            "bn_function_decompile", "bn_function_il", "bn_function_stack_layout",
            "bn_variable_list", "bn_calling_convention_list", "bn_function_xrefs_from",
            "bn_function_xrefs_to", "bn_string_list", "bn_string_at", "bn_symbol_list",
            "bn_symbol_list_at", "bn_import_list", "bn_export_list",
            "bn_entry_point_list", "bn_entry_point_add", "bn_section_list", "bn_segment_list", "bn_memory_read",
            "bn_data_variable_list", "bn_data_at", "bn_relocation_list",
            "bn_data_xrefs_from", "bn_data_xrefs_to", "bn_comment_get", "bn_comment_set",
            "bn_comment_delete", "bn_symbol_define", "bn_symbol_rename",
            "bn_symbol_undefine", "bn_function_prototype_set", "bn_calling_convention_set",
            "bn_variable_rename", "bn_variable_set_type", "bn_type_list", "bn_type_info",
            "bn_type_parse", "bn_type_define", "bn_type_struct_create",
            "bn_type_struct_modify", "bn_type_union_create", "bn_type_union_modify",
            "bn_type_enum_create", "bn_type_enum_modify", "bn_type_delete", "bn_type_rename",
            "bn_type_xrefs_from", "bn_type_xrefs_to", "bn_data_variable_define",
            "bn_data_variable_undefine", "bn_section_create", "bn_section_delete",
            "bn_section_modify", "bn_binary_header_info", "bn_linked_library_list",
            "bn_macho_load_command_list", "bn_elf_program_header_list",
            "bn_elf_dynamic_entry_list", "bn_pe_data_directory_list"})
    {
        const auto result = foundation.Handle(Request(
            binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call", name, {},
            R"({"arguments":{}})"), principal, current.session, {}, 1);
        ASSERT_TRUE(result.error.has_value()) << name;
        EXPECT_EQ(result.error->code, -32602) << name;
        EXPECT_EQ(result.error->httpStatus, 400) << name;
    }
}


TEST(McpFoundationTest, LegacyAnalysisSchemaErrorsRemainHttpSuccessful)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto result = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2025_03_26, "tools/call", "bn_string_at", {},
        R"({"arguments":{"binaryView":"ViewOnly"}})"), Principal(), {}, 1);
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(result.httpStatus, 200);
    EXPECT_EQ(result.error->code, -32602);
    EXPECT_EQ(result.error->httpStatus, 200);
}

TEST(McpFoundationTest, CreatesListsInspectsAndClosesModernSession)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto principal = Principal();
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    const auto created = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_analysis_session_create", {},
        R"({"name":"bn_analysis_session_create","arguments":{}})"),
        principal, now, 10);
    ASSERT_TRUE(created.handled);
    const auto reference = StructuredSession(created.body);
    ASSERT_TRUE(binjad::reference::IsFriendlyReference(reference));
    EXPECT_NE(created.body.find("structuredContent"), std::string::npos);
    EXPECT_NE(created.body.find(R"("type":"text")"), std::string::npos);

    const auto targetParams = std::string(R"({"arguments":{"analysisSession":")") +
        reference + "\"}}";
    const auto info = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_analysis_session_info", {}, targetParams), principal, now, 10);
    EXPECT_NE(info.body.find(reference), std::string::npos);
    const auto list = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_analysis_session_list", {}, R"({"arguments":{"offset":0,"limit":10}})"),
        principal, now, 10);
    EXPECT_NE(list.body.find(reference), std::string::npos);
    const auto closed = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_analysis_session_close", {}, targetParams), principal, now, 10);
    EXPECT_FALSE(closed.error.has_value());
    EXPECT_EQ(sessions.Size(), 0U);
}

TEST(McpFoundationTest, ExposesComputeSessionAndOpenItemResources)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::OpenItemRegistry openItems(references);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0", &openItems);
    const auto principal = Principal();
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point{};
    const auto created = sessions.Create(principal.id, 10, now);
    ASSERT_TRUE(created.session);
    const auto opened = openItems.Create(principal.id, created.session->reference,
        binjad::session::OpenItemSourceKind::ArbitraryPath, "/tmp/input", {},
        {{"Raw", false}, {"Mapped", true,
            R"({"loader":{"settings":{"platform":{"key":"loader.platform","type":"string"}}}})"}});
    ASSERT_TRUE(opened.openItem);
    ASSERT_EQ(opened.openItem->binaryViews.size(), 2U);
    EXPECT_FALSE(opened.openItem->binaryViews[1].loadSettingsSchemaJson.empty());
    const auto catalog = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "resources/list"),
        principal, now, 10);
    EXPECT_NE(catalog.body.find("binjad://compute"), std::string::npos);
    EXPECT_NE(catalog.body.find("binjad://analysis-sessions"), std::string::npos);
    EXPECT_NE(catalog.body.find("binjad://open-items"), std::string::npos);
    EXPECT_NE(catalog.body.find("binjad://docs"), std::string::npos);
    EXPECT_NE(catalog.body.find("text/markdown"), std::string::npos);
    const auto docs = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "resources/read", {},
        "binjad://docs"), principal, now, 10);
    EXPECT_FALSE(docs.error.has_value());
    EXPECT_NE(docs.body.find("project_file_open"), std::string::npos);
    EXPECT_NE(docs.body.find("source+type"), std::string::npos);
    EXPECT_NE(docs.body.find("close that project in the Binary Ninja GUI"), std::string::npos);
    EXPECT_NE(docs.body.find("same id without re-uploading"), std::string::npos);
    const auto compute = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "resources/read", {},
        "binjad://compute"), principal, now, 10);
    EXPECT_FALSE(compute.error.has_value());
    EXPECT_NE(compute.body.find("workerBudget"), std::string::npos);
    const auto session = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "resources/read", {},
        "binjad://analysis-sessions/" + created.session->reference), principal, now, 10);
    EXPECT_NE(session.body.find(created.session->reference), std::string::npos);
    const auto items = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "resources/read", {},
        "binjad://open-items"), principal, now, 10);
    EXPECT_FALSE(items.error.has_value());
    EXPECT_NE(items.body.find(opened.openItem->reference), std::string::npos);
    EXPECT_NE(items.body.find(created.session->reference), std::string::npos);
    EXPECT_NE(items.body.find("Mapped"), std::string::npos);
    const auto mapped = opened.openItem->binaryViews[1].reference;
    const auto settings = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_binary_view_load_settings", {},
        R"({"arguments":{"binaryView":")" + mapped + R"("}})"),
        principal, created.session, now, 10);
    EXPECT_FALSE(settings.error.has_value());
    EXPECT_NE(settings.body.find("loader.platform"), std::string::npos);
    EXPECT_NE(settings.body.find("serialized JSON strings"), std::string::npos);
}

TEST(McpFoundationTest, RejectsUnknownArgumentsAsProtocolErrors)
{
    binjad::Config config;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0");
    const auto result = foundation.Handle(Request(
        binjad::mcp::ProtocolVersion::V2026_07_28, "tools/call",
        "bn_compute_status", {}, R"({"arguments":{"unexpected":true}})"),
        Principal(), {}, 10);
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(result.error->code, -32602);
    EXPECT_EQ(result.error->httpStatus, 400);
}
