#include "binjad/binary_ninja_abi.hpp"
#include "binjad/config.hpp"
#include "binjad/http/drogon_routes.hpp"
#include "binjad/http/mcp_dispatcher.hpp"
#include "binjad/http/portal_routes.hpp"
#include "binjad/http/upload_routes.hpp"
#include "binjad/logging.hpp"
#include "binjad/overseer/file_child_coordinator.hpp"
#include "binjad/overseer/analysis_scheduler.hpp"
#include "binjad/overseer/collaboration_child_manager.hpp"
#include "binjad/overseer/project_child_coordinator.hpp"
#if defined(__APPLE__)
#include "binjad/platform/macos/mach_bootstrap.hpp"
#endif
#include "binjad/platform/paths.hpp"
#include "binjad/portal/api.hpp"
#include "binjad/portal/service.hpp"
#include "binjad/process/role.hpp"
#include "binjad/process/supervisor.hpp"
#include "binjad/project/local_project_registry.hpp"
#include "binjad/project/collaboration_project_registry.hpp"
#include "binjad/reference/friendly_reference.hpp"
#include "binjad/security/account_registry.hpp"
#include "binjad/security/bootstrap_credential.hpp"
#include "binjad/security/credential_store.hpp"
#include "binjad/security/token_registry.hpp"
#include "binjad/session/analysis_session_registry.hpp"
#include "binjad/session/job_registry.hpp"
#include "binjad/session/open_item_registry.hpp"
#include "binjad/version.hpp"
#include "binjad/worker/file_child.hpp"
#include "binjad/worker/project_child.hpp"
#include "binjad/upload/upload_registry.hpp"

#include <binaryninjacore.h>
#include <drogon/drogon.h>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace
{
void ReportError(std::string message)
{
    binjad::Log(binjad::LogLevel::Error, message);
    std::cerr << message << '\n';
}

struct SessionRuntime
{
    explicit SessionRuntime(const binjad::Config& config)
        : references(std::make_shared<binjad::reference::FriendlyReferencePool>()),
          openItems(std::make_shared<binjad::session::OpenItemRegistry>(*references)),
          projects(std::make_shared<binjad::project::LocalProjectRegistry>(*references)),
          collaborationProjects(std::make_shared<binjad::project::CollaborationProjectRegistry>(
              *references)),
          sessions(std::make_shared<binjad::session::AnalysisSessionRegistry>(
              *references, config.sessions.ttl)),
          subscriptions(std::make_shared<binjad::session::SubscriptionRegistry>()),
          scheduler(std::make_shared<binjad::overseer::AnalysisScheduler>(config.cpu)),
          jobs(std::make_shared<binjad::session::JobRegistry>(*references, *sessions)),
          uploads(std::make_shared<binjad::upload::UploadRegistry>(
              config, *references, *sessions, *projects, collaborationProjects.get())),
          dispatcher(nullptr)
    {
        openItems->SetChangedCallback([subscriptions = subscriptions](std::string_view owner) {
            subscriptions->PublishResource(owner, "binjad://open-items");
        });
        jobs->SetChangedCallback([subscriptions = subscriptions,
                                     mode = config.EffectiveMode()](const auto& job) {
            subscriptions->PublishResource(job.ownerTokenId, "binjad://jobs");
            subscriptions->PublishResource(job.ownerTokenId, "binjad://compute");
            if (job.analysisSession)
                subscriptions->PublishResource(job.ownerTokenId,
                    "binjad://analysis-sessions/" + *job.analysisSession);
            const bool terminal = job.state == binjad::session::JobState::Complete ||
                job.state == binjad::session::JobState::Failed ||
                job.state == binjad::session::JobState::Cancelled;
            if (terminal && (job.operation == "upload_commit" ||
                job.operation == "binary_view_save"))
            {
                subscriptions->PublishResource(job.ownerTokenId,
                    mode == binjad::Mode::Collaboration
                        ? "binjad://collaboration-projects"
                        : "binjad://local-projects");
            }
        });
    }

    void ConfigureDispatcher(const binjad::Config& config,
        binjad::overseer::FileChildCoordinator* coordinator,
        binjad::overseer::ProjectChildCoordinator* projectCoordinator,
        binjad::overseer::CollaborationChildManager* collaborationManager)
    {
        dispatcher = std::make_shared<binjad::http::McpDispatcher>(
            *sessions, BINJAD_VERSION, config, openItems.get(), coordinator, jobs.get(),
            projects.get(), projectCoordinator, scheduler.get(), uploads.get(),
            collaborationProjects.get(), collaborationManager,
            binjad::http::McpDispatcher::SteadyNow{},
            binjad::http::McpDispatcher::UnixNow{}, subscriptions);
    }

    std::shared_ptr<binjad::reference::FriendlyReferencePool> references;
    std::shared_ptr<binjad::session::OpenItemRegistry> openItems;
    std::shared_ptr<binjad::project::LocalProjectRegistry> projects;
    std::shared_ptr<binjad::project::CollaborationProjectRegistry> collaborationProjects;
    std::shared_ptr<binjad::session::AnalysisSessionRegistry> sessions;
    std::shared_ptr<binjad::session::SubscriptionRegistry> subscriptions;
    std::shared_ptr<binjad::overseer::AnalysisScheduler> scheduler;
    std::shared_ptr<binjad::session::JobRegistry> jobs;
    std::shared_ptr<binjad::upload::UploadRegistry> uploads;
    std::shared_ptr<binjad::http::McpDispatcher> dispatcher;
};

#if defined(__APPLE__)
struct FileRuntime
{
    FileRuntime(const binjad::Config& config, const std::filesystem::path& executable,
        binjad::session::OpenItemRegistry& openItems,
        binjad::project::LocalProjectRegistry& projects,
        binjad::project::CollaborationProjectRegistry& collaborationProjects,
        binjad::overseer::CollaborationChildManager::IdentityResolver identities,
        binjad::project::KnownProjectStore* knownProjects)
        : supervisor(binjad::CreateNativeProcessSupervisor()), bootstrap(*supervisor),
          coordinator(std::make_shared<binjad::overseer::FileChildCoordinator>(
              config, executable, *supervisor, bootstrap, openItems,
              binjad::overseer::FileChildCoordinator::EventCallback{}, &childLaunchMutex))
    {
        if (config.EffectiveMode() == binjad::Mode::Local)
            projectCoordinator = std::make_shared<binjad::overseer::ProjectChildCoordinator>(
                config, executable, *supervisor, bootstrap, projects, &childLaunchMutex,
                knownProjects);
        else if (config.EffectiveMode() == binjad::Mode::Collaboration)
            collaborationManager = std::make_shared<binjad::overseer::CollaborationChildManager>(
                config, executable, *supervisor, bootstrap, collaborationProjects,
                std::move(identities), &childLaunchMutex);
    }

    std::unique_ptr<binjad::ProcessSupervisor> supervisor;
    binjad::platform::macos::MachBootstrapServer bootstrap;
    std::mutex childLaunchMutex;
    std::shared_ptr<binjad::overseer::FileChildCoordinator> coordinator;
    std::shared_ptr<binjad::overseer::ProjectChildCoordinator> projectCoordinator;
    std::shared_ptr<binjad::overseer::CollaborationChildManager> collaborationManager;
};
#endif

struct AuthenticationRuntime
{
    AuthenticationRuntime(const binjad::Config& config, const std::filesystem::path& configPath)
        : credentials(binjad::security::CreateNativeCredentialStore(configPath)),
          bootstrap(*credentials), tokens(*credentials, config.storage.tokensPath),
          accounts(*credentials, config.storage.accountsPath),
          knownProjects(config.EffectiveMode() == binjad::Mode::Local
              ? std::make_unique<binjad::project::KnownProjectStore>(*credentials,
                    std::filesystem::absolute(configPath).lexically_normal().parent_path() /
                        "projects.json")
              : nullptr),
          portalService(config, accounts, tokens, bootstrap),
          portalApi(config, portalService, configPath)
    {
    }

    std::string Load()
    {
        if (const auto error = bootstrap.Load(); !error.empty())
            return "cannot load bootstrap credential: " + error;
        if (const auto error = tokens.Load(); !error.empty())
            return "cannot load token registry: " + error;
        if (const auto error = accounts.Load(); !error.empty())
            return "cannot load account registry: " + error;
        if (knownProjects)
        {
            if (const auto error = knownProjects->Load(); !error.empty())
                return "cannot load known project registry: " + error;
        }
        return {};
    }

    std::unique_ptr<binjad::security::CredentialStore> credentials;
    binjad::security::BootstrapCredential bootstrap;
    binjad::security::TokenRegistry tokens;
    binjad::security::AccountRegistry accounts;
    std::unique_ptr<binjad::project::KnownProjectStore> knownProjects;
    binjad::portal::Service portalService;
    binjad::portal::Api portalApi;
};

enum class OverseerCommand
{
    Run,
    MintBootstrap,
};

struct OverseerOptions
{
    OverseerCommand command = OverseerCommand::Run;
    std::filesystem::path configPath;
};

std::optional<OverseerOptions> ParseOverseerOptions(int argc, char** argv)
{
    OverseerOptions options{OverseerCommand::Run, binjad::platform::DefaultConfigPath()};
    int index = 1;
    if (index < argc && std::string_view(argv[index]) == "service")
    {
        if (index + 1 >= argc || std::string_view(argv[index + 1]) != "bootstrap")
        {
            ReportError("supported service command: bootstrap");
            return std::nullopt;
        }
        options.command = OverseerCommand::MintBootstrap;
        index += 2;
    }
    for (; index < argc; ++index)
    {
        const std::string_view argument(argv[index]);
        if (argument == "--config")
        {
            if (++index >= argc)
            {
                ReportError("--config requires a path");
                return std::nullopt;
            }
            options.configPath = argv[index];
            continue;
        }
        constexpr std::string_view prefix = "--config=";
        if (argument.starts_with(prefix) && argument.size() > prefix.size())
        {
            options.configPath = argument.substr(prefix.size());
            continue;
        }
        ReportError("unknown argument: " + std::string(argument));
        return std::nullopt;
    }
    return options;
}

int RunOverseer(int argc, char** argv)
{
    std::optional<OverseerOptions> options;
    try
    {
        options = ParseOverseerOptions(argc, argv);
    }
    catch (const std::exception& exception)
    {
        ReportError("cannot determine configuration path: " + std::string(exception.what()));
        return EXIT_FAILURE;
    }
    if (!options)
        return EXIT_FAILURE;

    const auto result = binjad::LoadOrCreateConfig(options->configPath);
    if (!result.config)
    {
        for (const auto& error : result.errors)
            ReportError("configuration " + error.path + ": " + error.message);
        return EXIT_FAILURE;
    }

    try
    {
        if (options->command == OverseerCommand::MintBootstrap)
        {
            auto credentials = binjad::security::CreateNativeCredentialStore(options->configPath);
            binjad::security::BootstrapCredential bootstrap(*credentials);
            if (const auto error = bootstrap.Load(); !error.empty())
                throw std::runtime_error("cannot load bootstrap credential: " + error);
            const auto minted = bootstrap.Mint();
            if (!minted.credential)
                throw std::runtime_error(minted.error);
            std::cout << *minted.credential << '\n';
            return EXIT_SUCCESS;
        }
        auto authenticationRuntime = std::make_shared<AuthenticationRuntime>(
            *result.config, options->configPath);
        if (const auto error = authenticationRuntime->Load(); !error.empty())
            throw std::runtime_error(error);
        auto sessionRuntime = std::make_shared<SessionRuntime>(*result.config);
#if defined(__APPLE__)
        const auto executable = std::filesystem::absolute(argc > 0 ? argv[0] : "binjad").lexically_normal();
        auto identityResolver = [authenticationRuntime](
            const binjad::security::TokenRecord& principal)
            -> binjad::overseer::CollaborationResult<binjad::overseer::CollaborationIdentity> {
            const auto accounts = authenticationRuntime->accounts.Records();
            const auto account = accounts.find(principal.issuerAccountId);
            if (account == accounts.end() || account->second.deletedAt ||
                !account->second.collaborationUsername)
                return {{}, "collaboration account binding is unavailable"};
            const auto token = authenticationRuntime->accounts.CollaborationAccessToken(
                principal.issuerAccountId);
            if (!token.error.empty())
                return {{}, token.error};
            if (!token.value)
                return {{}, "collaboration access token is unavailable"};
            return {binjad::overseer::CollaborationIdentity{
                *account->second.collaborationUsername, *token.value}, {}};
        };
        auto fileRuntime = std::make_shared<FileRuntime>(
            *result.config, executable, *sessionRuntime->openItems,
            *sessionRuntime->projects, *sessionRuntime->collaborationProjects,
            std::move(identityResolver), authenticationRuntime->knownProjects.get());
        sessionRuntime->sessions->SetClosedCallback(
            [fileRuntime, sessionRuntime](const auto& session) {
                sessionRuntime->subscriptions->RemoveSession(session.reference);
                sessionRuntime->uploads->RemoveByAnalysisSession(session.reference);
                fileRuntime->coordinator->CloseAnalysisSession(
                    session.ownerTokenId, session.reference);
                sessionRuntime->subscriptions->PublishResource(
                    session.ownerTokenId, "binjad://analysis-sessions");
            });
        sessionRuntime->ConfigureDispatcher(*result.config, fileRuntime->coordinator.get(),
            fileRuntime->projectCoordinator.get(), fileRuntime->collaborationManager.get());
        authenticationRuntime->portalApi.SetProjectDeleteCallback(
            [sessionRuntime, fileRuntime](std::string_view project) {
                if (!sessionRuntime->projects->Find(project))
                    return binjad::portal::Result<bool>{{}, "project not found"};
                if (sessionRuntime->openItems->HasProject(project))
                    return binjad::portal::Result<bool>{{},
                        "project has open analysis handles"};
                if (!fileRuntime->projectCoordinator)
                    return binjad::portal::Result<bool>{{},
                        "local project deletion is unavailable"};
                const auto error = fileRuntime->projectCoordinator->DeleteProject(project);
                return error.empty()
                    ? binjad::portal::Result<bool>{true, {}}
                    : binjad::portal::Result<bool>{{}, error};
            });
        authenticationRuntime->portalApi.SetProjectListCallback(
            [sessionRuntime] {
                std::vector<binjad::portal::ProjectSummary> result;
                for (const auto& project : sessionRuntime->projects->List())
                    result.push_back({project.reference, project.name, project.description});
                return result;
            });
        authenticationRuntime->portalApi.SetRuntimeStatusProvider(
            [sessionRuntime] {
                const auto compute = sessionRuntime->scheduler->Status();
                return binjad::portal::RuntimeStatus{
                    sessionRuntime->sessions->Size(),
                    sessionRuntime->openItems->Size(),
                    sessionRuntime->jobs->Size(),
                    sessionRuntime->projects->Size(),
                    compute.logicalCpuCount,
                    compute.workerBudget,
                    compute.allocatedWorkers,
                    compute.activeAnalyses,
                    compute.queuedAnalyses};
            });
        authenticationRuntime->portalApi.SetMcpDocumentationProviders(
            [dispatcher = sessionRuntime->dispatcher](auto version, auto role,
                std::string_view client) {
                return dispatcher->ContextDocumentation(version, role, client);
            },
            [dispatcher = sessionRuntime->dispatcher](auto version, auto role) {
                return dispatcher->ToolDocumentation(version, role);
            });
#else
        sessionRuntime->sessions->SetClosedCallback(
            [sessionRuntime](const auto& session) {
                sessionRuntime->subscriptions->RemoveSession(session.reference);
                sessionRuntime->uploads->RemoveByAnalysisSession(session.reference);
                auto& openItems = sessionRuntime->openItems;
                openItems->CloseByAnalysisSession(session.reference);
                sessionRuntime->subscriptions->PublishResource(
                    session.ownerTokenId, "binjad://analysis-sessions");
            });
        sessionRuntime->ConfigureDispatcher(*result.config, nullptr, nullptr, nullptr);
        authenticationRuntime->portalApi.SetMcpDocumentationProviders(
            [dispatcher = sessionRuntime->dispatcher](auto version, auto role,
                std::string_view client) {
                return dispatcher->ContextDocumentation(version, role, client);
            },
            [dispatcher = sessionRuntime->dispatcher](auto version, auto role) {
                return dispatcher->ToolDocumentation(version, role);
            });
#endif
        authenticationRuntime->portalService.SetTokenRevokedCallback(
            [sessionRuntime
#if defined(__APPLE__)
                , fileRuntime
#endif
            ](std::string_view tokenId) {
                sessionRuntime->jobs->CancelByToken(tokenId);
                sessionRuntime->jobs->RemoveByToken(tokenId);
                sessionRuntime->uploads->RemoveByToken(tokenId);
                sessionRuntime->subscriptions->RemoveOwner(tokenId);
#if defined(__APPLE__)
                if (fileRuntime->collaborationManager)
                    fileRuntime->collaborationManager->RemoveByToken(tokenId);
#endif
                sessionRuntime->sessions->CloseByOwner(tokenId);
            });
        if (const auto error = binjad::http::ConfigureDrogonUploadStorage(
                drogon::app(), *result.config); !error.empty())
            throw std::runtime_error("cannot configure HTTP upload storage: " + error);
        binjad::http::RegisterDrogonRoutes(drogon::app(), *result.config,
            authenticationRuntime->tokens.Authenticator(),
            [sessionRuntime, authenticationRuntime
#if defined(__APPLE__)
                , fileRuntime
#endif
            ](binjad::http::AdmittedMcpRequest request,
                binjad::http::DrogonResponseCallback callback) {
                (void)authenticationRuntime;
#if defined(__APPLE__)
                (void)fileRuntime;
#endif
                sessionRuntime->dispatcher->Handle(std::move(request), std::move(callback));
            });
        binjad::http::RegisterUploadRoutes(drogon::app(), *result.config,
            authenticationRuntime->tokens.Authenticator(), *sessionRuntime->uploads);
        auto portalApi = std::shared_ptr<binjad::portal::Api>(
            authenticationRuntime, &authenticationRuntime->portalApi);
        binjad::http::RegisterPortalRoutes(
            drogon::app(), *result.config, std::move(portalApi));
        drogon::app().registerBeginningAdvice([sessionRuntime
#if defined(__APPLE__)
            , fileRuntime
#endif
        ] {
            binjad::Log(binjad::LogLevel::Notice, "binjad overseer is ready");
            drogon::app().getLoop()->runEvery(60.0, [sessionRuntime
#if defined(__APPLE__)
                , fileRuntime
#endif
            ] {
                const auto now = binjad::session::AnalysisSessionRegistry::Clock::now();
                sessionRuntime->sessions->Sweep(now);
                sessionRuntime->uploads->Sweep(now);
#if defined(__APPLE__)
                if (fileRuntime->collaborationManager)
                {
                    for (const auto& token : fileRuntime->collaborationManager->Tokens())
                    {
                        if (sessionRuntime->sessions->List(token, now).empty())
                            fileRuntime->collaborationManager->RemoveByToken(token);
                    }
                }
#endif
            });
        });
        drogon::app().run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        ReportError("overseer startup failed: " + std::string(exception.what()));
        return EXIT_FAILURE;
    }
}
}

int main(int argc, char** argv)
{
    constexpr binjad::AbiRange compiledRange{
        BN_MINIMUM_CORE_ABI_VERSION,
        BN_CURRENT_CORE_ABI_VERSION,
    };
    const binjad::AbiRange runtimeRange{
        BNGetMinimumCoreABIVersion(),
        BNGetCurrentCoreABIVersion(),
    };

    if (!binjad::AbiRangesOverlap(compiledRange, runtimeRange))
    {
        std::ostringstream message;
        message << "Binary Ninja core ABI mismatch: binjad " << BINJAD_VERSION
                << " was built for ABI " << compiledRange.minimum << '-'
                << compiledRange.current << ", but the loaded core provides ABI "
                << runtimeRange.minimum << '-' << runtimeRange.current;
        ReportError(message.str());
        return EXIT_FAILURE;
    }

    const auto role = binjad::RoleFromArgv0(argc > 0 ? argv[0] : "binjad");
    if (role == binjad::ProcessRole::FileChild)
    {
#if defined(__APPLE__)
        try
        {
            auto channel = binjad::platform::macos::ConnectToOverseer(role);
            return binjad::RunFileChild(
                std::make_unique<binjad::platform::macos::MachChannel>(std::move(channel)));
        }
        catch (const std::exception& exception)
        {
            ReportError("file child startup failed: " + std::string(exception.what()));
            return EXIT_FAILURE;
        }
#else
        ReportError("file child IPC is not implemented for this platform");
        return EXIT_FAILURE;
#endif
    }
    if (role == binjad::ProcessRole::ProjectChild)
    {
#if defined(__APPLE__)
        try
        {
            auto channel = binjad::platform::macos::ConnectToOverseer(role);
            return binjad::RunProjectChild(
                std::make_unique<binjad::platform::macos::MachChannel>(std::move(channel)));
        }
        catch (const std::exception& exception)
        {
            ReportError("project child startup failed: " + std::string(exception.what()));
            return EXIT_FAILURE;
        }
#else
        ReportError("project child IPC is not implemented for this platform");
        return EXIT_FAILURE;
#endif
    }

    return RunOverseer(argc, argv);
}
