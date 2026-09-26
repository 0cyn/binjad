#include "binjad/overseer/FileChildCoordinator.hpp"

#include "binjad/ipc/Envelope.hpp"
#include "binjad/platform/Paths.hpp"
#include "binjad/security/Random.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <limits>
#include <stdexcept>
#include <thread>
#include <utility>

namespace binjad::overseer
{
namespace
{
bool IsSharedCachePrimary(const std::filesystem::path& path)
{
    const auto name = path.filename().string();
    return name.starts_with("dyld_shared_cache_") && name.find('.') == std::string::npos;
}

std::string AddSharedCachePrimaryOption(
    std::string optionsJson, const std::filesystem::path& primary)
{
    rapidjson::Document document;
    document.Parse(optionsJson.data(), optionsJson.size());
    if (document.HasParseError() || !document.IsObject())
        throw std::invalid_argument("BinaryView options must be a JSON object");
    constexpr auto key = "loader.dsc.primaryFilePath";
    if (!document.HasMember(key))
    {
        const auto value = primary.string();
        rapidjson::Value path;
        path.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()),
            document.GetAllocator());
        document.AddMember(rapidjson::StringRef(key), std::move(path), document.GetAllocator());
    }
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    return {buffer.GetString(), buffer.GetSize()};
}

std::string ExitDescription(const ChildExit& exit)
{
    std::string description = "file child exited";
    if (exit.crash)
        description += " after Mach exception " + std::to_string(exit.crash->exception);
    else if (exit.signal)
        description += " from signal " + std::to_string(*exit.signal);
    else if (exit.exitCode)
        description += " with status " + std::to_string(*exit.exitCode);
    return description;
}
}

struct FileChildCoordinator::ExitGate
{
    std::mutex mutex;
    FileChildCoordinator* owner = nullptr;
};

class FileChildCoordinator::Child
{
  public:
    struct AnalysisWaiter
    {
        std::shared_ptr<std::promise<ipc::AnalysisFinished>> completion;
        AnalysisProgressCallback progress;
    };

    Child(ProcessId processId, std::unique_ptr<ipc::ByteChannel> channel,
        std::filesystem::path workingDirectory, std::filesystem::path workingCopy,
        std::string ownerTokenId, std::string optionsJson, bool reuseDatabase,
        EventCallback eventCallback)
        : processId(processId), workingDirectory(std::move(workingDirectory)),
          workingCopy(std::move(workingCopy)), optionsJson(std::move(optionsJson)),
          ownerTokenId(std::move(ownerTokenId)), reuseDatabase(reuseDatabase),
          channel_(std::move(channel)),
          eventCallback_(std::move(eventCallback))
    {
        reader_ = std::jthread([this] { ReaderLoop(); });
    }

    ~Child()
    {
        {
            std::lock_guard lock(stateMutex_);
            closed_ = true;
        }
        channel_->Close();
        if (reader_.joinable())
            reader_.join();
    }

    void SetOpenItem(std::string openItem)
    {
        std::lock_guard lock(stateMutex_);
        openItem_ = std::move(openItem);
    }

    ipc::Reply Call(const ipc::Command& command, std::string_view openItem,
        AnalysisProgressCallback progress = {})
    {
        (void)openItem;
        std::lock_guard lock(commandMutex_);
        return CallLocked(command, std::move(progress));
    }

    ipc::Reply CallUntil(const ipc::Command& command,
        std::chrono::steady_clock::time_point deadline)
    {
        std::lock_guard lock(commandMutex_);
        return CallLocked(command, {}, deadline);
    }

    CoordinatorResult<ipc::AnalysisFinished> CallAndWaitForAnalysis(
        const ipc::Command& command, AnalysisProgressCallback progress)
    {
        std::future<ipc::AnalysisFinished> analysis;
        ipc::Reply reply;
        {
            std::lock_guard lock(commandMutex_);
            const auto requestId = requestIds_.Next();
            auto replyPromise = std::make_shared<std::promise<ipc::Reply>>();
            auto analysisPromise =
                std::make_shared<std::promise<ipc::AnalysisFinished>>();
            auto replyFuture = replyPromise->get_future();
            analysis = analysisPromise->get_future();
            {
                std::lock_guard stateLock(stateMutex_);
                if (closed_)
                    return {{}, "file child is closed"};
                if (!failure_.empty())
                    return {{}, failure_};
                pending_.emplace(requestId, replyPromise);
                analysisPending_.emplace(requestId,
                    AnalysisWaiter{analysisPromise, std::move(progress)});
            }
            ipc::Envelope request;
            request.set_protocol_version(ipc::kProtocolVersion);
            request.set_request_id(requestId);
            *request.mutable_command() = command;
            try
            {
                ipc::SendEnvelope(*channel_, request);
            }
            catch (const std::exception& exception)
            {
                std::lock_guard stateLock(stateMutex_);
                pending_.erase(requestId);
                analysisPending_.erase(requestId);
                return {{}, exception.what()};
            }
            try
            {
                reply = replyFuture.get();
            }
            catch (const std::exception& exception)
            {
                std::lock_guard stateLock(stateMutex_);
                analysisPending_.erase(requestId);
                return {{}, exception.what()};
            }
            if (!reply.success())
            {
                std::lock_guard stateLock(stateMutex_);
                analysisPending_.erase(requestId);
                return {{}, reply.error()};
            }
        }
        try
        {
            return {analysis.get(), {}};
        }
        catch (const std::exception& exception)
        {
            return {{}, exception.what()};
        }
    }

    std::string Close(std::string_view openItem, bool discardUncommitted)
    {
        (void)openItem;
        std::lock_guard lock(commandMutex_);
        {
            std::lock_guard stateLock(stateMutex_);
            if (closed_)
                return {};
            if (!discardUncommitted && pendingDatabaseCommit_)
                return "file has an uncommitted database save; explicit discard is required";
        }
        try
        {
            ipc::Command close;
            close.mutable_close_file()->set_discard_uncommitted(discardUncommitted);
            const auto closeReply = CallLocked(close);
            if (!closeReply.success())
                return closeReply.error();
            ipc::Command shutdown;
            shutdown.mutable_shutdown();
            const auto shutdownReply = CallLocked(shutdown);
            if (!shutdownReply.success())
                return shutdownReply.error();
            {
                std::lock_guard stateLock(stateMutex_);
                closed_ = true;
            }
            channel_->Close();
            if (reader_.joinable())
                reader_.join();
            return {};
        }
        catch (const std::exception& exception)
        {
            return exception.what();
        }
    }

    ProcessId processId;
    std::filesystem::path workingDirectory;
    std::filesystem::path workingCopy;
    std::string optionsJson;
    std::string ownerTokenId;
    bool reuseDatabase;

    void PromoteWorkingCopy(std::filesystem::path path)
    {
        std::lock_guard lock(stateMutex_);
        workingCopy = std::move(path);
        reuseDatabase = true;
        pendingDatabaseCommit_ = false;
    }

    bool RecordDatabaseSave(const std::filesystem::path& path)
    {
        std::lock_guard lock(stateMutex_);
        pendingDatabaseCommit_ = true;
        // A failed first commit leaves the core backed by its new private BNDB,
        // while the public source is still raw. Retries must retain sibling-save
        // semantics until that database has actually been committed.
        return path != workingCopy;
    }

    bool HasPendingDatabaseCommit() const
    {
        std::lock_guard lock(stateMutex_);
        return pendingDatabaseCommit_;
    }

    std::filesystem::path WorkingCopy() const
    {
        std::lock_guard lock(stateMutex_);
        return workingCopy;
    }

    struct Failure
    {
        bool failed = false;
        bool idleNotice = false;
        std::string error;
    };

    Failure FailureState() const
    {
        std::lock_guard lock(stateMutex_);
        return {!failure_.empty(), idleCrashNotice_, failure_};
    }

    void MarkExited(std::string error, bool idleNotice = true)
    {
        {
            std::lock_guard lock(stateMutex_);
            if (closed_)
                return;
            const bool firstFailure = failure_.empty();
            if (firstFailure)
                failure_ = std::move(error);
            if (!idleNotice)
            {
                suppressIdleNotice_ = true;
                idleCrashNotice_ = false;
            }
            if (firstFailure && idleNotice && pending_.empty())
                idleCrashNotice_ = true;
        }
        channel_->Close();
    }

  private:
    ipc::Reply CallLocked(const ipc::Command& command,
        AnalysisProgressCallback progress = {},
        std::optional<std::chrono::steady_clock::time_point> deadline = {})
    {
        const auto requestId = requestIds_.Next();
        auto promise = std::make_shared<std::promise<ipc::Reply>>();
        auto future = promise->get_future();
        {
            std::lock_guard lock(stateMutex_);
            if (closed_)
                throw std::runtime_error("file child is closed");
            if (!failure_.empty())
                throw ipc::ChannelError(failure_);
            pending_.emplace(requestId, promise);
            if (progress)
                progressPending_.emplace(requestId, std::move(progress));
        }
        ipc::Envelope request;
        request.set_protocol_version(ipc::kProtocolVersion);
        request.set_request_id(requestId);
        *request.mutable_command() = command;
        try
        {
            ipc::SendEnvelope(*channel_, request);
        }
        catch (...)
        {
            std::lock_guard lock(stateMutex_);
            pending_.erase(requestId);
            progressPending_.erase(requestId);
            throw;
        }
        try
        {
            if (deadline && future.wait_until(*deadline) != std::future_status::ready)
            {
                std::lock_guard lock(stateMutex_);
                pending_.erase(requestId);
                progressPending_.erase(requestId);
                throw std::runtime_error("file child command timed out");
            }
            auto reply = future.get();
            std::lock_guard lock(stateMutex_);
            progressPending_.erase(requestId);
            return reply;
        }
        catch (...)
        {
            std::lock_guard lock(stateMutex_);
            progressPending_.erase(requestId);
            throw;
        }
    }

    void ReaderLoop()
    {
        try
        {
            while (true)
            {
                auto response = ipc::ReceiveEnvelope(*channel_);
                if (response.has_event())
                {
                    std::shared_ptr<std::promise<ipc::AnalysisFinished>> analysisPromise;
                    AnalysisProgressCallback progress;
                    EventCallback callback;
                    std::string openItem;
                    {
                        std::lock_guard lock(stateMutex_);
                        if (response.event().has_analysis_finished())
                        {
                            const auto pending = analysisPending_.find(
                                response.event().originating_request_id());
                            if (pending != analysisPending_.end())
                            {
                                analysisPromise = std::move(pending->second.completion);
                                analysisPending_.erase(pending);
                            }
                        }
                        else if (response.event().has_progress())
                        {
                            const auto pending = analysisPending_.find(
                                response.event().originating_request_id());
                            if (pending != analysisPending_.end())
                                progress = pending->second.progress;
                            if (!progress)
                            {
                                const auto generic = progressPending_.find(
                                    response.event().originating_request_id());
                                if (generic != progressPending_.end())
                                    progress = generic->second;
                            }
                        }
                        callback = eventCallback_;
                        openItem = openItem_;
                    }
                    if (analysisPromise)
                        analysisPromise->set_value(response.event().analysis_finished());
                    if (progress)
                    {
                        try
                        {
                            progress(response.event().progress());
                        }
                        catch (...)
                        {}
                    }
                    if (callback)
                    {
                        try
                        {
                            callback(openItem, response.event());
                        }
                        catch (...)
                        {}
                    }
                    continue;
                }
                if (!response.has_reply())
                    throw ipc::ChannelError("file child returned an unexpected IPC envelope");
                std::shared_ptr<std::promise<ipc::Reply>> promise;
                {
                    std::lock_guard lock(stateMutex_);
                    const auto pending = pending_.find(response.request_id());
                    if (pending == pending_.end())
                        throw ipc::ChannelError("file child returned an unexpected IPC reply ID");
                    promise = std::move(pending->second);
                    pending_.erase(pending);
                }
                promise->set_value(response.reply());
            }
        }
        catch (const std::exception& exception)
        {
            std::vector<std::shared_ptr<std::promise<ipc::Reply>>> pending;
            std::vector<std::shared_ptr<std::promise<ipc::AnalysisFinished>>> analysisPending;
            std::string failure;
            {
                std::lock_guard lock(stateMutex_);
                if (failure_.empty())
                    failure_ = exception.what();
                if (!closed_ && !suppressIdleNotice_ && pending_.empty())
                    idleCrashNotice_ = true;
                for (auto& entry : pending_)
                    pending.push_back(std::move(entry.second));
                pending_.clear();
                for (auto& entry : analysisPending_)
                    analysisPending.push_back(std::move(entry.second.completion));
                analysisPending_.clear();
                progressPending_.clear();
                failure = failure_;
            }
            for (const auto& promise : pending)
            {
                try
                {
                    promise->set_exception(std::make_exception_ptr(
                        ipc::ChannelError(failure)));
                }
                catch (...)
                {}
            }
            for (const auto& promise : analysisPending)
            {
                try
                {
                    promise->set_exception(std::make_exception_ptr(
                        ipc::ChannelError(failure)));
                }
                catch (...)
                {}
            }
        }
    }

    std::unique_ptr<ipc::ByteChannel> channel_;
    EventCallback eventCallback_;
    ipc::RequestIdSource requestIds_;
    std::mutex commandMutex_;
    mutable std::mutex stateMutex_;
    std::unordered_map<std::uint64_t, std::shared_ptr<std::promise<ipc::Reply>>> pending_;
    std::unordered_map<std::uint64_t,
        AnalysisWaiter> analysisPending_;
    std::unordered_map<std::uint64_t, AnalysisProgressCallback> progressPending_;
    std::string openItem_;
    std::string failure_;
    bool closed_ = false;
    bool pendingDatabaseCommit_ = false;
    bool idleCrashNotice_ = false;
    bool suppressIdleNotice_ = false;
    std::jthread reader_;
};

FileChildCoordinator::FileChildCoordinator(Config config, std::filesystem::path executable,
    ProcessSupervisor& supervisor, ChildChannelAcceptor& acceptor,
    session::OpenItemRegistry& openItems, EventCallback eventCallback,
    std::mutex* launchMutex)
    : config_(std::move(config)), executable_(std::move(executable)),
      supervisor_(supervisor), acceptor_(acceptor), openItems_(openItems),
      eventCallback_(std::move(eventCallback)), launchMutex_(launchMutex),
      exitGate_(std::make_shared<ExitGate>())
{
    if (executable_.empty())
        throw std::invalid_argument("file child executable path must not be empty");
    exitGate_->owner = this;
    supervisor_.SetExitCallback([gate = exitGate_](const ChildExit& exit) {
        std::lock_guard lock(gate->mutex);
        if (gate->owner)
            gate->owner->HandleExit(exit);
    });
}

FileChildCoordinator::~FileChildCoordinator()
{
    supervisor_.SetExitCallback({});
    {
        std::lock_guard lock(exitGate_->mutex);
        exitGate_->owner = nullptr;
    }
    std::vector<std::pair<std::string, std::shared_ptr<Child>>> children;
    {
        std::lock_guard lock(mutex_);
        children.reserve(children_.size());
        for (const auto& child : children_)
            children.push_back(child);
        children_.clear();
    }
    for (const auto& [openItem, child] : children)
    {
        if (!child->Close(openItem, true).empty())
        {
            try
            {
                supervisor_.Terminate(child->processId);
            }
            catch (...)
            {}
        }
        CleanupWorkingDirectory(child->workingDirectory);
    }
}

CoordinatorResult<session::OpenItemRecord> FileChildCoordinator::OpenArbitraryPath(
    const security::TokenRecord& principal, std::string analysisSession,
    const std::filesystem::path& path, std::string optionsJson, bool reuseDatabase)
{
    if (!config_.projects.allowArbitraryPaths)
        return {{}, "arbitrary path opening is disabled"};
    if (principal.role != security::TokenRole::Admin)
        return {{}, "admin bearer token required for arbitrary path opening"};

    std::error_code filesystemError;
    const auto source = std::filesystem::canonical(path, filesystemError);
    if (filesystemError)
        return {{}, "cannot resolve source path: " + filesystemError.message()};
    return OpenManagedPath(principal, std::move(analysisSession), source,
        std::move(optionsJson), reuseDatabase,
        session::OpenItemSourceKind::ArbitraryPath, source.string());
}

CoordinatorResult<session::OpenItemRecord> FileChildCoordinator::OpenManagedPath(
    const security::TokenRecord& principal, std::string analysisSession,
    const std::filesystem::path& source, std::string optionsJson, bool reuseDatabase,
    session::OpenItemSourceKind sourceKind, std::string sourceDescription,
    std::optional<std::string> project)
{
    auto random = security::GenerateHex256();
    if (!random.value)
        return {{}, random.error};
    const auto workingDirectory = config_.storage.spoolPath / "open-items" / *random.value;
    auto leaf = source.filename();
    if (leaf.empty())
        leaf = "input";
    const auto workingCopy = workingDirectory / leaf;
    const auto copied = platform::CopyRegularFilePrivate(source, workingCopy);
    if (!copied.bytesCopied || !copied.error.empty())
    {
        CleanupWorkingDirectory(workingDirectory);
        return {{}, copied.error};
    }

    if (IsSharedCachePrimary(source))
    {
        try
        {
            if (sourceKind == session::OpenItemSourceKind::ArbitraryPath)
            {
                optionsJson = AddSharedCachePrimaryOption(
                    std::move(optionsJson), source);
            }
            else
            {
                const auto prefix = source.filename().string() + ".";
                for (const auto& entry : std::filesystem::directory_iterator(source.parent_path()))
                {
                    const auto filename = entry.path().filename().string();
                    if (!filename.starts_with(prefix))
                        continue;
                    const auto companion = platform::CopyRegularFilePrivate(
                        entry.path(), workingDirectory / entry.path().filename());
                    if (!companion.bytesCopied || !companion.error.empty())
                        throw std::runtime_error(companion.error);
                }
                optionsJson = AddSharedCachePrimaryOption(
                    std::move(optionsJson), workingCopy);
            }
        }
        catch (const std::exception& exception)
        {
            CleanupWorkingDirectory(workingDirectory);
            return {{}, std::string("cannot stage SharedCache companions: ") + exception.what()};
        }
    }

    ProcessId processId = 0;
    std::unique_ptr<ipc::ByteChannel> channel;
    try
    {
        std::unique_lock<std::mutex> launchLock;
        if (launchMutex_)
            launchLock = std::unique_lock(*launchMutex_);
        processId = supervisor_.Spawn(executable_, ProcessRole::FileChild);
        channel = acceptor_.Accept(processId, ProcessRole::FileChild);
    }
    catch (const std::exception& exception)
    {
        if (processId != 0)
        {
            try
            {
                supervisor_.Terminate(processId);
            }
            catch (...)
            {}
        }
        CleanupWorkingDirectory(workingDirectory);
        return {{}, exception.what()};
    }

    auto child = std::make_shared<Child>(
        processId, std::move(channel), workingDirectory, workingCopy,
        principal.id, optionsJson, reuseDatabase, eventCallback_);
    ipc::Command command;
    auto* open = command.mutable_open_file();
    open->set_path(workingCopy.string());
    open->set_options_json(optionsJson);
    open->set_reuse_database(reuseDatabase);
    ipc::Reply reply;
    try
    {
        reply = child->Call(command, {});
    }
    catch (const std::exception& exception)
    {
        try
        {
            supervisor_.Terminate(processId);
        }
        catch (...)
        {}
        CleanupWorkingDirectory(workingDirectory);
        return {{}, exception.what()};
    }
    if (!reply.success() || !reply.has_file_opened())
    {
        try
        {
            supervisor_.Terminate(processId);
        }
        catch (...)
        {}
        CleanupWorkingDirectory(workingDirectory);
        return {{}, reply.success() ? "file child returned no open result" : reply.error()};
    }

    std::vector<session::BinaryViewCandidateSpec> candidates;
    candidates.reserve(reply.file_opened().candidates_size());
    for (const auto& candidate : reply.file_opened().candidates())
        candidates.push_back({candidate.view_type(), candidate.recommended(),
            candidate.load_settings_schema_json()});
    auto registered = openItems_.Create(principal.id, std::move(analysisSession),
        sourceKind, sourceDescription.empty() ? source.string() : std::move(sourceDescription),
        std::move(project), candidates);
    if (!registered.openItem)
    {
        if (!child->Close({}, true).empty())
        {
            try
            {
                supervisor_.Terminate(processId);
            }
            catch (...)
            {}
        }
        CleanupWorkingDirectory(workingDirectory);
        return {{}, std::move(registered.error)};
    }
    {
        std::lock_guard lock(mutex_);
        children_.emplace(registered.openItem->reference, child);
    }
    child->SetOpenItem(registered.openItem->reference);
    return {std::move(registered.openItem), {}};
}

CoordinatorResult<session::BinaryViewRecord> FileChildCoordinator::OpenBinaryView(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, std::string optionsJson, bool analyze)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(
        ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    auto* open = command.mutable_open_binary_view();
    open->set_view_type(view.viewType);
    open->set_options_json(std::move(optionsJson));
    open->set_analyze(analyze);
    try
    {
        const auto reply = child->Call(command, view.openItem);
        if (!reply.success() || !reply.has_binary_view_opened())
            return {{}, reply.success() ? "file child returned no BinaryView result" : reply.error()};
        const auto& opened = reply.binary_view_opened();
        auto created = openItems_.MarkViewCreated(ownerTokenId, analysisSession, binaryView,
            opened.architecture(), opened.platform(), opened.effective_load_settings_json(),
            opened.start(), opened.end(), opened.entry_point());
        return created ? CoordinatorResult<session::BinaryViewRecord>{std::move(created), {}}
                       : CoordinatorResult<session::BinaryViewRecord>{{}, "BinaryView disappeared after opening"};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
    return {{}, "BinaryView open failed"};
}

CoordinatorResult<ipc::AnalysisStatus> FileChildCoordinator::AnalysisStatus(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    command.mutable_get_analysis_status()->set_view_type(view.viewType);
    try
    {
        const auto reply = child->Call(command, view.openItem);
        if (!reply.success() || !reply.has_analysis_status())
            return {{}, reply.success() ? "file child returned no analysis status" : reply.error()};
        auto status = reply.analysis_status();
        if (child->HasPendingDatabaseCommit())
            status.set_modified(true);
        return {std::move(status), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

std::string FileChildCoordinator::UpdateAnalysis(std::string_view ownerTokenId,
    std::string_view analysisSession, std::string_view binaryView)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return error;
    ipc::Command command;
    command.mutable_update_analysis()->set_view_type(view.viewType);
    try
    {
        const auto reply = child->Call(command, view.openItem);
        return reply.success() ? std::string{} : reply.error();
    }
    catch (const std::exception& exception)
    {
        return exception.what();
    }
}

std::string FileChildCoordinator::SetWorkerCount(std::string_view ownerTokenId,
    std::string_view analysisSession, std::string_view binaryView, std::size_t count)
{
    if (count == 0 || count > std::numeric_limits<std::uint32_t>::max())
        return "worker count is out of range";
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return error;
    ipc::Command command;
    command.mutable_set_worker_count()->set_count(static_cast<std::uint32_t>(count));
    try
    {
        const auto reply = child->Call(command, view.openItem);
        return reply.success() ? std::string{} : reply.error();
    }
    catch (const std::exception& exception)
    {
        return exception.what();
    }
}

CoordinatorResult<ipc::AnalysisFinished> FileChildCoordinator::UpdateAnalysisAndWait(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, AnalysisProgressCallback progress)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    command.mutable_update_analysis()->set_view_type(view.viewType);
    return child->CallAndWaitForAnalysis(command, std::move(progress));
}

CoordinatorResult<ipc::BinaryViewSaved> FileChildCoordinator::SaveBinaryView(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, const std::filesystem::path& destination,
    AnalysisProgressCallback progress)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    auto* save = command.mutable_save_binary_view();
    save->set_view_type(view.viewType);
    const auto saveDestination = destination.empty()
        ? child->workingDirectory / "saved.bndb" : destination;
    save->set_destination(saveDestination.string());
    try
    {
        const auto reply = child->Call(command, view.openItem, std::move(progress));
        if (!reply.success() || !reply.has_binary_view_saved())
            return {{}, reply.success() ? "file child returned no save result" : reply.error()};
        auto saved = reply.binary_view_saved();
        saved.set_created_database(child->RecordDatabaseSave(saved.path()));
        return {std::move(saved), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

CoordinatorResult<std::string> FileChildCoordinator::ExecuteAnalysisTool(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, std::string_view name,
    std::string argumentsJson)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    auto* execute = command.mutable_execute_analysis_tool();
    execute->set_view_type(view.viewType);
    execute->set_name(name.data(), name.size());
    execute->set_arguments_json(std::move(argumentsJson));
    try
    {
        const auto reply = child->Call(command, view.openItem);
        if (!reply.success() || !reply.has_analysis_tool_result())
            return {{}, reply.success() ? "file child returned no analysis result" : reply.error()};
        return {reply.analysis_tool_result().json(), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

CoordinatorResult<DiffSecondary> FileChildCoordinator::StageDiffView(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view primary, std::string_view secondary, std::string key)
{
    session::BinaryViewRecord primaryView;
    session::BinaryViewRecord secondaryView;
    std::string error;
    const auto primaryChild = ChildForView(
        ownerTokenId, analysisSession, primary, primaryView, error);
    if (!primaryChild)
        return {{}, std::move(error)};
    const auto secondaryChild = ChildForView(
        ownerTokenId, analysisSession, secondary, secondaryView, error);
    if (!secondaryChild)
        return {{}, std::move(error)};
    auto random = security::GenerateHex256();
    if (!random.value)
        return {{}, random.error};
    const auto directory = primaryChild->workingDirectory / "diff";
    std::error_code filesystemError;
    std::filesystem::create_directories(directory, filesystemError);
    if (filesystemError)
        return {{}, "cannot create diff staging directory: " + filesystemError.message()};
    const auto destination = directory / (*random.value + ".bndb");
    ipc::Command command;
    auto* save = command.mutable_save_binary_view();
    save->set_view_type(secondaryView.viewType);
    save->set_destination(destination.string());
    save->set_temporary_copy(true);
    try
    {
        const auto reply = secondaryChild->Call(command, secondaryView.openItem);
        if (!reply.success() || !reply.has_binary_view_saved())
            return {{}, reply.success() ? "secondary view produced no temporary database" : reply.error()};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
    return {DiffSecondary{destination, std::move(key)}, {}};
}

CoordinatorResult<DiffSecondary> FileChildCoordinator::StageDiffFile(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view primary, const std::filesystem::path& source, std::string key)
{
    session::BinaryViewRecord primaryView;
    std::string error;
    const auto primaryChild = ChildForView(
        ownerTokenId, analysisSession, primary, primaryView, error);
    if (!primaryChild)
        return {{}, std::move(error)};
    auto random = security::GenerateHex256();
    if (!random.value)
        return {{}, random.error};
    const auto directory = primaryChild->workingDirectory / "diff";
    std::error_code filesystemError;
    std::filesystem::create_directories(directory, filesystemError);
    if (filesystemError)
        return {{}, "cannot create diff staging directory: " + filesystemError.message()};
    const auto destination = directory / (*random.value + ".bndb");
    const auto copied = platform::CopyRegularFilePrivate(source, destination);
    if (!copied.bytesCopied || !copied.error.empty())
        return {{}, copied.error};
    return {DiffSecondary{destination, std::move(key)}, {}};
}

CoordinatorResult<ipc::AnalysisFinished> FileChildCoordinator::RunDiffAndWait(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view primary, const DiffSecondary& secondary,
    AnalysisProgressCallback progress)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, primary, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    auto* execute = command.mutable_execute_analysis_tool();
    execute->set_view_type(view.viewType);
    execute->set_name("bn_diff_run");
    execute->set_arguments_json("{}");
    execute->set_secondary_path(secondary.path.string());
    execute->set_diff_key(secondary.key);
    return child->CallAndWaitForAnalysis(command, std::move(progress));
}

CoordinatorResult<std::string> FileChildCoordinator::ExecuteDiffTool(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view primary, const DiffSecondary& secondary,
    std::string_view name, std::string argumentsJson)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, primary, view, error);
    if (!child)
        return {{}, std::move(error)};
    ipc::Command command;
    auto* execute = command.mutable_execute_analysis_tool();
    execute->set_view_type(view.viewType);
    execute->set_name(name.data(), name.size());
    execute->set_arguments_json(std::move(argumentsJson));
    execute->set_diff_key(secondary.key);
    try
    {
        const auto reply = child->Call(command, view.openItem);
        if (!reply.success() || !reply.has_analysis_tool_result())
            return {{}, reply.success() ? "file child returned no diff result" : reply.error()};
        return {reply.analysis_tool_result().json(), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

std::string FileChildCoordinator::PromoteSavedBinaryView(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, const std::filesystem::path& savedDatabase)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return error;
    child->PromoteWorkingCopy(savedDatabase);
    return {};
}

std::string FileChildCoordinator::AbortAnalysis(std::string_view ownerTokenId,
    std::string_view analysisSession, std::string_view binaryView)
{
    session::BinaryViewRecord view;
    std::string error;
    const auto child = ChildForView(ownerTokenId, analysisSession, binaryView, view, error);
    if (!child)
        return error;
    ipc::Command command;
    command.mutable_abort_analysis()->set_view_type(view.viewType);
    const auto deadline = std::chrono::steady_clock::now() + config_.jobs.cancellationGrace;
    const auto forceTermination = [&]() -> std::string {
        child->MarkExited("analysis cancellation grace period expired", false);
        try
        {
            supervisor_.Terminate(child->processId);
            return {};
        }
        catch (const std::exception& exception)
        {
            return std::string("cannot terminate unresponsive file child: ") + exception.what();
        }
    };
    try
    {
        const auto reply = child->CallUntil(command, deadline);
        if (!reply.success())
            return reply.error();
    }
    catch (const std::exception&)
    {
        return forceTermination();
    }
    while (std::chrono::steady_clock::now() < deadline)
    {
        ipc::Command statusCommand;
        statusCommand.mutable_get_analysis_status()->set_view_type(view.viewType);
        try
        {
            const auto reply = child->CallUntil(statusCommand, deadline);
            if (!reply.success())
                return reply.error();
            if (!reply.has_analysis_status())
                return "file child returned no analysis status";
            if (reply.analysis_status().state() != ipc::ANALYSIS_STATE_RUNNING)
                return {};
        }
        catch (const std::exception&)
        {
            return forceTermination();
        }
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero())
            break;
        std::this_thread::sleep_for(std::min(
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
            std::chrono::milliseconds(25)));
    }
    return forceTermination();
}

std::string FileChildCoordinator::Close(
    std::string_view ownerTokenId, std::string_view openItem, bool discardUncommitted)
{
    const auto item = openItems_.FindOpenItem(ownerTokenId, openItem);
    if (!item)
        return "open item not found";
    std::shared_ptr<Child> child;
    {
        std::lock_guard lock(mutex_);
        const auto found = children_.find(std::string(openItem));
        if (found == children_.end())
            return "file child not found";
        child = found->second;
    }
    if (const auto failure = child->FailureState(); failure.failed)
    {
        if (discardUncommitted)
        {
            {
                std::lock_guard lock(mutex_);
                children_.erase(std::string(openItem));
            }
            openItems_.Close(ownerTokenId, openItem);
            CleanupWorkingDirectory(child->workingDirectory);
            return {};
        }
        std::string recoveryError;
        child = RecoverIfNeeded(openItem, std::move(child), recoveryError);
        if (!child)
            return recoveryError;
    }
    if (const auto error = child->Close(openItem, discardUncommitted); !error.empty())
        return error;
    {
        std::lock_guard lock(mutex_);
        children_.erase(std::string(openItem));
    }
    openItems_.Close(ownerTokenId, openItem);
    CleanupWorkingDirectory(child->workingDirectory);
    return {};
}

void FileChildCoordinator::CloseAnalysisSession(
    std::string_view ownerTokenId, std::string_view analysisSession)
{
    const auto items = openItems_.ListForToken(ownerTokenId);
    for (const auto& item : items)
    {
        if (item.analysisSession == analysisSession)
            Close(ownerTokenId, item.reference, true);
    }
}

void FileChildCoordinator::CloseToken(std::string_view ownerTokenId)
{
    const auto items = openItems_.ListForToken(ownerTokenId);
    for (const auto& item : items)
        Close(ownerTokenId, item.reference, true);
}

std::size_t FileChildCoordinator::Size() const
{
    std::lock_guard lock(mutex_);
    return children_.size();
}

std::shared_ptr<FileChildCoordinator::Child> FileChildCoordinator::ChildForView(
    std::string_view ownerTokenId, std::string_view analysisSession,
    std::string_view binaryView, session::BinaryViewRecord& view, std::string& error)
{
    const auto foundView = openItems_.FindView(ownerTokenId, analysisSession, binaryView);
    if (!foundView)
    {
        error = "BinaryView not found";
        return {};
    }
    view = *foundView;
    std::shared_ptr<Child> child;
    {
        std::lock_guard lock(mutex_);
        const auto found = children_.find(view.openItem);
        if (found == children_.end())
        {
            error = "file child not found";
            return {};
        }
        child = found->second;
    }
    return RecoverIfNeeded(view.openItem, std::move(child), error);
}

std::shared_ptr<FileChildCoordinator::Child> FileChildCoordinator::RecoverIfNeeded(
    std::string_view openItem, std::shared_ptr<Child> child, std::string& error)
{
    auto failure = child->FailureState();
    if (!failure.failed)
        return child;
    std::lock_guard restartLock(restartMutex_);
    {
        std::lock_guard lock(mutex_);
        const auto current = children_.find(std::string(openItem));
        if (current == children_.end())
        {
            error = "file child not found";
            return {};
        }
        child = current->second;
    }
    failure = child->FailureState();
    if (!failure.failed)
        return child;
    auto restarted = Restart(openItem, child, error);
    if (!restarted)
        return {};
    if (failure.idleNotice)
    {
        error = failure.error + "; file child was reopened, retry the request";
        return {};
    }
    return restarted;
}

std::shared_ptr<FileChildCoordinator::Child> FileChildCoordinator::Restart(
    std::string_view openItem, const std::shared_ptr<Child>& previous, std::string& error)
{
    const auto item = openItems_.FindOpenItem(previous->ownerTokenId, openItem);
    if (!item)
    {
        error = "open item disappeared during file-child recovery";
        return {};
    }
    try
    {
        supervisor_.Terminate(previous->processId);
    }
    catch (...)
    {}

    ProcessId processId = 0;
    std::unique_ptr<ipc::ByteChannel> channel;
    try
    {
        std::unique_lock<std::mutex> launchLock;
        if (launchMutex_)
            launchLock = std::unique_lock(*launchMutex_);
        processId = supervisor_.Spawn(executable_, ProcessRole::FileChild);
        channel = acceptor_.Accept(processId, ProcessRole::FileChild);
        const auto workingCopy = previous->WorkingCopy();
        auto child = std::make_shared<Child>(processId, std::move(channel),
            previous->workingDirectory, workingCopy, previous->ownerTokenId,
            previous->optionsJson, previous->reuseDatabase, eventCallback_);
        child->SetOpenItem(std::string(openItem));

        ipc::Command openCommand;
        auto* open = openCommand.mutable_open_file();
        open->set_path(workingCopy.string());
        open->set_options_json(previous->optionsJson);
        open->set_reuse_database(previous->reuseDatabase);
        const auto openReply = child->Call(openCommand, openItem);
        if (!openReply.success() || !openReply.has_file_opened())
            throw std::runtime_error(openReply.success()
                ? "reopened file child returned no open result" : openReply.error());
        for (const auto& view : item->binaryViews)
        {
            if (!view.created)
                continue;
            ipc::Command viewCommand;
            auto* openView = viewCommand.mutable_open_binary_view();
            openView->set_view_type(view.viewType);
            openView->set_options_json(view.effectiveLoadSettingsJson.empty()
                ? "{}" : view.effectiveLoadSettingsJson);
            openView->set_analyze(false);
            const auto viewReply = child->Call(viewCommand, openItem);
            if (!viewReply.success() || !viewReply.has_binary_view_opened())
                throw std::runtime_error(viewReply.success()
                    ? "reopened file child returned no BinaryView result" : viewReply.error());
        }
        {
            std::lock_guard lock(mutex_);
            const auto current = children_.find(std::string(openItem));
            if (current == children_.end() || current->second != previous)
                throw std::runtime_error("open item changed during file-child recovery");
            current->second = child;
        }
        return child;
    }
    catch (const std::exception& exception)
    {
        if (processId != 0)
        {
            try
            {
                supervisor_.Terminate(processId);
            }
            catch (...)
            {}
        }
        error = std::string("cannot reopen crashed file child: ") + exception.what();
        return {};
    }
}

void FileChildCoordinator::HandleExit(const ChildExit& exit)
{
    std::shared_ptr<Child> child;
    {
        std::lock_guard lock(mutex_);
        const auto found = std::find_if(children_.begin(), children_.end(),
            [&](const auto& entry) { return entry.second->processId == exit.processId; });
        if (found == children_.end())
            return;
        child = found->second;
    }
    child->MarkExited(ExitDescription(exit));
}

void FileChildCoordinator::CleanupWorkingDirectory(const std::filesystem::path& path) const
{
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
}
}
