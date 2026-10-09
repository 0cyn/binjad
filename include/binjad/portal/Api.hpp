#pragma once

#include "binjad/Config.hpp"
#include "binjad/http/McpAdmission.hpp"
#include "binjad/mcp/Protocol.hpp"
#include "binjad/portal/ProjectManager.hpp"
#include "binjad/portal/SessionManager.hpp"
#include "binjad/portal/Service.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binjad::portal {
	struct RuntimeStatus
	{
		std::size_t analysisSessions = 0;
		std::size_t openItems = 0;
		std::size_t jobs = 0;
		std::size_t projects = 0;
		std::size_t logicalCpuCount = 0;
		std::size_t workerBudget = 0;
		std::size_t allocatedWorkers = 0;
		std::size_t activeAnalyses = 0;
		std::size_t queuedAnalyses = 0;
		std::uint64_t memoryBytes = 0;
	};

	struct ToolPackUpdate
	{
		ToolConfig tools;
		bool restartRequired = false;
	};

	struct ApiRequest
	{
		http::Method method = http::Method::Other;
		std::string path;
		std::optional<std::string> authorization;
		std::string body;
	};

	class Api
	{
	public:
		using RuntimeStatusProvider = std::function<RuntimeStatus()>;
		using ToolConfigApply = std::function<void(const ToolConfig&)>;
		using RestartCallback = std::function<void()>;
		using McpContextProvider =
			std::function<std::string(mcp::ProtocolVersion, security::TokenRole, std::string_view)>;
		using McpToolsProvider = std::function<std::string(mcp::ProtocolVersion, security::TokenRole)>;
		static constexpr std::size_t kMaxBodyBytes = 1024 * 1024;

		Api(Config config, Service& service, std::filesystem::path configPath = {});
		void SetProjectManager(std::shared_ptr<ProjectManager> manager);
		void SetSessionManager(std::shared_ptr<SessionManager> manager);
		void SetRuntimeStatusProvider(RuntimeStatusProvider callback);
		void SetToolConfigCallback(ToolConfigApply callback);
		void SetRestartCallback(RestartCallback callback);
		void SetMcpDocumentationProviders(McpContextProvider context, McpToolsProvider tools);
		ToolConfig ActiveToolConfig() const;
		Result<ToolPackUpdate> UpdateToolPacks(const std::vector<std::pair<std::string, bool>>& changes);
		http::ImmediateResponse Handle(const ApiRequest& request);
		http::ImmediateResponse PublicStatus() const;
		http::ImmediateResponse Page() const;
		http::ImmediateResponse SetupPage() const;
		http::ImmediateResponse Asset(std::string_view name) const;

	private:
		std::optional<security::AccountRecord> Authenticate(
			const ApiRequest& request, http::ImmediateResponse& error) const;
		http::ImmediateResponse RenderPage(std::string_view name) const;

		Config config_;
		Service& service_;
		std::string apiPath_;
		std::filesystem::path configPath_;
		std::shared_ptr<ProjectManager> projectManager_;
		std::shared_ptr<SessionManager> sessionManager_;
		RuntimeStatusProvider runtimeStatus_;
		ToolConfigApply toolConfigApply_;
		RestartCallback restartCallback_;
		McpContextProvider mcpContext_;
		McpToolsProvider mcpTools_;
		std::string activeConfiguration_;
		bool restartRequired_ = false;
		bool restartScheduled_ = false;
		mutable std::mutex configurationMutex_;
	};
}  // namespace binjad::portal
