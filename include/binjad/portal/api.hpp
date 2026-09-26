#pragma once

#include "binjad/Config.hpp"
#include "binjad/http/McpAdmission.hpp"
#include "binjad/mcp/Protocol.hpp"
#include "binjad/portal/Service.hpp"

#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::portal {
	struct ProjectSummary
	{
		std::string reference;
		std::string name;
		std::string description;
	};

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
	};

	struct ApiRequest
	{
		http::Method method = http::Method::Other;
		std::string path;
		std::optional<std::string> origin;
		std::optional<std::string> authorization;
		std::string body;
	};

	class Api
	{
	public:
		using ProjectCreate =
			std::function<Result<ProjectSummary>(std::string, std::optional<std::string>, std::string)>;
		using ProjectDelete = std::function<Result<bool>(std::string_view)>;
		using ProjectList = std::function<std::vector<ProjectSummary>()>;
		using RuntimeStatusProvider = std::function<RuntimeStatus()>;
		using ToolConfigApply = std::function<void(const ToolConfig&)>;
		using McpContextProvider =
			std::function<std::string(mcp::ProtocolVersion, security::TokenRole, std::string_view)>;
		using McpToolsProvider = std::function<std::string(mcp::ProtocolVersion, security::TokenRole)>;
		static constexpr std::size_t kMaxBodyBytes = 1024 * 1024;

		Api(Config config, Service& service, std::filesystem::path configPath = {});
		void SetProjectCreateCallback(ProjectCreate callback);
		void SetProjectDeleteCallback(ProjectDelete callback);
		void SetProjectListCallback(ProjectList callback);
		void SetRuntimeStatusProvider(RuntimeStatusProvider callback);
		void SetToolConfigCallback(ToolConfigApply callback);
		void SetMcpDocumentationProviders(McpContextProvider context, McpToolsProvider tools);
		http::ImmediateResponse Handle(const ApiRequest& request);
		http::ImmediateResponse Page() const;
		http::ImmediateResponse Asset(std::string_view name) const;

	private:
		std::optional<security::AccountRecord> Authenticate(
			const ApiRequest& request, http::ImmediateResponse& error) const;
		bool AllowedOrigin(const std::optional<std::string>& origin) const;

		Config config_;
		Service& service_;
		std::string apiPath_;
		std::filesystem::path configPath_;
		ProjectCreate projectCreate_;
		ProjectDelete projectDelete_;
		ProjectList projectList_;
		RuntimeStatusProvider runtimeStatus_;
		ToolConfigApply toolConfigApply_;
		McpContextProvider mcpContext_;
		McpToolsProvider mcpTools_;
		std::string activeConfiguration_;
		bool restartRequired_ = false;
		mutable std::mutex configurationMutex_;
	};
}  // namespace binjad::portal
