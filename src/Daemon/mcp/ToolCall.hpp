#pragma once

#include "binjad/Config.hpp"
#include "binjad/mcp/Foundation.hpp"
#include "binjad/security/TokenAuthenticator.hpp"
#include "binjad/session/AnalysisSessionRegistry.hpp"

#include <rapidjsonwrapper.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::overseer {
	class AnalysisScheduler;
	class FileChildCoordinator;
	class ProjectChildCoordinator;
}  // namespace binjad::overseer

namespace binjad::project {
	class LocalProjectRegistry;
}  // namespace binjad::project

namespace binjad::session {
	class JobRegistry;
	class OpenItemRegistry;
}  // namespace binjad::session

namespace binjad::upload {
	class UploadRegistry;
}

namespace binjad::download {
	class DownloadRegistry;
}

namespace binjad::mcp {
	enum class ToolCallCategory
	{
		Core,
		ProjectManagement,
		FunctionAnalysis,
		BinaryData,
		Search,
		Types,
		Annotations,
		BinaryEditing,
		History,
		HeaderParsing,
		UrlGeneration,
		Diffing,
		KernelCache,
		SharedCache,
		Debugger,
	};

	using ToolCallSchemaWriter = rapidjson::Writer<rapidjson::StringBuffer>;
	enum class ToolCallAvailability : std::uint32_t
	{
		None = 0,
		ModernProtocol = 1u << 0,
		LocalMode = 1u << 1,
		Admin = 1u << 2,
		ArbitraryPaths = 1u << 3,
		ProjectRegistration = 1u << 4,
	};

	constexpr ToolCallAvailability operator|(ToolCallAvailability left, ToolCallAvailability right)
	{
		return static_cast<ToolCallAvailability>(static_cast<std::uint32_t>(left) | static_cast<std::uint32_t>(right));
	}

	constexpr bool HasAvailability(ToolCallAvailability value, ToolCallAvailability flag)
	{
		return (static_cast<std::uint32_t>(value) & static_cast<std::uint32_t>(flag)) != 0;
	}

	struct ToolCallContext
	{
		const Config& config;
		session::AnalysisSessionRegistry& sessions;
		std::string_view serverVersion;
		session::OpenItemRegistry* openItems;
		overseer::FileChildCoordinator* fileCoordinator;
		session::JobRegistry* jobs;
		project::LocalProjectRegistry* projects;
		overseer::ProjectChildCoordinator* projectCoordinator;
		overseer::AnalysisScheduler* scheduler;
		upload::UploadRegistry* uploads;
		download::DownloadRegistry* downloads;
		const ValidatedRequest& request;
		const security::TokenRecord& principal;
		const std::optional<session::AnalysisSessionRecord>& currentSession;
		session::AnalysisSessionRegistry::Clock::time_point now;
		std::uint64_t unixNow;
		Foundation::JobProgressCallback progress;
		Foundation::AttachedJobCallback attached;
		const rapidjson::Value& arguments;
	};

	class ToolCall
	{
	public:
		ToolCall(std::string_view name, ToolCallCategory category,
			ToolCallAvailability availability = ToolCallAvailability::None);
		virtual ~ToolCall() = default;

		std::string_view Name() const { return name_; }
		std::string_view Description() const { return description_; }
		ToolCallCategory Category() const { return category_; }
		std::string_view InputSchema() const;
		std::string_view DocumentationCategory() const { return documentationCategory_; }
		ToolCallAvailability Availability() const { return availability_; }

		bool IsAvailable(const Config& config, ProtocolVersion version, security::TokenRole role) const;
		bool CanExecute(const Config& config, ProtocolVersion version, security::TokenRole role) const;
		std::string UnavailableReason(const Config& config, ProtocolVersion version, security::TokenRole role) const;
		bool ValidateArguments(const rapidjson::Value& arguments, std::string& error) const;
		virtual FoundationResult Execute(const ToolCallContext& context) const = 0;

	protected:
		void AllowRestrictedExecution() { allowRestrictedExecution_ = true; }
		virtual void WriteInputSchema(ToolCallSchemaWriter& writer) const = 0;

	private:
		std::string_view name_;
		std::string_view description_;
		ToolCallCategory category_;
		mutable std::once_flag inputSchemaOnce_;
		mutable std::string inputSchema_;
		std::string_view documentationCategory_;
		ToolCallAvailability availability_;
		bool allowRestrictedExecution_ = false;
	};

	std::string_view ToolCallCategoryName(ToolCallCategory category);
	std::string_view ToolCallCategoryId(ToolCallCategory category);
	bool ToolCallCategoryEnabled(ToolCallCategory category, const ToolConfig& config);
	bool ToolCallAdvertised(const ToolCall& tool, ToolDiscoveryMode mode);
	inline constexpr std::string_view kToolBrokerName = "bn_tools";

	const std::vector<std::unique_ptr<ToolCall>>& RegisteredToolCalls();
	const ToolCall* FindToolCall(std::string_view name);

	void RegisterToolBroker(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreSessionTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreProjectTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterProjectManagementTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreFileTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreAnalysisTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreUploadTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterCoreJobTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterFunctionAnalysisTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterBinaryDataTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterSearchTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterTypeTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterAnnotationTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterBinaryEditingTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterHistoryTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterHeaderParsingTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterUrlGenerationTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterDiffingTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterKernelCacheTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterSharedCacheTools(std::vector<std::unique_ptr<ToolCall>>& tools);
	void RegisterDebuggerTools(std::vector<std::unique_ptr<ToolCall>>& tools);

	FoundationResult ExecuteForwardedAnalysisTool(const ToolCallContext& context);
	FoundationResult ExecuteForwardedAnalysisTool(const ToolCallContext& context, std::string_view commandName);
	FoundationResult ExecuteOpenItemTool(const ToolCallContext& context);
	FoundationResult ToolCallSuccess(const ToolCallContext& context, std::string_view structured, bool isError = false);
	FoundationResult ToolCallInvalidArguments(const ToolCallContext& context, std::string message);
}  // namespace binjad::mcp
