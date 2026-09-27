#include "binjad/http/McpDispatcher.hpp"

#include "binjad/mcp/Protocol.hpp"

#include <drogon/HttpResponse.h>

#include <chrono>
#include <optional>
#include <string_view>
#include <utility>

namespace binjad::http {
	namespace {
		drogon::HttpResponsePtr JsonResponse(int status, std::string body)
		{
			auto response = drogon::HttpResponse::newHttpResponse();
			response->setStatusCode(static_cast<drogon::HttpStatusCode>(status));
			response->setContentTypeString("application/json");
			response->setBody(std::move(body));
			response->addHeader("Cache-Control", "no-store");
			return response;
		}

		drogon::HttpResponsePtr EmptyResponse(int status)
		{
			auto response = drogon::HttpResponse::newHttpResponse();
			response->setStatusCode(static_cast<drogon::HttpStatusCode>(status));
			response->addHeader("Cache-Control", "no-store");
			return response;
		}

		drogon::HttpResponsePtr ErrorResponse(mcp::ProtocolError error)
		{
			return JsonResponse(error.httpStatus, mcp::BuildErrorResponse(error));
		}

		mcp::ProtocolError SessionNotFound(const std::optional<mcp::RequestId>& id = std::nullopt)
		{
			return {-32001, 404, "session not found", id, {}};
		}

		std::uint64_t CurrentUnixSeconds()
		{
			return static_cast<std::uint64_t>(
				std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
					.count());
		}
	}  // namespace

	McpDispatcher::McpDispatcher(
		session::AnalysisSessionRegistry& sessions, std::string serverVersion, SteadyNow steadyNow, UnixNow unixNow) :
		McpDispatcher(sessions, std::move(serverVersion), Config {}, std::move(steadyNow), std::move(unixNow))
	{}

	std::string McpDispatcher::ContextDocumentation(
		mcp::ProtocolVersion version, security::TokenRole role, std::string_view clientName) const
	{
		return foundation_.ContextDocumentation(version, role, clientName);
	}

	std::string McpDispatcher::ToolDocumentation(mcp::ProtocolVersion version, security::TokenRole role) const
	{
		return foundation_.ToolDocumentation(version, role);
	}

	void McpDispatcher::SetToolConfig(ToolConfig config)
	{
		foundation_.SetToolConfig(std::move(config));
		subscriptions_->PublishToolsListChanged();
	}

	McpDispatcher::McpDispatcher(session::AnalysisSessionRegistry& sessions, std::string serverVersion, Config config,
		SteadyNow steadyNow, UnixNow unixNow) :
		McpDispatcher(sessions, std::move(serverVersion), std::move(config), nullptr, nullptr, nullptr, nullptr,
			nullptr, nullptr, nullptr, std::move(steadyNow), std::move(unixNow))
	{}

	McpDispatcher::McpDispatcher(session::AnalysisSessionRegistry& sessions, std::string serverVersion, Config config,
		session::OpenItemRegistry* openItems, overseer::FileChildCoordinator* fileCoordinator,
		session::JobRegistry* jobs, project::LocalProjectRegistry* projects,
		overseer::ProjectChildCoordinator* projectCoordinator, overseer::AnalysisScheduler* scheduler,
		upload::UploadRegistry* uploads, SteadyNow steadyNow, UnixNow unixNow,
		std::shared_ptr<session::SubscriptionRegistry> subscriptions) :
		sessions_(sessions), serverVersion_(std::move(serverVersion)),
		foundation_(std::move(config), sessions, serverVersion_, openItems, fileCoordinator, jobs, projects,
			projectCoordinator, scheduler, uploads),
		steadyNow_(steadyNow ? std::move(steadyNow) : [] { return session::AnalysisSessionRegistry::Clock::now(); }),
		unixNow_(unixNow ? std::move(unixNow) : CurrentUnixSeconds),
		subscriptions_(subscriptions ? std::move(subscriptions) : std::make_shared<session::SubscriptionRegistry>())
	{}

	void McpDispatcher::Handle(AdmittedMcpRequest request, DrogonResponseCallback callback)
	{
		const auto steadyNow = steadyNow_();
		if (request.method == Method::Get || request.method == Method::Delete)
		{
			if (!request.sessionId || !sessions_.FindLegacy(*request.sessionId, request.principal.id, steadyNow))
			{
				callback(ErrorResponse(SessionNotFound()));
				return;
			}
			if (request.method == Method::Delete)
			{
				callback(EmptyResponse(204));
				return;
			}
			if (!request.notification || !request.attachedSubscription)
			{
				callback(ErrorResponse({-32020, 406, "legacy GET requires Accept: text/event-stream", {}, {}}));
				return;
			}
			const auto session = sessions_.FindLegacy(*request.sessionId, request.principal.id, steadyNow, false);
			if (!sessions_.Retain(session->reference, request.principal.id, steadyNow))
			{
				callback(ErrorResponse(SessionNotFound()));
				return;
			}
			const auto listener =
				subscriptions_->ListenLegacy(session->reference, request.principal.id, request.notification);
			request.attachedSubscription(
				[weak = std::weak_ptr(subscriptions_), listener, sessions = &sessions_, owner = request.principal.id,
					session = session->reference] {
					if (const auto subscriptions = weak.lock())
						subscriptions->RemoveListener(listener);
					sessions->Release(session, owner);
				});
			return;
		}
		if (request.method != Method::Post)
		{
			callback(ErrorResponse({-32600, 405, "unsupported HTTP method", {}, {}}));
			return;
		}

		std::optional<mcp::ProtocolVersion> legacyVersion;
		std::optional<session::AnalysisSessionRecord> legacySession;
		if (request.sessionId)
		{
			legacySession = sessions_.FindLegacy(*request.sessionId, request.principal.id, steadyNow, false);
			if (!legacySession)
			{
				callback(ErrorResponse(SessionNotFound()));
				return;
			}
			legacyVersion = legacySession->legacyVersion;
		}
		const auto validated = mcp::ValidateRequest(request.body, request.transportHeaders, legacyVersion);
		if (validated.error)
		{
			callback(ErrorResponse(*validated.error));
			return;
		}
		const auto& message = *validated.request;
		if (message.method == "initialize")
		{
			if (request.sessionId)
			{
				callback(ErrorResponse({-32600, 400, "initialize must not carry Mcp-Session-Id", message.id, {}}));
				return;
			}
			const auto created = sessions_.Create(request.principal.id, unixNow_(), steadyNow, message.version);
			if (!created.session)
			{
				callback(ErrorResponse({-32603, 500, "cannot create session", message.id, {}}));
				return;
			}
			auto response =
				JsonResponse(200, mcp::BuildInitializeResponse(*message.id, message.version, serverVersion_));
			response->addHeader("Mcp-Session-Id", *created.session->legacyTransportId);
			response->addHeader("MCP-Protocol-Version", std::string(mcp::ToString(message.version)));
			callback(response);
			subscriptions_->PublishResource(request.principal.id, "binjad://analysis-sessions");
			return;
		}

		std::optional<session::AnalysisSessionRecord> analysisSession;
		if (mcp::IsModern(message.version) && !message.analysisSession.empty())
		{
			analysisSession = sessions_.Find(message.analysisSession, request.principal.id, steadyNow);
			if (!analysisSession)
			{
				callback(ErrorResponse(SessionNotFound(message.id)));
				return;
			}
		}
		else if (!mcp::IsModern(message.version))
		{
			analysisSession = sessions_.FindLegacy(*request.sessionId, request.principal.id, steadyNow);
			if (!analysisSession)
			{
				callback(ErrorResponse(SessionNotFound(message.id)));
				return;
			}
		}

		if (message.method == "server/discover")
		{
			auto response = JsonResponse(200, mcp::BuildDiscoveryResponse(*message.id, serverVersion_));
			response->addHeader("Cache-Control", "private, max-age=60");
			callback(response);
			return;
		}
		if (message.method == "ping")
		{
			callback(JsonResponse(200, mcp::BuildEmptyResultResponse(*message.id, message.version, serverVersion_)));
			return;
		}
		if (message.method == "resources/subscribe" || message.method == "resources/unsubscribe")
		{
			if (!analysisSession)
			{
				callback(ErrorResponse(SessionNotFound(message.id)));
				return;
			}
			if (message.method == "resources/subscribe")
				subscriptions_->SubscribeLegacy(analysisSession->reference, request.principal.id, message.uri);
			else
				subscriptions_->UnsubscribeLegacy(analysisSession->reference, request.principal.id, message.uri);
			callback(JsonResponse(200, mcp::BuildEmptyResultResponse(*message.id, message.version, serverVersion_)));
			return;
		}
		if (message.method == "subscriptions/listen")
		{
			if (!request.notification || !request.attachedSubscription || !message.subscription)
			{
				callback(ErrorResponse(
					{-32020, 406, "subscriptions/listen requires Accept: text/event-stream", message.id, {}}));
				return;
			}
			if (analysisSession && !sessions_.Retain(analysisSession->reference, request.principal.id, steadyNow))
			{
				callback(ErrorResponse(SessionNotFound(message.id)));
				return;
			}
			const auto listener =
				subscriptions_->ListenModern(request.principal.id, *message.subscription, request.notification);
			request.attachedSubscription(
				[weak = std::weak_ptr(subscriptions_), listener, sessions = &sessions_, owner = request.principal.id,
					session = analysisSession ? analysisSession->reference : std::string {}] {
					if (const auto subscriptions = weak.lock())
						subscriptions->RemoveListener(listener);
					if (!session.empty())
						sessions->Release(session, owner);
				});
			request.notification(mcp::BuildSubscriptionAcknowledgement(*message.id, *message.subscription));
			return;
		}
		if (message.notification)
		{
			callback(EmptyResponse(202));
			return;
		}
		const auto foundation = foundation_.Handle(message, request.principal, analysisSession, steadyNow, unixNow_(),
			std::move(request.progress), std::move(request.attachedJob));
		if (foundation.error)
		{
			callback(ErrorResponse(*foundation.error));
			return;
		}
		if (foundation.handled)
		{
			callback(JsonResponse(foundation.httpStatus, foundation.body));
			if (foundation.invokedTool.empty())
				PublishChanges(message, request.principal, analysisSession);
			else
			{
				auto invoked = message;
				invoked.name = foundation.invokedTool;
				PublishChanges(invoked, request.principal, analysisSession);
			}
			return;
		}
		callback(ErrorResponse(
			{-32601, mcp::IsModern(message.version) ? 404 : 200, "method not implemented", message.id, {}}));
	}

	std::shared_ptr<session::SubscriptionRegistry> McpDispatcher::Subscriptions() const
	{
		return subscriptions_;
	}

	void McpDispatcher::PublishChanges(const mcp::ValidatedRequest& request, const security::TokenRecord& principal,
		const std::optional<session::AnalysisSessionRecord>& analysisSession) const
	{
		if (request.method != "tools/call")
			return;
		if (request.name == "bn_analysis_session_create" || request.name == "bn_analysis_session_close")
			subscriptions_->PublishResource(principal.id, "binjad://analysis-sessions");
		const bool jobChanged = request.name == "bn_job_cancel" || request.name == "bn_job_result"
			|| request.name == "bn_analysis_update_async" || request.name == "bn_binary_view_save_async"
			|| request.name == "bn_local_project_directory_import" || request.name == "bn_local_project_relocate";
		if (jobChanged)
			subscriptions_->PublishResource(principal.id, "binjad://jobs");
		const bool computeChanged = request.name == "bn_analysis_update" || request.name == "bn_analysis_update_async"
			|| request.name == "bn_analysis_update_and_wait" || request.name == "bn_analysis_abort"
			|| request.name == "bn_job_cancel";
		if (computeChanged)
			subscriptions_->PublishResource(principal.id, "binjad://compute");
		const bool localProjectChanged = request.name == "bn_local_project_create"
			|| request.name == "bn_local_project_register" || request.name == "bn_local_project_file_import"
			|| request.name == "bn_local_project_file_import_batch"
			|| request.name == "bn_local_project_directory_import" || request.name == "bn_local_project_relocate"
			|| request.name == "bn_local_project_update" || request.name == "bn_local_project_folder_create"
			|| request.name == "bn_local_project_folder_update" || request.name == "bn_local_project_folder_delete"
			|| request.name == "bn_local_project_file_update" || request.name == "bn_local_project_file_delete"
			|| request.name == "bn_upload_commit";
		if (localProjectChanged)
			subscriptions_->PublishResource(principal.id, "binjad://local-projects");
		if (analysisSession && jobChanged)
			subscriptions_->PublishResource(principal.id, "binjad://analysis-sessions/" + analysisSession->reference);
	}
}  // namespace binjad::http
