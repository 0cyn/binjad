#pragma once

#include "binjad/Config.hpp"
#include "binjad/http/DrogonRoutes.hpp"
#include "binjad/portal/Api.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/RequestStream.h>

#include <functional>
#include <memory>

namespace binjad::http {
	class PortalRoutes : public std::enable_shared_from_this<PortalRoutes>
	{
	public:
		PortalRoutes(Config config, std::shared_ptr<portal::Api> api);
		void Register(drogon::HttpAppFramework& app);
		void HandleRoot(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;
		void HandlePublicStatus(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;
		void HandlePage(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;
		void HandleSetupPage(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;
		void HandleAsset(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;
		void HandleApi(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;

	private:
		Config config_;
		std::shared_ptr<portal::Api> api_;
	};

	std::shared_ptr<PortalRoutes> RegisterPortalRoutes(
		drogon::HttpAppFramework& app, Config config, std::shared_ptr<portal::Api> api);
}  // namespace binjad::http
