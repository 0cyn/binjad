#pragma once

#include "binjad/download/DownloadRegistry.hpp"
#include "binjad/http/DrogonRoutes.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/RequestStream.h>

#include <memory>

namespace binjad::http {
	class DownloadRoutes : public std::enable_shared_from_this<DownloadRoutes>
	{
	public:
		explicit DownloadRoutes(download::DownloadRegistry& downloads);
		void Register(drogon::HttpAppFramework& app);
		void Handle(const drogon::HttpRequestPtr& request, drogon::RequestStreamPtr stream,
			DrogonResponseCallback callback) const;

	private:
		download::DownloadRegistry& downloads_;
	};

	std::shared_ptr<DownloadRoutes> RegisterDownloadRoutes(
		drogon::HttpAppFramework& app, download::DownloadRegistry& downloads);
}  // namespace binjad::http
