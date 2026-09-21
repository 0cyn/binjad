#pragma once

#include "binjad/config.hpp"
#include "binjad/http/drogon_routes.hpp"
#include "binjad/security/token_authenticator.hpp"
#include "binjad/upload/upload_registry.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/RequestStream.h>

#include <memory>

namespace binjad::http
{
std::string ConfigureDrogonUploadStorage(
    drogon::HttpAppFramework& app, const Config& config);

class UploadRoutes : public std::enable_shared_from_this<UploadRoutes>
{
  public:
    UploadRoutes(Config config, const security::TokenAuthenticator& authenticator,
        upload::UploadRegistry& uploads);
    void Register(drogon::HttpAppFramework& app);
    void Handle(const drogon::HttpRequestPtr& request,
        drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const;

  private:
    Config config_;
    const security::TokenAuthenticator& authenticator_;
    upload::UploadRegistry& uploads_;
};

std::shared_ptr<UploadRoutes> RegisterUploadRoutes(drogon::HttpAppFramework& app,
    Config config, const security::TokenAuthenticator& authenticator,
    upload::UploadRegistry& uploads);
}
