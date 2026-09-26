#include "binjad/portal/Service.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace binjad::portal {
	namespace {
		std::uint64_t CurrentUnixSeconds()
		{
			return static_cast<std::uint64_t>(
				std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
					.count());
		}
	}  // namespace

	Service::Service(security::AccountRegistry& accounts, security::TokenRegistry& tokens, UnixNow unixNow) :
		accounts_(accounts), tokens_(tokens), unixNow_(unixNow ? std::move(unixNow) : CurrentUnixSeconds)
	{}

	void Service::SetTokenRevokedCallback(TokenRevoked callback)
	{
		tokenRevoked_ = std::move(callback);
	}

	Result<security::AccountRecord> Service::CreateInitialAccount(std::string username, std::string password)
	{
		auto created = accounts_.CreateInitial({std::move(username), std::move(password), unixNow_()});
		if (!created.record)
			return {{}, std::move(created.error)};
		return {std::move(created.record), {}};
	}

	Result<bool> Service::SetupRequired() const
	{
		return {!accounts_.Account().has_value(), {}};
	}

	security::AccountAuthenticationResult Service::Authenticate(
		std::string_view username, std::string_view password) const
	{
		return accounts_.Authenticate(username, password);
	}

	Result<security::AccountRecord> Service::CurrentAccount(const security::AccountRecord& actor) const
	{
		const auto account = accounts_.Account();
		return account && account->id == actor.id ?
			Result<security::AccountRecord> {*account, {}} :
			Result<security::AccountRecord> {{}, "account not found"};
	}

	Result<security::AccountRecord> Service::UpdatePassword(const security::AccountRecord& actor, std::string password)
	{
		if (!IsCurrent(actor))
			return {{}, "account not found"};
		auto updated = accounts_.UpdatePassword(actor.id, std::move(password));
		return {std::move(updated.record), std::move(updated.error)};
	}

	Result<security::TokenIssueResult> Service::RotateToken(
		const security::AccountRecord& actor, const TokenRequest& request)
	{
		if (!IsCurrent(actor))
			return {{}, "account not found"};
		const auto ttl = request.ttlSeconds;
		std::optional<std::uint64_t> expiresAt;
		const auto now = unixNow_();
		if (ttl != 0)
		{
			if (ttl > std::numeric_limits<std::uint64_t>::max() - now)
				return {{}, "token expiry overflows Unix time"};
			expiresAt = now + ttl;
		}
		auto issued = tokens_.ReplaceForIssuer({actor.id, security::TokenRole::Admin, {}, now, expiresAt});
		if (!issued.token)
			return {{}, std::move(issued.error)};
		if (tokenRevoked_)
		{
			for (const auto& replaced : issued.replaced)
				tokenRevoked_(replaced.id);
		}
		return {std::move(issued), {}};
	}

	Result<TokenStatus> Service::Token(const security::AccountRecord& actor) const
	{
		if (!IsCurrent(actor))
			return {{}, "account not found"};
		const auto records = tokens_.RecordsForIssuer(actor.id);
		return {TokenStatus {records.empty() ? std::nullopt : std::optional(records.front())}, {}};
	}

	Result<bool> Service::RevokeToken(const security::AccountRecord& actor)
	{
		if (!IsCurrent(actor))
			return {{}, "account not found"};
		const auto records = tokens_.RecordsForIssuer(actor.id);
		if (records.empty())
			return {false, {}};
		bool removed = false;
		if (const auto error = tokens_.Revoke(records.front().id, removed); !error.empty())
			return {{}, error};
		if (removed && tokenRevoked_)
			tokenRevoked_(records.front().id);
		return {removed, {}};
	}

	bool Service::IsCurrent(const security::AccountRecord& actor) const
	{
		const auto account = accounts_.Account();
		return account && account->id == actor.id;
	}
}  // namespace binjad::portal
