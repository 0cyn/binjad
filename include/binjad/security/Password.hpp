#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::security {
	struct Argon2Profile
	{
		std::uint32_t memoryKib;
		std::uint32_t iterations;
		std::uint32_t lanes;
		std::uint32_t saltBytes;
		std::uint32_t outputBytes;
	};

	inline constexpr Argon2Profile kPortalPasswordProfile {
		256 * 1024,
		3,
		1,
		16,
		32,
	};

	struct PasswordHashResult
	{
		std::optional<std::string> encoded;
		std::string error;
	};

	enum class PasswordVerification
	{
		Match,
		Mismatch,
		Error,
	};

	struct PasswordVerifyResult
	{
		PasswordVerification result = PasswordVerification::Error;
		std::string error;
	};

	PasswordHashResult HashPassword(std::string_view password, const Argon2Profile& profile = kPortalPasswordProfile);
	PasswordVerifyResult VerifyPassword(std::string_view password, std::string_view encoded);
	bool IsValidPortalPassword(std::string_view password);
}  // namespace binjad::security
