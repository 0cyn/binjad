#include "../../security/PlatformRandom.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <limits>

namespace binjad::security {
	std::string FillSecureRandom(std::span<unsigned char> output)
	{
		if (output.size() > std::numeric_limits<ULONG>::max())
			return "random request is too large";
		const auto status =
			BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(output.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		return status == 0 ? std::string {} : "BCryptGenRandom failed with status " + std::to_string(status);
	}
}  // namespace binjad::security
