#include "../../security/PlatformRandom.hpp"

#include <cerrno>
#include <cstring>
#include <sys/random.h>

namespace binjad::security {
	std::string FillSecureRandom(std::span<unsigned char> output)
	{
		while (!output.empty())
		{
			const auto count = ::getrandom(output.data(), output.size(), 0);
			if (count > 0)
			{
				output = output.subspan(static_cast<std::size_t>(count));
				continue;
			}
			if (count < 0 && errno == EINTR)
				continue;
			return std::string("getrandom failed: ") + std::strerror(errno);
		}
		return {};
	}
}  // namespace binjad::security
