#pragma once

#include <cstdint>

namespace binjad {
	struct AbiRange
	{
		std::uint32_t minimum;
		std::uint32_t current;
	};

	constexpr bool AbiRangesOverlap(AbiRange lhs, AbiRange rhs)
	{
		return lhs.minimum <= rhs.current && rhs.minimum <= lhs.current;
	}
}  // namespace binjad
