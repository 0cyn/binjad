#include "binjad/platform/Cpu.hpp"

#include <Windows.h>

namespace binjad::platform {
	CpuCapacityResult ActiveLogicalCpuCount()
	{
		const auto count = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		if (count == 0)
			return {{}, "cannot query active logical CPU count"};
		return {static_cast<std::size_t>(count), {}};
	}
}  // namespace binjad::platform
