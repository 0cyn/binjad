#pragma once

namespace binjad {
	class BinaryNinjaRuntime
	{
	public:
		explicit BinaryNinjaRuntime(bool allowUserPlugins);
		BinaryNinjaRuntime(const BinaryNinjaRuntime&) = delete;
		BinaryNinjaRuntime& operator=(const BinaryNinjaRuntime&) = delete;
		~BinaryNinjaRuntime();

	private:
		bool initialized_ = false;
	};
}  // namespace binjad
