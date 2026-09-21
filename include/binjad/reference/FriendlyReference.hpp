#pragma once

#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace binjad::reference {
	struct FriendlyReferenceResult
	{
		std::optional<std::string> value;
		std::string error;
	};

	class FriendlyReferencePool
	{
	public:
		FriendlyReferenceResult Acquire();
		bool Release(std::string_view reference);
		std::size_t Size() const;

	private:
		mutable std::mutex mutex_;
		std::unordered_set<std::string> active_;
	};

	bool IsFriendlyReference(std::string_view reference);
	std::size_t FriendlyWordCount();
}  // namespace binjad::reference
