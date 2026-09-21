#pragma once

#include <binaryninjaapi.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <thread>

namespace binjad::binary_ninja {
	class DiffTools
	{
	public:
		using ProgressCallback = std::function<void(double)>;
		using CompletionCallback = std::function<void(bool, std::string)>;

		DiffTools() = default;
		DiffTools(const DiffTools&) = delete;
		DiffTools& operator=(const DiffTools&) = delete;
		~DiffTools();

		std::string Begin(BinaryNinja::Ref<BinaryNinja::BinaryView> primary, std::string key,
			const std::string& secondaryDatabase, ProgressCallback progress, CompletionCallback completion);

		struct State
		{
			BinaryNinja::Ref<BinaryNinja::BinaryView> primary;
			BinaryNinja::Ref<BinaryNinja::BinaryView> secondary;
			BinaryNinja::Ref<BinaryNinja::FileMetadata> secondaryFile;
			BinaryNinja::Ref<BinaryNinja::SimilaritySession> session;
			BinaryNinja::Ref<BinaryNinja::SimilarityProvider> provider;
			BinaryNinja::Ref<BinaryNinja::SimilaritySessionNode> primaryNode;
			BinaryNinja::Ref<BinaryNinja::SimilaritySessionNode> secondaryNode;
			BinaryNinja::Ref<BinaryNinja::SimilaritySessionCompletion> completion;
			std::atomic<bool> finished {false};
			std::atomic<bool> succeeded {false};

			~State();
		};

		std::shared_ptr<State> Find(std::string_view key, BinaryNinja::BinaryView& primary) const;
		std::string Release(std::string_view key);
		void Close() noexcept;

	private:
		mutable std::mutex mutex_;
		std::unordered_map<std::string, std::shared_ptr<State>> states_;
		std::vector<std::jthread> workers_;
	};
}  // namespace binjad::binary_ninja
