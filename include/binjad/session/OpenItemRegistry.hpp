#pragma once

#include "binjad/reference/FriendlyReference.hpp"

#include <functional>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace binjad::session {
	enum class OpenItemSourceKind
	{
		ArbitraryPath,
		LocalProject,
	};

	struct BinaryViewCandidateSpec
	{
		std::string viewType;
		bool recommended = false;
		std::string loadSettingsSchemaJson;
	};

	struct BinaryViewRecord
	{
		std::string reference;
		std::string openItem;
		std::string analysisSession;
		std::string viewType;
		bool recommended = false;
		bool created = false;
		std::string loadSettingsSchemaJson;
		std::string architecture;
		std::string platform;
		std::string effectiveLoadSettingsJson;
		std::uint64_t start = 0;
		std::uint64_t end = 0;
		std::uint64_t entryPoint = 0;
	};

	struct OpenItemRecord
	{
		std::string reference;
		std::string ownerTokenId;
		std::string analysisSession;
		OpenItemSourceKind sourceKind = OpenItemSourceKind::ArbitraryPath;
		std::string source;
		std::optional<std::string> project;
		std::vector<BinaryViewRecord> binaryViews;
	};

	struct OpenItemCreateResult
	{
		std::optional<OpenItemRecord> openItem;
		std::string error;
	};

	class OpenItemRegistry
	{
	public:
		using ChangedCallback = std::function<void(std::string_view)>;

		explicit OpenItemRegistry(reference::FriendlyReferencePool& references);
		OpenItemRegistry(const OpenItemRegistry&) = delete;
		OpenItemRegistry& operator=(const OpenItemRegistry&) = delete;
		~OpenItemRegistry();

		OpenItemCreateResult Create(std::string ownerTokenId, std::string analysisSession,
			OpenItemSourceKind sourceKind, std::string source, std::optional<std::string> project,
			const std::vector<BinaryViewCandidateSpec>& candidates);
		std::vector<OpenItemRecord> ListForToken(std::string_view ownerTokenId) const;
		std::vector<BinaryViewRecord> ListViews(std::string_view ownerTokenId, std::string_view analysisSession) const;
		std::optional<OpenItemRecord> FindOpenItem(std::string_view ownerTokenId, std::string_view openItem) const;
		std::optional<BinaryViewRecord> FindView(
			std::string_view ownerTokenId, std::string_view analysisSession, std::string_view binaryView) const;
		std::optional<BinaryViewRecord> MarkViewCreated(std::string_view ownerTokenId, std::string_view analysisSession,
			std::string_view binaryView, std::string architecture = {}, std::string platform = {},
			std::string effectiveLoadSettingsJson = {}, std::uint64_t start = 0, std::uint64_t end = 0,
			std::uint64_t entryPoint = 0);
		std::optional<OpenItemRecord> UpdateSource(std::string_view ownerTokenId, std::string_view openItem,
			OpenItemSourceKind sourceKind, std::string source, std::optional<std::string> project);
		void UpdateProjectSource(std::string_view project, std::string_view oldSource, std::string newSource);
		bool HasProjectSource(std::string_view project, std::string_view source) const;
		void UpdateProjectSourcePrefix(
			std::string_view project, std::string_view oldPrefix, std::string_view newPrefix);
		bool HasProjectSourcePrefix(std::string_view project, std::string_view prefix) const;
		bool HasProject(std::string_view project) const;
		std::optional<OpenItemRecord> Close(std::string_view ownerTokenId, std::string_view openItem);
		std::vector<OpenItemRecord> CloseByAnalysisSession(std::string_view analysisSession);
		std::vector<OpenItemRecord> CloseByToken(std::string_view ownerTokenId);
		void SetChangedCallback(ChangedCallback callback);
		std::size_t Size() const;

	private:
		void ReleaseReferences(const OpenItemRecord& record);

		reference::FriendlyReferencePool& references_;
		std::unordered_map<std::string, OpenItemRecord> openItems_;
		std::unordered_map<std::string, std::string> viewOwners_;
		ChangedCallback changedCallback_;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::session
