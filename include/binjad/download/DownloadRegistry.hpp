#pragma once

#include "binjad/Config.hpp"
#include "binjad/project/LocalProjectRegistry.hpp"
#include "binjad/session/AnalysisSessionRegistry.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binjad::download {
	inline constexpr std::chrono::seconds kDownloadTtl {3600};

	struct DownloadRecord
	{
		std::string ownerTokenId;
		std::string analysisSession;
		std::string project;
		std::filesystem::path artifactPath;
		std::filesystem::path workingDirectory;
		std::string attachmentName;
		std::string contentType;
		std::string sha256;
		std::uint64_t size = 0;
		std::uint64_t createdAtUnix = 0;
		std::uint64_t expiresAtUnix = 0;
		bool consumed = false;
	};

	struct DownloadIssueResult
	{
		std::optional<DownloadRecord> download;
		std::string url;
		std::string error;
	};

	class DownloadRegistry
	{
	public:
		using Clock = session::AnalysisSessionRegistry::Clock;

		DownloadRegistry(
			Config config, session::AnalysisSessionRegistry& sessions, project::LocalProjectRegistry& projects);
		DownloadRegistry(const DownloadRegistry&) = delete;
		DownloadRegistry& operator=(const DownloadRegistry&) = delete;
		~DownloadRegistry();

		DownloadIssueResult Issue(std::string ownerTokenId, std::string analysisSession, std::string project,
			std::filesystem::path artifactPath, std::filesystem::path workingDirectory, std::string attachmentName,
			std::string contentType, std::uint64_t size, std::string sha256, std::uint64_t nowUnix,
			Clock::time_point now);
		std::optional<DownloadRecord> Claim(std::string_view capability, Clock::time_point now);
		void RemoveByAnalysisSession(std::string_view analysisSession);
		void RemoveByToken(std::string_view ownerTokenId);
		void Sweep(Clock::time_point now);
		std::size_t Size() const;

	private:
		struct Entry
		{
			DownloadRecord record;
			Clock::time_point expiresAt;
		};

		using EntryMap = std::unordered_map<std::string, Entry>;
		void RemoveEntry(EntryMap::iterator entry);

		Config config_;
		session::AnalysisSessionRegistry& sessions_;
		project::LocalProjectRegistry& projects_;
		EntryMap downloads_;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::download
