#pragma once

#include "binjad/portal/Service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::portal {
	struct RecoveryView
	{
		std::string reference;
		std::string openItem;
		std::string viewType;
		std::string architecture;
		std::string platform;
		bool recommended = false;
		bool created = false;
		bool statusAvailable = false;
		std::string analysisState;
		bool modified = false;
		bool analysisChanged = false;
		std::uint64_t completed = 0;
		std::uint64_t total = 0;
		std::string error;
	};

	struct RecoveryOpenItem
	{
		std::string reference;
		std::string sourceKind;
		std::string source;
		std::optional<std::string> project;
		std::vector<RecoveryView> views;
	};

	struct RecoveryJob
	{
		std::string reference;
		std::string operation;
		std::string state;
		std::optional<std::string> binaryView;
		std::uint64_t createdAt = 0;
		std::uint64_t updatedAt = 0;
		std::string phase;
		std::uint64_t completed = 0;
		std::uint64_t total = 0;
		std::string message;
		bool cancelRequested = false;
	};

	struct RecoverySessionSummary
	{
		std::string reference;
		std::uint64_t createdAt = 0;
		std::uint64_t inactiveSeconds = 0;
		bool legacy = false;
		std::size_t retainers = 0;
		std::size_t openItems = 0;
		std::size_t jobs = 0;
		std::size_t activeJobs = 0;
	};

	struct RecoverySessionDetails
	{
		RecoverySessionSummary session;
		std::vector<RecoveryOpenItem> openItems;
		std::vector<RecoveryJob> jobs;
	};

	struct RecoverySave
	{
		std::string binaryView;
		std::string openItem;
		std::string destination;
		std::string sourceKind;
		bool createdDatabase = false;
	};

	struct RecoverySaveFailure
	{
		std::string binaryView;
		std::string source;
		std::string error;
	};

	struct RecoveryBatchSave
	{
		std::vector<RecoverySave> saved;
		std::vector<RecoverySaveFailure> failed;
		std::size_t skipped = 0;
	};

	class SessionManager
	{
	public:
		virtual ~SessionManager() = default;

		virtual Result<std::vector<RecoverySessionSummary>> List(std::string_view ownerTokenId) = 0;
		virtual Result<RecoverySessionDetails> Details(
			std::string_view ownerTokenId, std::string_view analysisSession) = 0;
		virtual Result<RecoverySave> Save(std::string_view ownerTokenId, std::string_view analysisSession,
			std::string_view binaryView, std::optional<std::string> destination) = 0;
		virtual Result<RecoveryBatchSave> SaveAll(std::string_view ownerTokenId, std::string_view analysisSession) = 0;
		virtual Result<bool> Abort(
			std::string_view ownerTokenId, std::string_view analysisSession, std::string_view binaryView) = 0;
		virtual Result<bool> CancelJob(
			std::string_view ownerTokenId, std::string_view analysisSession, std::string_view job) = 0;
		virtual Result<bool> CloseItem(std::string_view ownerTokenId, std::string_view analysisSession,
			std::string_view openItem, bool discard) = 0;
		virtual Result<bool> ForceClose(std::string_view ownerTokenId, std::string_view analysisSession) = 0;
	};
}  // namespace binjad::portal
