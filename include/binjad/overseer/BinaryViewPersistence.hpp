#pragma once

#include "binjad/overseer/FileChildCoordinator.hpp"
#include "binjad/session/OpenItemRegistry.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::overseer {
	class ProjectChildCoordinator;

	struct CommittedBinaryView
	{
		std::string binaryView;
		std::string openItem;
		std::string destination;
		bool createdDatabase = false;
		session::OpenItemSourceKind sourceKind = session::OpenItemSourceKind::ArbitraryPath;
	};

	struct BinaryViewPersistenceResult
	{
		std::optional<CommittedBinaryView> value;
		std::string error;
		bool cancelled = false;
	};

	using PersistenceCancelCallback = std::function<bool()>;

	BinaryViewPersistenceResult SaveAndCommitBinaryView(FileChildCoordinator& files, ProjectChildCoordinator* projects,
		session::OpenItemRegistry& openItems, std::string_view ownerTokenId, std::string_view analysisSession,
		std::string_view binaryView, const std::optional<std::string>& destination = {},
		FileChildCoordinator::AnalysisProgressCallback progress = {}, PersistenceCancelCallback cancelled = {});
}  // namespace binjad::overseer
