#include "binjad/overseer/BinaryViewPersistence.hpp"

#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/platform/Paths.hpp"

#include <utility>

namespace binjad::overseer {
	BinaryViewPersistenceResult SaveAndCommitBinaryView(FileChildCoordinator& files, ProjectChildCoordinator* projects,
		session::OpenItemRegistry& openItems, std::string_view ownerTokenId, std::string_view analysisSession,
		std::string_view binaryView, const std::optional<std::string>& destination,
		FileChildCoordinator::AnalysisProgressCallback progress, PersistenceCancelCallback cancelled)
	{
		const auto view = openItems.FindView(ownerTokenId, analysisSession, binaryView);
		if (!view || !view->created)
			return {{}, "BinaryView not found or not materialized"};
		const auto item = openItems.FindOpenItem(ownerTokenId, view->openItem);
		if (!item || item->analysisSession != analysisSession)
			return {{}, "open item not found"};
		const auto saved = files.SaveBinaryView(ownerTokenId, analysisSession, binaryView, {}, std::move(progress));
		if (!saved.value)
			return {{}, saved.error};
		if (cancelled && cancelled())
			return {{}, {}, true};

		std::string committedDestination;
		if (item->sourceKind == session::OpenItemSourceKind::ArbitraryPath)
		{
			const auto target = destination ?
				std::filesystem::absolute(*destination).lexically_normal() :
				saved.value->created_database() ?
				std::filesystem::path(item->source + ".bndb") :
				std::filesystem::path(item->source);
			const auto original = std::filesystem::path(item->source).lexically_normal();
			const auto installed = platform::InstallRegularFileAtomically(
				saved.value->path(), target, !saved.value->created_database() && target == original);
			if (!installed.installed)
				return {{}, installed.error};
			committedDestination = target.string();
			openItems.UpdateSource(
				ownerTokenId, item->reference, session::OpenItemSourceKind::ArbitraryPath, committedDestination, {});
		}
		else
		{
			if (!item->project || !projects)
				return {{}, "local project service is unavailable"};
			const auto target =
				destination.value_or(saved.value->created_database() ? item->source + ".bndb" : item->source);
			const auto committed = projects->CommitFile(*item->project, target, saved.value->path(),
				!saved.value->created_database() && target == item->source, false, "Saved analysis database");
			if (!committed.value)
				return {{}, committed.error};
			committedDestination = committed.value->path;
			openItems.UpdateSource(ownerTokenId, item->reference, session::OpenItemSourceKind::LocalProject,
				committedDestination, item->project);
		}

		const auto promoted =
			files.PromoteSavedBinaryView(ownerTokenId, analysisSession, binaryView, saved.value->path());
		if (!promoted.empty())
			return {{}, promoted};
		return {CommittedBinaryView {std::string(binaryView), item->reference, std::move(committedDestination),
					saved.value->created_database(), item->sourceKind},
			{}};
	}
}  // namespace binjad::overseer
