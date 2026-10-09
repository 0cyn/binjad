#pragma once

#include "binjad/overseer/ProjectChildCoordinator.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::download {
	struct PreparedProjectArtifact
	{
		std::filesystem::path path;
		std::filesystem::path workingDirectory;
		std::string attachmentName;
		std::string contentType;
		std::string sha256;
		std::uint64_t size = 0;
		std::uint64_t files = 0;
		std::uint64_t directories = 0;
		bool archive = false;
	};

	struct ProjectArtifactResult
	{
		std::optional<PreparedProjectArtifact> artifact;
		std::string error;
		bool cancelled = false;
	};

	using ProjectDownloadProgress = std::function<bool(
		std::string_view phase, std::uint64_t completed, std::uint64_t total, std::string_view message)>;

	ProjectArtifactResult PrepareProjectArtifact(overseer::ProjectChildCoordinator& coordinator,
		std::string_view project, overseer::ProjectDownloadKind kind, const std::vector<std::string>& paths,
		std::string attachmentSeed, const ProjectDownloadProgress& progress = {});
}  // namespace binjad::download
