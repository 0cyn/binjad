#pragma once

#include "binjad/reference/FriendlyReference.hpp"
#include "binjad/security/IntegrityFile.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace binjad::project {
	class KnownProjectStore
	{
	public:
		KnownProjectStore(security::CredentialStore& credentials, std::filesystem::path path);

		std::string Load();
		std::vector<std::filesystem::path> Paths() const;
		std::string Add(const std::filesystem::path& path);
		std::string Remove(const std::filesystem::path& path);

	private:
		std::string Persist(const std::vector<std::filesystem::path>& paths);

		security::IntegrityFile file_;
		std::vector<std::filesystem::path> paths_;
		mutable std::mutex mutex_;
	};

	struct LocalProjectRecord
	{
		std::string reference;
		std::string internalId;
		std::filesystem::path storagePath;
		std::string name;
		std::string description;
	};

	struct LocalProjectFileRecord
	{
		std::string internalId;
		std::string path;
		std::string name;
		std::string description;
		std::int64_t creationTimestamp = 0;
		std::string project;
		std::string folderInternalId;
		std::optional<std::string> folderPath;
		std::filesystem::path backingPath;
	};

	struct LocalProjectFolderRecord
	{
		std::string internalId;
		std::string parentInternalId;
		std::string path;
		std::string name;
		std::string description;
		std::string project;
		std::optional<std::string> parentPath;
	};

	class LocalProjectRegistry
	{
	public:
		explicit LocalProjectRegistry(reference::FriendlyReferencePool& references);
		LocalProjectRegistry(const LocalProjectRegistry&) = delete;
		LocalProjectRegistry& operator=(const LocalProjectRegistry&) = delete;
		~LocalProjectRegistry();

		std::string Replace(std::vector<LocalProjectRecord> projects);
		std::string Upsert(LocalProjectRecord& project);
		std::vector<LocalProjectRecord> List() const;
		std::optional<LocalProjectRecord> Find(std::string_view reference) const;
		bool RemoveProject(std::string_view reference);
		std::string AssignFiles(std::string_view project, std::vector<LocalProjectFileRecord>& files);
		std::string AssignFolders(std::string_view project, std::vector<LocalProjectFolderRecord>& folders);
		std::optional<LocalProjectFileRecord> FindFile(std::string_view project, std::string_view path) const;
		std::optional<LocalProjectFolderRecord> FindFolderById(
			std::string_view project, std::string_view internalId) const;
		void RemoveFile(std::string_view project, std::string_view path);
		std::size_t Size() const;

	private:
		reference::FriendlyReferencePool& references_;
		std::vector<LocalProjectRecord> projects_;
		std::unordered_map<std::string, LocalProjectFileRecord> files_;
		std::unordered_map<std::string, LocalProjectFolderRecord> folders_;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::project
