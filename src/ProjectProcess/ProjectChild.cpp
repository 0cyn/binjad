#include "binjad/worker/ProjectChild.hpp"

#include "binjad/binary_ninja/Runtime.hpp"
#include "binjad/ipc/Envelope.hpp"
#include "binjad/platform/Paths.hpp"

#include <binaryninjaapi.h>
#include <rapidjsonwrapper.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace binjad {
	namespace {
		std::string ExternalProjectPath(std::string path)
		{
			while (!path.empty() && (path.front() == '/' || path.front() == '\\'))
				path.erase(path.begin());
			return path;
		}

		std::runtime_error ProjectMutationError(std::string_view operation)
		{
			return std::runtime_error(std::string(operation) +
        "; ask the user to close this project in the Binary Ninja GUI and retry "
        "because it may be open in another process or read-only");
		}

		std::string FolderPath(BinaryNinja::Ref<BinaryNinja::ProjectFolder> folder)
		{
			std::vector<std::string> components;
			while (folder)
			{
				components.push_back(folder->GetName());
				folder = folder->GetParent();
			}
			std::reverse(components.begin(), components.end());
			std::filesystem::path result;
			for (const auto& component : components)
				result /= component;
			return result.generic_string();
		}

		class ProjectScope
		{
		public:
			explicit ProjectScope(const std::string& path) : project_(BinaryNinja::Project::OpenProject(path))
			{
				if (!project_)
					throw std::runtime_error("cannot open Binary Ninja project");
				if (!project_->IsOpen() && !project_->Open())
					throw ProjectMutationError("cannot acquire Binary Ninja project lock");
			}

			explicit ProjectScope(BinaryNinja::Ref<BinaryNinja::Project> project) : project_(std::move(project))
			{
				if (!project_)
					throw std::runtime_error("cannot create Binary Ninja project");
			}

			~ProjectScope()
			{
				if (project_ && project_->IsOpen())
					project_->Close();
			}

			BinaryNinja::Project* operator->() const { return project_.GetPtr(); }

			void Close()
			{
				if (project_ && project_->IsOpen() && !project_->Close())
					throw std::runtime_error("cannot release Binary Ninja project lock");
				project_ = nullptr;
			}

		private:
			BinaryNinja::Ref<BinaryNinja::Project> project_;
		};

		void FillProject(ipc::LocalProject& row, ProjectScope& project)
		{
			row.set_id(project->GetId());
			row.set_path(project->GetPath());
			row.set_name(project->GetName());
			row.set_description(project->GetDescription());
		}

		void FillFolder(ipc::LocalProjectFolder& row, const BinaryNinja::Ref<BinaryNinja::ProjectFolder>& folder)
		{
			row.set_id(folder->GetId());
			if (const auto parent = folder->GetParent())
				row.set_parent_id(parent->GetId());
			row.set_path(FolderPath(folder));
			row.set_name(folder->GetName());
			row.set_description(folder->GetDescription());
		}

		void FillFile(ipc::LocalProjectFile& row, const BinaryNinja::Ref<BinaryNinja::ProjectFile>& file)
		{
			row.set_id(file->GetId());
			row.set_path(ExternalProjectPath(file->GetPathInProject()));
			row.set_name(file->GetName());
			row.set_description(file->GetDescription());
			row.set_creation_timestamp(file->GetCreationTimestamp());
			row.set_backing_path(file->GetPathOnDisk());
			if (const auto folder = file->GetFolder())
				row.set_folder_id(folder->GetId());
		}

		std::vector<BinaryNinja::Ref<BinaryNinja::ProjectFile>> FilesByExternalPath(
			ProjectScope& project, const std::string& path)
		{
			auto matches = project->GetFilesByPathInProject(path);
			if (matches.empty())
				matches = project->GetFilesByPathInProject('/' + path);
			return matches;
		}

		std::vector<std::filesystem::path> Discover(const ipc::ScanLocalProjects& command)
		{
			std::vector<std::filesystem::path> projects;
			for (const auto& rootString : command.roots())
			{
				const std::filesystem::path root(rootString);
				std::error_code error;
				if (!std::filesystem::is_directory(root, error) || error)
					throw std::runtime_error("project root is not a directory: " + root.string());
				std::filesystem::recursive_directory_iterator iterator(root, error);
				const std::filesystem::recursive_directory_iterator end;
				if (error)
					throw std::runtime_error("cannot scan project root: " + error.message());
				while (iterator != end)
				{
					const auto entry = *iterator;
					const auto extension = entry.path().extension();
					std::error_code statusError;
					if (entry.is_directory(statusError)
						&& entry.path().filename().string().starts_with(".binjad-staging-"))
					{
						iterator.disable_recursion_pending();
					}
					else if (!statusError && entry.is_directory(statusError) && extension == ".bnpr")
					{
						projects.push_back(entry.path().lexically_normal());
						iterator.disable_recursion_pending();
					}
					else if (!statusError && entry.is_regular_file(statusError) && extension == ".bnpm")
					{
						projects.push_back(entry.path().lexically_normal());
					}
					iterator.increment(error);
					if (error)
						throw std::runtime_error("cannot scan project root: " + error.message());
				}
			}
			for (const auto& projectString : command.projects())
			{
				const std::filesystem::path project(projectString);
				const auto extension = project.extension();
				std::error_code error;
				const bool valid = extension == ".bnpr" ?
					std::filesystem::is_directory(project, error) :
					extension == ".bnpm" && std::filesystem::is_regular_file(project, error);
				if (error || !valid)
					throw std::runtime_error(
						"registered project path is not a .bnpr or .bnpm project: " + project.string());
				projects.push_back(project.lexically_normal());
			}
			std::sort(projects.begin(), projects.end());
			projects.erase(std::unique(projects.begin(), projects.end()), projects.end());
			return projects;
		}

		class ProjectChild
		{
		public:
			explicit ProjectChild(std::unique_ptr<ipc::ByteChannel> channel) :
				channel_(std::move(channel)), runtime_(true)
			{}

			int Run()
			{
				try
				{
					bool running = true;
					while (running)
					{
						const auto envelope = ipc::ReceiveEnvelope(*channel_);
						if (!envelope.has_command() || envelope.request_id() == 0)
						{
							Failure(envelope.request_id(), "expected a command with a nonzero request ID");
							continue;
						}
						Dispatch(envelope, running);
					}
					return EXIT_SUCCESS;
				}
				catch (...)
				{
					return EXIT_FAILURE;
				}
			}

		private:
			void Dispatch(const ipc::Envelope& envelope, bool& running)
			{
				try
				{
					const auto& command = envelope.command();
					ipc::Reply reply;
					reply.set_success(true);
					if (command.has_scan_local_projects())
						Scan(command.scan_local_projects(), *reply.mutable_local_project_catalog());
					else if (command.has_list_local_project_files())
						ListFiles(command.list_local_project_files(), *reply.mutable_local_project_files());
					else if (command.has_export_local_project_file())
						Export(command.export_local_project_file(), *reply.mutable_local_project_file_exported());
					else if (command.has_commit_local_project_file())
						Commit(command.commit_local_project_file(), *reply.mutable_local_project_file_committed());
					else if (command.has_create_local_project())
						CreateProject(command.create_local_project(), *reply.mutable_local_project());
					else if (command.has_update_local_project())
						UpdateProject(command.update_local_project(), *reply.mutable_local_project());
					else if (command.has_list_local_project_folders())
						ListFolders(command.list_local_project_folders(), *reply.mutable_local_project_folders());
					else if (command.has_create_local_project_folder())
						CreateFolder(command.create_local_project_folder(), *reply.mutable_local_project_folder());
					else if (command.has_update_local_project_folder())
						UpdateFolder(command.update_local_project_folder(), *reply.mutable_local_project_folder());
					else if (command.has_delete_local_project_folder())
						DeleteFolder(command.delete_local_project_folder());
					else if (command.has_update_local_project_file())
						UpdateFile(command.update_local_project_file(), *reply.mutable_local_project_file());
					else if (command.has_delete_local_project_file())
						DeleteFile(command.delete_local_project_file());
					else if (command.has_delete_local_project())
						DeleteProject(command.delete_local_project());
					else if (command.has_shutdown())
						running = false;
					else
						throw std::invalid_argument("command is not valid for a project child");
					Send(envelope.request_id(), reply);
				}
				catch (const std::exception& exception)
				{
					Failure(envelope.request_id(), exception.what());
				}
			}

			void Scan(const ipc::ScanLocalProjects& command, ipc::LocalProjectCatalog& result)
			{
				std::map<std::string, std::filesystem::path> ids;
				for (const auto& path : Discover(command))
				{
					ProjectScope project(path.string());
					const auto id = project->GetId();
					if (id.empty())
						throw std::runtime_error("project has no durable ID: " + path.string());
					if (const auto duplicate = ids.find(id); duplicate != ids.end())
						throw std::runtime_error(
							"duplicate project ID at " + duplicate->second.string() + " and " + path.string());
					ids.emplace(id, path);
					auto* row = result.add_projects();
					row->set_id(id);
					row->set_path(path.string());
					row->set_name(project->GetName());
					row->set_description(project->GetDescription());
					project.Close();
				}
			}

			void ListFiles(const ipc::ListLocalProjectFiles& command, ipc::LocalProjectFiles& result)
			{
				ProjectScope project(command.project_path());
				auto files = project->GetFiles();
				std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
					return left->GetPathInProject() < right->GetPathInProject();
				});
				for (const auto& file : files)
				{
					FillFile(*result.add_files(), file);
				}
				files.clear();
				project.Close();
			}

			void Export(const ipc::ExportLocalProjectFile& command, ipc::LocalProjectFileExported& result)
			{
				ProjectScope project(command.project_path());
				auto matches = FilesByExternalPath(project, command.path());
				if (matches.empty())
					throw std::runtime_error("project file not found");
				if (matches.size() != 1)
					throw std::runtime_error("project file path is ambiguous");
				if (!matches.front()->Export(command.destination()))
					throw std::runtime_error("cannot export project file");
				result.set_id(matches.front()->GetId());
				result.set_path(ExternalProjectPath(matches.front()->GetPathInProject()));
				matches.clear();
				project.Close();
			}

			void Commit(const ipc::CommitLocalProjectFile& command, ipc::LocalProjectFileCommitted& result)
			{
				ProjectScope project(command.project_path());
				auto matches = FilesByExternalPath(project, command.path());
				BinaryNinja::Ref<BinaryNinja::ProjectFile> committed;
				if (command.replace_existing())
				{
					if (matches.size() != 1)
						throw std::runtime_error(
							matches.empty() ? "project file not found" : "project file path is ambiguous");
					const auto installed = platform::InstallRegularFileAtomically(
						command.source_path(), matches.front()->GetPathOnDisk(), true);
					if (!installed.installed)
						throw std::runtime_error(installed.error);
					committed = matches.front();
				}
				else
				{
					if (!matches.empty())
						throw std::runtime_error("project file destination already exists");
					const std::filesystem::path destination(command.path());
					const auto parentPath = destination.parent_path().generic_string();
					BinaryNinja::Ref<BinaryNinja::ProjectFolder> parent;
					if (!parentPath.empty())
					{
						for (const auto& folder : project->GetFolders())
						{
							if (FolderPath(folder) == parentPath)
							{
								parent = folder;
								break;
							}
						}
						if (!parent && command.create_folders())
						{
							std::filesystem::path current;
							BinaryNinja::Ref<BinaryNinja::ProjectFolder> currentParent;
							for (const auto& component : destination.parent_path())
							{
								current /= component;
								BinaryNinja::Ref<BinaryNinja::ProjectFolder> found;
								for (const auto& folder : project->GetFolders())
								{
									if (FolderPath(folder) == current.generic_string())
									{
										found = folder;
										break;
									}
								}
								if (!found)
									found = project->CreateFolder(currentParent, component.string(), "");
								if (!found)
									throw ProjectMutationError("cannot create project destination folder");
								currentParent = found;
							}
							parent = currentParent;
						}
						if (!parent)
							throw std::runtime_error("project destination folder not found");
					}
					committed = project->CreateFileFromPath(
						command.source_path(), parent, destination.filename().string(), command.description());
					if (!committed)
						throw ProjectMutationError("cannot create project database file");
				}
				result.set_id(committed->GetId());
				result.set_path(ExternalProjectPath(committed->GetPathInProject()));
				committed = nullptr;
				matches.clear();
				project.Close();
			}

			void CreateProject(const ipc::CreateLocalProject& command, ipc::LocalProject& result)
			{
				ProjectScope project(BinaryNinja::Project::CreateProject(command.path(), command.name()));
				if (!command.description().empty() && !project->SetDescription(command.description()))
					throw std::runtime_error("cannot set project description");
				FillProject(result, project);
				project.Close();
			}

			void UpdateProject(const ipc::UpdateLocalProject& command, ipc::LocalProject& result)
			{
				ProjectScope project(command.project_path());
				if (command.has_name() && !project->SetName(command.name()))
					throw ProjectMutationError("cannot update project name");
				if (command.has_description() && !project->SetDescription(command.description()))
					throw ProjectMutationError("cannot update project description");
				FillProject(result, project);
				project.Close();
			}

			void ListFolders(const ipc::ListLocalProjectFolders& command, ipc::LocalProjectFolders& result)
			{
				ProjectScope project(command.project_path());
				auto folders = project->GetFolders();
				std::sort(folders.begin(), folders.end(), [](const auto& left, const auto& right) {
					return FolderPath(left) < FolderPath(right);
				});
				for (const auto& folder : folders)
					FillFolder(*result.add_folders(), folder);
				folders.clear();
				project.Close();
			}

			BinaryNinja::Ref<BinaryNinja::ProjectFolder> Folder(ProjectScope& project, const std::string& id)
			{
				if (id.empty())
					return nullptr;
				auto folder = project->GetFolderById(id);
				if (!folder)
					throw std::runtime_error("project folder not found");
				return folder;
			}

			void CreateFolder(const ipc::CreateLocalProjectFolder& command, ipc::LocalProjectFolder& result)
			{
				ProjectScope project(command.project_path());
				auto parent = Folder(project, command.parent_id());
				auto folder = project->CreateFolder(parent, command.name(), command.description());
				if (!folder)
					throw ProjectMutationError("cannot create project folder");
				FillFolder(result, folder);
				folder = nullptr;
				parent = nullptr;
				project.Close();
			}

			void UpdateFolder(const ipc::UpdateLocalProjectFolder& command, ipc::LocalProjectFolder& result)
			{
				ProjectScope project(command.project_path());
				auto folder = Folder(project, command.id());
				if (command.has_name() && !folder->SetName(command.name()))
					throw ProjectMutationError("cannot update project folder name");
				if (command.has_description() && !folder->SetDescription(command.description()))
					throw ProjectMutationError("cannot update project folder description");
				if (command.has_parent_id())
				{
					auto parent = Folder(project, command.parent_id());
					if (!folder->SetParent(parent))
						throw ProjectMutationError("cannot move project folder");
				}
				FillFolder(result, folder);
				folder = nullptr;
				project.Close();
			}

			void DeleteFolder(const ipc::DeleteLocalProjectFolder& command)
			{
				if (!command.recursive())
					throw std::invalid_argument("recursive folder deletion requires confirmation");
				ProjectScope project(command.project_path());
				auto folder = Folder(project, command.id());
				if (!project->DeleteFolder(folder))
					throw ProjectMutationError("cannot delete project folder");
				folder = nullptr;
				project.Close();
			}

			void UpdateFile(const ipc::UpdateLocalProjectFile& command, ipc::LocalProjectFile& result)
			{
				ProjectScope project(command.project_path());
				auto file = project->GetFileById(command.id());
				if (!file)
					throw std::runtime_error("project file not found");
				if (command.has_name() && !file->SetName(command.name()))
					throw ProjectMutationError("cannot update project file name");
				if (command.has_description() && !file->SetDescription(command.description()))
					throw ProjectMutationError("cannot update project file description");
				if (command.has_folder_id())
				{
					auto folder = Folder(project, command.folder_id());
					if (!file->SetFolder(folder))
						throw ProjectMutationError("cannot move project file");
				}
				FillFile(result, file);
				file = nullptr;
				project.Close();
			}

			void DeleteFile(const ipc::DeleteLocalProjectFile& command)
			{
				if (!command.delete_())
					throw std::invalid_argument("project file deletion requires confirmation");
				ProjectScope project(command.project_path());
				auto file = project->GetFileById(command.id());
				if (!file)
					throw std::runtime_error("project file not found");
				if (!project->DeleteFile_(file))
					throw ProjectMutationError("cannot delete project file");
				file = nullptr;
				project.Close();
			}

			void DeleteProject(const ipc::DeleteLocalProject& command)
			{
				ProjectScope project(command.project_path());
				project.Close();
				std::error_code error;
				const auto removed = std::filesystem::remove_all(command.project_path(), error);
				if (error || removed == 0)
					throw std::runtime_error(error ?
							"cannot delete local project: " + error.message() :
							"local project storage was not found");
			}

			void Send(std::uint64_t requestId, const ipc::Reply& reply)
			{
				ipc::Envelope envelope;
				envelope.set_protocol_version(ipc::kProtocolVersion);
				envelope.set_request_id(requestId);
				*envelope.mutable_reply() = reply;
				ipc::SendEnvelope(*channel_, envelope);
			}

			void Failure(std::uint64_t requestId, std::string message)
			{
				ipc::Reply reply;
				reply.set_success(false);
				reply.set_error(std::move(message));
				Send(requestId, reply);
			}

			std::unique_ptr<ipc::ByteChannel> channel_;
			BinaryNinjaRuntime runtime_;
		};
	}  // namespace

	int RunProjectChild(std::unique_ptr<ipc::ByteChannel> channel)
	{
		if (!channel)
			return EXIT_FAILURE;
		return ProjectChild(std::move(channel)).Run();
	}
}  // namespace binjad
