#pragma once

#include "binjad/binary_ninja/DiffTools.hpp"
#include "binjad/binary_ninja/Runtime.hpp"
#include "binjad/ipc/Envelope.hpp"

#include <binaryninjaapi.h>
#include <rapidjsonwrapper.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace binjad {
	struct FileChildCandidate
	{
		BinaryNinja::Ref<BinaryNinja::BinaryViewType> type;
		bool recommended = false;
		std::string loadSettingsSchemaJson;
	};

	struct FileChildViewState
	{
		BinaryNinja::Ref<BinaryNinja::BinaryView> view;
		std::string effectiveLoadSettingsJson;
		std::vector<BinaryNinja::Ref<BinaryNinja::AnalysisCompletionEvent>> completionEvents;
		std::unordered_map<std::uint64_t, BinaryNinja::Ref<BinaryNinja::Function>> userFunctions;
		bool analysisActive = false;
		bool abortRequested = false;
	};

	class FileChild
	{
	public:
		explicit FileChild(std::unique_ptr<ipc::ByteChannel> channel);
		~FileChild();

		int Run();

	private:
		void AddCandidate(const std::string& name, BinaryNinja::Ref<BinaryNinja::BinaryViewType> type);
		bool HasMappedLoadOptions() const;
		void EnumerateCandidates();
		ipc::Reply OpenFile(const ipc::OpenFile& command);
		std::string ApplyLoadSettings(
			const FileChildCandidate& candidate, const std::string& options, const std::string& explicitOptions);
		ipc::Reply OpenBinaryView(const ipc::OpenBinaryView& command);
		std::shared_ptr<FileChildViewState> View(const std::string& viewType) const;
		void StartAnalysis(const std::string& viewType, std::uint64_t origin);
		ipc::Reply AnalysisStatus(const std::string& viewType) const;
		ipc::Reply SaveBinaryView(const ipc::SaveBinaryView& command);
		void Abort(const std::string& viewType);
		void Close(bool discard);
		void Dispatch(const ipc::Envelope& envelope, bool& running);
		void SendReply(std::uint64_t requestId, ipc::Reply reply);
		void SendFailure(std::uint64_t requestId, std::string_view error);
		void SendProgress(std::uint64_t origin, std::string_view phase, std::size_t completed, std::size_t total);
		void SendEvent(std::uint64_t origin, ipc::AnalysisState state, std::string_view error);
		void Send(const ipc::Envelope& envelope);

		std::unique_ptr<ipc::ByteChannel> channel_;
		BinaryNinjaRuntime runtime_;
		binary_ninja::DiffTools diffTools_;
		BinaryNinja::Ref<BinaryNinja::FileMetadata> file_;
		BinaryNinja::Ref<BinaryNinja::BinaryView> data_;
		std::unordered_map<std::string, FileChildCandidate> candidates_;
		std::vector<std::string> candidateOrder_;
		mutable std::mutex viewMutex_;
		std::unordered_map<std::string, std::shared_ptr<FileChildViewState>> views_;
		std::string activeAnalysisView_;
		std::optional<std::string> activeUndoId_;
		std::string activeUndoView_;
		std::mutex sendMutex_;
		bool databaseBacked_ = false;
		bool snapshotApplied_ = false;
		bool reuseDatabase_ = false;
		std::string loadOptions_;
		std::filesystem::path openedPath_;
		std::uint64_t currentRequest_ = 0;
	};
}  // namespace binjad
