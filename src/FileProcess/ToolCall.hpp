#pragma once

#include "FileChild.hpp"

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace binjad {
	struct FileChildToolCallContext
	{
		const ipc::ExecuteAnalysisTool& request;
		const rapidjson::Value& arguments;
		std::shared_ptr<FileChildViewState> view;
		BinaryNinja::Ref<BinaryNinja::FileMetadata> file;
		binary_ninja::DiffTools& diffTools;
		std::optional<std::string>& activeUndoId;
		std::string& activeUndoView;
		std::mutex& viewMutex;
		std::function<void(std::string_view, std::size_t, std::size_t)> progress;
		std::function<void(ipc::AnalysisState, std::string_view)> finished;

		const std::string& name() const { return request.name(); }
		const std::string& view_type() const { return request.view_type(); }
		const std::string& arguments_json() const { return request.arguments_json(); }
		const std::string& diff_key() const { return request.diff_key(); }
		const std::string& secondary_path() const { return request.secondary_path(); }
		operator const ipc::ExecuteAnalysisTool&() const { return request; }
	};

	class FileChildToolCall
	{
	public:
		explicit FileChildToolCall(std::string_view name) : name_(name) {}
		virtual ~FileChildToolCall() = default;

		std::string_view Name() const { return name_; }
		virtual ipc::Reply Execute(const FileChildToolCallContext& context) const = 0;

	private:
		std::string_view name_;
	};

	const FileChildToolCall* FindFileChildToolCall(std::string_view name);

	void RegisterAnalysisToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterAnalysisMutationToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterDiffingToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterHeaderParsingToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterKernelCacheToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterSharedCacheToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);
	void RegisterDebuggerToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools);

	BinaryNinja::Ref<BinaryNinja::Function> ResolveFunction(
		const FileChildToolCallContext& context, const rapidjson::Value& arguments);
	BinaryNinja::Ref<BinaryNinja::Type> ParseRequestedType(
		const FileChildToolCallContext& context, const rapidjson::Value& arguments);
}  // namespace binjad
