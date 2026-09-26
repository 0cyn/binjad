#include "ToolCall.hpp"

#include <stdexcept>
#include <unordered_map>

namespace binjad {
	namespace {
		struct FileChildToolCallRegistry
		{
			std::vector<std::unique_ptr<FileChildToolCall>> tools;
			std::unordered_map<std::string_view, const FileChildToolCall*> byName;
		};

		const FileChildToolCallRegistry& Registry()
		{
			static const auto registry = [] {
				FileChildToolCallRegistry result;
				RegisterAnalysisToolCalls(result.tools);
				RegisterAnalysisMutationToolCalls(result.tools);
				RegisterDiffingToolCalls(result.tools);
				RegisterHeaderParsingToolCalls(result.tools);
				RegisterKernelCacheToolCalls(result.tools);
				RegisterSharedCacheToolCalls(result.tools);
				RegisterDebuggerToolCalls(result.tools);

				result.byName.reserve(result.tools.size());
				for (const auto& tool : result.tools)
				{
					if (!result.byName.emplace(tool->Name(), tool.get()).second)
						throw std::logic_error("duplicate file-child tool registration");
				}
				return result;
			}();
			return registry;
		}
	}  // namespace

	const FileChildToolCall* FindFileChildToolCall(std::string_view name)
	{
		const auto found = Registry().byName.find(name);
		return found == Registry().byName.end() ? nullptr : found->second;
	}
}  // namespace binjad
