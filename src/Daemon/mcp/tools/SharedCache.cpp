#include "../ToolCall.hpp"
#include "../ToolSchema.hpp"

namespace binjad::mcp {
	namespace {
#define BINJAD_SHARED_TOOL(Type, Name, LegacyDescription, ...) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, ToolCallCategory::SharedCache) {} \
		FoundationResult Execute(const ToolCallContext& context) const override \
		{ \
			return ExecuteForwardedAnalysisTool(context); \
		} \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter& writer) const override \
		{ \
			schema::WriteObject(writer, Name, {__VA_ARGS__}); \
		} \
	}

		BINJAD_SHARED_TOOL(SharedCacheImageListTool, "bn_shared_cache_image_list",
			"List images available in a SharedCache BinaryView.", schema::String("binaryView", true),
			schema::Boolean("loaded"), schema::String("query"), schema::Integer("offset", false, 0),
			schema::Integer("limit", false, 1, 1000));
		BINJAD_SHARED_TOOL(SharedCacheImageInfoTool, "bn_shared_cache_image_info",
			"Inspect one exact SharedCache image and its dependencies.", schema::String("binaryView", true),
			schema::NonEmptyString("image", true));
		BINJAD_SHARED_TOOL(SharedCacheImageLoadTool, "bn_shared_cache_image_load",
			"Load one exact SharedCache image into the BinaryView.", schema::String("binaryView", true),
			schema::NonEmptyString("image", true));
		BINJAD_SHARED_TOOL(SharedCacheRegionListTool, "bn_shared_cache_region_list", "List SharedCache regions.",
			schema::String("binaryView", true), schema::Boolean("loaded"), schema::String("query"),
			schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
		BINJAD_SHARED_TOOL(SharedCacheRegionLoadTool, "bn_shared_cache_region_load",
			"Load one exact SharedCache region into the BinaryView.", schema::String("binaryView", true),
			schema::NonEmptyString("region", true));
		BINJAD_SHARED_TOOL(SharedCacheEntryListTool, "bn_shared_cache_entry_list",
			"List files comprising a SharedCache.", schema::String("binaryView", true), schema::String("query"),
			schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));
		BINJAD_SHARED_TOOL(SharedCacheSymbolListTool, "bn_shared_cache_symbol_list",
			"List exported SharedCache symbols.", schema::String("binaryView", true), schema::String("query"),
			schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000));

#undef BINJAD_SHARED_TOOL
	}  // namespace

	void RegisterSharedCacheTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<SharedCacheImageListTool>());
		tools.emplace_back(std::make_unique<SharedCacheImageInfoTool>());
		tools.emplace_back(std::make_unique<SharedCacheImageLoadTool>());
		tools.emplace_back(std::make_unique<SharedCacheRegionListTool>());
		tools.emplace_back(std::make_unique<SharedCacheRegionLoadTool>());
		tools.emplace_back(std::make_unique<SharedCacheEntryListTool>());
		tools.emplace_back(std::make_unique<SharedCacheSymbolListTool>());
	}
}  // namespace binjad::mcp
