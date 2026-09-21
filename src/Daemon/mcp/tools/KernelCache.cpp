#include "../ToolCall.hpp"

namespace binjad::mcp {
	namespace {
#define BINJAD_KERNEL_TOOL(Type, Name, LegacyDescription) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, ToolCallCategory::KernelCache) {} \
		FoundationResult Execute(const ToolCallContext& context) const override \
		{ \
			return ExecuteForwardedAnalysisTool(context); \
		} \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter & writer) const override

		BINJAD_KERNEL_TOOL(KernelCacheImageListTool, "bn_kernel_cache_image_list",
			"List KernelCache images; query first, default 50 rows, then continue with nextOffset.")
		{
			writer.StartObject();
			writer.Key("type");
			writer.String("object");
			writer.Key("properties");
			writer.StartObject();
			writer.Key("binaryView");
			writer.StartObject();
			writer.Key("type");
			writer.String("string");
			writer.EndObject();
			writer.Key("loaded");
			writer.StartObject();
			writer.Key("type");
			writer.String("boolean");
			writer.EndObject();
			writer.Key("query");
			writer.StartObject();
			writer.Key("type");
			writer.String("string");
			writer.EndObject();
			writer.Key("offset");
			writer.StartObject();
			writer.Key("type");
			writer.String("integer");
			writer.Key("minimum");
			writer.Uint(0);
			writer.EndObject();
			writer.Key("limit");
			writer.StartObject();
			writer.Key("type");
			writer.String("integer");
			writer.Key("minimum");
			writer.Uint(1);
			writer.Key("maximum");
			writer.Uint(1000);
			writer.EndObject();
			writer.EndObject();
			writer.Key("required");
			writer.StartArray();
			writer.String("binaryView");
			writer.EndArray();
			writer.Key("additionalProperties");
			writer.Bool(false);
			writer.EndObject();
		}
	};

#define BINJAD_KERNEL_IMAGE_TOOL(Type, Name, LegacyDescription) \
	BINJAD_KERNEL_TOOL(Type, Name, LegacyDescription) \
	{ \
		writer.StartObject(); \
		writer.Key("type"); \
		writer.String("object"); \
		writer.Key("properties"); \
		writer.StartObject(); \
		writer.Key("binaryView"); \
		writer.StartObject(); \
		writer.Key("type"); \
		writer.String("string"); \
		writer.EndObject(); \
		writer.Key("image"); \
		writer.StartObject(); \
		writer.Key("type"); \
		writer.String("string"); \
		writer.Key("minLength"); \
		writer.Uint(1); \
		writer.EndObject(); \
		writer.EndObject(); \
		writer.Key("required"); \
		writer.StartArray(); \
		writer.String("binaryView"); \
		writer.String("image"); \
		writer.EndArray(); \
		writer.Key("additionalProperties"); \
		writer.Bool(false); \
		writer.EndObject(); \
	} \
	}

	BINJAD_KERNEL_IMAGE_TOOL(KernelCacheImageInfoTool, "bn_kernel_cache_image_info",
		"Inspect one exact KernelCache image and its dependencies.");
	BINJAD_KERNEL_IMAGE_TOOL(KernelCacheImageLoadTool, "bn_kernel_cache_image_load",
		"Load one exact KernelCache image into the BinaryView.");

	BINJAD_KERNEL_TOOL(KernelCacheSymbolListTool, "bn_kernel_cache_symbol_list", "List exported KernelCache symbols.")
	{
		writer.StartObject();
		writer.Key("type");
		writer.String("object");
		writer.Key("properties");
		writer.StartObject();
		for (const auto* name : {"binaryView", "query"})
		{
			writer.Key(name);
			writer.StartObject();
			writer.Key("type");
			writer.String("string");
			writer.EndObject();
		}
		writer.Key("offset");
		writer.StartObject();
		writer.Key("type");
		writer.String("integer");
		writer.Key("minimum");
		writer.Uint(0);
		writer.EndObject();
		writer.Key("limit");
		writer.StartObject();
		writer.Key("type");
		writer.String("integer");
		writer.Key("minimum");
		writer.Uint(1);
		writer.Key("maximum");
		writer.Uint(1000);
		writer.EndObject();
		writer.EndObject();
		writer.Key("required");
		writer.StartArray();
		writer.String("binaryView");
		writer.EndArray();
		writer.Key("additionalProperties");
		writer.Bool(false);
		writer.EndObject();
	}
};

#undef BINJAD_KERNEL_IMAGE_TOOL
#undef BINJAD_KERNEL_TOOL
}  // namespace

void RegisterKernelCacheTools(std::vector<std::unique_ptr<ToolCall>>& tools)
{
	tools.emplace_back(std::make_unique<KernelCacheImageListTool>());
	tools.emplace_back(std::make_unique<KernelCacheImageInfoTool>());
	tools.emplace_back(std::make_unique<KernelCacheImageLoadTool>());
	tools.emplace_back(std::make_unique<KernelCacheSymbolListTool>());
}
}  // namespace binjad::mcp
