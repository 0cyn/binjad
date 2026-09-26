#include "../ToolCall.hpp"
#include "../ToolSchema.hpp"

namespace binjad::mcp {
	namespace {
#define BINJAD_HEADER_TOOL(Type, Name, Description, ...) \
	class Type final : public ToolCall \
	{ \
	public: \
		Type() : ToolCall(Name, Description, ToolCallCategory::HeaderParsing, "Header Parsing") {} \
		FoundationResult Execute(const ToolCallContext& context) const override \
		{ \
			return ExecuteForwardedAnalysisTool(context); \
		} \
\
	private: \
		void WriteInputSchema(ToolCallSchemaWriter& writer) const override \
		{ \
			schema::WriteObject(writer, {__VA_ARGS__}); \
		} \
	}

		BINJAD_HEADER_TOOL(BinaryHeaderInfoTool, "bn_binary_header_info",
			"Inspect generic and format-specific Mach-O, ELF, or PE header identity, layout, runtime, and security "
			"fields.",
			schema::String("binaryView", true));
		BINJAD_HEADER_TOOL(LinkedLibraryListTool, "bn_linked_library_list",
			"List libraries linked by Mach-O load commands, ELF DT_NEEDED entries, or PE import and delay-import "
			"tables.",
			schema::String("binaryView", true), schema::String("query"), schema::Integer("offset", false, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_HEADER_TOOL(MachoLoadCommandListTool, "bn_macho_load_command_list",
			"List parsed Mach-O load commands with command-specific fields.", schema::String("binaryView", true),
			schema::String("query"), schema::Integer("offset", false, 0), schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_HEADER_TOOL(ElfProgramHeaderListTool, "bn_elf_program_header_list",
			"List parsed ELF program headers, including interpreter, dynamic, GNU stack, and GNU RELRO segments.",
			schema::String("binaryView", true), schema::String("query"), schema::Integer("offset", false, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_HEADER_TOOL(ElfDynamicEntryListTool, "bn_elf_dynamic_entry_list",
			"List parsed ELF dynamic entries and resolve string-valued tags such as NEEDED, SONAME, RPATH, and "
			"RUNPATH.",
			schema::String("binaryView", true), schema::String("query"), schema::Integer("offset", false, 0),
			schema::Integer("limit", false, 1, 1000, 50));
		BINJAD_HEADER_TOOL(PeDataDirectoryListTool, "bn_pe_data_directory_list",
			"List parsed PE optional-header data directories with names, RVAs, mapped addresses, and sizes.",
			schema::String("binaryView", true), schema::String("query"), schema::Integer("offset", false, 0),
			schema::Integer("limit", false, 1, 1000, 50));

#undef BINJAD_HEADER_TOOL
	}  // namespace

	void RegisterHeaderParsingTools(std::vector<std::unique_ptr<ToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<BinaryHeaderInfoTool>());
		tools.emplace_back(std::make_unique<LinkedLibraryListTool>());
		tools.emplace_back(std::make_unique<MachoLoadCommandListTool>());
		tools.emplace_back(std::make_unique<ElfProgramHeaderListTool>());
		tools.emplace_back(std::make_unique<ElfDynamicEntryListTool>());
		tools.emplace_back(std::make_unique<PeDataDirectoryListTool>());
	}
}  // namespace binjad::mcp
