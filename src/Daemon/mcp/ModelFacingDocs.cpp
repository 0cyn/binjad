#include "ModelFacingDocs.hpp"

#include <stdexcept>
#include <string>
#include <tuple>

namespace binjad::mcp::docs {
	namespace {
		// This translation unit is the authoritative source for prose sent to models.
		// Legacy declaration text in tool implementation files remains compatibility-only and is ignored.
		using ToolMap = std::unordered_map<std::string_view, ToolDocumentation>;
		using CategoryMap = std::unordered_map<std::string_view, CategoryDocumentation>;
		using ResourceMap = std::unordered_map<std::string_view, ResourceDocumentation>;
		using FailureMap = std::unordered_map<std::string_view, FailureContractDocumentation>;

		constexpr std::string_view kModernDiscoveryInstructions =
			"Create a session. Flow: open item -> binary_view_open -> analyze -> query/mutate -> save -> close. "
			"Query first, use small limits, and continue with nextOffset. Always close items. Four-word references are "
			"opaque handles: pass them verbatim to tools, but do not interpret or discuss their words in user-facing "
			"responses. See binjad://docs.";

		constexpr std::string_view kLegacyInitializationInstructions =
			"Flow: open item -> binary_view_open -> analyze -> query/mutate -> save -> close. Query first, use small "
			"limits, and continue with nextOffset. Always close items; the transport manages this legacy analysis "
			"session. Four-word references are opaque handles: pass them verbatim to tools, but do not interpret or "
			"discuss their words in user-facing responses. See binjad://docs.";

		constexpr std::string_view kQuickStart =
			"Tool discovery: when bn_tools is advertised, use categories, list, and describe before calling an omitted "
			"tool through bn_tools with operation=call. The common lifecycle and control surface remains direct.\n"
			"Flow: project_list -> file_list -> project_file_open -> binary_view_open(recommended) -> "
			"analysis_update_and_wait -> query/mutate -> binary_view_save(if changed) -> open_item_close.\n"
			"Uploads: bn_upload_get_url returns a one-time PUT capability and explicit authorization requirements; "
			"commit to a project-relative folder path; import-only commits return JSON and successful retries return "
			"the original result; use bn_upload_list/cancel for cleanup. Local administrators should prefer "
			"bn_local_project_file_import_batch for explicit files already on the server, or "
			"bn_local_project_directory_import to preserve a directory tree; resume a partial directory import with "
			"the returned lastCompleted value as startAfter.\n"
			"Project files: project-relative paths are unique and select files together with project; imports accept "
			"an initial description; bn_local_project_file_list returns descriptions; bn_local_project_file_update "
			"sets or replaces one, and an empty description string clears it.\n"
			"Project documents: use bn_project_text_read for line/query pagination over UTF-8 text and Markdown; use "
			"bn_project_json_read with RFC 6901 pointers to page object keys or array indexes without expanding "
			"unrelated subtrees. These tools read project files directly without a BinaryView.\n"
			"Project writes: if a mutation says the project may be open or read-only, ask the user to close that "
			"project in the Binary Ninja GUI, then retry. Failed upload commits remain staged and may be retried with "
			"the same id without re-uploading.\n"
			"Project recovery: bn_local_project_root_list returns private root indexes. "
			"bn_local_project_relocate copies a closed outside-root project beneath one selected root, verifies its "
			"durable ID, retains the old source on disk, and removes the old registration.\n"
			"Headers: bn_binary_header_info summarizes Mach-O, ELF, or PE identity and security fields; use "
			"bn_linked_library_list for dependencies and the format-specific Header Parsing lists for low-level rows.\n"
			"Functions: FunctionSymbol is annotation only; use bn_entry_point_add for an analysis root and "
			"bn_function_create for a persistent user function, then update analysis and save the BinaryView.\n"
			"URLs: every generated Binary Ninja URL identifies a file to open. bn_url_open_item links owned "
			"arbitrary-path provenance. For a local-project item, call "
			"bn_binary_view_save after the latest changes, then call bn_url_project_file with "
			"updated_bndb_has_been_saved:true; its URL opens the committed project backing file, never unsaved child "
			"state. Use bn_url_remote_file for an absolute http, https, or file URL. The optional expr navigates "
			"within that linked file. Context-only expression URLs are not supported.\n"
			"Raw firmware: open only discovers candidates; select Mapped rather than Raw, call "
			"bn_binary_view_load_settings, then pass fully qualified loader.platform, loader.imageBase, and "
			"loader.entryPointOffset options to bn_binary_view_open. Thumb vector values have bit zero set, but Mapped "
			"entry/function addresses use the aligned code address. loader.segments and loader.sections are serialized "
			"JSON strings.\n"
			"Rules: every view tool needs binaryView; query first, use small limits, and continue with nextOffset; "
			"async job results are one-shot; direct C types use definition, while source+type selects a parsed "
			"declaration; after function/variable mutation follow nextAction; set prototypes before variable names; "
			"reopen BNDBs with reuseDatabase:true and analyze:false; close only items created by your workflow because "
			"token-wide lists may include concurrent clients; legacy analysis sessions are transport-managed.";

		constexpr std::string_view kOpenCodeProjectionBoundary =
			"OpenCode controls the final provider-specific model encoding. This projection applies its MCP namespace "
			"convention to the exact current binjad tool definitions; only mcpWire is byte-for-byte server output.";

		constexpr std::string_view kPage50Response =
			"Return at most 50 items by default; continue with the response nextOffset.";
		constexpr std::string_view kPage50 = "Defaults to 50; continue with nextOffset.";
		constexpr std::string_view kPage50Query = "Defaults to 50; use query first and continue with nextOffset.";
		constexpr std::string_view kRendered200 = "Defaults to 200 rendered lines; continue with nextOffset.";
		constexpr std::string_view kLoadOptions =
			"Candidate-specific Binary Ninja load settings. Call bn_binary_view_load_settings first; Raw accepts none, "
			"while Mapped exposes fully qualified loader.* keys and requires serialized JSON strings for segments and "
			"sections.";
		constexpr std::string_view kDiffPrimary = "Materialized primary BinaryView to compare and mutate.";
		constexpr std::string_view kDiffSecondary =
			"Secondary BinaryView reference when project is omitted, or project-relative BNDB path when project is "
			"present. Repeat the run identity exactly.";
		constexpr std::string_view kDiffProject =
			"Project reference used by bn_diff_run_project; omit for a bn_diff_run_view cache.";
		constexpr std::string_view kUrlExpression =
			"Optional Binary Ninja navigation expression within the linked file, such as a function, section, or "
			"address.";
	}  // namespace

	std::string_view ModernDiscoveryInstructions()
	{
		return kModernDiscoveryInstructions;
	}

	std::string_view LegacyInitializationInstructions()
	{
		return kLegacyInitializationInstructions;
	}

	std::string_view QuickStart()
	{
		return kQuickStart;
	}

	std::string_view OpenCodeProjectionBoundary()
	{
		return kOpenCodeProjectionBoundary;
	}

	const std::unordered_map<std::string_view, CategoryDocumentation>& Categories()
	{
		// clang-format off: one documentation record per line is easier to edit.
		static const CategoryMap categories {
			{"core", {"Core Workflow", "Projects, uploads, file and BinaryView lifecycle, analysis, jobs, and essential queries."}},
			{"project_management", {"Project Management & Documents", "Project metadata, files, folders, imports, and project documents."}},
			{"function_analysis", {"Function Analysis", "IL, calls, code references, and stack layout."}},
			{"binary_data", {"Binary Data", "Imports, exports, entries, sections, segments, data, relocations, and references."}},
			{"search", {"Search", "Comments, bytes, instructions, IL, constants, and project-wide search."}},
			{"types", {"Types & Signatures", "Types, signatures, calling conventions, and function variables."}},
			{"annotations", {"Annotations & Symbols", "Comments, symbols, bookmarks, tags, and custom metadata."}},
			{"binary_editing", {"Binary Editing", "Functions, entries, data, sections, segments, rebasing, memory maps, and strings."}},
			{"history", {"Transactions & History", "Transactions, rollback, undo, and redo."}},
			{"header_parsing", {"Header Parsing", "Mach-O, ELF, and PE headers and security metadata."}},
			{"url_generation", {"URL Generation", "Binary Ninja open and navigation links."}},
			{"diffing", {"Diffing", "Google BinDiff comparisons and metadata transfer."}},
			{"kernel_cache", {"KernelCache", "KernelCache images, dependencies, symbols, and selective loading."}},
			{"shared_cache", {"SharedCache", "SharedCache images, regions, entries, symbols, and selective loading."}},
			{"debugger", {"Debugger", "Admin-only debugger target control and inspection."}},
		};
		// clang-format on
		return categories;
	}

	const CategoryDocumentation& Category(std::string_view id)
	{
		const auto& categories = Categories();
		const auto found = categories.find(id);
		if (found == categories.end())
			throw std::logic_error("missing model-facing category documentation: " + std::string(id));
		return found->second;
	}

	const std::unordered_map<std::string_view, ResourceDocumentation>& Resources()
	{
		// clang-format off: one documentation record per line is easier to edit.
		static const ResourceMap resources {
			{"binjad://docs", {"Quick start", "Minimal binjad lifecycle and argument rules.", "text/markdown"}},
			{"binjad://compute", {"Compute status", "Current analysis capacity and allocation.", "application/json"}},
			{"binjad://analysis-sessions", {"Analysis sessions", "Analysis sessions owned by this bearer token.", "application/json"}},
			{"binjad://open-items", {"Open items", "Open files and BinaryView candidates owned by this bearer token.", "application/json"}},
			{"binjad://jobs", {"Detached jobs", "Detached jobs owned by this bearer token.", "application/json"}},
			{"binjad://local-projects", {"Local projects", "Shared local Binary Ninja project catalog.", "application/json"}},
			{"binjad://analysis-sessions/{analysisSession}", {"Analysis session", "One analysis session owned by this bearer token.", "application/json"}},
		};
		// clang-format on
		return resources;
	}

	const ResourceDocumentation& Resource(std::string_view uri)
	{
		const auto& resources = Resources();
		const auto found = resources.find(uri);
		if (found == resources.end())
			throw std::logic_error("missing model-facing resource documentation: " + std::string(uri));
		return found->second;
	}

	std::string_view Availability(std::string_view id)
	{
		// clang-format off: one documentation record per line is easier to edit.
		static const std::unordered_map<std::string_view, std::string_view> availability {
			{"brokered_discovery", "Requires tools.discovery_mode to be 'brokered'."},
			{"disabled_suffix", " tools are disabled in the running configuration."},
			{"modern_protocol", "Requires the modern MCP protocol session model."},
			{"admin", "Requires an admin bearer token."},
			{"arbitrary_paths", "Requires projects.allow_arbitrary_paths in local mode."},
			{"project_registration", "Requires projects.allow_project_registration in local mode."},
			{"not_advertised", "Not advertised for the selected protocol, role, mode, or running options."},
		};
		// clang-format on
		const auto found = availability.find(id);
		if (found == availability.end())
			throw std::logic_error("missing model-facing availability documentation: " + std::string(id));
		return found->second;
	}

	const std::unordered_map<std::string_view, FailureContractDocumentation>& FailureContracts()
	{
		// clang-format off: one documentation record per line is easier to edit.
		static const FailureMap failures {
			{"invalid_arguments", {"A required argument is absent, has the wrong type or range, or an unknown argument is supplied.", "JSON-RPC -32602; HTTP 400 for modern MCP and HTTP 200 for legacy MCP."}},
			{"analysis_session_unavailable", {"The analysis session is unknown, expired, belongs to another token, or is not valid for this protocol flow.", "JSON-RPC error, normally session not found; no tool result is produced."}},
			{"binary_view_unavailable", {"The BinaryView reference is unknown, belongs to another session, is not materialized, or its file child failed.", "Tool result with isError:true and a structured error string."}},
			{"open_item_unavailable", {"The open-item reference is unknown, belongs to another token/session, is busy, or requires discard acknowledgement.", "Tool result with isError:true and a structured error string."}},
			{"project_unavailable", {"The project/file/folder is unknown, unauthorized, locked by another Binary Ninja process, read-only, or unavailable in the active project mode.", "Tool result with isError:true; lock failures instruct the caller to ask the user to close the GUI project and retry."}},
			{"job_unavailable", {"The job is unknown, owned by another token, not terminal, already consumed, or cannot be cancelled.", "Tool result with isError:true and a structured error string."}},
			{"function_unavailable", {"The function selector is absent or ambiguous, analysis has not created it, or the requested architecture/view does not contain it.", "Tool result with isError:true; FunctionSymbol-only failures direct callers to bn_function_create."}},
			{"type_unavailable", {"A named type cannot be found, is the wrong class, already exists for a create operation, or C parsing fails.", "Tool result with isError:true and parse or selection details."}},
			{"address_unavailable", {"The address expression is invalid, unmapped, outside loaded cache content, or unsuitable for the requested operation.", "Tool result with isError:true and contextual load/analyze guidance where available."}},
			{"plugin_state", {"The optional plugin surface is disabled, unavailable, the view is incompatible, or required cache content is not loaded.", "Unavailable tools are omitted from discovery; runtime state failures are isError:true tool results."}},
			{"debugger_state", {"The caller is not an admin, debuggercore is unavailable, target configuration is incomplete, or the target state rejects the operation.", "The surface is omitted for non-admins; runtime failures are isError:true tool results or failed jobs."}},
			{"diff_state", {"Google BinDiff is unavailable, a secondary is not a valid BNDB, the comparison is running, absent, cancelled, or belongs to another explicit pair, or a requested match is absent.", "Run failures are terminal job results; cached query and mutation failures are isError:true tool results."}},
			{"persistence_failure", {"Storage is locked, read-only, collides with an unrelated destination, upload state is invalid, or a a persistence operation fails.", "Tool result or terminal job with structured error/conflict data; documented retryable uploads retain their staged id."}},
			{"service_failure", {"A required daemon service/child is unavailable or an unexpected internal operation fails.", "JSON-RPC -32603 when no tool result can be formed; otherwise an isError:true tool result or failed job."}},
		};
		// clang-format on
		return failures;
	}

	const std::unordered_map<std::string_view, ToolDocumentation>& Tools()
	{
		static const auto tools = [] {
			// clang-format off: keep the registry compact and preserve one tool or argument record per line.
			ToolMap tools {
			{"bn_analysis_abort", {"Files and views", "Abort analysis for a materialized explicit BinaryView.", {}}},
			{"bn_analysis_session_close", {"Sessions and compute", "Close an owned analysis session.", {}}},
			{"bn_analysis_session_create", {"Sessions and compute", "Create an analysis session.", {}}},
			{"bn_analysis_session_info", {"Sessions and compute", "Inspect an owned analysis session; omit analysisSession or use current for the request's current session.", {}}},
			{"bn_analysis_session_list", {"Sessions and compute", "List owned analysis sessions.", {}}},
			{"bn_analysis_status", {"Files and views", "Return analysis status for a materialized explicit BinaryView.", {}}},
			{"bn_analysis_update", {"Files and views", "Start analysis without waiting; prefer update_and_wait for normal client workflows.", {}}},
			{"bn_analysis_update_and_wait", {"Files and views", "Preferred analysis operation; waits until the deadline, then returns a job to poll every 10 seconds and consume with job_result.", {}}},
			{"bn_analysis_update_async", {"Files and views", "Start analysis for a materialized BinaryView as an immediately detached job.", {}}},
			{"bn_binary_header_info", {"Header Parsing", "Inspect generic and format-specific Mach-O, ELF, or PE header identity, layout, runtime, and security fields.", {}}},
			{"bn_binary_view_list", {"Files and views", "List BinaryView candidates in the current analysis session.", {}}},
			{"bn_binary_view_load_settings", {"Files and views", "Return the authoritative Binary Ninja load-settings schema and effective settings for one BinaryView candidate.", {}}},
			{"bn_binary_view_open", {"Files and views", "Materialize an explicit candidate; inspect load settings first, use Mapped for raw firmware, and use analyze:false for reused BNDB analysis.", {}}},
			{"bn_binary_view_rebase", {"Files and views", "Rebase an explicit BinaryView to a new base address.", {}}},
			{"bn_binary_view_save", {"Files and views", "Save and commit an explicit BinaryView.", {}}},
			{"bn_binary_view_save_async", {"Files and views", "Save and commit an explicit BinaryView as an immediately detached job.", {}}},
			{"bn_bookmark_create", {"Other", "Create a persistent bookmark at an address.", {}}},
			{"bn_bookmark_delete", {"Other", "Delete one persistent bookmark by its Binary Ninja tag id.", {}}},
			{"bn_bookmark_list", {"Other", "List persistent bookmarks with pagination.", {}}},
			{"bn_calling_convention_list", {"Functions", "List calling conventions available to one analyzed function.", {}}},
			{"bn_calling_convention_set", {"Functions", "Set a function's user calling convention.", {}}},
			{"bn_comment_delete", {"Data and references", "Delete the comment at an address.", {}}},
			{"bn_comment_get", {"Data and references", "Return the comment at an address.", {}}},
			{"bn_comment_list", {"Data and references", "List all global address comments with bounded pagination.", {}}},
			{"bn_comment_search", {"Data and references", "Search global address comments case-insensitively.", {}}},
			{"bn_comment_set", {"Data and references", "Set a non-empty comment at an address.", {}}},
			{"bn_compute_status", {"Sessions and compute", "Report daemon analysis capacity and allocation.", {}}},
			{"bn_constant_search", {"Data and references", "Search globally for rendered uses of one constant or address value.", {}}},
			{"bn_data_at", {"Data and references", "Return compact data context at an address.", {}}},
			{"bn_data_variable_define", {"Data and references", "Define a typed user data variable; use definition for a direct type, or source plus optional type to select a parsed declaration.", {}}},
			{"bn_data_variable_list", {"Data and references", "List typed data variables with compact rows.", {}}},
			{"bn_data_variable_undefine", {"Data and references", "Remove an exact data variable.", {}}},
			{"bn_data_xrefs_from", {"Data and references", "List addresses referenced by data values stored at an address or range; code instruction references are excluded.", {}}},
			{"bn_data_xrefs_to", {"Data and references", "List data locations that reference a target address or range; code instruction references are excluded.", {}}},
			{"bn_debugger_adapter_list", {"Debugger", "List debugger adapters available for an explicit BinaryView.", {}}},
			{"bn_debugger_attach", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_attach_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_breakpoint_add", {"Debugger", "Add an absolute software breakpoint.", {}}},
			{"bn_debugger_breakpoint_delete", {"Debugger", "Delete an absolute software breakpoint.", {}}},
			{"bn_debugger_breakpoint_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_configure", {"Debugger", "Configure the debugger adapter and target.", {}}},
			{"bn_debugger_connect", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_connect_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_detach", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_frame_list", {"Debugger", "List stack frames for a target thread.", {}}},
			{"bn_debugger_go", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_go_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_launch", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_launch_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_memory_read", {"Debugger", "Read target process memory.", {}}},
			{"bn_debugger_memory_region_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_memory_write", {"Debugger", "Write target process memory from hexadecimal bytes.", {}}},
			{"bn_debugger_module_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_pause", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_pause_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_process_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_quit", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_register_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_register_set", {"Debugger", "Set one target register value.", {}}},
			{"bn_debugger_restart", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_restart_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_status", {"Debugger", "Return debugger state and target configuration.", {}}},
			{"bn_debugger_step_into", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_step_into_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_step_over", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_step_over_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_step_return", {"Debugger", "Issue an immediate debugger control operation.", {}}},
			{"bn_debugger_step_return_and_wait", {"Debugger", "Run a bounded debugger control operation as an attached or detached job.", {}}},
			{"bn_debugger_thread_list", {"Debugger", "List debugger target state.", {}}},
			{"bn_debugger_thread_set", {"Debugger", "Select the active debugger target thread.", {}}},
			{"bn_diff_apply_from_secondary", {"Diffing", "Explicitly invoke Google BinDiff's native metadata transfer for one exact match, mutating only the primary view.", {}}},
			{"bn_diff_function_matches", {"Diffing", "List Google BinDiff matches for one primary function.", {}}},
			{"bn_diff_match_info", {"Diffing", "Return one exact primary-to-secondary function match.", {}}},
			{"bn_diff_match_list", {"Diffing", "List cached function matches with query, metric thresholds, deterministic sorting, and pagination.", {}}},
			{"bn_diff_port_name_from_secondary", {"Diffing", "Explicitly copy one matched secondary function name onto the primary function.", {}}},
			{"bn_diff_port_names_from_secondary", {"Diffing", "Copy high-confidence secondary names onto auto-named primary functions while preserving existing primary names.", {}}},
			{"bn_diff_primary_unmatched_list", {"Diffing", "List unmatched primary functions with deterministic sorting and pagination.", {}}},
			{"bn_diff_run_project", {"Diffing", "Run a job-backed Google BinDiff comparison against a project-relative secondary BNDB; results target the primary view.", {}}},
			{"bn_diff_run_view", {"Diffing", "Run a job-backed Google BinDiff comparison after saving an open secondary BinaryView to a temporary BNDB; results target the primary view.", {}}},
			{"bn_diff_secondary_unmatched_list", {"Diffing", "List unmatched secondary functions with deterministic sorting and pagination.", {}}},
			{"bn_diff_summary", {"Diffing", "Summarize one cached Google BinDiff comparison with matched/unmatched counts plus exact/changed and score aggregates.", {}}},
			{"bn_elf_dynamic_entry_list", {"Header Parsing", "List parsed ELF dynamic entries and resolve string-valued tags such as NEEDED, SONAME, RPATH, and RUNPATH.", {}}},
			{"bn_elf_program_header_list", {"Header Parsing", "List parsed ELF program headers, including interpreter, dynamic, GNU stack, and GNU RELRO segments.", {}}},
			{"bn_entry_point_add", {"Symbols and entries", "Add an analysis entry point at a mapped address using the BinaryView's default platform.", {}}},
			{"bn_entry_point_list", {"Symbols and entries", "List loader entry functions; KernelCache views include module init/term targets with analyzed state.", {}}},
			{"bn_export_list", {"Symbols and entries", "List exports; enabled KernelCache views use loaded-image cache symbols.", {}}},
			{"bn_function_callees", {"Functions", "List callees reached from callsites in one analyzed function.", {}}},
			{"bn_function_callers", {"Functions", "List callsites that call one analyzed function.", {}}},
			{"bn_function_create", {"Functions", "Create a user function at a mapped address; defining a FunctionSymbol alone does not create a function.", {}}},
			{"bn_function_decompile", {"Functions", "Render an exact analyzed function, default 200 lines; language auto-selects Pseudo Objective-C or Pseudo Rust when applicable; confirm targets with function_list first.", {}}},
			{"bn_function_delete", {"Functions", "Remove one exact function as a persistent user analysis override.", {}}},
			{"bn_function_disassembly", {"Functions", "Render 200 disassembly lines by default; continue with nextOffset.", {}}},
			{"bn_function_il", {"Functions", "Render 200 LLIL, MLIL, or HLIL lines by default; continue with nextOffset.", {}}},
			{"bn_function_info", {"Functions", "Return detailed metadata for one analyzed function.", {}}},
			{"bn_function_list", {"Functions", "List functions; query first, default 50 rows, then continue with nextOffset.", {}}},
			{"bn_function_prototype_set", {"Functions", "Set a parsed user prototype; if needsUpdate, run analysis update before variable rename/readback.", {}}},
			{"bn_function_stack_layout", {"Functions", "List stack variables for one analyzed function.", {}}},
			{"bn_function_xrefs_from", {"Functions", "List code references originating in one analyzed function.", {}}},
			{"bn_function_xrefs_to", {"Functions", "List code references into one analyzed function.", {}}},
			{"bn_il_search", {"Data and references", "Search rendered LLIL, MLIL, or HLIL across analyzed functions.", {}}},
			{"bn_import_list", {"Symbols and entries", "List import symbols with compact rows.", {}}},
			{"bn_instruction_search", {"Data and references", "Search rendered disassembly text across an explicit address range or the whole view.", {}}},
			{"bn_job_cancel", {"Jobs", "Request cancellation of a detached job.", {}}},
			{"bn_job_info", {"Jobs", "Inspect a detached job.", {}}},
			{"bn_job_list", {"Jobs", "List detached jobs owned by this bearer token.", {}}},
			{"bn_job_result", {"Jobs", "Retrieve and consume a terminal detached-job result.", {}}},
			{"bn_kernel_cache_image_info", {"KernelCache", "Inspect one exact KernelCache image and its dependencies.", {}}},
			{"bn_kernel_cache_image_list", {"KernelCache", "List KernelCache images; query first, default 50 rows, then continue with nextOffset.", {}}},
			{"bn_kernel_cache_image_load", {"KernelCache", "Load one exact KernelCache image into the BinaryView.", {}}},
			{"bn_kernel_cache_symbol_list", {"KernelCache", "List exported KernelCache symbols.", {}}},
			{"bn_linked_library_list", {"Header Parsing", "List libraries linked by Mach-O load commands, ELF DT_NEEDED entries, or PE import and delay-import tables.", {}}},
			{"bn_local_project_create", {"Projects", "Create a local project beneath the configured default root, or at an absolute path for an administrator.", {}}},
			{"bn_local_project_directory_import", {"Projects", "Import a server-local directory recursively as an attached or detached job, preserving hierarchy, including hidden files, skipping symlinks, and rejecting destination file collisions.", {}}},
			{"bn_local_project_file_delete", {"Projects", "Delete a local project file selected by project and path.", {}}},
			{"bn_local_project_file_import", {"Projects", "Import one server-local regular file with optional project-file name and description; administrator only.", {}}},
			{"bn_local_project_file_import_batch", {"Projects", "Import up to 1000 server-local regular files with optional per-file names and descriptions; administrator only.", {}}},
			{"bn_local_project_file_list", {"Projects", "List local project files and their names, descriptions, paths, folders, and timestamps with optional filters.", {}}},
			{"bn_local_project_file_update", {"Projects", "Update a local project file selected by project and path: set, replace, or clear its description, rename it, or move it to a folder path.", {}}},
			{"bn_local_project_folder_create", {"Projects", "Create a local project folder beneath an optional parent path.", {}}},
			{"bn_local_project_folder_delete", {"Projects", "Recursively delete a local project folder selected by project and path.", {}}},
			{"bn_local_project_folder_list", {"Projects", "List folders in a local project.", {}}},
			{"bn_local_project_folder_update", {"Projects", "Update or move a local project folder selected by project and path.", {}}},
			{"bn_local_project_info", {"Projects", "Inspect a local project.", {}}},
			{"bn_local_project_list", {"Projects", "List local projects.", {}}},
			{"bn_local_project_register", {"Projects", "Register an existing local .bnpr or .bnpm project by absolute path.", {}}},
			{"bn_local_project_relocate", {"Projects", "Copy an outside-root local project into a configured root, verify its durable ID, retain the source on disk, and remove the source registration; administrator only.", {}}},
			{"bn_local_project_root_list", {"Projects", "List configured project roots by config-order index without exposing filesystem paths.", {}}},
			{"bn_local_project_update", {"Projects", "Update local project metadata.", {}}},
			{"bn_macho_load_command_list", {"Header Parsing", "List parsed Mach-O load commands with command-specific fields.", {}}},
			{"bn_memory_map_preview", {"Memory and strings", "Preview a segment or rebase operation without mutating the BinaryView.", {}}},
			{"bn_memory_read", {"Memory and strings", "Read mapped bytes as lowercase hexadecimal.", {}}},
			{"bn_memory_search", {"Data and references", "Search mapped bytes with Binary Ninja advanced binary-search syntax.", {}}},
			{"bn_metadata_delete", {"Other", "Delete one persistent custom BinaryView metadata value in the binjad.user namespace.", {}}},
			{"bn_metadata_get", {"Other", "Read one persistent custom BinaryView metadata value in the binjad.user namespace.", {}}},
			{"bn_metadata_set", {"Other", "Store one arbitrary JSON custom BinaryView metadata value in the binjad.user namespace.", {}}},
			{"bn_open_item_close", {"Files and views", "Close an open item.", {}}},
			{"bn_open_item_list", {"Files and views", "List open items owned by this bearer token across concurrent analysis sessions; close only items created by your workflow.", {}}},
			{"bn_open_item_open", {"Files and views", "Discover BinaryView candidates for an authorized path or project file; call bn_binary_view_open before using a candidate.", {}}},
			{"bn_pe_data_directory_list", {"Header Parsing", "List parsed PE optional-header data directories with names, RVAs, mapped addresses, and sizes.", {}}},
			{"bn_project_analysis_search", {"Data and references", "Search functions, symbols, strings, and comments across materialized BinaryViews currently open from one project.", {}}},
			{"bn_project_file_open", {"Projects", "Discover BinaryView candidates for a project file; call bn_binary_view_open before using a candidate.", {}}},
			{"bn_project_json_read", {"Projects", "Navigate a project JSON file by RFC 6901 pointer; paginate object keys or array indexes without expanding unrelated subtrees.", {}}},
			{"bn_project_text_read", {"Projects", "Read a UTF-8 project file by lines with resumable pagination and an optional case-insensitive line query.", {}}},
			{"bn_redo", {"Other", "Redo the last undone mutation for an explicit BinaryView's file.", {}}},
			{"bn_relocation_list", {"Data and references", "List full relocation metadata.", {}}},
			{"bn_section_create", {"Sections and segments", "Create a user-defined section.", {}}},
			{"bn_section_delete", {"Sections and segments", "Delete an exact auto- or user-defined section.", {}}},
			{"bn_section_list", {"Sections and segments", "List section ranges and semantics.", {}}},
			{"bn_section_modify", {"Sections and segments", "Modify an exact auto- or user-defined section.", {}}},
			{"bn_segment_create", {"Sections and segments", "Create a user mapped segment.", {}}},
			{"bn_segment_delete", {"Sections and segments", "Delete one exact user mapped segment.", {}}},
			{"bn_segment_list", {"Sections and segments", "List full mapped-segment metadata.", {}}},
			{"bn_segment_modify", {"Sections and segments", "Replace one exact user mapped segment.", {}}},
			{"bn_shared_cache_entry_list", {"SharedCache", "List files comprising a SharedCache.", {}}},
			{"bn_shared_cache_image_info", {"SharedCache", "Inspect one exact SharedCache image and its dependencies.", {}}},
			{"bn_shared_cache_image_list", {"SharedCache", "List images available in a SharedCache BinaryView.", {}}},
			{"bn_shared_cache_image_load", {"SharedCache", "Load one exact SharedCache image into the BinaryView.", {}}},
			{"bn_shared_cache_region_list", {"SharedCache", "List SharedCache regions.", {}}},
			{"bn_shared_cache_region_load", {"SharedCache", "Load one exact SharedCache region into the BinaryView.", {}}},
			{"bn_shared_cache_symbol_list", {"SharedCache", "List exported SharedCache symbols.", {}}},
			{"bn_string_at", {"Memory and strings", "Return detailed decoded string data at an address.", {}}},
			{"bn_string_define", {"Memory and strings", "Define a typed user string data object at an address.", {}}},
			{"bn_string_list", {"Memory and strings", "List strings; query first, default 50 rows, then continue with nextOffset.", {}}},
			{"bn_string_undefine", {"Memory and strings", "Undefine a user string data object at an address.", {}}},
			{"bn_symbol_define", {"Symbols and entries", "Define a user symbol at an address; FunctionSymbol annotation does not create a function.", {}}},
			{"bn_symbol_list", {"Symbols and entries", "List symbols; query first, default 50 rows, then continue with nextOffset.", {}}},
			{"bn_symbol_list_at", {"Symbols and entries", "Return full symbol metadata at an exact address.", {}}},
			{"bn_symbol_rename", {"Symbols and entries", "Rename one exactly selected symbol.", {}}},
			{"bn_symbol_undefine", {"Symbols and entries", "Undefine one exactly selected user symbol.", {}}},
			{"bn_tag_create", {"Other", "Create a persistent user data tag at an address, creating its tag type when needed.", {}}},
			{"bn_tag_delete", {"Other", "Delete one persistent user tag by its Binary Ninja tag id.", {}}},
			{"bn_tag_list", {"Other", "List persistent user tags with optional type/data query filters.", {}}},
			{"bn_tools", {"Tool discovery", "Discover and call enabled binjad tools omitted from brokered discovery. Operations: categories; list(category, query?, offset?, limit?); describe(name); call(name, arguments?). Categories: core, project_management, function_analysis, binary_data, search, types, annotations, binary_editing, history, header_parsing, url_generation, diffing, kernel_cache, shared_cache, debugger. Use describe before call so the selected tool's arguments follow its exact schema.", {}}},
			{"bn_transaction_begin", {"Other", "Begin one explicit undo transaction for an explicit BinaryView's open item.", {}}},
			{"bn_transaction_commit", {"Other", "Commit the active transaction for an explicit BinaryView.", {}}},
			{"bn_transaction_rollback", {"Other", "Roll back the active transaction for an explicit BinaryView.", {}}},
			{"bn_type_define", {"Types", "Parse and define selected named types.", {}}},
			{"bn_type_delete", {"Types", "Delete one exact named type.", {}}},
			{"bn_type_enum_create", {"Types", "Parse and define exactly one new enum type.", {}}},
			{"bn_type_enum_modify", {"Types", "Parse and replace exactly one existing enum type.", {}}},
			{"bn_type_info", {"Types", "Return metadata and a complete C declaration for one named type.", {}}},
			{"bn_type_list", {"Types", "List named types with compact class rows.", {}}},
			{"bn_type_parse", {"Types", "Parse C source without defining types.", {}}},
			{"bn_type_rename", {"Types", "Rename one exact named type.", {}}},
			{"bn_type_struct_create", {"Types", "Parse and define exactly one new struct type.", {}}},
			{"bn_type_struct_modify", {"Types", "Parse and replace exactly one existing struct type.", {}}},
			{"bn_type_union_create", {"Types", "Parse and define exactly one new union type.", {}}},
			{"bn_type_union_modify", {"Types", "Parse and replace exactly one existing union type.", {}}},
			{"bn_type_xrefs_from", {"Types", "List outgoing named-type references.", {}}},
			{"bn_type_xrefs_to", {"Types", "List grouped incoming code, data, and type references.", {}}},
			{"bn_undo", {"Other", "Undo the last committed mutation for an explicit BinaryView's file.", {}}},
			{"bn_upload_cancel", {"Uploads", "Cancel and remove an inactive staged upload.", {}}},
			{"bn_upload_commit", {"Uploads", "Commit a completed staged upload idempotently to its bound project.", {}}},
			{"bn_upload_get_url", {"Uploads", "Issue a session-, project-, and filename-bound one-time upload capability with transport instructions.", {}}},
			{"bn_upload_list", {"Uploads", "List staged uploads owned by this bearer token.", {}}},
			{"bn_url_open_item", {"URL Generation", "Generate a Binary Ninja URL for an owned arbitrary-path open item, optionally navigating to an expr.", {}}},
			{"bn_url_project_file", {"URL Generation", "Generate a Binary Ninja URL for the committed BNDB backing an owned local-project open item. Call bn_binary_view_save first, then explicitly confirm that the updated BNDB has been saved.", {}}},
			{"bn_url_remote_file", {"URL Generation", "Generate a Binary Ninja URL for an absolute http, https, or file URL, optionally navigating to an expr.", {}}},
			{"bn_variable_list", {"Functions", "List variables for one analyzed function.", {}}},
			{"bn_variable_rename", {"Functions", "Rename one variable after prototype edits; follow returned nextAction before readback.", {}}},
			{"bn_variable_set_type", {"Functions", "Set one variable type; follow returned nextAction before readback.", {}}},
			};

			const std::tuple<std::string_view, std::string_view, std::string_view> arguments[] {
				{"bn_analysis_session_list", "limit", kPage50Response},
				{"bn_open_item_open", "options", kLoadOptions},
				{"bn_open_item_list", "limit", kPage50Response},
				{"bn_binary_view_list", "limit", kPage50Response},
				{"bn_function_list", "limit", "Defaults to 50; use query and continue with nextOffset."},
				{"bn_function_disassembly", "limit", kPage50},
				{"bn_function_decompile", "language",
					"Omit for automatic Pseudo Objective-C on Objective-C methods, Pseudo Rust on Rust symbols, and Pseudo C "
					"otherwise; explicit names are case/separator insensitive."},
				{"bn_function_decompile", "limit", kRendered200},
				{"bn_string_list", "limit", kPage50Query},
				{"bn_symbol_list", "limit", kPage50Query},
				{"bn_job_list", "limit", kPage50Response},
				{"bn_function_callers", "limit", kPage50},
				{"bn_function_callees", "limit", kPage50},
				{"bn_function_il", "limit", kRendered200},
				{"bn_function_stack_layout", "limit", kPage50},
				{"bn_function_xrefs_from", "limit", kPage50},
				{"bn_function_xrefs_to", "limit", kPage50},
				{"bn_import_list", "limit", kPage50Query},
				{"bn_export_list", "limit", kPage50Query},
				{"bn_variable_list", "limit", kPage50},
				{"bn_tools", "operation",
					"Choose category discovery, compact tool listing, exact schema lookup, or invocation."},
				{"bn_tools", "category", "Required by list."},
				{"bn_tools", "query", "Optional case-insensitive name or description filter."},
				{"bn_tools", "name", "Required by describe and call."},
				{"bn_tools", "arguments", "Arguments for the selected tool when operation is call."},
				{"bn_diff_run_view", "primary", kDiffPrimary},
				{"bn_diff_run_view", "secondary",
					"Materialized secondary BinaryView to save as a temporary read-only BNDB."},
				{"bn_diff_run_project", "primary", kDiffPrimary},
				{"bn_diff_run_project", "secondary", kDiffSecondary},
				{"bn_diff_run_project", "project", kDiffProject},
				{"bn_diff_summary", "primary", kDiffPrimary},
				{"bn_diff_summary", "secondary", kDiffSecondary},
				{"bn_diff_summary", "project", kDiffProject},
				{"bn_diff_match_list", "primary", kDiffPrimary},
				{"bn_diff_match_list", "secondary", kDiffSecondary},
				{"bn_diff_match_list", "project", kDiffProject},
				{"bn_diff_primary_unmatched_list", "primary", kDiffPrimary},
				{"bn_diff_primary_unmatched_list", "secondary", kDiffSecondary},
				{"bn_diff_primary_unmatched_list", "project", kDiffProject},
				{"bn_diff_secondary_unmatched_list", "primary", kDiffPrimary},
				{"bn_diff_secondary_unmatched_list", "secondary", kDiffSecondary},
				{"bn_diff_secondary_unmatched_list", "project", kDiffProject},
				{"bn_diff_function_matches", "primary", kDiffPrimary},
				{"bn_diff_function_matches", "secondary", kDiffSecondary},
				{"bn_diff_function_matches", "project", kDiffProject},
				{"bn_diff_match_info", "primary", kDiffPrimary},
				{"bn_diff_match_info", "secondary", kDiffSecondary},
				{"bn_diff_match_info", "project", kDiffProject},
				{"bn_diff_port_name_from_secondary", "primary", kDiffPrimary},
				{"bn_diff_port_name_from_secondary", "secondary", kDiffSecondary},
				{"bn_diff_port_name_from_secondary", "project", kDiffProject},
				{"bn_diff_apply_from_secondary", "primary", kDiffPrimary},
				{"bn_diff_apply_from_secondary", "secondary", kDiffSecondary},
				{"bn_diff_apply_from_secondary", "project", kDiffProject},
				{"bn_diff_port_names_from_secondary", "primary", kDiffPrimary},
				{"bn_diff_port_names_from_secondary", "secondary", kDiffSecondary},
				{"bn_diff_port_names_from_secondary", "project", kDiffProject},
				{"bn_local_project_list", "limit", kPage50Response},
				{"bn_local_project_file_list", "folder", "Exact project-relative folder path."},
				{"bn_project_file_open", "options", kLoadOptions},
				{"bn_local_project_file_import", "folder", "Project-relative destination folder path."},
				{"bn_local_project_file_import", "description",
					"Initial project-file description; it can later be changed or cleared with "
					"bn_local_project_file_update."},
				{"bn_local_project_file_import_batch", "folder", "Project-relative destination folder path."},
				{"bn_local_project_file_import_batch", "files.description",
					"Initial project-file description for this imported file."},
				{"bn_local_project_directory_import", "folder", "Optional project-relative destination folder."},
				{"bn_local_project_directory_import", "startAfter",
					"Resume after this exact source-relative path from a prior result's lastCompleted field."},
				{"bn_local_project_directory_import", "description",
					"Description assigned to every imported project file."},
				{"bn_local_project_relocate", "path",
					"Contained destination path beneath the selected root, ending in the source project extension."},
				{"bn_local_project_file_update", "description",
					"Set or replace the project-file description; pass an empty string to clear it."},
				{"bn_local_project_file_update", "folder",
					"Project-relative destination folder path, or null for project root."},
				{"bn_project_text_read", "query",
					"Optional case-insensitive line filter; offsets apply to matching lines."},
				{"bn_project_json_read", "pointer",
					"RFC 6901 JSON Pointer selecting the value to inspect; omit or use an empty string for the root."},
				{"bn_upload_commit", "folder", "Project-relative folder path; missing folders are created."},
				{"bn_upload_list", "limit", kPage50Response},
				{"bn_url_open_item", "openItem",
					"Owned arbitrary-path open-item reference. Use bn_url_project_file for local-project items."},
				{"bn_url_open_item", "expr", kUrlExpression},
				{"bn_url_project_file", "openItem",
					"Owned local-project open-item reference targeting a committed BNDB."},
				{"bn_url_project_file", "updated_bndb_has_been_saved",
					"Required true acknowledgment that bn_binary_view_save completed after the latest relevant changes. The "
					"URL opens committed project contents and cannot include unsaved file-child state."},
				{"bn_url_project_file", "expr", kUrlExpression},
				{"bn_url_remote_file", "url",
					"Percent-encoded absolute http, https, or file URL for Binary Ninja to download or open."},
				{"bn_url_remote_file", "expr", kUrlExpression},
			};
			// clang-format on
			for (const auto& [tool, argument, description] : arguments)
			{
				const auto found = tools.find(tool);
				if (found == tools.end())
					throw std::logic_error("argument documentation references an unknown tool: " + std::string(tool));
				if (!found->second.arguments.emplace(argument, description).second)
					throw std::logic_error("duplicate model-facing argument documentation: " + std::string(tool) + "."
						+ std::string(argument));
			}
			return tools;
		}();
		return tools;
	}

	const ToolDocumentation& Tool(std::string_view name)
	{
		const auto& tools = Tools();
		const auto found = tools.find(name);
		if (found == tools.end())
			throw std::logic_error("missing model-facing tool documentation: " + std::string(name));
		return found->second;
	}

	std::string_view ToolArgument(std::string_view tool, std::string_view argument)
	{
		const auto& arguments = Tool(tool).arguments;
		const auto found = arguments.find(argument);
		return found == arguments.end() ? std::string_view {} : found->second;
	}
}  // namespace binjad::mcp::docs
