#include "../PluginToolSupport.hpp"
#include "../ToolCall.hpp"
#include "../ToolSupport.hpp"

#include <kernelcacheapi.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace binjad {
	using namespace file_process;
	using namespace file_process::plugin;

	namespace {
#define BINJAD_KERNEL_TOOL(Type, Name) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& context) const override; \
	}; \
	ipc::Reply Type::Execute(const FileChildToolCallContext& context) const

		BINJAD_KERNEL_TOOL(KernelCacheImageListTool, "bn_kernel_cache_image_list")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(context.arguments, {"binaryView", "loaded", "query", "offset", "limit"});
			const auto loaded = OptionalBoolean(context.arguments, "loaded", false);
			const auto query = OptionalString(context.arguments, "query");
			const auto [offset, limit] = Pagination(context.arguments);
			auto images = loaded ? controller->GetLoadedImages() : controller->GetImages();
			if (!query.empty())
				std::erase_if(images, [&](const auto& image) { return !ContainsInsensitive(image.name, query); });
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, images, offset, limit, [](auto& output, const auto& image) {
				output.StartObject();
				output.Key("name");
				output.String(image.name.data(), static_cast<rapidjson::SizeType>(image.name.size()));
				output.Key("headerVirtualAddress");
				WriteAddress(output, image.headerVirtualAddress);
				output.Key("headerFileAddress");
				WriteAddress(output, image.headerFileAddress);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_KERNEL_TOOL(KernelCacheImageInfoTool, "bn_kernel_cache_image_info")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(context.arguments, {"binaryView", "image"});
			const auto name = RequiredString(context.arguments, "image");
			const auto image = controller->GetImageWithName(name);
			if (!image)
				throw std::invalid_argument("KernelCache image not found");
			// The matched C++ wrapper leaves its count uninitialized when the plugin returns no list.
			BNKernelCacheImage apiImage {
				BNAllocString(image->name.c_str()), image->headerVirtualAddress, image->headerFileAddress};
			std::size_t dependencyCount = 0;
			auto** rawDependencies =
				BNKernelCacheControllerGetImageDependencies(controller->GetObject(), &apiImage, &dependencyCount);
			BNKernelCacheFreeImage(apiImage);
			std::vector<std::string> dependencies;
			dependencies.reserve(dependencyCount);
			for (std::size_t index = 0; index < dependencyCount; ++index)
				dependencies.emplace_back(rawDependencies[index]);
			BNFreeStringList(rawDependencies, dependencyCount);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("name");
			writer.String(image->name.data(), static_cast<rapidjson::SizeType>(image->name.size()));
			writer.Key("headerVirtualAddress");
			WriteAddress(writer, image->headerVirtualAddress);
			writer.Key("headerFileAddress");
			WriteAddress(writer, image->headerFileAddress);
			writer.Key("loaded");
			writer.Bool(controller->IsImageLoaded(*image));
			writer.Key("dependencies");
			writer.StartArray();
			for (const auto& dependency : dependencies)
				writer.String(dependency.data(), static_cast<rapidjson::SizeType>(dependency.size()));
			writer.EndArray();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_KERNEL_TOOL(KernelCacheImageLoadTool, "bn_kernel_cache_image_load")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(context.arguments, {"binaryView", "image"});
			const auto name = RequiredString(context.arguments, "image");
			const auto image = controller->GetImageWithName(name);
			if (!image)
				throw std::invalid_argument("KernelCache image not found");
			const auto alreadyLoaded = controller->IsImageLoaded(*image);
			const auto applied = alreadyLoaded || controller->ApplyImage(*context.view->view, *image);
			if (!applied)
				throw std::runtime_error("KernelCache image could not be loaded");
			if (!alreadyLoaded)
				context.view->view->AddAnalysisOption("linearsweep");
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("image");
			writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
			writer.Key("loaded");
			writer.Bool(true);
			writer.Key("alreadyLoaded");
			writer.Bool(alreadyLoaded);
			if (!alreadyLoaded)
			{
				writer.Key("nextAction");
				writer.String(
					"call bn_analysis_update_and_wait; if it returns a running job, poll bn_job_info no more than "
					"every 10 seconds and call bn_job_result when terminal");
			}
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_KERNEL_TOOL(KernelCacheSymbolListTool, "bn_kernel_cache_symbol_list")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(context.arguments, {"binaryView", "query", "offset", "limit"});
			const auto query = OptionalString(context.arguments, "query");
			const auto [offset, limit] = Pagination(context.arguments);
			auto symbols = controller->GetSymbols();
			if (!query.empty())
				std::erase_if(symbols, [&](const auto& symbol) { return !ContainsInsensitive(symbol.name, query); });
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, symbols, offset, limit, [](auto& output, const auto& symbol) {
				output.StartObject();
				output.Key("address");
				WriteAddress(output, symbol.address);
				output.Key("name");
				output.String(symbol.name.data(), static_cast<rapidjson::SizeType>(symbol.name.size()));
				output.Key("type");
				output.String(symbol.type == FunctionSymbol ?
						"FunctionSymbol" :
						symbol.type == DataSymbol ?
						"DataSymbol" :
						"UnknownSymbol");
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_KERNEL_TOOL(KernelCacheEntryPointListTool, "bn_kernel_cache_entry_point_list")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(context.arguments, {"binaryView", "offset", "limit"});
			const auto [offset, limit] = Pagination(context.arguments);
			struct EntryPointRow
			{
				std::uint64_t address;
				std::string name;
				std::string source;
				bool analyzed;
			};
			std::vector<EntryPointRow> entries;
			for (const auto& section : context.view->view->GetSections())
			{
				const auto name = section->GetName();
				const bool initializer = name.ends_with("__mod_init_func");
				const bool terminator = name.ends_with("__mod_term_func");
				if (!initializer && !terminator)
					continue;
				for (auto cursor = section->GetStart();
					cursor <= section->GetEnd() && section->GetEnd() - cursor >= sizeof(std::uint64_t);
					cursor += sizeof(std::uint64_t))
				{
					std::uint64_t target = 0;
					if (context.view->view->Read(&target, cursor, sizeof(target)) != sizeof(target) || target == 0
						|| !context.view->view->IsValidOffset(target))
						continue;
					const auto symbol = context.view->view->GetSymbolByAddress(target);
					const auto functions = context.view->view->GetAnalysisFunctionsForAddress(target);
					entries.push_back({target, symbol ? symbol->GetShortName() : HexAddress(target),
						initializer ? "kernelCacheModInit" : "kernelCacheModTerm", !functions.empty()});
				}
			}
			auto symbols = controller->GetSymbols();
			std::erase_if(symbols, [&](const auto& symbol) {
				if (symbol.type != FunctionSymbol || !context.view->view->IsValidOffset(symbol.address))
					return true;
				const auto name = Lower(symbol.name);
				return name.find("module_start") == std::string::npos && name != "_kmod_start" && name != "kmod_start"
					&& name != "_start" && name != "start";
			});
			for (const auto& symbol : symbols)
				entries.push_back({symbol.address, symbol.name, "kernelCacheModuleStart", true});
			std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
				if (left.address != right.address)
					return left.address < right.address;
				return left.source < right.source;
			});
			entries.erase(
				std::unique(entries.begin(), entries.end(),
					[](const auto& left, const auto& right) {
						return left.address == right.address && left.source == right.source;
					}),
				entries.end());
			const auto begin = std::min(offset, entries.size());
			const auto end = std::min(entries.size(), begin + std::min(limit, entries.size() - begin));
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("entryPoints");
			writer.StartArray();
			for (std::size_t index = begin; index < end; ++index)
			{
				writer.StartObject();
				writer.Key("address");
				WriteAddress(writer, entries[index].address);
				writer.Key("name");
				writer.String(entries[index].name.data(), static_cast<rapidjson::SizeType>(entries[index].name.size()));
				writer.Key("source");
				writer.String(
					entries[index].source.data(), static_cast<rapidjson::SizeType>(entries[index].source.size()));
				writer.Key("analyzed");
				writer.Bool(entries[index].analyzed);
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(end - begin);
			writer.Key("total");
			writer.Uint64(entries.size());
			writer.Key("nextOffset");
			if (end < entries.size())
				writer.Uint64(end);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(end < entries.size());
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_KERNEL_TOOL(KernelCacheExportListTool, "bn_kernel_cache_export_list")
		{
			auto controller = KernelCacheAPI::KernelCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a KernelCache view");
			RequireOnly(
				context.arguments, {"binaryView", "offset", "limit", "address", "start", "end", "length", "query"});
			auto symbols = controller->GetSymbols();
			std::erase_if(symbols, [&](const auto& symbol) {
				return !context.view->view->IsValidOffset(symbol.address);
			});
			std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
				if (left.address != right.address)
					return left.address < right.address;
				if (left.type != right.type)
					return left.type < right.type;
				return left.name < right.name;
			});
			symbols.erase(
				std::unique(symbols.begin(), symbols.end(),
					[](const auto& left, const auto& right) {
						return left.address == right.address && left.type == right.type && left.name == right.name;
					}),
				symbols.end());
			std::optional<std::uint64_t> address;
			std::optional<std::uint64_t> start;
			std::optional<std::uint64_t> end;
			if (const auto member = context.arguments.FindMember("address"); member != context.arguments.MemberEnd())
				address = ParseExpression(*context.view->view, member->value, "address");
			if (const auto member = context.arguments.FindMember("start"); member != context.arguments.MemberEnd())
				start = ParseExpression(*context.view->view, member->value, "start");
			if (const auto member = context.arguments.FindMember("end"); member != context.arguments.MemberEnd())
				end = ParseExpression(*context.view->view, member->value, "end");
			if (const auto member = context.arguments.FindMember("length"); member != context.arguments.MemberEnd())
			{
				const auto length = member->value.IsUint64() ?
					member->value.GetUint64() :
					ParseExpression(*context.view->view, member->value, "length");
				if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
					throw std::invalid_argument("export range length is invalid");
				end = *start + length;
			}
			const auto query = OptionalString(context.arguments, "query");
			std::erase_if(symbols, [&](const auto& symbol) {
				if (symbol.type != FunctionSymbol && symbol.type != DataSymbol)
					return true;
				if (address && symbol.address != *address)
					return true;
				if (start && symbol.address < *start)
					return true;
				if (end && symbol.address >= *end)
					return true;
				return !query.empty() && !ContainsInsensitive(symbol.name, query);
			});
			const auto [offset, limit] = Pagination(context.arguments);
			const auto begin = std::min(offset, symbols.size());
			const auto pageEnd = std::min(symbols.size(), begin + std::min(limit, symbols.size() - begin));
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("symbols");
			writer.StartArray();
			for (std::size_t index = begin; index < pageEnd; ++index)
			{
				const auto& symbol = symbols[index];
				writer.StartObject();
				writer.Key("address");
				WriteAddress(writer, symbol.address);
				writer.Key("name");
				writer.String(symbol.name.data(), static_cast<rapidjson::SizeType>(symbol.name.size()));
				writer.Key("type");
				writer.String(symbol.type == FunctionSymbol ? "FunctionSymbol" : "DataSymbol");
				writer.EndObject();
			}
			writer.EndArray();
			writer.Key("count");
			writer.Uint64(pageEnd - begin);
			writer.Key("total");
			writer.Uint64(symbols.size());
			writer.Key("nextOffset");
			if (pageEnd < symbols.size())
				writer.Uint64(pageEnd);
			else
				writer.Null();
			writer.Key("truncated");
			writer.Bool(pageEnd < symbols.size());
			writer.EndObject();
			return JsonReply(buffer);
		};

#undef BINJAD_KERNEL_TOOL
	}  // namespace

	void RegisterKernelCacheToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<KernelCacheImageListTool>());
		tools.emplace_back(std::make_unique<KernelCacheImageInfoTool>());
		tools.emplace_back(std::make_unique<KernelCacheImageLoadTool>());
		tools.emplace_back(std::make_unique<KernelCacheSymbolListTool>());
		tools.emplace_back(std::make_unique<KernelCacheEntryPointListTool>());
		tools.emplace_back(std::make_unique<KernelCacheExportListTool>());
	}
}  // namespace binjad
