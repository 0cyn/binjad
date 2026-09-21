#include "../PluginToolSupport.hpp"
#include "../ToolCall.hpp"

#include <sharedcacheapi.h>

#include <algorithm>
#include <string>
#include <vector>

namespace binjad {
	using namespace file_process::plugin;

	namespace {
#define BINJAD_SHARED_TOOL(Type, Name) \
	class Type final : public FileChildToolCall \
	{ \
	public: \
		Type() : FileChildToolCall(Name) {} \
		ipc::Reply Execute(const FileChildToolCallContext& context) const override; \
	}; \
	ipc::Reply Type::Execute(const FileChildToolCallContext& context) const

		BINJAD_SHARED_TOOL(SharedCacheImageListTool, "bn_shared_cache_image_list")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
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
				output.Key("headerAddress");
				WriteAddress(output, image.headerAddress);
				output.Key("regionCount");
				output.Uint64(image.regionStarts.size());
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_SHARED_TOOL(SharedCacheImageInfoTool, "bn_shared_cache_image_info")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
			RequireOnly(context.arguments, {"binaryView", "image"});
			const auto name = RequiredString(context.arguments, "image");
			const auto image = controller->GetImageWithName(name);
			if (!image)
				throw std::invalid_argument("SharedCache image not found");
			// The matched C++ wrapper leaves its count uninitialized when the plugin returns no list.
			BNSharedCacheImage apiImage {};
			apiImage.name = BNAllocString(image->name.c_str());
			apiImage.headerAddress = image->headerAddress;
			apiImage.regionStartCount = image->regionStarts.size();
			auto regionStarts = image->regionStarts;
			apiImage.regionStarts = BNSharedCacheAllocRegionList(regionStarts.data(), regionStarts.size());
			std::size_t dependencyCount = 0;
			auto** rawDependencies =
				BNSharedCacheControllerGetImageDependencies(controller->GetObject(), &apiImage, &dependencyCount);
			BNSharedCacheFreeImage(apiImage);
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
			writer.Key("headerAddress");
			WriteAddress(writer, image->headerAddress);
			writer.Key("loaded");
			writer.Bool(controller->IsImageLoaded(*image));
			writer.Key("regions");
			writer.StartArray();
			for (const auto address : image->regionStarts)
				WriteAddress(writer, address);
			writer.EndArray();
			writer.Key("dependencies");
			writer.StartArray();
			for (const auto& dependency : dependencies)
				writer.String(dependency.data(), static_cast<rapidjson::SizeType>(dependency.size()));
			writer.EndArray();
			writer.EndObject();
			return JsonReply(buffer);
		};

		BINJAD_SHARED_TOOL(SharedCacheImageLoadTool, "bn_shared_cache_image_load")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
			RequireOnly(context.arguments, {"binaryView", "image"});
			const auto name = RequiredString(context.arguments, "image");
			const auto image = controller->GetImageWithName(name);
			if (!image)
				throw std::invalid_argument("SharedCache image not found");
			const auto alreadyLoaded = controller->IsImageLoaded(*image);
			const auto applied = alreadyLoaded || controller->ApplyImage(*context.view->view, *image);
			if (!applied)
				throw std::runtime_error("SharedCache image could not be loaded");
			if (!alreadyLoaded)
			{
				context.view->view->AddAnalysisOption("linearsweep");
				context.view->view->AddAnalysisOption("pointersweep");
			}
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

		BINJAD_SHARED_TOOL(SharedCacheRegionListTool, "bn_shared_cache_region_list")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
			RequireOnly(context.arguments, {"binaryView", "loaded", "query", "offset", "limit"});
			const auto loaded = OptionalBoolean(context.arguments, "loaded", false);
			const auto query = OptionalString(context.arguments, "query");
			const auto [offset, limit] = Pagination(context.arguments);
			auto regions = loaded ? controller->GetLoadedRegions() : controller->GetRegions();
			if (!query.empty())
				std::erase_if(regions, [&](const auto& region) { return !ContainsInsensitive(region.name, query); });
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, regions, offset, limit, [&](auto& output, const auto& region) {
				output.StartObject();
				output.Key("name");
				output.String(region.name.data(), static_cast<rapidjson::SizeType>(region.name.size()));
				output.Key("start");
				WriteAddress(output, region.start);
				output.Key("size");
				output.Uint64(region.size);
				output.Key("imageStart");
				WriteAddress(output, region.imageStart.value_or(0));
				output.Key("loaded");
				output.Bool(controller->IsRegionLoaded(region));
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_SHARED_TOOL(SharedCacheRegionLoadTool, "bn_shared_cache_region_load")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
			RequireOnly(context.arguments, {"binaryView", "region"});
			const auto name = RequiredString(context.arguments, "region");
			const auto regions = controller->GetRegions();
			const auto found = std::find_if(regions.begin(), regions.end(), [&](const auto& region) {
				return region.name == name;
			});
			if (found == regions.end())
				throw std::invalid_argument("SharedCache region not found");
			const auto alreadyLoaded = controller->IsRegionLoaded(*found);
			const auto applied = alreadyLoaded || controller->ApplyRegion(*context.view->view, *found);
			if (!applied)
				throw std::runtime_error("SharedCache region could not be loaded");
			if (!alreadyLoaded)
			{
				context.view->view->AddAnalysisOption("linearsweep");
				context.view->view->AddAnalysisOption("pointersweep");
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("region");
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

		BINJAD_SHARED_TOOL(SharedCacheEntryListTool, "bn_shared_cache_entry_list")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
			RequireOnly(context.arguments, {"binaryView", "query", "offset", "limit"});
			const auto query = OptionalString(context.arguments, "query");
			const auto [offset, limit] = Pagination(context.arguments);
			auto entries = controller->GetEntries();
			if (!query.empty())
			{
				std::erase_if(entries, [&](const auto& entry) {
					return !ContainsInsensitive(entry.path, query) && !ContainsInsensitive(entry.name, query);
				});
			}
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			WritePage(writer, entries, offset, limit, [](auto& output, const auto& entry) {
				output.StartObject();
				output.Key("path");
				output.String(entry.path.data(), static_cast<rapidjson::SizeType>(entry.path.size()));
				output.Key("name");
				output.String(entry.name.data(), static_cast<rapidjson::SizeType>(entry.name.size()));
				output.Key("type");
				output.Int(entry.entryType);
				output.Key("mappingCount");
				output.Uint64(entry.mappings.size());
				output.EndObject();
			});
			return JsonReply(buffer);
		};

		BINJAD_SHARED_TOOL(SharedCacheSymbolListTool, "bn_shared_cache_symbol_list")
		{
			auto controller = SharedCacheAPI::SharedCacheController::GetController(*context.view->view);
			if (!controller)
				throw std::invalid_argument("BinaryView is not a SharedCache view");
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
				output.Int(symbol.type);
				output.Key("binding");
				output.Int(symbol.binding);
				output.EndObject();
			});
			return JsonReply(buffer);
		};

#undef BINJAD_SHARED_TOOL
	}  // namespace

	void RegisterSharedCacheToolCalls(std::vector<std::unique_ptr<FileChildToolCall>>& tools)
	{
		tools.emplace_back(std::make_unique<SharedCacheImageListTool>());
		tools.emplace_back(std::make_unique<SharedCacheImageInfoTool>());
		tools.emplace_back(std::make_unique<SharedCacheImageLoadTool>());
		tools.emplace_back(std::make_unique<SharedCacheRegionListTool>());
		tools.emplace_back(std::make_unique<SharedCacheRegionLoadTool>());
		tools.emplace_back(std::make_unique<SharedCacheEntryListTool>());
		tools.emplace_back(std::make_unique<SharedCacheSymbolListTool>());
	}
}  // namespace binjad
