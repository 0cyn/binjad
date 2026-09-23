#include "binjad/binary_ninja/plugin_tools.hpp"

#include <binaryninjaapi.h>
#include <rapidjsonwrapper.h>

#include "kernelcachecore.h"
#include "sharedcachecore.h"
#include "ffi.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace binjad::binary_ninja
{
namespace
{
using rapidjson::Document;
using rapidjson::StringBuffer;
using rapidjson::Value;
using rapidjson::Writer;

class DynamicLibrary
{
  public:
    explicit DynamicLibrary(const std::filesystem::path& path)
    {
#if defined(_WIN32)
        handle_ = LoadLibraryW(path.c_str());
#else
        handle_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
        if (!handle_)
            throw std::runtime_error("cannot load Binary Ninja plugin library: " + path.string());
    }

    ~DynamicLibrary()
    {
        if (!handle_)
            return;
#if defined(_WIN32)
        FreeLibrary(handle_);
#else
        dlclose(handle_);
#endif
    }

    template <typename Function>
    Function Symbol(const char* name) const
    {
#if defined(_WIN32)
        const auto symbol = GetProcAddress(handle_, name);
#else
        const auto symbol = dlsym(handle_, name);
#endif
        if (!symbol)
            throw std::runtime_error(std::string("Binary Ninja plugin is missing required symbol ") + name);
        return reinterpret_cast<Function>(symbol);
    }

  private:
#if defined(_WIN32)
    HMODULE handle_ = nullptr;
#else
    void* handle_ = nullptr;
#endif
};

std::filesystem::path PluginPath(std::string_view baseName)
{
#if defined(_WIN32)
    const auto filename = std::string(baseName) + ".dll";
#elif defined(__APPLE__)
    const auto filename = "lib" + std::string(baseName) + ".dylib";
#else
    const auto filename = "lib" + std::string(baseName) + ".so";
#endif
    return std::filesystem::path(BinaryNinja::GetBundledPluginDirectory()) / filename;
}

Document ParseArguments(std::string_view json)
{
    Document document;
    document.Parse(json.data(), json.size());
    if (document.HasParseError() || !document.IsObject())
        throw std::invalid_argument("plugin tool arguments must be an object");
    return document;
}

void RequireOnly(const Value& value, std::initializer_list<std::string_view> fields)
{
    for (auto member = value.MemberBegin(); member != value.MemberEnd(); ++member)
    {
        const std::string_view name(member->name.GetString(), member->name.GetStringLength());
        if (std::find(fields.begin(), fields.end(), name) == fields.end())
            throw std::invalid_argument("unknown argument: " + std::string(name));
    }
}

std::string RequiredString(const Value& value, const char* name)
{
    const auto member = value.FindMember(name);
    if (member == value.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() == 0)
        throw std::invalid_argument(std::string(name) + " must be a non-empty string");
    return {member->value.GetString(), member->value.GetStringLength()};
}

std::string OptionalString(const Value& value, const char* name)
{
    const auto member = value.FindMember(name);
    if (member == value.MemberEnd())
        return {};
    if (!member->value.IsString())
        throw std::invalid_argument(std::string(name) + " must be a string");
    return {member->value.GetString(), member->value.GetStringLength()};
}

bool OptionalBoolean(const Value& value, const char* name, bool fallback)
{
    const auto member = value.FindMember(name);
    if (member == value.MemberEnd())
        return fallback;
    if (!member->value.IsBool())
        throw std::invalid_argument(std::string(name) + " must be a boolean");
    return member->value.GetBool();
}

std::pair<std::size_t, std::size_t> Pagination(const Value& value)
{
    std::uint64_t offset = 0;
    std::uint64_t limit = 50;
    if (const auto member = value.FindMember("offset"); member != value.MemberEnd())
    {
        if (!member->value.IsUint64())
            throw std::invalid_argument("offset must be a non-negative integer");
        offset = member->value.GetUint64();
    }
    if (const auto member = value.FindMember("limit"); member != value.MemberEnd())
    {
        if (!member->value.IsUint64() || member->value.GetUint64() == 0 ||
            member->value.GetUint64() > 1000)
            throw std::invalid_argument("limit must be an integer from 1 through 1000");
        limit = member->value.GetUint64();
    }
    if (offset > std::numeric_limits<std::size_t>::max())
        offset = std::numeric_limits<std::size_t>::max();
    return {static_cast<std::size_t>(offset), static_cast<std::size_t>(limit)};
}

bool ContainsInsensitive(std::string_view value, std::string_view query)
{
    return std::search(value.begin(), value.end(), query.begin(), query.end(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        }) != value.end();
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

template <typename WriterType>
void WriteAddress(WriterType& writer, std::uint64_t address)
{
    char buffer[19]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
        static_cast<unsigned long long>(address));
    writer.String(buffer);
}

std::string HexAddress(std::uint64_t address)
{
    char buffer[19]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
        static_cast<unsigned long long>(address));
    return buffer;
}

template <typename WriterType, typename Collection, typename Callback>
void WritePage(WriterType& writer, const Collection& values,
    std::size_t offset, std::size_t limit, Callback callback)
{
    const auto begin = std::min(offset, values.size());
    const auto end = std::min(values.size(), begin + std::min(limit, values.size() - begin));
    writer.StartObject();
    writer.Key("items");
    writer.StartArray();
    for (std::size_t index = begin; index < end; ++index)
        callback(writer, values[index]);
    writer.EndArray();
    writer.Key("total"); writer.Uint64(values.size());
    writer.Key("offset"); writer.Uint64(begin);
    writer.Key("limit"); writer.Uint64(limit);
    writer.EndObject();
}

std::string BufferString(const StringBuffer& buffer)
{
    return {buffer.GetString(), buffer.GetSize()};
}

std::uint64_t ParseExpression(
    BinaryNinja::BinaryView& view, const Value& value, std::string_view field)
{
    if (!value.IsString())
        throw std::invalid_argument(std::string(field) + " must be a string");
    std::uint64_t result = 0;
    std::string error;
    BinaryNinja::Ref<BinaryNinja::BinaryView> reference(&view);
    if (!BinaryNinja::BinaryView::ParseExpression(reference,
            std::string(value.GetString(), value.GetStringLength()), result, 0, error))
        throw std::invalid_argument(error.empty()
            ? std::string(field) + " is not a valid expression" : error);
    return result;
}

class KernelCacheApi
{
  public:
    KernelCacheApi() : library_(PluginPath("kernelcache"))
    {
        getController_ = library_.Symbol<GetController>("BNGetKernelCacheController");
        freeController_ = library_.Symbol<FreeController>("BNFreeKernelCacheControllerReference");
        getImages_ = library_.Symbol<GetImages>("BNKernelCacheControllerGetImages");
        getLoadedImages_ = library_.Symbol<GetImages>("BNKernelCacheControllerGetLoadedImages");
        freeImages_ = library_.Symbol<FreeImages>("BNKernelCacheFreeImageList");
        getImage_ = library_.Symbol<GetImage>("BNKernelCacheControllerGetImageWithName");
        getImageContaining_ = library_.Symbol<GetImageContaining>(
            "BNKernelCacheControllerGetImageContaining");
        freeImage_ = library_.Symbol<FreeImage>("BNKernelCacheFreeImage");
        isLoaded_ = library_.Symbol<IsLoaded>("BNKernelCacheControllerIsImageLoaded");
        dependencies_ = library_.Symbol<Dependencies>("BNKernelCacheControllerGetImageDependencies");
        applyImage_ = library_.Symbol<ApplyImage>("BNKernelCacheControllerApplyImage");
        getSymbols_ = library_.Symbol<GetSymbols>("BNKernelCacheControllerGetSymbols");
        freeSymbols_ = library_.Symbol<FreeSymbols>("BNKernelCacheFreeSymbolList");
    }

    std::string Execute(std::string_view name, BinaryNinja::BinaryView& view, const Value& arguments)
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            throw std::invalid_argument("BinaryView is not a KernelCache view");
        struct Guard
        {
            BNKernelCacheController* controller;
            FreeController release;
            ~Guard() { release(controller); }
        } guard{controller, freeController_};

        if (name == "bn_kernel_cache_image_list")
            return ImageList(controller, arguments);
        if (name == "bn_kernel_cache_image_info")
            return ImageInfo(controller, arguments);
        if (name == "bn_kernel_cache_image_load")
            return ImageLoad(controller, view, arguments);
        if (name == "bn_kernel_cache_symbol_list")
            return SymbolList(controller, arguments);
        if (name == "bn_kernel_cache_entry_point_list")
            return EntryPointList(controller, view, arguments);
        if (name == "bn_kernel_cache_export_list")
            return ExportList(controller, view, arguments);
        throw std::invalid_argument("KernelCache tool is not implemented");
    }

    std::string DescribeAddress(BinaryNinja::BinaryView& view, std::uint64_t address)
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            return {};
        struct Guard
        {
            BNKernelCacheController* controller;
            FreeController release;
            ~Guard() { release(controller); }
        } guard{controller, freeController_};
        BNKernelCacheImage image{};
        if (getImageContaining_(controller, address, &image))
        {
            const std::string name = image.name ? image.name : "";
            const auto loaded = isLoaded_(controller, &image);
            freeImage_(image);
            if (!loaded)
                return "address " + HexAddress(address) +
                    " is in unloaded KernelCache image '" + name +
                    "'; call bn_kernel_cache_image_load for that image, then "
                    "bn_analysis_update_and_wait";
            return "address " + HexAddress(address) +
                " is in loaded KernelCache image '" + name +
                "' but is not an analyzed function start";
        }
        if (view.IsValidOffset(address))
            return "address " + HexAddress(address) +
                " is in a loaded KernelCache mapped range but is not an analyzed function start";
        return "address " + HexAddress(address) +
            " is not contained in a KernelCache image or loaded mapped range";
    }

  private:
    using GetController = BNKernelCacheController* (*)(BNBinaryView*);
    using FreeController = void (*)(BNKernelCacheController*);
    using GetImages = BNKernelCacheImage* (*)(BNKernelCacheController*, std::size_t*);
    using FreeImages = void (*)(BNKernelCacheImage*, std::size_t);
    using GetImage = bool (*)(BNKernelCacheController*, const char*, BNKernelCacheImage*);
    using GetImageContaining = bool (*)(BNKernelCacheController*, std::uint64_t, BNKernelCacheImage*);
    using FreeImage = void (*)(BNKernelCacheImage);
    using IsLoaded = bool (*)(BNKernelCacheController*, BNKernelCacheImage*);
    using Dependencies = char** (*)(BNKernelCacheController*, BNKernelCacheImage*, std::size_t*);
    using ApplyImage = bool (*)(BNKernelCacheController*, BNBinaryView*, BNKernelCacheImage*);
    using GetSymbols = BNKernelCacheSymbol* (*)(BNKernelCacheController*, std::size_t*);
    using FreeSymbols = void (*)(BNKernelCacheSymbol*, std::size_t);

    std::string ImageList(BNKernelCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "loaded", "query", "offset", "limit"});
        const auto loaded = OptionalBoolean(arguments, "loaded", false);
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = loaded ? getLoadedImages_(controller, &count) : getImages_(controller, &count);
        std::vector<BNKernelCacheImage> images;
        for (std::size_t index = 0; index < count; ++index)
        {
            if (query.empty() || ContainsInsensitive(raw[index].name ? raw[index].name : "", query))
                images.push_back(raw[index]);
        }
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, images, offset, limit, [](auto& output, const auto& image) {
            output.StartObject();
            output.Key("name"); output.String(image.name ? image.name : "");
            output.Key("headerVirtualAddress"); WriteAddress(output, image.headerVirtualAddress);
            output.Key("headerFileAddress"); WriteAddress(output, image.headerFileAddress);
            output.EndObject();
        });
        freeImages_(raw, count);
        return BufferString(buffer);
    }

    std::string ImageInfo(BNKernelCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "image"});
        const auto name = RequiredString(arguments, "image");
        BNKernelCacheImage image{};
        if (!getImage_(controller, name.c_str(), &image))
            throw std::invalid_argument("KernelCache image not found");
        std::size_t dependencyCount = 0;
        auto** dependencies = dependencies_(controller, &image, &dependencyCount);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("name"); writer.String(image.name ? image.name : "");
        writer.Key("headerVirtualAddress"); WriteAddress(writer, image.headerVirtualAddress);
        writer.Key("headerFileAddress"); WriteAddress(writer, image.headerFileAddress);
        writer.Key("loaded"); writer.Bool(isLoaded_(controller, &image));
        writer.Key("dependencies"); writer.StartArray();
        for (std::size_t index = 0; index < dependencyCount; ++index)
            writer.String(dependencies[index]);
        writer.EndArray();
        writer.EndObject();
        BNFreeStringList(dependencies, dependencyCount);
        freeImage_(image);
        return BufferString(buffer);
    }

    std::string ImageLoad(BNKernelCacheController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "image"});
        const auto name = RequiredString(arguments, "image");
        BNKernelCacheImage image{};
        if (!getImage_(controller, name.c_str(), &image))
            throw std::invalid_argument("KernelCache image not found");
        const auto alreadyLoaded = isLoaded_(controller, &image);
        const auto applied = alreadyLoaded || applyImage_(controller, view.GetObject(), &image);
        if (applied && !alreadyLoaded)
            view.AddAnalysisOption("linearsweep");
        freeImage_(image);
        if (!applied)
            throw std::runtime_error("KernelCache image could not be loaded");
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("image"); writer.String(name.data(),
            static_cast<rapidjson::SizeType>(name.size()));
        writer.Key("loaded"); writer.Bool(true);
        writer.Key("alreadyLoaded"); writer.Bool(alreadyLoaded);
        if (!alreadyLoaded)
        {
            writer.Key("nextAction");
            writer.String("call bn_analysis_update_and_wait; if it returns a running job, poll bn_job_info no more than every 10 seconds and call bn_job_result when terminal");
        }
        writer.EndObject();
        return BufferString(buffer);
    }

    std::string SymbolList(BNKernelCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "query", "offset", "limit"});
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = getSymbols_(controller, &count);
        std::vector<BNKernelCacheSymbol> symbols;
        for (std::size_t index = 0; index < count; ++index)
        {
            if (query.empty() || ContainsInsensitive(raw[index].name ? raw[index].name : "", query))
                symbols.push_back(raw[index]);
        }
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, symbols, offset, limit, [](auto& output, const auto& symbol) {
            output.StartObject();
            output.Key("address"); WriteAddress(output, symbol.address);
            output.Key("name"); output.String(symbol.name ? symbol.name : "");
            output.Key("type"); output.String(symbol.symbolType == FunctionSymbol ? "FunctionSymbol" :
                symbol.symbolType == DataSymbol ? "DataSymbol" : "UnknownSymbol");
            output.EndObject();
        });
        freeSymbols_(raw, count);
        return BufferString(buffer);
    }

    struct SymbolRow
    {
        BNSymbolType type;
        std::uint64_t address;
        std::string name;
    };

    std::vector<SymbolRow> LoadedSymbols(
        BNKernelCacheController* controller, BinaryNinja::BinaryView& view)
    {
        std::size_t count = 0;
        auto* raw = getSymbols_(controller, &count);
        std::vector<SymbolRow> symbols;
        for (std::size_t index = 0; index < count; ++index)
        {
            if (view.IsValidOffset(raw[index].address))
                symbols.push_back({raw[index].symbolType, raw[index].address,
                    raw[index].name ? raw[index].name : ""});
        }
        freeSymbols_(raw, count);
        std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
            if (left.address != right.address) return left.address < right.address;
            if (left.type != right.type) return left.type < right.type;
            return left.name < right.name;
        });
        symbols.erase(std::unique(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
            return left.address == right.address && left.type == right.type && left.name == right.name;
        }), symbols.end());
        return symbols;
    }

    std::string EntryPointList(BNKernelCacheController* controller,
        BinaryNinja::BinaryView& view, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        struct EntryPointRow
        {
            std::uint64_t address;
            std::string name;
            std::string source;
            bool analyzed;
        };
        std::vector<EntryPointRow> entries;
        for (const auto& section : view.GetSections())
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
                if (view.Read(&target, cursor, sizeof(target)) != sizeof(target) ||
                    target == 0 || !view.IsValidOffset(target))
                    continue;
                const auto symbol = view.GetSymbolByAddress(target);
                const auto functions = view.GetAnalysisFunctionsForAddress(target);
                entries.push_back({target,
                    symbol ? symbol->GetShortName() : HexAddress(target),
                    initializer ? "kernelCacheModInit" : "kernelCacheModTerm",
                    !functions.empty()});
            }
        }
        auto symbols = LoadedSymbols(controller, view);
        std::erase_if(symbols, [](const auto& symbol) {
            if (symbol.type != FunctionSymbol)
                return true;
            const auto name = Lower(symbol.name);
            return name.find("module_start") == std::string::npos &&
                name != "_kmod_start" && name != "kmod_start" &&
                name != "_start" && name != "start";
        });
        for (const auto& symbol : symbols)
            entries.push_back({symbol.address, symbol.name,
                "kernelCacheModuleStart", true});
        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            if (left.address != right.address) return left.address < right.address;
            return left.source < right.source;
        });
        entries.erase(std::unique(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.address == right.address && left.source == right.source;
        }), entries.end());
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        const auto begin = std::min(offset, entries.size());
        const auto end = std::min(entries.size(), begin + std::min(limit, entries.size() - begin));
        writer.StartObject(); writer.Key("entryPoints"); writer.StartArray();
        for (std::size_t index = begin; index < end; ++index)
        {
            writer.StartObject(); writer.Key("address"); WriteAddress(writer, entries[index].address);
            writer.Key("name"); writer.String(entries[index].name.data(),
                static_cast<rapidjson::SizeType>(entries[index].name.size()));
            writer.Key("source"); writer.String(entries[index].source.data(),
                static_cast<rapidjson::SizeType>(entries[index].source.size()));
            writer.Key("analyzed"); writer.Bool(entries[index].analyzed);
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("count"); writer.Uint64(end - begin);
        writer.Key("total"); writer.Uint64(entries.size()); writer.Key("nextOffset");
        if (end < entries.size()) writer.Uint64(end); else writer.Null();
        writer.Key("truncated"); writer.Bool(end < entries.size()); writer.EndObject();
        return BufferString(buffer);
    }

    std::string ExportList(BNKernelCacheController* controller,
        BinaryNinja::BinaryView& view, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit", "address",
            "start", "end", "length", "query"});
        auto symbols = LoadedSymbols(controller, view);
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        if (const auto member = arguments.FindMember("address"); member != arguments.MemberEnd())
            address = ParseExpression(view, member->value, "address");
        if (const auto member = arguments.FindMember("start"); member != arguments.MemberEnd())
            start = ParseExpression(view, member->value, "start");
        if (const auto member = arguments.FindMember("end"); member != arguments.MemberEnd())
            end = ParseExpression(view, member->value, "end");
        if (const auto member = arguments.FindMember("length"); member != arguments.MemberEnd())
        {
            const auto length = member->value.IsUint64()
                ? member->value.GetUint64() : ParseExpression(view, member->value, "length");
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("export range length is invalid");
            end = *start + length;
        }
        const auto query = OptionalString(arguments, "query");
        std::erase_if(symbols, [&](const auto& symbol) {
            if (symbol.type != FunctionSymbol && symbol.type != DataSymbol) return true;
            if (address && symbol.address != *address) return true;
            if (start && symbol.address < *start) return true;
            if (end && symbol.address >= *end) return true;
            return !query.empty() && !ContainsInsensitive(symbol.name, query);
        });
        const auto [offset, limit] = Pagination(arguments);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        const auto begin = std::min(offset, symbols.size());
        const auto pageEnd = std::min(
            symbols.size(), begin + std::min(limit, symbols.size() - begin));
        writer.StartObject(); writer.Key("symbols"); writer.StartArray();
        for (std::size_t index = begin; index < pageEnd; ++index)
        {
            const auto& symbol = symbols[index];
            writer.StartObject(); writer.Key("address"); WriteAddress(writer, symbol.address);
            writer.Key("name"); writer.String(symbol.name.data(),
                static_cast<rapidjson::SizeType>(symbol.name.size()));
            writer.Key("type"); writer.String(symbol.type == FunctionSymbol
                ? "FunctionSymbol" : "DataSymbol");
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("count"); writer.Uint64(pageEnd - begin);
        writer.Key("total"); writer.Uint64(symbols.size()); writer.Key("nextOffset");
        if (pageEnd < symbols.size()) writer.Uint64(pageEnd); else writer.Null();
        writer.Key("truncated"); writer.Bool(pageEnd < symbols.size()); writer.EndObject();
        return BufferString(buffer);
    }

    DynamicLibrary library_;
    GetController getController_{};
    FreeController freeController_{};
    GetImages getImages_{};
    GetImages getLoadedImages_{};
    FreeImages freeImages_{};
    GetImage getImage_{};
    GetImageContaining getImageContaining_{};
    FreeImage freeImage_{};
    IsLoaded isLoaded_{};
    Dependencies dependencies_{};
    ApplyImage applyImage_{};
    GetSymbols getSymbols_{};
    FreeSymbols freeSymbols_{};
};

class SharedCacheApi
{
  public:
    SharedCacheApi() : library_(PluginPath("sharedcache"))
    {
        getController_ = library_.Symbol<GetController>("BNGetSharedCacheController");
        freeController_ = library_.Symbol<FreeController>("BNFreeSharedCacheControllerReference");
        getImages_ = library_.Symbol<GetImages>("BNSharedCacheControllerGetImages");
        getLoadedImages_ = library_.Symbol<GetImages>("BNSharedCacheControllerGetLoadedImages");
        freeImages_ = library_.Symbol<FreeImages>("BNSharedCacheFreeImageList");
        getImage_ = library_.Symbol<GetImage>("BNSharedCacheControllerGetImageWithName");
        getImageContaining_ = library_.Symbol<GetImageContaining>(
            "BNSharedCacheControllerGetImageContaining");
        freeImage_ = library_.Symbol<FreeImage>("BNSharedCacheFreeImage");
        isImageLoaded_ = library_.Symbol<IsImageLoaded>("BNSharedCacheControllerIsImageLoaded");
        dependencies_ = library_.Symbol<Dependencies>("BNSharedCacheControllerGetImageDependencies");
        applyImage_ = library_.Symbol<ApplyImage>("BNSharedCacheControllerApplyImage");
        getRegions_ = library_.Symbol<GetRegions>("BNSharedCacheControllerGetRegions");
        getRegionContaining_ = library_.Symbol<GetRegionContaining>(
            "BNSharedCacheControllerGetRegionContaining");
        freeRegion_ = library_.Symbol<FreeRegion>("BNSharedCacheFreeRegion");
        freeRegions_ = library_.Symbol<FreeRegions>("BNSharedCacheFreeRegionList");
        isRegionLoaded_ = library_.Symbol<IsRegionLoaded>("BNSharedCacheControllerIsRegionLoaded");
        applyRegion_ = library_.Symbol<ApplyRegion>("BNSharedCacheControllerApplyRegion");
        getEntries_ = library_.Symbol<GetEntries>("BNSharedCacheControllerGetEntries");
        freeEntries_ = library_.Symbol<FreeEntries>("BNSharedCacheFreeEntryList");
        getSymbols_ = library_.Symbol<GetSymbols>("BNSharedCacheControllerGetSymbols");
        freeSymbols_ = library_.Symbol<FreeSymbols>("BNSharedCacheFreeSymbolList");
    }

    std::string Execute(std::string_view name, BinaryNinja::BinaryView& view, const Value& arguments)
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            throw std::invalid_argument("BinaryView is not a SharedCache view");
        struct Guard
        {
            BNSharedCacheController* controller;
            FreeController release;
            ~Guard() { release(controller); }
        } guard{controller, freeController_};
        if (name == "bn_shared_cache_image_list") return ImageList(controller, arguments);
        if (name == "bn_shared_cache_image_info") return ImageInfo(controller, arguments);
        if (name == "bn_shared_cache_image_load") return ImageLoad(controller, view, arguments);
        if (name == "bn_shared_cache_region_list") return RegionList(controller, arguments);
        if (name == "bn_shared_cache_region_load") return RegionLoad(controller, view, arguments);
        if (name == "bn_shared_cache_entry_list") return EntryList(controller, arguments);
        if (name == "bn_shared_cache_symbol_list") return SymbolList(controller, arguments);
        throw std::invalid_argument("SharedCache tool is not implemented");
    }

    std::string DescribeAddress(BinaryNinja::BinaryView& view, std::uint64_t address)
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            return {};
        struct Guard
        {
            BNSharedCacheController* controller;
            FreeController release;
            ~Guard() { release(controller); }
        } guard{controller, freeController_};
        BNSharedCacheImage image{};
        if (getImageContaining_(controller, address, &image))
        {
            const std::string name = image.name ? image.name : "";
            const auto loaded = isImageLoaded_(controller, &image);
            freeImage_(image);
            if (!loaded)
                return "address " + HexAddress(address) +
                    " is in unloaded SharedCache image '" + name +
                    "'; call bn_shared_cache_image_load for that image, then "
                    "bn_analysis_update_and_wait";
            return "address " + HexAddress(address) +
                " is in loaded SharedCache image '" + name +
                "' but is not an analyzed function start";
        }
        BNSharedCacheRegion region{};
        if (getRegionContaining_(controller, address, &region))
        {
            const std::string name = region.name ? region.name : "";
            const auto loaded = isRegionLoaded_(controller, &region);
            freeRegion_(region);
            if (!loaded)
                return "address " + HexAddress(address) +
                    " is in unloaded SharedCache region '" + name +
                    "'; call bn_shared_cache_region_load for that region, then "
                    "bn_analysis_update_and_wait";
            return "address " + HexAddress(address) +
                " is in loaded SharedCache region '" + name +
                "' but is not an analyzed function start";
        }
        if (view.IsValidOffset(address))
            return "address " + HexAddress(address) +
                " is in a loaded SharedCache mapped range but is not an analyzed function start";
        return "address " + HexAddress(address) +
            " is not contained in a SharedCache image, region, or loaded mapped range";
    }

  private:
    using GetController = BNSharedCacheController* (*)(BNBinaryView*);
    using FreeController = void (*)(BNSharedCacheController*);
    using GetImages = BNSharedCacheImage* (*)(BNSharedCacheController*, std::size_t*);
    using FreeImages = void (*)(BNSharedCacheImage*, std::size_t);
    using GetImage = bool (*)(BNSharedCacheController*, const char*, BNSharedCacheImage*);
    using GetImageContaining = bool (*)(BNSharedCacheController*, std::uint64_t, BNSharedCacheImage*);
    using FreeImage = void (*)(BNSharedCacheImage);
    using IsImageLoaded = bool (*)(BNSharedCacheController*, BNSharedCacheImage*);
    using Dependencies = char** (*)(BNSharedCacheController*, BNSharedCacheImage*, std::size_t*);
    using ApplyImage = bool (*)(BNSharedCacheController*, BNBinaryView*, BNSharedCacheImage*);
    using GetRegions = BNSharedCacheRegion* (*)(BNSharedCacheController*, std::size_t*);
    using GetRegionContaining = bool (*)(BNSharedCacheController*, std::uint64_t, BNSharedCacheRegion*);
    using FreeRegion = void (*)(BNSharedCacheRegion);
    using FreeRegions = void (*)(BNSharedCacheRegion*, std::size_t);
    using IsRegionLoaded = bool (*)(BNSharedCacheController*, BNSharedCacheRegion*);
    using ApplyRegion = bool (*)(BNSharedCacheController*, BNBinaryView*, BNSharedCacheRegion*);
    using GetEntries = BNSharedCacheEntry* (*)(BNSharedCacheController*, std::size_t*);
    using FreeEntries = void (*)(BNSharedCacheEntry*, std::size_t);
    using GetSymbols = BNSharedCacheSymbol* (*)(BNSharedCacheController*, std::size_t*);
    using FreeSymbols = void (*)(BNSharedCacheSymbol*, std::size_t);

    std::string ImageList(BNSharedCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "loaded", "query", "offset", "limit"});
        const auto loaded = OptionalBoolean(arguments, "loaded", false);
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = loaded ? getLoadedImages_(controller, &count) : getImages_(controller, &count);
        std::vector<BNSharedCacheImage> images;
        for (std::size_t index = 0; index < count; ++index)
            if (query.empty() || ContainsInsensitive(raw[index].name ? raw[index].name : "", query))
                images.push_back(raw[index]);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, images, offset, limit, [](auto& output, const auto& image) {
            output.StartObject();
            output.Key("name"); output.String(image.name ? image.name : "");
            output.Key("headerAddress"); WriteAddress(output, image.headerAddress);
            output.Key("regionCount"); output.Uint64(image.regionStartCount);
            output.EndObject();
        });
        freeImages_(raw, count);
        return BufferString(buffer);
    }

    std::string ImageInfo(BNSharedCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "image"});
        const auto name = RequiredString(arguments, "image");
        BNSharedCacheImage image{};
        if (!getImage_(controller, name.c_str(), &image))
            throw std::invalid_argument("SharedCache image not found");
        std::size_t dependencyCount = 0;
        auto** dependencies = dependencies_(controller, &image, &dependencyCount);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("name"); writer.String(image.name ? image.name : "");
        writer.Key("headerAddress"); WriteAddress(writer, image.headerAddress);
        writer.Key("loaded"); writer.Bool(isImageLoaded_(controller, &image));
        writer.Key("regions"); writer.StartArray();
        for (std::size_t index = 0; index < image.regionStartCount; ++index)
            WriteAddress(writer, image.regionStarts[index]);
        writer.EndArray();
        writer.Key("dependencies"); writer.StartArray();
        for (std::size_t index = 0; index < dependencyCount; ++index)
            writer.String(dependencies[index]);
        writer.EndArray();
        writer.EndObject();
        BNFreeStringList(dependencies, dependencyCount);
        freeImage_(image);
        return BufferString(buffer);
    }

    std::string ImageLoad(BNSharedCacheController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "image"});
        const auto name = RequiredString(arguments, "image");
        BNSharedCacheImage image{};
        if (!getImage_(controller, name.c_str(), &image))
            throw std::invalid_argument("SharedCache image not found");
        const auto alreadyLoaded = isImageLoaded_(controller, &image);
        const auto applied = alreadyLoaded || applyImage_(controller, view.GetObject(), &image);
        if (applied && !alreadyLoaded)
        {
            view.AddAnalysisOption("linearsweep");
            view.AddAnalysisOption("pointersweep");
        }
        freeImage_(image);
        if (!applied)
            throw std::runtime_error("SharedCache image could not be loaded");
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("image"); writer.String(name.data(),
            static_cast<rapidjson::SizeType>(name.size()));
        writer.Key("loaded"); writer.Bool(true);
        writer.Key("alreadyLoaded"); writer.Bool(alreadyLoaded);
        if (!alreadyLoaded)
        {
            writer.Key("nextAction");
            writer.String("call bn_analysis_update_and_wait; if it returns a running job, poll bn_job_info no more than every 10 seconds and call bn_job_result when terminal");
        }
        writer.EndObject();
        return BufferString(buffer);
    }

    std::string RegionList(BNSharedCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "loaded", "query", "offset", "limit"});
        const auto loadedOnly = OptionalBoolean(arguments, "loaded", false);
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = getRegions_(controller, &count);
        std::vector<BNSharedCacheRegion> regions;
        for (std::size_t index = 0; index < count; ++index)
        {
            if (loadedOnly && !isRegionLoaded_(controller, &raw[index])) continue;
            if (!query.empty() && !ContainsInsensitive(raw[index].name ? raw[index].name : "", query)) continue;
            regions.push_back(raw[index]);
        }
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, regions, offset, limit, [&](auto& output, const auto& region) {
            output.StartObject();
            output.Key("name"); output.String(region.name ? region.name : "");
            output.Key("start"); WriteAddress(output, region.vmAddress);
            output.Key("size"); output.Uint64(region.size);
            output.Key("imageStart"); WriteAddress(output, region.imageStart);
            output.Key("loaded"); output.Bool(isRegionLoaded_(controller,
                const_cast<BNSharedCacheRegion*>(&region)));
            output.EndObject();
        });
        freeRegions_(raw, count);
        return BufferString(buffer);
    }

    std::string RegionLoad(BNSharedCacheController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "region"});
        const auto name = RequiredString(arguments, "region");
        std::size_t count = 0;
        auto* regions = getRegions_(controller, &count);
        auto* found = static_cast<BNSharedCacheRegion*>(nullptr);
        for (std::size_t index = 0; index < count; ++index)
            if (regions[index].name && name == regions[index].name) found = &regions[index];
        if (!found)
        {
            freeRegions_(regions, count);
            throw std::invalid_argument("SharedCache region not found");
        }
        const auto alreadyLoaded = isRegionLoaded_(controller, found);
        const auto applied = alreadyLoaded || applyRegion_(controller, view.GetObject(), found);
        if (applied && !alreadyLoaded)
        {
            view.AddAnalysisOption("linearsweep");
            view.AddAnalysisOption("pointersweep");
        }
        freeRegions_(regions, count);
        if (!applied)
            throw std::runtime_error("SharedCache region could not be loaded");
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("region"); writer.String(name.data(),
            static_cast<rapidjson::SizeType>(name.size()));
        writer.Key("loaded"); writer.Bool(true);
        writer.Key("alreadyLoaded"); writer.Bool(alreadyLoaded);
        if (!alreadyLoaded)
        {
            writer.Key("nextAction");
            writer.String("call bn_analysis_update_and_wait; if it returns a running job, poll bn_job_info no more than every 10 seconds and call bn_job_result when terminal");
        }
        writer.EndObject();
        return BufferString(buffer);
    }

    std::string EntryList(BNSharedCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "query", "offset", "limit"});
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = getEntries_(controller, &count);
        std::vector<BNSharedCacheEntry> entries;
        for (std::size_t index = 0; index < count; ++index)
            if (query.empty() || ContainsInsensitive(raw[index].path ? raw[index].path : "", query) ||
                ContainsInsensitive(raw[index].name ? raw[index].name : "", query))
                entries.push_back(raw[index]);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, entries, offset, limit, [](auto& output, const auto& entry) {
            output.StartObject();
            output.Key("path"); output.String(entry.path ? entry.path : "");
            output.Key("name"); output.String(entry.name ? entry.name : "");
            output.Key("type"); output.Int(entry.entryType);
            output.Key("mappingCount"); output.Uint64(entry.mappingCount);
            output.EndObject();
        });
        freeEntries_(raw, count);
        return BufferString(buffer);
    }

    std::string SymbolList(BNSharedCacheController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "query", "offset", "limit"});
        const auto query = OptionalString(arguments, "query");
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* raw = getSymbols_(controller, &count);
        std::vector<BNSharedCacheSymbol> symbols;
        for (std::size_t index = 0; index < count; ++index)
            if (query.empty() || ContainsInsensitive(raw[index].name ? raw[index].name : "", query))
                symbols.push_back(raw[index]);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        WritePage(writer, symbols, offset, limit, [](auto& output, const auto& symbol) {
            output.StartObject();
            output.Key("address"); WriteAddress(output, symbol.address);
            output.Key("name"); output.String(symbol.name ? symbol.name : "");
            output.Key("type"); output.Int(symbol.symbolType);
            output.Key("binding"); output.Int(symbol.symbolBinding);
            output.EndObject();
        });
        freeSymbols_(raw, count);
        return BufferString(buffer);
    }

    DynamicLibrary library_;
    GetController getController_{};
    FreeController freeController_{};
    GetImages getImages_{};
    GetImages getLoadedImages_{};
    FreeImages freeImages_{};
    GetImage getImage_{};
    GetImageContaining getImageContaining_{};
    FreeImage freeImage_{};
    IsImageLoaded isImageLoaded_{};
    Dependencies dependencies_{};
    ApplyImage applyImage_{};
    GetRegions getRegions_{};
    GetRegionContaining getRegionContaining_{};
    FreeRegion freeRegion_{};
    FreeRegions freeRegions_{};
    IsRegionLoaded isRegionLoaded_{};
    ApplyRegion applyRegion_{};
    GetEntries getEntries_{};
    FreeEntries freeEntries_{};
    GetSymbols getSymbols_{};
    FreeSymbols freeSymbols_{};
};

class DebuggerApi
{
  public:
    DebuggerApi() : library_(PluginPath("debuggercore"))
    {
#define LOAD(member, symbol) member = library_.Symbol<decltype(member)>(symbol)
        LOAD(getController_, "BNGetDebuggerController");
        LOAD(freeController_, "BNDebuggerFreeController");
        LOAD(freeString_, "BNDebuggerFreeString");
        LOAD(freeStringList_, "BNDebuggerFreeStringList");
        LOAD(getAdapters_, "BNGetAvailableDebugAdapterTypes");
        LOAD(getAdapter_, "BNDebuggerGetAdapterType");
        LOAD(setAdapter_, "BNDebuggerSetAdapterType");
        LOAD(isConnected_, "BNDebuggerIsConnected");
        LOAD(isRunning_, "BNDebuggerIsRunning");
        LOAD(getConnectionStatus_, "BNDebuggerGetConnectionStatus");
        LOAD(getTargetStatus_, "BNDebuggerGetTargetStatus");
        LOAD(getStopReason_, "BNDebuggerGetStopReason");
        LOAD(getStopReasonString_, "BNDebuggerGetStopReasonString");
        LOAD(getIp_, "BNDebuggerGetIP");
        LOAD(getStackPointer_, "BNDebuggerGetStackPointer");
        LOAD(getActivePid_, "BNDebuggerGetActivePID");
        LOAD(getProcesses_, "BNDebuggerGetProcessList");
        LOAD(freeProcesses_, "BNDebuggerFreeProcessList");
        LOAD(getActiveThread_, "BNDebuggerGetActiveThread");
        LOAD(setActiveThread_, "BNDebuggerSetActiveThread");
        LOAD(getRemoteHost_, "BNDebuggerGetRemoteHost");
        LOAD(getRemotePort_, "BNDebuggerGetRemotePort");
        LOAD(getPidAttach_, "BNDebuggerGetPIDAttach");
        LOAD(getInputFile_, "BNDebuggerGetInputFile");
        LOAD(getExecutablePath_, "BNDebuggerGetExecutablePath");
        LOAD(getWorkingDirectory_, "BNDebuggerGetWorkingDirectory");
        LOAD(getCommandLine_, "BNDebuggerGetCommandLineArguments");
        LOAD(setRemoteHost_, "BNDebuggerSetRemoteHost");
        LOAD(setRemotePort_, "BNDebuggerSetRemotePort");
        LOAD(setPidAttach_, "BNDebuggerSetPIDAttach");
        LOAD(setInputFile_, "BNDebuggerSetInputFile");
        LOAD(setExecutablePath_, "BNDebuggerSetExecutablePath");
        LOAD(setWorkingDirectory_, "BNDebuggerSetWorkingDirectory");
        LOAD(setCommandLine_, "BNDebuggerSetCommandLineArguments");
        LOAD(launch_, "BNDebuggerLaunch");
        LOAD(connect_, "BNDebuggerConnect");
        LOAD(attach_, "BNDebuggerAttach");
        LOAD(go_, "BNDebuggerGo");
        LOAD(pause_, "BNDebuggerPause");
        LOAD(stepInto_, "BNDebuggerStepInto");
        LOAD(stepOver_, "BNDebuggerStepOver");
        LOAD(stepReturn_, "BNDebuggerStepReturn");
        LOAD(restart_, "BNDebuggerRestart");
        LOAD(quit_, "BNDebuggerQuit");
        LOAD(quitWait_, "BNDebuggerQuitAndWaitWithTimeout");
        LOAD(detach_, "BNDebuggerDetach");
        LOAD(destroy_, "BNDebuggerDestroyController");
        LOAD(launchWait_, "BNDebuggerLaunchAndWaitWithTimeout");
        LOAD(connectWait_, "BNDebuggerConnectAndWaitWithTimeout");
        LOAD(attachWait_, "BNDebuggerAttachAndWaitWithTimeout");
        LOAD(goWait_, "BNDebuggerGoAndWaitWithTimeout");
        LOAD(pauseWait_, "BNDebuggerPauseAndWaitWithTimeout");
        LOAD(stepIntoWait_, "BNDebuggerStepIntoAndWaitWithTimeout");
        LOAD(stepOverWait_, "BNDebuggerStepOverAndWaitWithTimeout");
        LOAD(stepReturnWait_, "BNDebuggerStepReturnAndWaitWithTimeout");
        LOAD(restartWait_, "BNDebuggerRestartAndWaitWithTimeout");
        LOAD(getThreads_, "BNDebuggerGetThreads");
        LOAD(freeThreads_, "BNDebuggerFreeThreads");
        LOAD(getFrames_, "BNDebuggerGetFramesOfThread");
        LOAD(freeFrames_, "BNDebuggerFreeFrames");
        LOAD(getRegisters_, "BNDebuggerGetRegisters");
        LOAD(freeRegisters_, "BNDebuggerFreeRegisters");
        LOAD(setRegister_, "BNDebuggerSetRegisterValue");
        LOAD(getModules_, "BNDebuggerGetModules");
        LOAD(freeModules_, "BNDebuggerFreeModules");
        LOAD(getMemoryMap_, "BNDebuggerGetMemoryMap");
        LOAD(freeMemoryMap_, "BNDebuggerFreeMemoryRegions");
        LOAD(readMemory_, "BNDebuggerReadMemory");
        LOAD(writeMemory_, "BNDebuggerWriteMemory");
        LOAD(getBreakpoints_, "BNDebuggerGetBreakpoints");
        LOAD(freeBreakpoints_, "BNDebuggerFreeBreakpoints");
        LOAD(addBreakpoint_, "BNDebuggerAddAbsoluteBreakpoint");
        LOAD(deleteBreakpoint_, "BNDebuggerDeleteAbsoluteBreakpoint");
#undef LOAD
    }

    std::string Execute(std::string_view name, BinaryNinja::BinaryView& view, const Value& arguments)
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            throw std::runtime_error("Debugger controller is unavailable");
        struct Guard
        {
            BNDebuggerController* controller;
            decltype(freeController_) release;
            ~Guard() { release(controller); }
        } guard{controller, freeController_};

        if (name == "bn_debugger_adapter_list") return AdapterList(view, arguments);
        if (name == "bn_debugger_status") return Status(controller, arguments);
        if (name == "bn_debugger_configure") return Configure(controller, arguments);
        if (name == "bn_debugger_process_list") return ProcessList(controller, arguments);
        if (name == "bn_debugger_thread_list") return ThreadList(controller, arguments);
        if (name == "bn_debugger_thread_set") return ThreadSet(controller, arguments);
        if (name == "bn_debugger_frame_list") return FrameList(controller, arguments);
        if (name == "bn_debugger_register_list") return RegisterList(controller, arguments);
        if (name == "bn_debugger_register_set") return RegisterSet(controller, view, arguments);
        if (name == "bn_debugger_module_list") return ModuleList(controller, arguments);
        if (name == "bn_debugger_memory_region_list") return MemoryRegionList(controller, arguments);
        if (name == "bn_debugger_memory_read") return MemoryRead(controller, view, arguments);
        if (name == "bn_debugger_memory_write") return MemoryWrite(controller, view, arguments);
        if (name == "bn_debugger_breakpoint_list") return BreakpointList(controller, arguments);
        if (name == "bn_debugger_breakpoint_add") return BreakpointChange(controller, view, arguments, true);
        if (name == "bn_debugger_breakpoint_delete") return BreakpointChange(controller, view, arguments, false);
        if (name.ends_with("_and_wait")) return WaitControl(controller, name, arguments);
        return ImmediateControl(controller, name, arguments);
    }

    void Close(BinaryNinja::BinaryView& view) noexcept
    {
        auto* controller = getController_(view.GetObject());
        if (!controller)
            return;
        if (isConnected_(controller))
            quitWait_(controller, 5000);
        destroy_(controller);
        freeController_(controller);
    }

  private:
    std::string TakeString(char* value)
    {
        if (!value)
            return {};
        std::string result(value);
        freeString_(value);
        return result;
    }

    std::uint64_t Address(BinaryNinja::BinaryView& view, const Value& arguments,
        const char* field)
    {
        const auto expression = RequiredString(arguments, field);
        std::uint64_t value = 0;
        std::string error;
        BinaryNinja::Ref<BinaryNinja::BinaryView> reference(&view);
        if (!BinaryNinja::BinaryView::ParseExpression(
                reference, expression, value, 0, error))
            throw std::invalid_argument(error.empty()
                ? std::string(field) + " is not a valid address expression" : error);
        return value;
    }

    std::string AdapterList(BinaryNinja::BinaryView& view, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView"});
        std::size_t count = 0;
        auto** adapters = getAdapters_(view.GetObject(), &count);
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("adapters"); writer.StartArray();
        for (std::size_t index = 0; index < count; ++index)
            writer.String(adapters[index]);
        writer.EndArray(); writer.EndObject();
        freeStringList_(adapters, count);
        return BufferString(buffer);
    }

    std::string Status(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView"});
        const auto adapter = TakeString(getAdapter_(controller));
        const auto reason = getStopReason_(controller);
        const auto reasonName = TakeString(getStopReasonString_(reason));
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("adapter"); writer.String(adapter.data(), static_cast<rapidjson::SizeType>(adapter.size()));
        writer.Key("connected"); writer.Bool(isConnected_(controller));
        writer.Key("running"); writer.Bool(isRunning_(controller));
        writer.Key("connectionStatus"); writer.Int(getConnectionStatus_(controller));
        writer.Key("targetStatus"); writer.Int(getTargetStatus_(controller));
        writer.Key("stopReason"); writer.Int(reason);
        writer.Key("stopReasonName"); writer.String(reasonName.data(), static_cast<rapidjson::SizeType>(reasonName.size()));
        writer.Key("pid"); writer.Uint(getActivePid_(controller));
        writer.Key("instructionPointer"); WriteAddress(writer, getIp_(controller));
        writer.Key("stackPointer"); WriteAddress(writer, getStackPointer_(controller));
        writer.Key("configuration"); writer.StartObject();
        const auto executable = TakeString(getExecutablePath_(controller));
        const auto input = TakeString(getInputFile_(controller));
        const auto working = TakeString(getWorkingDirectory_(controller));
        const auto commandLine = TakeString(getCommandLine_(controller));
        const auto host = TakeString(getRemoteHost_(controller));
        writer.Key("executable"); writer.String(executable.data(), static_cast<rapidjson::SizeType>(executable.size()));
        writer.Key("inputFile"); writer.String(input.data(), static_cast<rapidjson::SizeType>(input.size()));
        writer.Key("workingDirectory"); writer.String(working.data(), static_cast<rapidjson::SizeType>(working.size()));
        writer.Key("commandLine"); writer.String(commandLine.data(), static_cast<rapidjson::SizeType>(commandLine.size()));
        writer.Key("remoteHost"); writer.String(host.data(), static_cast<rapidjson::SizeType>(host.size()));
        writer.Key("remotePort"); writer.Uint(getRemotePort_(controller));
        writer.Key("attachPid"); writer.Int(getPidAttach_(controller));
        writer.EndObject(); writer.EndObject();
        return BufferString(buffer);
    }

    std::string Configure(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "adapter", "executable", "inputFile",
            "workingDirectory", "commandLine", "remoteHost", "remotePort", "attachPid"});
        const auto setString = [&](const char* field, auto setter) {
            const auto member = arguments.FindMember(field);
            if (member == arguments.MemberEnd()) return;
            if (!member->value.IsString())
                throw std::invalid_argument(std::string(field) + " must be a string");
            setter(controller, member->value.GetString());
        };
        setString("adapter", setAdapter_);
        setString("executable", setExecutablePath_);
        setString("inputFile", setInputFile_);
        setString("workingDirectory", setWorkingDirectory_);
        setString("commandLine", setCommandLine_);
        setString("remoteHost", setRemoteHost_);
        if (const auto member = arguments.FindMember("remotePort"); member != arguments.MemberEnd())
        {
            if (!member->value.IsUint() || member->value.GetUint() > 65535)
                throw std::invalid_argument("remotePort must be an integer from 0 through 65535");
            setRemotePort_(controller, member->value.GetUint());
        }
        if (const auto member = arguments.FindMember("attachPid"); member != arguments.MemberEnd())
        {
            if (!member->value.IsInt())
                throw std::invalid_argument("attachPid must be a signed 32-bit integer");
            setPidAttach_(controller, member->value.GetInt());
        }
        Document statusArguments;
        statusArguments.SetObject();
        statusArguments.AddMember("binaryView", "configured", statusArguments.GetAllocator());
        return Status(controller, statusArguments);
    }

    std::string ImmediateControl(BNDebuggerController* controller, std::string_view name,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView"});
        bool accepted = true;
        if (name == "bn_debugger_launch") accepted = launch_(controller);
        else if (name == "bn_debugger_connect") accepted = connect_(controller);
        else if (name == "bn_debugger_attach") accepted = attach_(controller);
        else if (name == "bn_debugger_go") accepted = go_(controller);
        else if (name == "bn_debugger_pause") pause_(controller);
        else if (name == "bn_debugger_step_into") accepted = stepInto_(controller, NormalFunctionGraph);
        else if (name == "bn_debugger_step_over") accepted = stepOver_(controller, NormalFunctionGraph);
        else if (name == "bn_debugger_step_return") accepted = stepReturn_(controller);
        else if (name == "bn_debugger_restart") restart_(controller);
        else if (name == "bn_debugger_quit") quit_(controller);
        else if (name == "bn_debugger_detach") detach_(controller);
        else throw std::invalid_argument("Debugger control tool is not implemented");
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("accepted"); writer.Bool(accepted); writer.EndObject();
        return BufferString(buffer);
    }

    std::string WaitControl(BNDebuggerController* controller, std::string_view name,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "timeoutMilliseconds"});
        const auto timeout = arguments.FindMember("timeoutMilliseconds");
        if (timeout == arguments.MemberEnd() || !timeout->value.IsUint64() ||
            timeout->value.GetUint64() == 0 || timeout->value.GetUint64() > 30000)
            throw std::invalid_argument("timeoutMilliseconds must be an integer from 1 through 30000");
        const auto milliseconds = timeout->value.GetUint64();
        BNDebugStopReason reason = UnknownReason;
        if (name == "bn_debugger_launch_and_wait") reason = launchWait_(controller, milliseconds);
        else if (name == "bn_debugger_connect_and_wait") reason = connectWait_(controller, milliseconds);
        else if (name == "bn_debugger_attach_and_wait") reason = attachWait_(controller, milliseconds);
        else if (name == "bn_debugger_go_and_wait") reason = goWait_(controller, milliseconds);
        else if (name == "bn_debugger_pause_and_wait") reason = pauseWait_(controller, milliseconds);
        else if (name == "bn_debugger_step_into_and_wait") reason = stepIntoWait_(controller, NormalFunctionGraph, milliseconds);
        else if (name == "bn_debugger_step_over_and_wait") reason = stepOverWait_(controller, NormalFunctionGraph, milliseconds);
        else if (name == "bn_debugger_step_return_and_wait") reason = stepReturnWait_(controller, milliseconds);
        else if (name == "bn_debugger_restart_and_wait") reason = restartWait_(controller, milliseconds);
        else throw std::invalid_argument("Debugger wait tool is not implemented");
        const auto reasonName = TakeString(getStopReasonString_(reason));
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("stopReason"); writer.Int(reason);
        writer.Key("stopReasonName"); writer.String(reasonName.data(), static_cast<rapidjson::SizeType>(reasonName.size()));
        writer.EndObject();
        return BufferString(buffer);
    }

    std::string ThreadList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* threads = getThreads_(controller, &count);
        std::vector<BNDebugThread> values;
        if (threads && count != 0)
            values.assign(threads, threads + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& thread) {
            output.StartObject(); output.Key("id"); output.Uint(thread.m_tid);
            output.Key("instructionPointer"); WriteAddress(output, thread.m_rip);
            output.Key("frozen"); output.Bool(thread.m_isFrozen); output.EndObject();
        });
        freeThreads_(threads, count);
        return BufferString(buffer);
    }

    std::string ProcessList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* processes = getProcesses_(controller, &count);
        std::vector<BNDebugProcess> values;
        if (processes && count != 0)
            values.assign(processes, processes + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& process) {
            output.StartObject(); output.Key("pid"); output.Uint(process.m_pid);
            output.Key("name"); output.String(process.m_processName ? process.m_processName : "");
            output.Key("commandLine"); output.String(process.m_commandLine ? process.m_commandLine : "");
            output.EndObject();
        });
        freeProcesses_(processes, count);
        return BufferString(buffer);
    }

    std::string ThreadSet(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "thread"});
        const auto member = arguments.FindMember("thread");
        if (member == arguments.MemberEnd() || !member->value.IsUint())
            throw std::invalid_argument("thread must be an unsigned 32-bit integer");
        std::size_t count = 0;
        auto* threads = getThreads_(controller, &count);
        if (!threads || count == 0)
            throw std::invalid_argument("debugger thread not found");
        const auto found = std::find_if(threads, threads + count, [&](const auto& thread) {
            return thread.m_tid == member->value.GetUint();
        });
        if (found == threads + count)
        {
            freeThreads_(threads, count);
            throw std::invalid_argument("debugger thread not found");
        }
        const auto selected = *found;
        setActiveThread_(controller, selected);
        freeThreads_(threads, count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("thread"); writer.Uint(selected.m_tid);
        writer.Key("instructionPointer"); WriteAddress(writer, selected.m_rip);
        writer.Key("active"); writer.Bool(true); writer.EndObject();
        return BufferString(buffer);
    }

    std::string FrameList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "thread", "offset", "limit"});
        const auto thread = arguments.FindMember("thread");
        if (thread != arguments.MemberEnd() && !thread->value.IsUint())
            throw std::invalid_argument("thread must be an unsigned 32-bit integer");
        const auto threadId = thread == arguments.MemberEnd()
            ? getActiveThread_(controller).m_tid : thread->value.GetUint();
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* frames = getFrames_(controller, threadId, &count);
        std::vector<BNDebugFrame> values;
        if (frames && count != 0)
            values.assign(frames, frames + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& frame) {
            output.StartObject(); output.Key("index"); output.Uint64(frame.m_index);
            output.Key("pc"); WriteAddress(output, frame.m_pc);
            output.Key("sp"); WriteAddress(output, frame.m_sp);
            output.Key("fp"); WriteAddress(output, frame.m_fp);
            output.Key("function"); output.String(frame.m_functionName ? frame.m_functionName : "");
            output.Key("functionStart"); WriteAddress(output, frame.m_functionStart);
            output.Key("module"); output.String(frame.m_module ? frame.m_module : ""); output.EndObject();
        });
        freeFrames_(frames, count);
        return BufferString(buffer);
    }

    std::string RegisterList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0;
        auto* registers = getRegisters_(controller, &count);
        std::vector<BNDebugRegister> values;
        if (registers && count != 0)
            values.assign(registers, registers + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& reg) {
            output.StartObject(); output.Key("name"); output.String(reg.m_name ? reg.m_name : "");
            output.Key("width"); output.Uint64(reg.m_width);
            output.Key("index"); output.Uint64(reg.m_registerIndex);
            output.Key("value");
            std::string hex = "0x";
            bool started = false;
            for (std::size_t index = sizeof(reg.m_value); index-- > 0;)
            {
                const auto byte = reg.m_value[index];
                if (!started && byte == 0 && index != 0) continue;
                char part[3]{}; std::snprintf(part, sizeof(part), started ? "%02x" : "%x", byte);
                hex += part; started = true;
            }
            output.String(hex.data(), static_cast<rapidjson::SizeType>(hex.size()));
            output.Key("hint"); output.String(reg.m_hint ? reg.m_hint : ""); output.EndObject();
        });
        freeRegisters_(registers, count);
        return BufferString(buffer);
    }

    std::string RegisterSet(BNDebuggerController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "register", "value"});
        const auto name = RequiredString(arguments, "register");
        const auto value = Address(view, arguments, "value");
        std::uint8_t bytes[64]{};
        for (std::size_t index = 0; index < sizeof(value); ++index)
            bytes[index] = static_cast<std::uint8_t>(value >> (index * 8));
        if (!setRegister_(controller, name.c_str(), bytes))
            throw std::runtime_error("debugger register update failed");
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("register");
        writer.String(name.data(), static_cast<rapidjson::SizeType>(name.size()));
        writer.Key("updated"); writer.Bool(true); writer.EndObject();
        return BufferString(buffer);
    }

    std::string ModuleList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0; auto* modules = getModules_(controller, &count);
        std::vector<BNDebugModule> values;
        if (modules && count != 0)
            values.assign(modules, modules + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& module) {
            output.StartObject(); output.Key("name"); output.String(module.m_name ? module.m_name : "");
            output.Key("shortName"); output.String(module.m_short_name ? module.m_short_name : "");
            output.Key("address"); WriteAddress(output, module.m_address);
            output.Key("size"); output.Uint64(module.m_size);
            output.Key("loaded"); output.Bool(module.m_loaded); output.EndObject();
        });
        freeModules_(modules, count); return BufferString(buffer);
    }

    std::string MemoryRegionList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0; auto* regions = getMemoryMap_(controller, &count);
        std::vector<BNDebugMemoryRegion> values;
        if (regions && count != 0)
            values.assign(regions, regions + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& region) {
            output.StartObject(); output.Key("name"); output.String(region.m_name ? region.m_name : "");
            output.Key("start"); WriteAddress(output, region.m_start);
            output.Key("size"); output.Uint64(region.m_size);
            output.Key("read"); output.Bool(region.m_read); output.Key("write"); output.Bool(region.m_write);
            output.Key("execute"); output.Bool(region.m_execute); output.Key("shared"); output.Bool(region.m_shared);
            output.EndObject();
        });
        freeMemoryMap_(regions, count); return BufferString(buffer);
    }

    std::string MemoryRead(BNDebuggerController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "address", "length"});
        const auto address = Address(view, arguments, "address");
        const auto length = arguments.FindMember("length");
        if (length == arguments.MemberEnd() || !length->value.IsUint64() ||
            length->value.GetUint64() == 0 || length->value.GetUint64() > 65536)
            throw std::invalid_argument("length must be an integer from 1 through 65536");
        BinaryNinja::DataBuffer data(readMemory_(controller, address,
            static_cast<std::size_t>(length->value.GetUint64())));
        const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
        std::string hex;
        hex.reserve(data.GetLength() * 2);
        constexpr char digits[] = "0123456789abcdef";
        for (std::size_t index = 0; index < data.GetLength(); ++index)
        {
            hex.push_back(digits[bytes[index] >> 4]); hex.push_back(digits[bytes[index] & 0xf]);
        }
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("address"); WriteAddress(writer, address);
        writer.Key("requested"); writer.Uint64(length->value.GetUint64());
        writer.Key("read"); writer.Uint64(data.GetLength());
        writer.Key("hex"); writer.String(hex.data(), static_cast<rapidjson::SizeType>(hex.size()));
        writer.EndObject(); return BufferString(buffer);
    }

    std::string MemoryWrite(BNDebuggerController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "address", "hex"});
        const auto address = Address(view, arguments, "address");
        const auto hex = RequiredString(arguments, "hex");
        if (hex.size() % 2 != 0 || hex.size() > 131072)
            throw std::invalid_argument("hex must contain an even number of at most 131072 hexadecimal characters");
        std::vector<std::uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        const auto nibble = [](char value) -> int {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        };
        for (std::size_t index = 0; index < hex.size(); index += 2)
        {
            const auto high = nibble(hex[index]); const auto low = nibble(hex[index + 1]);
            if (high < 0 || low < 0) throw std::invalid_argument("hex contains a non-hexadecimal character");
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
        }
        BinaryNinja::DataBuffer data(bytes.data(), bytes.size());
        if (!writeMemory_(controller, address, data.GetBufferObject()))
            throw std::runtime_error("debugger memory write failed");
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("address"); WriteAddress(writer, address);
        writer.Key("written"); writer.Uint64(bytes.size()); writer.EndObject();
        return BufferString(buffer);
    }

    std::string BreakpointList(BNDebuggerController* controller, const Value& arguments)
    {
        RequireOnly(arguments, {"binaryView", "offset", "limit"});
        const auto [offset, limit] = Pagination(arguments);
        std::size_t count = 0; auto* points = getBreakpoints_(controller, &count);
        std::vector<BNDebugBreakpoint> values;
        if (points && count != 0)
            values.assign(points, points + count);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        WritePage(writer, values, offset, limit, [](auto& output, const auto& point) {
            output.StartObject(); output.Key("address"); WriteAddress(output, point.address);
            output.Key("module"); output.String(point.module ? point.module : "");
            output.Key("offset"); WriteAddress(output, point.offset);
            output.Key("enabled"); output.Bool(point.enabled);
            output.Key("condition"); output.String(point.condition ? point.condition : "");
            output.Key("type"); output.Int(point.type); output.EndObject();
        });
        freeBreakpoints_(points, count); return BufferString(buffer);
    }

    std::string BreakpointChange(BNDebuggerController* controller, BinaryNinja::BinaryView& view,
        const Value& arguments, bool add)
    {
        RequireOnly(arguments, {"binaryView", "address"});
        const auto address = Address(view, arguments, "address");
        if (add) addBreakpoint_(controller, address); else deleteBreakpoint_(controller, address);
        StringBuffer buffer; Writer<StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("address"); WriteAddress(writer, address);
        writer.Key(add ? "added" : "deleted"); writer.Bool(true); writer.EndObject();
        return BufferString(buffer);
    }

    DynamicLibrary library_;
    BNDebuggerController* (*getController_)(BNBinaryView*){};
    void (*freeController_)(BNDebuggerController*){};
    void (*freeString_)(char*){};
    void (*freeStringList_)(char**, std::size_t){};
    char** (*getAdapters_)(BNBinaryView*, std::size_t*){};
    char* (*getAdapter_)(BNDebuggerController*){};
    void (*setAdapter_)(BNDebuggerController*, const char*){};
    bool (*isConnected_)(BNDebuggerController*){};
    bool (*isRunning_)(BNDebuggerController*){};
    BNDebugAdapterConnectionStatus (*getConnectionStatus_)(BNDebuggerController*){};
    BNDebugAdapterTargetStatus (*getTargetStatus_)(BNDebuggerController*){};
    BNDebugStopReason (*getStopReason_)(BNDebuggerController*){};
    char* (*getStopReasonString_)(BNDebugStopReason){};
    std::uint64_t (*getIp_)(BNDebuggerController*){};
    std::uint64_t (*getStackPointer_)(BNDebuggerController*){};
    std::uint32_t (*getActivePid_)(BNDebuggerController*){};
    BNDebugProcess* (*getProcesses_)(BNDebuggerController*, std::size_t*){};
    void (*freeProcesses_)(BNDebugProcess*, std::size_t){};
    BNDebugThread (*getActiveThread_)(BNDebuggerController*){};
    void (*setActiveThread_)(BNDebuggerController*, BNDebugThread){};
    char* (*getRemoteHost_)(BNDebuggerController*){};
    std::uint32_t (*getRemotePort_)(BNDebuggerController*){};
    std::int32_t (*getPidAttach_)(BNDebuggerController*){};
    char* (*getInputFile_)(BNDebuggerController*){};
    char* (*getExecutablePath_)(BNDebuggerController*){};
    char* (*getWorkingDirectory_)(BNDebuggerController*){};
    char* (*getCommandLine_)(BNDebuggerController*){};
    void (*setRemoteHost_)(BNDebuggerController*, const char*){};
    void (*setRemotePort_)(BNDebuggerController*, std::uint32_t){};
    void (*setPidAttach_)(BNDebuggerController*, std::int32_t){};
    void (*setInputFile_)(BNDebuggerController*, const char*){};
    void (*setExecutablePath_)(BNDebuggerController*, const char*){};
    void (*setWorkingDirectory_)(BNDebuggerController*, const char*){};
    void (*setCommandLine_)(BNDebuggerController*, const char*){};
    bool (*launch_)(BNDebuggerController*){};
    bool (*connect_)(BNDebuggerController*){};
    bool (*attach_)(BNDebuggerController*){};
    bool (*go_)(BNDebuggerController*){};
    void (*pause_)(BNDebuggerController*){};
    bool (*stepInto_)(BNDebuggerController*, BNFunctionGraphType){};
    bool (*stepOver_)(BNDebuggerController*, BNFunctionGraphType){};
    bool (*stepReturn_)(BNDebuggerController*){};
    void (*restart_)(BNDebuggerController*){};
    void (*quit_)(BNDebuggerController*){};
    void (*quitWait_)(BNDebuggerController*, std::uint64_t){};
    void (*detach_)(BNDebuggerController*){};
    void (*destroy_)(BNDebuggerController*){};
    BNDebugStopReason (*launchWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*connectWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*attachWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*goWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*pauseWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*stepIntoWait_)(BNDebuggerController*, BNFunctionGraphType, std::uint64_t){};
    BNDebugStopReason (*stepOverWait_)(BNDebuggerController*, BNFunctionGraphType, std::uint64_t){};
    BNDebugStopReason (*stepReturnWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugStopReason (*restartWait_)(BNDebuggerController*, std::uint64_t){};
    BNDebugThread* (*getThreads_)(BNDebuggerController*, std::size_t*){};
    void (*freeThreads_)(BNDebugThread*, std::size_t){};
    BNDebugFrame* (*getFrames_)(BNDebuggerController*, std::uint32_t, std::size_t*){};
    void (*freeFrames_)(BNDebugFrame*, std::size_t){};
    BNDebugRegister* (*getRegisters_)(BNDebuggerController*, std::size_t*){};
    void (*freeRegisters_)(BNDebugRegister*, std::size_t){};
    bool (*setRegister_)(BNDebuggerController*, const char*, const std::uint8_t*){};
    BNDebugModule* (*getModules_)(BNDebuggerController*, std::size_t*){};
    void (*freeModules_)(BNDebugModule*, std::size_t){};
    BNDebugMemoryRegion* (*getMemoryMap_)(BNDebuggerController*, std::size_t*){};
    void (*freeMemoryMap_)(BNDebugMemoryRegion*, std::size_t){};
    BNDataBuffer* (*readMemory_)(BNDebuggerController*, std::uint64_t, std::size_t){};
    bool (*writeMemory_)(BNDebuggerController*, std::uint64_t, BNDataBuffer*){};
    BNDebugBreakpoint* (*getBreakpoints_)(BNDebuggerController*, std::size_t*){};
    void (*freeBreakpoints_)(BNDebugBreakpoint*, std::size_t){};
    void (*addBreakpoint_)(BNDebuggerController*, std::uint64_t){};
    void (*deleteBreakpoint_)(BNDebuggerController*, std::uint64_t){};
};
}

class PluginTools::Impl
{
  public:
    std::string Execute(std::string_view name, BinaryNinja::BinaryView& view,
        std::string_view argumentsJson)
    {
        const auto arguments = ParseArguments(argumentsJson);
        if (name.starts_with("bn_kernel_cache_"))
        {
            if (!kernelCache_)
                kernelCache_ = std::make_unique<KernelCacheApi>();
            return kernelCache_->Execute(name, view, arguments);
        }
        if (name.starts_with("bn_shared_cache_"))
        {
            if (!sharedCache_)
                sharedCache_ = std::make_unique<SharedCacheApi>();
            return sharedCache_->Execute(name, view, arguments);
        }
        if (name.starts_with("bn_debugger_"))
        {
            if (!debugger_)
                debugger_ = std::make_unique<DebuggerApi>();
            return debugger_->Execute(name, view, arguments);
        }
        throw std::invalid_argument("plugin tool is not implemented");
    }

    void Close(BinaryNinja::BinaryView& view) noexcept
    {
        if (debugger_)
            debugger_->Close(view);
    }

    std::optional<std::string> DescribeAddress(
        BinaryNinja::BinaryView& view, std::uint64_t address)
    {
        if (view.GetTypeName() == "KCView")
        {
            if (!kernelCache_)
                kernelCache_ = std::make_unique<KernelCacheApi>();
            const auto description = kernelCache_->DescribeAddress(view, address);
            if (!description.empty()) return description;
        }
        else if (view.GetTypeName() == "DSCView")
        {
            if (!sharedCache_)
                sharedCache_ = std::make_unique<SharedCacheApi>();
            const auto description = sharedCache_->DescribeAddress(view, address);
            if (!description.empty()) return description;
        }
        return std::nullopt;
    }

  private:
    std::unique_ptr<KernelCacheApi> kernelCache_;
    std::unique_ptr<SharedCacheApi> sharedCache_;
    std::unique_ptr<DebuggerApi> debugger_;
};

PluginTools::PluginTools() : impl_(std::make_unique<Impl>()) {}
PluginTools::~PluginTools() = default;

std::string PluginTools::Execute(std::string_view name, BinaryNinja::BinaryView& view,
    std::string_view argumentsJson)
{
    return impl_->Execute(name, view, argumentsJson);
}

void PluginTools::Close(BinaryNinja::BinaryView& view) noexcept
{
    impl_->Close(view);
}

std::optional<std::string> PluginTools::DescribeAddress(
    BinaryNinja::BinaryView& view, std::uint64_t address)
{
    return impl_->DescribeAddress(view, address);
}
}
