#include "binjad/worker/file_child.hpp"

#include "binjad/binary_ninja/runtime.hpp"
#include "binjad/binary_ninja/language.hpp"
#include "binjad/binary_ninja/diff_tools.hpp"
#include "binjad/binary_ninja/plugin_tools.hpp"
#include "binjad/binary_ninja/string_codec.hpp"
#include "binjad/ipc/envelope.hpp"

#include <binaryninjaapi.h>
#include <highlevelilinstruction.h>

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <cctype>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace binjad
{
namespace
{
using binary_ninja::DecodeString;
using binary_ninja::HexBytes;
using binary_ninja::StringEncodingName;
using binary_ninja::SliceString;

constexpr std::size_t kDefaultListLimit = 50;
constexpr std::size_t kDefaultRenderLimit = 200;

std::string HexAddress(std::uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string NormalizedName(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const auto character : value)
    {
        if (character == ' ' || character == '-' || character == '_')
            continue;
        result.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(character))));
    }
    return result;
}

BinaryNinja::QualifiedName QualifiedNameFromString(std::string_view name)
{
    std::vector<std::string> components;
    while (!name.empty())
    {
        const auto separator = name.find("::");
        components.emplace_back(name.substr(0, separator));
        if (separator == std::string_view::npos)
            break;
        name.remove_prefix(separator + 2);
    }
    return BinaryNinja::QualifiedName(components);
}

std::string TokenText(const std::vector<BinaryNinja::InstructionTextToken>& tokens)
{
    std::string text;
    for (const auto& token : tokens)
        text += token.text;
    return text;
}

std::string RenderTypeDefinition(BinaryNinja::BinaryView* view,
    const BinaryNinja::QualifiedName& name, const BinaryNinja::Ref<BinaryNinja::Type>& type)
{
    std::string definition;
    const auto lines = type->GetLines(view->GetTypeContainer(), name.GetString(), 64, false);
    for (std::size_t index = 0; index < lines.size(); ++index)
    {
        if (index != 0)
            definition += '\n';
        definition += TokenText(lines[index].tokens);
    }
    return definition;
}

struct DetectedStringData
{
    BNStringType type;
    std::vector<std::uint8_t> bytes;
};

DetectedStringData ReadDetectedString(BinaryNinja::BinaryView* view,
    BNStringType type, std::uint64_t start, std::size_t length)
{
    const auto data = view->ReadBuffer(start, length);
    const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
    DetectedStringData result{type, {}};
    if (bytes && data.GetLength() != 0)
        result.bytes.assign(bytes, bytes + data.GetLength());
    if (type != AsciiString || data.GetLength() != length ||
        length > std::numeric_limits<std::size_t>::max() - 4096)
        return result;

    const auto expanded = view->ReadBuffer(start, length + 4096);
    const auto* expandedBytes = static_cast<const std::uint8_t*>(expanded.GetData());
    if (expanded.GetLength() <= length || expandedBytes[length] < 0x80)
        return result;
    const auto terminator = std::find(
        expandedBytes + length, expandedBytes + expanded.GetLength(), std::uint8_t{0});
    if (terminator == expandedBytes + expanded.GetLength())
        return result;
    const auto expandedLength = static_cast<std::size_t>(terminator - expandedBytes);
    const auto decoded = DecodeString(Utf8String,
        std::span<const std::uint8_t>(expandedBytes, expandedLength),
        std::numeric_limits<std::size_t>::max());
    if (!decoded.decoded)
        return result;
    result.type = Utf8String;
    result.bytes.assign(expandedBytes, terminator);
    return result;
}

std::optional<DetectedStringData> ReadNullTerminatedString(
    BinaryNinja::BinaryView* view, std::uint64_t start)
{
    constexpr std::size_t maximumLength = 4096;
    const auto data = view->ReadBuffer(start, maximumLength);
    const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
    if (!bytes || data.GetLength() == 0)
        return std::nullopt;
    const auto terminator = std::find(bytes, bytes + data.GetLength(), std::uint8_t{0});
    if (terminator == bytes || terminator == bytes + data.GetLength())
        return std::nullopt;
    if (std::any_of(bytes, terminator, [](std::uint8_t byte) {
            return byte < 0x20 || byte == 0x7f;
        }))
        return std::nullopt;
    const auto type = std::any_of(bytes, terminator,
        [](std::uint8_t byte) { return byte >= 0x80; }) ? Utf8String : AsciiString;
    std::vector<std::uint8_t> value(bytes, terminator);
    if (!DecodeString(type, value, std::numeric_limits<std::size_t>::max()).decoded)
        return std::nullopt;
    return DetectedStringData{type, std::move(value)};
}

const char* AnalysisSkipReasonName(BNAnalysisSkipReason reason)
{
    switch (reason)
    {
        case NoSkipReason: return "NoSkipReason";
        case AlwaysSkipReason: return "AlwaysSkipReason";
        case ExceedFunctionSizeSkipReason: return "ExceedFunctionSizeSkipReason";
        case ExceedFunctionAnalysisTimeSkipReason: return "ExceedFunctionAnalysisTimeSkipReason";
        case ExceedFunctionUpdateCountSkipReason: return "ExceedFunctionUpdateCountSkipReason";
        case NewAutoFunctionAnalysisSuppressedReason: return "NewAutoFunctionAnalysisSuppressedReason";
        case BasicAnalysisSkipReason: return "BasicAnalysisSkipReason";
        case IntermediateAnalysisSkipReason: return "IntermediateAnalysisSkipReason";
        case AnalysisPipelineSuspendedReason: return "AnalysisPipelineSuspendedReason";
    }
    return "UnknownSkipReason";
}

const char* VariableSourceName(BNVariableSourceType source)
{
    switch (source)
    {
        case StackVariableSourceType: return "stack";
        case RegisterVariableSourceType: return "register";
        case FlagVariableSourceType: return "flag";
        case CompositeReturnValueSourceType: return "compositeReturn";
        case CompositeParameterSourceType: return "compositeParameter";
    }
    return "unknown";
}

BNVariableSourceType ParseVariableSource(std::string_view source)
{
    if (source == "stack") return StackVariableSourceType;
    if (source == "register") return RegisterVariableSourceType;
    if (source == "flag") return FlagVariableSourceType;
    if (source == "compositeReturn") return CompositeReturnValueSourceType;
    if (source == "compositeParameter") return CompositeParameterSourceType;
    throw std::invalid_argument("unknown variable source");
}

const char* SymbolTypeName(BNSymbolType type)
{
    switch (type)
    {
        case FunctionSymbol: return "FunctionSymbol";
        case ImportAddressSymbol: return "ImportAddressSymbol";
        case ImportedFunctionSymbol: return "ImportedFunctionSymbol";
        case DataSymbol: return "DataSymbol";
        case ImportedDataSymbol: return "ImportedDataSymbol";
        case ExternalSymbol: return "ExternalSymbol";
        case LibraryFunctionSymbol: return "LibraryFunctionSymbol";
        case SymbolicFunctionSymbol: return "SymbolicFunctionSymbol";
        case LocalLabelSymbol: return "LocalLabelSymbol";
    }
    return "UnknownSymbol";
}

const char* SymbolBindingName(BNSymbolBinding binding)
{
    switch (binding)
    {
        case NoBinding: return "NoBinding";
        case LocalBinding: return "LocalBinding";
        case GlobalBinding: return "GlobalBinding";
        case WeakBinding: return "WeakBinding";
    }
    return "UnknownBinding";
}

const char* SectionSemanticsName(BNSectionSemantics semantics)
{
    switch (semantics)
    {
        case DefaultSectionSemantics: return "DefaultSectionSemantics";
        case ReadOnlyCodeSectionSemantics: return "ReadOnlyCodeSectionSemantics";
        case ReadOnlyDataSectionSemantics: return "ReadOnlyDataSectionSemantics";
        case ReadWriteDataSectionSemantics: return "ReadWriteDataSectionSemantics";
        case ExternalSectionSemantics: return "ExternalSectionSemantics";
    }
    return "UnknownSectionSemantics";
}

BNSectionSemantics ParseSectionSemantics(std::string_view semantics)
{
    if (semantics == "DefaultSectionSemantics") return DefaultSectionSemantics;
    if (semantics == "ReadOnlyCodeSectionSemantics") return ReadOnlyCodeSectionSemantics;
    if (semantics == "ReadOnlyDataSectionSemantics") return ReadOnlyDataSectionSemantics;
    if (semantics == "ReadWriteDataSectionSemantics") return ReadWriteDataSectionSemantics;
    if (semantics == "ExternalSectionSemantics") return ExternalSectionSemantics;
    throw std::invalid_argument("unknown section semantics");
}

const char* TypeClassName(BNTypeClass type)
{
    switch (type)
    {
        case VoidTypeClass: return "VoidTypeClass";
        case BoolTypeClass: return "BoolTypeClass";
        case IntegerTypeClass: return "IntegerTypeClass";
        case FloatTypeClass: return "FloatTypeClass";
        case StructureTypeClass: return "StructureTypeClass";
        case EnumerationTypeClass: return "EnumerationTypeClass";
        case PointerTypeClass: return "PointerTypeClass";
        case ArrayTypeClass: return "ArrayTypeClass";
        case FunctionTypeClass: return "FunctionTypeClass";
        case VarArgsTypeClass: return "VarArgsTypeClass";
        case ValueTypeClass: return "ValueTypeClass";
        case NamedTypeReferenceClass: return "NamedTypeReferenceClass";
        case WideCharTypeClass: return "WideCharTypeClass";
        case FragmentTypeClass: return "FragmentTypeClass";
    }
    return "UnknownTypeClass";
}

BNSymbolType ParseSymbolType(std::string_view type)
{
    if (type == "FunctionSymbol") return FunctionSymbol;
    if (type == "ImportAddressSymbol") return ImportAddressSymbol;
    if (type == "ImportedFunctionSymbol") return ImportedFunctionSymbol;
    if (type == "DataSymbol") return DataSymbol;
    if (type == "ImportedDataSymbol") return ImportedDataSymbol;
    if (type == "ExternalSymbol") return ExternalSymbol;
    if (type == "LibraryFunctionSymbol") return LibraryFunctionSymbol;
    if (type == "SymbolicFunctionSymbol") return SymbolicFunctionSymbol;
    if (type == "LocalLabelSymbol") return LocalLabelSymbol;
    throw std::invalid_argument("unknown symbol type");
}

BNSymbolBinding ParseSymbolBinding(std::string_view binding)
{
    if (binding == "NoBinding") return NoBinding;
    if (binding == "LocalBinding") return LocalBinding;
    if (binding == "GlobalBinding") return GlobalBinding;
    if (binding == "WeakBinding") return WeakBinding;
    throw std::invalid_argument("unknown symbol binding");
}

std::string MergeLoadOptions(
    std::string_view base, std::string_view overrides, bool reuseDatabase)
{
    rapidjson::Document document;
    const auto input = base.empty() ? std::string_view("{}") : base;
    try
    {
        document.Parse(input.data(), input.size());
    }
    catch (const ParseException&)
    {
        throw std::invalid_argument("file load options must be a JSON object");
    }
    if (document.HasParseError() || !document.IsObject())
        throw std::invalid_argument("file load options must be a JSON object");

    rapidjson::Document overrideDocument;
    const auto overrideInput = overrides.empty() ? std::string_view("{}") : overrides;
    try
    {
        overrideDocument.Parse(overrideInput.data(), overrideInput.size());
    }
    catch (const ParseException&)
    {
        throw std::invalid_argument("BinaryView load options must be a JSON object");
    }
    if (overrideDocument.HasParseError() || !overrideDocument.IsObject())
        throw std::invalid_argument("BinaryView load options must be a JSON object");
    for (const auto& member : overrideDocument.GetObject())
    {
        rapidjson::Value name(member.name, document.GetAllocator());
        rapidjson::Value value(member.value, document.GetAllocator());
        const auto existing = document.FindMember(name);
        if (existing == document.MemberEnd())
            document.AddMember(std::move(name), std::move(value), document.GetAllocator());
        else
            existing->value = std::move(value);
    }

    if (reuseDatabase)
    {
        constexpr auto key = "analysis.database.suppressReanalysis";
        const auto existing = document.FindMember(key);
        if (existing == document.MemberEnd())
            document.AddMember(rapidjson::StringRef(key), true, document.GetAllocator());
        else if (!existing->value.IsBool())
            throw std::invalid_argument(
                "analysis.database.suppressReanalysis must be a boolean");
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);
    return {buffer.GetString(), buffer.GetSize()};
}

struct Candidate
{
    BinaryNinja::Ref<BinaryNinja::BinaryViewType> type;
    bool recommended = false;
    std::string loadSettingsSchemaJson;
};

struct ViewState
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
    explicit FileChild(std::unique_ptr<ipc::ByteChannel> channel)
        : channel_(std::move(channel)), runtime_(true)
    {
    }

    ~FileChild()
    {
        try
        {
            Close(true);
        }
        catch (...)
        {}
    }

    int Run()
    {
        try
        {
            bool running = true;
            while (running)
            {
                const auto envelope = ipc::ReceiveEnvelope(*channel_);
                if (!envelope.has_command() || envelope.request_id() == 0)
                {
                    SendFailure(envelope.request_id(), "expected a command with a nonzero request ID");
                    continue;
                }
                Dispatch(envelope, running);
            }
            return EXIT_SUCCESS;
        }
        catch (const std::exception& exception)
        {
            try
            {
                SendEvent(0, ipc::ANALYSIS_STATE_FAILED, exception.what());
            }
            catch (...)
            {}
            return EXIT_FAILURE;
        }
    }

  private:
    void AddCandidate(const std::string& name,
        BinaryNinja::Ref<BinaryNinja::BinaryViewType> type)
    {
        if (name.empty() || candidates_.contains(name))
            return;
        std::string schema;
        if (type)
        {
            if (const auto settings = type->GetLoadSettingsForData(data_))
            {
                settings->SetResourceId(name);
                schema = settings->SerializeSchema();
            }
        }
        candidateOrder_.push_back(name);
        candidates_.emplace(name, Candidate{std::move(type), false, std::move(schema)});
    }

    bool HasMappedLoadOptions() const
    {
        rapidjson::Document options;
        options.Parse(loadOptions_.data(), loadOptions_.size());
        if (options.HasParseError() || !options.IsObject())
            return false;
        for (const auto& member : options.GetObject())
        {
            const std::string_view name(member.name.GetString(), member.name.GetStringLength());
            if (name == "loader.platform" || name == "loader.architecture" ||
                name == "loader.imageBase" || name == "loader.entryPoint" ||
                name == "loader.entryPointOffset" || name == "loader.segments" ||
                name == "loader.sections")
                return true;
        }
        return false;
    }

    void EnumerateCandidates()
    {
        for (const auto& name : file_->GetExistingViews())
            AddCandidate(name, BinaryNinja::BinaryViewType::GetByName(name));
        AddCandidate(data_->GetTypeName(),
            BinaryNinja::BinaryViewType::GetByName(data_->GetTypeName()));
        for (const auto& type : BinaryNinja::BinaryViewType::GetViewTypesForData(data_))
        {
            if (type && !type->IsDeprecated())
                AddCandidate(type->GetName(), type);
        }
        if (data_->GetTypeName() == "Raw")
            AddCandidate("Mapped", BinaryNinja::BinaryViewType::GetByName("Mapped"));
        if (candidateOrder_.empty())
            throw std::runtime_error("Binary Ninja found no BinaryView candidates");

        auto recommended = std::find_if(candidateOrder_.begin(), candidateOrder_.end(),
            [&](const auto& name) {
                return name != "Raw" && name != "Mapped" && candidates_.at(name).type;
            });
        if (databaseBacked_)
        {
            const auto configurationType = data_->GetTypeName();
            const auto existing = candidates_.find(configurationType);
            if (existing != candidates_.end())
                recommended = std::find(candidateOrder_.begin(), candidateOrder_.end(), configurationType);
        }
        else if (HasMappedLoadOptions() && candidates_.contains("Mapped"))
            recommended = std::find(candidateOrder_.begin(), candidateOrder_.end(), "Mapped");
        if (recommended == candidateOrder_.end())
            recommended = candidateOrder_.begin();
        candidates_.at(*recommended).recommended = true;
    }

    ipc::Reply OpenFile(const ipc::OpenFile& command)
    {
        if (file_)
            throw std::runtime_error("file child already owns an open item");
        if (command.path().empty())
            throw std::invalid_argument("open path must not be empty");
        loadOptions_ = MergeLoadOptions(command.options_json(), {}, false);
        try
        {
            openedPath_ = command.path();
            databaseBacked_ = BNIsDatabase(command.path().c_str());
            reuseDatabase_ = command.reuse_database() && databaseBacked_;
            if (reuseDatabase_)
            {
                if (!BinaryNinja::Settings::Instance()->Contains(
                    "analysis.database.suppressReanalysis"))
                    throw std::runtime_error(
                        "Binary Ninja does not expose BNDB reanalysis suppression");
                loadOptions_ = MergeLoadOptions(loadOptions_, {}, true);
            }
            if (databaseBacked_)
            {
                data_ = BinaryNinja::Load(command.path(), false, loadOptions_);
                if (data_)
                    file_ = data_->GetFile();
            }
            else
            {
                BinaryNinja::TransformSession transforms(
                    command.path(), TransformSessionModeFull, loadOptions_);
                if (transforms.Process() && transforms.HasAnyStages() &&
                    transforms.HasSinglePath())
                {
                    data_ = transforms.GetCurrentView();
                    if (data_)
                        file_ = data_->GetFile();
                }
                if (!data_)
                {
                    file_ = new BinaryNinja::FileMetadata(command.path());
                    data_ = BinaryNinja::BinaryData::CreateFromFilename(file_, command.path());
                }
            }
            if (!data_)
                throw std::runtime_error("Binary Ninja could not open the file metadata");
            snapshotApplied_ = !databaseBacked_ || file_->IsSnapshotDataAppliedWithoutError();
            EnumerateCandidates();
        }
        catch (...)
        {
            if (file_)
                file_->Close();
            candidates_.clear();
            candidateOrder_.clear();
            data_ = nullptr;
            file_ = nullptr;
            databaseBacked_ = false;
            snapshotApplied_ = false;
            reuseDatabase_ = false;
            loadOptions_.clear();
            openedPath_.clear();
            throw;
        }

        ipc::Reply reply;
        reply.set_success(true);
        auto* opened = reply.mutable_file_opened();
        opened->set_database_backed(databaseBacked_);
        opened->set_snapshot_applied(snapshotApplied_);
        for (const auto& name : candidateOrder_)
        {
            auto* candidate = opened->add_candidates();
            candidate->set_view_type(name);
            candidate->set_recommended(candidates_.at(name).recommended);
            candidate->set_created(false);
            candidate->set_load_settings_schema_json(
                candidates_.at(name).loadSettingsSchemaJson);
        }
        return reply;
    }

    std::string ApplyLoadSettings(const Candidate& candidate,
        const std::string& options, const std::string& explicitOptions)
    {
        if (!candidate.type)
            return {};
        const auto settings = candidate.type->GetLoadSettingsForData(data_);
        if (!settings)
        {
            if (explicitOptions != "{}")
                throw std::invalid_argument("BinaryView type does not accept load options; select Mapped for raw firmware and inspect bn_binary_view_load_settings");
            return {};
        }
        settings->SetResourceId(candidate.type->GetName());
        rapidjson::Document requested;
        requested.Parse(explicitOptions.data(), explicitOptions.size());
        if (requested.HasParseError() || !requested.IsObject())
            throw std::invalid_argument("BinaryView load options must be a JSON object");
        for (const auto& member : requested.GetObject())
        {
            const std::string name(member.name.GetString(), member.name.GetStringLength());
            if (!settings->Contains(name) && name != "loader.architecture" &&
                name != "loader.entryPoint")
                throw std::invalid_argument("BinaryView load option '" + name +
                    "' is not supported by " + candidate.type->GetName() +
                    "; call bn_binary_view_load_settings for the authoritative schema");
        }
        if (!settings->DeserializeSettings(options, data_, SettingsResourceScope))
            throw std::invalid_argument("Binary Ninja rejected the BinaryView load options");
        data_->SetLoadSettings(candidate.type->GetName(), settings);
        return settings->SerializeSettings(data_, SettingsResourceScope);
    }

    ipc::Reply OpenBinaryView(const ipc::OpenBinaryView& command)
    {
        if (!file_ || !data_)
            throw std::runtime_error("no open item exists");
        if (command.view_type().empty())
            throw std::invalid_argument("BinaryView type must not be empty");
        const auto candidate = candidates_.find(command.view_type());
        if (candidate == candidates_.end())
            throw std::runtime_error("BinaryView candidate not found");

        std::shared_ptr<ViewState> state;
        {
            std::lock_guard lock(viewMutex_);
            const auto existing = views_.find(command.view_type());
            if (existing != views_.end())
                state = existing->second;
        }
        if (!state)
        {
            const auto options = MergeLoadOptions(
                loadOptions_, command.options_json(), reuseDatabase_);
            const auto effectiveSettings = ApplyLoadSettings(
                candidate->second, options, command.options_json());
            BinaryNinja::Ref<BinaryNinja::BinaryView> view;
            if (command.view_type() == data_->GetTypeName())
            {
                view = data_;
            }
            else if (databaseBacked_)
            {
                view = file_->GetViewOfType(command.view_type());
            }
            if (!view && candidate->second.type)
            {
                view = candidate->second.type->Create(data_);
                if (view && !view->Init())
                    view = nullptr;
            }
            if (!view)
                throw std::runtime_error("Binary Ninja could not materialize the BinaryView");
            state = std::make_shared<ViewState>();
            state->view = view;
            state->effectiveLoadSettingsJson = effectiveSettings;
            std::lock_guard lock(viewMutex_);
            views_.emplace(command.view_type(), state);
        }
        else if (command.options_json() != "{}")
        {
            throw std::invalid_argument(
                "BinaryView is already materialized; load options cannot be changed. Close the open item, reopen it, and configure the candidate before materialization");
        }

        ipc::Reply reply;
        reply.set_success(true);
        auto* opened = reply.mutable_binary_view_opened();
        opened->set_view_type(command.view_type());
        if (const auto architecture = state->view->GetDefaultArchitecture())
            opened->set_architecture(architecture->GetName());
        if (const auto platform = state->view->GetDefaultPlatform())
            opened->set_platform(platform->GetName());
        opened->set_effective_load_settings_json(state->effectiveLoadSettingsJson);
        opened->set_start(state->view->GetStart());
        opened->set_end(state->view->GetEnd());
        opened->set_entry_point(state->view->GetEntryPoint());
        opened->set_database_backed(file_->IsBackedByDatabase(command.view_type()));
        opened->set_snapshot_applied(
            !databaseBacked_ || file_->IsSnapshotDataAppliedWithoutError());
        return reply;
    }

    std::shared_ptr<ViewState> View(const std::string& viewType) const
    {
        std::lock_guard lock(viewMutex_);
        const auto view = views_.find(viewType);
        if (view == views_.end())
            throw std::runtime_error(
                "BinaryView is not materialized; call bn_binary_view_open first");
        return view->second;
    }

    BinaryNinja::Ref<BinaryNinja::Function> ResolveFunction(
        const std::shared_ptr<ViewState>& state, const rapidjson::Value& arguments)
    {
        if (!arguments.IsObject() || !arguments.HasMember("function") ||
            !arguments["function"].IsString())
            throw std::invalid_argument("function selector must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& selector = arguments["function"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(selector.GetString(), selector.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid function selector" : parseError);
        auto functions = state->view->GetAnalysisFunctionsForAddress(address);
        const bool hasFunctionAtAddress = !functions.empty();
        std::optional<std::string> requestedArchitecture;
        if (const auto arch = arguments.FindMember("arch"); arch != arguments.MemberEnd())
        {
            const std::string wanted(arch->value.GetString(), arch->value.GetStringLength());
            requestedArchitecture = wanted;
            std::erase_if(functions, [&](const auto& function) {
                const auto architecture = function->GetArchitecture();
                return !architecture || architecture->GetName() != wanted;
            });
        }
        if (functions.empty())
        {
            if (hasFunctionAtAddress && requestedArchitecture)
                throw std::invalid_argument("function exists at " + HexAddress(address) +
                    " but not for requested architecture '" + *requestedArchitecture + "'");
            const auto symbols = state->view->GetSymbols(address, 1);
            if (std::any_of(symbols.begin(), symbols.end(), [&](const auto& symbol) {
                    return symbol->GetAddress() == address &&
                        symbol->GetType() == FunctionSymbol;
                }))
                throw std::invalid_argument("function not found at " + HexAddress(address) +
                    "; a FunctionSymbol exists, but symbols do not create functions; "
                    "call bn_function_create for this BinaryView and address");
            if (const auto description = pluginTools_.DescribeAddress(*state->view, address))
                throw std::invalid_argument("function not found: " + *description);
            throw std::invalid_argument("function not found at " + HexAddress(address));
        }
        if (functions.size() != 1)
            throw std::invalid_argument("function selector is ambiguous; specify arch");
        return functions.front();
    }

    BinaryNinja::Ref<BinaryNinja::Type> ParseRequestedType(
        const std::shared_ptr<ViewState>& state, const rapidjson::Value& arguments)
    {
        const bool hasDefinition = arguments.HasMember("definition");
        const bool hasSource = arguments.HasMember("source");
        if (hasDefinition == hasSource)
            throw std::invalid_argument("exactly one of definition or source is required");
        std::string errors;
        if (hasDefinition)
        {
            const auto& value = arguments["definition"];
            if (!value.IsString() || value.GetStringLength() == 0)
                throw std::invalid_argument("definition must be a non-empty string");
            BinaryNinja::QualifiedNameAndType parsed;
            if (!state->view->ParseTypeString(
                    std::string(value.GetString(), value.GetStringLength()), parsed, errors) ||
                !parsed.type)
                throw std::invalid_argument(errors.empty() ? "invalid type definition" : errors);
            return parsed.type;
        }
        const auto& source = arguments["source"];
        if (!source.IsString() || source.GetStringLength() == 0)
            throw std::invalid_argument("source must be a non-empty string");
        std::vector<std::string> options;
        std::vector<std::string> includeDirs;
        auto readStrings = [&](const char* name, std::vector<std::string>& output) {
            if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
            {
                if (!value->value.IsArray())
                    throw std::invalid_argument(std::string(name) + " must be an array of strings");
                for (const auto& item : value->value.GetArray())
                {
                    if (!item.IsString())
                        throw std::invalid_argument(std::string(name) + " must be an array of strings");
                    output.emplace_back(item.GetString(), item.GetStringLength());
                }
            }
        };
        readStrings("options", options);
        readStrings("includeDirs", includeDirs);
        bool importDependencies = true;
        if (const auto value = arguments.FindMember("importDependencies");
            value != arguments.MemberEnd())
        {
            if (!value->value.IsBool())
                throw std::invalid_argument("importDependencies must be a boolean");
            importDependencies = value->value.GetBool();
        }
        BinaryNinja::TypeParserResult parsed;
        if (!state->view->ParseTypesFromSource(
                std::string(source.GetString(), source.GetStringLength()), options, includeDirs,
                parsed, errors, {}, importDependencies))
            throw std::invalid_argument(errors.empty() ? "invalid type source" : errors);
        std::vector<BinaryNinja::ParsedType> candidates;
        candidates.insert(candidates.end(), parsed.types.begin(), parsed.types.end());
        candidates.insert(candidates.end(), parsed.variables.begin(), parsed.variables.end());
        candidates.insert(candidates.end(), parsed.functions.begin(), parsed.functions.end());
        if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
        {
            const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
            std::erase_if(candidates, [&](const auto& candidate) {
                return candidate.name.GetString() != wanted;
            });
        }
        if (candidates.empty())
            throw std::invalid_argument("parsed type not found");
        if (candidates.size() != 1)
            throw std::invalid_argument("type source is ambiguous; specify type");
        return candidates.front().type;
    }

    void StartAnalysis(const std::string& viewType, std::uint64_t origin)
    {
        const auto state = View(viewType);
        BinaryNinja::Ref<BinaryNinja::BinaryView> view;
        {
            std::lock_guard lock(viewMutex_);
            if (!activeAnalysisView_.empty())
                throw std::runtime_error("analysis is already active for this open item");
            state->analysisActive = true;
            state->abortRequested = false;
            activeAnalysisView_ = viewType;
            view = state->view;
        }
        if (view->AnalysisIsAborted())
        {
            BinaryNinja::WorkflowMachine machine(view);
            if (!machine.Enable())
            {
                std::lock_guard lock(viewMutex_);
                state->analysisActive = false;
                activeAnalysisView_.clear();
                throw std::runtime_error("failed to re-enable the Binary Ninja workflow");
            }
        }

        try
        {
            auto completion = view->AddAnalysisCompletionEvent([this, state, viewType, origin] {
                ipc::AnalysisState result;
                {
                    std::lock_guard lock(viewMutex_);
                    result = state->abortRequested
                        ? ipc::ANALYSIS_STATE_ABORTED : ipc::ANALYSIS_STATE_COMPLETE;
                    state->analysisActive = false;
                    if (activeAnalysisView_ == viewType)
                        activeAnalysisView_.clear();
                }
                try
                {
                    SendEvent(origin, result, {});
                }
                catch (...)
                {}
            });
            if (!completion)
                throw std::runtime_error("failed to register analysis completion event");
            {
                std::lock_guard lock(viewMutex_);
                state->completionEvents.push_back(completion);
            }
            view->UpdateAnalysis();
        }
        catch (...)
        {
            std::lock_guard lock(viewMutex_);
            state->analysisActive = false;
            if (activeAnalysisView_ == viewType)
                activeAnalysisView_.clear();
            throw;
        }
    }

    ipc::Reply AnalysisStatus(const std::string& viewType) const
    {
        if (viewType.empty())
            throw std::invalid_argument("BinaryView type must not be empty");
        ipc::Reply reply;
        reply.set_success(true);
        auto* status = reply.mutable_analysis_status();
        status->set_worker_count(static_cast<std::uint32_t>(BinaryNinja::GetWorkerThreadCount()));
        std::shared_ptr<ViewState> state;
        {
            std::lock_guard lock(viewMutex_);
            const auto existing = views_.find(viewType);
            if (existing != views_.end())
                state = existing->second;
        }
        status->set_has_view(static_cast<bool>(state));
        if (!state)
        {
            status->set_state(ipc::ANALYSIS_STATE_IDLE);
            return reply;
        }

        const auto progress = state->view->GetAnalysisProgress();
        status->set_completed(progress.count);
        status->set_total(progress.total);
        bool analysisActive = false;
        {
            std::lock_guard lock(viewMutex_);
            analysisActive = state->analysisActive;
        }
        if (analysisActive)
            status->set_state(ipc::ANALYSIS_STATE_RUNNING);
        else if (state->view->AnalysisIsAborted())
            status->set_state(ipc::ANALYSIS_STATE_ABORTED);
        else if (state->view->HasInitialAnalysis())
            status->set_state(ipc::ANALYSIS_STATE_COMPLETE);
        else
            status->set_state(ipc::ANALYSIS_STATE_IDLE);
        status->set_modified(file_->IsModified());
        status->set_analysis_changed(file_->IsAnalysisChanged());
        return reply;
    }

    ipc::Reply SaveBinaryView(const ipc::SaveBinaryView& command)
    {
        if (activeUndoId_)
            throw std::runtime_error("cannot save while an explicit transaction is active; commit or roll it back first");
        std::shared_ptr<ViewState> state;
        {
            std::lock_guard lock(viewMutex_);
            const auto existing = views_.find(command.view_type());
            if (existing == views_.end())
                throw std::runtime_error(
                    "BinaryView is not materialized; call bn_binary_view_open first");
            state = existing->second;
            if (state->analysisActive)
                throw std::runtime_error("cannot save while analysis is active");
        }
        const bool temporaryCopy = command.temporary_copy();
        const bool createdDatabase = !databaseBacked_ || temporaryCopy;
        const auto progress = [this](std::size_t completed, std::size_t total) {
            SendProgress(currentRequest_, "save", completed, total);
            return true;
        };
        auto savedPath = openedPath_;
        bool saved = false;
        if (createdDatabase)
        {
            if (command.destination().empty())
                throw std::invalid_argument("new database save requires a destination");
            savedPath = command.destination();
            saved = state->view->CreateDatabase(savedPath.string(), progress);
        }
        else
        {
            auto snapshotView = file_->GetViewOfType("Raw");
            if (!snapshotView)
                snapshotView = state->view;
            saved = (!file_->IsModified() && !file_->IsAnalysisChanged()) ||
                snapshotView->SaveAutoSnapshot(progress);
        }
        if (!saved)
            throw std::runtime_error("Binary Ninja could not save the analysis database");
        if (createdDatabase && !temporaryCopy)
        {
            openedPath_ = savedPath;
            databaseBacked_ = true;
            snapshotApplied_ = true;
        }
        ipc::Reply reply;
        reply.set_success(true);
        auto* result = reply.mutable_binary_view_saved();
        result->set_path(savedPath.string());
        result->set_created_database(createdDatabase);
        return reply;
    }

    ipc::Reply FunctionList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("function-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        auto parseExpression = [&](const rapidjson::Value& value) {
            if (!value.IsString())
                throw std::invalid_argument("address expression must be a string");
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid address expression" : error);
            return result;
        };
        if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
            address = parseExpression(value->value);
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
            end = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
        {
            std::uint64_t length = 0;
            if (value->value.IsUint64())
                length = value->value.GetUint64();
            else
                length = parseExpression(value->value);
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("function range length is invalid");
            end = *start + length;
        }
        std::string query;
        if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
            query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));

        auto functions = state->view->GetAnalysisFunctionList();
        std::erase_if(functions, [&](const auto& function) {
            const auto functionAddress = function->GetStart();
            if (address && functionAddress != *address)
                return true;
            if (start && functionAddress < *start)
                return true;
            if (end && functionAddress >= *end)
                return true;
            if (!query.empty())
            {
                const auto symbol = function->GetSymbol();
                if (!symbol)
                    return true;
                return Lower(symbol->GetShortName()).find(query) == std::string::npos &&
                    Lower(symbol->GetFullName()).find(query) == std::string::npos &&
                    Lower(symbol->GetRawName()).find(query) == std::string::npos;
            }
            return false;
        });
        std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
            if (left->GetStart() != right->GetStart())
                return left->GetStart() < right->GetStart();
            const auto leftArch = left->GetArchitecture();
            const auto rightArch = right->GetArchitecture();
            const auto leftName = leftArch ? leftArch->GetName() : std::string{};
            const auto rightName = rightArch ? rightArch->GetName() : std::string{};
            if (leftName != rightName)
                return leftName < rightName;
            const auto leftSymbol = left->GetSymbol();
            const auto rightSymbol = right->GetSymbol();
            return (leftSymbol ? leftSymbol->GetRawName() : std::string{}) <
                (rightSymbol ? rightSymbol->GetRawName() : std::string{});
        });
        offset = std::min(offset, functions.size());
        const auto finish = offset + std::min(limit, functions.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("functions"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& function = functions[index];
            const auto symbol = function->GetSymbol();
            const auto platform = function->GetPlatform();
            const auto type = function->GetType();
            const auto addressText = HexAddress(function->GetStart());
            writer.StartObject();
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key("name");
            const auto name = symbol ? symbol->GetShortName() : addressText;
            writer.String(name.data(), name.size());
            writer.Key("type");
            const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
            writer.String(typeText.data(), typeText.size());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(functions.size());
        writer.Key("nextOffset");
        if (finish < functions.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < functions.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionInfo(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        const auto symbol = function->GetSymbol();
        const auto architecture = function->GetArchitecture();
        const auto platform = function->GetPlatform();
        const auto type = function->GetType();
        const auto callingConvention = function->GetCallingConvention().GetValue();
        const auto addressText = HexAddress(function->GetStart());
        const auto name = symbol ? symbol->GetShortName() : addressText;
        const auto architectureName = architecture ? architecture->GetName() : std::string{};
        const auto platformName = platform ? platform->GetName() : std::string{};
        const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
        const auto blocks = function->GetBasicBlocks();
        const auto ranges = function->GetAddressRanges();

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("name"); writer.String(name.data(), name.size());
        writer.Key("start"); writer.String(addressText.data(), addressText.size());
        writer.Key("lowestAddress");
        const auto lowestAddress = HexAddress(function->GetLowestAddress());
        writer.String(lowestAddress.data(), lowestAddress.size());
        writer.Key("highestAddress");
        const auto highestAddress = HexAddress(function->GetHighestAddress());
        writer.String(highestAddress.data(), highestAddress.size());
        writer.Key("architecture");
        writer.String(architectureName.data(), architectureName.size());
        writer.Key("platform"); writer.String(platformName.data(), platformName.size());
        writer.Key("type"); writer.String(typeText.data(), typeText.size());
        writer.Key("hasUserType"); writer.Bool(function->HasUserType());
        writer.Key("callingConvention");
        if (callingConvention)
        {
            const auto callingConventionName = callingConvention->GetName();
            writer.String(callingConventionName.data(), callingConventionName.size());
        }
        else
            writer.Null();
        writer.Key("exported"); writer.Bool(function->IsExported());
        writer.Key("autoDiscovered"); writer.Bool(function->WasAutomaticallyDiscovered());
        writer.Key("hasUserAnnotations"); writer.Bool(function->HasUserAnnotations());
        const bool needsUpdate = function->NeedsUpdate();
        writer.Key("needsUpdate"); writer.Bool(needsUpdate);
        if (needsUpdate)
        {
            writer.Key("nextAction");
            writer.String("Call bn_analysis_update_and_wait before readback or dependent variable mutations.");
        }
        writer.Key("analysisSkipped"); writer.Bool(function->IsAnalysisSkipped());
        writer.Key("analysisSkipReason");
        writer.String(AnalysisSkipReasonName(function->GetAnalysisSkipReason()));
        writer.Key("basicBlockCount"); writer.Uint64(blocks.size());
        writer.Key("ranges"); writer.StartArray();
        for (const auto& range : ranges)
        {
            const auto start = HexAddress(range.start);
            const auto end = HexAddress(range.end);
            writer.StartObject();
            writer.Key("start"); writer.String(start.data(), start.size());
            writer.Key("end"); writer.String(end.data(), end.size());
            writer.Key("length"); writer.Uint64(range.end - range.start);
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("basicBlocks"); writer.StartArray();
        for (std::size_t index = 0; index < blocks.size(); ++index)
        {
            const auto start = HexAddress(blocks[index]->GetStart());
            const auto end = HexAddress(blocks[index]->GetEnd());
            writer.StartObject();
            writer.Key("index"); writer.Uint64(index);
            writer.Key("start"); writer.String(start.data(), start.size());
            writer.Key("end"); writer.String(end.data(), end.size());
            writer.Key("length"); writer.Uint64(blocks[index]->GetEnd() - blocks[index]->GetStart());
            writer.Key("incoming"); writer.Uint64(blocks[index]->GetIncomingEdges().size());
            writer.Key("outgoing"); writer.Uint64(blocks[index]->GetOutgoingEdges().size());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionCallers(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto callers = state->view->GetCallers(function->GetStart());
        std::sort(callers.begin(), callers.end(), [](const auto& left, const auto& right) {
            if (left.addr != right.addr)
                return left.addr < right.addr;
            const auto leftStart = left.func ? left.func->GetStart() : 0;
            const auto rightStart = right.func ? right.func->GetStart() : 0;
            return leftStart < rightStart;
        });
        offset = std::min(offset, callers.size());
        const auto finish = offset + std::min(limit, callers.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("callers"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& caller = callers[index];
            const auto callerAddress = caller.func ? caller.func->GetStart() : caller.addr;
            const auto callerAddressText = HexAddress(callerAddress);
            const auto callsite = HexAddress(caller.addr);
            const auto symbol = caller.func ? caller.func->GetSymbol() : nullptr;
            const auto name = symbol ? symbol->GetShortName() : callerAddressText;
            writer.StartObject();
            writer.Key("callsite"); writer.String(callsite.data(), callsite.size());
            writer.Key("caller"); writer.StartObject();
            writer.Key("address");
            writer.String(callerAddressText.data(), callerAddressText.size());
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.EndObject(); writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(callers.size());
        writer.Key("nextOffset");
        if (finish < callers.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < callers.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionCallees(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        struct Callee
        {
            std::uint64_t callsite;
            std::uint64_t target;
        };
        std::vector<Callee> callees;
        for (const auto& callsite : function->GetCallSites())
        {
            for (const auto target : state->view->GetCallees(callsite))
                callees.push_back({callsite.addr, target});
        }
        std::sort(callees.begin(), callees.end(), [](const auto& left, const auto& right) {
            return std::tie(left.callsite, left.target) < std::tie(right.callsite, right.target);
        });
        offset = std::min(offset, callees.size());
        const auto finish = offset + std::min(limit, callees.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("callees"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto callsite = HexAddress(callees[index].callsite);
            const auto target = HexAddress(callees[index].target);
            writer.StartObject();
            writer.Key("callsite"); writer.String(callsite.data(), callsite.size());
            writer.Key("target"); writer.String(target.data(), target.size());
            writer.Key("functions"); writer.StartArray();
            for (const auto& targetFunction :
                state->view->GetAnalysisFunctionsForAddress(callees[index].target))
            {
                const auto functionAddress = HexAddress(targetFunction->GetStart());
                const auto symbol = targetFunction->GetSymbol();
                const auto name = symbol ? symbol->GetShortName() : functionAddress;
                writer.StartObject();
                writer.Key("address");
                writer.String(functionAddress.data(), functionAddress.size());
                writer.Key("name"); writer.String(name.data(), name.size());
                writer.EndObject();
            }
            writer.EndArray(); writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(callees.size());
        writer.Key("nextOffset");
        if (finish < callees.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < callees.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionDisassembly(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultRenderLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());

        const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
        settings->SetOption(ShowAddress, false);
        settings->SetOption(ShowOpcode, false);
        std::vector<std::string> lines;
        for (const auto& line : function->GetTypeTokens(settings))
            lines.push_back("  " + TokenText(line.tokens));
        if (!lines.empty())
            lines.emplace_back();
        auto blocks = function->GetBasicBlocks();
        std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) {
            return left->GetStart() < right->GetStart();
        });
        bool firstBlock = true;
        for (const auto& block : blocks)
        {
            if (!firstBlock)
                lines.emplace_back();
            firstBlock = false;
            for (const auto& line : block->GetDisassemblyText(settings))
                lines.push_back(HexAddress(line.addr) + "  " + TokenText(line.tokens));
        }
        while (!lines.empty() && lines.back().empty())
            lines.pop_back();
        offset = std::min(offset, lines.size());
        const auto finish = offset + std::min(limit, lines.size() - offset);
        std::string text;
        for (auto index = offset; index < finish; ++index)
        {
            if (index != offset)
                text += '\n';
            text += lines[index];
        }
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("text"); writer.String(text.data(), text.size());
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(lines.size());
        writer.Key("nextOffset");
        if (finish < lines.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < lines.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionDecompile(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        const auto languageArgument = arguments.FindMember("language");
        const bool explicitLanguage = languageArgument != arguments.MemberEnd();
        std::string languageName = "Pseudo C";
        std::string languageReason = "default";
        if (explicitLanguage)
        {
            const auto& value = languageArgument->value;
            languageName.assign(value.GetString(), value.GetStringLength());
            languageReason = "requested";
        }
        else if (const auto symbol = function->GetSymbol())
        {
            const auto preference = binary_ninja::PreferredLanguageForSymbol(
                symbol->GetShortName(), symbol->GetRawName());
            languageName = preference.name;
            languageReason = preference.reason;
        }
        std::size_t offset = 0;
        std::size_t limit = kDefaultRenderLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());

        const auto findRepresentation = [&](std::string requested,
                                            std::string& resolvedName) {
            auto result = function->GetLanguageRepresentation(requested);
            if (result)
            {
                resolvedName = std::move(requested);
                return result;
            }
            const auto normalized = NormalizedName(requested);
            for (const auto& type : BinaryNinja::LanguageRepresentationFunctionType::GetTypes())
            {
                if (!type || !type->IsValid(state->view) ||
                    NormalizedName(type->GetName()) != normalized)
                    continue;
                if (result)
                    throw std::invalid_argument(
                        "language representation name is ambiguous: " + requested);
                resolvedName = type->GetName();
                result = function->GetLanguageRepresentation(resolvedName);
            }
            return result;
        };
        std::string resolvedLanguage;
        auto representation = findRepresentation(languageName, resolvedLanguage);
        if (!representation && !explicitLanguage && languageName != "Pseudo C")
        {
            languageName = "Pseudo C";
            languageReason = "fallback";
            representation = findRepresentation(languageName, resolvedLanguage);
        }
        if (!representation)
        {
            bool analysisActive = false;
            {
                std::lock_guard lock(viewMutex_);
                analysisActive = state->analysisActive;
            }
            throw std::invalid_argument("language representation is unavailable: " + languageName +
                (analysisActive
                    ? "; analysis is running, so wait for its job to finish before retrying"
                    : "; use bn_function_il with level hlil as a fallback"));
        }
        languageName = std::move(resolvedLanguage);
        const auto highLevelIL = representation->GetHighLevelILFunction();
        if (!highLevelIL)
            throw std::runtime_error("high-level IL is unavailable for the function");
        const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
        settings->SetOption(ShowAddress, false);
        settings->SetOption(ShowOpcode, false);
        settings->SetOption(ShowTypeCasts, true);
        settings->SetOption(IndentHLILBody, true);
        std::vector<std::string> lines;
        for (const auto& line : function->GetTypeTokens(settings))
            lines.push_back("  " + TokenText(line.tokens));
        if (!lines.empty())
            lines.emplace_back();
        for (const auto& line :
            representation->GetLinearLines(highLevelIL->GetRootExpr(), settings))
            lines.push_back(TokenText(line.tokens));
        while (!lines.empty() && lines.back().empty())
            lines.pop_back();
        offset = std::min(offset, lines.size());
        const auto finish = offset + std::min(limit, lines.size() - offset);
        std::string text;
        for (auto index = offset; index < finish; ++index)
        {
            if (index != offset)
                text += '\n';
            text += lines[index];
        }
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("language"); writer.String(languageName.data(), languageName.size());
        if (!explicitLanguage)
        {
            writer.Key("languageSelection");
            writer.String(languageReason.data(), languageReason.size());
        }
        writer.Key("text"); writer.String(text.data(), text.size());
        writer.Key("needsUpdate"); writer.Bool(function->NeedsUpdate());
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(lines.size());
        writer.Key("nextOffset");
        if (finish < lines.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < lines.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionIL(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::string level = "hlil";
        if (const auto value = arguments.FindMember("level"); value != arguments.MemberEnd())
            level.assign(value->value.GetString(), value->value.GetStringLength());
        bool ssa = false;
        if (const auto value = arguments.FindMember("ssa"); value != arguments.MemberEnd())
            ssa = value->value.GetBool();
        std::size_t offset = 0;
        std::size_t limit = kDefaultRenderLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());

        std::vector<BinaryNinja::Ref<BinaryNinja::BasicBlock>> blocks;
        if (level == "llil")
        {
            auto il = function->GetLowLevelIL();
            if (!il)
                throw std::runtime_error("low-level IL is unavailable for the function");
            if (ssa)
                il = il->GetSSAForm();
            blocks = il->GetBasicBlocks();
        }
        else if (level == "mlil")
        {
            auto il = function->GetMediumLevelIL();
            if (!il)
                throw std::runtime_error("medium-level IL is unavailable for the function");
            if (ssa)
                il = il->GetSSAForm();
            blocks = il->GetBasicBlocks();
        }
        else if (level == "hlil")
        {
            auto il = function->GetHighLevelIL();
            if (!il)
                throw std::runtime_error("high-level IL is unavailable for the function");
            if (ssa)
                il = il->GetSSAForm();
            blocks = il->GetBasicBlocks();
        }
        else
            throw std::invalid_argument("level must be llil, mlil, or hlil");

        const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
        settings->SetOption(ShowAddress, false);
        settings->SetOption(ShowOpcode, false);
        settings->SetOption(ShowTypeCasts, true);
        std::vector<std::string> lines;
        for (const auto& line : function->GetTypeTokens(settings))
            lines.push_back("  " + TokenText(line.tokens));
        if (!lines.empty())
            lines.emplace_back();
        std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) {
            return left->GetStart() < right->GetStart();
        });
        bool firstBlock = true;
        for (const auto& block : blocks)
        {
            if (!firstBlock)
                lines.emplace_back();
            firstBlock = false;
            for (const auto& line : block->GetDisassemblyText(settings))
                lines.push_back(HexAddress(line.addr) + "  " + TokenText(line.tokens));
        }
        while (!lines.empty() && lines.back().empty())
            lines.pop_back();
        offset = std::min(offset, lines.size());
        const auto finish = offset + std::min(limit, lines.size() - offset);
        std::string text;
        for (auto index = offset; index < finish; ++index)
        {
            if (index != offset)
                text += '\n';
            text += lines[index];
        }
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("level"); writer.String(level.data(), level.size());
        writer.Key("ssa"); writer.Bool(ssa);
        writer.Key("text"); writer.String(text.data(), text.size());
        writer.Key("needsUpdate"); writer.Bool(function->NeedsUpdate());
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(lines.size());
        writer.Key("nextOffset");
        if (finish < lines.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < lines.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionStackLayout(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        struct StackVariable
        {
            std::int64_t frameOffset;
            BinaryNinja::VariableNameAndType variable;
        };
        std::vector<StackVariable> variables;
        for (const auto& [frameOffset, entries] : function->GetStackLayout())
        {
            for (const auto& entry : entries)
                variables.push_back({frameOffset, entry});
        }
        offset = std::min(offset, variables.size());
        const auto finish = offset + std::min(limit, variables.size() - offset);
        const auto platform = function->GetPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("variables"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& entry = variables[index];
            const auto type = entry.variable.type.GetValue();
            const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
            writer.StartObject();
            writer.Key("offset"); writer.Int64(entry.frameOffset);
            writer.Key("name");
            writer.String(entry.variable.name.data(), entry.variable.name.size());
            writer.Key("type"); writer.String(typeText.data(), typeText.size());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(variables.size());
        writer.Key("nextOffset");
        if (finish < variables.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < variables.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply VariableList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        const auto variableMap = function->GetVariables();
        std::vector<BinaryNinja::VariableNameAndType> variables;
        variables.reserve(variableMap.size());
        for (const auto& entry : variableMap)
            variables.push_back(entry.second);
        offset = std::min(offset, variables.size());
        const auto finish = offset + std::min(limit, variables.size() - offset);
        const auto platform = function->GetPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("variables"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& entry = variables[index];
            const auto type = entry.type.GetValue();
            const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
            writer.StartObject();
            writer.Key("name"); writer.String(entry.name.data(), entry.name.size());
            writer.Key("type"); writer.String(typeText.data(), typeText.size());
            writer.Key("source"); writer.String(VariableSourceName(entry.var.type));
            writer.Key("index"); writer.Uint(entry.var.index);
            writer.Key("storage"); writer.Int64(entry.var.storage);
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(variables.size());
        writer.Key("nextOffset");
        if (finish < variables.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < variables.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply CallingConventionList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        const auto platform = function->GetPlatform();
        if (!platform)
            throw std::runtime_error("function has no platform");
        const auto current = function->GetCallingConvention().GetValue();
        std::vector<std::string> names;
        for (const auto& convention : platform->GetCallingConventions())
        {
            if (convention)
                names.push_back(convention->GetName());
        }
        std::sort(names.begin(), names.end());
        names.erase(std::unique(names.begin(), names.end()), names.end());
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("current");
        if (current)
        {
            const auto currentName = current->GetName();
            writer.String(currentName.data(), currentName.size());
        }
        else
            writer.Null();
        writer.Key("callingConventions"); writer.StartArray();
        for (const auto& name : names)
            writer.String(name.data(), name.size());
        writer.EndArray(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionXrefsFrom(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        struct Reference
        {
            std::uint64_t source;
            std::uint64_t target;
        };
        std::vector<Reference> references;
        for (const auto& block : function->GetBasicBlocks())
        {
            const auto architecture = block->GetArchitecture();
            if (!architecture)
                continue;
            for (auto source = block->GetStart(); source < block->GetEnd();)
            {
                BinaryNinja::ReferenceSource referenceSource;
                referenceSource.func = function;
                referenceSource.arch = architecture;
                referenceSource.addr = source;
                for (const auto target : state->view->GetCodeReferencesFrom(referenceSource))
                    references.push_back({source, target});
                const auto length = state->view->GetInstructionLength(architecture, source);
                if (length == 0 || length > block->GetEnd() - source)
                    break;
                source += length;
            }
        }
        std::sort(references.begin(), references.end(), [](const auto& left, const auto& right) {
            return std::tie(left.source, left.target) < std::tie(right.source, right.target);
        });
        references.erase(std::unique(references.begin(), references.end(),
            [](const auto& left, const auto& right) {
                return left.source == right.source && left.target == right.target;
            }), references.end());
        offset = std::min(offset, references.size());
        const auto finish = offset + std::min(limit, references.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("references"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto source = HexAddress(references[index].source);
            const auto target = HexAddress(references[index].target);
            writer.StartObject();
            writer.Key("source"); writer.String(source.data(), source.size());
            writer.Key("target"); writer.String(target.data(), target.size());
            writer.Key("functions"); writer.StartArray();
            for (const auto& targetFunction :
                state->view->GetAnalysisFunctionsContainingAddress(references[index].target))
            {
                const auto functionAddress = HexAddress(targetFunction->GetStart());
                const auto symbol = targetFunction->GetSymbol();
                const auto name = symbol ? symbol->GetShortName() : functionAddress;
                writer.StartObject();
                writer.Key("address");
                writer.String(functionAddress.data(), functionAddress.size());
                writer.Key("name"); writer.String(name.data(), name.size());
                writer.EndObject();
            }
            writer.EndArray(); writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(references.size());
        writer.Key("nextOffset");
        if (finish < references.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < references.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionXrefsTo(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        const auto function = ResolveFunction(state, arguments);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        std::vector<BinaryNinja::ReferenceSource> references;
        for (const auto& range : function->GetAddressRanges())
        {
            auto rangeReferences = state->view->GetCodeReferences(range.start, range.end - range.start);
            references.insert(references.end(), rangeReferences.begin(), rangeReferences.end());
        }
        std::sort(references.begin(), references.end(), [](const auto& left, const auto& right) {
            if (left.addr != right.addr)
                return left.addr < right.addr;
            const auto leftStart = left.func ? left.func->GetStart() : 0;
            const auto rightStart = right.func ? right.func->GetStart() : 0;
            return leftStart < rightStart;
        });
        references.erase(std::unique(references.begin(), references.end(),
            [](const auto& left, const auto& right) {
                const auto leftStart = left.func ? left.func->GetStart() : 0;
                const auto rightStart = right.func ? right.func->GetStart() : 0;
                return left.addr == right.addr && leftStart == rightStart;
            }), references.end());
        offset = std::min(offset, references.size());
        const auto finish = offset + std::min(limit, references.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("references"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& reference = references[index];
            const auto source = HexAddress(reference.addr);
            writer.StartObject();
            writer.Key("source"); writer.String(source.data(), source.size());
            writer.Key("function");
            if (reference.func)
            {
                const auto functionAddress = HexAddress(reference.func->GetStart());
                const auto symbol = reference.func->GetSymbol();
                const auto name = symbol ? symbol->GetShortName() : functionAddress;
                writer.StartObject();
                writer.Key("address");
                writer.String(functionAddress.data(), functionAddress.size());
                writer.Key("name"); writer.String(name.data(), name.size());
                writer.EndObject();
            }
            else
                writer.Null();
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(references.size());
        writer.Key("nextOffset");
        if (finish < references.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < references.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply StringList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        const bool sharedCacheView = state->view->GetTypeName() == "DSCView";
        {
            std::lock_guard lock(viewMutex_);
            if (state->analysisActive && sharedCacheView)
            {
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                writer.StartObject();
                writer.Key("available"); writer.Bool(false);
                writer.Key("state"); writer.String("analysis_running");
                writer.Key("retryAfterMilliseconds"); writer.Uint(10000);
                writer.Key("nextAction");
                writer.String("Wait for SharedCache analysis to finish before listing strings. If analysis_update_and_wait returned a job, poll bn_job_info no more than every 10 seconds and call bn_job_result when terminal.");
                writer.EndObject();
                ipc::Reply reply;
                reply.set_success(true);
                reply.mutable_analysis_tool_result()->set_json(
                    buffer.GetString(), buffer.GetSize());
                return reply;
            }
        }
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("string-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid address expression" : error);
            return result;
        };
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
            address = parseExpression(value->value);
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
            end = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
        {
            std::uint64_t length = value->value.IsUint64()
                ? value->value.GetUint64() : parseExpression(value->value);
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("string range length is invalid");
            end = *start + length;
        }
        std::string query;
        if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
            query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));

        auto strings = state->view->GetStrings();
        std::erase_if(strings, [&](const auto& string) {
            if (address && string.start != *address)
                return true;
            if (start && string.start < *start)
                return true;
            if (end && string.start >= *end)
                return true;
            if (!query.empty())
            {
                const auto detected = ReadDetectedString(
                    state->view, string.type, string.start, string.length);
                const auto preview = DecodeString(detected.type,
                    detected.bytes,
                    std::numeric_limits<std::size_t>::max());
                return Lower(preview.text).find(query) == std::string::npos;
            }
            return false;
        });
        std::sort(strings.begin(), strings.end(), [](const auto& left, const auto& right) {
            if (left.start != right.start)
                return left.start < right.start;
            return left.type < right.type;
        });
        offset = std::min(offset, strings.size());
        const auto finish = offset + std::min(limit, strings.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("strings"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& string = strings[index];
            const auto detected = ReadDetectedString(
                state->view, string.type, string.start, string.length);
            const auto preview = DecodeString(detected.type, detected.bytes);
            const auto addressText = HexAddress(string.start);
            writer.StartObject();
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key(preview.decoded ? "value" : "bytes");
            writer.String(preview.text.data(), preview.text.size());
            if (preview.truncated)
            {
                writer.Key("length"); writer.Uint64(preview.length);
                writer.Key("truncated"); writer.Bool(true);
            }
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(strings.size());
        writer.Key("nextOffset");
        if (finish < strings.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < strings.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply StringAt(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("string address must be a string");
        const auto& addressValue = arguments["address"];
        std::uint64_t address = 0;
        std::string parseError;
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid string address" : parseError);
        BNStringReference reference{};
        const bool detectedByAnalysis = state->view->GetStringAtAddress(address, reference);
        std::size_t offset = 0;
        std::size_t limit = 4096;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto detected = detectedByAnalysis
            ? std::optional<DetectedStringData>(ReadDetectedString(
                  state->view, reference.type, reference.start, reference.length))
            : ReadNullTerminatedString(state->view, address);
        if (!detected)
            throw std::invalid_argument(
                "string not found and no valid NUL-terminated UTF-8 string exists at address");
        const std::span<const std::uint8_t> bytes(detected->bytes);
        const auto decoded = DecodeString(detected->type, bytes,
            std::numeric_limits<std::size_t>::max());
        const auto chunk = SliceString(decoded, bytes, offset, limit);
        const auto addressText = HexAddress(detectedByAnalysis ? reference.start : address);
        const auto encoding = StringEncodingName(detected->type);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("encoding");
        if (encoding) writer.String(encoding); else writer.Null();
        writer.Key("byteLength"); writer.Uint64(detected->bytes.size());
        writer.Key("characterLength");
        if (decoded.decoded) writer.Uint64(chunk.total); else writer.Null();
        writer.Key(decoded.decoded ? "value" : "bytes");
        writer.String(chunk.text.data(), chunk.text.size());
        writer.Key("offset"); writer.Uint64(chunk.offset);
        writer.Key("count"); writer.Uint64(chunk.count);
        writer.Key("nextOffset");
        if (chunk.nextOffset) writer.Uint64(*chunk.nextOffset); else writer.Null();
        writer.Key("truncated"); writer.Bool(chunk.truncated);
        if (!detectedByAnalysis)
        {
            writer.Key("inferred"); writer.Bool(true);
        }
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SymbolList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("symbol-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid address expression" : error);
            return result;
        };
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
            address = parseExpression(value->value);
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
            end = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
        {
            std::uint64_t length = value->value.IsUint64()
                ? value->value.GetUint64() : parseExpression(value->value);
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("symbol range length is invalid");
            end = *start + length;
        }
        std::string query;
        if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
            query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));
        auto symbols = state->view->GetSymbols();
        std::erase_if(symbols, [&](const auto& symbol) {
            if (command.name() == "bn_import_list" &&
                symbol->GetType() != ImportAddressSymbol &&
                symbol->GetType() != ImportedFunctionSymbol &&
                symbol->GetType() != ImportedDataSymbol)
                return true;
            if (command.name() == "bn_export_list")
            {
                const bool exportedType = symbol->GetType() == FunctionSymbol ||
                    symbol->GetType() == DataSymbol;
                const bool exportedBinding = symbol->GetBinding() == GlobalBinding ||
                    symbol->GetBinding() == WeakBinding;
                if (!exportedType || !exportedBinding)
                    return true;
            }
            if (address && symbol->GetAddress() != *address)
                return true;
            if (start && symbol->GetAddress() < *start)
                return true;
            if (end && symbol->GetAddress() >= *end)
                return true;
            return !query.empty() &&
                Lower(symbol->GetShortName()).find(query) == std::string::npos &&
                Lower(symbol->GetFullName()).find(query) == std::string::npos &&
                Lower(symbol->GetRawName()).find(query) == std::string::npos;
        });
        std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
            if (left->GetAddress() != right->GetAddress())
                return left->GetAddress() < right->GetAddress();
            if (left->GetType() != right->GetType())
                return left->GetType() < right->GetType();
            return left->GetFullName() < right->GetFullName();
        });
        offset = std::min(offset, symbols.size());
        const auto finish = offset + std::min(limit, symbols.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("symbols"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& symbol = symbols[index];
            const auto addressText = HexAddress(symbol->GetAddress());
            const auto name = symbol->GetFullName();
            writer.StartObject();
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("type"); writer.String(SymbolTypeName(symbol->GetType()));
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(symbols.size());
        writer.Key("nextOffset");
        if (finish < symbols.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < symbols.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SymbolListAt(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("symbol address must be a string");
        const auto& addressValue = arguments["address"];
        std::uint64_t address = 0;
        std::string parseError;
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid symbol address" : parseError);
        auto symbols = state->view->GetSymbols(address, 1);
        std::erase_if(symbols, [&](const auto& symbol) {
            return symbol->GetAddress() != address;
        });
        std::sort(symbols.begin(), symbols.end(), [](const auto& left, const auto& right) {
            if (left->GetType() != right->GetType())
                return left->GetType() < right->GetType();
            return left->GetFullName() < right->GetFullName();
        });
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("symbols"); writer.StartArray();
        for (const auto& symbol : symbols)
        {
            const auto addressText = HexAddress(symbol->GetAddress());
            const auto shortName = symbol->GetShortName();
            const auto fullName = symbol->GetFullName();
            const auto rawName = symbol->GetRawName();
            const auto nameSpace = symbol->GetNameSpace();
            writer.StartObject();
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key("type"); writer.String(SymbolTypeName(symbol->GetType()));
            writer.Key("shortName"); writer.String(shortName.data(), shortName.size());
            writer.Key("fullName"); writer.String(fullName.data(), fullName.size());
            writer.Key("rawName"); writer.String(rawName.data(), rawName.size());
            writer.Key("namespace"); writer.StartArray();
            for (const auto& component : nameSpace)
                writer.String(component.data(), component.size());
            writer.EndArray();
            writer.Key("ordinal"); writer.Uint64(symbol->GetOrdinal());
            writer.Key("binding"); writer.String(SymbolBindingName(symbol->GetBinding()));
            writer.Key("autoDefined"); writer.Bool(symbol->IsAutoDefined());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(symbols.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply EntryPointList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("entry-point arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto functions = state->view->GetAllEntryFunctions();
        std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
            return left->GetStart() < right->GetStart();
        });
        offset = std::min(offset, functions.size());
        const auto finish = offset + std::min(limit, functions.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("entryPoints"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& function = functions[index];
            const auto address = HexAddress(function->GetStart());
            const auto symbol = function->GetSymbol();
            const auto name = symbol ? symbol->GetShortName() : address;
            writer.StartObject();
            writer.Key("address"); writer.String(address.data(), address.size());
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(functions.size());
        writer.Key("nextOffset");
        if (finish < functions.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < functions.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply EntryPointAdd(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("entry-point address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& value = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid entry-point address" : parseError);
        if (!state->view->IsValidOffset(address))
            throw std::invalid_argument("entry-point address is not mapped");
        const auto platform = state->view->GetDefaultPlatform();
        if (!platform)
            throw std::runtime_error("BinaryView has no default platform. For raw firmware, close the open item, reopen it, select the Mapped candidate, inspect bn_binary_view_load_settings, and set loader.platform before materialization");
        const auto entries = state->view->GetAllEntryFunctions();
        const bool existing = std::any_of(entries.begin(), entries.end(),
            [&](const auto& function) { return function->GetStart() == address; });
        if (!existing)
            state->view->AddEntryPointForAnalysis(platform.GetPtr(), address);
        const auto functions = state->view->GetAnalysisFunctionList();
        const bool functionPresent = std::any_of(functions.begin(), functions.end(),
            [&](const auto& function) { return function->GetStart() == address; });
        const auto addressText = HexAddress(address);
        const auto platformName = platform->GetName();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("platform"); writer.String(platformName.data(), platformName.size());
        writer.Key("added"); writer.Bool(!existing);
        writer.Key("functionPresent"); writer.Bool(functionPresent);
        writer.Key("nextAction");
        writer.String(functionPresent
            ? "Call bn_analysis_update_and_wait, then bn_binary_view_save to persist changes."
            : "Call bn_function_create at this address, then bn_analysis_update_and_wait and bn_binary_view_save.");
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionCreate(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("function address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& value = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid function address" : parseError);
        if (!state->view->IsValidOffset(address))
            throw std::invalid_argument("function address is not mapped");
        const auto platform = state->view->GetDefaultPlatform();
        if (!platform)
            throw std::runtime_error("BinaryView has no default platform. For raw firmware, close the open item, reopen it, select the Mapped candidate, inspect bn_binary_view_load_settings, and set loader.platform before materialization");
        auto functions = state->view->GetAnalysisFunctionList();
        auto existing = std::find_if(functions.begin(), functions.end(),
            [&](const auto& function) {
                return function->GetStart() == address &&
                    function->GetPlatform().GetPtr() == platform.GetPtr();
            });
        const auto tracked = state->userFunctions.find(address);
        const bool created = existing == functions.end() && tracked == state->userFunctions.end();
        BinaryNinja::Ref<BinaryNinja::Function> function;
        if (existing != functions.end())
            function = *existing;
        else if (tracked != state->userFunctions.end())
            function = tracked->second;
        else
        {
            function = state->view->CreateUserFunction(platform.GetPtr(), address);
            if (function)
                state->userFunctions.emplace(address, function);
        }
        if (!function)
            throw std::runtime_error("Binary Ninja could not create the user function");
        const auto symbol = function->GetSymbol();
        const auto architecture = function->GetArchitecture();
        const auto type = function->GetType();
        const auto addressText = HexAddress(function->GetStart());
        const auto name = symbol ? symbol->GetShortName() : addressText;
        const auto architectureName = architecture ? architecture->GetName() : std::string{};
        const auto platformName = platform->GetName();
        const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("name"); writer.String(name.data(), name.size());
        writer.Key("architecture");
        writer.String(architectureName.data(), architectureName.size());
        writer.Key("platform"); writer.String(platformName.data(), platformName.size());
        writer.Key("type"); writer.String(typeText.data(), typeText.size());
        writer.Key("created"); writer.Bool(created);
        writer.Key("autoDiscovered"); writer.Bool(function->WasAutomaticallyDiscovered());
        writer.Key("needsUpdate"); writer.Bool(function->NeedsUpdate());
        writer.Key("nextAction");
        writer.String("Call bn_analysis_update_and_wait, then bn_binary_view_save to persist the user function.");
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SectionList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("section-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto sections = state->view->GetSections();
        std::sort(sections.begin(), sections.end(), [](const auto& left, const auto& right) {
            if (left->GetStart() != right->GetStart())
                return left->GetStart() < right->GetStart();
            return left->GetName() < right->GetName();
        });
        offset = std::min(offset, sections.size());
        const auto finish = offset + std::min(limit, sections.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("sections"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& section = sections[index];
            const auto name = section->GetName();
            const auto start = HexAddress(section->GetStart());
            const auto end = HexAddress(section->GetEnd());
            writer.StartObject();
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("start"); writer.String(start.data(), start.size());
            writer.Key("end"); writer.String(end.data(), end.size());
            writer.Key("semantics"); writer.String(SectionSemanticsName(section->GetSemantics()));
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(sections.size());
        writer.Key("nextOffset");
        if (finish < sections.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < sections.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SegmentList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("segment-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto segments = state->view->GetSegments();
        std::sort(segments.begin(), segments.end(), [](const auto& left, const auto& right) {
            return left->GetStart() < right->GetStart();
        });
        offset = std::min(offset, segments.size());
        const auto finish = offset + std::min(limit, segments.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("segments"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& segment = segments[index];
            const auto flags = segment->GetFlags();
            const auto start = HexAddress(segment->GetStart());
            const auto end = HexAddress(segment->GetEnd());
            const auto dataOffset = HexAddress(segment->GetDataOffset());
            const auto dataEnd = HexAddress(segment->GetDataEnd());
            writer.StartObject();
            writer.Key("segment"); writer.String(start.data(), start.size());
            writer.Key("start"); writer.String(start.data(), start.size());
            writer.Key("end"); writer.String(end.data(), end.size());
            writer.Key("length"); writer.Uint64(segment->GetLength());
            writer.Key("dataOffset"); writer.String(dataOffset.data(), dataOffset.size());
            writer.Key("dataLength"); writer.Uint64(segment->GetDataLength());
            writer.Key("dataEnd"); writer.String(dataEnd.data(), dataEnd.size());
            writer.Key("flags"); writer.StartArray();
            for (const auto& [flag, name] : {
                    std::pair{SegmentReadable, "SegmentReadable"},
                    std::pair{SegmentWritable, "SegmentWritable"},
                    std::pair{SegmentExecutable, "SegmentExecutable"},
                    std::pair{SegmentContainsData, "SegmentContainsData"},
                    std::pair{SegmentContainsCode, "SegmentContainsCode"},
                    std::pair{SegmentDenyWrite, "SegmentDenyWrite"},
                    std::pair{SegmentDenyExecute, "SegmentDenyExecute"}})
            {
                if ((flags & flag) != 0)
                    writer.String(name);
            }
            writer.EndArray();
            writer.Key("readable"); writer.Bool((flags & SegmentReadable) != 0);
            writer.Key("writable"); writer.Bool((flags & SegmentWritable) != 0);
            writer.Key("executable"); writer.Bool((flags & SegmentExecutable) != 0);
            writer.Key("containsData"); writer.Bool((flags & SegmentContainsData) != 0);
            writer.Key("containsCode"); writer.Bool((flags & SegmentContainsCode) != 0);
            writer.Key("denyWrite"); writer.Bool((flags & SegmentDenyWrite) != 0);
            writer.Key("denyExecute"); writer.Bool((flags & SegmentDenyExecute) != 0);
            writer.Key("autoDefined"); writer.Bool(segment->IsAutoDefined());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(segments.size());
        writer.Key("nextOffset");
        if (finish < segments.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < segments.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply MemoryRead(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString() || !arguments.HasMember("length"))
            throw std::invalid_argument("memory address and length are required");
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid memory expression" : error);
            return result;
        };
        const auto address = parseExpression(arguments["address"]);
        const auto& lengthValue = arguments["length"];
        if (!lengthValue.IsUint64() && !lengthValue.IsString())
            throw std::invalid_argument("memory length must be an integer or expression");
        const auto length = lengthValue.IsUint64()
            ? lengthValue.GetUint64() : parseExpression(lengthValue);
        if (length > 65536)
            throw std::invalid_argument("memory read length exceeds 65536 bytes");
        const auto data = state->view->ReadBuffer(address, static_cast<std::size_t>(length));
        const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
        const auto hex = HexBytes({bytes, data.GetLength()});
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("bytesRead"); writer.Uint64(data.GetLength());
        writer.Key("hex"); writer.String(hex.data(), hex.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply DataVariableList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("data-variable arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid address expression" : error);
            return result;
        };
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
            address = parseExpression(value->value);
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
            end = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
        {
            const auto length = value->value.IsUint64()
                ? value->value.GetUint64() : parseExpression(value->value);
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("data-variable range length is invalid");
            end = *start + length;
        }
        std::vector<BinaryNinja::DataVariable> variables;
        for (const auto& [variableAddress, variable] : state->view->GetDataVariables())
        {
            if (address && variableAddress != *address)
                continue;
            if (start && variableAddress < *start)
                continue;
            if (end && variableAddress >= *end)
                continue;
            variables.push_back(variable);
        }
        offset = std::min(offset, variables.size());
        const auto finish = offset + std::min(limit, variables.size() - offset);
        const auto platform = state->view->GetDefaultPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("dataVariables"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& variable = variables[index];
            const auto type = variable.type.GetValue();
            const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
            const auto addressText = HexAddress(variable.address);
            writer.StartObject();
            writer.Key("address"); writer.String(addressText.data(), addressText.size());
            writer.Key("type"); writer.String(typeText.data(), typeText.size());
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(variables.size());
        writer.Key("nextOffset");
        if (finish < variables.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < variables.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply DataAt(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("data address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty() ? "invalid data address" : parseError);

        BinaryNinja::DataVariable dataVariable;
        bool hasDataVariable = state->view->GetDataVariableAtAddress(address, dataVariable);
        bool exactDataVariable = hasDataVariable;
        if (!hasDataVariable)
        {
            const auto variables = state->view->GetDataVariables();
            auto candidate = variables.upper_bound(address);
            if (candidate != variables.begin())
            {
                --candidate;
                const auto type = candidate->second.type.GetValue();
                if (type && address - candidate->first < type->GetWidth())
                {
                    dataVariable = candidate->second;
                    hasDataVariable = true;
                }
            }
        }
        std::string formatted;
        if (hasDataVariable)
        {
            const auto type = dataVariable.type.GetValue();
            if (type)
            {
                std::vector<BinaryNinja::InstructionTextToken> prefix;
                std::vector<std::pair<BinaryNinja::Type*, std::size_t>> context;
                const auto lines = BinaryNinja::DataRendererContainer::RenderLinesForData(
                    state->view, dataVariable.address, type, prefix, 80, context);
                for (std::size_t index = 0; index < lines.size(); ++index)
                {
                    if (index != 0)
                        formatted += '\n';
                    formatted += TokenText(lines[index].tokens);
                }
            }
        }
        const auto data = state->view->ReadBuffer(address, 32);
        const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
        const auto hex = HexBytes({bytes, data.GetLength()});
        const auto addressText = HexAddress(address);
        const auto platform = state->view->GetDefaultPlatform();
        const auto symbols = state->view->GetSymbols(address, 1);
        const auto functions = state->view->GetAnalysisFunctionsContainingAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("dataVariable");
        if (hasDataVariable)
        {
            const auto type = dataVariable.type.GetValue();
            const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
            writer.StartObject();
            writer.Key("type"); writer.String(typeText.data(), typeText.size());
            writer.Key("formatted"); writer.String(formatted.data(), formatted.size());
            writer.Key("confidence"); writer.Uint(dataVariable.type.GetConfidence());
            writer.Key("autoDiscovered"); writer.Bool(dataVariable.autoDiscovered);
            writer.EndObject();
        }
        else
            writer.Null();
        writer.Key("exactDataVariable"); writer.Bool(exactDataVariable);
        writer.Key("memory"); writer.StartObject();
        writer.Key("bytesRead"); writer.Uint64(data.GetLength());
        writer.Key("hex"); writer.String(hex.data(), hex.size());
        writer.EndObject();
        const auto comment = state->view->GetCommentForAddress(address);
        writer.Key("comment"); writer.String(comment.data(), comment.size());
        writer.Key("symbols"); writer.StartArray();
        for (const auto& symbol : symbols)
        {
            if (symbol->GetAddress() != address)
                continue;
            const auto name = symbol->GetFullName();
            writer.StartObject();
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("type"); writer.String(SymbolTypeName(symbol->GetType()));
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("functions"); writer.StartArray();
        for (const auto& function : functions)
        {
            const auto functionAddress = HexAddress(function->GetStart());
            const auto symbol = function->GetSymbol();
            const auto name = symbol ? symbol->GetShortName() : functionAddress;
            writer.StartObject();
            writer.Key("address"); writer.String(functionAddress.data(), functionAddress.size());
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.EndObject();
        }
        writer.EndArray(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply RelocationList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("relocation arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid address expression" : error);
            return result;
        };
        std::optional<std::uint64_t> address;
        std::optional<std::uint64_t> start;
        std::optional<std::uint64_t> end;
        if (const auto value = arguments.FindMember("address"); value != arguments.MemberEnd())
            address = parseExpression(value->value);
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("end"); value != arguments.MemberEnd())
            end = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
        {
            const auto length = value->value.IsUint64()
                ? value->value.GetUint64() : parseExpression(value->value);
            if (!start || length > std::numeric_limits<std::uint64_t>::max() - *start)
                throw std::invalid_argument("relocation range length is invalid");
            end = *start + length;
        }
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        if (address)
            ranges = state->view->GetRelocationRangesAtAddress(*address);
        else if (start && end)
            ranges = state->view->GetRelocationRangesInRange(
                *start, static_cast<std::size_t>(*end - *start));
        else
            ranges = state->view->GetRelocationRanges();
        std::vector<BinaryNinja::Ref<BinaryNinja::Relocation>> relocations;
        for (const auto& [rangeStart, rangeEnd] : ranges)
        {
            // This API revision's C++ range wrapper leaves zero-initialized entries in front.
            if (rangeEnd <= rangeStart)
                continue;
            for (const auto& relocation : state->view->GetRelocationsAt(rangeStart))
            {
                if (address && relocation->GetAddress() != *address)
                    continue;
                if (start && relocation->GetAddress() < *start)
                    continue;
                if (end && relocation->GetAddress() >= *end)
                    continue;
                relocations.push_back(relocation);
            }
        }
        std::sort(relocations.begin(), relocations.end(), [](const auto& left, const auto& right) {
            if (left->GetAddress() != right->GetAddress())
                return left->GetAddress() < right->GetAddress();
            return left->GetTarget() < right->GetTarget();
        });
        relocations.erase(std::unique(relocations.begin(), relocations.end(),
            [](const auto& left, const auto& right) {
                return left->GetAddress() == right->GetAddress() &&
                    left->GetTarget() == right->GetTarget();
            }), relocations.end());
        offset = std::min(offset, relocations.size());
        const auto finish = offset + std::min(limit, relocations.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("relocations"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto& relocation = relocations[index];
            const auto info = relocation->GetInfo();
            const auto relocationAddress = HexAddress(relocation->GetAddress());
            const auto target = HexAddress(relocation->GetTarget());
            const auto architecture = relocation->GetArchitecture();
            const auto architectureName = architecture ? architecture->GetName() : std::string{};
            const auto symbol = relocation->GetSymbol();
            writer.StartObject();
            writer.Key("address"); writer.String(relocationAddress.data(), relocationAddress.size());
            writer.Key("target"); writer.String(target.data(), target.size());
            writer.Key("architecture");
            writer.String(architectureName.data(), architectureName.size());
            writer.Key("symbol");
            if (symbol)
            {
                const auto symbolAddress = HexAddress(symbol->GetAddress());
                writer.String(symbolAddress.data(), symbolAddress.size());
            }
            else writer.Null();
            writer.Key("symbolName");
            if (symbol)
            {
                const auto symbolName = symbol->GetFullName();
                writer.String(symbolName.data(), symbolName.size());
            }
            else writer.Null();
            writer.Key("type"); writer.Uint(info.type);
            writer.Key("nativeType"); writer.Uint64(info.nativeType);
            writer.Key("external"); writer.Bool(info.external);
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(relocations.size());
        writer.Key("nextOffset");
        if (finish < relocations.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < relocations.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply DataXrefsFrom(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("data reference address must be a string");
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty()
                    ? "invalid data reference expression" : error);
            return result;
        };
        const auto address = parseExpression(arguments["address"]);
        std::optional<std::uint64_t> length;
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
            length = value->value.IsUint64()
                ? value->value.GetUint64() : parseExpression(value->value);
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        const bool incoming = command.name() == "bn_data_xrefs_to";
        auto references = incoming
            ? (length ? state->view->GetDataReferences(address, *length)
                      : state->view->GetDataReferences(address))
            : (length ? state->view->GetDataReferencesFrom(address, *length)
                      : state->view->GetDataReferencesFrom(address));
        std::sort(references.begin(), references.end());
        references.erase(std::unique(references.begin(), references.end()), references.end());
        offset = std::min(offset, references.size());
        const auto finish = offset + std::min(limit, references.size() - offset);
        const auto platform = state->view->GetDefaultPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("references"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            const auto reference = HexAddress(references[index]);
            BinaryNinja::DataVariable variable;
            writer.StartObject();
            writer.Key(incoming ? "source" : "target");
            writer.String(reference.data(), reference.size());
            writer.Key("dataVariable");
            if (state->view->GetDataVariableAtAddress(references[index], variable))
            {
                const auto type = variable.type.GetValue();
                const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
                writer.StartObject();
                writer.Key("address"); writer.String(reference.data(), reference.size());
                writer.Key("type"); writer.String(typeText.data(), typeText.size());
                writer.EndObject();
            }
            else writer.Null();
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(references.size());
        writer.Key("nextOffset");
        if (finish < references.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < references.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SearchTool(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("search arguments must be an object");
        std::size_t offset = 0, limit = 50;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        bool caseSensitive = false;
        if (const auto value = arguments.FindMember("caseSensitive"); value != arguments.MemberEnd())
            caseSensitive = value->value.GetBool();
        auto stringArgument = [&](const char* name, bool required = true) {
            const auto value = arguments.FindMember(name);
            if (value == arguments.MemberEnd())
            {
                if (required) throw std::invalid_argument(std::string(name) + " is required");
                return std::string{};
            }
            if (!value->value.IsString())
                throw std::invalid_argument(std::string(name) + " must be a string");
            return std::string(value->value.GetString(), value->value.GetStringLength());
        };
        auto parseAddress = [&](const char* name, std::uint64_t fallback) {
            const auto value = arguments.FindMember(name);
            if (value == arguments.MemberEnd()) return fallback;
            std::uint64_t result = 0; std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value->value.GetString(), value->value.GetStringLength()),
                    result, 0, error))
                throw std::invalid_argument(error.empty() ? "invalid address expression" : error);
            return result;
        };
        const auto start = parseAddress("start", state->view->GetStart());
        const auto end = parseAddress("end", state->view->GetEnd());
        if (end < start) throw std::invalid_argument("end must not precede start");
        struct Match { std::uint64_t address; std::string kind; std::string text; std::string function; };
        std::vector<Match> matches;
        const auto name = command.name();
        if (name == "bn_comment_list" || name == "bn_comment_search")
        {
            const auto query = name == "bn_comment_search" ? Lower(stringArgument("query")) : std::string{};
            for (const auto address : state->view->GetCommentedAddresses())
            {
                const auto comment = state->view->GetCommentForAddress(address);
                if (query.empty() || Lower(comment).find(query) != std::string::npos)
                    matches.push_back({address, "comment", comment, {}});
            }
        }
        else if (name == "bn_memory_search")
        {
            const auto pattern = stringArgument("pattern");
            state->view->Search(pattern, [](std::size_t, std::size_t) { return true; },
                [&](std::uint64_t address, const BinaryNinja::DataBuffer& match) {
                    if (address < start || address >= end) return true;
                    const auto* bytes = static_cast<const std::uint8_t*>(match.GetData());
                    matches.push_back({address, "memory", HexBytes({bytes, match.GetLength()}), {}});
                    return true;
                });
        }
        else if (name == "bn_instruction_search")
        {
            const auto query = stringArgument("query");
            const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
            const auto flags = caseSensitive ? FindCaseSensitive : FindCaseInsensitive;
            state->view->FindAllText(start, end, query, settings, flags, NormalFunctionGraph,
                [](std::size_t, std::size_t) { return true; },
                [&](std::uint64_t address, const std::string&, const BinaryNinja::LinearDisassemblyLine& line) {
                    matches.push_back({address, "instruction", TokenText(line.contents.tokens), {}});
                    return true;
                });
        }
        else if (name == "bn_constant_search")
        {
            const auto expression = stringArgument("value");
            std::uint64_t constant = 0; std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view, expression, constant, 0, error))
                throw std::invalid_argument(error.empty() ? "invalid constant expression" : error);
            const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
            state->view->FindAllConstant(start, end, constant, settings, NormalFunctionGraph,
                [](std::size_t, std::size_t) { return true; },
                [&](std::uint64_t address, const BinaryNinja::LinearDisassemblyLine& line) {
                    matches.push_back({address, "constant", TokenText(line.contents.tokens), {}});
                    return true;
                });
        }
        else if (name == "bn_il_search")
        {
            auto query = stringArgument("query");
            if (!caseSensitive) query = Lower(query);
            auto functionQuery = Lower(stringArgument("functionQuery", false));
            const auto level = stringArgument("level", false).empty() ? "hlil" : stringArgument("level");
            bool ssa = false;
            if (const auto value = arguments.FindMember("ssa"); value != arguments.MemberEnd()) ssa = value->value.GetBool();
            const auto settings = BinaryNinja::DisassemblySettings::GetDefaultLinearSettings();
            for (const auto& function : state->view->GetAnalysisFunctionList())
            {
                if (!functionQuery.empty() && Lower(function->GetSymbol()->GetFullName()).find(functionQuery) == std::string::npos)
                    continue;
                std::vector<BinaryNinja::Ref<BinaryNinja::BasicBlock>> blocks;
                if (level == "llil") { auto il = function->GetLowLevelILIfAvailable(); if (!il) continue; if (ssa) il = il->GetSSAForm(); blocks = il->GetBasicBlocks(); }
                else if (level == "mlil") { auto il = function->GetMediumLevelILIfAvailable(); if (!il) continue; if (ssa) il = il->GetSSAForm(); blocks = il->GetBasicBlocks(); }
                else if (level == "hlil") { auto il = function->GetHighLevelILIfAvailable(); if (!il) continue; if (ssa) il = il->GetSSAForm(); blocks = il->GetBasicBlocks(); }
                else throw std::invalid_argument("level must be llil, mlil, or hlil");
                for (const auto& block : blocks)
                    for (const auto& line : block->GetDisassemblyText(settings))
                    {
                        const auto text = TokenText(line.tokens);
                        const auto comparable = caseSensitive ? text : Lower(text);
                        if (comparable.find(query) != std::string::npos)
                            matches.push_back({line.addr, level, text, function->GetSymbol()->GetFullName()});
                    }
            }
        }
        else if (name == "bn_project_analysis_search")
        {
            const auto query = Lower(stringArgument("query"));
            for (const auto& function : state->view->GetAnalysisFunctionList())
            {
                const auto text = function->GetSymbol()->GetFullName();
                if (Lower(text).find(query) != std::string::npos)
                    matches.push_back({function->GetStart(), "function", text, text});
            }
            for (const auto& symbol : state->view->GetSymbols())
                if (Lower(symbol->GetFullName()).find(query) != std::string::npos)
                    matches.push_back({symbol->GetAddress(), "symbol", symbol->GetFullName(), {}});
            for (const auto& string : state->view->GetStrings())
            {
                const auto detected = ReadDetectedString(
                    state->view, string.type, string.start, string.length);
                const auto preview = DecodeString(detected.type, detected.bytes, 128);
                if (Lower(preview.text).find(query) != std::string::npos)
                    matches.push_back({string.start, "string", preview.text, {}});
            }
            for (const auto address : state->view->GetCommentedAddresses())
            {
                const auto text = state->view->GetCommentForAddress(address);
                if (Lower(text).find(query) != std::string::npos)
                    matches.push_back({address, "comment", text, {}});
            }
        }
        else throw std::invalid_argument("unknown search tool");
        std::sort(matches.begin(), matches.end(), [](const auto& left, const auto& right) {
            if (left.address != right.address) return left.address < right.address;
            if (left.kind != right.kind) return left.kind < right.kind;
            return left.text < right.text;
        });
        offset = std::min(offset, matches.size());
        const auto finish = offset + std::min(limit, matches.size() - offset);
        rapidjson::StringBuffer buffer; rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("matches"); writer.StartArray();
        for (std::size_t index = offset; index < finish; ++index)
        {
            const auto& match = matches[index]; writer.StartObject();
            writer.Key("address"); const auto address = HexAddress(match.address); writer.String(address.data(), address.size());
            writer.Key("kind"); writer.String(match.kind.data(), match.kind.size());
            writer.Key("text"); writer.String(match.text.data(), match.text.size());
            if (!match.function.empty()) { writer.Key("function"); writer.String(match.function.data(), match.function.size()); }
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(matches.size()); writer.Key("nextOffset");
        if (finish < matches.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < matches.size()); writer.EndObject();
        ipc::Reply reply; reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply CommentGet(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("comment address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& value = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid comment address" : parseError);
        const auto comment = state->view->GetCommentForAddress(address);
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("text"); writer.String(comment.data(), comment.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply CommentSet(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString() || !arguments.HasMember("text") ||
            !arguments["text"].IsString() || arguments["text"].GetStringLength() == 0)
            throw std::invalid_argument("comment address and non-empty text are required");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid comment address" : parseError);
        const std::string text(arguments["text"].GetString(), arguments["text"].GetStringLength());
        state->view->SetCommentForAddress(address, text);
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("text"); writer.String(text.data(), text.size());
        writer.Key("updated"); writer.Bool(true);
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply CommentDelete(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("comment address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid comment address" : parseError);
        state->view->SetCommentForAddress(address, "");
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("deleted"); writer.Bool(true);
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SymbolDefine(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString() || !arguments.HasMember("name") ||
            !arguments["name"].IsString() || arguments["name"].GetStringLength() == 0)
            throw std::invalid_argument("symbol address and non-empty name are required");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
        const std::string name(arguments["name"].GetString(), arguments["name"].GetStringLength());
        auto type = DataSymbol;
        auto binding = NoBinding;
        std::string nameSpace;
        std::uint64_t ordinal = 0;
        if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd())
            type = ParseSymbolType({value->value.GetString(), value->value.GetStringLength()});
        if (const auto value = arguments.FindMember("binding"); value != arguments.MemberEnd())
            binding = ParseSymbolBinding({value->value.GetString(), value->value.GetStringLength()});
        if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
            nameSpace.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("ordinal"); value != arguments.MemberEnd())
            ordinal = value->value.GetUint64();
        const BinaryNinja::NameSpace symbolNameSpace = nameSpace.empty()
            ? BinaryNinja::NameSpace(DEFAULT_INTERNAL_NAMESPACE)
            : BinaryNinja::NameSpace(nameSpace);
        BinaryNinja::Ref<BinaryNinja::Symbol> symbol = new BinaryNinja::Symbol(
            type, name, address, binding, symbolNameSpace, ordinal);
        state->view->DefineUserSymbol(symbol);
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("symbol"); writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("type"); writer.String(SymbolTypeName(type));
        writer.Key("shortName"); writer.String(name.data(), name.size());
        writer.Key("fullName"); writer.String(name.data(), name.size());
        writer.Key("rawName"); writer.String(name.data(), name.size());
        writer.Key("namespace"); writer.StartArray();
        for (const auto& component : symbolNameSpace)
            writer.String(component.data(), component.size());
        writer.EndArray();
        writer.Key("ordinal"); writer.Uint64(ordinal);
        writer.Key("binding"); writer.String(SymbolBindingName(binding));
        writer.Key("autoDefined"); writer.Bool(false);
        writer.EndObject(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SymbolRename(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString() || !arguments.HasMember("newName") ||
            !arguments["newName"].IsString() || arguments["newName"].GetStringLength() == 0)
            throw std::invalid_argument("symbol address and non-empty newName are required");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
        auto symbols = state->view->GetSymbols(address, 1);
        std::erase_if(symbols, [&](const auto& symbol) {
            if (symbol->GetAddress() != address)
                return true;
            if (const auto value = arguments.FindMember("name"); value != arguments.MemberEnd())
            {
                const std::string wanted(value->value.GetString(), value->value.GetStringLength());
                if (symbol->GetShortName() != wanted && symbol->GetFullName() != wanted &&
                    symbol->GetRawName() != wanted)
                    return true;
            }
            if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd() &&
                symbol->GetType() != ParseSymbolType(
                    {value->value.GetString(), value->value.GetStringLength()}))
                return true;
            if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
            {
                std::string wanted(value->value.GetString(), value->value.GetStringLength());
                if (wanted.empty())
                    wanted = DEFAULT_INTERNAL_NAMESPACE;
                if (symbol->GetNameSpace().GetString() != wanted)
                    return true;
            }
            if (const auto value = arguments.FindMember("ordinal"); value != arguments.MemberEnd() &&
                symbol->GetOrdinal() != value->value.GetUint64())
                return true;
            return false;
        });
        if (symbols.empty())
            throw std::invalid_argument("symbol not found");
        if (symbols.size() != 1)
            throw std::invalid_argument("symbol selector is ambiguous");
        const auto& current = symbols.front();
        const std::string newName(
            arguments["newName"].GetString(), arguments["newName"].GetStringLength());
        const auto nameSpace = current->GetNameSpace();
        BinaryNinja::Ref<BinaryNinja::Symbol> replacement = new BinaryNinja::Symbol(
            current->GetType(), newName, address, current->GetBinding(),
            nameSpace, current->GetOrdinal());
        state->view->DefineUserSymbol(replacement);
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("symbol"); writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("type"); writer.String(SymbolTypeName(current->GetType()));
        writer.Key("shortName"); writer.String(newName.data(), newName.size());
        writer.Key("fullName"); writer.String(newName.data(), newName.size());
        writer.Key("rawName"); writer.String(newName.data(), newName.size());
        writer.Key("namespace"); writer.StartArray();
        for (const auto& component : nameSpace)
            writer.String(component.data(), component.size());
        writer.EndArray();
        writer.Key("ordinal"); writer.Uint64(current->GetOrdinal());
        writer.Key("binding"); writer.String(SymbolBindingName(current->GetBinding()));
        writer.Key("autoDefined"); writer.Bool(false);
        writer.EndObject(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SymbolUndefine(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("address") ||
            !arguments["address"].IsString())
            throw std::invalid_argument("symbol address must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& addressValue = arguments["address"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(addressValue.GetString(), addressValue.GetStringLength()),
                address, 0, parseError))
            throw std::invalid_argument(parseError.empty() ? "invalid symbol address" : parseError);
        auto symbols = state->view->GetSymbols(address, 1);
        std::erase_if(symbols, [&](const auto& symbol) {
            if (symbol->GetAddress() != address || symbol->IsAutoDefined())
                return true;
            if (const auto value = arguments.FindMember("name"); value != arguments.MemberEnd())
            {
                const std::string wanted(value->value.GetString(), value->value.GetStringLength());
                if (symbol->GetShortName() != wanted && symbol->GetFullName() != wanted &&
                    symbol->GetRawName() != wanted)
                    return true;
            }
            if (const auto value = arguments.FindMember("type"); value != arguments.MemberEnd() &&
                symbol->GetType() != ParseSymbolType(
                    {value->value.GetString(), value->value.GetStringLength()}))
                return true;
            if (const auto value = arguments.FindMember("namespace"); value != arguments.MemberEnd())
            {
                std::string wanted(value->value.GetString(), value->value.GetStringLength());
                if (wanted.empty()) wanted = DEFAULT_INTERNAL_NAMESPACE;
                if (symbol->GetNameSpace().GetString() != wanted)
                    return true;
            }
            if (const auto value = arguments.FindMember("ordinal"); value != arguments.MemberEnd() &&
                symbol->GetOrdinal() != value->value.GetUint64())
                return true;
            return false;
        });
        if (symbols.empty())
            throw std::invalid_argument("user symbol not found");
        if (symbols.size() != 1)
            throw std::invalid_argument("symbol selector is ambiguous");
        state->view->UndefineUserSymbol(symbols.front());
        const auto addressText = HexAddress(address);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("address"); writer.String(addressText.data(), addressText.size());
        writer.Key("deleted"); writer.Bool(true);
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply FunctionPrototypeSet(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("prototype") ||
            !arguments["prototype"].IsString() || arguments["prototype"].GetStringLength() == 0)
            throw std::invalid_argument("prototype must be a non-empty string");
        const auto function = ResolveFunction(state, arguments);
        const std::string prototype(
            arguments["prototype"].GetString(), arguments["prototype"].GetStringLength());
        BinaryNinja::QualifiedNameAndType parsed;
        std::string errors;
        if (!state->view->ParseTypeString(prototype, parsed, errors) || !parsed.type)
            throw std::invalid_argument(errors.empty() ? "invalid function prototype" : errors);
        if (parsed.type->GetClass() != FunctionTypeClass)
            throw std::invalid_argument("prototype must describe a function type");
        function->SetUserType(parsed.type);
        return FunctionInfo(command);
    }

    ipc::Reply CallingConventionSet(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("callingConvention") ||
            !arguments["callingConvention"].IsString() ||
            arguments["callingConvention"].GetStringLength() == 0)
            throw std::invalid_argument("callingConvention must be a non-empty string");
        const auto function = ResolveFunction(state, arguments);
        const auto platform = function->GetPlatform();
        if (!platform)
            throw std::runtime_error("function has no platform");
        const std::string name(arguments["callingConvention"].GetString(),
            arguments["callingConvention"].GetStringLength());
        BinaryNinja::Ref<BinaryNinja::CallingConvention> selected;
        for (const auto& convention : platform->GetCallingConventions())
        {
            if (convention && convention->GetName() == name)
            {
                selected = convention;
                break;
            }
        }
        if (!selected)
            throw std::invalid_argument("calling convention is not available for the function platform");
        function->SetCallingConvention(
            BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::CallingConvention>>(selected, 255));
        return FunctionInfo(command);
    }

    ipc::Reply VariableRename(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("variable") ||
            !arguments["variable"].IsString() || !arguments.HasMember("newName") ||
            !arguments["newName"].IsString() || arguments["newName"].GetStringLength() == 0)
            throw std::invalid_argument("variable and non-empty newName are required");
        const auto function = ResolveFunction(state, arguments);
        const std::string variableName(
            arguments["variable"].GetString(), arguments["variable"].GetStringLength());
        std::vector<BinaryNinja::VariableNameAndType> matches;
        for (const auto& entry : function->GetVariables())
        {
            const auto& variable = entry.second;
            if (variable.name != variableName)
                continue;
            if (const auto value = arguments.FindMember("source"); value != arguments.MemberEnd() &&
                variable.var.type != ParseVariableSource(
                    {value->value.GetString(), value->value.GetStringLength()}))
                continue;
            if (const auto value = arguments.FindMember("index"); value != arguments.MemberEnd() &&
                variable.var.index != value->value.GetUint())
                continue;
            if (const auto value = arguments.FindMember("storage"); value != arguments.MemberEnd() &&
                variable.var.storage != value->value.GetInt64())
                continue;
            matches.push_back(variable);
        }
        if (matches.empty())
            throw std::invalid_argument("variable not found");
        if (matches.size() != 1)
            throw std::invalid_argument("variable selector is ambiguous");
        const std::string newName(
            arguments["newName"].GetString(), arguments["newName"].GetStringLength());
        const auto& variable = matches.front();
        function->CreateUserVariable(variable.var, variable.type, newName);
        const auto type = variable.type.GetValue();
        const auto platform = function->GetPlatform();
        const auto typeText = type ? type->GetString(platform.GetPtr()) : std::string{};
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("variable"); writer.StartObject();
        writer.Key("name"); writer.String(newName.data(), newName.size());
        writer.Key("type"); writer.String(typeText.data(), typeText.size());
        writer.Key("source"); writer.String(VariableSourceName(variable.var.type));
        writer.Key("index"); writer.Uint(variable.var.index);
        writer.Key("storage"); writer.Int64(variable.var.storage);
        writer.EndObject();
        writer.Key("needsUpdate"); writer.Bool(true);
        writer.Key("nextAction");
        writer.String("Call bn_analysis_update_and_wait before readback.");
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply VariableSetType(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("variable") ||
            !arguments["variable"].IsString())
            throw std::invalid_argument("variable must be a string");
        const auto function = ResolveFunction(state, arguments);
        const std::string variableName(
            arguments["variable"].GetString(), arguments["variable"].GetStringLength());
        std::vector<BinaryNinja::VariableNameAndType> matches;
        for (const auto& entry : function->GetVariables())
        {
            const auto& variable = entry.second;
            if (variable.name != variableName)
                continue;
            if (const auto value = arguments.FindMember("variableSource");
                value != arguments.MemberEnd() &&
                variable.var.type != ParseVariableSource(
                    {value->value.GetString(), value->value.GetStringLength()}))
                continue;
            if (const auto value = arguments.FindMember("index"); value != arguments.MemberEnd() &&
                variable.var.index != value->value.GetUint())
                continue;
            if (const auto value = arguments.FindMember("storage"); value != arguments.MemberEnd() &&
                variable.var.storage != value->value.GetInt64())
                continue;
            matches.push_back(variable);
        }
        if (matches.empty())
            throw std::invalid_argument("variable not found");
        if (matches.size() != 1)
            throw std::invalid_argument("variable selector is ambiguous");
        const auto parsedType = ParseRequestedType(state, arguments);
        const auto& variable = matches.front();
        const BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>> userType(parsedType, 255);
        function->CreateUserVariable(variable.var, userType, variable.name);
        const auto platform = function->GetPlatform();
        const auto typeText = parsedType->GetString(platform.GetPtr());
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("variable"); writer.StartObject();
        writer.Key("name"); writer.String(variable.name.data(), variable.name.size());
        writer.Key("type"); writer.String(typeText.data(), typeText.size());
        writer.Key("source"); writer.String(VariableSourceName(variable.var.type));
        writer.Key("index"); writer.Uint(variable.var.index);
        writer.Key("storage"); writer.Int64(variable.var.storage);
        writer.EndObject();
        writer.Key("needsUpdate"); writer.Bool(true);
        writer.Key("nextAction");
        writer.String("Call bn_analysis_update_and_wait before readback.");
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeList(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject())
            throw std::invalid_argument("type-list arguments must be an object");
        std::size_t offset = 0;
        std::size_t limit = kDefaultListLimit;
        if (const auto value = arguments.FindMember("offset"); value != arguments.MemberEnd())
            offset = static_cast<std::size_t>(value->value.GetUint64());
        if (const auto value = arguments.FindMember("limit"); value != arguments.MemberEnd())
            limit = static_cast<std::size_t>(value->value.GetUint64());
        std::string query;
        if (const auto value = arguments.FindMember("query"); value != arguments.MemberEnd())
            query = Lower(std::string(value->value.GetString(), value->value.GetStringLength()));
        std::vector<std::pair<std::string, BinaryNinja::Ref<BinaryNinja::Type>>> types;
        for (const auto& [name, type] : state->view->GetTypes())
        {
            const auto nameText = name.GetString();
            if (!query.empty() && Lower(nameText).find(query) == std::string::npos)
                continue;
            types.emplace_back(nameText, type);
        }
        offset = std::min(offset, types.size());
        const auto finish = offset + std::min(limit, types.size() - offset);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("types"); writer.StartArray();
        for (auto index = offset; index < finish; ++index)
        {
            writer.StartObject();
            writer.Key("name"); writer.String(types[index].first.data(), types[index].first.size());
            writer.Key("class"); writer.String(TypeClassName(types[index].second->GetClass()));
            writer.EndObject();
        }
        writer.EndArray();
        writer.Key("count"); writer.Uint64(finish - offset);
        writer.Key("total"); writer.Uint64(types.size());
        writer.Key("nextOffset");
        if (finish < types.size()) writer.Uint64(finish); else writer.Null();
        writer.Key("truncated"); writer.Bool(finish < types.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeInfo(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("type") ||
            !arguments["type"].IsString() || arguments["type"].GetStringLength() == 0)
            throw std::invalid_argument("type must be a non-empty string");
        const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
        BinaryNinja::QualifiedName selectedName;
        BinaryNinja::Ref<BinaryNinja::Type> selectedType;
        for (const auto& [name, type] : state->view->GetTypes())
        {
            if (name.GetString() == requested)
            {
                if (selectedType)
                    throw std::invalid_argument("type name is ambiguous");
                selectedName = name;
                selectedType = type;
            }
        }
        if (!selectedType)
            throw std::invalid_argument("type not found");
        const auto definition = RenderTypeDefinition(state->view, selectedName, selectedType);
        const auto typeId = state->view->GetTypeId(selectedName);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("name"); writer.String(requested.data(), requested.size());
        writer.Key("id"); writer.String(typeId.data(), typeId.size());
        writer.Key("class"); writer.String(TypeClassName(selectedType->GetClass()));
        writer.Key("width"); writer.Uint64(selectedType->GetWidth());
        writer.Key("alignment"); writer.Uint64(selectedType->GetAlignment());
        writer.Key("autoDefined"); writer.Bool(state->view->IsTypeAutoDefined(selectedName));
        writer.Key("definition"); writer.String(definition.data(), definition.size());
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeParse(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("source") ||
            !arguments["source"].IsString() || arguments["source"].GetStringLength() == 0)
            throw std::invalid_argument("source must be a non-empty string");
        std::vector<std::string> options;
        std::vector<std::string> includeDirs;
        auto readStrings = [&](const char* name, std::vector<std::string>& output) {
            if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
            {
                if (!value->value.IsArray())
                    throw std::invalid_argument(std::string(name) + " must be an array of strings");
                for (const auto& item : value->value.GetArray())
                {
                    if (!item.IsString())
                        throw std::invalid_argument(std::string(name) + " must be an array of strings");
                    output.emplace_back(item.GetString(), item.GetStringLength());
                }
            }
        };
        readStrings("options", options);
        readStrings("includeDirs", includeDirs);
        bool importDependencies = true;
        if (const auto value = arguments.FindMember("importDependencies");
            value != arguments.MemberEnd())
            importDependencies = value->value.GetBool();
        BinaryNinja::TypeParserResult parsed;
        std::string errors;
        const bool success = state->view->ParseTypesFromSource(
            std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()),
            options, includeDirs, parsed, errors, {}, importDependencies);
        const auto printer = BinaryNinja::TypePrinter::GetDefault();
        const auto platform = state->view->GetDefaultPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("success"); writer.Bool(success);
        writer.Key("errors"); writer.String(errors.data(), errors.size());
        auto writeTypes = [&](const char* key, const auto& values, bool fullDefinition) {
            writer.Key(key); writer.StartArray();
            for (const auto& value : values)
            {
                const auto name = value.name.GetString();
                const auto definition = fullDefinition
                    ? RenderTypeDefinition(state->view, value.name, value.type)
                    : printer->GetTypeString(value.type, platform, value.name) + ";";
                writer.StartObject();
                writer.Key("name"); writer.String(name.data(), name.size());
                if (fullDefinition)
                {
                    writer.Key("class"); writer.String(TypeClassName(value.type->GetClass()));
                }
                writer.Key("definition"); writer.String(definition.data(), definition.size());
                writer.EndObject();
            }
            writer.EndArray();
        };
        writeTypes("types", parsed.types, true);
        writeTypes("variables", parsed.variables, false);
        writeTypes("functions", parsed.functions, false);
        writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeDefine(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("source") ||
            !arguments["source"].IsString() || arguments["source"].GetStringLength() == 0)
            throw std::invalid_argument("source must be a non-empty string");
        std::vector<std::string> options;
        std::vector<std::string> includeDirs;
        auto readStrings = [&](const char* name, std::vector<std::string>& output) {
            if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
            {
                if (!value->value.IsArray())
                    throw std::invalid_argument(std::string(name) + " must be an array of strings");
                for (const auto& item : value->value.GetArray())
                {
                    if (!item.IsString())
                        throw std::invalid_argument(std::string(name) + " must be an array of strings");
                    output.emplace_back(item.GetString(), item.GetStringLength());
                }
            }
        };
        readStrings("options", options);
        readStrings("includeDirs", includeDirs);
        bool importDependencies = true;
        if (const auto value = arguments.FindMember("importDependencies");
            value != arguments.MemberEnd())
            importDependencies = value->value.GetBool();
        BinaryNinja::TypeParserResult parsed;
        std::string errors;
        if (!state->view->ParseTypesFromSource(
                std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()),
                options, includeDirs, parsed, errors, {}, importDependencies))
            throw std::invalid_argument(errors.empty() ? "invalid type source" : errors);
        std::vector<BinaryNinja::ParsedType> selected = parsed.types;
        if (const auto requested = arguments.FindMember("types"); requested != arguments.MemberEnd())
        {
            std::set<std::string> names;
            for (const auto& item : requested->value.GetArray())
                names.emplace(item.GetString(), item.GetStringLength());
            std::erase_if(selected, [&](const auto& type) {
                return !names.contains(type.name.GetString());
            });
            for (const auto& name : names)
            {
                if (std::none_of(selected.begin(), selected.end(), [&](const auto& type) {
                        return type.name.GetString() == name;
                    }))
                    throw std::invalid_argument("parsed type not found: " + name);
            }
        }
        if (selected.empty())
            throw std::invalid_argument("source contains no selected named types");
        state->view->DefineUserTypes(selected);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("types"); writer.StartArray();
        for (const auto& parsedType : selected)
        {
            const auto name = parsedType.name.GetString();
            const auto stored = state->view->GetTypeByName(parsedType.name);
            const auto typeId = state->view->GetTypeId(parsedType.name);
            const auto definition = RenderTypeDefinition(state->view, parsedType.name, stored);
            writer.StartObject();
            writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("id"); writer.String(typeId.data(), typeId.size());
            writer.Key("class"); writer.String(TypeClassName(stored->GetClass()));
            writer.Key("width"); writer.Uint64(stored->GetWidth());
            writer.Key("alignment"); writer.Uint64(stored->GetAlignment());
            writer.Key("autoDefined"); writer.Bool(state->view->IsTypeAutoDefined(parsedType.name));
            writer.Key("definition"); writer.String(definition.data(), definition.size());
            writer.EndObject();
        }
        writer.EndArray(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeStructCreate(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("source") ||
            !arguments["source"].IsString() || arguments["source"].GetStringLength() == 0)
            throw std::invalid_argument("source must be a non-empty string");
        std::vector<std::string> options;
        std::vector<std::string> includeDirs;
        auto readStrings = [&](const char* name, std::vector<std::string>& output) {
            if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
                for (const auto& item : value->value.GetArray())
                    output.emplace_back(item.GetString(), item.GetStringLength());
        };
        readStrings("options", options);
        readStrings("includeDirs", includeDirs);
        bool importDependencies = true;
        if (const auto value = arguments.FindMember("importDependencies");
            value != arguments.MemberEnd())
            importDependencies = value->value.GetBool();
        BinaryNinja::TypeParserResult parsed;
        std::string errors;
        if (!state->view->ParseTypesFromSource(
                std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()),
                options, includeDirs, parsed, errors, {}, importDependencies))
            throw std::invalid_argument(errors.empty() ? "invalid struct source" : errors);
        auto candidates = parsed.types;
        if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
        {
            const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
            std::erase_if(candidates, [&](const auto& candidate) {
                return candidate.name.GetString() != wanted;
            });
        }
        const bool unionType = command.name() == "bn_type_union_create" ||
            command.name() == "bn_type_union_modify";
        const auto expectedVariant = unionType ? UnionStructureType : StructStructureType;
        std::erase_if(candidates, [&](const auto& candidate) {
            if (!candidate.type || candidate.type->GetClass() != StructureTypeClass)
                return true;
            const auto structure = candidate.type->GetStructure();
            return !structure || structure->GetStructureType() != expectedVariant;
        });
        if (candidates.empty())
            throw std::invalid_argument(unionType
                ? "matching union definition not found" : "matching struct definition not found");
        if (candidates.size() != 1)
            throw std::invalid_argument(unionType
                ? "union source is ambiguous; specify type"
                : "struct source is ambiguous; specify type");
        const auto& selected = candidates.front();
        const auto existing = state->view->GetTypeByName(selected.name);
        const bool modify = command.name() == "bn_type_struct_modify" ||
            command.name() == "bn_type_union_modify";
        if (!modify && existing)
            throw std::invalid_argument("type already exists");
        if (modify && !existing)
            throw std::invalid_argument("type does not exist");
        if (modify && (existing->GetClass() != StructureTypeClass ||
                !existing->GetStructure() ||
                existing->GetStructure()->GetStructureType() != expectedVariant))
            throw std::invalid_argument(unionType
                ? "existing type is not a union" : "existing type is not a struct");
        state->view->DefineUserType(selected.name, selected.type);
        rapidjson::StringBuffer argumentsBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
        const auto name = selected.name.GetString();
        writer.StartObject(); writer.Key("type"); writer.String(name.data(), name.size()); writer.EndObject();
        ipc::ExecuteAnalysisTool infoCommand = command;
        infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
        return TypeInfo(infoCommand);
    }

    ipc::Reply TypeEnumCreate(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("source") ||
            !arguments["source"].IsString() || arguments["source"].GetStringLength() == 0)
            throw std::invalid_argument("source must be a non-empty string");
        std::vector<std::string> options;
        std::vector<std::string> includeDirs;
        auto readStrings = [&](const char* name, std::vector<std::string>& output) {
            if (const auto value = arguments.FindMember(name); value != arguments.MemberEnd())
                for (const auto& item : value->value.GetArray())
                    output.emplace_back(item.GetString(), item.GetStringLength());
        };
        readStrings("options", options);
        readStrings("includeDirs", includeDirs);
        bool importDependencies = true;
        if (const auto value = arguments.FindMember("importDependencies");
            value != arguments.MemberEnd())
            importDependencies = value->value.GetBool();
        BinaryNinja::TypeParserResult parsed;
        std::string errors;
        if (!state->view->ParseTypesFromSource(
                std::string(arguments["source"].GetString(), arguments["source"].GetStringLength()),
                options, includeDirs, parsed, errors, {}, importDependencies))
            throw std::invalid_argument(errors.empty() ? "invalid enum source" : errors);
        auto candidates = parsed.types;
        if (const auto selected = arguments.FindMember("type"); selected != arguments.MemberEnd())
        {
            const std::string wanted(selected->value.GetString(), selected->value.GetStringLength());
            std::erase_if(candidates, [&](const auto& candidate) {
                return candidate.name.GetString() != wanted;
            });
        }
        std::erase_if(candidates, [](const auto& candidate) {
            return !candidate.type || candidate.type->GetClass() != EnumerationTypeClass;
        });
        if (candidates.empty())
            throw std::invalid_argument("matching enum definition not found");
        if (candidates.size() != 1)
            throw std::invalid_argument("enum source is ambiguous; specify type");
        const auto& selected = candidates.front();
        const auto existing = state->view->GetTypeByName(selected.name);
        const bool modify = command.name() == "bn_type_enum_modify";
        if (!modify && existing)
            throw std::invalid_argument("type already exists");
        if (modify && !existing)
            throw std::invalid_argument("type does not exist");
        if (modify && existing->GetClass() != EnumerationTypeClass)
            throw std::invalid_argument("existing type is not an enum");
        state->view->DefineUserType(selected.name, selected.type);
        rapidjson::StringBuffer argumentsBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
        const auto name = selected.name.GetString();
        writer.StartObject(); writer.Key("type"); writer.String(name.data(), name.size()); writer.EndObject();
        ipc::ExecuteAnalysisTool infoCommand = command;
        infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
        return TypeInfo(infoCommand);
    }

    ipc::Reply TypeDelete(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("type") ||
            !arguments["type"].IsString() || arguments["type"].GetStringLength() == 0)
            throw std::invalid_argument("type must be a non-empty string");
        const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
        std::optional<BinaryNinja::QualifiedName> selected;
        for (const auto& [name, type] : state->view->GetTypes())
        {
            if (name.GetString() == requested)
            {
                if (selected)
                    throw std::invalid_argument("type name is ambiguous");
                selected = name;
            }
        }
        if (!selected)
            throw std::invalid_argument("type not found");
        if (state->view->IsTypeAutoDefined(*selected))
            state->view->UndefineType(state->view->GetTypeId(*selected));
        else
            state->view->UndefineUserType(*selected);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("type"); writer.String(requested.data(), requested.size());
        writer.Key("deleted"); writer.Bool(true); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeRename(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("type") ||
            !arguments["type"].IsString() || !arguments.HasMember("newType") ||
            !arguments["newType"].IsString() || arguments["newType"].GetStringLength() == 0)
            throw std::invalid_argument("type and non-empty newType are required");
        const std::string current(arguments["type"].GetString(), arguments["type"].GetStringLength());
        const std::string replacement(
            arguments["newType"].GetString(), arguments["newType"].GetStringLength());
        std::optional<BinaryNinja::QualifiedName> currentName;
        for (const auto& [name, type] : state->view->GetTypes())
        {
            if (name.GetString() == current)
                currentName = name;
            if (name.GetString() == replacement && name.GetString() != current)
                throw std::invalid_argument("destination type already exists");
        }
        if (!currentName)
            throw std::invalid_argument("type not found");
        const auto newName = QualifiedNameFromString(replacement);
        state->view->RenameType(*currentName, newName);
        rapidjson::StringBuffer argumentsBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
        writer.StartObject(); writer.Key("type");
        writer.String(replacement.data(), replacement.size()); writer.EndObject();
        ipc::ExecuteAnalysisTool infoCommand = command;
        infoCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
        return TypeInfo(infoCommand);
    }

    ipc::Reply TypeXrefsFrom(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("type") ||
            !arguments["type"].IsString())
            throw std::invalid_argument("type must be a string");
        const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
        std::optional<BinaryNinja::QualifiedName> selected;
        for (const auto& [name, type] : state->view->GetTypes())
            if (name.GetString() == requested) selected = name;
        if (!selected)
            throw std::invalid_argument("type not found");
        bool recursive = false;
        if (const auto value = arguments.FindMember("recursive"); value != arguments.MemberEnd())
            recursive = value->value.GetBool();
        const auto references = recursive
            ? state->view->GetOutgoingRecursiveTypeReferences(*selected)
            : state->view->GetOutgoingDirectTypeReferences(*selected);
        std::vector<std::string> names;
        for (const auto& reference : references)
            names.push_back(reference.GetString());
        std::sort(names.begin(), names.end());
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("type"); writer.String(requested.data(), requested.size());
        writer.Key("references"); writer.StartArray();
        for (const auto& name : names)
        {
            const auto referencedType = state->view->GetTypeByName(QualifiedNameFromString(name));
            writer.StartObject(); writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("class");
            if (referencedType) writer.String(TypeClassName(referencedType->GetClass()));
            else writer.Null();
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("recursive"); writer.Bool(recursive); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply TypeXrefsTo(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("type") ||
            !arguments["type"].IsString())
            throw std::invalid_argument("type must be a string");
        const std::string requested(arguments["type"].GetString(), arguments["type"].GetStringLength());
        std::optional<BinaryNinja::QualifiedName> selected;
        for (const auto& [name, type] : state->view->GetTypes())
            if (name.GetString() == requested) selected = name;
        if (!selected)
            throw std::invalid_argument("type not found");
        std::optional<std::size_t> maxItems;
        if (const auto value = arguments.FindMember("maxItems"); value != arguments.MemberEnd())
            maxItems = static_cast<std::size_t>(value->value.GetUint64());
        auto references = state->view->GetAllReferencesForType(*selected, maxItems);
        std::sort(references.codeRefs.begin(), references.codeRefs.end(),
            [](const auto& left, const auto& right) { return left.addr < right.addr; });
        std::sort(references.dataRefs.begin(), references.dataRefs.end());
        std::sort(references.typeRefs.begin(), references.typeRefs.end(),
            [](const auto& left, const auto& right) {
                return left.name.GetString() < right.name.GetString();
            });
        const auto platform = state->view->GetDefaultPlatform();
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("type"); writer.String(requested.data(), requested.size());
        writer.Key("code"); writer.StartArray();
        for (const auto& reference : references.codeRefs)
        {
            const auto address = HexAddress(reference.addr);
            const auto symbol = reference.func ? reference.func->GetSymbol() : nullptr;
            const auto functionName = symbol ? symbol->GetShortName() : std::string{};
            const auto architecture = reference.arch ? reference.arch->GetName() : std::string{};
            writer.StartObject(); writer.Key("address"); writer.String(address.data(), address.size());
            writer.Key("function"); writer.String(functionName.data(), functionName.size());
            writer.Key("arch"); writer.String(architecture.data(), architecture.size());
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("data"); writer.StartArray();
        for (const auto reference : references.dataRefs)
        {
            const auto address = HexAddress(reference);
            BinaryNinja::DataVariable variable;
            writer.StartObject(); writer.Key("address"); writer.String(address.data(), address.size());
            writer.Key("type");
            if (state->view->GetDataVariableAtAddress(reference, variable) && variable.type.GetValue())
            {
                const auto typeText = variable.type.GetValue()->GetString(platform.GetPtr());
                writer.String(typeText.data(), typeText.size());
            }
            else writer.Null();
            writer.EndObject();
        }
        writer.EndArray(); writer.Key("types"); writer.StartArray();
        for (const auto& reference : references.typeRefs)
        {
            const auto name = reference.name.GetString();
            const auto type = state->view->GetTypeByName(reference.name);
            writer.StartObject(); writer.Key("name"); writer.String(name.data(), name.size());
            writer.Key("class");
            if (type) writer.String(TypeClassName(type->GetClass())); else writer.Null();
            writer.EndObject();
        }
        writer.EndArray(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply DataVariableDefine(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("datavar") ||
            !arguments["datavar"].IsString())
            throw std::invalid_argument("datavar must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& value = arguments["datavar"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid data-variable address" : parseError);
        const auto type = ParseRequestedType(state, arguments);
        state->view->DefineUserDataVariable(address,
            BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>(type, 255));
        rapidjson::StringBuffer argumentsBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
        const auto addressText = HexAddress(address);
        writer.StartObject(); writer.Key("address");
        writer.String(addressText.data(), addressText.size()); writer.EndObject();
        ipc::ExecuteAnalysisTool dataCommand = command;
        dataCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
        return DataAt(dataCommand);
    }

    ipc::Reply DataVariableUndefine(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("datavar") ||
            !arguments["datavar"].IsString())
            throw std::invalid_argument("datavar must be a string");
        std::uint64_t address = 0;
        std::string parseError;
        const auto& value = arguments["datavar"];
        if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                std::string(value.GetString(), value.GetStringLength()), address, 0, parseError))
            throw std::invalid_argument(parseError.empty()
                ? "invalid data-variable address" : parseError);
        BinaryNinja::DataVariable variable;
        if (!state->view->GetDataVariableAtAddress(address, variable))
            throw std::invalid_argument("data variable not found");
        if (variable.autoDiscovered)
            state->view->UndefineDataVariable(address, true);
        else
            state->view->UndefineUserDataVariable(address);
        rapidjson::StringBuffer argumentsBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(argumentsBuffer);
        const auto addressText = HexAddress(address);
        writer.StartObject(); writer.Key("address");
        writer.String(addressText.data(), addressText.size()); writer.EndObject();
        ipc::ExecuteAnalysisTool dataCommand = command;
        dataCommand.set_arguments_json(argumentsBuffer.GetString(), argumentsBuffer.GetSize());
        return DataAt(dataCommand);
    }

    ipc::Reply SectionCreate(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("section") ||
            !arguments["section"].IsString() || arguments["section"].GetStringLength() == 0 ||
            !arguments.HasMember("start") || !arguments["start"].IsString() ||
            !arguments.HasMember("length"))
            throw std::invalid_argument("section, start, and length are required");
        const std::string name(
            arguments["section"].GetString(), arguments["section"].GetStringLength());
        if (state->view->GetSectionByName(name))
            throw std::invalid_argument("section already exists");
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty() ? "invalid section expression" : error);
            return result;
        };
        const auto start = parseExpression(arguments["start"]);
        const auto& lengthValue = arguments["length"];
        const auto length = lengthValue.IsUint64()
            ? lengthValue.GetUint64() : parseExpression(lengthValue);
        if (length > std::numeric_limits<std::uint64_t>::max() - start)
            throw std::invalid_argument("section range overflows");
        auto semantics = DefaultSectionSemantics;
        std::string typeName;
        std::uint64_t alignment = 1;
        std::uint64_t entrySize = 0;
        std::string linkedSection;
        std::string infoSection;
        std::uint64_t infoData = 0;
        if (const auto value = arguments.FindMember("semantics"); value != arguments.MemberEnd())
            semantics = ParseSectionSemantics(
                {value->value.GetString(), value->value.GetStringLength()});
        if (const auto value = arguments.FindMember("typeName"); value != arguments.MemberEnd())
            typeName.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("alignment"); value != arguments.MemberEnd())
            alignment = value->value.GetUint64();
        if (const auto value = arguments.FindMember("entrySize"); value != arguments.MemberEnd())
            entrySize = value->value.GetUint64();
        if (const auto value = arguments.FindMember("linkedSection"); value != arguments.MemberEnd())
            linkedSection.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("infoSection"); value != arguments.MemberEnd())
            infoSection.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("infoData"); value != arguments.MemberEnd())
            infoData = value->value.GetUint64();
        state->view->AddUserSection(name, start, length, semantics, typeName, alignment,
            entrySize, linkedSection, infoSection, infoData);
        const auto startText = HexAddress(start);
        const auto endText = HexAddress(start + length);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("section"); writer.StartObject();
        writer.Key("name"); writer.String(name.data(), name.size());
        writer.Key("start"); writer.String(startText.data(), startText.size());
        writer.Key("end"); writer.String(endText.data(), endText.size());
        writer.Key("semantics"); writer.String(SectionSemanticsName(semantics));
        writer.EndObject(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SectionDelete(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("section") ||
            !arguments["section"].IsString() || arguments["section"].GetStringLength() == 0)
            throw std::invalid_argument("section must be a non-empty string");
        const std::string name(
            arguments["section"].GetString(), arguments["section"].GetStringLength());
        const auto section = state->view->GetSectionByName(name);
        if (!section)
            throw std::invalid_argument("section not found");
        if (section->AutoDefined())
            state->view->RemoveAutoSection(name);
        else
            state->view->RemoveUserSection(name);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("section"); writer.String(name.data(), name.size());
        writer.Key("deleted"); writer.Bool(true); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply SectionModify(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments;
        arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject() || !arguments.HasMember("section") ||
            !arguments["section"].IsString() || arguments["section"].GetStringLength() == 0)
            throw std::invalid_argument("section must be a non-empty string");
        const std::string currentName(
            arguments["section"].GetString(), arguments["section"].GetStringLength());
        const auto section = state->view->GetSectionByName(currentName);
        if (!section)
            throw std::invalid_argument("section not found");
        auto parseExpression = [&](const rapidjson::Value& value) {
            std::uint64_t result = 0;
            std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value.GetString(), value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty() ? "invalid section expression" : error);
            return result;
        };
        auto name = currentName;
        auto start = section->GetStart();
        auto length = section->GetLength();
        auto semantics = section->GetSemantics();
        auto typeName = section->GetType();
        auto alignment = section->GetAlignment();
        auto entrySize = section->GetEntrySize();
        auto linkedSection = section->GetLinkedSection();
        auto infoSection = section->GetInfoSection();
        auto infoData = section->GetInfoData();
        if (const auto value = arguments.FindMember("newSection"); value != arguments.MemberEnd())
            name.assign(value->value.GetString(), value->value.GetStringLength());
        if (name != currentName && state->view->GetSectionByName(name))
            throw std::invalid_argument("destination section already exists");
        if (const auto value = arguments.FindMember("start"); value != arguments.MemberEnd())
            start = parseExpression(value->value);
        if (const auto value = arguments.FindMember("length"); value != arguments.MemberEnd())
            length = value->value.IsUint64() ? value->value.GetUint64() : parseExpression(value->value);
        if (length > std::numeric_limits<std::uint64_t>::max() - start)
            throw std::invalid_argument("section range overflows");
        if (const auto value = arguments.FindMember("semantics"); value != arguments.MemberEnd())
            semantics = ParseSectionSemantics(
                {value->value.GetString(), value->value.GetStringLength()});
        if (const auto value = arguments.FindMember("typeName"); value != arguments.MemberEnd())
            typeName.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("alignment"); value != arguments.MemberEnd())
            alignment = value->value.GetUint64();
        if (const auto value = arguments.FindMember("entrySize"); value != arguments.MemberEnd())
            entrySize = value->value.GetUint64();
        if (const auto value = arguments.FindMember("linkedSection"); value != arguments.MemberEnd())
            linkedSection.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("infoSection"); value != arguments.MemberEnd())
            infoSection.assign(value->value.GetString(), value->value.GetStringLength());
        if (const auto value = arguments.FindMember("infoData"); value != arguments.MemberEnd())
            infoData = value->value.GetUint64();
        const bool autoDefined = section->AutoDefined();
        if (autoDefined) state->view->RemoveAutoSection(currentName);
        else state->view->RemoveUserSection(currentName);
        if (autoDefined)
            state->view->AddAutoSection(name, start, length, semantics, typeName, alignment,
                entrySize, linkedSection, infoSection, infoData);
        else
            state->view->AddUserSection(name, start, length, semantics, typeName, alignment,
                entrySize, linkedSection, infoSection, infoData);
        const auto startText = HexAddress(start);
        const auto endText = HexAddress(start + length);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("section"); writer.StartObject();
        writer.Key("name"); writer.String(name.data(), name.size());
        writer.Key("start"); writer.String(startText.data(), startText.size());
        writer.Key("end"); writer.String(endText.data(), endText.size());
        writer.Key("semantics"); writer.String(SectionSemanticsName(semantics));
        writer.EndObject(); writer.EndObject();
        ipc::Reply reply;
        reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize());
        return reply;
    }

    ipc::Reply NativeMutation(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments; arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject()) throw std::invalid_argument("mutation arguments must be an object");
        auto parse = [&](const char* name, bool required = true, std::uint64_t fallback = 0) {
            const auto value = arguments.FindMember(name);
            if (value == arguments.MemberEnd()) { if (required) throw std::invalid_argument(std::string(name) + " is required"); return fallback; }
            std::uint64_t result = 0; std::string error;
            if (!value->value.IsString() || !BinaryNinja::BinaryView::ParseExpression(state->view,
                    std::string(value->value.GetString(), value->value.GetStringLength()), result, 0, error))
                throw std::invalid_argument(error.empty() ? std::string("invalid ") + name : error);
            return result;
        };
        auto exactUserSegment = [&](std::uint64_t start, std::uint64_t length) {
            for (const auto& segment : state->view->GetSegments())
                if (segment->GetStart() == start && segment->GetLength() == length && !segment->IsAutoDefined()) return segment;
            return BinaryNinja::Ref<BinaryNinja::Segment>();
        };
        const auto name = command.name();
        rapidjson::StringBuffer buffer; rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("operation"); writer.String(name.data(), name.size());
        if (name == "bn_function_delete")
        {
            const auto function = ResolveFunction(state, arguments);
            const auto address = function->GetStart(); state->view->RemoveUserFunction(function);
            writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size());
            writer.Key("deleted"); writer.Bool(true);
        }
        else if (name == "bn_string_define")
        {
            const auto address = parse("address"), length = parse("length");
            if (length == 0 || !state->view->IsValidOffset(address) || !state->view->IsValidOffset(address + length - 1))
                throw std::invalid_argument("string range must be non-empty and mapped");
            const auto encoding = std::string(arguments["encoding"].GetString(), arguments["encoding"].GetStringLength());
            std::size_t width = encoding == "utf16" ? 2 : encoding == "utf32" ? 4 : 1;
            if (length % width != 0) throw std::invalid_argument("string length is not aligned to its encoding width");
            auto element = width == 1 ? BinaryNinja::Type::IntegerType(1, true, "char") : BinaryNinja::Type::WideCharType(width);
            state->view->DefineUserDataVariable(address, BinaryNinja::Type::ArrayType(element, length / width));
            writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size());
            writer.Key("length"); writer.Uint64(length); writer.Key("encoding"); writer.String(encoding.data(), encoding.size());
        }
        else if (name == "bn_string_undefine")
        {
            const auto address = parse("address"); state->view->UndefineUserDataVariable(address);
            writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size()); writer.Key("undefined"); writer.Bool(true);
        }
        else if (name == "bn_binary_view_rebase")
        {
            const auto address = parse("address");
            if (!file_->Rebase(state->view.GetPtr(), address)) throw std::runtime_error("Binary Ninja rejected the rebase");
            writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size()); writer.Key("rebased"); writer.Bool(true);
        }
        else
        {
            const auto operation = name == "bn_memory_map_preview"
                ? std::string(arguments["operation"].GetString(), arguments["operation"].GetStringLength()) : name;
            const bool remove = operation == "delete" || operation == "bn_segment_delete";
            const bool modify = operation == "modify" || operation == "bn_segment_modify";
            const bool create = operation == "create" || operation == "bn_segment_create";
            const bool rebase = operation == "rebase";
            if (!remove && !modify && !create && !rebase) throw std::invalid_argument("operation must be create, modify, delete, or rebase");
            if (name == "bn_memory_map_preview")
            {
                writer.Key("valid"); writer.Bool(true); writer.Key("mutated"); writer.Bool(false);
                if (rebase) { const auto address = parse("address"); writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size()); }
                else { const auto start = parse("start"), length = parse("length"); writer.Key("existingUserSegment"); writer.Bool(static_cast<bool>(exactUserSegment(start, length))); }
            }
            else
            {
                const auto start = parse("start"), length = parse("length");
                if (length == 0) throw std::invalid_argument("segment length must be nonzero");
                if ((remove || modify) && !exactUserSegment(start, length)) throw std::invalid_argument("exact user segment not found");
                if (remove || modify) state->view->RemoveUserSegment(start, length);
                std::uint64_t resultStart = start, resultLength = length;
                if (!remove)
                {
                    if (modify) { resultStart = parse("newStart", false, start); resultLength = parse("newLength", false, length); }
                    const auto dataOffset = parse("dataOffset"), dataLength = parse("dataLength");
                    if (resultLength == 0 || dataLength > resultLength) throw std::invalid_argument("segment lengths are invalid");
                    const auto flags = arguments["flags"].GetUint();
                    state->view->AddUserSegment(resultStart, resultLength, dataOffset, dataLength, flags);
                    writer.Key("flags"); writer.Uint(flags);
                }
                writer.Key("start"); const auto startText = HexAddress(resultStart); writer.String(startText.data(), startText.size());
                writer.Key("length"); writer.Uint64(resultLength); writer.Key("deleted"); writer.Bool(remove);
            }
        }
        writer.Key("nextAction"); writer.String("Run bn_analysis_update_and_wait when analysis semantics changed, then bn_binary_view_save to persist the mutation.");
        writer.EndObject(); ipc::Reply reply; reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize()); return reply;
    }

    ipc::Reply TransactionTool(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        const auto name = command.name();
        if (name == "bn_transaction_begin")
        {
            if (activeUndoId_) throw std::runtime_error("an explicit transaction is already active for this open item");
            activeUndoId_ = state->view->BeginUndoActions(false);
            if (activeUndoId_->empty()) { activeUndoId_.reset(); throw std::runtime_error("Binary Ninja did not create an undo transaction"); }
            activeUndoView_ = command.view_type();
        }
        else if (name == "bn_transaction_commit" || name == "bn_transaction_rollback")
        {
            if (!activeUndoId_ || activeUndoView_ != command.view_type())
                throw std::runtime_error("no active transaction exists for this BinaryView");
            if (name == "bn_transaction_commit") state->view->CommitUndoActions(*activeUndoId_);
            else state->view->RevertUndoActions(*activeUndoId_);
            activeUndoId_.reset(); activeUndoView_.clear();
        }
        else
        {
            if (activeUndoId_) throw std::runtime_error("commit or roll back the active transaction before undo or redo");
            const bool undo = name == "bn_undo";
            if (undo ? !state->view->CanUndo() : !state->view->CanRedo())
                throw std::runtime_error(undo ? "nothing is available to undo" : "nothing is available to redo");
            if (!(undo ? state->view->Undo() : state->view->Redo()))
                throw std::runtime_error(undo ? "undo failed" : "redo failed");
        }
        rapidjson::StringBuffer buffer; rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject(); writer.Key("operation"); writer.String(name.data(), name.size());
        writer.Key("active"); writer.Bool(activeUndoId_.has_value());
        if (activeUndoId_) { writer.Key("coreTransactionId"); writer.String(activeUndoId_->data(), activeUndoId_->size()); }
        writer.Key("canUndo"); writer.Bool(state->view->CanUndo()); writer.Key("canRedo"); writer.Bool(state->view->CanRedo());
        writer.EndObject(); ipc::Reply reply; reply.set_success(true);
        reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize()); return reply;
    }

    ipc::Reply AnnotationTool(const ipc::ExecuteAnalysisTool& command)
    {
        const auto state = View(command.view_type());
        rapidjson::Document arguments; arguments.Parse(command.arguments_json().data(), command.arguments_json().size());
        if (!arguments.IsObject()) throw std::invalid_argument("annotation arguments must be an object");
        auto stringArg = [&](const char* key, bool required = true) {
            const auto value = arguments.FindMember(key);
            if (value == arguments.MemberEnd()) { if (required) throw std::invalid_argument(std::string(key) + " is required"); return std::string{}; }
            if (!value->value.IsString()) throw std::invalid_argument(std::string(key) + " must be a string");
            return std::string(value->value.GetString(), value->value.GetStringLength());
        };
        auto addressArg = [&] {
            const auto expression = stringArg("address"); std::uint64_t address = 0; std::string error;
            if (!BinaryNinja::BinaryView::ParseExpression(state->view, expression, address, 0, error))
                throw std::invalid_argument(error.empty() ? "invalid address" : error);
            if (!state->view->IsValidOffset(address)) throw std::invalid_argument("address is not mapped");
            return address;
        };
        std::function<BinaryNinja::Ref<BinaryNinja::Metadata>(const rapidjson::Value&)> metadata =
            [&](const rapidjson::Value& value) -> BinaryNinja::Ref<BinaryNinja::Metadata> {
                if (value.IsNull()) throw std::invalid_argument("Binary Ninja metadata cannot represent JSON null");
                if (value.IsBool()) return new BinaryNinja::Metadata(value.GetBool());
                if (value.IsUint64()) return new BinaryNinja::Metadata(value.GetUint64());
                if (value.IsInt64()) return new BinaryNinja::Metadata(value.GetInt64());
                if (value.IsNumber()) return new BinaryNinja::Metadata(value.GetDouble());
                if (value.IsString()) return new BinaryNinja::Metadata(std::string(value.GetString(), value.GetStringLength()));
                if (value.IsArray()) { std::vector<BinaryNinja::Ref<BinaryNinja::Metadata>> values; for (const auto& item : value.GetArray()) values.push_back(metadata(item)); return new BinaryNinja::Metadata(values); }
                std::map<std::string, BinaryNinja::Ref<BinaryNinja::Metadata>> values;
                for (const auto& item : value.GetObject()) values.emplace(std::string(item.name.GetString(), item.name.GetStringLength()), metadata(item.value));
                return new BinaryNinja::Metadata(values);
            };
        const auto name = command.name();
        rapidjson::StringBuffer buffer; rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        if (name.starts_with("bn_metadata_"))
        {
            const auto key = stringArg("key");
            if (key.empty() || key.size() > 256) throw std::invalid_argument("key must contain 1 through 256 bytes");
            const auto namespaced = "binjad.user." + key;
            writer.Key("key"); writer.String(key.data(), key.size());
            if (name == "bn_metadata_set")
            {
                state->view->StoreMetadata(namespaced, metadata(arguments["value"]));
                writer.Key("value"); arguments["value"].Accept(writer);
            }
            else if (name == "bn_metadata_delete")
            { state->view->RemoveMetadata(namespaced); writer.Key("deleted"); writer.Bool(true); }
            else
            {
                const auto value = state->view->QueryMetadata(namespaced);
                if (!value) throw std::invalid_argument("custom metadata key not found");
                const auto json = value->GetJsonString(); rapidjson::Document parsed; parsed.Parse(json.data(), json.size());
                if (parsed.HasParseError()) throw std::runtime_error("stored metadata is not valid JSON");
                writer.Key("value"); parsed.Accept(writer);
            }
        }
        else
        {
            const bool bookmark = name.starts_with("bn_bookmark_");
            std::vector<BinaryNinja::Ref<BinaryNinja::TagType>> types;
            for (const auto& type : state->view->GetTagTypes())
                if (type->GetType() == (bookmark ? BookmarksTagType : UserTagType)) types.push_back(type);
            if (name.ends_with("_create"))
            {
                const auto address = addressArg();
                const auto typeName = bookmark ? std::string("Bookmarks") : stringArg("type");
                auto type = state->view->GetTagType(typeName, bookmark ? BookmarksTagType : UserTagType);
                if (!type) { type = new BinaryNinja::TagType(state->view.GetPtr(), typeName, bookmark ? "B" : stringArg("icon", false), true, bookmark ? BookmarksTagType : UserTagType); state->view->AddTagType(type); }
                const auto data = bookmark ? stringArg("note", false) : stringArg("data", false);
                const auto tag = state->view->CreateUserDataTag(address, type, data, false);
                writer.Key("id"); const auto id = tag->GetId(); writer.String(id.data(), id.size());
                writer.Key("address"); const auto text = HexAddress(address); writer.String(text.data(), text.size());
                writer.Key("type"); writer.String(typeName.data(), typeName.size()); writer.Key(bookmark ? "note" : "data"); writer.String(data.data(), data.size());
            }
            else if (name.ends_with("_delete"))
            {
                const auto id = stringArg("id"); bool removed = false;
                for (const auto& type : types) for (const auto& ref : state->view->GetAllTagReferencesOfType(type))
                    if (!ref.autoDefined && ref.tag->GetId() == id && ref.refType == DataTagReference)
                    { state->view->RemoveUserDataTag(ref.addr, ref.tag); removed = true; }
                if (!removed) throw std::invalid_argument(bookmark ? "bookmark not found" : "tag not found");
                writer.Key("id"); writer.String(id.data(), id.size()); writer.Key("deleted"); writer.Bool(true);
            }
            else
            {
                const auto query = Lower(stringArg("query", false)); const auto typeFilter = stringArg("type", false);
                std::size_t offset = 0, limit = 50;
                if (arguments.HasMember("offset")) offset = arguments["offset"].GetUint64();
                if (arguments.HasMember("limit")) limit = arguments["limit"].GetUint64();
                std::vector<BinaryNinja::TagReference> refs;
                for (const auto& type : types) if (typeFilter.empty() || type->GetName() == typeFilter)
                    for (const auto& ref : state->view->GetAllTagReferencesOfType(type))
                        if (!ref.autoDefined && (query.empty() || Lower(ref.tag->GetData()).find(query) != std::string::npos)) refs.push_back(ref);
                std::sort(refs.begin(), refs.end(), [](const auto& a, const auto& b) { return a.addr < b.addr || (a.addr == b.addr && a.tag->GetId() < b.tag->GetId()); });
                offset = std::min(offset, refs.size()); const auto end = offset + std::min(limit, refs.size() - offset);
                writer.Key(bookmark ? "bookmarks" : "tags"); writer.StartArray();
                for (std::size_t i = offset; i < end; ++i) { const auto& ref = refs[i]; writer.StartObject(); const auto id = ref.tag->GetId(); writer.Key("id"); writer.String(id.data(), id.size()); const auto text = HexAddress(ref.addr); writer.Key("address"); writer.String(text.data(), text.size()); const auto typeName = ref.tag->GetType()->GetName(); writer.Key("type"); writer.String(typeName.data(), typeName.size()); const auto data = ref.tag->GetData(); writer.Key(bookmark ? "note" : "data"); writer.String(data.data(), data.size()); writer.EndObject(); }
                writer.EndArray(); writer.Key("count"); writer.Uint64(end - offset); writer.Key("total"); writer.Uint64(refs.size()); writer.Key("nextOffset"); if (end < refs.size()) writer.Uint64(end); else writer.Null(); writer.Key("truncated"); writer.Bool(end < refs.size());
            }
        }
        writer.EndObject(); ipc::Reply reply; reply.set_success(true); reply.mutable_analysis_tool_result()->set_json(buffer.GetString(), buffer.GetSize()); return reply;
    }

    void Abort(const std::string& viewType)
    {
        const auto state = View(viewType);
        {
            std::lock_guard lock(viewMutex_);
            if (!state->analysisActive || activeAnalysisView_ != viewType)
                throw std::runtime_error("no analysis is active for this BinaryView");
            state->abortRequested = true;
        }
        state->view->AbortAnalysis();
    }

    void Close(bool discard)
    {
        if (!file_)
            return;
        if (activeUndoId_)
        {
            if (!discard) throw std::runtime_error("file has an active transaction; explicit discard is required");
            file_->RevertUndoActions(*activeUndoId_);
            activeUndoId_.reset(); activeUndoView_.clear();
        }
        if (!discard && (file_->IsModified() || file_->IsAnalysisChanged()))
            throw std::runtime_error("file has uncommitted state; explicit discard is required");

        diffTools_.Close();
        struct ClosingView
        {
            std::shared_ptr<ViewState> state;
            bool analysisActive;
        };
        std::vector<ClosingView> states;
        {
            std::lock_guard lock(viewMutex_);
            for (const auto& [name, state] : views_)
            {
                state->abortRequested = state->analysisActive;
                states.push_back({state, state->analysisActive});
                state->analysisActive = false;
            }
            activeAnalysisView_.clear();
        }
        for (const auto& closing : states)
        {
            if (closing.analysisActive)
                closing.state->view->AbortAnalysis();
            for (const auto& event : closing.state->completionEvents)
            {
                if (event)
                    event->Cancel();
            }
            pluginTools_.Close(*closing.state->view);
        }
        {
            std::lock_guard lock(viewMutex_);
            views_.clear();
        }
        file_->Close();
        candidates_.clear();
        candidateOrder_.clear();
        data_ = nullptr;
        file_ = nullptr;
        databaseBacked_ = false;
        snapshotApplied_ = false;
        reuseDatabase_ = false;
        loadOptions_.clear();
        openedPath_.clear();
    }

    void Dispatch(const ipc::Envelope& envelope, bool& running)
    {
        currentRequest_ = envelope.request_id();
        const auto& command = envelope.command();
        try
        {
            ipc::Reply reply;
            std::optional<std::string> analysisView;
            switch (command.action_case())
            {
                case ipc::Command::kOpenFile:
                    reply = OpenFile(command.open_file());
                    break;
                case ipc::Command::kOpenBinaryView:
                    reply = OpenBinaryView(command.open_binary_view());
                    if (command.open_binary_view().analyze())
                        analysisView = command.open_binary_view().view_type();
                    break;
                case ipc::Command::kSaveBinaryView:
                    reply = SaveBinaryView(command.save_binary_view());
                    break;
                case ipc::Command::kExecuteAnalysisTool:
                    if (command.execute_analysis_tool().name() == "bn_diff_run")
                    {
                        const auto& tool = command.execute_analysis_tool();
                        const auto state = View(tool.view_type());
                        {
                            std::lock_guard lock(viewMutex_);
                            if (state->analysisActive)
                                throw std::runtime_error("primary analysis is still active");
                        }
                        const auto origin = envelope.request_id();
                        const auto json = diffTools_.Begin(state->view, tool.diff_key(),
                            tool.secondary_path(),
                            [this, origin](double value) {
                                SendProgress(origin, "diff", static_cast<std::size_t>(value * 1000.0), 1000);
                            },
                            [this, origin](bool success, std::string error) {
                                try
                                {
                                    SendEvent(origin, success ? ipc::ANALYSIS_STATE_COMPLETE :
                                        ipc::ANALYSIS_STATE_ABORTED, error);
                                }
                                catch (...)
                                {}
                            });
                        reply.set_success(true);
                        reply.mutable_analysis_tool_result()->set_json(json);
                    }
                    else if (command.execute_analysis_tool().name().starts_with("bn_diff_") ||
                        command.execute_analysis_tool().name() == "binjad_internal_diff_release")
                    {
                        const auto& tool = command.execute_analysis_tool();
                        const auto state = View(tool.view_type());
                        const auto json = diffTools_.Execute(tool.name(), state->view,
                            tool.diff_key(), tool.arguments_json());
                        reply.set_success(true);
                        reply.mutable_analysis_tool_result()->set_json(json);
                    }
                    else if (command.execute_analysis_tool().name().starts_with("bn_kernel_cache_") ||
                        command.execute_analysis_tool().name().starts_with("bn_shared_cache_") ||
                        command.execute_analysis_tool().name().starts_with("bn_debugger_"))
                    {
                        const auto& tool = command.execute_analysis_tool();
                        auto view = View(tool.view_type());
                        const auto json = pluginTools_.Execute(
                            tool.name(), *view->view, tool.arguments_json());
                        reply.set_success(true);
                        reply.mutable_analysis_tool_result()->set_json(json);
                    }
                    else if (command.execute_analysis_tool().name() == "bn_function_list")
                        reply = FunctionList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_info")
                        reply = FunctionInfo(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_create")
                        reply = FunctionCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_callers")
                        reply = FunctionCallers(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_callees")
                        reply = FunctionCallees(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_disassembly")
                        reply = FunctionDisassembly(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_decompile")
                        reply = FunctionDecompile(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_il")
                        reply = FunctionIL(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_stack_layout")
                        reply = FunctionStackLayout(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_variable_list")
                        reply = VariableList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_calling_convention_list")
                        reply = CallingConventionList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_xrefs_from")
                        reply = FunctionXrefsFrom(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_xrefs_to")
                        reply = FunctionXrefsTo(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_string_list")
                        reply = StringList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_string_at")
                        reply = StringAt(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_symbol_list")
                        reply = SymbolList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_import_list")
                        reply = SymbolList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_export_list")
                        reply = SymbolList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_symbol_list_at")
                        reply = SymbolListAt(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_entry_point_list")
                        reply = EntryPointList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_entry_point_add")
                        reply = EntryPointAdd(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_section_list")
                        reply = SectionList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_segment_list")
                        reply = SegmentList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_memory_read")
                        reply = MemoryRead(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_variable_list")
                        reply = DataVariableList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_at")
                        reply = DataAt(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_relocation_list")
                        reply = RelocationList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_xrefs_from")
                        reply = DataXrefsFrom(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_xrefs_to")
                        reply = DataXrefsFrom(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_comment_get")
                        reply = CommentGet(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_comment_list" ||
                        command.execute_analysis_tool().name() == "bn_comment_search" ||
                        command.execute_analysis_tool().name() == "bn_memory_search" ||
                        command.execute_analysis_tool().name() == "bn_instruction_search" ||
                        command.execute_analysis_tool().name() == "bn_il_search" ||
                        command.execute_analysis_tool().name() == "bn_constant_search" ||
                        command.execute_analysis_tool().name() == "bn_project_analysis_search")
                        reply = SearchTool(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_comment_set")
                        reply = CommentSet(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_comment_delete")
                        reply = CommentDelete(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_symbol_define")
                        reply = SymbolDefine(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_symbol_rename")
                        reply = SymbolRename(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_symbol_undefine")
                        reply = SymbolUndefine(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_function_prototype_set")
                        reply = FunctionPrototypeSet(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_calling_convention_set")
                        reply = CallingConventionSet(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_variable_rename")
                        reply = VariableRename(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_variable_set_type")
                        reply = VariableSetType(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_list")
                        reply = TypeList(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_info")
                        reply = TypeInfo(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_parse")
                        reply = TypeParse(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_define")
                        reply = TypeDefine(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_struct_create")
                        reply = TypeStructCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_struct_modify")
                        reply = TypeStructCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_union_create")
                        reply = TypeStructCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_union_modify")
                        reply = TypeStructCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_enum_create")
                        reply = TypeEnumCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_enum_modify")
                        reply = TypeEnumCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_delete")
                        reply = TypeDelete(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_rename")
                        reply = TypeRename(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_xrefs_from")
                        reply = TypeXrefsFrom(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_type_xrefs_to")
                        reply = TypeXrefsTo(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_variable_define")
                        reply = DataVariableDefine(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_data_variable_undefine")
                        reply = DataVariableUndefine(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_section_create")
                        reply = SectionCreate(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_section_delete")
                        reply = SectionDelete(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_section_modify")
                        reply = SectionModify(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_transaction_begin" ||
                        command.execute_analysis_tool().name() == "bn_transaction_commit" ||
                        command.execute_analysis_tool().name() == "bn_transaction_rollback" ||
                        command.execute_analysis_tool().name() == "bn_undo" ||
                        command.execute_analysis_tool().name() == "bn_redo")
                        reply = TransactionTool(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_bookmark_create" ||
                        command.execute_analysis_tool().name() == "bn_bookmark_list" ||
                        command.execute_analysis_tool().name() == "bn_bookmark_delete" ||
                        command.execute_analysis_tool().name() == "bn_tag_create" ||
                        command.execute_analysis_tool().name() == "bn_tag_list" ||
                        command.execute_analysis_tool().name() == "bn_tag_delete" ||
                        command.execute_analysis_tool().name() == "bn_metadata_get" ||
                        command.execute_analysis_tool().name() == "bn_metadata_set" ||
                        command.execute_analysis_tool().name() == "bn_metadata_delete")
                        reply = AnnotationTool(command.execute_analysis_tool());
                    else if (command.execute_analysis_tool().name() == "bn_segment_create" ||
                        command.execute_analysis_tool().name() == "bn_segment_modify" ||
                        command.execute_analysis_tool().name() == "bn_segment_delete" ||
                        command.execute_analysis_tool().name() == "bn_binary_view_rebase" ||
                        command.execute_analysis_tool().name() == "bn_memory_map_preview" ||
                        command.execute_analysis_tool().name() == "bn_function_delete" ||
                        command.execute_analysis_tool().name() == "bn_string_define" ||
                        command.execute_analysis_tool().name() == "bn_string_undefine")
                        reply = NativeMutation(command.execute_analysis_tool());
                    else
                        throw std::invalid_argument("analysis tool is not implemented");
                    break;
                case ipc::Command::kCloseFile:
                    Close(command.close_file().discard_uncommitted());
                    reply.set_success(true);
                    break;
                case ipc::Command::kSetWorkerCount:
                    if (command.set_worker_count().count() == 0)
                        throw std::invalid_argument("worker count must be greater than zero");
                    BinaryNinja::SetWorkerThreadCount(command.set_worker_count().count());
                    reply.set_success(true);
                    break;
                case ipc::Command::kUpdateAnalysis:
                    View(command.update_analysis().view_type());
                    reply.set_success(true);
                    analysisView = command.update_analysis().view_type();
                    break;
                case ipc::Command::kGetAnalysisStatus:
                    reply = AnalysisStatus(command.get_analysis_status().view_type());
                    break;
                case ipc::Command::kAbortAnalysis:
                    Abort(command.abort_analysis().view_type());
                    reply.set_success(true);
                    break;
                case ipc::Command::kShutdown:
                    Close(true);
                    reply.set_success(true);
                    running = false;
                    break;
                case ipc::Command::kScanLocalProjects:
                case ipc::Command::kListLocalProjectFiles:
                case ipc::Command::kExportLocalProjectFile:
                case ipc::Command::kCommitLocalProjectFile:
                case ipc::Command::kCreateLocalProject:
                case ipc::Command::kUpdateLocalProject:
                case ipc::Command::kListLocalProjectFolders:
                case ipc::Command::kCreateLocalProjectFolder:
                case ipc::Command::kUpdateLocalProjectFolder:
                case ipc::Command::kDeleteLocalProjectFolder:
                case ipc::Command::kUpdateLocalProjectFile:
                case ipc::Command::kDeleteLocalProjectFile:
                case ipc::Command::kDeleteLocalProject:
                case ipc::Command::kConfigureCollaboration:
                case ipc::Command::kListCollaborationProjects:
                case ipc::Command::kListCollaborationFiles:
                case ipc::Command::kDownloadCollaborationFile:
                case ipc::Command::kSaveCollaborationDatabase:
                case ipc::Command::kUploadCollaborationFile:
                    throw std::invalid_argument("project command is not valid for a file child");
                case ipc::Command::ACTION_NOT_SET:
                    throw std::invalid_argument("command has no action");
            }
            SendReply(envelope.request_id(), std::move(reply));
            if (analysisView)
            {
                try
                {
                    StartAnalysis(*analysisView, envelope.request_id());
                }
                catch (const std::exception& exception)
                {
                    SendEvent(envelope.request_id(), ipc::ANALYSIS_STATE_FAILED, exception.what());
                }
            }
        }
        catch (const std::exception& exception)
        {
            SendFailure(envelope.request_id(), exception.what());
        }
    }

    void SendReply(std::uint64_t requestId, ipc::Reply reply)
    {
        ipc::Envelope envelope;
        envelope.set_protocol_version(ipc::kProtocolVersion);
        envelope.set_request_id(requestId);
        *envelope.mutable_reply() = std::move(reply);
        Send(envelope);
    }

    void SendFailure(std::uint64_t requestId, std::string_view error)
    {
        ipc::Reply reply;
        reply.set_success(false);
        reply.set_error(error.data(), error.size());
        SendReply(requestId, std::move(reply));
    }

    void SendProgress(std::uint64_t origin, std::string_view phase,
        std::size_t completed, std::size_t total)
    {
        ipc::Envelope envelope;
        envelope.set_protocol_version(ipc::kProtocolVersion);
        envelope.set_request_id(0);
        auto* event = envelope.mutable_event();
        event->set_originating_request_id(origin);
        auto* progress = event->mutable_progress();
        progress->set_phase(phase.data(), phase.size());
        progress->set_completed(completed);
        progress->set_total(total);
        Send(envelope);
    }

    void SendEvent(std::uint64_t origin, ipc::AnalysisState state, std::string_view error)
    {
        ipc::Envelope envelope;
        envelope.set_protocol_version(ipc::kProtocolVersion);
        envelope.set_request_id(0);
        auto* event = envelope.mutable_event();
        event->set_originating_request_id(origin);
        auto* finished = event->mutable_analysis_finished();
        finished->set_state(state);
        if (!error.empty())
            finished->set_error(error.data(), error.size());
        Send(envelope);
    }

    void Send(const ipc::Envelope& envelope)
    {
        std::lock_guard lock(sendMutex_);
        ipc::SendEnvelope(*channel_, envelope);
    }

    std::unique_ptr<ipc::ByteChannel> channel_;
    BinaryNinjaRuntime runtime_;
    binary_ninja::DiffTools diffTools_;
    binary_ninja::PluginTools pluginTools_;
    BinaryNinja::Ref<BinaryNinja::FileMetadata> file_;
    BinaryNinja::Ref<BinaryNinja::BinaryView> data_;
    std::unordered_map<std::string, Candidate> candidates_;
    std::vector<std::string> candidateOrder_;
    mutable std::mutex viewMutex_;
    std::unordered_map<std::string, std::shared_ptr<ViewState>> views_;
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
}

int RunFileChild(std::unique_ptr<ipc::ByteChannel> channel)
{
    if (!channel)
        return EXIT_FAILURE;
    try
    {
        FileChild child(std::move(channel));
        return child.Run();
    }
    catch (...)
    {
        return EXIT_FAILURE;
    }
}
}
