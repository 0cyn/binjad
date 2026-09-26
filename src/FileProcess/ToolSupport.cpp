#include "ToolSupport.hpp"

#include "binjad/binary_ninja/StringCodec.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace binjad::file_process {
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
			result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
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

	std::string RenderTypeDefinition(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name,
		const BinaryNinja::Ref<BinaryNinja::Type>& type)
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

	DetectedStringData ReadDetectedString(
		BinaryNinja::BinaryView* view, BNStringType type, std::uint64_t start, std::size_t length)
	{
		using binary_ninja::DecodeString;
		const auto data = view->ReadBuffer(start, length);
		const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
		DetectedStringData result {type, {}};
		if (bytes && data.GetLength() != 0)
			result.bytes.assign(bytes, bytes + data.GetLength());
		if (type != AsciiString || data.GetLength() != length
			|| length > std::numeric_limits<std::size_t>::max() - 4096)
			return result;

		const auto expanded = view->ReadBuffer(start, length + 4096);
		const auto* expandedBytes = static_cast<const std::uint8_t*>(expanded.GetData());
		if (expanded.GetLength() <= length || expandedBytes[length] < 0x80)
			return result;
		const auto terminator =
			std::find(expandedBytes + length, expandedBytes + expanded.GetLength(), std::uint8_t {0});
		if (terminator == expandedBytes + expanded.GetLength())
			return result;
		const auto expandedLength = static_cast<std::size_t>(terminator - expandedBytes);
		const auto decoded = DecodeString(Utf8String, std::span<const std::uint8_t>(expandedBytes, expandedLength),
			std::numeric_limits<std::size_t>::max());
		if (!decoded.decoded)
			return result;
		result.type = Utf8String;
		result.bytes.assign(expandedBytes, terminator);
		return result;
	}

	std::optional<DetectedStringData> ReadNullTerminatedString(BinaryNinja::BinaryView* view, std::uint64_t start)
	{
		using binary_ninja::DecodeString;
		constexpr std::size_t maximumLength = 4096;
		const auto data = view->ReadBuffer(start, maximumLength);
		const auto* bytes = static_cast<const std::uint8_t*>(data.GetData());
		if (!bytes || data.GetLength() == 0)
			return std::nullopt;
		const auto terminator = std::find(bytes, bytes + data.GetLength(), std::uint8_t {0});
		if (terminator == bytes || terminator == bytes + data.GetLength())
			return std::nullopt;
		if (std::any_of(bytes, terminator, [](std::uint8_t byte) { return byte < 0x20 || byte == 0x7f; }))
			return std::nullopt;
		const auto type =
			std::any_of(bytes, terminator, [](std::uint8_t byte) { return byte >= 0x80; }) ? Utf8String : AsciiString;
		std::vector<std::uint8_t> value(bytes, terminator);
		if (!DecodeString(type, value, std::numeric_limits<std::size_t>::max()).decoded)
			return std::nullopt;
		return DetectedStringData {type, std::move(value)};
	}

	const char* AnalysisSkipReasonName(BNAnalysisSkipReason reason)
	{
		switch (reason)
		{
		case NoSkipReason:
			return "NoSkipReason";
		case AlwaysSkipReason:
			return "AlwaysSkipReason";
		case ExceedFunctionSizeSkipReason:
			return "ExceedFunctionSizeSkipReason";
		case ExceedFunctionAnalysisTimeSkipReason:
			return "ExceedFunctionAnalysisTimeSkipReason";
		case ExceedFunctionUpdateCountSkipReason:
			return "ExceedFunctionUpdateCountSkipReason";
		case NewAutoFunctionAnalysisSuppressedReason:
			return "NewAutoFunctionAnalysisSuppressedReason";
		case BasicAnalysisSkipReason:
			return "BasicAnalysisSkipReason";
		case IntermediateAnalysisSkipReason:
			return "IntermediateAnalysisSkipReason";
		case AnalysisPipelineSuspendedReason:
			return "AnalysisPipelineSuspendedReason";
		}
		return "UnknownSkipReason";
	}

	const char* VariableSourceName(BNVariableSourceType source)
	{
		switch (source)
		{
		case StackVariableSourceType:
			return "stack";
		case RegisterVariableSourceType:
			return "register";
		case FlagVariableSourceType:
			return "flag";
		case CompositeReturnValueSourceType:
			return "compositeReturn";
		case CompositeParameterSourceType:
			return "compositeParameter";
		}
		return "unknown";
	}

	BNVariableSourceType ParseVariableSource(std::string_view source)
	{
		if (source == "stack")
			return StackVariableSourceType;
		if (source == "register")
			return RegisterVariableSourceType;
		if (source == "flag")
			return FlagVariableSourceType;
		if (source == "compositeReturn")
			return CompositeReturnValueSourceType;
		if (source == "compositeParameter")
			return CompositeParameterSourceType;
		throw std::invalid_argument("unknown variable source");
	}

	const char* SymbolTypeName(BNSymbolType type)
	{
		switch (type)
		{
		case FunctionSymbol:
			return "FunctionSymbol";
		case ImportAddressSymbol:
			return "ImportAddressSymbol";
		case ImportedFunctionSymbol:
			return "ImportedFunctionSymbol";
		case DataSymbol:
			return "DataSymbol";
		case ImportedDataSymbol:
			return "ImportedDataSymbol";
		case ExternalSymbol:
			return "ExternalSymbol";
		case LibraryFunctionSymbol:
			return "LibraryFunctionSymbol";
		case SymbolicFunctionSymbol:
			return "SymbolicFunctionSymbol";
		case LocalLabelSymbol:
			return "LocalLabelSymbol";
		}
		return "UnknownSymbol";
	}

	const char* SymbolBindingName(BNSymbolBinding binding)
	{
		switch (binding)
		{
		case NoBinding:
			return "NoBinding";
		case LocalBinding:
			return "LocalBinding";
		case GlobalBinding:
			return "GlobalBinding";
		case WeakBinding:
			return "WeakBinding";
		}
		return "UnknownBinding";
	}

	const char* SectionSemanticsName(BNSectionSemantics semantics)
	{
		switch (semantics)
		{
		case DefaultSectionSemantics:
			return "DefaultSectionSemantics";
		case ReadOnlyCodeSectionSemantics:
			return "ReadOnlyCodeSectionSemantics";
		case ReadOnlyDataSectionSemantics:
			return "ReadOnlyDataSectionSemantics";
		case ReadWriteDataSectionSemantics:
			return "ReadWriteDataSectionSemantics";
		case ExternalSectionSemantics:
			return "ExternalSectionSemantics";
		}
		return "UnknownSectionSemantics";
	}

	BNSectionSemantics ParseSectionSemantics(std::string_view semantics)
	{
		if (semantics == "DefaultSectionSemantics")
			return DefaultSectionSemantics;
		if (semantics == "ReadOnlyCodeSectionSemantics")
			return ReadOnlyCodeSectionSemantics;
		if (semantics == "ReadOnlyDataSectionSemantics")
			return ReadOnlyDataSectionSemantics;
		if (semantics == "ReadWriteDataSectionSemantics")
			return ReadWriteDataSectionSemantics;
		if (semantics == "ExternalSectionSemantics")
			return ExternalSectionSemantics;
		throw std::invalid_argument("unknown section semantics");
	}

	const char* TypeClassName(BNTypeClass type)
	{
		switch (type)
		{
		case VoidTypeClass:
			return "VoidTypeClass";
		case BoolTypeClass:
			return "BoolTypeClass";
		case IntegerTypeClass:
			return "IntegerTypeClass";
		case FloatTypeClass:
			return "FloatTypeClass";
		case StructureTypeClass:
			return "StructureTypeClass";
		case EnumerationTypeClass:
			return "EnumerationTypeClass";
		case PointerTypeClass:
			return "PointerTypeClass";
		case ArrayTypeClass:
			return "ArrayTypeClass";
		case FunctionTypeClass:
			return "FunctionTypeClass";
		case VarArgsTypeClass:
			return "VarArgsTypeClass";
		case ValueTypeClass:
			return "ValueTypeClass";
		case NamedTypeReferenceClass:
			return "NamedTypeReferenceClass";
		case WideCharTypeClass:
			return "WideCharTypeClass";
		case FragmentTypeClass:
			return "FragmentTypeClass";
		}
		return "UnknownTypeClass";
	}

	BNSymbolType ParseSymbolType(std::string_view type)
	{
		if (type == "FunctionSymbol")
			return FunctionSymbol;
		if (type == "ImportAddressSymbol")
			return ImportAddressSymbol;
		if (type == "ImportedFunctionSymbol")
			return ImportedFunctionSymbol;
		if (type == "DataSymbol")
			return DataSymbol;
		if (type == "ImportedDataSymbol")
			return ImportedDataSymbol;
		if (type == "ExternalSymbol")
			return ExternalSymbol;
		if (type == "LibraryFunctionSymbol")
			return LibraryFunctionSymbol;
		if (type == "SymbolicFunctionSymbol")
			return SymbolicFunctionSymbol;
		if (type == "LocalLabelSymbol")
			return LocalLabelSymbol;
		throw std::invalid_argument("unknown symbol type");
	}

	BNSymbolBinding ParseSymbolBinding(std::string_view binding)
	{
		if (binding == "NoBinding")
			return NoBinding;
		if (binding == "LocalBinding")
			return LocalBinding;
		if (binding == "GlobalBinding")
			return GlobalBinding;
		if (binding == "WeakBinding")
			return WeakBinding;
		throw std::invalid_argument("unknown symbol binding");
	}
}  // namespace binjad::file_process
