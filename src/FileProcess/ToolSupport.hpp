#pragma once

#include <binaryninjaapi.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::file_process {
	inline constexpr std::size_t kDefaultListLimit = 50;
	inline constexpr std::size_t kDefaultRenderLimit = 200;

	std::string HexAddress(std::uint64_t value);
	std::string Lower(std::string value);
	std::string NormalizedName(std::string_view value);
	BinaryNinja::QualifiedName QualifiedNameFromString(std::string_view name);
	std::string TokenText(const std::vector<BinaryNinja::InstructionTextToken>& tokens);
	std::string RenderTypeDefinition(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name,
		const BinaryNinja::Ref<BinaryNinja::Type>& type);

	struct DetectedStringData
	{
		BNStringType type;
		std::vector<std::uint8_t> bytes;
	};

	DetectedStringData ReadDetectedString(
		BinaryNinja::BinaryView* view, BNStringType type, std::uint64_t start, std::size_t length);
	std::optional<DetectedStringData> ReadNullTerminatedString(BinaryNinja::BinaryView* view, std::uint64_t start);

	const char* AnalysisSkipReasonName(BNAnalysisSkipReason reason);
	const char* VariableSourceName(BNVariableSourceType source);
	BNVariableSourceType ParseVariableSource(std::string_view source);
	const char* SymbolTypeName(BNSymbolType type);
	const char* SymbolBindingName(BNSymbolBinding binding);
	const char* SectionSemanticsName(BNSectionSemantics semantics);
	BNSectionSemantics ParseSectionSemantics(std::string_view semantics);
	std::vector<std::string_view> SegmentFlagNames(std::uint32_t flags);
	const char* TypeClassName(BNTypeClass type);
	BNSymbolType ParseSymbolType(std::string_view type);
	BNSymbolBinding ParseSymbolBinding(std::string_view binding);
}  // namespace binjad::file_process
