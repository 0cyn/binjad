#pragma once

#include <string_view>
#include <unordered_map>

namespace binjad::mcp::docs {
	struct ToolDocumentation
	{
		std::string_view category;
		std::string_view description;
		std::unordered_map<std::string_view, std::string_view> arguments;
	};

	struct CategoryDocumentation
	{
		std::string_view name;
		std::string_view description;
	};

	struct ResourceDocumentation
	{
		std::string_view name;
		std::string_view description;
		std::string_view mimeType;
	};

	struct FailureContractDocumentation
	{
		std::string_view when;
		std::string_view surface;
	};

	std::string_view ModernDiscoveryInstructions();
	std::string_view LegacyInitializationInstructions();
	std::string_view QuickStart();
	std::string_view OpenCodeProjectionBoundary();

	const ToolDocumentation& Tool(std::string_view name);
	std::string_view ToolArgument(std::string_view tool, std::string_view argument);
	const std::unordered_map<std::string_view, ToolDocumentation>& Tools();

	const CategoryDocumentation& Category(std::string_view id);
	const std::unordered_map<std::string_view, CategoryDocumentation>& Categories();

	const ResourceDocumentation& Resource(std::string_view uri);
	const std::unordered_map<std::string_view, ResourceDocumentation>& Resources();

	std::string_view Availability(std::string_view id);

	const std::unordered_map<std::string_view, FailureContractDocumentation>& FailureContracts();
}  // namespace binjad::mcp::docs
