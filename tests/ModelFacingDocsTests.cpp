#include "ModelFacingDocs.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {
	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}
}  // namespace

int main()
{
	try
	{
		const auto& tools = binjad::mcp::docs::Tools();
		Require(tools.size() == 205, "model-facing tool registry count changed");
		for (const auto& [name, documentation] : tools)
		{
			Require(name.starts_with("bn_"), "model-facing tool name is invalid");
			Require(!documentation.category.empty(), "model-facing tool category is empty");
			Require(!documentation.description.empty(), "model-facing tool description is empty");
			for (const auto& [argument, description] : documentation.arguments)
			{
				Require(!argument.empty(), "model-facing argument name is empty");
				Require(!description.empty(), "model-facing argument description is empty");
			}
		}

		Require(binjad::mcp::docs::Categories().size() == 15, "model-facing category registry count changed");
		Require(binjad::mcp::docs::Resources().size() == 7, "model-facing resource registry count changed");
		Require(
			binjad::mcp::docs::FailureContracts().size() == 14, "model-facing failure-contract registry count changed");
		Require(!binjad::mcp::docs::ModernDiscoveryInstructions().empty(), "modern instructions are empty");
		Require(!binjad::mcp::docs::LegacyInitializationInstructions().empty(), "legacy instructions are empty");
		Require(!binjad::mcp::docs::QuickStart().empty(), "quick-start documentation is empty");
		Require(binjad::mcp::docs::QuickStart().find("Thumb vector values") != std::string_view::npos,
			"quick-start raw-firmware guidance is incomplete");
		Require(!binjad::mcp::docs::OpenCodeProjectionBoundary().empty(), "OpenCode boundary is empty");
		Require(!binjad::mcp::docs::ToolArgument("bn_function_decompile", "language").empty(),
			"known argument documentation is unavailable");
		Require(binjad::mcp::docs::ToolArgument("bn_function_decompile", "unknown").empty(),
			"unknown argument documentation was not empty");

		std::cout << "Model-facing documentation tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "Model-facing documentation test failed: " << exception.what() << '\n';
		return 1;
	}
}
