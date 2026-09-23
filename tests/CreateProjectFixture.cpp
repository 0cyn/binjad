#include "binjad/binary_ninja/runtime.hpp"

#include <binaryninjaapi.h>

#include <filesystem>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 2)
        return EXIT_FAILURE;
    try
    {
        binjad::BinaryNinjaRuntime runtime(true);
        const auto root = std::filesystem::path(argv[1]);
        std::filesystem::create_directories(root);
        auto project = BinaryNinja::Project::CreateProject(
            (root / "Example.bnpr").string(), "Example");
        if (!project)
            throw std::runtime_error("cannot create project fixture");
        auto file = project->CreateFileFromPath(
            "/usr/bin/true", nullptr, "true", "Integration fixture");
        if (!file)
            throw std::runtime_error("cannot import project fixture file");
        file = nullptr;
        if (!project->Close())
            throw std::runtime_error("cannot close project fixture");
        project = nullptr;
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
