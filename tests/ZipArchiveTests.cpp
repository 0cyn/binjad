#include "binjad/download/ZipArchive.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}

	struct Cleanup
	{
		std::filesystem::path path;
		~Cleanup()
		{
			std::error_code ignored;
			std::filesystem::remove_all(path, ignored);
		}
	};
}  // namespace

int main()
{
	try
	{
		const auto root = std::filesystem::current_path() / ".binjad-zip-archive-tests";
		Cleanup cleanup {root};
		std::error_code ignored;
		std::filesystem::remove_all(root, ignored);
		const auto source = root / "source";
		std::filesystem::create_directories(source / "nested" / "empty");
		{
			std::ofstream output(source / "root.bin", std::ios::binary);
			output << "root contents";
		}
		{
			std::ofstream output(source / "nested" / "child.bin", std::ios::binary);
			output << "child contents";
		}
		const auto destination = root / "result.zip";
		const auto result = binjad::download::CreateZipArchive(source, destination);
		Require(result.created, result.error);
		Require(result.files == 2, "ZIP file count changed");
		Require(result.directories == 2, "ZIP directory count changed");
		Require(result.inputBytes == 27, "ZIP input byte count changed");
		Require(result.archiveBytes == std::filesystem::file_size(destination), "ZIP output byte count changed");

		const auto cancelledDestination = root / "cancelled.zip";
		const auto cancelled = binjad::download::CreateZipArchive(
			source, cancelledDestination, [](std::uint64_t, std::uint64_t, std::string_view) { return false; });
		Require(cancelled.cancelled && !cancelled.created, "ZIP cancellation did not stop archive creation");
		Require(!std::filesystem::exists(cancelledDestination), "cancelled ZIP artifact was retained");

		const auto contained = binjad::download::CreateZipArchive(source, source / "contained.zip");
		Require(!contained.created && !std::filesystem::exists(source / "contained.zip"),
			"ZIP destination inside the source directory was accepted");

		std::filesystem::create_symlink(source / "root.bin", source / "unsafe-link");
		const auto linkedDestination = root / "linked.zip";
		const auto linked = binjad::download::CreateZipArchive(source, linkedDestination);
		Require(!linked.created && !std::filesystem::exists(linkedDestination),
			"ZIP source containing a symbolic link was accepted");

		std::filesystem::remove(source / "unsafe-link");
		{
			std::ofstream output(source / "CON.txt", std::ios::binary);
			output << "reserved name";
		}
		const auto reservedDestination = root / "reserved.zip";
		const auto reserved = binjad::download::CreateZipArchive(source, reservedDestination);
		Require(!reserved.created && !std::filesystem::exists(reservedDestination),
			"ZIP source containing a reserved cross-platform path was accepted");
		std::cout << "ZIP archive tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "ZIP archive tests failed: " << exception.what() << '\n';
		return 1;
	}
}
