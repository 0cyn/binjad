#include "binjad/launcher/Launcher.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

int main(int argc, char** argv)
{
	try
	{
		binjad::launcher::Launcher launcher(binjad::launcher::Launcher::CurrentExecutablePath());
		return launcher.Run(argc, argv);
	}
	catch (const std::exception& exception)
	{
		std::cerr << "binjad launcher: " << exception.what() << '\n';
		return EXIT_FAILURE;
	}
}
