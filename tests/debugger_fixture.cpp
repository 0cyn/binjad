#include <chrono>
#include <thread>

extern "C" volatile int binjad_debugger_fixture_value = 7;

int main()
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    return binjad_debugger_fixture_value == 7 ? 0 : 1;
}
