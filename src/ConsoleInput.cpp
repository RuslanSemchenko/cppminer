#include "ConsoleInput.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace cppminer {
namespace {

std::thread g_keyThread;
std::atomic<bool> g_keyStop{false};
std::function<void()> g_onHashrateKey;

bool stdinIsInteractive()
{
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

void keyThreadMain()
{
#ifdef _WIN32
    while (!g_keyStop.load(std::memory_order_relaxed)) {
        if (_kbhit()) {
            const int ch = _getch();
            if (ch == 'h' || ch == 'H')
                if (g_onHashrateKey)
                    g_onHashrateKey();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
#else
    termios oldMode{};
    if (tcgetattr(STDIN_FILENO, &oldMode) != 0)
        return;
    termios rawMode = oldMode;
    rawMode.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
    rawMode.c_cc[VMIN] = 0;
    rawMode.c_cc[VTIME] = 1; // 0.1 s read timeout
    if (tcsetattr(STDIN_FILENO, TCSANOW, &rawMode) != 0)
        return;

    while (!g_keyStop.load(std::memory_order_relaxed)) {
        char ch = 0;
        const ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n == 1 && (ch == 'h' || ch == 'H') && g_onHashrateKey)
            g_onHashrateKey();
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldMode);
#endif
}

} // namespace

void startConsoleKeyWatcher(std::function<void()> onHashrateKey)
{
    stopConsoleKeyWatcher();
    if (!stdinIsInteractive())
        return;
    g_onHashrateKey = std::move(onHashrateKey);
    g_keyStop.store(false, std::memory_order_relaxed);
    g_keyThread = std::thread(keyThreadMain);
}

void stopConsoleKeyWatcher()
{
    g_keyStop.store(true, std::memory_order_relaxed);
    if (g_keyThread.joinable())
        g_keyThread.join();
    g_onHashrateKey = nullptr;
}

} // namespace cppminer
