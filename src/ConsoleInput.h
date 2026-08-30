#pragma once

// Optional stdin watcher: when mining in an interactive terminal, pressing
// 'h' invokes the callback (xmrig-style hashrate snapshot).

#include <functional>

namespace cppminer {

void startConsoleKeyWatcher(std::function<void()> onHashrateKey);
void stopConsoleKeyWatcher();

} // namespace cppminer
