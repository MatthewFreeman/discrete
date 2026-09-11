#pragma once

#include <stdexcept>
#ifdef _WIN32
#include <Windows.h>
#else
#include <ctime>
#endif

namespace P2pTransportTest {
inline double processCpuSeconds() {
#ifdef _WIN32
  // MSVC's std::clock measures elapsed wall time, not process CPU time.
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
    throw std::runtime_error("Cannot measure process CPU time");
  const auto seconds = [](FILETIME time) {
    ULARGE_INTEGER ticks{};
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    return static_cast<double>(ticks.QuadPart) / 10000000.0;
  };
  return seconds(kernel) + seconds(user);
#else
  const auto ticks = std::clock();
  if (ticks == static_cast<std::clock_t>(-1))
    throw std::runtime_error("Cannot measure process CPU time");
  return static_cast<double>(ticks) / CLOCKS_PER_SEC;
#endif
}
}
