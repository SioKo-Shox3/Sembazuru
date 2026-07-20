#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>

namespace {
bool ParseCount(const wchar_t* text, unsigned long long* value) {
    wchar_t* end = nullptr;
    const unsigned long long parsed = std::wcstoull(text, &end, 10);
    if (text[0] == L'\0' || end == nullptr || *end != L'\0' || parsed == 0) {
        return false;
    }
    *value = parsed;
    return true;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--help") == 0) {
        std::puts("usage: trace_write_probe <existing-path> <count> [--free-library]");
        return 0;
    }
    if (argc != 3 && argc != 4) {
        return 2;
    }
    unsigned long long count = 0;
    if (!ParseCount(argv[2], &count)) {
        return 3;
    }
    if (GetFileAttributesW(argv[1]) == INVALID_FILE_ATTRIBUTES) {
        return 4;
    }

    constexpr std::uint64_t kCanaryIterations = 25000000ULL;
    volatile std::uint64_t canaryState = 0x9E3779B97F4A7C15ULL;
    LARGE_INTEGER canaryStart = {};
    LARGE_INTEGER canaryEnd = {};
    if (!QueryPerformanceCounter(&canaryStart)) {
        return 5;
    }
    for (std::uint64_t i = 0; i < kCanaryIterations; ++i) {
        canaryState = canaryState * 0xD1342543DE82EF95ULL + i + 0x94D049BB133111EBULL;
    }
    if (!QueryPerformanceCounter(&canaryEnd) || canaryEnd.QuadPart <= canaryStart.QuadPart) {
        return 5;
    }

    IO_COUNTERS before = {};
    IO_COUNTERS after = {};
    if (!GetProcessIoCounters(GetCurrentProcess(), &before)) {
        return 6;
    }
    LARGE_INTEGER hookLoopStart = {};
    LARGE_INTEGER hookLoopEnd = {};
    if (!QueryPerformanceCounter(&hookLoopStart)) {
        return 7;
    }
    for (unsigned long long i = 0; i < count; ++i) {
        if (GetFileAttributesW(argv[1]) == INVALID_FILE_ATTRIBUTES) {
            return 8;
        }
    }
    if (!QueryPerformanceCounter(&hookLoopEnd) || hookLoopEnd.QuadPart <= hookLoopStart.QuadPart) {
        return 7;
    }
    if (!GetProcessIoCounters(GetCurrentProcess(), &after)) {
        return 6;
    }

    // All observable output intentionally happens after the measured interval.
    std::printf("write_ops_delta=%llu canary_ticks=%lld hook_loop_ticks=%lld\n",
                after.WriteOperationCount - before.WriteOperationCount,
                static_cast<long long>(canaryEnd.QuadPart - canaryStart.QuadPart),
                static_cast<long long>(hookLoopEnd.QuadPart - hookLoopStart.QuadPart));
    if (argc == 4 && std::wcscmp(argv[3], L"--free-library") == 0) {
        HMODULE module = GetModuleHandleW(L"sbz_interceptor64.dll");
        if (module == nullptr) {
            module = GetModuleHandleW(L"sbz_interceptor32.dll");
        }
        if (module == nullptr || !FreeLibrary(module)) {
            return 8;
        }
    } else if (argc == 4) {
        return 9;
    }
    return 0;
}
