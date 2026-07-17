#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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

    IO_COUNTERS before = {};
    IO_COUNTERS after = {};
    if (!GetProcessIoCounters(GetCurrentProcess(), &before)) {
        return 5;
    }
    for (unsigned long long i = 0; i < count; ++i) {
        if (GetFileAttributesW(argv[1]) == INVALID_FILE_ATTRIBUTES) {
            return 6;
        }
    }
    if (!GetProcessIoCounters(GetCurrentProcess(), &after)) {
        return 7;
    }

    // All observable output intentionally happens after the measured interval.
    std::printf("write_ops_delta=%llu\n",
                after.WriteOperationCount - before.WriteOperationCount);
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
