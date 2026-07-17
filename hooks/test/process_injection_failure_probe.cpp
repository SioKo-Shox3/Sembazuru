#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cwchar>

namespace {

constexpr DWORD kChildTimeoutMs = 30000;

bool ToAnsi(const wchar_t* source, char* destination, int capacity) {
    BOOL usedDefault = FALSE;
    int written = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, source, -1,
                                      destination, capacity, nullptr,
                                      &usedDefault);
    return written > 0 && !usedDefault;
}

int Child(const wchar_t* sentinel, bool requireHook) {
    if (requireHook && GetModuleHandleW(L"sbz_interceptor64.dll") == nullptr) {
        return 32;
    }
    HANDLE file = CreateFileW(sentinel, GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return 31;
    }
    CloseHandle(file);
    return 0;
}

int Parent(bool ansi, bool requireHook, bool customEnvironment,
           const wchar_t* child, const wchar_t* sentinel) {
    wchar_t command[4096];
    if (_snwprintf_s(command, _countof(command), _TRUNCATE,
                     L"\"%s\" %s \"%s\"", child,
                     requireHook ? L"--child-module" : L"--child", sentinel) <
        0) {
        return 15;
    }
    char childA[1024];
    char commandA[4096];
    if (ansi &&
        (!ToAnsi(child, childA, sizeof(childA)) ||
         !ToAnsi(command, commandA, sizeof(commandA)))) {
        return 16;
    }

    PROCESS_INFORMATION process{};
    BOOL created = FALSE;
    if (ansi) {
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        char environment[] = "SBZ_PROBE_UNRELATED=1\0";
        created = CreateProcessA(childA, commandA, nullptr, nullptr, FALSE,
                                 0, customEnvironment ? environment : nullptr,
                                 nullptr, &startup, &process);
    } else {
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        wchar_t environment[] = L"SBZ_PROBE_UNRELATED=1\0";
        DWORD flags = customEnvironment ? CREATE_UNICODE_ENVIRONMENT : 0;
        created = CreateProcessW(
            child, command, nullptr, nullptr, FALSE, flags,
            customEnvironment ? environment : nullptr, nullptr, &startup,
            &process);
    }
    if (!created) return 21;

    DWORD wait = WaitForSingleObject(process.hProcess, kChildTimeoutMs);
    DWORD childExit = 22;
    if (wait == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &childExit);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return childExit == 0 ? 20 : 22;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && wcscmp(argv[1], L"--child") == 0) {
        return Child(argv[2], false);
    }
    if (argc == 3 && wcscmp(argv[1], L"--child-module") == 0) {
        return Child(argv[2], true);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-w") == 0) {
        return Parent(false, false, false, argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-a") == 0) {
        return Parent(true, false, false, argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-success-w") == 0) {
        return Parent(false, true, false, argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-success-a") == 0) {
        return Parent(true, true, false, argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-custom-w") == 0) {
        return Parent(false, true, true, argv[2], argv[3]);
    }
    if (argc == 4 && wcscmp(argv[1], L"--parent-custom-a") == 0) {
        return Parent(true, true, true, argv[2], argv[3]);
    }
    return 2;
}
