// Sembazuru M0 PoC launcher.
//
// Starts a target process with the interceptor DLL injected, using the
// documented Detours injection path (DetourCreateProcessWithDllExW) rather
// than anything that pattern-matches to malware TTPs. Waits for the target
// and propagates its exit code.
//
// Usage: launcher.exe <path\to\interceptor.dll> <command> [args...]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <string>

#include "detours.h"

namespace {

// Quotes one argv element back into command-line form (minimal CRT-style
// quoting: sufficient for the PoC, revisited when this grows past a PoC).
void AppendQuoted(std::wstring& cmd, const wchar_t* arg) {
    if (!cmd.empty()) {
        cmd += L' ';
    }
    const bool needsQuotes = wcschr(arg, L' ') || wcschr(arg, L'\t') || !*arg;
    if (!needsQuotes) {
        cmd += arg;
        return;
    }
    cmd += L'"';
    cmd += arg;  // PoC: args with embedded quotes/backslash runs unsupported
    cmd += L'"';
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        fwprintf(stderr,
                 L"usage: %s <interceptor.dll> <command> [args...]\n",
                 argv[0]);
        return 2;
    }

    wchar_t dllFullW[MAX_PATH];
    if (GetFullPathNameW(argv[1], MAX_PATH, dllFullW, nullptr) == 0) {
        fwprintf(stderr, L"error: cannot resolve DLL path '%s'\n", argv[1]);
        return 2;
    }
    // DetourCreateProcessWithDllExW takes the DLL path as ANSI.
    char dllFullA[MAX_PATH];
    if (WideCharToMultiByte(CP_ACP, 0, dllFullW, -1, dllFullA,
                            sizeof(dllFullA), nullptr, nullptr) == 0) {
        fwprintf(stderr, L"error: DLL path not representable in ANSI\n");
        return 2;
    }

    std::wstring cmd;
    for (int i = 2; i < argc; ++i) {
        AppendQuoted(cmd, argv[i]);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!DetourCreateProcessWithDllExW(nullptr, cmd.data(), nullptr, nullptr,
                                       FALSE, 0, nullptr, nullptr, &si, &pi,
                                       dllFullA, nullptr)) {
        fwprintf(stderr, L"error: failed to launch '%s' (GetLastError=%lu)\n",
                 cmd.c_str(), GetLastError());
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
}
