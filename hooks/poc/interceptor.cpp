// Sembazuru M0 PoC interceptor.
//
// Hooks exactly one API (CreateFileW), logs each call, and passes through
// unchanged. Observe-only by design; anything more belongs to M1.
// Done-when (docs/DESIGN.md M0): a CreateFile issued by cl.exe shows up in
// the log file named by SEMBAZURU_POC_LOG.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "detours.h"

namespace {

HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                DWORD, DWORD, HANDLE) = CreateFileW;

HANDLE g_log = INVALID_HANDLE_VALUE;
LONG g_logInitDone = 0;
SRWLOCK g_logLock = SRWLOCK_INIT;

// Opens the log lazily on the first hooked call instead of in DllMain, to
// keep loader-lock work minimal. Must only call APIs that are not hooked
// (or true trampolines) so logging can never re-enter the hook.
void EnsureLogOpen() {
    if (InterlockedCompareExchange(&g_logInitDone, 1, 0) != 0) {
        return;
    }
    wchar_t path[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"SEMBAZURU_POC_LOG", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return;  // No log requested; stay silent and pass everything through.
    }
    g_log = TrueCreateFileW(path, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void LogCreateFile(LPCWSTR fileName) {
    EnsureLogOpen();
    if (g_log == INVALID_HANDLE_VALUE || fileName == nullptr) {
        return;
    }

    char line[1024];
    int prefixLen = wsprintfA(line, "[sembazuru-poc pid=%lu] CreateFileW: ",
                              GetCurrentProcessId());
    int pathLen =
        WideCharToMultiByte(CP_UTF8, 0, fileName, -1, line + prefixLen,
                            static_cast<int>(sizeof(line)) - prefixLen - 3,
                            nullptr, nullptr);
    int len = prefixLen + (pathLen > 0 ? pathLen - 1 : 0);  // drop NUL
    line[len++] = '\r';
    line[len++] = '\n';

    AcquireSRWLockExclusive(&g_logLock);
    DWORD written = 0;
    WriteFile(g_log, line, static_cast<DWORD>(len), &written, nullptr);
    ReleaseSRWLockExclusive(&g_logLock);
}

HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,
                                DWORD dwShareMode,
                                LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                DWORD dwCreationDisposition,
                                DWORD dwFlagsAndAttributes,
                                HANDLE hTemplateFile) {
    LogCreateFile(lpFileName);
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                           lpSecurityAttributes, dwCreationDisposition,
                           dwFlagsAndAttributes, hTemplateFile);
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    // Detours re-launches this DLL inside a helper process when bitness
    // differs; that instance must do nothing.
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&reinterpret_cast<PVOID&>(TrueCreateFileW),
                     HookedCreateFileW);
        if (DetourTransactionCommit() != NO_ERROR) {
            // A failed commit rolls the transaction back; refuse to load
            // rather than run half-instrumented.
            return FALSE;
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&reinterpret_cast<PVOID&>(TrueCreateFileW),
                     HookedCreateFileW);
        DetourTransactionCommit();
        if (g_log != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log);
        }
    }
    return TRUE;
}
