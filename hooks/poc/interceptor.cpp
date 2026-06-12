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
bool g_logInitDone = false;
SRWLOCK g_logLock = SRWLOCK_INIT;

// Opens the log lazily on the first hooked call instead of in DllMain, to
// keep loader-lock work minimal. Caller must hold g_logLock: init and handle
// publication stay under the same lock so no thread can observe a torn or
// stale g_log. Must only call APIs that are not hooked (or true trampolines)
// so logging can never re-enter the hook.
void EnsureLogOpenLocked() {
    if (g_logInitDone) {
        return;
    }
    g_logInitDone = true;
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
    if (fileName == nullptr) {
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
    EnsureLogOpenLocked();
    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log, line, static_cast<DWORD>(len), &written, nullptr);
    }
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

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    // Detours re-launches this DLL inside a helper process when bitness
    // differs; that instance must do nothing.
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        LONG err = DetourAttach(&reinterpret_cast<PVOID&>(TrueCreateFileW),
                                HookedCreateFileW);
        if (err == NO_ERROR) {
            err = DetourTransactionCommit();  // failure rolls back the TX
        } else {
            DetourTransactionAbort();
        }
        if (err != NO_ERROR) {
            // Refuse to load rather than run half-instrumented.
            return FALSE;
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (reserved != nullptr) {
            // Process termination: other threads may be frozen mid-write.
            // Let the OS reclaim hooks and handles instead of racing them.
            return TRUE;
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&reinterpret_cast<PVOID&>(TrueCreateFileW),
                     HookedCreateFileW);
        DetourTransactionCommit();
        AcquireSRWLockExclusive(&g_logLock);
        if (g_log != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log);
            g_log = INVALID_HANDLE_VALUE;
        }
        ReleaseSRWLockExclusive(&g_logLock);
    }
    return TRUE;
}
