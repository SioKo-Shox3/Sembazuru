// Shared declarations between the hook bodies (interceptor.cpp) and the
// trace writer (trace_writer.cpp).
//
// Re-entrancy contract: everything in the trace:: namespace may only call
// True* trampolines or APIs that this DLL never hooks. Breaking this rule
// recurses straight back into a hook.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Trampolines the writer needs (defined in interceptor.cpp).
extern HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD,
                                       LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                       HANDLE);
extern DWORD(WINAPI* TrueGetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);

namespace trace {

// Record types and ops; values are part of the on-disk format.
// See docs/trace-format.md §5.
enum RecordType : BYTE {
    kFile = 1,
    kProcess = 2,
    kRegistry = 3,
    kEnv = 4,
};

enum FileOp : BYTE {
    kOpenRead = 1,
    kOpenWrite = 2,
    kOpenReadWrite = 3,
    kProbe = 4,
    kEnumerate = 5,
    kDelete = 6,
    kMove = 7,
    kCreateDir = 8,
    kRemoveDir = 9,
};

enum ProcessOp : BYTE {
    kChildCreated = 1,
};

enum RegistryOp : BYTE {
    kOpenKey = 1,
    kQueryValue = 2,
};

enum EnvOp : BYTE {
    kEnvRead = 1,
    kEnvBlockRead = 2,
};

// Called from DllMain(DLL_PROCESS_ATTACH): snapshots pid/ppid/QPC and the
// DLL's own path. Loader-lock safe (no LoadLibrary, no file I/O).
void Initialize(HMODULE self);

// Called from DllMain(DLL_PROCESS_DETACH) when reserved == nullptr.
void Shutdown();

// True once the trace file is open (opens it lazily on first use).
// Used by the CreateProcess hooks to decide whether to propagate.
bool Enabled();

// ANSI path of this DLL for DetourCreateProcessWithDllEx*, or nullptr if
// the path is not representable in the ANSI code page.
const char* DllPathA();

// Appends one record. pathLen/auxLen in WCHARs; -1 means NUL-terminated.
// Never throws, never re-enters hooks, preserves nothing (callers must
// save and restore GetLastError around it).
void Record(BYTE type, BYTE op, DWORD status, ULONGLONG extra,
            const wchar_t* path, int pathLen = -1,
            const wchar_t* aux = nullptr, int auxLen = -1);

}  // namespace trace
