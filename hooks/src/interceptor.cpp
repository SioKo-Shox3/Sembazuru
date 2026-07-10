// Sembazuru M1 interceptor: observe-only tracing of file I/O, child
// processes, registry reads, and environment reads. Writes the binary
// format specified in docs/trace-format.md; all analysis lives in Rust.
//
// Invariants every hook must keep:
//  - Call the True* trampoline first, then record, then return the result
//    unchanged. Never alter arguments or outcomes (observe-only).
//  - Save GetLastError() right after the True* call and restore it before
//    returning: recording does I/O that clobbers it, and callers legally
//    inspect it even on success (e.g. ERROR_ALREADY_EXISTS).
//  - Recording must only use True* trampolines or never-hooked APIs.

#include "common.h"

#include "detours.h"

// winternl.h gives NTSTATUS / PIO_STATUS_BLOCK / FILE_INFORMATION_CLASS for the
// one NT function this layer observes (see the NT-layer hooks section below).
#include <winternl.h>

#include <cstddef>
#include <cstring>
#include <cwchar>
#include <cwctype>

namespace {

// --- Trampolines (defaults are the real functions; Detours rewrites) ----

HANDLE(WINAPI* TrueCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                DWORD, DWORD, HANDLE) = CreateFileA;
DWORD(WINAPI* TrueGetFileAttributesW)(LPCWSTR) = GetFileAttributesW;
DWORD(WINAPI* TrueGetFileAttributesA)(LPCSTR) = GetFileAttributesA;
BOOL(WINAPI* TrueGetFileAttributesExW)
(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID) = GetFileAttributesExW;
BOOL(WINAPI* TrueGetFileAttributesExA)
(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID) = GetFileAttributesExA;
HANDLE(WINAPI* TrueFindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW) =
    FindFirstFileW;
HANDLE(WINAPI* TrueFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA) =
    FindFirstFileA;
HANDLE(WINAPI* TrueFindFirstFileExW)
(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD) =
    FindFirstFileExW;
HANDLE(WINAPI* TrueFindFirstFileExA)
(LPCSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD) =
    FindFirstFileExA;
DWORD(WINAPI* TrueGetCurrentDirectoryW)(DWORD, LPWSTR) = GetCurrentDirectoryW;
DWORD(WINAPI* TrueGetCurrentDirectoryA)(DWORD, LPSTR) = GetCurrentDirectoryA;
BOOL(WINAPI* TrueSetCurrentDirectoryW)(LPCWSTR) = SetCurrentDirectoryW;
BOOL(WINAPI* TrueSetCurrentDirectoryA)(LPCSTR) = SetCurrentDirectoryA;
DWORD(WINAPI* TrueGetFullPathNameW)(LPCWSTR, DWORD, LPWSTR, LPWSTR*) =
    GetFullPathNameW;
DWORD(WINAPI* TrueGetFullPathNameA)(LPCSTR, DWORD, LPSTR, LPSTR*) =
    GetFullPathNameA;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
BOOL(WINAPI* TrueDeleteFileA)(LPCSTR) = DeleteFileA;
BOOL(WINAPI* TrueMoveFileW)(LPCWSTR, LPCWSTR) = MoveFileW;
BOOL(WINAPI* TrueMoveFileA)(LPCSTR, LPCSTR) = MoveFileA;
BOOL(WINAPI* TrueMoveFileExW)(LPCWSTR, LPCWSTR, DWORD) = MoveFileExW;
BOOL(WINAPI* TrueMoveFileExA)(LPCSTR, LPCSTR, DWORD) = MoveFileExA;
BOOL(WINAPI* TrueCreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES) =
    CreateDirectoryW;
BOOL(WINAPI* TrueCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES) =
    CreateDirectoryA;
BOOL(WINAPI* TrueRemoveDirectoryW)(LPCWSTR) = RemoveDirectoryW;
BOOL(WINAPI* TrueRemoveDirectoryA)(LPCSTR) = RemoveDirectoryA;
BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                 LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                 LPCWSTR, LPSTARTUPINFOW,
                                 LPPROCESS_INFORMATION) = CreateProcessW;
BOOL(WINAPI* TrueCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                 LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                 LPCSTR, LPSTARTUPINFOA,
                                 LPPROCESS_INFORMATION) = CreateProcessA;
LSTATUS(APIENTRY* TrueRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) =
    RegOpenKeyExW;
LSTATUS(APIENTRY* TrueRegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) =
    RegOpenKeyExA;
LSTATUS(APIENTRY* TrueRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD,
                                        LPBYTE, LPDWORD) = RegQueryValueExW;
LSTATUS(APIENTRY* TrueRegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD,
                                        LPBYTE, LPDWORD) = RegQueryValueExA;
LSTATUS(APIENTRY* TrueRegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD,
                                    PVOID, LPDWORD) = RegGetValueW;
LSTATUS(APIENTRY* TrueRegGetValueA)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD,
                                    PVOID, LPDWORD) = RegGetValueA;
LSTATUS(APIENTRY* TrueRegCloseKey)(HKEY) = RegCloseKey;
DWORD(WINAPI* TrueGetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD) =
    GetEnvironmentVariableA;
LPWCH(WINAPI* TrueGetEnvironmentStringsW)(void) = GetEnvironmentStringsW;

// NtSetInformationFile is resolved at runtime (it is not a static import of
// this DLL), so its trampoline starts null and is filled in DllMain.
using NtSetInformationFile_t = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                                ULONG, FILE_INFORMATION_CLASS);
NtSetInformationFile_t TrueNtSetInformationFile = nullptr;

// FILE_INFORMATION_CLASS values we act on. winternl.h's enum is minimal and
// does not name these, so they are spelled out (values are stable ABI).
constexpr int kFileRenameInformation = 10;
constexpr int kFileDispositionInformation = 13;
constexpr int kFileDispositionInformationEx = 64;
constexpr int kFileRenameInformationEx = 65;
constexpr ULONG kFileDispositionDelete = 0x1;  // FILE_DISPOSITION_DELETE

// Layouts per ntifs.h (absent from the user-mode SDK). The classic and *Ex
// rename forms share this layout for the fields we read; the leading union is
// ReplaceIfExists (classic) / Flags (Ex).
struct FileRenameInformationLayout {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;  // bytes, not WCHARs
    WCHAR FileName[1];     // FileNameLength bytes; NOT NUL-terminated
};
struct FileDispositionInformationLayout {
    BOOLEAN DeleteFile;
};
struct FileDispositionInformationExLayout {
    ULONG Flags;
};

// --- VFS redirect mode (M3.2) --------------------------------------------
//
// When SEMBAZURU_MODE=vfs, a read-only open whose path is under
// SEMBAZURU_VFS_ROOT is redirected: the hook asks the worker (over the named
// pipe SEMBAZURU_VFS_PIPE) to hydrate the file and opens the returned local
// scratch copy instead. Writes, paths outside the root, and the worker's own
// toolchain/SDK pass straight through to the real filesystem. If the worker
// cannot supply the file, the hook falls through to a normal local open
// (local fallback, non-negotiable #2). All pipe and scratch I/O uses True* /
// never-hooked APIs, honoring the re-entrancy contract.

bool g_vfsMode = false;
wchar_t g_vfsRoot[1024];  // lowercased, no trailing backslash
int g_vfsRootLen = 0;
wchar_t g_vfsPipe[260];     // full \\.\pipe\<name>
wchar_t g_vfsScratch[1024]; // lowercased scratch root, no trailing backslash
int g_vfsScratchLen = 0;    // 0 = not configured (no scratch guard)
wchar_t g_vfsCwd[1024]; // lowercased submitted cwd, no trailing backslash
int g_vfsCwdLen = 0;    // 0 = resolve relatives against the process cwd
wchar_t g_vfsCwdDisplay[1024]; // submitted cwd spelling for API returns
int g_vfsCwdDisplayLen = 0;
wchar_t g_vfsActualCwd[1024]; // lowercased process cwd, no trailing backslash
int g_vfsActualCwdLen = 0;    // lower length for prefix checks
int g_vfsActualCwdDisplayLen = 0; // display length for suffix slicing
// Strict virtualization (M8.2 (2), ADR 0007 §a(2)). When true, a read-only open
// committed to the VFS (under vfs_root) that cannot be supplied FAILS instead of
// falling through to a local open, and drops kUnvirtMarker so the worker re-runs
// the action locally. Default false keeps the compiler-compatible fail-open.
bool g_vfsStrict = false;
thread_local bool g_vfsInternalIoActive = false;

// Marker dropped in the scratch root when the remote attempt must be abandoned
// and re-run locally. Strict unsupplied reads and VFS-root wildcard enumeration
// both use it. Must match `UNVIRT_MARKER` in `crates/worker/src/lib.rs`.
const wchar_t* kUnvirtMarker = L".sbz-unvirtualized";
// Marker dropped when a scratch-cwd action writes under the logical root. Until
// the worker uploads outputs through WriteBack, such a run must fall back locally
// rather than report remote success with outputs stranded in scratch.
const wchar_t* kUnsafeOutputMarker = L".sbz-unsafe-output";

int TrimTrailingBackslashes(wchar_t* s, DWORD len) {
    while (len > 0 && s[len - 1] == L'\\') {
        s[--len] = L'\0';
    }
    return static_cast<int>(len);
}

// Lowercases [0,len) in place and strips trailing backslashes, returning the
// new length. Shared by the root/scratch config readers.
int LowerAndTrim(wchar_t* s, DWORD len) {
    for (DWORD i = 0; i < len; i++) {
        s[i] = towlower(s[i]);
    }
    return TrimTrailingBackslashes(s, len);
}

// Reads the VFS configuration from the environment. Called once at attach,
// BEFORE the hooks are installed, so it uses the real GetEnvironmentVariableW.
void InitVfsConfig() {
    wchar_t mode[16];
    DWORD n = GetEnvironmentVariableW(L"SEMBAZURU_MODE", mode, 16);
    if (n == 0 || n >= 16 || _wcsicmp(mode, L"vfs") != 0) {
        return;
    }
    wchar_t root[1024];
    DWORD rn = GetEnvironmentVariableW(L"SEMBAZURU_VFS_ROOT", root, 1024);
    if (rn == 0 || rn >= 1024) {
        return;
    }
    wchar_t name[200];
    DWORD pn = GetEnvironmentVariableW(L"SEMBAZURU_VFS_PIPE", name, 200);
    if (pn == 0 || pn >= 200) {
        return;
    }
    int rootLen = LowerAndTrim(root, rn);
    memcpy(g_vfsRoot, root, (static_cast<size_t>(rootLen) + 1) * sizeof(wchar_t));
    g_vfsRootLen = rootLen;
    if (_snwprintf_s(g_vfsPipe, 260, _TRUNCATE, L"\\\\.\\pipe\\%s", name) < 0) {
        return;
    }
    // Scratch root (optional but always set by the worker): redirected reads are
    // served from here, so opens under it must NOT themselves redirect (anti-
    // recursion), and a worker-returned path is only trusted if it lies here.
    wchar_t scratch[1024];
    DWORD sn = GetEnvironmentVariableW(L"SEMBAZURU_VFS_SCRATCH", scratch, 1024);
    if (sn > 0 && sn < 1024) {
        int sl = LowerAndTrim(scratch, sn);
        memcpy(g_vfsScratch, scratch,
               (static_cast<size_t>(sl) + 1) * sizeof(wchar_t));
        g_vfsScratchLen = sl;
    }
    // When the service worker cannot enter the submitted cwd directly, it starts
    // the child from the scratch tree. Keep resolving relative source reads as if
    // the child were still in the submitted cwd, so bare compiler inputs remain
    // virtualized under SEMBAZURU_VFS_ROOT.
    wchar_t cwd[1024];
    DWORD cwn = GetEnvironmentVariableW(L"SEMBAZURU_VFS_CWD", cwd, 1024);
    if (cwn > 0 && cwn < 1024) {
        wchar_t cwdAbs[1024];
        DWORD can = TrueGetFullPathNameW(cwd, 1024, cwdAbs, nullptr);
        if (can > 0 && can < 1024) {
            int displayLen = TrimTrailingBackslashes(cwdAbs, can);
            memcpy(g_vfsCwdDisplay, cwdAbs,
                   (static_cast<size_t>(displayLen) + 1) * sizeof(wchar_t));
            g_vfsCwdDisplayLen = displayLen;
            wchar_t cwdLower[1024];
            memcpy(cwdLower, cwdAbs,
                   (static_cast<size_t>(displayLen) + 1) * sizeof(wchar_t));
            int cl = LowerAndTrim(cwdLower, displayLen);
            memcpy(g_vfsCwd, cwdLower,
                   (static_cast<size_t>(cl) + 1) * sizeof(wchar_t));
            g_vfsCwdLen = cl;
            wchar_t actualCwdDisplay[1024];
            DWORD acn = TrueGetCurrentDirectoryW(1024, actualCwdDisplay);
            if (acn > 0 && acn < 1024) {
                int actualDisplayLen =
                    TrimTrailingBackslashes(actualCwdDisplay, acn);
                wchar_t actualCwdLower[1024];
                memcpy(actualCwdLower, actualCwdDisplay,
                       (static_cast<size_t>(actualDisplayLen) + 1) *
                           sizeof(wchar_t));
                int actualLowerLen =
                    LowerAndTrim(actualCwdLower, actualDisplayLen);
                memcpy(g_vfsActualCwd, actualCwdLower,
                       (static_cast<size_t>(actualLowerLen) + 1) *
                           sizeof(wchar_t));
                g_vfsActualCwdLen = actualLowerLen;
                g_vfsActualCwdDisplayLen = actualDisplayLen;
            }
        }
    }
    // Strict mode (M8.2 (2)): any set, non-"0" value enables it.
    wchar_t strict[16];
    DWORD stn = GetEnvironmentVariableW(L"SEMBAZURU_VFS_STRICT", strict, 16);
    g_vfsStrict = (stn > 0 && stn < 16 && wcscmp(strict, L"0") != 0);
    g_vfsMode = true;
}

// Defined in the Helpers section below; forward-declared so the read-only check
// can reuse the single source of truth for access-mask classification.
BYTE ClassifyCreateFile(DWORD access, DWORD disposition);

// A read-only open (read intent, no write/create/truncate): only these are
// served from the agent. Writes are local and returned via WriteBack (M3.3).
bool IsReadOnlyOpen(DWORD access, DWORD disposition) {
    return ClassifyCreateFile(access, disposition) == trace::kOpenRead;
}

// True if the lowercased absolute `abs` (length `absLen`) lies under the
// lowercased `prefix` (length `prefixLen`), with the match ending on a separator
// boundary (or exact), so c:\work\a does not swallow the sibling c:\work\ab.
bool PathUnderPrefix(const wchar_t* abs, int absLen, const wchar_t* prefix,
                     int prefixLen) {
    if (prefixLen == 0 || absLen < prefixLen) {
        return false;
    }
    if (wcsncmp(abs, prefix, prefixLen) != 0) {
        return false;
    }
    wchar_t after = abs[prefixLen];
    return after == L'\0' || after == L'\\';
}

bool IsSlash(wchar_t c) { return c == L'\\' || c == L'/'; }

bool HasDrivePrefix(const wchar_t* path) {
    return path != nullptr && path[0] != L'\0' && path[1] == L':';
}

bool IsFullyQualifiedPath(const wchar_t* path) {
    if (path == nullptr || path[0] == L'\0') {
        return false;
    }
    if (HasDrivePrefix(path) && IsSlash(path[2])) {
        return true;
    }
    return IsSlash(path[0]) && IsSlash(path[1]);
}

bool HasWin32NamespacePrefix(const wchar_t* path, wchar_t marker) {
    return path != nullptr && lstrlenW(path) >= 4 && IsSlash(path[0]) &&
           IsSlash(path[1]) && path[2] == marker && IsSlash(path[3]);
}

bool IsWin32DeviceNamespacePath(const wchar_t* path) {
    return HasWin32NamespacePrefix(path, L'.');
}

bool IsLocalDosVerbatimPath(const wchar_t* path) {
    if (!HasWin32NamespacePrefix(path, L'?')) {
        return false;
    }
    const wchar_t* normal = path + 4;
    return lstrlenW(normal) >= 3 && normal[1] == L':' && IsSlash(normal[2]);
}

bool StripLocalDosVerbatimPath(const wchar_t* path, wchar_t* out, int cap) {
    if (!IsLocalDosVerbatimPath(path) || out == nullptr || cap <= 0) {
        return false;
    }
    const wchar_t* normal = path + 4;
    int len = lstrlenW(normal);
    if (len <= 0 || len >= cap) {
        return false;
    }
    memcpy(out, normal, (static_cast<size_t>(len) + 1) * sizeof(wchar_t));
    return true;
}

DWORD FullPathNormalizingLocalDosVerbatim(const wchar_t* path, wchar_t* out,
                                          int cap) {
    if (path == nullptr || out == nullptr || cap <= 0 ||
        IsWin32DeviceNamespacePath(path)) {
        return 0;
    }
    wchar_t stripped[1024];
    const wchar_t* input = path;
    if (StripLocalDosVerbatimPath(path, stripped, ARRAYSIZE(stripped))) {
        input = stripped;
    }
    DWORD n = TrueGetFullPathNameW(input, cap, out, nullptr);
    if (n == 0 || n >= static_cast<DWORD>(cap)) {
        return n;
    }
    wchar_t normal[1024];
    if (StripLocalDosVerbatimPath(out, normal, ARRAYSIZE(normal))) {
        int len = lstrlenW(normal);
        if (len >= cap) {
            return static_cast<DWORD>(len);
        }
        memcpy(out, normal, (static_cast<size_t>(len) + 1) * sizeof(wchar_t));
        n = static_cast<DWORD>(len);
    }
    return n;
}

bool ComposeUnderVfsCwd(const wchar_t* path, wchar_t* out, int cap) {
    if (g_vfsCwdLen == 0 || path == nullptr || cap <= 0) {
        return false;
    }
    const wchar_t* cwd =
        g_vfsCwdDisplayLen > 0 ? g_vfsCwdDisplay : g_vfsCwd;
    if (HasDrivePrefix(path) && !IsSlash(path[2])) {
        if (g_vfsCwdLen < 2 || g_vfsCwd[1] != L':' ||
            towlower(g_vfsCwd[0]) != towlower(path[0])) {
            return false;
        }
        return _snwprintf_s(out, cap, _TRUNCATE, L"%s\\%s", cwd,
                            path + 2) >= 0;
    }
    if (IsSlash(path[0]) && !IsSlash(path[1])) {
        if (g_vfsCwdLen < 2 || g_vfsCwd[1] != L':') {
            return false;
        }
        return _snwprintf_s(out, cap, _TRUNCATE, L"%c:%s", cwd[0], path) >=
               0;
    }
    return _snwprintf_s(out, cap, _TRUNCATE, L"%s\\%s", cwd, path) >= 0;
}

bool ComposeFromActualCwdPath(const wchar_t* actualDisplay,
                              const wchar_t* actualLower, int actualLen,
                              wchar_t* out, int cap) {
    if (g_vfsCwdLen == 0 || g_vfsActualCwdLen == 0 ||
        g_vfsActualCwdDisplayLen == 0 ||
        !PathUnderPrefix(actualLower, actualLen, g_vfsActualCwd,
                         g_vfsActualCwdLen)) {
        return false;
    }
    // Slice the display path with the display length. The lower length above is
    // only for boundary-aware prefix checks.
    const wchar_t* suffix = actualDisplay + g_vfsActualCwdDisplayLen;
    if (*suffix == L'\\') {
        suffix++;
    }
    const wchar_t* cwd =
        g_vfsCwdDisplayLen > 0 ? g_vfsCwdDisplay : g_vfsCwd;
    if (*suffix == L'\0') {
        return _snwprintf_s(out, cap, _TRUNCATE, L"%s", cwd) >= 0;
    }
    return _snwprintf_s(out, cap, _TRUNCATE, L"%s\\%s", cwd, suffix) >= 0;
}

DWORD FullPathForVfsRootCheck(const wchar_t* path, wchar_t* absOut, int absCap) {
    if (g_vfsCwdLen > 0 && !IsFullyQualifiedPath(path)) {
        wchar_t joined[1024];
        if (ComposeUnderVfsCwd(path, joined, 1024)) {
            DWORD n =
                FullPathNormalizingLocalDosVerbatim(joined, absOut, absCap);
            if (n > 0 && n < static_cast<DWORD>(absCap)) {
                return n;
            }
        }
    }
    DWORD n = FullPathNormalizingLocalDosVerbatim(path, absOut, absCap);
    if (n > 0 && n < static_cast<DWORD>(absCap)) {
        wchar_t actualDisplay[1024];
        memcpy(actualDisplay, absOut,
               (static_cast<size_t>(n) + 1) * sizeof(wchar_t));
        wchar_t actualLower[1024];
        memcpy(actualLower, absOut,
               (static_cast<size_t>(n) + 1) * sizeof(wchar_t));
        int actualLen = LowerAndTrim(actualLower, n);
        if (ComposeFromActualCwdPath(actualDisplay, actualLower, actualLen,
                                     absOut, absCap)) {
            return static_cast<DWORD>(lstrlenW(absOut));
        }
    }
    return n;
}

// True if `path` (resolved to absolute against the cwd) lies under g_vfsRoot and
// NOT under the scratch root. Writes the display-spelled absolute path into
// `absOut`; lowercased copies are used only for prefix checks.
// Excluding scratch is the anti-recursion guard: a scratch open must never be
// re-redirected even if scratch happens to sit under the VFS root.
bool IsUnderVfsRoot(const wchar_t* path, wchar_t* absOut, int absCap) {
    DWORD an = FullPathForVfsRootCheck(path, absOut, absCap);
    if (an == 0 || an >= static_cast<DWORD>(absCap)) {
        return false;  // unresolved or too long: do not redirect (fall to local)
    }
    wchar_t lower[1024];
    memcpy(lower, absOut, (static_cast<size_t>(an) + 1) * sizeof(wchar_t));
    int absLen = LowerAndTrim(lower, an);
    if (PathUnderPrefix(lower, absLen, g_vfsScratch, g_vfsScratchLen)) {
        return false;  // a scratch path: never redirect (anti-recursion)
    }
    return PathUnderPrefix(lower, absLen, g_vfsRoot, g_vfsRootLen);
}

bool WriteAllPipe(HANDLE h, const void* buf, DWORD len) {
    const BYTE* p = static_cast<const BYTE*>(buf);
    DWORD done = 0;
    while (done < len) {
        DWORD w = 0;
        if (!WriteFile(h, p + done, len - done, &w, nullptr) || w == 0) {
            return false;
        }
        done += w;
    }
    return true;
}

bool ReadExactPipe(HANDLE h, void* buf, DWORD len) {
    BYTE* p = static_cast<BYTE*>(buf);
    DWORD done = 0;
    while (done < len) {
        DWORD r = 0;
        if (!ReadFile(h, p + done, len - done, &r, nullptr) || r == 0) {
            return false;
        }
        done += r;
    }
    return true;
}

// Asks the worker to hydrate `absPath`; on success writes the local scratch path
// (wide) into `localOut` and returns true. On not-found/error returns false and
// the caller falls back to a local open. One short-lived pipe connection per
// call (a per-thread persistent connection is an M3.5 latency optimization).
bool VfsHydrate(const wchar_t* absPath, wchar_t* localOut, int localCap) {
    // Wide -> UTF-8 request. Paths are bounded (abs buffer is 1024 wide), so an
    // 8 KiB UTF-8 buffer is ample and keeps stack use modest in this hot path.
    const int kBuf = 8192;
    int u8len =
        WideCharToMultiByte(CP_UTF8, 0, absPath, -1, nullptr, 0, nullptr, nullptr);
    if (u8len <= 1 || u8len > kBuf) {
        return false;
    }
    char u8[kBuf];
    if (WideCharToMultiByte(CP_UTF8, 0, absPath, -1, u8, u8len, nullptr,
                            nullptr) == 0) {
        return false;
    }
    DWORD payloadLen = static_cast<DWORD>(u8len - 1);  // drop NUL

    HANDLE pipe = TrueCreateFileW(g_vfsPipe, GENERIC_READ | GENERIC_WRITE, 0,
                                  nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_PIPE_BUSY &&
            WaitNamedPipeW(g_vfsPipe, 5000)) {
            pipe = TrueCreateFileW(g_vfsPipe, GENERIC_READ | GENERIC_WRITE, 0,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            return false;
        }
    }

    bool ok = false;
    if (WriteAllPipe(pipe, &payloadLen, 4) &&
        WriteAllPipe(pipe, u8, payloadLen)) {
        DWORD respLen = 0;
        if (ReadExactPipe(pipe, &respLen, 4) && respLen >= 1 &&
            respLen <= static_cast<DWORD>(kBuf)) {
            char resp[kBuf];
            if (ReadExactPipe(pipe, resp, respLen)) {
                BYTE status = static_cast<BYTE>(resp[0]);
                if (status == 0 && respLen > 1) {
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, resp + 1,
                                                   static_cast<int>(respLen - 1),
                                                   nullptr, 0);
                    if (wlen > 0 && wlen < localCap) {
                        int w = MultiByteToWideChar(
                            CP_UTF8, 0, resp + 1,
                            static_cast<int>(respLen - 1), localOut, wlen);
                        if (w > 0) {
                            localOut[w] = L'\0';
                            ok = true;
                        }
                    }
                }
            }
        }
    }
    CloseHandle(pipe);
    return ok;
}

// Drops a marker in the scratch root. Best-effort: uses the real CreateFileW; if
// it cannot be written the worker simply won't fall back - never worse than the
// pre-marker path.
void VfsMarkScratchMarker(const wchar_t* markerName) {
    if (g_vfsScratchLen == 0) {
        return;  // no scratch root to drop the marker in
    }
    wchar_t marker[1100];
    if (_snwprintf_s(marker, 1100, _TRUNCATE, L"%s\\%s", g_vfsScratch,
                     markerName) < 0) {
        return;
    }
    HANDLE h = TrueCreateFileW(marker, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
}

// Drops the local-rerun marker (kUnvirtMarker) in the scratch root, once per
// process, so the worker turns this action into a local re-run.
void VfsMarkUnvirtualized() {
    static LONG written = 0;
    if (InterlockedExchange(&written, 1) != 0) {
        return;  // already marked this action
    }
    VfsMarkScratchMarker(kUnvirtMarker);
}

// Drops the unsafe-output marker once when a scratch-cwd action mutates a path
// under the logical root. The worker will fail the remote attempt and let the
// daemon's mandatory local fallback preserve outputs.
void VfsMarkUnsafeOutput() {
    static LONG written = 0;
    if (InterlockedExchange(&written, 1) != 0) {
        return;
    }
    VfsMarkScratchMarker(kUnsafeOutputMarker);
}

bool CanonicalScratchPath(const wchar_t* local, wchar_t* canonOut, int canonCap) {
    if (g_vfsScratchLen == 0 || local == nullptr || canonOut == nullptr ||
        canonCap <= 0) {
        return false;
    }
    DWORD cn = FullPathNormalizingLocalDosVerbatim(local, canonOut, canonCap);
    if (cn == 0 || cn >= static_cast<DWORD>(canonCap)) {
        return false;
    }
    int cl = LowerAndTrim(canonOut, cn);
    return PathUnderPrefix(canonOut, cl, g_vfsScratch, g_vfsScratchLen);
}

HANDLE VfsInternalCreateFileW(const wchar_t* local, DWORD access, DWORD share,
                              LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                              DWORD flags, HANDLE templ) {
    bool previous = g_vfsInternalIoActive;
    HANDLE result = INVALID_HANDLE_VALUE;
    __try {
        g_vfsInternalIoActive = true;
        result =
            TrueCreateFileW(local, access, share, sa, disposition, flags, templ);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

DWORD VfsInternalGetFileAttributesW(const wchar_t* local) {
    bool previous = g_vfsInternalIoActive;
    DWORD result = INVALID_FILE_ATTRIBUTES;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueGetFileAttributesW(local);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

BOOL VfsInternalGetFileAttributesExW(const wchar_t* local,
                                     GET_FILEEX_INFO_LEVELS level,
                                     LPVOID info) {
    bool previous = g_vfsInternalIoActive;
    BOOL result = FALSE;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueGetFileAttributesExW(local, level, info);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

HANDLE VfsInternalFindFirstFileW(const wchar_t* local,
                                 LPWIN32_FIND_DATAW data) {
    bool previous = g_vfsInternalIoActive;
    HANDLE result = INVALID_HANDLE_VALUE;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueFindFirstFileW(local, data);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

HANDLE VfsInternalFindFirstFileA(const char* local,
                                 LPWIN32_FIND_DATAA data) {
    bool previous = g_vfsInternalIoActive;
    HANDLE result = INVALID_HANDLE_VALUE;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueFindFirstFileA(local, data);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

HANDLE VfsInternalFindFirstFileExW(const wchar_t* local,
                                   FINDEX_INFO_LEVELS level, LPVOID data,
                                   FINDEX_SEARCH_OPS op, LPVOID filter,
                                   DWORD flags) {
    bool previous = g_vfsInternalIoActive;
    HANDLE result = INVALID_HANDLE_VALUE;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueFindFirstFileExW(local, level, data, op, filter, flags);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

HANDLE VfsInternalFindFirstFileExA(const char* local,
                                   FINDEX_INFO_LEVELS level, LPVOID data,
                                   FINDEX_SEARCH_OPS op, LPVOID filter,
                                   DWORD flags) {
    bool previous = g_vfsInternalIoActive;
    HANDLE result = INVALID_HANDLE_VALUE;
    __try {
        g_vfsInternalIoActive = true;
        result = TrueFindFirstFileExA(local, level, data, op, filter, flags);
    } __finally {
        g_vfsInternalIoActive = previous;
    }
    return result;
}

// If VFS mode applies to this read-only open, returns a redirected handle to the
// hydrated scratch copy. Returns INVALID_HANDLE_VALUE with *handled=false when
// the open should proceed normally (not vfs mode, not a read, outside root, or -
// in non-strict mode - the worker could not supply it, so local fallback).
//
// Once IsUnderVfsRoot passes we are COMMITTED to virtualizing this path. Any
// later failure to produce a valid hydrated handle is an unvirtualized access:
// in strict mode (M8.2 (2)) it FAILS the open (sets *handled, drops the marker) so
// the worker re-runs locally - never a silent local read of a wrong/absent file;
// in non-strict mode it keeps the compiler-compatible fail-open (handled=false).
HANDLE VfsTryRedirect(const wchar_t* path, DWORD access, DWORD share,
                      LPSECURITY_ATTRIBUTES sa, DWORD disposition, DWORD flags,
                      HANDLE templ, bool* handled, wchar_t* logicalOut,
                      int logicalCap) {
    *handled = false;
    if (logicalOut != nullptr && logicalCap > 0) {
        logicalOut[0] = L'\0';
    }
    if (!g_vfsMode || path == nullptr || !IsReadOnlyOpen(access, disposition)) {
        return INVALID_HANDLE_VALUE;
    }
    wchar_t abs[1024];
    if (!IsUnderVfsRoot(path, abs, 1024)) {
        return INVALID_HANDLE_VALUE;  // outside root: a worker-local file, open it
    }
    if (logicalOut != nullptr && logicalCap > 0) {
        _snwprintf_s(logicalOut, logicalCap, _TRUNCATE, L"%s", abs);
    }
    // Committed-failure exit for a path under vfs_root we could not virtualize.
    auto committedFailure = [&]() -> HANDLE {
        if (g_vfsStrict) {
            VfsMarkUnvirtualized();
            *handled = true;  // do NOT fall through to a local open
            SetLastError(ERROR_FILE_NOT_FOUND);
        }
        return INVALID_HANDLE_VALUE;
    };
    wchar_t local[1024];
    if (!VfsHydrate(abs, local, 1024)) {
        return committedFailure();  // agent could not supply it
    }
    // Trust but verify: the worker must return a path under the scratch root.
    // This bounds the damage a buggy/hostile worker can do - it cannot redirect a
    // read to an arbitrary file the compiler would consume as source (M7.1).
    //
    //  * A scratch root MUST be configured in VFS mode; if it is not, fail closed
    //    rather than open an unvalidated worker-supplied path.
    //  * Canonicalize the returned path (GetFullPathName) BEFORE the prefix check,
    //    so a worker cannot escape scratch with `<scratch>\..\..\secret`: `..`,
    //    mixed separators, and relative components are collapsed first, then the
    //    boundary-aware prefix check runs on the resolved, lowercased path.
    if (g_vfsScratchLen == 0) {
        return committedFailure();  // no scratch guard configured
    }
    wchar_t canon[1024];
    if (!CanonicalScratchPath(local, canon, 1024)) {
        return committedFailure();  // worker returned an out-of-scratch path
    }
    *handled = true;
    return VfsInternalCreateFileW(canon, access, share, sa, disposition, flags,
                                  templ);
}

bool VfsMaterializeForProbe(const wchar_t* path, wchar_t* localOut,
                            int localCap, wchar_t* logicalOut,
                            int logicalCap, bool* handled) {
    *handled = false;
    if (logicalOut != nullptr && logicalCap > 0) {
        logicalOut[0] = L'\0';
    }
    if (!g_vfsMode || path == nullptr) {
        return false;
    }

    wchar_t abs[1024];
    if (!IsUnderVfsRoot(path, abs, 1024)) {
        return false;
    }
    if (logicalOut != nullptr && logicalCap > 0) {
        _snwprintf_s(logicalOut, logicalCap, _TRUNCATE, L"%s", abs);
    }

    auto committedFailure = [&]() -> bool {
        if (g_vfsStrict) {
            VfsMarkUnvirtualized();
            *handled = true;
            SetLastError(ERROR_FILE_NOT_FOUND);
        }
        return false;
    };

    wchar_t local[1024];
    if (!VfsHydrate(abs, local, 1024)) {
        return committedFailure();
    }
    if (!CanonicalScratchPath(local, localOut, localCap)) {
        return committedFailure();
    }
    *handled = true;
    return true;
}

bool HasWildcard(const wchar_t* path) {
    if (path == nullptr) {
        return false;
    }
    const wchar_t* scan = HasWin32NamespacePrefix(path, L'?') ? path + 4 : path;
    return wcspbrk(scan, L"*?") != nullptr;
}

bool VfsFailWildcardEnumeration(const wchar_t* pattern, wchar_t* logicalOut,
                                int logicalCap, bool* handled) {
    *handled = false;
    if (logicalOut != nullptr && logicalCap > 0) {
        logicalOut[0] = L'\0';
    }
    if (!g_vfsMode || !HasWildcard(pattern)) {
        return false;
    }
    wchar_t abs[1024];
    if (!IsUnderVfsRoot(pattern, abs, 1024)) {
        return false;
    }
    if (logicalOut != nullptr && logicalCap > 0) {
        _snwprintf_s(logicalOut, logicalCap, _TRUNCATE, L"%s", abs);
    }
    VfsMarkUnvirtualized();
    *handled = true;
    SetLastError(ERROR_FILE_NOT_FOUND);
    return true;
}

// --- Helpers -------------------------------------------------------------

// ANSI argument converted for recording. Stack for the common case, heap
// for long strings; null or failed conversion records as empty.
class WideArg {
   public:
    explicit WideArg(const char* s) {
        if (s == nullptr) {
            return;
        }
        int needed = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
        if (needed <= 0 || needed > kMaxChars) {
            // Reject absurd lengths: keeps `needed * 2` from overflowing a
            // 32-bit SIZE_T on a future 32-bit interceptor build. Real paths,
            // command lines, and env values are far below this bound.
            return;
        }
        wchar_t* dst = stack_;
        if (needed > kStackCap) {
            heap_ = static_cast<wchar_t*>(HeapAlloc(
                GetProcessHeap(), 0, static_cast<SIZE_T>(needed) * 2));
            if (heap_ == nullptr) {
                return;
            }
            dst = heap_;
        }
        int written = MultiByteToWideChar(CP_ACP, 0, s, -1, dst, needed);
        if (written > 0) {
            ptr_ = dst;
            len_ = written - 1;  // drop NUL
        }
    }
    ~WideArg() {
        if (heap_ != nullptr) {
            HeapFree(GetProcessHeap(), 0, heap_);
        }
    }
    WideArg(const WideArg&) = delete;
    WideArg& operator=(const WideArg&) = delete;

    const wchar_t* get() const { return ptr_; }
    int length() const { return len_; }

   private:
    static const int kStackCap = 512;
    static const int kMaxChars = 1 << 20;  // 1M wchars; far above any real arg
    wchar_t stack_[kStackCap];
    wchar_t* heap_ = nullptr;
    const wchar_t* ptr_ = nullptr;
    int len_ = 0;
};

bool WideToAnsi(const wchar_t* w, char* out, DWORD outCap, int* bytesNoNul) {
    if (w == nullptr || out == nullptr || outCap == 0) {
        return false;
    }
    int needed = WideCharToMultiByte(CP_ACP, 0, w, -1, nullptr, 0, nullptr,
                                     nullptr);
    if (needed <= 0 || static_cast<DWORD>(needed) > outCap) {
        return false;
    }
    int written = WideCharToMultiByte(CP_ACP, 0, w, -1, out, outCap, nullptr,
                                      nullptr);
    if (written <= 0) {
        return false;
    }
    if (bytesNoNul != nullptr) {
        *bytesNoNul = written - 1;
    }
    return true;
}

void SetFilePartW(LPWSTR buffer, LPWSTR* filePart) {
    if (filePart == nullptr) {
        return;
    }
    *filePart = nullptr;
    if (buffer == nullptr) {
        return;
    }
    wchar_t* last = wcsrchr(buffer, L'\\');
    if (last != nullptr && last[1] != L'\0') {
        *filePart = last + 1;
    }
}

void SetFilePartA(LPSTR buffer, LPSTR* filePart) {
    if (filePart == nullptr) {
        return;
    }
    *filePart = nullptr;
    if (buffer == nullptr) {
        return;
    }
    char* last = strrchr(buffer, '\\');
    if (last != nullptr && last[1] != '\0') {
        *filePart = last + 1;
    }
}

DWORD CopyLogicalPathW(const wchar_t* src, DWORD srcLen, DWORD bufferLen,
                       LPWSTR buffer, LPWSTR* filePart) {
    if (bufferLen <= srcLen || buffer == nullptr) {
        return srcLen + 1;
    }
    memcpy(buffer, src, (static_cast<size_t>(srcLen) + 1) * sizeof(wchar_t));
    SetFilePartW(buffer, filePart);
    return srcLen;
}

DWORD CopyLogicalPathA(const wchar_t* src, DWORD bufferLen, LPSTR buffer,
                       LPSTR* filePart) {
    char tmp[2048];
    int bytesNoNul = 0;
    if (!WideToAnsi(src, tmp, ARRAYSIZE(tmp), &bytesNoNul)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    DWORD srcLen = static_cast<DWORD>(bytesNoNul);
    if (bufferLen <= srcLen || buffer == nullptr) {
        return srcLen + 1;
    }
    memcpy(buffer, tmp, static_cast<size_t>(srcLen) + 1);
    SetFilePartA(buffer, filePart);
    return srcLen;
}

DWORD LogicalFullPathName(const wchar_t* path, wchar_t* out, int cap) {
    if (g_vfsCwdLen == 0 || path == nullptr || out == nullptr || cap <= 0) {
        return 0;
    }
    if (!IsFullyQualifiedPath(path)) {
        wchar_t joined[1024];
        if (ComposeUnderVfsCwd(path, joined, 1024)) {
            DWORD n = TrueGetFullPathNameW(joined, cap, out, nullptr);
            if (n > 0 && n < static_cast<DWORD>(cap)) {
                return n;
            }
        }
    }

    wchar_t actual[1024];
    DWORD n = TrueGetFullPathNameW(path, 1024, actual, nullptr);
    if (n == 0 || n >= 1024) {
        return 0;
    }
    wchar_t actualLower[1024];
    memcpy(actualLower, actual, (static_cast<size_t>(n) + 1) * sizeof(wchar_t));
    int actualLen = LowerAndTrim(actualLower, n);
    if (ComposeFromActualCwdPath(actual, actualLower, actualLen, out, cap)) {
        return static_cast<DWORD>(lstrlenW(out));
    }
    return 0;
}

// CreateFile classification per docs/trace-format.md §5.2: the access mask
// decides read/write intent, and a disposition that can create or truncate
// the file is a write effect even with a read-only mask.
BYTE ClassifyCreateFile(DWORD access, DWORD disposition) {
    bool write =
        (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA |
                   FILE_APPEND_DATA | DELETE)) != 0 ||
        disposition == CREATE_NEW || disposition == CREATE_ALWAYS ||
        disposition == OPEN_ALWAYS || disposition == TRUNCATE_EXISTING;
    bool read = (access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA |
                           GENERIC_EXECUTE | FILE_EXECUTE)) != 0;
    if (read && write) {
        return trace::kOpenReadWrite;
    }
    if (write) {
        return trace::kOpenWrite;
    }
    if (read) {
        return trace::kOpenRead;
    }
    return trace::kProbe;  // metadata-only open (e.g. attribute query)
}

void MaybeMarkVfsMutation(const wchar_t* path) {
    if (!g_vfsMode || g_vfsCwdLen == 0 || path == nullptr) {
        return;
    }
    wchar_t logical[1024];
    if (IsUnderVfsRoot(path, logical, 1024)) {
        VfsMarkUnsafeOutput();
    }
}

void MaybeMarkVfsCreateMutation(const wchar_t* path, DWORD access,
                                DWORD disposition) {
    BYTE cls = ClassifyCreateFile(access, disposition);
    if (cls == trace::kOpenRead || cls == trace::kProbe) {
        return;
    }
    MaybeMarkVfsMutation(path);
}

ULONGLONG PackAccessDisposition(DWORD access, DWORD disposition) {
    return static_cast<ULONGLONG>(access) |
           (static_cast<ULONGLONG>(disposition) << 32);
}

void RecordCreateFile(const wchar_t* path, int pathLen, DWORD access,
                      DWORD disposition, DWORD status) {
    trace::Record(trace::kFile, ClassifyCreateFile(access, disposition),
                  status, PackAccessDisposition(access, disposition), path,
                  pathLen);
}

// --- Registry HKEY -> path map (docs/trace-format.md §5.4) ---------------
//
// Bounded: at most kRegMapCap live entries; overflow keys resolve as
// "<unresolved>", a visible gap rather than unbounded growth.

const int kRegMapCap = 256;
struct RegEntry {
    HKEY key;
    wchar_t* path;  // HeapAlloc'd, NUL-terminated
};
RegEntry g_regMap[kRegMapCap];
SRWLOCK g_regLock = SRWLOCK_INIT;

const wchar_t* PredefinedRootName(HKEY key) {
    if (key == HKEY_CLASSES_ROOT) return L"HKCR";
    if (key == HKEY_CURRENT_USER) return L"HKCU";
    if (key == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (key == HKEY_USERS) return L"HKU";
    if (key == HKEY_CURRENT_CONFIG) return L"HKCC";
    if (key == HKEY_PERFORMANCE_DATA) return L"HKPD";
    return nullptr;
}

void AppendBounded(wchar_t* buf, int cap, int& pos, const wchar_t* s) {
    if (s == nullptr) {
        return;
    }
    while (*s != L'\0' && pos < cap - 1) {
        buf[pos++] = *s++;
    }
    buf[pos] = L'\0';
}

// Resolves a key handle to a path into buf. Caller must NOT hold g_regLock.
void ResolveKey(HKEY key, wchar_t* buf, int cap) {
    int pos = 0;
    buf[0] = L'\0';
    const wchar_t* root = PredefinedRootName(key);
    if (root != nullptr) {
        AppendBounded(buf, cap, pos, root);
        return;
    }
    AcquireSRWLockShared(&g_regLock);
    for (int i = 0; i < kRegMapCap; i++) {
        if (g_regMap[i].key == key && g_regMap[i].path != nullptr) {
            AppendBounded(buf, cap, pos, g_regMap[i].path);
            ReleaseSRWLockShared(&g_regLock);
            return;
        }
    }
    ReleaseSRWLockShared(&g_regLock);
    AppendBounded(buf, cap, pos, L"<unresolved>");
}

// Composes parent-path + "\" + subkey into buf (subkey may be null).
void ComposeKeyPath(HKEY parent, const wchar_t* subKey, wchar_t* buf,
                    int cap) {
    ResolveKey(parent, buf, cap);
    if (subKey != nullptr && subKey[0] != L'\0') {
        int pos = lstrlenW(buf);
        AppendBounded(buf, cap, pos, L"\\");
        AppendBounded(buf, cap, pos, subKey);
    }
}

void RegMapAdd(HKEY key, const wchar_t* fullPath) {
    SIZE_T bytes = (static_cast<SIZE_T>(lstrlenW(fullPath)) + 1) * 2;
    wchar_t* copy =
        static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, bytes));
    if (copy == nullptr) {
        return;
    }
    memcpy(copy, fullPath, bytes);
    AcquireSRWLockExclusive(&g_regLock);
    int freeSlot = -1;
    for (int i = 0; i < kRegMapCap; i++) {
        if (g_regMap[i].key == key && g_regMap[i].path != nullptr) {
            HeapFree(GetProcessHeap(), 0, g_regMap[i].path);
            g_regMap[i].path = copy;
            ReleaseSRWLockExclusive(&g_regLock);
            return;
        }
        if (freeSlot < 0 && g_regMap[i].path == nullptr) {
            freeSlot = i;
        }
    }
    if (freeSlot >= 0) {
        g_regMap[freeSlot].key = key;
        g_regMap[freeSlot].path = copy;
        copy = nullptr;
    }
    ReleaseSRWLockExclusive(&g_regLock);
    if (copy != nullptr) {
        HeapFree(GetProcessHeap(), 0, copy);  // map full: drop, stay bounded
    }
}

void RegMapRemove(HKEY key) {
    AcquireSRWLockExclusive(&g_regLock);
    for (int i = 0; i < kRegMapCap; i++) {
        if (g_regMap[i].key == key && g_regMap[i].path != nullptr) {
            HeapFree(GetProcessHeap(), 0, g_regMap[i].path);
            g_regMap[i].path = nullptr;
            g_regMap[i].key = nullptr;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_regLock);
}

// --- File hooks ----------------------------------------------------------

HANDLE WINAPI HookedCreateFileW(LPCWSTR path, DWORD access, DWORD share,
                                LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                                DWORD flags, HANDLE templ) {
    // VFS mode: a read-only open under the session root is served from the
    // agent (hydrated to a local scratch copy). On any miss we fall through to
    // the normal local open below.
    bool handled = false;
    wchar_t logical[1024];
    HANDLE redirected = VfsTryRedirect(path, access, share, sa, disposition,
                                       flags, templ, &handled, logical,
                                       ARRAYSIZE(logical));
    if (handled) {
        // Record the redirected read under its LOGICAL (requested) path so the
        // action's true input set - the VFS-supplied sources and headers - is
        // captured in the trace. Without this a redirected read is invisible to
        // the trace, so a changed source would not move the action cache's strong
        // key and a stale result could be served (BLOCK-A). Preserve the
        // redirected open's own GetLastError across the recording I/O.
        DWORD saved = GetLastError();
        const wchar_t* recordPath = logical[0] != L'\0' ? logical : path;
        // Internal True* calls may re-enter hooks; restoration makes the outer
        // logical-path record visible while nested scratch records stay hidden.
        if (!g_vfsInternalIoActive) {
            RecordCreateFile(recordPath, -1, access, disposition,
                             redirected == INVALID_HANDLE_VALUE ? saved : 0);
        }
        SetLastError(saved);
        return redirected;
    }

    MaybeMarkVfsCreateMutation(path, access, disposition);
    HANDLE h =
        TrueCreateFileW(path, access, share, sa, disposition, flags, templ);
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        RecordCreateFile(path, -1, access, disposition,
                         h == INVALID_HANDLE_VALUE ? saved : 0);
    }
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedCreateFileA(LPCSTR path, DWORD access, DWORD share,
                                LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                                DWORD flags, HANDLE templ) {
    WideArg w(path);
    // VFS mode: classify on the widened path and redirect read-only opens the
    // same way as the W variant. The redirected handle is opened via the W path
    // (a handle is a handle), avoiding an ANSI round-trip on the scratch name.
    if (g_vfsMode && path != nullptr) {
        if (w.get() != nullptr) {
            bool handled = false;
            wchar_t logical[1024];
            HANDLE redirected = VfsTryRedirect(w.get(), access, share, sa,
                                               disposition, flags, templ,
                                               &handled, logical,
                                               ARRAYSIZE(logical));
            if (handled) {
                // Record the redirected read under its logical (requested) path,
                // same as the W variant - keep VFS-supplied inputs in the trace
                // so the action cache's strong key covers them (BLOCK-A).
                DWORD saved = GetLastError();
                const wchar_t* recordPath =
                    logical[0] != L'\0' ? logical : w.get();
                if (!g_vfsInternalIoActive) {
                    RecordCreateFile(
                        recordPath, -1, access, disposition,
                        redirected == INVALID_HANDLE_VALUE ? saved : 0);
                }
                SetLastError(saved);
                return redirected;
            }
        }
    }

    MaybeMarkVfsCreateMutation(w.get(), access, disposition);
    HANDLE h =
        TrueCreateFileA(path, access, share, sa, disposition, flags, templ);
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        RecordCreateFile(w.get(), w.length(), access, disposition,
                         h == INVALID_HANDLE_VALUE ? saved : 0);
    }
    SetLastError(saved);
    return h;
}

DWORD WINAPI HookedGetCurrentDirectoryW(DWORD bufferLen, LPWSTR buffer) {
    if (g_vfsCwdLen > 0) {
        const wchar_t* cwd =
            g_vfsCwdDisplayLen > 0 ? g_vfsCwdDisplay : g_vfsCwd;
        DWORD cwdLen = static_cast<DWORD>(
            g_vfsCwdDisplayLen > 0 ? g_vfsCwdDisplayLen : g_vfsCwdLen);
        return CopyLogicalPathW(cwd, cwdLen, bufferLen, buffer, nullptr);
    }
    return TrueGetCurrentDirectoryW(bufferLen, buffer);
}

DWORD WINAPI HookedGetCurrentDirectoryA(DWORD bufferLen, LPSTR buffer) {
    if (g_vfsCwdLen > 0) {
        const wchar_t* cwd =
            g_vfsCwdDisplayLen > 0 ? g_vfsCwdDisplay : g_vfsCwd;
        return CopyLogicalPathA(cwd, bufferLen, buffer, nullptr);
    }
    return TrueGetCurrentDirectoryA(bufferLen, buffer);
}

BOOL WINAPI HookedSetCurrentDirectoryW(LPCWSTR path) {
    // In scratch-cwd VFS mode, changing cwd would desync the static
    // logical/scratch cwd mapping. Fail fast in the remote attempt and mark it
    // for local rerun instead of exposing inconsistent cwd behavior.
    if (g_vfsMode && g_vfsCwdLen > 0) {
        VfsMarkUnvirtualized();
        SetLastError(ERROR_RETRY);
        return FALSE;
    }
    return TrueSetCurrentDirectoryW(path);
}

BOOL WINAPI HookedSetCurrentDirectoryA(LPCSTR path) {
    if (g_vfsMode && g_vfsCwdLen > 0) {
        VfsMarkUnvirtualized();
        SetLastError(ERROR_RETRY);
        return FALSE;
    }
    return TrueSetCurrentDirectoryA(path);
}

DWORD WINAPI HookedGetFullPathNameW(LPCWSTR path, DWORD bufferLen,
                                    LPWSTR buffer, LPWSTR* filePart) {
    wchar_t logical[1024];
    DWORD logicalLen = LogicalFullPathName(path, logical, 1024);
    if (logicalLen > 0) {
        return CopyLogicalPathW(logical, logicalLen, bufferLen, buffer,
                                filePart);
    }
    return TrueGetFullPathNameW(path, bufferLen, buffer, filePart);
}

DWORD WINAPI HookedGetFullPathNameA(LPCSTR path, DWORD bufferLen, LPSTR buffer,
                                    LPSTR* filePart) {
    WideArg w(path);
    if (w.get() != nullptr) {
        wchar_t logical[1024];
        DWORD logicalLen = LogicalFullPathName(w.get(), logical, 1024);
        if (logicalLen > 0) {
            return CopyLogicalPathA(logical, bufferLen, buffer, filePart);
        }
    }
    return TrueGetFullPathNameA(path, bufferLen, buffer, filePart);
}

DWORD WINAPI HookedGetFileAttributesW(LPCWSTR path) {
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = path;
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (VfsMaterializeForProbe(path, local, 1024, logical, 1024, &handled)) {
        attrs = VfsInternalGetFileAttributesW(local);
        recordPath = logical;
    } else if (handled) {
        attrs = INVALID_FILE_ATTRIBUTES;
        recordPath = logical;
    } else {
        attrs = TrueGetFileAttributesW(path);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kProbe,
                      attrs == INVALID_FILE_ATTRIBUTES ? saved : 0, attrs,
                      recordPath);
    }
    SetLastError(saved);
    return attrs;
}

DWORD WINAPI HookedGetFileAttributesA(LPCSTR path) {
    WideArg w(path);
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = w.get();
    DWORD attrs = INVALID_FILE_ATTRIBUTES;
    if (VfsMaterializeForProbe(w.get(), local, 1024, logical, 1024,
                               &handled)) {
        attrs = VfsInternalGetFileAttributesW(local);
        recordPath = logical;
    } else if (handled) {
        attrs = INVALID_FILE_ATTRIBUTES;
        recordPath = logical;
    } else {
        attrs = TrueGetFileAttributesA(path);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kProbe,
                      attrs == INVALID_FILE_ATTRIBUTES ? saved : 0, attrs,
                      recordPath, -1);
    }
    SetLastError(saved);
    return attrs;
}

ULONGLONG ExAttrsExtra(BOOL ok, GET_FILEEX_INFO_LEVELS level, LPVOID info) {
    if (ok && level == GetFileExInfoStandard && info != nullptr) {
        return static_cast<const WIN32_FILE_ATTRIBUTE_DATA*>(info)
            ->dwFileAttributes;
    }
    return INVALID_FILE_ATTRIBUTES;
}

BOOL WINAPI HookedGetFileAttributesExW(LPCWSTR path,
                                       GET_FILEEX_INFO_LEVELS level,
                                       LPVOID info) {
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = path;
    BOOL ok = FALSE;
    if (VfsMaterializeForProbe(path, local, 1024, logical, 1024, &handled)) {
        ok = VfsInternalGetFileAttributesExW(local, level, info);
        recordPath = logical;
    } else if (handled) {
        ok = FALSE;
        recordPath = logical;
    } else {
        ok = TrueGetFileAttributesExW(path, level, info);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kProbe, ok ? 0 : saved,
                      ExAttrsExtra(ok, level, info), recordPath);
    }
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedGetFileAttributesExA(LPCSTR path,
                                       GET_FILEEX_INFO_LEVELS level,
                                       LPVOID info) {
    WideArg w(path);
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = w.get();
    BOOL ok = FALSE;
    if (VfsMaterializeForProbe(w.get(), local, 1024, logical, 1024,
                               &handled)) {
        ok = VfsInternalGetFileAttributesExW(local, level, info);
        recordPath = logical;
    } else if (handled) {
        ok = FALSE;
        recordPath = logical;
    } else {
        ok = TrueGetFileAttributesExA(path, level, info);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kProbe, ok ? 0 : saved,
                      ExAttrsExtra(ok, level, info), recordPath, -1);
    }
    SetLastError(saved);
    return ok;
}

HANDLE WINAPI HookedFindFirstFileW(LPCWSTR pattern, LPWIN32_FIND_DATAW data) {
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = pattern;
    HANDLE h = INVALID_HANDLE_VALUE;
    if (VfsFailWildcardEnumeration(pattern, logical, 1024, &handled)) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else if (VfsMaterializeForProbe(pattern, local, 1024, logical, 1024,
                                      &handled)) {
        h = VfsInternalFindFirstFileW(local, data);
        recordPath = logical;
    } else if (handled) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else {
        h = TrueFindFirstFileW(pattern, data);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kEnumerate,
                      h == INVALID_HANDLE_VALUE ? saved : 0, 0, recordPath);
    }
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileA(LPCSTR pattern, LPWIN32_FIND_DATAA data) {
    WideArg w(pattern);
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = w.get();
    HANDLE h = INVALID_HANDLE_VALUE;
    if (VfsFailWildcardEnumeration(w.get(), logical, 1024, &handled)) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else if (VfsMaterializeForProbe(w.get(), local, 1024, logical, 1024,
                                      &handled)) {
        char localA[2048];
        if (WideToAnsi(local, localA, ARRAYSIZE(localA), nullptr)) {
            h = VfsInternalFindFirstFileA(localA, data);
        }
        recordPath = logical;
    } else if (handled) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else {
        h = TrueFindFirstFileA(pattern, data);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kEnumerate,
                      h == INVALID_HANDLE_VALUE ? saved : 0, 0, recordPath, -1);
    }
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileExW(LPCWSTR pattern,
                                     FINDEX_INFO_LEVELS level, LPVOID data,
                                     FINDEX_SEARCH_OPS op, LPVOID filter,
                                     DWORD flags) {
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = pattern;
    HANDLE h = INVALID_HANDLE_VALUE;
    if (VfsFailWildcardEnumeration(pattern, logical, 1024, &handled)) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else if (VfsMaterializeForProbe(pattern, local, 1024, logical, 1024,
                                      &handled)) {
        h = VfsInternalFindFirstFileExW(local, level, data, op, filter, flags);
        recordPath = logical;
    } else if (handled) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else {
        h = TrueFindFirstFileExW(pattern, level, data, op, filter, flags);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kEnumerate,
                      h == INVALID_HANDLE_VALUE ? saved : 0, 0, recordPath);
    }
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileExA(LPCSTR pattern, FINDEX_INFO_LEVELS level,
                                     LPVOID data, FINDEX_SEARCH_OPS op,
                                     LPVOID filter, DWORD flags) {
    WideArg w(pattern);
    wchar_t local[1024];
    wchar_t logical[1024];
    bool handled = false;
    const wchar_t* recordPath = w.get();
    HANDLE h = INVALID_HANDLE_VALUE;
    if (VfsFailWildcardEnumeration(w.get(), logical, 1024, &handled)) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else if (VfsMaterializeForProbe(w.get(), local, 1024, logical, 1024,
                                      &handled)) {
        char localA[2048];
        if (WideToAnsi(local, localA, ARRAYSIZE(localA), nullptr)) {
            h = VfsInternalFindFirstFileExA(localA, level, data, op, filter,
                                            flags);
        }
        recordPath = logical;
    } else if (handled) {
        h = INVALID_HANDLE_VALUE;
        recordPath = logical;
    } else {
        h = TrueFindFirstFileExA(pattern, level, data, op, filter, flags);
    }
    DWORD saved = GetLastError();
    if (!g_vfsInternalIoActive) {
        trace::Record(trace::kFile, trace::kEnumerate,
                      h == INVALID_HANDLE_VALUE ? saved : 0, 0, recordPath, -1);
    }
    SetLastError(saved);
    return h;
}

BOOL WINAPI HookedDeleteFileW(LPCWSTR path) {
    MaybeMarkVfsMutation(path);
    BOOL ok = TrueDeleteFileW(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kDelete, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedDeleteFileA(LPCSTR path) {
    WideArg w(path);
    MaybeMarkVfsMutation(w.get());
    BOOL ok = TrueDeleteFileA(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kDelete, ok ? 0 : saved, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileW(LPCWSTR from, LPCWSTR to) {
    MaybeMarkVfsMutation(from);
    MaybeMarkVfsMutation(to);
    BOOL ok = TrueMoveFileW(from, to);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, 0, from, -1, to);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileA(LPCSTR from, LPCSTR to) {
    WideArg wf(from);
    WideArg wt(to);
    MaybeMarkVfsMutation(wf.get());
    MaybeMarkVfsMutation(wt.get());
    BOOL ok = TrueMoveFileA(from, to);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, 0, wf.get(),
                  wf.length(), wt.get(), wt.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) {
    MaybeMarkVfsMutation(from);
    MaybeMarkVfsMutation(to);
    BOOL ok = TrueMoveFileExW(from, to, flags);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, flags, from, -1,
                  to);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileExA(LPCSTR from, LPCSTR to, DWORD flags) {
    WideArg wf(from);
    WideArg wt(to);
    MaybeMarkVfsMutation(wf.get());
    MaybeMarkVfsMutation(wt.get());
    BOOL ok = TrueMoveFileExA(from, to, flags);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, flags, wf.get(),
                  wf.length(), wt.get(), wt.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedCreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES sa) {
    MaybeMarkVfsMutation(path);
    BOOL ok = TrueCreateDirectoryW(path, sa);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kCreateDir, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedCreateDirectoryA(LPCSTR path, LPSECURITY_ATTRIBUTES sa) {
    WideArg w(path);
    MaybeMarkVfsMutation(w.get());
    BOOL ok = TrueCreateDirectoryA(path, sa);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kCreateDir, ok ? 0 : saved, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedRemoveDirectoryW(LPCWSTR path) {
    MaybeMarkVfsMutation(path);
    BOOL ok = TrueRemoveDirectoryW(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kRemoveDir, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedRemoveDirectoryA(LPCSTR path) {
    WideArg w(path);
    MaybeMarkVfsMutation(w.get());
    BOOL ok = TrueRemoveDirectoryA(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kRemoveDir, ok ? 0 : saved, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return ok;
}

// --- Process hooks -------------------------------------------------------

BOOL WINAPI HookedCreateProcessW(LPCWSTR app, LPWSTR cmd,
                                 LPSECURITY_ATTRIBUTES pa,
                                 LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                 DWORD flags, LPVOID env, LPCWSTR dir,
                                 LPSTARTUPINFOW si,
                                 LPPROCESS_INFORMATION pi) {
    const char* dll = trace::DllPathA();
    BOOL ok;
    DWORD saved;
    if (dll != nullptr && trace::Enabled()) {
        ok = DetourCreateProcessWithDllExW(app, cmd, pa, ta, inherit, flags,
                                           env, dir, si, pi, dll,
                                           TrueCreateProcessW);
        saved = GetLastError();
        if (!ok) {
            // Injection-capable spawn failed (Detours kills the child on
            // injection failure). Observe-only must not break the build:
            // retry untraced; the missing child trace surfaces as a reader
            // warning.
            ok = TrueCreateProcessW(app, cmd, pa, ta, inherit, flags, env,
                                    dir, si, pi);
            saved = GetLastError();
        }
    } else {
        ok = TrueCreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir,
                                si, pi);
        saved = GetLastError();
    }
    trace::Record(trace::kProcess, trace::kChildCreated, ok ? 0 : saved,
                  ok && pi != nullptr ? pi->dwProcessId : 0, app, -1, cmd);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedCreateProcessA(LPCSTR app, LPSTR cmd,
                                 LPSECURITY_ATTRIBUTES pa,
                                 LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                 DWORD flags, LPVOID env, LPCSTR dir,
                                 LPSTARTUPINFOA si,
                                 LPPROCESS_INFORMATION pi) {
    const char* dll = trace::DllPathA();
    BOOL ok;
    DWORD saved;
    if (dll != nullptr && trace::Enabled()) {
        ok = DetourCreateProcessWithDllExA(app, cmd, pa, ta, inherit, flags,
                                           env, dir, si, pi, dll,
                                           TrueCreateProcessA);
        saved = GetLastError();
        if (!ok) {
            ok = TrueCreateProcessA(app, cmd, pa, ta, inherit, flags, env,
                                    dir, si, pi);
            saved = GetLastError();
        }
    } else {
        ok = TrueCreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir,
                                si, pi);
        saved = GetLastError();
    }
    WideArg wapp(app);
    WideArg wcmd(cmd);
    trace::Record(trace::kProcess, trace::kChildCreated, ok ? 0 : saved,
                  ok && pi != nullptr ? pi->dwProcessId : 0, wapp.get(),
                  wapp.length(), wcmd.get(), wcmd.length());
    SetLastError(saved);
    return ok;
}

// --- Registry hooks ------------------------------------------------------

const int kKeyPathCap = 2048;

LSTATUS APIENTRY HookedRegOpenKeyExW(HKEY parent, LPCWSTR subKey,
                                     DWORD options, REGSAM sam,
                                     PHKEY result) {
    LSTATUS st = TrueRegOpenKeyExW(parent, subKey, options, sam, result);
    DWORD saved = GetLastError();
    wchar_t full[kKeyPathCap];
    ComposeKeyPath(parent, subKey, full, kKeyPathCap);
    if (st == ERROR_SUCCESS && result != nullptr && *result != nullptr) {
        RegMapAdd(*result, full);
    }
    trace::Record(trace::kRegistry, trace::kOpenKey,
                  static_cast<DWORD>(st), 0, full);
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegOpenKeyExA(HKEY parent, LPCSTR subKey,
                                     DWORD options, REGSAM sam,
                                     PHKEY result) {
    LSTATUS st = TrueRegOpenKeyExA(parent, subKey, options, sam, result);
    DWORD saved = GetLastError();
    WideArg wsub(subKey);
    wchar_t full[kKeyPathCap];
    ComposeKeyPath(parent, wsub.get(), full, kKeyPathCap);
    if (st == ERROR_SUCCESS && result != nullptr && *result != nullptr) {
        RegMapAdd(*result, full);
    }
    trace::Record(trace::kRegistry, trace::kOpenKey,
                  static_cast<DWORD>(st), 0, full);
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegQueryValueExW(HKEY key, LPCWSTR value,
                                        LPDWORD reserved, LPDWORD type,
                                        LPBYTE data, LPDWORD cb) {
    LSTATUS st = TrueRegQueryValueExW(key, value, reserved, type, data, cb);
    DWORD saved = GetLastError();
    wchar_t keyPath[kKeyPathCap];
    ResolveKey(key, keyPath, kKeyPathCap);
    ULONGLONG extra =
        (st == ERROR_SUCCESS && type != nullptr) ? *type : 0;
    trace::Record(trace::kRegistry, trace::kQueryValue,
                  static_cast<DWORD>(st), extra, keyPath, -1, value);
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegQueryValueExA(HKEY key, LPCSTR value,
                                        LPDWORD reserved, LPDWORD type,
                                        LPBYTE data, LPDWORD cb) {
    LSTATUS st = TrueRegQueryValueExA(key, value, reserved, type, data, cb);
    DWORD saved = GetLastError();
    wchar_t keyPath[kKeyPathCap];
    ResolveKey(key, keyPath, kKeyPathCap);
    WideArg wvalue(value);
    ULONGLONG extra =
        (st == ERROR_SUCCESS && type != nullptr) ? *type : 0;
    trace::Record(trace::kRegistry, trace::kQueryValue,
                  static_cast<DWORD>(st), extra, keyPath, -1, wvalue.get(),
                  wvalue.length());
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegGetValueW(HKEY key, LPCWSTR subKey, LPCWSTR value,
                                    DWORD flags, LPDWORD type, PVOID data,
                                    LPDWORD cb) {
    LSTATUS st = TrueRegGetValueW(key, subKey, value, flags, type, data, cb);
    DWORD saved = GetLastError();
    wchar_t full[kKeyPathCap];
    ComposeKeyPath(key, subKey, full, kKeyPathCap);
    ULONGLONG extra =
        (st == ERROR_SUCCESS && type != nullptr) ? *type : 0;
    trace::Record(trace::kRegistry, trace::kQueryValue,
                  static_cast<DWORD>(st), extra, full, -1, value);
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegGetValueA(HKEY key, LPCSTR subKey, LPCSTR value,
                                    DWORD flags, LPDWORD type, PVOID data,
                                    LPDWORD cb) {
    LSTATUS st = TrueRegGetValueA(key, subKey, value, flags, type, data, cb);
    DWORD saved = GetLastError();
    WideArg wsub(subKey);
    WideArg wvalue(value);
    wchar_t full[kKeyPathCap];
    ComposeKeyPath(key, wsub.get(), full, kKeyPathCap);
    ULONGLONG extra =
        (st == ERROR_SUCCESS && type != nullptr) ? *type : 0;
    trace::Record(trace::kRegistry, trace::kQueryValue,
                  static_cast<DWORD>(st), extra, full, -1, wvalue.get(),
                  wvalue.length());
    SetLastError(saved);
    return st;
}

LSTATUS APIENTRY HookedRegCloseKey(HKEY key) {
    // Remove before closing so a concurrent open that reuses the handle
    // value can't be mis-attributed to the old path. TrueRegCloseKey runs
    // last, so the caller's GetLastError reflects the close, not the heap
    // free in RegMapRemove; no save/restore needed here.
    RegMapRemove(key);
    return TrueRegCloseKey(key);
}

// --- Environment hooks ---------------------------------------------------

DWORD WINAPI HookedGetEnvironmentVariableW(LPCWSTR name, LPWSTR buf,
                                           DWORD size) {
    DWORD ret = TrueGetEnvironmentVariableW(name, buf, size);
    DWORD saved = GetLastError();
    if (name != nullptr) {
        if (ret == 0 && saved == ERROR_ENVVAR_NOT_FOUND) {
            trace::Record(trace::kEnv, trace::kEnvRead,
                          ERROR_ENVVAR_NOT_FOUND, 0, name);
        } else if (ret > 0 && ret < size && buf != nullptr) {
            trace::Record(trace::kEnv, trace::kEnvRead, 0, 0, name, -1, buf,
                          static_cast<int>(ret));
        }
        // ret >= size is a length probe; the caller's follow-up call with
        // a large-enough buffer produces the record.
    }
    SetLastError(saved);
    return ret;
}

DWORD WINAPI HookedGetEnvironmentVariableA(LPCSTR name, LPSTR buf,
                                           DWORD size) {
    DWORD ret = TrueGetEnvironmentVariableA(name, buf, size);
    DWORD saved = GetLastError();
    if (name != nullptr) {
        WideArg wname(name);
        if (ret == 0 && saved == ERROR_ENVVAR_NOT_FOUND) {
            trace::Record(trace::kEnv, trace::kEnvRead,
                          ERROR_ENVVAR_NOT_FOUND, 0, wname.get(),
                          wname.length());
        } else if (ret > 0 && ret < size && buf != nullptr) {
            WideArg wvalue(buf);
            trace::Record(trace::kEnv, trace::kEnvRead, 0, 0, wname.get(),
                          wname.length(), wvalue.get(), wvalue.length());
        }
    }
    SetLastError(saved);
    return ret;
}

// CRT runtimes snapshot the whole environment block once at startup and
// serve getenv() from the copy; without this hook those reads would be
// invisible. Recorded as a block read (docs/trace-format.md §5.5 op 2).
LPWCH WINAPI HookedGetEnvironmentStringsW() {
    LPWCH block = TrueGetEnvironmentStringsW();
    DWORD saved = GetLastError();
    trace::Record(trace::kEnv, trace::kEnvBlockRead,
                  block == nullptr ? saved : 0, 0, nullptr);
    SetLastError(saved);
    return block;
}

// --- NT-layer hooks ------------------------------------------------------
//
// Only NtSetInformationFile, and only for the rename and disposition classes.
// clang-cl/lld write each output to a run-varying temp and then rename it onto
// the final name with NtSetInformationFile(FileRenameInformation), bypassing
// the Win32 MoveFile family -- invisible to the Win32 hooks and the documented
// gap of docs/trace-format.md §8. MSVC cl/link do not import ntdll at all
// (verified with dumpbin /imports) and their reads/enumerations go through the
// Win32 layer, so this is the only NT hook the target toolchains require.

// Resolves a handle to its full DOS path into buf (NUL-terminated). Returns the
// WCHAR length (excluding NUL), or 0 on failure/would-truncate. Uses only
// GetFinalPathNameByHandleW, which queries the existing handle and opens
// nothing, so it honors the re-entrancy contract (no path back into a hook).
int PathFromHandle(HANDLE h, wchar_t* buf, DWORD cap) {
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD n = GetFinalPathNameByHandleW(h, buf, cap,
                                        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0 || n >= cap) {
        return 0;  // failure, or the path would not fit (avoid truncation)
    }
    return static_cast<int>(n);
}

NTSTATUS NTAPI HookedNtSetInformationFile(HANDLE handle, PIO_STATUS_BLOCK iosb,
                                          PVOID info, ULONG length,
                                          FILE_INFORMATION_CLASS infoClass) {
    const int cls = static_cast<int>(infoClass);
    const bool isRename =
        cls == kFileRenameInformation || cls == kFileRenameInformationEx;
    const bool isDispose =
        cls == kFileDispositionInformation || cls == kFileDispositionInformationEx;

    // A rename retargets the handle, so the source path must be captured BEFORE
    // the real call runs. Capturing is a read-only query; it does not change the
    // call's outcome (observe-only). GetFinalPathNameByHandleW clobbers the
    // thread's last error here, but that is harmless: the error the caller sees
    // is saved AFTER True* below and restored on every return path.
    wchar_t src[1024];
    int srcLen = 0;
    if (isRename || isDispose) {
        srcLen = PathFromHandle(handle, src, 1024);
    }

    NTSTATUS st = TrueNtSetInformationFile(handle, iosb, info, length, infoClass);
    DWORD saved = GetLastError();

    // NT_SUCCESS(st): the status high bit (sign bit) is clear.
    if (st >= 0 && srcLen > 0 && info != nullptr) {
        if (isRename &&
            length >= offsetof(FileRenameInformationLayout, FileName)) {
            const auto* ri = static_cast<const FileRenameInformationLayout*>(info);
            const ULONG nameBytes = ri->FileNameLength;
            // Bound the variable-length name read to the caller-provided buffer.
            const ULONG avail =
                length - offsetof(FileRenameInformationLayout, FileName);
            if (nameBytes > 0 && nameBytes <= avail) {
                const int nameChars = static_cast<int>(nameBytes / sizeof(WCHAR));
                if (ri->RootDirectory == nullptr) {
                    // Fully-qualified NT path in FileName (\??\C:\...).
                    trace::Record(trace::kFile, trace::kMove, 0, 0, src, srcLen,
                                  ri->FileName, nameChars);
                } else {
                    // Relative to RootDirectory: resolve the dir and compose
                    // base + "\" + FileName into a bounded buffer.
                    wchar_t base[1024];
                    int baseLen = PathFromHandle(ri->RootDirectory, base, 1024);
                    if (baseLen > 0) {
                        wchar_t dest[2048];
                        int p = 0;
                        for (int i = 0; i < baseLen && p < 2046; i++) {
                            dest[p++] = base[i];
                        }
                        if (p < 2046) {
                            dest[p++] = L'\\';
                        }
                        for (int i = 0; i < nameChars && p < 2047; i++) {
                            dest[p++] = ri->FileName[i];
                        }
                        trace::Record(trace::kFile, trace::kMove, 0, 0, src,
                                      srcLen, dest, p);
                    }
                }
            }
        } else if (isDispose) {
            bool deleting = false;
            if (cls == kFileDispositionInformation &&
                length >= sizeof(FileDispositionInformationLayout)) {
                deleting = static_cast<const FileDispositionInformationLayout*>(info)
                               ->DeleteFile != 0;
            } else if (cls == kFileDispositionInformationEx &&
                       length >= sizeof(FileDispositionInformationExLayout)) {
                deleting =
                    (static_cast<const FileDispositionInformationExLayout*>(info)
                         ->Flags &
                     kFileDispositionDelete) != 0;
            }
            if (deleting) {
                trace::Record(trace::kFile, trace::kDelete, 0, 0, src, srcLen);
            }
        }
    }
    SetLastError(saved);
    return st;
}

// --- Hook table and DllMain ----------------------------------------------

struct HookPair {
    PVOID* trampoline;
    PVOID hook;
};

#define HOOK(name) \
    { &reinterpret_cast<PVOID&>(True##name), \
      reinterpret_cast<PVOID>(Hooked##name) }

const HookPair kHooks[] = {
    HOOK(CreateFileW),
    HOOK(CreateFileA),
    HOOK(GetFileAttributesW),
    HOOK(GetFileAttributesA),
    HOOK(GetFileAttributesExW),
    HOOK(GetFileAttributesExA),
    HOOK(FindFirstFileW),
    HOOK(FindFirstFileA),
    HOOK(FindFirstFileExW),
    HOOK(FindFirstFileExA),
    HOOK(GetCurrentDirectoryW),
    HOOK(GetCurrentDirectoryA),
    HOOK(SetCurrentDirectoryW),
    HOOK(SetCurrentDirectoryA),
    HOOK(GetFullPathNameW),
    HOOK(GetFullPathNameA),
    HOOK(DeleteFileW),
    HOOK(DeleteFileA),
    HOOK(MoveFileW),
    HOOK(MoveFileA),
    HOOK(MoveFileExW),
    HOOK(MoveFileExA),
    HOOK(CreateDirectoryW),
    HOOK(CreateDirectoryA),
    HOOK(RemoveDirectoryW),
    HOOK(RemoveDirectoryA),
    HOOK(CreateProcessW),
    HOOK(CreateProcessA),
    HOOK(RegOpenKeyExW),
    HOOK(RegOpenKeyExA),
    HOOK(RegQueryValueExW),
    HOOK(RegQueryValueExA),
    HOOK(RegGetValueW),
    HOOK(RegGetValueA),
    HOOK(RegCloseKey),
    HOOK(GetEnvironmentVariableW),
    HOOK(GetEnvironmentVariableA),
    HOOK(GetEnvironmentStringsW),
};

#undef HOOK

}  // namespace

// TrueCreateFileW / TrueGetEnvironmentVariableW are shared with the writer
// (common.h), so they live outside the anonymous namespace.
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                DWORD, DWORD, HANDLE) = CreateFileW;
DWORD(WINAPI* TrueGetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD) =
    GetEnvironmentVariableW;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (reason == DLL_PROCESS_ATTACH) {
        trace::Initialize(instance);
        // Read VFS config with the real env API, before any hooks are armed.
        InitVfsConfig();
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        LONG err = NO_ERROR;
        for (const HookPair& h : kHooks) {
            err = DetourAttach(h.trampoline, h.hook);
            if (err != NO_ERROR) {
                break;
            }
        }
        // NT-layer hook, resolved at runtime (not a static import). Attach only
        // if the table above succeeded and ntdll exposes the function; a missing
        // NtSetInformationFile is not fatal (the Win32 hooks still load).
        if (err == NO_ERROR) {
            if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll")) {
                TrueNtSetInformationFile = reinterpret_cast<NtSetInformationFile_t>(
                    reinterpret_cast<void*>(
                        GetProcAddress(ntdll, "NtSetInformationFile")));
            }
            if (TrueNtSetInformationFile != nullptr) {
                err = DetourAttach(
                    &reinterpret_cast<PVOID&>(TrueNtSetInformationFile),
                    reinterpret_cast<PVOID>(HookedNtSetInformationFile));
            }
        }
        if (err == NO_ERROR) {
            err = DetourTransactionCommit();
        } else {
            DetourTransactionAbort();
        }
        if (err != NO_ERROR) {
            return FALSE;  // refuse to load half-instrumented
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (reserved != nullptr) {
            // Process termination: threads may be frozen mid-write; let
            // the OS reclaim hooks and handles instead of racing them.
            return TRUE;
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        for (const HookPair& h : kHooks) {
            DetourDetach(h.trampoline, h.hook);
        }
        if (TrueNtSetInformationFile != nullptr) {
            DetourDetach(&reinterpret_cast<PVOID&>(TrueNtSetInformationFile),
                         reinterpret_cast<PVOID>(HookedNtSetInformationFile));
        }
        DetourTransactionCommit();
        trace::Shutdown();
    }
    return TRUE;
}
