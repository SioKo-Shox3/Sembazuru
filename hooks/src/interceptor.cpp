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
        if (needed <= 0) {
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
    wchar_t stack_[kStackCap];
    wchar_t* heap_ = nullptr;
    const wchar_t* ptr_ = nullptr;
    int len_ = 0;
};

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
    HANDLE h =
        TrueCreateFileW(path, access, share, sa, disposition, flags, templ);
    DWORD saved = GetLastError();
    RecordCreateFile(path, -1, access, disposition,
                     h == INVALID_HANDLE_VALUE ? saved : 0);
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedCreateFileA(LPCSTR path, DWORD access, DWORD share,
                                LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                                DWORD flags, HANDLE templ) {
    HANDLE h =
        TrueCreateFileA(path, access, share, sa, disposition, flags, templ);
    DWORD saved = GetLastError();
    WideArg w(path);
    RecordCreateFile(w.get(), w.length(), access, disposition,
                     h == INVALID_HANDLE_VALUE ? saved : 0);
    SetLastError(saved);
    return h;
}

DWORD WINAPI HookedGetFileAttributesW(LPCWSTR path) {
    DWORD attrs = TrueGetFileAttributesW(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kProbe,
                  attrs == INVALID_FILE_ATTRIBUTES ? saved : 0, attrs, path);
    SetLastError(saved);
    return attrs;
}

DWORD WINAPI HookedGetFileAttributesA(LPCSTR path) {
    DWORD attrs = TrueGetFileAttributesA(path);
    DWORD saved = GetLastError();
    WideArg w(path);
    trace::Record(trace::kFile, trace::kProbe,
                  attrs == INVALID_FILE_ATTRIBUTES ? saved : 0, attrs,
                  w.get(), w.length());
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
    BOOL ok = TrueGetFileAttributesExW(path, level, info);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kProbe, ok ? 0 : saved,
                  ExAttrsExtra(ok, level, info), path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedGetFileAttributesExA(LPCSTR path,
                                       GET_FILEEX_INFO_LEVELS level,
                                       LPVOID info) {
    BOOL ok = TrueGetFileAttributesExA(path, level, info);
    DWORD saved = GetLastError();
    WideArg w(path);
    trace::Record(trace::kFile, trace::kProbe, ok ? 0 : saved,
                  ExAttrsExtra(ok, level, info), w.get(), w.length());
    SetLastError(saved);
    return ok;
}

HANDLE WINAPI HookedFindFirstFileW(LPCWSTR pattern, LPWIN32_FIND_DATAW data) {
    HANDLE h = TrueFindFirstFileW(pattern, data);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kEnumerate,
                  h == INVALID_HANDLE_VALUE ? saved : 0, 0, pattern);
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileA(LPCSTR pattern, LPWIN32_FIND_DATAA data) {
    HANDLE h = TrueFindFirstFileA(pattern, data);
    DWORD saved = GetLastError();
    WideArg w(pattern);
    trace::Record(trace::kFile, trace::kEnumerate,
                  h == INVALID_HANDLE_VALUE ? saved : 0, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileExW(LPCWSTR pattern,
                                     FINDEX_INFO_LEVELS level, LPVOID data,
                                     FINDEX_SEARCH_OPS op, LPVOID filter,
                                     DWORD flags) {
    HANDLE h = TrueFindFirstFileExW(pattern, level, data, op, filter, flags);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kEnumerate,
                  h == INVALID_HANDLE_VALUE ? saved : 0, 0, pattern);
    SetLastError(saved);
    return h;
}

HANDLE WINAPI HookedFindFirstFileExA(LPCSTR pattern, FINDEX_INFO_LEVELS level,
                                     LPVOID data, FINDEX_SEARCH_OPS op,
                                     LPVOID filter, DWORD flags) {
    HANDLE h = TrueFindFirstFileExA(pattern, level, data, op, filter, flags);
    DWORD saved = GetLastError();
    WideArg w(pattern);
    trace::Record(trace::kFile, trace::kEnumerate,
                  h == INVALID_HANDLE_VALUE ? saved : 0, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return h;
}

BOOL WINAPI HookedDeleteFileW(LPCWSTR path) {
    BOOL ok = TrueDeleteFileW(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kDelete, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedDeleteFileA(LPCSTR path) {
    BOOL ok = TrueDeleteFileA(path);
    DWORD saved = GetLastError();
    WideArg w(path);
    trace::Record(trace::kFile, trace::kDelete, ok ? 0 : saved, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileW(LPCWSTR from, LPCWSTR to) {
    BOOL ok = TrueMoveFileW(from, to);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, 0, from, -1, to);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileA(LPCSTR from, LPCSTR to) {
    BOOL ok = TrueMoveFileA(from, to);
    DWORD saved = GetLastError();
    WideArg wf(from);
    WideArg wt(to);
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, 0, wf.get(),
                  wf.length(), wt.get(), wt.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) {
    BOOL ok = TrueMoveFileExW(from, to, flags);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, flags, from, -1,
                  to);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedMoveFileExA(LPCSTR from, LPCSTR to, DWORD flags) {
    BOOL ok = TrueMoveFileExA(from, to, flags);
    DWORD saved = GetLastError();
    WideArg wf(from);
    WideArg wt(to);
    trace::Record(trace::kFile, trace::kMove, ok ? 0 : saved, flags, wf.get(),
                  wf.length(), wt.get(), wt.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedCreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES sa) {
    BOOL ok = TrueCreateDirectoryW(path, sa);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kCreateDir, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedCreateDirectoryA(LPCSTR path, LPSECURITY_ATTRIBUTES sa) {
    BOOL ok = TrueCreateDirectoryA(path, sa);
    DWORD saved = GetLastError();
    WideArg w(path);
    trace::Record(trace::kFile, trace::kCreateDir, ok ? 0 : saved, 0, w.get(),
                  w.length());
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedRemoveDirectoryW(LPCWSTR path) {
    BOOL ok = TrueRemoveDirectoryW(path);
    DWORD saved = GetLastError();
    trace::Record(trace::kFile, trace::kRemoveDir, ok ? 0 : saved, 0, path);
    SetLastError(saved);
    return ok;
}

BOOL WINAPI HookedRemoveDirectoryA(LPCSTR path) {
    BOOL ok = TrueRemoveDirectoryA(path);
    DWORD saved = GetLastError();
    WideArg w(path);
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
    // value can't be mis-attributed to the old path.
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
        DetourTransactionCommit();
        trace::Shutdown();
    }
    return TRUE;
}
