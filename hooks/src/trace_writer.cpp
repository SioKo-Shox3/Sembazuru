// Binary trace writer. Implements the writer side of docs/trace-format.md.
//
// Everything here runs inside hooked processes, possibly on many threads at
// once. Only True* trampolines and never-hooked APIs may be called (see
// common.h). All writes happen under one SRWLOCK, which is what gives
// records their atomicity on disk.

#include "common.h"

namespace trace {
namespace {

#pragma pack(push, 1)
struct FileHeader {
    char magic[4];
    DWORD version;
    DWORD pid;
    DWORD parentPid;
    ULONGLONG qpcFrequency;
    ULONGLONG startQpc;
    ULONGLONG startFiletime;
    // followed by: string exe_path, string command_line, string cwd
};
struct RecordHeader {
    BYTE type;
    BYTE op;
    WORD reserved;
    DWORD status;
    DWORD tid;
    ULONGLONG qpc;
    ULONGLONG extra;
    // followed by: string path, string aux
};
#pragma pack(pop)
static_assert(sizeof(FileHeader) == 40, "format v0 layout");
static_assert(sizeof(RecordHeader) == 28, "format v0 layout");

HMODULE g_self = nullptr;
DWORD g_pid = 0;
DWORD g_parentPid = 0;
ULONGLONG g_qpcFrequency = 0;
ULONGLONG g_startQpc = 0;
ULONGLONG g_startFiletime = 0;

wchar_t g_dllPathW[1024];
char g_dllPathA[1024];
bool g_dllPathAValid = false;

// Working directory sampled at DLL attach. The reader resolves relative paths
// against this so a relative open (e.g. `main.c`) and its absolute form fold
// to one dependency-graph entry. Empty (len 0) when the CWD did not fit the
// buffer or could not be read; the reader then leaves relative paths verbatim.
wchar_t g_cwdW[1024];
int g_cwdLen = 0;

HANDLE g_file = INVALID_HANDLE_VALUE;
bool g_initDone = false;
SRWLOCK g_lock = SRWLOCK_INIT;

// NtQueryInformationProcess(ProcessBasicInformation) is the documented way
// to get the parent PID without a toolhelp snapshot (which opens handles
// and is too heavy for DllMain).
typedef LONG(NTAPI* NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG,
                                                 PULONG);
struct ProcessBasicInfo {
    PVOID reserved1;
    PVOID pebBaseAddress;
    PVOID reserved2[2];
    ULONG_PTR uniqueProcessId;
    ULONG_PTR inheritedFromUniqueProcessId;
};

DWORD QueryParentPid() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return 0;
    }
    auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (fn == nullptr) {
        return 0;
    }
    ProcessBasicInfo info = {};
    ULONG len = 0;
    if (fn(GetCurrentProcess(), 0 /*ProcessBasicInformation*/, &info,
           sizeof(info), &len) != 0) {
        return 0;
    }
    return static_cast<DWORD>(info.inheritedFromUniqueProcessId);
}

void AppendUint64(wchar_t* buf, int cap, int& pos, ULONGLONG v) {
    wchar_t digits[20];
    int n = 0;
    do {
        digits[n++] = static_cast<wchar_t>(L'0' + (v % 10));
        v /= 10;
    } while (v != 0);
    while (n > 0 && pos < cap - 1) {
        buf[pos++] = digits[--n];
    }
    buf[pos] = L'\0';
}

void AppendStr(wchar_t* buf, int cap, int& pos, const wchar_t* s) {
    while (*s != L'\0' && pos < cap - 1) {
        buf[pos++] = *s++;
    }
    buf[pos] = L'\0';
}

constexpr size_t kStackRecordBytes = 1024;

// A writer failure must be terminal: a later record cannot safely follow a
// partial v0 record.  Tracing is observe-only, so disable it and leave the
// intercepted process alone.
void DisableLocked() {
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    g_initDone = true;
}

// Caller holds g_lock.  A normal complete buffer produces exactly one
// synchronous WriteFile.  A short successful write is resumed from its suffix
// under the same lock so records cannot interleave; a failed/zero write turns
// tracing off permanently.
bool WriteAllLocked(const BYTE* bytes, DWORD size) {
    DWORD offset = 0;
    while (offset < size) {
        DWORD written = 0;
        if (!WriteFile(g_file, bytes + offset, size - offset, &written,
                       nullptr) || written == 0 || written > size - offset) {
            DisableLocked();
            return false;
        }
        offset += written;
    }
    return true;
}

bool StringFieldSize(const wchar_t* value, int length, size_t* out) {
    if (length < -1) {
        return false;
    }
    int chars = 0;
    if (value != nullptr) {
        if (length == -1) {
            chars = lstrlenW(value);
        } else {
            chars = length;
        }
    }
    const size_t count = static_cast<size_t>(chars);
    if (count > (static_cast<size_t>(MAXDWORD) - sizeof(DWORD)) /
                    sizeof(wchar_t)) {
        return false;
    }
    *out = sizeof(DWORD) + count * sizeof(wchar_t);
    return true;
}

bool AppendStringField(BYTE* destination, size_t capacity, size_t* offset,
                       const wchar_t* value, int length) {
    size_t fieldSize = 0;
    if (!StringFieldSize(value, length, &fieldSize) ||
        fieldSize > capacity - *offset) {
        return false;
    }
    int chars = 0;
    if (value != nullptr) {
        chars = length == -1 ? lstrlenW(value) : length;
    }
    const DWORD count = static_cast<DWORD>(chars);
    memcpy(destination + *offset, &count, sizeof(count));
    *offset += sizeof(count);
    if (count != 0) {
        memcpy(destination + *offset, value,
               static_cast<size_t>(count) * sizeof(wchar_t));
        *offset += static_cast<size_t>(count) * sizeof(wchar_t);
    }
    return true;
}

// Header fields retain the v0 writer's established frame boundaries.  Unlike
// records, header emission is a one-time lazy-open path rather than the hot
// per-hook operation; every failed frame still disables tracing terminally.
bool WriteStringFieldLocked(const wchar_t* value, int length) {
    size_t fieldSize = 0;
    if (!StringFieldSize(value, length, &fieldSize)) {
        DisableLocked();
        return false;
    }
    const int chars = value == nullptr ? 0 :
                      (length == -1 ? lstrlenW(value) : length);
    const DWORD count = static_cast<DWORD>(chars);
    if (!WriteAllLocked(reinterpret_cast<const BYTE*>(&count), sizeof(count))) {
        return false;
    }
    return count == 0 || WriteAllLocked(reinterpret_cast<const BYTE*>(value),
                                         count * sizeof(wchar_t));
}

// Build a complete v0 payload without holding g_lock.  Heap allocation is
// deliberately reserved for valid, long records; malformed/overflow inputs
// never put a partial byte on disk.
bool BuildRecord(const RecordHeader& header, const wchar_t* path, int pathLen,
                 const wchar_t* aux, int auxLen, BYTE* stack,
                 size_t stackCapacity, BYTE** bytes, DWORD* byteCount,
                 bool* heapAllocated) {
    size_t pathBytes = 0;
    size_t auxBytes = 0;
    if (!StringFieldSize(path, pathLen, &pathBytes) ||
        !StringFieldSize(aux, auxLen, &auxBytes) ||
        pathBytes > static_cast<size_t>(MAXDWORD) - sizeof(header) ||
        auxBytes > static_cast<size_t>(MAXDWORD) - sizeof(header) - pathBytes) {
        return false;
    }
    const size_t total = sizeof(header) + pathBytes + auxBytes;
    BYTE* target = stack;
    *heapAllocated = false;
    if (total > stackCapacity) {
        target = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, total));
        if (target == nullptr) {
            return false;
        }
        *heapAllocated = true;
    }
    size_t offset = 0;
    memcpy(target + offset, &header, sizeof(header));
    offset += sizeof(header);
    const bool complete =
        AppendStringField(target, total, &offset, path, pathLen) &&
        AppendStringField(target, total, &offset, aux, auxLen) && offset == total;
    if (!complete) {
        if (*heapAllocated) {
            HeapFree(GetProcessHeap(), 0, target);
        }
        return false;
    }
    *bytes = target;
    *byteCount = static_cast<DWORD>(total);
    return true;
}

// Caller holds g_lock. Opens the trace file and writes the header on the
// first record. Any failure leaves g_file INVALID: tracing silently off,
// the process untouched (fail-open).
void EnsureOpenLocked() {
    if (g_initDone) {
        return;
    }
    g_initDone = true;

    wchar_t dir[2048];
    DWORD n = TrueGetEnvironmentVariableW(L"SEMBAZURU_TRACE_DIR", dir,
                                          ARRAYSIZE(dir));
    if (n == 0 || n >= ARRAYSIZE(dir)) {
        return;
    }

    wchar_t path[2048 + 64];
    int pos = 0;
    AppendStr(path, ARRAYSIZE(path), pos, dir);
    AppendStr(path, ARRAYSIZE(path), pos, L"\\");
    AppendUint64(path, ARRAYSIZE(path), pos, g_pid);
    AppendStr(path, ARRAYSIZE(path), pos, L"-");
    AppendUint64(path, ARRAYSIZE(path), pos, g_startQpc);
    AppendStr(path, ARRAYSIZE(path), pos, L".sbzt");

    g_file = TrueCreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_file == INVALID_HANDLE_VALUE) {
        return;
    }

    FileHeader hdr = {};
    hdr.magic[0] = 'S';
    hdr.magic[1] = 'B';
    hdr.magic[2] = 'Z';
    hdr.magic[3] = 'T';
    hdr.version = 0;
    hdr.pid = g_pid;
    hdr.parentPid = g_parentPid;
    hdr.qpcFrequency = g_qpcFrequency;
    hdr.startQpc = g_startQpc;
    hdr.startFiletime = g_startFiletime;
    wchar_t exe[1024];
    DWORD exeLen = GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
    if (!WriteAllLocked(reinterpret_cast<const BYTE*>(&hdr), sizeof(hdr)) ||
        !WriteStringFieldLocked(exe, static_cast<int>(exeLen)) ||
        !WriteStringFieldLocked(GetCommandLineW(), -1) ||
        !WriteStringFieldLocked(g_cwdLen > 0 ? g_cwdW : nullptr, g_cwdLen)) {
        return;
    }
}

}  // namespace

void Initialize(HMODULE self) {
    g_self = self;
    g_pid = GetCurrentProcessId();
    g_parentPid = QueryParentPid();

    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    g_qpcFrequency = static_cast<ULONGLONG>(li.QuadPart);
    QueryPerformanceCounter(&li);
    g_startQpc = static_cast<ULONGLONG>(li.QuadPart);

    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    g_startFiletime =
        (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

    // CWD at attach. GetCurrentDirectoryW returns the length in WCHARs (no
    // NUL) on success, or the required size (incl. NUL) if the buffer is too
    // small; in the latter case the buffer is untouched, so we record empty.
    // Not hooked and loader-lock safe (reads the PEB, no file I/O).
    DWORD cwdLen = GetCurrentDirectoryW(ARRAYSIZE(g_cwdW), g_cwdW);
    g_cwdLen = (cwdLen > 0 && cwdLen < ARRAYSIZE(g_cwdW)) ? static_cast<int>(cwdLen) : 0;
    // A service worker may start the process from a scratch mirror when the
    // submitted cwd is not accessible to the worker account. Preserve the
    // submitted cwd in the trace so relative reads and outputs stay anchored to
    // the logical build root rather than to the disposable scratch tree.
    wchar_t vfsCwd[1024];
    DWORD vfsCwdLen = TrueGetEnvironmentVariableW(L"SEMBAZURU_VFS_CWD", vfsCwd,
                                                  ARRAYSIZE(vfsCwd));
    if (vfsCwdLen > 0 && vfsCwdLen < ARRAYSIZE(vfsCwd)) {
        wchar_t full[1024];
        DWORD fullLen = GetFullPathNameW(vfsCwd, ARRAYSIZE(full), full, nullptr);
        if (fullLen > 0 && fullLen < ARRAYSIZE(full)) {
            memcpy(g_cwdW, full,
                   (static_cast<size_t>(fullLen) + 1) * sizeof(wchar_t));
            g_cwdLen = static_cast<int>(fullLen);
        }
    }

    DWORD len = GetModuleFileNameW(self, g_dllPathW, ARRAYSIZE(g_dllPathW));
    if (len > 0 && len < ARRAYSIZE(g_dllPathW)) {
        // Detours injects by ANSI path; a lossy conversion must disable
        // propagation rather than inject a wrong path into children.
        BOOL usedDefault = FALSE;
        int r = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, g_dllPathW,
                                    -1, g_dllPathA, sizeof(g_dllPathA),
                                    nullptr, &usedDefault);
        g_dllPathAValid = (r > 0 && !usedDefault);
    }
}

void Shutdown() {
    AcquireSRWLockExclusive(&g_lock);
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

bool Enabled() {
    AcquireSRWLockExclusive(&g_lock);
    EnsureOpenLocked();
    bool enabled = (g_file != INVALID_HANDLE_VALUE);
    ReleaseSRWLockExclusive(&g_lock);
    return enabled;
}

const char* DllPathA() {
    return g_dllPathAValid ? g_dllPathA : nullptr;
}

void Record(BYTE type, BYTE op, DWORD status, ULONGLONG extra,
            const wchar_t* path, int pathLen, const wchar_t* aux,
            int auxLen) {
    RecordHeader hdr = {};
    hdr.type = type;
    hdr.op = op;
    hdr.reserved = 0;
    hdr.status = status;
    hdr.tid = GetCurrentThreadId();
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    hdr.qpc = static_cast<ULONGLONG>(li.QuadPart);
    hdr.extra = extra;

    BYTE stack[kStackRecordBytes];
    BYTE* bytes = nullptr;
    DWORD byteCount = 0;
    bool heapAllocated = false;
    if (!BuildRecord(hdr, path, pathLen, aux, auxLen, stack, ARRAYSIZE(stack),
                     &bytes, &byteCount, &heapAllocated)) {
        AcquireSRWLockExclusive(&g_lock);
        DisableLocked();
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }

    AcquireSRWLockExclusive(&g_lock);
    EnsureOpenLocked();
    if (g_file != INVALID_HANDLE_VALUE) {
        WriteAllLocked(bytes, byteCount);
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (heapAllocated) {
        HeapFree(GetProcessHeap(), 0, bytes);
    }
}

}  // namespace trace
