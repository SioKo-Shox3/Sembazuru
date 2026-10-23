// WINDOWS の起動情報と固定モジュールの有無を USER32 明示ロードの前後で記録する。
// CRT・ヒープ・TLS を使わず、外部入力とポインタ値を出力しない。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {
constexpr DWORD kDesktopLimit = 128;
constexpr char kDigits[] = "0123456789abcdef";

struct Snapshot {
    const char* state;
    DWORD units;
    char hex[kDesktopLimit * 4];
    bool user32;
    bool gdi32;
    bool win32u;
};

void WriteBytes(HANDLE output, const char* bytes, DWORD size) {
    while (size != 0) {
        DWORD written = 0;
        if (!WriteFile(output, bytes, size, &written, nullptr) || written == 0 || written > size) {
            ExitProcess(13);
        }
        bytes += written;
        size -= written;
    }
}

template <SIZE_T N>
void WriteText(HANDLE output, const char (&text)[N]) {
    WriteBytes(output, text, static_cast<DWORD>(N - 1));
}

void WriteString(HANDLE output, const char* text) {
    DWORD length = 0;
    // 呼出し元は固定状態名だけを渡す。走査にも上限を置く。
    while (length != 16 && text[length] != 0) { ++length; }
    WriteBytes(output, text, length);
}

void CaptureSnapshot(Snapshot& snapshot) {
    STARTUPINFOW startup;
    startup.cb = sizeof(startup);
    GetStartupInfoW(&startup);
    snapshot.units = 0;
    snapshot.state = "null";
    if (startup.lpDesktop != nullptr) {
        snapshot.state = "bounded";
        const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(startup.lpDesktop);
        for (DWORD i = 0; i != kDesktopLimit; ++i) {
            WCHAR unit = 0;
            SIZE_T read = 0;
            const ULONG_PTR offset = static_cast<ULONG_PTR>(i) * sizeof(WCHAR);
            // OS 由来のポインタも直接参照せず、読取り不能は観測状態として保存する。
            if (address > MAXULONG_PTR - offset ||
                !ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address + offset),
                                   &unit, sizeof(unit), &read) || read != sizeof(unit)) {
                snapshot.state = "unreadable";
                break;
            }
            if (unit == 0) {
                snapshot.state = i == 0 ? "empty" : "terminated";
                break;
            }
            for (DWORD digit = 0; digit != 4; ++digit) {
                snapshot.hex[i * 4 + digit] = kDigits[(unit >> ((3 - digit) * 4)) & 15];
            }
            ++snapshot.units;
        }
    }
    snapshot.user32 = GetModuleHandleW(L"user32.dll") != nullptr;
    snapshot.gdi32 = GetModuleHandleW(L"gdi32.dll") != nullptr;
    snapshot.win32u = GetModuleHandleW(L"win32u.dll") != nullptr;
}

void WriteSnapshot(HANDLE output, const Snapshot& snapshot, bool after) {
    if (after) { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 after desktop="); }
    else { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 before desktop="); }
    WriteString(output, snapshot.state);
    WriteText(output, " units=");
    char number[3];
    DWORD length = 0;
    if (snapshot.units >= 100) { number[length++] = static_cast<char>('0' + snapshot.units / 100); }
    if (snapshot.units >= 10) { number[length++] = static_cast<char>('0' + (snapshot.units / 10) % 10); }
    number[length++] = static_cast<char>('0' + snapshot.units % 10);
    WriteBytes(output, number, length);
    WriteText(output, " hex=");
    if (snapshot.units == 0) { WriteText(output, "-"); }
    else { WriteBytes(output, snapshot.hex, snapshot.units * 4); }
    WriteText(output, " user32=");
    WriteBytes(output, snapshot.user32 ? "1" : "0", 1);
    WriteText(output, " gdi32=");
    WriteBytes(output, snapshot.gdi32 ? "1" : "0", 1);
    WriteText(output, " win32u=");
    WriteBytes(output, snapshot.win32u ? "1\n" : "0\n", 2);
}

void WriteError(HANDLE output, DWORD error) {
    char hex[9];
    for (DWORD i = 0; i != 8; ++i) { hex[i] = kDigits[(error >> ((7 - i) * 4)) & 15]; }
    hex[8] = '\n';
    WriteBytes(output, hex, sizeof(hex));
}
}

// /ENTRY の固定入口。ロード直後の GLE は追加の観測 API より先に保存する。
extern "C" __declspec(noreturn) void WINAPI ProbeEntry() {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 entry\n");
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    const bool preloaded = GetModuleHandleW(L"user32.dll") != nullptr;
    if (preloaded) { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 user32_preloaded=1\n"); }
    else { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 user32_preloaded=0\n"); }
    Snapshot snapshot;
    CaptureSnapshot(snapshot);
    WriteSnapshot(output, snapshot, false);
    if (preloaded) {
        WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 complete\n");
        ExitProcess(12);
    }
    WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_begin\n");
    SetLastError(ERROR_SUCCESS);
    const HMODULE user32 = LoadLibraryExW(L"user32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const DWORD error = GetLastError();
    CaptureSnapshot(snapshot);
    if (user32 != nullptr) { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_result=1 gle=0x"); }
    else { WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_result=0 gle=0x"); }
    WriteError(output, error);
    WriteSnapshot(output, snapshot, true);
    WriteText(output, "SBZ_WINDOWS_STARTUP_PROBE_V1 complete\n");
    ExitProcess(user32 != nullptr ? 0 : 11);
}
