// 固定GDI32通常ロード中の固定3モジュール自己loader通知を有界に記録する。
// 通知はdynamic linking前であり、DLLの初期化成功を表さない。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <stddef.h>

struct ProbeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    const WCHAR* Buffer;
};
struct ProbeNotification {
    ULONG Flags;
    const ProbeUnicodeString* FullDllName;
    const ProbeUnicodeString* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};
static_assert(sizeof(ProbeNotification) == 40, "notification_layout");
static_assert(offsetof(ProbeNotification, BaseDllName) == 16, "basename_offset");

namespace {
// Gate: 0=受付中、1=書込み中、2=凍結。slot: 0=空、1=未確定、2..7=確定。
// 全共有状態は整列済みLONGへのintrinsicだけで読む。カウンタを増やし続けない。
struct Storage {
    volatile LONG gate;
    volatile LONG flags;
    volatile LONG slots[16];
};
Storage storage;
HMODULE retainedModule;
PVOID retainedCookie;
constexpr char digits[] = "0123456789abcdef";
}

// OSから有効期間付きで渡されるBaseDllNameだけを参照する。任意ポインタは入力しない。
// 競合・再入は待機せず明示bitへ落とす。名前とポインタをstorageへ持ち越さない。
extern "C" __declspec(noinline) void CALLBACK ProbeNotificationCallback(
    ULONG reason, const ProbeNotification* data, PVOID context) {
    if (context != &storage) { return; }
    const LONG gate = _InterlockedCompareExchange(&storage.gate, 1, 0);
    if (gate != 0) {
        _InterlockedOr(&storage.flags, gate == 1 ? 8 : 16);
        return;
    }
    if (reason != 1 && reason != 2) {
        _InterlockedOr(&storage.flags, 2);
    } else if (data == nullptr || data->BaseDllName == nullptr) {
        _InterlockedOr(&storage.flags, 4);
    } else {
        const ProbeUnicodeString* name = data->BaseDllName;
        if (name->Buffer == nullptr || (reinterpret_cast<ULONG_PTR>(name->Buffer) & 1) != 0 ||
            name->Length == 0 || (name->Length & 1) != 0 ||
            (name->MaximumLength & 1) != 0 || name->Length > name->MaximumLength ||
            name->Length > 128) {
            _InterlockedOr(&storage.flags, 4);
        } else {
            ULONG module = 0;
            // 比較は各候補最大10コード単位。未知名は保存しない。
            for (ULONG candidate = 1; candidate <= 3; ++candidate) {
                const WCHAR* expected = candidate == 1 ? L"user32.dll" :
                                        candidate == 2 ? L"gdi32.dll" : L"win32u.dll";
                const ULONG units = candidate == 2 ? 9 : 10;
                bool equal = name->Length == units * sizeof(WCHAR);
                if (equal) {
                    for (ULONG i = 0; i < units; ++i) {
                        WCHAR value = name->Buffer[i];
                        if (value >= L'A' && value <= L'Z') { value += L'a' - L'A'; }
                        if (value != expected[i]) { equal = false; break; }
                    }
                }
                if (equal) { module = candidate; break; }
            }
            if (module != 0) {
                bool stored = false;
                for (ULONG slot = 0; slot < 16; ++slot) {
                    if (_InterlockedCompareExchange(&storage.slots[slot], 1, 0) == 0) {
                        // module ID 1..3、reason1/2を1個の原子値として公開する。
                        _InterlockedExchange(&storage.slots[slot],
                                             static_cast<LONG>(1 + module + (reason - 1) * 3));
                        stored = true;
                        break;
                    }
                }
                if (!stored) { _InterlockedOr(&storage.flags, 1); }
            }
        }
    }
    // 出力側が既に凍結した場合は受付中へ戻さない。
    _InterlockedCompareExchange(&storage.gate, 0, 1);
}

namespace {
using RegisterNotification = LONG (NTAPI*)(ULONG, decltype(&ProbeNotificationCallback), PVOID, PVOID*);
using UnregisterNotification = LONG (NTAPI*)(PVOID);

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
template <SIZE_T N> void WriteText(HANDLE output, const char (&text)[N]) {
    WriteBytes(output, text, static_cast<DWORD>(N - 1));
}
void WriteHex(HANDLE output, ULONG value) {
    char hex[8];
    for (ULONG i = 0; i != 8; ++i) { hex[i] = digits[(value >> ((7 - i) * 4)) & 15]; }
    WriteBytes(output, hex, 8);
}
void WriteStatus(HANDLE output, bool acquired, LONG status) {
    if (acquired) { WriteText(output, "0x"); WriteHex(output, static_cast<ULONG>(status)); }
    else { WriteText(output, "unavailable"); }
}
}

// 登録失敗・解除失敗でもstorage/cookie/moduleの寿命はプロセス終了まで続く。
extern "C" __declspec(noreturn) void WINAPI ProbeEntry() {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteText(output, "SBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 entry\n");
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto registerNotification = ntdll ? reinterpret_cast<RegisterNotification>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification")) : nullptr;
    const auto unregisterNotification = ntdll ? reinterpret_cast<UnregisterNotification>(
        GetProcAddress(ntdll, "LdrUnregisterDllNotification")) : nullptr;
    WriteText(output, "SBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 api ntdll=");
    WriteBytes(output, ntdll ? "1" : "0", 1);
    WriteText(output, " register="); WriteBytes(output, registerNotification ? "1" : "0", 1);
    WriteText(output, " unregister="); WriteBytes(output, unregisterNotification ? "1\n" : "0\n", 2);
    const bool resolved = registerNotification != nullptr && unregisterNotification != nullptr;
    const LONG registerStatus = resolved ? registerNotification(0, ProbeNotificationCallback, &storage,
                                                               &retainedCookie) : 0;
    const bool registered = resolved && registerStatus == 0 && retainedCookie != nullptr;
    WriteText(output, "SBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 register status=");
    WriteStatus(output, resolved, registerStatus);
    WriteText(output, " cookie="); WriteBytes(output, retainedCookie ? "1\n" : "0\n", 2);
    // 未登録でも通常ロードの観測を独立して残す。
    WriteText(output, "SBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 gdi32_load_begin flags=0x00000800\n");
    SetLastError(ERROR_SUCCESS);
    retainedModule = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const DWORD loadError = GetLastError();
    const LONG unregisterStatus = registered ? unregisterNotification(retainedCookie) : 0;
    // 凍結時に進行中だったcallbackは終了を待たず、busyと未確定slotをそのまま記録する。
    const LONG busy = _InterlockedExchange(&storage.gate, 2);
    char slots[16];
    for (ULONG i = 0; i != 16; ++i) {
        const LONG value = _InterlockedCompareExchange(&storage.slots[i], 0, 0);
        slots[i] = value == 0 ? '-' : value == 1 ? '?' : static_cast<char>('0' + value - 1);
    }
    const LONG flags = _InterlockedCompareExchange(&storage.flags, 0, 0);
    WriteText(output, "SBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 gdi32_load_result=");
    WriteBytes(output, retainedModule ? "1" : "0", 1);
    WriteText(output, " gle=0x"); WriteHex(output, loadError);
    WriteText(output, "\nSBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 unregister status=");
    WriteStatus(output, registered, unregisterStatus);
    WriteText(output, "\nSBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 snapshot slots=");
    WriteBytes(output, slots, 16);
    WriteText(output, " flags=0x"); WriteHex(output, static_cast<ULONG>(flags));
    WriteText(output, " busy="); WriteBytes(output, busy == 1 ? "1" : "0", 1);
    WriteText(output, "\nSBZ_GDI32_LOADER_NOTIFICATION_PROBE_V1 complete\n");
    ExitProcess(!resolved ? 31 : !registered ? 32 : unregisterStatus != 0 ? 33 : retainedModule ? 0 : 11);
}
