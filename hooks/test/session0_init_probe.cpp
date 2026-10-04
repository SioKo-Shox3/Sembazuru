// EXE の entry 到達と USER32 の明示ロード境界を固定形式で記録する。
// CRT 初期化、動的な静的変数、例外、TLS、ヒープを使用しない。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {
constexpr UINT kLoadFailed = 11;
constexpr UINT kAlreadyLoaded = 12;
constexpr UINT kWriteFailed = 13;

// 部分書込みを進め、失敗または進捗ゼロなら成功列の生成を中断する。
void WriteBytes(HANDLE output, const char* bytes, DWORD size) {
    while (size != 0) {
        DWORD written = 0;
        if (!WriteFile(output, bytes, size, &written, nullptr) ||
            written == 0 || written > size) {
            ExitProcess(kWriteFailed);
        }
        bytes += written;
        size -= written;
    }
}

template <SIZE_T N>
void WriteText(HANDLE output, const char (&text)[N]) {
    WriteBytes(output, text, static_cast<DWORD>(N - 1));
}

void WriteError(HANDLE output, DWORD error) {
    char hex[9];
    constexpr char digits[] = "0123456789abcdef";
    for (DWORD i = 0; i != 8; ++i) {
        hex[i] = digits[(error >> ((7 - i) * 4)) & 15];
    }
    hex[8] = '\n';
    WriteBytes(output, hex, sizeof(hex));
}
}

// /ENTRY から直接呼ばれる。終了は CRT の後処理を介さず ExitProcess に渡す。
extern "C" __declspec(noreturn) void WINAPI ProbeEntry() {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteText(output, "SBZ_INIT_PROBE_V1 entry\n");
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    if (GetModuleHandleW(L"user32.dll") != nullptr) {
        WriteText(output, "SBZ_INIT_PROBE_V1 user32_preloaded=1\n");
        WriteText(output, "SBZ_INIT_PROBE_V1 complete\n");
        ExitProcess(kAlreadyLoaded);
    }
    WriteText(output, "SBZ_INIT_PROBE_V1 user32_preloaded=0\n");
    WriteText(output, "SBZ_INIT_PROBE_V1 user32_load_begin\n");
    SetLastError(ERROR_SUCCESS);
    const HMODULE user32 = LoadLibraryExW(L"user32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const DWORD error = GetLastError();
    // 成功時の GLE は診断値として保存するが、成功・失敗の判定には使わない。
    if (user32 != nullptr) {
        WriteText(output, "SBZ_INIT_PROBE_V1 user32_load_result=1 gle=0x");
    } else {
        WriteText(output, "SBZ_INIT_PROBE_V1 user32_load_result=0 gle=0x");
    }
    WriteError(output, error);
    WriteText(output, "SBZ_INIT_PROBE_V1 complete\n");
    ExitProcess(user32 != nullptr ? 0 : kLoadFailed);
}
