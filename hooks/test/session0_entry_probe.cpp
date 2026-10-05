// 標準ハンドルや CRT を介さず、固定終了値で専用 entry への到達を観測する。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// 引数・静的構築・TLS・ヒープを使わず、最初の呼出しで終了処理に渡す。
extern "C" __declspec(noreturn) void WINAPI ProbeEntry() {
    ExitProcess(0x53425a45);
}
