// DLL 終了通知と標準ハンドルを介さず、自己終了の固定値で entry 到達を観測する。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// 自プロセスの疑似ハンドルだけを使い、PID・handle・引数を入力させない。
extern "C" __declspec(noreturn) void WINAPI ProbeEntry() {
    TerminateProcess(GetCurrentProcess(), 0x53425a54);
    // 成功時は戻らない。API から戻った場合は肯定値を作らず、親の期限と回収に委ねる。
    for (;;) {
        YieldProcessor();
    }
}
