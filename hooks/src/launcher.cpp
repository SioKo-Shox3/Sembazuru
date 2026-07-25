// Sembazuru trace launcher.
//
// Starts a target process with the interceptor DLL injected, using the
// documented Detours injection path (DetourCreateProcessWithDllExW) rather
// than anything that pattern-matches to malware TTPs. Waits for the target
// and propagates its exit code. Child processes are propagated to by the
// interceptor's own CreateProcess hooks, not by this launcher.
//
// Usage: launcher.exe <path\to\sbz_interceptor64.dll> <command> [args...]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <string>

#include "detours.h"
#include "vfs_attestation.h"

namespace {

enum class DetourLaunchStage {
    kNotCalled,
    kNativeCreateFailed,
    kNativeCreateSucceeded,
};

DetourLaunchStage g_detourLaunchStage = DetourLaunchStage::kNotCalled;

BOOL WINAPI CreateProcessForDetours(
    LPCWSTR application, LPWSTR command, LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags,
    LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
    LPPROCESS_INFORMATION process) {
    BOOL result = CreateProcessW(application, command, processAttributes, threadAttributes,
                                 inheritHandles, creationFlags, environment, directory,
                                 startup, process);
    g_detourLaunchStage = result ? DetourLaunchStage::kNativeCreateSucceeded
                                 : DetourLaunchStage::kNativeCreateFailed;
    return result;
}

// Quotes one argv element back into command-line form (minimal CRT-style
// quoting: sufficient for the PoC, revisited when this grows past a PoC).
void AppendQuoted(std::wstring& cmd, const wchar_t* arg) {
    if (!cmd.empty()) {
        cmd += L' ';
    }
    const bool needsQuotes = wcschr(arg, L' ') || wcschr(arg, L'\t') || !*arg;
    if (!needsQuotes) {
        cmd += arg;
        return;
    }
    cmd += L'"';
    cmd += arg;  // PoC: args with embedded quotes/backslash runs unsupported
    cmd += L'"';
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        fwprintf(stderr,
                 L"usage: %s <interceptor.dll> <command> [args...]\n",
                 argv[0]);
        return 2;
    }

    wchar_t dllFullW[MAX_PATH];
    if (GetFullPathNameW(argv[1], MAX_PATH, dllFullW, nullptr) == 0) {
        fwprintf(stderr, L"error: cannot resolve DLL path '%s'\n", argv[1]);
        return 2;
    }
    // DetourCreateProcessWithDllExW takes the DLL path as ANSI.
    char dllFullA[MAX_PATH];
    if (WideCharToMultiByte(CP_ACP, 0, dllFullW, -1, dllFullA,
                            sizeof(dllFullA), nullptr, nullptr) == 0) {
        fwprintf(stderr, L"error: DLL path not representable in ANSI\n");
        return 2;
    }

    std::wstring cmd;
    for (int i = 2; i < argc; ++i) {
        AppendQuoted(cmd, argv[i]);
    }

    // Forward our standard handles so the traced tool's stdout/stderr (e.g.
    // cl /showIncludes) flow through transparently; a tracer must not eat the
    // wrapped tool's output. Requires bInheritHandles = TRUE below.
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};

    const bool vfs = vfs_attestation::VfsRequested();
    if (vfs && !vfs_attestation::OpenFromBootstrapEnvironment()) {
        fwprintf(stderr, L"error: VFS bootstrap handles unavailable gle=%lu\n",
                 GetLastError());
        return 1;
    }

    g_detourLaunchStage = DetourLaunchStage::kNotCalled;
    if (!DetourCreateProcessWithDllExW(nullptr, cmd.data(), nullptr, nullptr,
                                       TRUE, vfs ? CREATE_SUSPENDED : 0, nullptr, nullptr, &si, &pi,
                                       dllFullA, CreateProcessForDetours)) {
        if (vfs) {
            const wchar_t* stage =
                g_detourLaunchStage == DetourLaunchStage::kNativeCreateFailed
                    ? L"native-create"
                    : L"detour-update";
            fwprintf(stderr,
                     L"error: failed to launch VFS target stage=%ls gle=%lu\n",
                     stage, GetLastError());
        } else {
            fwprintf(stderr, L"error: failed to launch '%s' (GetLastError=%lu)\n",
                     cmd.c_str(), GetLastError());
        }
        return 1;
    }

    if (vfs) {
        // Detours has injected while the target remains suspended. Register its
        // PID before it can execute, then resume exactly once. Any failure is
        // conservative: reap the child so a remote VFS action cannot succeed
        // without its loader-attestation slot.
        if (!vfs_attestation::CopyPayloadToProcess(pi.hProcess) ||
            !vfs_attestation::RegisterExpected(pi.dwProcessId) ||
            ResumeThread(pi.hThread) != 1) {
            DWORD saved = GetLastError();
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            fwprintf(stderr, L"error: VFS attestation setup failed (GetLastError=%lu)\n", saved);
            return 1;
        }
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
}
