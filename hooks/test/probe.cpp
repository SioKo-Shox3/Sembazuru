// Cross-bitness injection probe (M7.3). A minimal program that opens the file
// named by argv[1] for read (so an injected interceptor records the open in its
// trace) and exits 0. Built for both architectures; the 32-bit build is launched
// by the 64-bit launcher in hooks/test/m7_inject32.ps1 to prove the 32-bit
// interceptor (sbz_interceptor32.dll) is injected into a 32-bit child via
// Detours' cross-bitness sibling lookup.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        return 2;
    }
    HANDLE h = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    return 0;
}
