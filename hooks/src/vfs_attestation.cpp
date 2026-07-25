#include "vfs_attestation.h"

#include <cstdint>
#include <cwchar>

#include "detours.h"

namespace vfs_attestation {
namespace {

HANDLE g_mapping = nullptr;
HANDLE g_semaphore = nullptr;
Header* g_header = nullptr;
DWORD g_generation = 0;

constexpr DWORD kPayloadMagic = 0x53425A50;  // "SBZP"

bool ParseDecimalHandle(const wchar_t* name, unsigned __int64* value) {
    wchar_t text[32];
    DWORD length = GetEnvironmentVariableW(name, text, ARRAYSIZE(text));
    if (length == 0 || length >= ARRAYSIZE(text)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    unsigned __int64 parsed = 0;
    for (DWORD i = 0; i < length; ++i) {
        if (text[i] < L'0' || text[i] > L'9' ||
            parsed > (UINT64_MAX - static_cast<unsigned>(text[i] - L'0')) / 10) {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
        parsed = parsed * 10 + static_cast<unsigned>(text[i] - L'0');
    }
    *value = parsed;
    return true;
}

bool ParseDecimalDword(const wchar_t* name, DWORD* value) {
    unsigned __int64 parsed = 0;
    if (!ParseDecimalHandle(name, &parsed) || parsed == 0 || parsed > MAXDWORD) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    *value = static_cast<DWORD>(parsed);
    return true;
}

bool HeaderValid() {
    return g_header != nullptr &&
           static_cast<DWORD>(g_header->magic) == kMagic &&
           static_cast<DWORD>(g_header->version) == kVersion &&
           static_cast<DWORD>(g_header->maxSlots) == kMaxSlots &&
           static_cast<DWORD>(g_header->generation) == g_generation &&
           g_header->corrupt == 0;
}

Slot* Slots() { return reinterpret_cast<Slot*>(g_header + 1); }

bool OpenPayload(const Payload& payload) {
    if (!PayloadValid(&payload, sizeof(payload), sizeof(void*) == 4)) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    HANDLE mapping = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(payload.mapping));
    Header* header = static_cast<Header*>(MapViewOfFile(
        mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
        sizeof(Header) + kMaxSlots * sizeof(Slot)));
    if (header == nullptr) {
        return false;
    }
    HANDLE semaphore = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(payload.semaphore));
    g_mapping = mapping;
    g_semaphore = semaphore;
    g_header = header;
    g_generation = payload.generation;
    if (!HeaderValid()) {
        Close();
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

}  // namespace

const GUID kPayloadGuid = {0x765079bc, 0x4c90, 0x47d6,
                            {0xaf, 0x06, 0xab, 0x5d, 0xa9, 0x84, 0x6c, 0x21}};

Payload MakePayload(DWORD generation, unsigned __int64 mapping,
                    unsigned __int64 semaphore) {
    return {kPayloadMagic, kVersion, generation, 0, mapping, semaphore};
}

bool PayloadValid(const Payload* payload, DWORD bytes, bool targetIs32Bit) {
    if (payload == nullptr || bytes != sizeof(Payload) ||
        payload->magic != kPayloadMagic || payload->version != kVersion ||
        payload->generation == 0 || payload->reserved != 0 || payload->mapping == 0 ||
        payload->semaphore == 0 || payload->mapping == static_cast<unsigned __int64>(-1) ||
        payload->semaphore == static_cast<unsigned __int64>(-1) ||
        payload->mapping == payload->semaphore) {
        return false;
    }
    return !targetIs32Bit ||
           ((payload->mapping >> 32) == 0 && (payload->semaphore >> 32) == 0);
}

bool VfsRequested() {
    wchar_t mode[16];
    DWORD length = GetEnvironmentVariableW(L"SEMBAZURU_MODE", mode, ARRAYSIZE(mode));
    return length > 0 && length < ARRAYSIZE(mode) && _wcsicmp(mode, L"vfs") == 0;
}

bool OpenFromBootstrapEnvironment() {
    if (g_header != nullptr) {
        if (HeaderValid()) {
            return true;
        }
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    unsigned __int64 mapping = 0;
    unsigned __int64 semaphore = 0;
    DWORD generation = 0;
    if (!ParseDecimalHandle(L"SEMBAZURU_VFS_MAPPING_HANDLE", &mapping) ||
        !ParseDecimalHandle(L"SEMBAZURU_VFS_SEMAPHORE_HANDLE", &semaphore) ||
        !ParseDecimalDword(L"SEMBAZURU_VFS_ATTESTATION_GENERATION", &generation)) {
        return false;
    }
    return OpenPayload(MakePayload(generation, mapping, semaphore));
}

bool OpenFromPayload() {
    DWORD bytes = 0;
    const auto* payload = static_cast<const Payload*>(
        DetourFindPayloadEx(kPayloadGuid, &bytes));
    return PayloadValid(payload, bytes, sizeof(void*) == 4) && OpenPayload(*payload);
}

bool CopyPayloadToProcess(HANDLE process) {
    if (!HeaderValid() || process == nullptr) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    HANDLE mapping = nullptr;
    HANDLE semaphore = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), g_mapping, process, &mapping,
                         FILE_MAP_READ | FILE_MAP_WRITE, FALSE, 0) ||
        !DuplicateHandle(GetCurrentProcess(), g_semaphore, process, &semaphore,
                         SEMAPHORE_MODIFY_STATE, FALSE, 0)) {
        return false;
    }
    Payload payload = MakePayload(g_generation,
        static_cast<unsigned __int64>(reinterpret_cast<uintptr_t>(mapping)),
        static_cast<unsigned __int64>(reinterpret_cast<uintptr_t>(semaphore)));
    return DetourCopyPayloadToProcess(process, kPayloadGuid, &payload, sizeof(payload)) != FALSE;
}

bool RegisterExpected(DWORD pid) {
    if (!HeaderValid() || pid == 0) {
        return false;
    }
    LONG index = InterlockedIncrement(&g_header->slotCount) - 1;
    if (index < 0 || static_cast<DWORD>(index) >= kMaxSlots) {
        InterlockedExchange(&g_header->corrupt, 1);
        return false;
    }
    Slot* slot = Slots() + index;
    InterlockedExchange(&slot->generation, static_cast<LONG>(g_generation));
    InterlockedExchange(&slot->pid, static_cast<LONG>(pid));
    InterlockedExchange(&slot->attached, 0);
    MemoryBarrier();
    return true;
}

bool MarkAttached(DWORD pid) {
    if (!HeaderValid() || pid == 0) {
        return false;
    }
    LONG count = g_header->slotCount;
    if (count <= 0 || static_cast<DWORD>(count) > kMaxSlots) {
        InterlockedExchange(&g_header->corrupt, 1);
        return false;
    }
    Slot* slots = Slots();
    for (LONG i = count - 1; i >= 0; --i) {
        Slot* slot = slots + i;
        if (static_cast<DWORD>(slot->generation) == g_generation &&
            static_cast<DWORD>(slot->pid) == pid &&
            InterlockedCompareExchange(&slot->attached, 1, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool SignalFailure() {
    return g_semaphore != nullptr && ReleaseSemaphore(g_semaphore, 1, nullptr) != FALSE;
}

void Close() {
    if (g_header != nullptr) {
        UnmapViewOfFile(g_header);
        g_header = nullptr;
    }
    g_semaphore = nullptr;
    g_mapping = nullptr;
    g_generation = 0;
}

}  // namespace vfs_attestation
