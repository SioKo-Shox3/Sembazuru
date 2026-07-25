#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>

namespace vfs_attestation {

// This ABI deliberately contains only 32-bit words. Both interceptor builds
// therefore share the same named pagefile mapping without packing ambiguity.
constexpr DWORD kMagic = 0x53425A41;  // "SBZA"
constexpr DWORD kVersion = 1;
constexpr DWORD kMaxSlots = 1024;
extern const GUID kPayloadGuid;

struct Header {
    volatile LONG magic;
    volatile LONG version;
    volatile LONG maxSlots;
    volatile LONG slotCount;
    volatile LONG generation;
    volatile LONG corrupt;
};

struct Slot {
    volatile LONG generation;
    volatile LONG pid;
    volatile LONG attached;
};

static_assert(sizeof(Header) == 24, "attestation header must remain a 32-bit ABI");
static_assert(sizeof(Slot) == 12, "attestation slot must remain a 32-bit ABI");

struct Payload {
    DWORD magic;
    DWORD version;
    DWORD generation;
    DWORD reserved;
    unsigned __int64 mapping;
    unsigned __int64 semaphore;
};

static_assert(sizeof(Payload) == 32, "payload must remain a cross-bitness ABI");
static_assert(offsetof(Payload, magic) == 0, "payload magic offset");
static_assert(offsetof(Payload, version) == 4, "payload version offset");
static_assert(offsetof(Payload, generation) == 8, "payload generation offset");
static_assert(offsetof(Payload, reserved) == 12, "payload reserved offset");
static_assert(offsetof(Payload, mapping) == 16, "payload mapping offset");
static_assert(offsetof(Payload, semaphore) == 24, "payload semaphore offset");

Payload MakePayload(DWORD generation, unsigned __int64 mapping,
                    unsigned __int64 semaphore);
bool PayloadValid(const Payload* payload, DWORD bytes, bool targetIs32Bit);

bool VfsRequested();
bool OpenFromBootstrapEnvironment();
bool OpenFromPayload();
bool CopyPayloadToProcess(HANDLE process);
bool RegisterExpected(DWORD pid);
bool MarkAttached(DWORD pid);
bool SignalFailure();
void Close();

}  // namespace vfs_attestation
