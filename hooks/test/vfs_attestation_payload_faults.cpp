#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdio>

#include "vfs_attestation.h"

namespace {

bool Expect(bool value, const char* message) {
    if (!value) {
        std::fprintf(stderr, "FAIL: %s\n", message);
    }
    return value;
}

}  // namespace

int main() {
    using vfs_attestation::Payload;
    bool ok = true;
    ok &= Expect(sizeof(Payload) == 32, "payload size");
    ok &= Expect(offsetof(Payload, magic) == 0, "magic offset");
    ok &= Expect(offsetof(Payload, version) == 4, "version offset");
    ok &= Expect(offsetof(Payload, generation) == 8, "generation offset");
    ok &= Expect(offsetof(Payload, reserved) == 12, "reserved offset");
    ok &= Expect(offsetof(Payload, mapping) == 16, "mapping offset");
    ok &= Expect(offsetof(Payload, semaphore) == 24, "semaphore offset");

    Payload payload = vfs_attestation::MakePayload(7, 0x40, 0x44);
    ok &= Expect(vfs_attestation::PayloadValid(&payload, sizeof(payload), false),
                 "literal golden payload");
    ok &= Expect(!vfs_attestation::PayloadValid(nullptr, sizeof(payload), false),
                 "missing payload");
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload) - 1, false),
                 "wrong size");
    ++payload.magic;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "magic");
    --payload.magic;
    ++payload.version;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "version");
    --payload.version;
    payload.generation = 0;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "generation");
    payload.generation = 7;
    payload.reserved = 1;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "reserved");
    payload.reserved = 0;
    payload.mapping = 0;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "zero");
    payload.mapping = ~0ULL;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "invalid");
    payload.mapping = 0x40;
    payload.semaphore = 0x40;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), false), "equal");
    payload.semaphore = 0x44;
    payload.mapping = 0x1'0000'0040ULL;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), true), "x86 mapping upper bits");
    payload.mapping = 0x40;
    payload.semaphore = 0x1'0000'0044ULL;
    ok &= Expect(!vfs_attestation::PayloadValid(&payload, sizeof(payload), true), "x86 semaphore upper bits");
    return ok ? 0 : 1;
}
