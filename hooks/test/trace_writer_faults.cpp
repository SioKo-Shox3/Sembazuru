#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

namespace {
enum class WriteMode { kComplete, kPartialThenComplete, kPartialThenFail, kFail, kZero };

std::vector<unsigned char> g_bytes;
unsigned g_writeCalls = 0;
unsigned g_closeCalls = 0;
SIZE_T g_heapFailAfter = static_cast<SIZE_T>(-1);
unsigned g_heapAllocCalls = 0;
WriteMode g_writeMode = WriteMode::kComplete;
unsigned g_failOnCall = 0;

BOOL WINAPI TestWriteFile(HANDLE, LPCVOID data, DWORD size, LPDWORD written,
                          LPOVERLAPPED) {
    ++g_writeCalls;
    if (g_failOnCall != 0 && g_writeCalls == g_failOnCall) {
        *written = 0;
        return FALSE;
    }
    if (g_writeMode == WriteMode::kFail) {
        *written = 0;
        return FALSE;
    }
    if (g_writeMode == WriteMode::kZero) {
        *written = 0;
        return TRUE;
    }
    DWORD accepted = size;
    if (g_writeMode == WriteMode::kPartialThenComplete ||
        g_writeMode == WriteMode::kPartialThenFail) {
        accepted = size > 1 ? size / 2 : 1;
        g_writeMode = g_writeMode == WriteMode::kPartialThenFail
                          ? WriteMode::kFail
                          : WriteMode::kComplete;
    }
    const auto* first = static_cast<const unsigned char*>(data);
    g_bytes.insert(g_bytes.end(), first, first + accepted);
    *written = accepted;
    return TRUE;
}

LPVOID WINAPI TestHeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    ++g_heapAllocCalls;
    if (g_heapFailAfter == 0) {
        return nullptr;
    }
    if (g_heapFailAfter != static_cast<SIZE_T>(-1)) {
        --g_heapFailAfter;
    }
    return HeapAlloc(heap, flags, size);
}

BOOL WINAPI TestHeapFree(HANDLE heap, DWORD flags, LPVOID memory) {
    return HeapFree(heap, flags, memory);
}

BOOL WINAPI TestCloseHandle(HANDLE) {
    ++g_closeCalls;
    return TRUE;
}

HANDLE WINAPI TestCreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                              DWORD, DWORD, HANDLE) {
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));
}

DWORD WINAPI TestGetEnvironmentVariableW(LPCWSTR, LPWSTR buffer, DWORD size) {
    constexpr wchar_t kDir[] = L"C:\\trace";
    constexpr DWORD kChars = ARRAYSIZE(kDir) - 1;
    if (size <= kChars) {
        return kChars + 1;
    }
    memcpy(buffer, kDir, sizeof(kDir));
    return kChars;
}
}  // namespace

#define WriteFile TestWriteFile
#define HeapAlloc TestHeapAlloc
#define HeapFree TestHeapFree
#define CloseHandle TestCloseHandle
#include "../src/trace_writer.cpp"
#undef CloseHandle
#undef HeapFree
#undef HeapAlloc
#undef WriteFile

HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                DWORD, DWORD, HANDLE) = TestCreateFileW;
DWORD(WINAPI* TrueGetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD) =
    TestGetEnvironmentVariableW;

namespace {
void ResetOpenWriter() {
    g_bytes.clear();
    g_writeCalls = 0;
    g_closeCalls = 0;
    g_heapFailAfter = static_cast<SIZE_T>(-1);
    g_heapAllocCalls = 0;
    g_writeMode = WriteMode::kComplete;
    g_failOnCall = 0;
    trace::g_file = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));
    trace::g_initDone = true;
}

void ResetClosedWriter() {
    ResetOpenWriter();
    trace::g_file = INVALID_HANDLE_VALUE;
    trace::g_initDone = false;
}

bool Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

void RecordPathAux(const wchar_t* path = L"path", int pathLen = -1,
                   const wchar_t* aux = L"aux", int auxLen = 3) {
    trace::Record(trace::kFile, trace::kProbe, 0, 0, path, pathLen, aux,
                  auxLen);
}

bool ParseRecords(const std::vector<unsigned char>& bytes, unsigned expected) {
    constexpr size_t kHeader = sizeof(trace::RecordHeader);
    size_t offset = 0;
    unsigned count = 0;
    while (offset < bytes.size()) {
        if (bytes.size() - offset < kHeader) {
            return false;
        }
        offset += kHeader;
        for (unsigned field = 0; field != 2; ++field) {
            if (bytes.size() - offset < sizeof(DWORD)) {
                return false;
            }
            DWORD chars = 0;
            memcpy(&chars, bytes.data() + offset, sizeof(chars));
            offset += sizeof(chars);
            const size_t fieldBytes = static_cast<size_t>(chars) * sizeof(wchar_t);
            if (fieldBytes > bytes.size() - offset) {
                return false;
            }
            offset += fieldBytes;
        }
        ++count;
    }
    return count == expected;
}

bool TestGoldenAndExactOne() {
    ResetOpenWriter();
    RecordPathAux(L"path", -1, L"aux", 3);
    const size_t expectedBytes = sizeof(trace::RecordHeader) + sizeof(DWORD) +
                                 4 * sizeof(wchar_t) + sizeof(DWORD) +
                                 3 * sizeof(wchar_t);
    trace::RecordHeader header = {};
    DWORD pathChars = 0;
    DWORD auxChars = 0;
    memcpy(&header, g_bytes.data(), sizeof(header));
    memcpy(&pathChars, g_bytes.data() + sizeof(trace::RecordHeader),
           sizeof(pathChars));
    memcpy(&auxChars, g_bytes.data() + sizeof(trace::RecordHeader) +
                         sizeof(DWORD) + 4 * sizeof(wchar_t),
           sizeof(auxChars));
    return Check(g_writeCalls == 1, "normal record is exactly one WriteFile") &&
           Check(g_heapAllocCalls == 0, "common short record does not heap allocate") &&
           Check(g_bytes.size() == expectedBytes, "v0 record byte size") &&
           Check(header.type == trace::kFile && header.op == trace::kProbe &&
                     header.reserved == 0 && header.status == 0 &&
                     header.extra == 0,
                 "v0 fixed RecordHeader fields") &&
           Check(pathChars == 4 && auxChars == 3, "v0 UTF-16 counts") &&
           Check(memcmp(g_bytes.data() + sizeof(trace::RecordHeader) +
                            sizeof(DWORD),
                        L"path", 4 * sizeof(wchar_t)) == 0 &&
                     memcmp(g_bytes.data() + sizeof(trace::RecordHeader) +
                                sizeof(DWORD) + 4 * sizeof(wchar_t) +
                                sizeof(DWORD),
                            L"aux", 3 * sizeof(wchar_t)) == 0,
                 "v0 UTF-16 path and aux payload") &&
           Check(ParseRecords(g_bytes, 1), "v0 record parser");
}

bool TestLongAndAllocationFailure() {
    std::vector<wchar_t> longPath(2048, L'x');
    ResetOpenWriter();
    RecordPathAux(longPath.data(), static_cast<int>(longPath.size()), L"", 0);
    if (!Check(g_writeCalls == 1 && g_heapAllocCalls == 1 && ParseRecords(g_bytes, 1),
               "long record remains one complete write")) {
        return false;
    }
    ResetOpenWriter();
    g_heapFailAfter = 0;
    RecordPathAux(longPath.data(), static_cast<int>(longPath.size()), L"", 0);
    const unsigned afterHeapFailure = g_writeCalls;
    RecordPathAux();
    return Check(afterHeapFailure == 0 && g_bytes.empty() &&
                     g_writeCalls == afterHeapFailure &&
                     trace::g_file == INVALID_HANDLE_VALUE,
                 "heap failure terminally disables before any byte");
}

bool TestInvalidAndOverflow() {
    ResetOpenWriter();
    RecordPathAux(L"path", -2, L"aux", 3);
    const unsigned afterInvalid = g_writeCalls;
    RecordPathAux();
    if (!Check(afterInvalid == 0 && g_writeCalls == afterInvalid &&
                   trace::g_file == INVALID_HANDLE_VALUE,
               "invalid length terminally disables before any byte")) {
        return false;
    }
    ResetOpenWriter();
    RecordPathAux(L"x", (std::numeric_limits<int>::max)(), L"", 0);
    const unsigned afterOverflow = g_writeCalls;
    RecordPathAux();
    return Check(afterOverflow == 0 && g_bytes.empty() &&
                     g_writeCalls == afterOverflow &&
                     trace::g_file == INVALID_HANDLE_VALUE,
                 "DWORD overflow terminally disables before any byte");
}

bool TestPartialAndTerminalFailures() {
    ResetOpenWriter();
    g_writeMode = WriteMode::kPartialThenComplete;
    RecordPathAux();
    if (!Check(g_writeCalls == 2 && ParseRecords(g_bytes, 1),
               "partial write resumes only its suffix")) {
        return false;
    }
    ResetOpenWriter();
    g_writeMode = WriteMode::kPartialThenFail;
    RecordPathAux();
    const unsigned afterPartialFailure = g_writeCalls;
    const size_t fragmentBytes = g_bytes.size();
    RecordPathAux();
    if (!Check(afterPartialFailure == 2 && fragmentBytes != 0 &&
                   fragmentBytes < sizeof(trace::RecordHeader) + 32 &&
                   g_writeCalls == afterPartialFailure &&
                   trace::g_file == INVALID_HANDLE_VALUE,
               "partial then failure leaves only a truncated final fragment")) {
        return false;
    }
    for (WriteMode mode : {WriteMode::kFail, WriteMode::kZero}) {
        ResetOpenWriter();
        g_writeMode = mode;
        RecordPathAux();
        const unsigned afterFailure = g_writeCalls;
        RecordPathAux();
        if (!Check(afterFailure == 1 && g_writeCalls == afterFailure &&
                       trace::g_file == INVALID_HANDLE_VALUE,
                   "write failure terminally disables writer")) {
            return false;
        }
    }
    ResetClosedWriter();
    g_failOnCall = 2;
    RecordPathAux();
    const unsigned afterHeaderFailure = g_writeCalls;
    RecordPathAux();
    return Check(afterHeaderFailure == 2 && g_writeCalls == afterHeaderFailure &&
                     trace::g_file == INVALID_HANDLE_VALUE,
                 "mid-header failure terminally disables writer");
}

bool TestThreadsAndShutdown() {
    ResetOpenWriter();
    constexpr unsigned kThreads = 4;
    constexpr unsigned kPerThread = 40;
    std::vector<std::thread> threads;
    for (unsigned i = 0; i != kThreads; ++i) {
        threads.emplace_back([=] {
            for (unsigned j = 0; j != kPerThread; ++j) {
                RecordPathAux();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    if (!Check(g_writeCalls == kThreads * kPerThread &&
                   ParseRecords(g_bytes, kThreads * kPerThread),
               "thread records never interleave")) {
        return false;
    }
    trace::Shutdown();
    return Check(g_closeCalls == 1 && trace::g_file == INVALID_HANDLE_VALUE,
                 "Shutdown closes once");
}
}  // namespace

int main() {
    return TestGoldenAndExactOne() && TestLongAndAllocationFailure() &&
                   TestInvalidAndOverflow() && TestPartialAndTerminalFailures() &&
                   TestThreadsAndShutdown()
               ? 0
               : 1;
}
