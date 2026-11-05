#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include "vtable_slot_hook.h"
#include "source_apb_validator.h"

#include <array>
#include <cstdint>
#include <cstdarg>
#include <cwchar>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


namespace {

constexpr SIZE_T kPatchRva = 0x2935477;
constexpr SIZE_T kProcessFileRva = 0x3C1D270;
constexpr SIZE_T kBorrowedDiscardCallRva = 0x3C1D4E0;
constexpr SIZE_T kDiscardNoLockRva = 0x3A0C010;
constexpr SIZE_T kPhysicsBuilderVtableRva = 0x6F3B130;
constexpr SIZE_T kDepotGlobalRva = 0xBF3D010;
constexpr SIZE_T kMainThreadIdRva = 0xBF3DB70;
constexpr SIZE_T kProjectContextGlobalRva = 0xBF3E190;
constexpr SIZE_T kFindFileUseLinksRva = 0x39F6380;
constexpr SIZE_T kGetAbsolutePathRva = 0x3A15260;
constexpr SIZE_T kTStringDestructorRva = 0x39BD670;
constexpr SIZE_T kResourceReloadRva = 0x39DA350;
constexpr SIZE_T kDiskFileVtableRva = 0x6EAC240;
constexpr SIZE_T kCachedDirectoryVtableRva = 0x6EBB2E8;
constexpr SIZE_T kPhysicalDirectoryVtableRva = 0x6EFEA50;
constexpr SIZE_T kVirtualDirectoryVtableRva = 0x6ED99E0;
constexpr SIZE_T kApexClothVtableRva = 0x6BF5510;
constexpr SIZE_T kQuarantineMapRva = 0xBF3D120;
constexpr std::array<UCHAR, 15> kProcessFilePrologue = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0x48, 0x89, 0x6C, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18
};
constexpr std::array<UCHAR, 5> kBorrowedDiscardCallBytes = {
    0xE8, 0x2B, 0xEB, 0xDE, 0xFF
};
constexpr LONGLONG kExpectedEditorSize = 198239184;
constexpr std::array<UCHAR, 32> kExpectedSha256 = { 0x37, 0xA8, 0xB2, 0x54, 0xDA, 0x91, 0x3C, 0x65, 0x70, 0x64, 0x47, 0xF4, 0x79, 0x78, 0x06, 0x51, 0xB7, 0x06, 0xC1, 0xA8, 0xB4, 0xED, 0x3E, 0xF7, 0x58, 0xAA, 0xAF, 0xC0, 0x04, 0x86, 0x69, 0x49 };

using ProcessFileFn = bool(WINAPI*)(void*, void*, void*, void*);
using FindFileUseLinksFn = void*(WINAPI*)(void*, const void*, unsigned int);
using GetAbsolutePathFn = void*(WINAPI*)(void*, void*);
using TStringDestructorFn = void(WINAPI*)(void*);
using ResourceReloadFn = bool(WINAPI*)(void*, bool);
using DiscardNoLockFn = void(WINAPI*)(void*);

HMODULE g_self = nullptr;
INIT_ONCE g_traceOnce = INIT_ONCE_STATIC_INIT;
void* g_processFileTrampoline = nullptr;
UCHAR* g_editorBase = nullptr;
void* g_borrowedRelay = nullptr;
DiscardNoLockFn g_discardNoLock = nullptr;
bool g_borrowedCallPatched = false;
volatile LONG g_traceCalls = 0;
volatile LONG g_redclothCalls = 0;
thread_local bool g_insideTrace = false;
thread_local bool g_interventionActive = false;
thread_local char g_activeDepotPath[768] = {};
struct BorrowedCleanupGuard {
    bool active;
    void* file;
    void* resource;
    void* handle;
    UCHAR fileFlags;
    DWORD threadId;
    unsigned int callsiteHits;
    unsigned int exactMatches;
    unsigned int skips;
    unsigned int failClosedSkips;
    unsigned int forwards;
    unsigned int rejectionBits;
    bool failClosedOnRoot = false;
    // Captured from the existing cleanup checks; no additional editor call.
    bool callsiteLoadFlagsReadable = false;
    UCHAR callsiteLoadFlags = 0xFF;
    bool callsiteHandleFlagsReadable = false;
    std::uint32_t callsiteHandleFlags = 0;
};
thread_local BorrowedCleanupGuard g_borrowedGuard{};
// A Reload that changed a resource can make a file sticky invalid.
// The initial-busy handoff remains one-shot even after native success.
enum class FileState { InProgress, Invalid };
std::mutex g_fileStatesMutex;
std::unordered_map<std::string, FileState> g_fileStates;
// A native ProcessFile handoff from the quarantine state is experimental.
// Permit it only once per physical file in this editor process.
std::unordered_set<std::string> g_quarantineAttempts;
// A clean load-state file may still retain a post-Reload cloth attachment.
// Keep this separate handoff one-shot as well.
std::unordered_set<std::string> g_cleanAttachmentAttempts;

void Log(const wchar_t* format, ...) {
    wchar_t message[1024] = {};
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(message, _countof(message), _TRUNCATE, format, args);
    va_end(args);

    wchar_t line[1200] = {};
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"%04u-%02u-%02u %02u:%02u:%02u.%03u PID %lu %s\r\n",
                 now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
                 now.wSecond, now.wMilliseconds, GetCurrentProcessId(), message);
    OutputDebugStringW(line);

    wchar_t path[MAX_PATH] = {};
    const DWORD length = GetTempPathW(_countof(path), path);
    if (length == 0 || length >= _countof(path)) return;
    const int written = _snwprintf_s(path + length, _countof(path) - length,
                                    _TRUNCATE, L"redkit_apb_proxy_%lu.log",
                                    GetCurrentProcessId());
    if (written < 0) return;

    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    const int size = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (size > 1) {
        std::vector<char> utf8(static_cast<size_t>(size));
        if (WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8.data(), size,
                                nullptr, nullptr) == size) {
            DWORD bytesWritten = 0;
            WriteFile(file, utf8.data(), static_cast<DWORD>(size - 1), &bytesWritten, nullptr);
        }
    }
    CloseHandle(file);
}

bool ComputeSha256(const wchar_t* path, std::array<UCHAR, 32>& digest) {
    HANDLE file = CreateFileW(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        Log(L"Cannot open editor.exe for SHA-256 (Win32 %lu).", GetLastError());
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<UCHAR> hashObject;
    bool result = false;
    do {
        LARGE_INTEGER size = {};
        if (!GetFileSizeEx(file, &size) || size.QuadPart != kExpectedEditorSize) {
            Log(L"Editor file size differs from the tested build; trace skipped.");
            break;
        }
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                                       nullptr, 0);
        if (status < 0) {
            Log(L"BCryptOpenAlgorithmProvider failed (0x%08X).",
                static_cast<unsigned>(status));
            break;
        }
        DWORD objectLength = 0;
        DWORD returned = 0;
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&objectLength),
                                   sizeof(objectLength), &returned, 0);
        if (status < 0 || returned != sizeof(objectLength)) {
            Log(L"BCryptGetProperty failed (0x%08X).", static_cast<unsigned>(status));
            break;
        }
        hashObject.resize(objectLength);
        status = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength,
                                  nullptr, 0, 0);
        if (status < 0) {
            Log(L"BCryptCreateHash failed (0x%08X).", static_cast<unsigned>(status));
            break;
        }

        std::vector<UCHAR> buffer(1024 * 1024);
        bool readOkay = true;
        for (;;) {
            DWORD count = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                          &count, nullptr)) {
                Log(L"Reading editor.exe failed (Win32 %lu).", GetLastError());
                readOkay = false;
                break;
            }
            if (count == 0) break;
            status = BCryptHashData(hash, buffer.data(), count, 0);
            if (status < 0) {
                Log(L"BCryptHashData failed (0x%08X).", static_cast<unsigned>(status));
                readOkay = false;
                break;
            }
        }
        if (!readOkay) break;
        status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        if (status < 0) {
            Log(L"BCryptFinishHash failed (0x%08X).", static_cast<unsigned>(status));
            break;
        }
        result = true;
    } while (false);

    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return result;
}

bool SafeCopy(const void* source, void* destination, SIZE_T size) {
    if (!source) return false;
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), source, destination, size, &copied) &&
           copied == size;
}

// The 12-byte TString<char> has a pointer followed by a NUL-inclusive length.
// Copy exactly those fields and at most 767 bytes of string data.
template <size_t N>
bool ReadBoundedTString12(const void* stringObject, char (&result)[N]) {
    if (!stringObject) return false;
    const auto* address = static_cast<const UCHAR*>(stringObject);
    void* data = nullptr;
    unsigned int length = 0;
    if (!SafeCopy(address, &data, sizeof(data)) ||
        !SafeCopy(address + sizeof(data), &length, sizeof(length)) ||
        !data || length <= 1 || length > N ||
        !SafeCopy(data, result, length) || result[length - 1] != '\0' ||
        std::strlen(result) != length - 1) return false;
    return true;
}

void NormalizeSlashes(char* path) {
    for (char* current = path; *current; ++current) {
        if (*current == '/') *current = '\\';
    }
}

bool HasExtension(const char* path, const char* extension) {
    const size_t pathLength = std::strlen(path);
    const size_t suffixLength = std::strlen(extension);
    return pathLength > suffixLength &&
        _stricmp(path + pathLength - suffixLength, extension) == 0;
}

bool ValidPathSegments(const char* path, size_t start) {
    const size_t length = std::strlen(path);
    if (start >= length) return false;
    size_t segmentStart = start;
    for (size_t position = start; position <= length; ++position) {
        if (position != length && path[position] != '\\') continue;
        const size_t segmentLength = position - segmentStart;
        if (segmentLength == 0 ||
            (segmentLength == 1 && path[segmentStart] == '.') ||
            (segmentLength == 2 && path[segmentStart] == '.' &&
             path[segmentStart + 1] == '.') ||
            path[position - 1] == ' ' || path[position - 1] == '.') {
            return false;
        }
        for (size_t index = segmentStart; index < position; ++index) {
            const unsigned char c = static_cast<unsigned char>(path[index]);
            if (c < 32 || c == 127 || c == ':' || c == '"' ||
                c == '<' || c == '>' || c == '|' || c == '?' ||
                c == '*' || c == '/') return false;
        }
        segmentStart = position + 1;
    }
    return true;
}

bool ValidateProjectFile(char* projectFile, char (&workspace)[768],
                         const wchar_t*& reason) {
    NormalizeSlashes(projectFile);
    if (!HasExtension(projectFile, ".w3edit")) {
        reason = L"context is not a .w3edit path";
        return false;
    }
    const size_t length = std::strlen(projectFile);
    size_t componentStart = 0;
    const unsigned char drive = static_cast<unsigned char>(projectFile[0]);
    if (((drive >= 'A' && drive <= 'Z') ||
         (drive >= 'a' && drive <= 'z')) &&
        projectFile[1] == ':' && projectFile[2] == '\\') {
        componentStart = 3;
    } else if (projectFile[0] == '\\' && projectFile[1] == '\\' &&
               projectFile[2] != '\\' && projectFile[2] != '.' &&
               projectFile[2] != '?') {
        const char* serverEnd = std::strchr(projectFile + 2, '\\');
        const char* shareEnd = serverEnd ? std::strchr(serverEnd + 1, '\\') : nullptr;
        if (!serverEnd || serverEnd == projectFile + 2 ||
            !shareEnd || shareEnd == serverEnd + 1) {
            reason = L"context UNC server/share invalid";
            return false;
        }
        componentStart = 2;
    } else {
        reason = L"context .w3edit path is not absolute drive or UNC";
        return false;
    }
    if (!ValidPathSegments(projectFile, componentStart)) {
        reason = L"context .w3edit path has empty, dot, or invalid component";
        return false;
    }
    const char* finalSeparator = std::strrchr(projectFile, '\\');
    if (!finalSeparator ||
        std::strlen(finalSeparator + 1) <= std::strlen(".w3edit")) {
        reason = L"context .w3edit filename stem absent";
        return false;
    }
    const size_t parentLength =
        static_cast<size_t>(finalSeparator - projectFile) + 1;
    constexpr char kWorkspaceSuffix[] = "workspace\\";
    if (parentLength + sizeof(kWorkspaceSuffix) > sizeof(workspace)) {
        reason = L"derived workspace path exceeds bound";
        return false;
    }
    std::memcpy(workspace, projectFile, parentLength);
    std::memcpy(workspace + parentLength,
                kWorkspaceSuffix, sizeof(kWorkspaceSuffix));
    if (length <= parentLength) {
        reason = L"context .w3edit basename absent";
        return false;
    }
    return true;
}

bool ValidateDepotPath(char* depotPath, const wchar_t*& reason) {
    NormalizeSlashes(depotPath);
    if (depotPath[0] == '\\' || !HasExtension(depotPath, ".redcloth")) {
        reason = L"depot path is rooted or not .redcloth";
        return false;
    }
    const char* basename = std::strrchr(depotPath, '\\');
    basename = basename ? basename + 1 : depotPath;
    if (std::strlen(basename) <= std::strlen(".redcloth")) {
        reason = L"depot .redcloth filename stem absent";
        return false;
    }
    if (!ValidPathSegments(depotPath, 0)) {
        reason = L"depot path has empty, dot, traversal, or invalid component";
        return false;
    }
    return true;
}

bool ProjectFileExists(const char* projectFile) {
    wchar_t widePath[768] = {};
    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, projectFile, -1,
        widePath, _countof(widePath));
    if (count <= 1 || count > _countof(widePath)) return false;
    const DWORD attributes = GetFileAttributesW(widePath);
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

struct GateSnapshot {
    DWORD threadId = 0;
    DWORD mainThreadId = 0;
    void* context = nullptr;
    void* depot = nullptr;
    void* file = nullptr;
    void* fileVtable = nullptr;
    void* parent = nullptr;
    void* physicalRoot = nullptr;
    void* resource = nullptr;
    void* resourceVtable = nullptr;
    void* linkedFile = nullptr;
    void* apb = nullptr;
    unsigned int apbCount = 0;
    unsigned int ancestryDepth = 0;
    UCHAR fileFlags = 0;
    UCHAR loadFlags = 0;
    bool contextReadable = false;
    bool projectPathReadable = false;
    bool projectFileExists = false;
    bool depotReadable = false;
    bool physicalRootMatched = false;
    bool absolutePathMatched = false;
    bool sourceApbChecked = false;
    redkit::SourceApbResult sourceApb;
    bool eligible = false;
    char projectFile[768] = {};
    char workspaceRoot[768] = {};
    char depotPath[768] = {};
    char physicalRootPath[768] = {};
    char absolutePath[768] = {};
    const wchar_t* reason = L"not evaluated";
};

bool ReadAbsolutePath(void* file, char (&path)[768]) {
    // This is safe only after every directory ancestor is an exact known
    // physical type and the final root equals the active workspace.
    struct TStringStorage { void* data; UINT_PTR lengthAndCapacity; } result = {};
    const auto getter = reinterpret_cast<GetAbsolutePathFn>(
        g_editorBase + kGetAbsolutePathRva);
    const auto destructor = reinterpret_cast<TStringDestructorFn>(
        g_editorBase + kTStringDestructorRva);
    getter(file, &result);
    const unsigned int length =
        static_cast<unsigned int>(result.lengthAndCapacity);
    const bool valid = length > 1 && length <= sizeof(path) && result.data &&
        SafeCopy(result.data, path, length) && path[length - 1] == '\0' &&
        std::strlen(path) == length - 1;
    destructor(&result);
    if (valid) NormalizeSlashes(path);
    return valid;
}

bool WalkPhysicalAncestry(GateSnapshot& snapshot) {
    void* seen[64] = {};
    void* current = snapshot.parent;
    for (unsigned int depth = 0; depth < _countof(seen); ++depth) {
        if (!current) {
            snapshot.reason = L"directory ancestor null";
            return false;
        }
        for (unsigned int previous = 0; previous < depth; ++previous) {
            if (seen[previous] == current) {
                snapshot.reason = L"directory ancestry cycle";
                return false;
            }
        }
        seen[depth] = current;
        snapshot.ancestryDepth = depth + 1;
        void* vtable = nullptr;
        if (!SafeCopy(current, &vtable, sizeof(vtable))) {
            snapshot.reason = L"directory vtable unreadable";
            return false;
        }
        const auto* directory = static_cast<const UCHAR*>(current);
        if (vtable == g_editorBase + kPhysicalDirectoryVtableRva) {
            snapshot.physicalRoot = current;
            if (!ReadBoundedTString12(directory + 0x50,
                                      snapshot.physicalRootPath)) {
                snapshot.reason = L"physical root TString unreadable";
                return false;
            }
            NormalizeSlashes(snapshot.physicalRootPath);
            snapshot.physicalRootMatched =
                _stricmp(snapshot.physicalRootPath,
                         snapshot.workspaceRoot) == 0;
            if (!snapshot.physicalRootMatched)
                snapshot.reason = L"physical root differs from active project workspace";
            return snapshot.physicalRootMatched;
        }
        if (vtable == g_editorBase + kVirtualDirectoryVtableRva) {
            snapshot.reason = L"virtual directory rejected before GetAbsolutePath";
            return false;
        }
        if (vtable != g_editorBase + kCachedDirectoryVtableRva) {
            snapshot.reason = L"unknown directory type rejected";
            return false;
        }
        char name[128] = {};
        if (!ReadBoundedTString12(directory + 0x30, name) ||
            !SafeCopy(directory + 0x28, &current, sizeof(current))) {
            snapshot.reason = L"directory name or ancestor unreadable";
            return false;
        }
    }
    snapshot.reason = L"directory ancestry exceeded 64 nodes";
    return false;
}

GateSnapshot EvaluateGate(const void* pathObject, const char* depotPath,
                          bool requireAttachment = true,
                          bool ignoreBusyFlags = false) {
    GateSnapshot snapshot;
    snapshot.threadId = GetCurrentThreadId();
    strcpy_s(snapshot.depotPath, depotPath);
    if (!ValidateDepotPath(snapshot.depotPath, snapshot.reason))
        return snapshot;
    SafeCopy(g_editorBase + kMainThreadIdRva,
             &snapshot.mainThreadId, sizeof(snapshot.mainThreadId));
    snapshot.contextReadable = SafeCopy(
        g_editorBase + kProjectContextGlobalRva,
        &snapshot.context, sizeof(snapshot.context));
    if (!snapshot.contextReadable || !snapshot.context) {
        snapshot.reason = L"active project context pointer unreadable or null";
        return snapshot;
    }
    snapshot.projectPathReadable = ReadBoundedTString12(
        static_cast<const UCHAR*>(snapshot.context) + 0xE0,
        snapshot.projectFile);
    if (!snapshot.projectPathReadable) {
        snapshot.reason = L"active project TString unreadable or oversize";
        return snapshot;
    }
    if (!ValidateProjectFile(snapshot.projectFile,
                             snapshot.workspaceRoot, snapshot.reason))
        return snapshot;
    if (snapshot.mainThreadId == 0 ||
        snapshot.mainThreadId != snapshot.threadId) {
        snapshot.reason = L"not editor main thread; resolver skipped";
        return snapshot;
    }
    snapshot.projectFileExists = ProjectFileExists(snapshot.projectFile);
    if (!snapshot.projectFileExists) {
        snapshot.reason = L"active .w3edit file absent or not readable as UTF-8";
        return snapshot;
    }
    snapshot.depotReadable = SafeCopy(g_editorBase + kDepotGlobalRva,
                                      &snapshot.depot, sizeof(snapshot.depot));
    if (!snapshot.depotReadable || !snapshot.depot) {
        snapshot.reason = L"depot pointer unreadable or null";
        return snapshot;
    }
    const auto findFile = reinterpret_cast<FindFileUseLinksFn>(
        g_editorBase + kFindFileUseLinksRva);
    snapshot.file = findFile(snapshot.depot, pathObject, 0);
    if (!snapshot.file) {
        snapshot.reason = L"depot path did not resolve";
        return snapshot;
    }
    if (!SafeCopy(snapshot.file, &snapshot.fileVtable,
                  sizeof(snapshot.fileVtable)) ||
        snapshot.fileVtable != g_editorBase + kDiskFileVtableRva) {
        snapshot.reason = L"resolved file is not exact CDiskFile type";
        return snapshot;
    }
    const auto* file = static_cast<const UCHAR*>(snapshot.file);
    if (!SafeCopy(file + 8, &snapshot.parent, sizeof(snapshot.parent)) ||
        !snapshot.parent) {
        snapshot.reason = L"file parent unreadable or null";
        return snapshot;
    }
    if (!WalkPhysicalAncestry(snapshot)) return snapshot;
    if (!ReadAbsolutePath(snapshot.file, snapshot.absolutePath)) {
        snapshot.reason = L"CDiskFile absolute path unreadable";
        return snapshot;
    }
    const std::string expectedPath =
        std::string(snapshot.workspaceRoot) + snapshot.depotPath;
    snapshot.absolutePathMatched =
        expectedPath.size() < sizeof(snapshot.absolutePath) &&
        _stricmp(snapshot.absolutePath, expectedPath.c_str()) == 0;
    if (!snapshot.absolutePathMatched) {
        snapshot.reason = L"absolute file path != workspace root + depot path";
        return snapshot;
    }
    if (!SafeCopy(file + 0x4C, &snapshot.fileFlags,
                  sizeof(snapshot.fileFlags)) ||
        (!ignoreBusyFlags && (snapshot.fileFlags & 0x02) != 0)) {
        snapshot.reason = L"file flags unreadable or modified bit set";
        return snapshot;
    }
    if (!SafeCopy(file + 0x34, &snapshot.loadFlags,
                  sizeof(snapshot.loadFlags)) ||
        (!ignoreBusyFlags && (snapshot.loadFlags & 0x0E) != 0)) {
        snapshot.reason = L"file load-state flags unreadable or busy";
        return snapshot;
    }
    // After Reload a successful detach has a null attachment. Recheck the
    // complete physical and active-project identity before BeginLoad.
    if (!requireAttachment) {
        snapshot.eligible = true;
        snapshot.reason = L"active workspace and physical file revalidated";
        return snapshot;
    }
    if (!SafeCopy(file + 0x10, &snapshot.resource,
                  sizeof(snapshot.resource)) || !snapshot.resource) {
        snapshot.reason = L"file attachment unreadable or absent";
        return snapshot;
    }
    const auto* resource = static_cast<const UCHAR*>(snapshot.resource);
    if (!SafeCopy(resource, &snapshot.resourceVtable,
                  sizeof(snapshot.resourceVtable)) ||
        snapshot.resourceVtable != g_editorBase + kApexClothVtableRva) {
        snapshot.reason = L"attachment is not exact CApexClothResource type";
        return snapshot;
    }
    if (!SafeCopy(resource + 0x58, &snapshot.linkedFile,
                  sizeof(snapshot.linkedFile)) ||
        snapshot.linkedFile != snapshot.file) {
        snapshot.reason = L"resource-to-file reciprocal link absent";
        return snapshot;
    }
    if (!SafeCopy(resource + 0x154, &snapshot.apb,
                  sizeof(snapshot.apb)) ||
        !SafeCopy(resource + 0x15C, &snapshot.apbCount,
                  sizeof(snapshot.apbCount)) ||
        snapshot.apb || snapshot.apbCount != 0) {
        snapshot.reason = L"in-memory APB unreadable or not empty";
        return snapshot;
    }
    wchar_t sourcePath[768] = {};
    const int sourcePathLength = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, snapshot.absolutePath, -1,
        sourcePath, _countof(sourcePath));
    if (sourcePathLength <= 1 ||
        sourcePathLength > static_cast<int>(_countof(sourcePath))) {
        snapshot.reason = L"source path is not valid UTF-8";
        return snapshot;
    }
    snapshot.sourceApbChecked = true;
    snapshot.sourceApb = redkit::ValidateSourceApbFile(sourcePath);
    if (!snapshot.sourceApb.valid()) {
        snapshot.reason = L"source .redcloth lacks one validated APB";
        return snapshot;
    }
    snapshot.eligible = true;
    snapshot.reason = L"active-project, empty-APB, and source APB preflight passed";
    return snapshot;
}

void LogGate(const GateSnapshot& snapshot, LONG call, LONG redclothCall,
             bool processResult) {
    Log(L"GATE call=%ld redclothCall=%ld eligible=%u reason=%s "
        L"tid=%lu mainTid=%lu processResult=%u",
        call, redclothCall, snapshot.eligible ? 1u : 0u, snapshot.reason,
        snapshot.threadId, snapshot.mainThreadId, processResult ? 1u : 0u);
    Log(L"GATE project contextReadable=%u context=%p pathReadable=%u "
        L"projectFileExists=%u projectFile=%S",
        snapshot.contextReadable ? 1u : 0u, snapshot.context,
        snapshot.projectPathReadable ? 1u : 0u,
        snapshot.projectFileExists ? 1u : 0u, snapshot.projectFile);
    Log(L"GATE workspace=%S", snapshot.workspaceRoot);
    Log(L"GATE depotPath=%S", snapshot.depotPath);
    Log(L"GATE file depotReadable=%u depot=%p file=%p vt=%p "
        L"parent=%p depth=%u physicalRoot=%p physicalMatch=%u",
        snapshot.depotReadable ? 1u : 0u, snapshot.depot, snapshot.file,
        snapshot.fileVtable, snapshot.parent, snapshot.ancestryDepth,
        snapshot.physicalRoot, snapshot.physicalRootMatched ? 1u : 0u);
    Log(L"GATE physicalPath=%S", snapshot.physicalRootPath);
    Log(L"GATE absoluteMatch=%u absolutePath=%S",
        snapshot.absolutePathMatched ? 1u : 0u, snapshot.absolutePath);
    Log(L"GATE state fileFlags=%02X loadFlags=%02X resource=%p vt=%p "
        L"linkedFile=%p apb=%p count=%u",
        snapshot.fileFlags, snapshot.loadFlags, snapshot.resource,
        snapshot.resourceVtable, snapshot.linkedFile, snapshot.apb,
        snapshot.apbCount);
    Log(L"GATE source checked=%u valid=%u reason=%S fileSize=%llu "
        L"cr2wVersion=%u apbOffset=%u apbSize=%u",
        snapshot.sourceApbChecked ? 1u : 0u,
        snapshot.sourceApb.valid() ? 1u : 0u,
        snapshot.sourceApb.reason,
        static_cast<unsigned long long>(snapshot.sourceApb.fileSize),
        snapshot.sourceApb.cr2wVersion, snapshot.sourceApb.apbOffset,
        snapshot.sourceApb.apbSize);
}

struct SourceGuard {
    HANDLE file = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION identity = {};
    std::array<UCHAR, 32> sha256 = {};
    wchar_t path[768] = {};
    SourceGuard() = default;
    SourceGuard(const SourceGuard&) = delete;
    SourceGuard& operator=(const SourceGuard&) = delete;
    ~SourceGuard() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
};

void ReleaseSourceGuard(SourceGuard& guard) {
    if (guard.file != INVALID_HANDLE_VALUE) {
        CloseHandle(guard.file);
        guard.file = INVALID_HANDLE_VALUE;
    }
}

bool SameSourceIdentity(const BY_HANDLE_FILE_INFORMATION& a,
                        const BY_HANDLE_FILE_INFORMATION& b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow &&
        a.nFileSizeHigh == b.nFileSizeHigh &&
        a.nFileSizeLow == b.nFileSizeLow &&
        CompareFileTime(&a.ftLastWriteTime, &b.ftLastWriteTime) == 0;
}

bool HashSourceHandle(HANDLE file, std::array<UCHAR, 32>& digest) {
    LARGE_INTEGER beginning = {};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<UCHAR> object;
    bool okay = false;
    do {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                        nullptr, 0) < 0) break;
        DWORD length = 0, returned = 0;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                             reinterpret_cast<PUCHAR>(&length), sizeof(length),
                             &returned, 0) < 0 || returned != sizeof(length)) break;
        object.resize(length);
        if (BCryptCreateHash(algorithm, &hash, object.data(), length,
                             nullptr, 0, 0) < 0) break;
        std::vector<UCHAR> buffer(1024 * 1024);
        okay = true;
        for (;;) {
            DWORD count = 0;
            if (!ReadFile(file, buffer.data(),
                          static_cast<DWORD>(buffer.size()), &count, nullptr)) {
                okay = false;
                break;
            }
            if (!count) break;
            if (BCryptHashData(hash, buffer.data(), count, 0) < 0) {
                okay = false;
                break;
            }
        }
        if (okay && BCryptFinishHash(hash, digest.data(),
                                     static_cast<ULONG>(digest.size()), 0) < 0)
            okay = false;
    } while (false);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return okay;
}

bool OpenSourceGuard(const GateSnapshot& snapshot, SourceGuard& guard,
                     const wchar_t*& reason) {
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        snapshot.absolutePath, -1, guard.path, _countof(guard.path));
    if (count <= 1 || count > _countof(guard.path)) {
        reason = L"source path UTF-8 conversion failed";
        return false;
    }
    // Keep this handle through ProcessFile. Sharing only READ rules out normal
    // writes and replacement while the old resource is detached.
    guard.file = CreateFileW(guard.path, GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (guard.file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(guard.file, &guard.identity) ||
        (guard.identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        reason = L"source could not be held read-only for intervention";
        return false;
    }
    const std::uint64_t size =
        (static_cast<std::uint64_t>(guard.identity.nFileSizeHigh) << 32) |
        guard.identity.nFileSizeLow;
    if (size != snapshot.sourceApb.fileSize ||
        size > redkit::kMaximumSourceClothBytes) {
        reason = L"source size changed after gate validation";
        return false;
    }
    LARGE_INTEGER beginning = {};
    if (!SetFilePointerEx(guard.file, beginning, nullptr, FILE_BEGIN)) {
        reason = L"held source could not be rewound";
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        DWORD received = 0;
        const DWORD request = static_cast<DWORD>(
            bytes.size() - cursor < (1u << 20)
                ? bytes.size() - cursor : (1u << 20));
        if (!ReadFile(guard.file, bytes.data() + cursor, request,
                      &received, nullptr) || !received) {
            reason = L"held source could not be completely read";
            return false;
        }
        cursor += received;
    }
    const auto heldValidation = redkit::ValidateSourceApbBytes(
        bytes.data(), bytes.size());
    if (!heldValidation.valid() ||
        heldValidation.fileSize != snapshot.sourceApb.fileSize ||
        heldValidation.apbOffset != snapshot.sourceApb.apbOffset ||
        heldValidation.apbSize != snapshot.sourceApb.apbSize ||
        !HashSourceHandle(guard.file, guard.sha256)) {
        reason = L"held source APB or SHA-256 validation failed";
        return false;
    }
    return true;
}

bool SourceStillIdentical(const SourceGuard& guard) {
    BY_HANDLE_FILE_INFORMATION held = {};
    if (!GetFileInformationByHandle(guard.file, &held) ||
        !SameSourceIdentity(guard.identity, held)) return false;
    HANDLE current = CreateFileW(guard.path, GENERIC_READ, FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
    if (current == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION found = {};
    const bool same = GetFileInformationByHandle(current, &found) &&
        SameSourceIdentity(guard.identity, found);
    CloseHandle(current);
    if (!same) return false;
    std::array<UCHAR, 32> digest = {};
    return HashSourceHandle(guard.file, digest) && digest == guard.sha256;
}

enum class ApbEqualityStatus : unsigned int {
    NotChecked = 0,
    Equal,
    InvalidInputs,
    SourceReadFailed,
    MemoryReadFailed,
    Different,
};

struct ApbEquality {
    ApbEqualityStatus status = ApbEqualityStatus::NotChecked;
    std::uint32_t mismatchOffset = 0;
};

// Read-only comparison used by the resource gates.
// The held source handle rules out a normal file write/replacement during it.
ApbEquality CompareHeldSourceApb(const GateSnapshot& snapshot,
                                 SourceGuard& source, const void* apb,
                                 unsigned int count) {
    ApbEquality result;
    if (source.file == INVALID_HANDLE_VALUE || !apb ||
        !snapshot.sourceApb.valid() || !snapshot.sourceApb.apbSize ||
        count != snapshot.sourceApb.apbSize ||
        static_cast<std::uint64_t>(snapshot.sourceApb.apbOffset) + count >
            snapshot.sourceApb.fileSize) {
        result.status = ApbEqualityStatus::InvalidInputs;
        return result;
    }
    LARGE_INTEGER position = {};
    position.QuadPart = snapshot.sourceApb.apbOffset;
    if (!SetFilePointerEx(source.file, position, nullptr, FILE_BEGIN)) {
        result.status = ApbEqualityStatus::SourceReadFailed;
        return result;
    }
    std::array<UCHAR, 16 * 1024> sourceBytes = {};
    std::array<UCHAR, 16 * 1024> attachedBytes = {};
    for (std::uint32_t cursor = 0; cursor < count;) {
        const DWORD amount = static_cast<DWORD>(
            count - cursor < sourceBytes.size()
                ? count - cursor : sourceBytes.size());
        DWORD received = 0;
        if (!ReadFile(source.file, sourceBytes.data(), amount, &received,
                      nullptr) || received != amount) {
            result.status = ApbEqualityStatus::SourceReadFailed;
            return result;
        }
        if (!SafeCopy(static_cast<const UCHAR*>(apb) + cursor,
                      attachedBytes.data(), amount)) {
            result.status = ApbEqualityStatus::MemoryReadFailed;
            return result;
        }
        if (std::memcmp(sourceBytes.data(), attachedBytes.data(), amount)) {
            for (DWORD index = 0; index < amount; ++index) {
                if (sourceBytes[index] != attachedBytes[index]) {
                    result.status = ApbEqualityStatus::Different;
                    result.mismatchOffset = cursor + index;
                    return result;
                }
            }
        }
        cursor += amount;
    }
    result.status = ApbEqualityStatus::Equal;
    return result;
}

// Passive, bounded lookup of the exact CDiskFile* in the editor's quarantine map.
// The map uses a Win32 CRITICAL_SECTION at +0x30. The file's +0x3C lock
// is an editor CLightMutex with no validated nonblocking acquire routine, so
// file-state samples here are explicitly unsynchronized observations.
enum class QuarantineLookupStatus : unsigned int {
    NotRun = 0,
    MapBusy,
    FileStateUnreadable,
    FileStateChanged,
    InvalidHeader,
    InvalidBucket,
    InvalidNode,
    TraversalLimit,
    KeyHashMismatch,
    Member,
    Absent,
};

struct QuarantineLookup {
    QuarantineLookupStatus status = QuarantineLookupStatus::NotRun;
    bool beforeReadable = false;
    bool afterReadable = false;
    UCHAR flagsBefore = 0;
    UCHAR flagsAfter = 0;
    void* attachmentBefore = nullptr;
    void* attachmentAfter = nullptr;
    std::uint32_t bucketCount = 0;
    std::uint32_t entryCount = 0;
    std::uint32_t hash = 0;
    std::uint32_t bucket = 0;
    std::uint32_t traversed = 0;
    bool keyHashMismatch = false;
};

struct QuarantineNodeView {
    void* key;
    void* unused;
    std::uint32_t hash;
    std::uint32_t padding;
    void* next;
};
static_assert(sizeof(QuarantineNodeView) == 0x20);

bool ReadObservedFileState(void* file, UCHAR& flags, void*& attachment) {
    const auto* bytes = static_cast<const UCHAR*>(file);
    return SafeCopy(bytes + 0x34, &flags, sizeof(flags)) &&
        SafeCopy(bytes + 0x10, &attachment, sizeof(attachment));
}

std::uint32_t QuarantineHash(void* file) {
    const std::uint32_t low = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(file));
    std::uint32_t hash = low ^ 0x003D0000u;
    hash = (hash >> 16) ^ low;
    hash *= 9u;
    hash ^= hash >> 4;
    hash *= 0x27D4EB2Du;
    hash ^= hash >> 15;
    return hash;
}

bool AlignedUserPointer(const void* pointer) {
    const auto value = reinterpret_cast<std::uintptr_t>(pointer);
    return value >= 0x10000u && value <= 0x00007FFFFFFFFFFFu &&
        (value & (alignof(void*) - 1)) == 0;
}

// The only patched native instruction is ProcessFile+0x270. Its call passes
// r14 in RCX. A near relay jumps here without changing registers or the
// return address, so the ordinary Win64 function ABI still applies.
void WINAPI BorrowedDiscardCall(void* object) {
    auto& guard = g_borrowedGuard;
    if (guard.active) {
        ++guard.callsiteHits;
        unsigned int rejection = 0;
        const void* const returnAddress = _ReturnAddress();
        if (returnAddress != g_editorBase + kBorrowedDiscardCallRva + 5)
            rejection |= 0x01;
        DWORD editorMainThread = 0;
        if (GetCurrentThreadId() != guard.threadId ||
            !SafeCopy(g_editorBase + kMainThreadIdRva, &editorMainThread,
                      sizeof(editorMainThread)) ||
            editorMainThread != guard.threadId)
            rejection |= 0x02;
        if (object != guard.resource || !AlignedUserPointer(object))
            rejection |= 0x04;
        if (rejection == 0) {
            const auto* file = static_cast<const UCHAR*>(guard.file);
            const auto* cloth = static_cast<const UCHAR*>(object);
            void* attachment = nullptr;
            void* vtable = nullptr;
            void* linkedFile = nullptr;
            void* handle = nullptr;
            UCHAR loadFlags = 0xFF;
            UCHAR fileFlags = 0xFF;
            UCHAR resourceLoadByte = 0xFF;
            std::uint32_t handleFlags = 0;
            std::uint32_t objectFlags = 0;
            bool loadFlagsReadable = false;
            bool handleFlagsReadable = false;
            if (!SafeCopy(file + 0x10, &attachment, sizeof(attachment)) ||
                attachment != object ||
                !(loadFlagsReadable = SafeCopy(
                      file + 0x34, &loadFlags, sizeof(loadFlags))) ||
                loadFlags != 0 ||
                !SafeCopy(file + 0x4C, &fileFlags, sizeof(fileFlags)) ||
                fileFlags != guard.fileFlags)
                rejection |= 0x08;
            guard.callsiteLoadFlagsReadable = loadFlagsReadable;
            guard.callsiteLoadFlags = loadFlags;
            if (!SafeCopy(cloth, &vtable, sizeof(vtable)) ||
                vtable != g_editorBase + kApexClothVtableRva ||
                !SafeCopy(cloth + 0x58, &linkedFile,
                          sizeof(linkedFile)) ||
                linkedFile != guard.file ||
                !SafeCopy(cloth + 0x60, &resourceLoadByte,
                          sizeof(resourceLoadByte)) ||
                resourceLoadByte != 0)
                rejection |= 0x10;
            if (!SafeCopy(cloth + 0x08, &handle, sizeof(handle)) ||
                handle != guard.handle || !AlignedUserPointer(handle) ||
                !(handleFlagsReadable = SafeCopy(
                      static_cast<const UCHAR*>(handle) + 0x04,
                      &handleFlags, sizeof(handleFlags))) ||
                (handleFlags & 0x04) != 0)
                rejection |= 0x20;
            guard.callsiteHandleFlagsReadable = handleFlagsReadable;
            guard.callsiteHandleFlags = handleFlags;
            if (!SafeCopy(cloth + 0x54, &objectFlags,
                          sizeof(objectFlags)) ||
                (objectFlags & 0x04) == 0)
                rejection |= 0x40;
        }
        if (rejection == 0) {
            ++guard.exactMatches;
            if (guard.skips == 0) {
                ++guard.skips;
                return;
            }
            rejection = 0x80;  // Never suppress a second cleanup call.
        }
        // A rooted exact replacement must not be forwarded to the editor's
        // DiscardNoLock if the dynamic dequarantine check failed. Suppress
        // only one such exact call, then force the entire guarded handoff to
        // fail. Unrelated objects and repeated calls retain native behavior.
        if (guard.failClosedOnRoot && (rejection & 0x07) == 0 &&
            guard.callsiteHits == 1 &&
            guard.skips == 0 && guard.failClosedSkips == 0) {
            void* attachment = nullptr;
            void* vtable = nullptr;
            void* linkedFile = nullptr;
            void* handle = nullptr;
            UCHAR fileFlags = 0xFF;
            std::uint32_t rootFlags = 0;
            const auto* file = static_cast<const UCHAR*>(guard.file);
            const auto* cloth = static_cast<const UCHAR*>(object);
            const bool exactRootedReplacement =
                SafeCopy(file + 0x10, &attachment, sizeof(attachment)) &&
                attachment == object &&
                SafeCopy(file + 0x4C, &fileFlags, sizeof(fileFlags)) &&
                fileFlags == guard.fileFlags &&
                SafeCopy(cloth, &vtable, sizeof(vtable)) &&
                vtable == g_editorBase + kApexClothVtableRva &&
                SafeCopy(cloth + 0x58, &linkedFile, sizeof(linkedFile)) &&
                linkedFile == guard.file &&
                SafeCopy(cloth + 0x08, &handle, sizeof(handle)) &&
                handle == guard.handle &&
                SafeCopy(cloth + 0x54, &rootFlags, sizeof(rootFlags)) &&
                (rootFlags & 0x04) != 0;
            if (exactRootedReplacement) {
                ++guard.failClosedSkips;
                guard.rejectionBits |= rejection | 0x100;
                return;
            }
        }
        guard.rejectionBits |= rejection;
        ++guard.forwards;
    }
    // All nonmatching calls retain the editor's original cleanup semantics.
    g_discardNoLock(object);
}

struct BorrowedPostState {
    bool valid = false;
    bool slotReadable = false;
    void* attachment = nullptr;
    void* linkedFile = nullptr;
    void* handle = nullptr;
    UCHAR loadFlags = 0xFF;
    UCHAR fileFlags = 0xFF;
    UCHAR resourceLoadByte = 0xFF;
    std::uint32_t handleFlags = 0;
    std::uint32_t rootFlags = 0;
};

BorrowedPostState ObserveBorrowedPostState(
    void* filePointer, void* expectedResource, void* expectedHandle,
    UCHAR expectedFileFlags) {
    BorrowedPostState state;
    const auto* file = static_cast<const UCHAR*>(filePointer);
    state.slotReadable = SafeCopy(file + 0x10, &state.attachment,
                                  sizeof(state.attachment));
    if (!state.slotReadable || state.attachment != expectedResource ||
        !AlignedUserPointer(state.attachment)) return state;
    const auto* cloth = static_cast<const UCHAR*>(state.attachment);
    void* vtable = nullptr;
    state.valid =
        SafeCopy(file + 0x34, &state.loadFlags,
                 sizeof(state.loadFlags)) && state.loadFlags == 0 &&
        SafeCopy(file + 0x4C, &state.fileFlags,
                 sizeof(state.fileFlags)) &&
        state.fileFlags == expectedFileFlags &&
        SafeCopy(cloth, &vtable, sizeof(vtable)) &&
        vtable == g_editorBase + kApexClothVtableRva &&
        SafeCopy(cloth + 0x58, &state.linkedFile,
                 sizeof(state.linkedFile)) &&
        state.linkedFile == filePointer &&
        SafeCopy(cloth + 0x60, &state.resourceLoadByte,
                 sizeof(state.resourceLoadByte)) &&
        state.resourceLoadByte == 0 &&
        SafeCopy(cloth + 0x08, &state.handle,
                 sizeof(state.handle)) &&
        state.handle == expectedHandle &&
        AlignedUserPointer(state.handle) &&
        SafeCopy(static_cast<const UCHAR*>(state.handle) + 0x04,
                 &state.handleFlags, sizeof(state.handleFlags)) &&
        (state.handleFlags & 0x04) == 0 &&
        SafeCopy(cloth + 0x54, &state.rootFlags,
                 sizeof(state.rootFlags)) &&
        (state.rootFlags & 0x04) != 0;
    return state;
}

QuarantineLookup ProbeQuarantineMap(void* file, void* expectedAttachment,
                                     bool requireState = true) {
    QuarantineLookup result;
    if (!file || !g_editorBase || (requireState && !expectedAttachment))
        return result;
    UCHAR* const map = g_editorBase + kQuarantineMapRva;
    auto* const mapLock = reinterpret_cast<CRITICAL_SECTION*>(map + 0x30);
    // A failed try keeps the guarded abort; this lookup never waits on
    // editor synchronization and never calls an editor resource method.
    if (!TryEnterCriticalSection(mapLock)) {
        result.status = QuarantineLookupStatus::MapBusy;
        return result;
    }
    do {
        result.beforeReadable = ReadObservedFileState(
            file, result.flagsBefore, result.attachmentBefore);
        if (!result.beforeReadable) {
            result.status = QuarantineLookupStatus::FileStateUnreadable;
            break;
        }
        if (requireState && ((result.flagsBefore & 0x02) == 0 ||
            result.attachmentBefore != expectedAttachment)) {
            result.status = QuarantineLookupStatus::FileStateChanged;
            break;
        }
        void* buckets = nullptr;
        if (!SafeCopy(map, &result.bucketCount, sizeof(result.bucketCount)) ||
            !SafeCopy(map + 0x04, &result.entryCount,
                      sizeof(result.entryCount)) ||
            !SafeCopy(map + 0x20, &buckets, sizeof(buckets)) ||
            result.bucketCount == 0 || result.bucketCount > (1u << 20) ||
            result.entryCount > (1u << 20) ||
            !AlignedUserPointer(buckets)) {
            result.status = QuarantineLookupStatus::InvalidHeader;
            break;
        }
        result.hash = QuarantineHash(file);
        result.bucket = result.hash % result.bucketCount;
        const auto base = reinterpret_cast<std::uintptr_t>(buckets);
        const auto offset = static_cast<std::uintptr_t>(result.bucket) *
            sizeof(void*);
        if (base > UINTPTR_MAX - offset - sizeof(void*)) {
            result.status = QuarantineLookupStatus::InvalidBucket;
            break;
        }
        void* node = nullptr;
        if (!SafeCopy(reinterpret_cast<const void*>(base + offset),
                      &node, sizeof(node))) {
            result.status = QuarantineLookupStatus::InvalidBucket;
            break;
        }
        constexpr std::size_t kHardNodeLimit = 256;
        std::array<void*, kHardNodeLimit> visited = {};
        while (node) {
            if (result.traversed >= result.entryCount) {
                result.status = QuarantineLookupStatus::InvalidNode;
                break;
            }
            if (result.traversed >= kHardNodeLimit) {
                result.status = QuarantineLookupStatus::TraversalLimit;
                break;
            }
            if (!AlignedUserPointer(node)) {
                result.status = QuarantineLookupStatus::InvalidNode;
                break;
            }
            bool cycle = false;
            for (std::uint32_t index = 0; index < result.traversed; ++index) {
                if (visited[index] == node) { cycle = true; break; }
            }
            if (cycle) {
                result.status = QuarantineLookupStatus::InvalidNode;
                break;
            }
            visited[result.traversed] = node;
            QuarantineNodeView view = {};
            if (!SafeCopy(node, &view, sizeof(view))) {
                result.status = QuarantineLookupStatus::InvalidNode;
                break;
            }
            ++result.traversed;
            if (view.key == file) {
                if (view.hash == result.hash) {
                    result.status = QuarantineLookupStatus::Member;
                    break;
                }
                result.keyHashMismatch = true;
            }
            node = view.next;
        }
        if (result.status == QuarantineLookupStatus::NotRun) {
            result.status = result.keyHashMismatch
                ? QuarantineLookupStatus::KeyHashMismatch
                : QuarantineLookupStatus::Absent;
        }
    } while (false);
    result.afterReadable = ReadObservedFileState(
        file, result.flagsAfter, result.attachmentAfter);
    LeaveCriticalSection(mapLock);
    return result;
}

const wchar_t* QuarantineLookupName(QuarantineLookupStatus status) {
    switch (status) {
    case QuarantineLookupStatus::NotRun: return L"not-run";
    case QuarantineLookupStatus::MapBusy: return L"map-busy";
    case QuarantineLookupStatus::FileStateUnreadable: return L"file-state-unreadable";
    case QuarantineLookupStatus::FileStateChanged: return L"file-state-changed";
    case QuarantineLookupStatus::InvalidHeader: return L"invalid-header";
    case QuarantineLookupStatus::InvalidBucket: return L"invalid-bucket";
    case QuarantineLookupStatus::InvalidNode: return L"invalid-node";
    case QuarantineLookupStatus::TraversalLimit: return L"traversal-limit";
    case QuarantineLookupStatus::KeyHashMismatch: return L"key-hash-mismatch";
    case QuarantineLookupStatus::Member: return L"member";
    case QuarantineLookupStatus::Absent: return L"absent";
    }
    return L"unknown";
}

struct FileLockObservation {
    bool readable = false;
    std::uint32_t ownerThread = 0;
    std::uint32_t outstanding = 0;
    std::uint32_t recursion = 0;
    UCHAR wakeByte = 0;
    bool idle() const {
        return readable && ownerThread == 0 && outstanding == 0 &&
            recursion == 0;
    }
};

FileLockObservation ObserveFileLock(void* file) {
    FileLockObservation result;
    if (!file) return result;
    const auto* bytes = static_cast<const UCHAR*>(file);
    result.readable =
        SafeCopy(bytes + 0x3C, &result.ownerThread,
                 sizeof(result.ownerThread)) &&
        SafeCopy(bytes + 0x40, &result.outstanding,
                 sizeof(result.outstanding)) &&
        SafeCopy(bytes + 0x44, &result.recursion,
                 sizeof(result.recursion)) &&
        SafeCopy(bytes + 0x48, &result.wakeByte,
                 sizeof(result.wakeByte));
    return result;
}

struct BusyHandoffPostState {
    bool valid = false;
    bool clean = false;
    bool busy = false;
    bool mapStable = false;
    bool lockIdle = false;
    bool slotReadable = false;
    void* attachment = nullptr;
    void* linkedFile = nullptr;
    void* handle = nullptr;
    void* apb = nullptr;
    unsigned int apbCount = 0;
    bool apbMagicReadable = false;
    std::array<UCHAR, 4> apbMagic = {};
    UCHAR fileFlags = 0xFF;
    UCHAR loadFlags = 0xFF;
    UCHAR resourceByte = 0xFF;
    std::uint32_t handleFlags = 0;
    std::uint32_t rootFlags = 0;
    QuarantineLookup map;
};

BusyHandoffPostState ObserveBusyHandoffPostState(
    void* filePointer, void* expectedResource, void* expectedHandle,
    UCHAR expectedFileFlags) {
    BusyHandoffPostState state;
    const auto* file = static_cast<const UCHAR*>(filePointer);
    state.slotReadable = SafeCopy(file + 0x10, &state.attachment,
                                  sizeof(state.attachment));
    if (!state.slotReadable || state.attachment != expectedResource ||
        !AlignedUserPointer(state.attachment)) return state;
    const auto* cloth = static_cast<const UCHAR*>(state.attachment);
    void* vtable = nullptr;
    const bool fieldsReady =
        SafeCopy(file + 0x34, &state.loadFlags, sizeof(state.loadFlags)) &&
        SafeCopy(file + 0x4C, &state.fileFlags, sizeof(state.fileFlags)) &&
        state.fileFlags == expectedFileFlags &&
        SafeCopy(cloth, &vtable, sizeof(vtable)) &&
        vtable == g_editorBase + kApexClothVtableRva &&
        SafeCopy(cloth + 0x58, &state.linkedFile,
                 sizeof(state.linkedFile)) &&
        state.linkedFile == filePointer &&
        SafeCopy(cloth + 0x60, &state.resourceByte,
                 sizeof(state.resourceByte)) &&
        state.resourceByte == 0 &&
        SafeCopy(cloth + 0x08, &state.handle, sizeof(state.handle)) &&
        state.handle == expectedHandle &&
        AlignedUserPointer(state.handle) &&
        SafeCopy(static_cast<const UCHAR*>(state.handle) + 0x04,
                 &state.handleFlags, sizeof(state.handleFlags)) &&
        SafeCopy(cloth + 0x54, &state.rootFlags,
                 sizeof(state.rootFlags)) &&
        (state.rootFlags & 0x04) != 0 &&
        SafeCopy(cloth + 0x154, &state.apb, sizeof(state.apb)) &&
        SafeCopy(cloth + 0x15C, &state.apbCount,
                 sizeof(state.apbCount));
    if (!fieldsReady ||
        (state.loadFlags != 0 && state.loadFlags != 0x02)) return state;
    if (state.apb && state.apbCount >= state.apbMagic.size())
        state.apbMagicReadable = SafeCopy(
            state.apb, state.apbMagic.data(), state.apbMagic.size());
    state.map = ProbeQuarantineMap(
        filePointer, state.loadFlags == 0x02 ? expectedResource : nullptr,
        state.loadFlags == 0x02);
    state.mapStable = state.map.beforeReadable &&
        state.map.afterReadable &&
        state.map.flagsBefore == state.loadFlags &&
        state.map.flagsAfter == state.loadFlags &&
        state.map.attachmentBefore == expectedResource &&
        state.map.attachmentAfter == expectedResource;
    const FileLockObservation lock = ObserveFileLock(filePointer);
    state.lockIdle = lock.idle();
    state.clean = state.mapStable && state.loadFlags == 0 &&
        (state.handleFlags & 0x04) == 0 &&
        state.map.status == QuarantineLookupStatus::Absent;
    state.busy = state.mapStable && state.loadFlags == 0x02 &&
        (state.handleFlags & 0x04) != 0 &&
        state.map.status == QuarantineLookupStatus::Member;
    state.valid = state.lockIdle && (state.clean || state.busy);
    return state;
}

std::string FileKey(const char* absolutePath) {
    std::string result(absolutePath);
    for (char& c : result) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return result;
}

bool ClaimFile(const std::string& key, const wchar_t*& reason) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    const auto found = g_fileStates.find(key);
    if (found != g_fileStates.end()) {
        reason = found->second == FileState::Invalid
            ? L"file was left invalid by an earlier Reload; restart editor"
            : L"file Reload already in progress";
        return false;
    }
    g_fileStates.emplace(key, FileState::InProgress);
    return true;
}

bool HasFileState(const std::string& key, const wchar_t*& reason) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    const auto found = g_fileStates.find(key);
    if (found == g_fileStates.end()) return false;
    reason = found->second == FileState::Invalid
        ? L"file invalid after previous Reload; ProcessFile blocked until editor restart"
        : L"file Reload still in progress; ProcessFile blocked";
    return true;
}

bool AnyFileState() {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    return !g_fileStates.empty();
}

bool HasQuarantineAttempt(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    return g_quarantineAttempts.find(key) != g_quarantineAttempts.end();
}

bool ClaimQuarantineAttempt(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    if (g_cleanAttachmentAttempts.find(key) != g_cleanAttachmentAttempts.end())
        return false;
    return g_quarantineAttempts.emplace(key).second;
}

bool HasCleanAttachmentAttempt(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    return g_cleanAttachmentAttempts.find(key) !=
        g_cleanAttachmentAttempts.end();
}

bool ClaimCleanAttachmentAttempt(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    if (g_quarantineAttempts.find(key) != g_quarantineAttempts.end())
        return false;
    return g_cleanAttachmentAttempts.emplace(key).second;
}

bool CurrentActiveFileKey(const char* depotPath, std::string& key) {
    char safeDepot[768] = {};
    strcpy_s(safeDepot, depotPath);
    const wchar_t* why = nullptr;
    if (!ValidateDepotPath(safeDepot, why)) return false;
    DWORD mainThread = 0;
    if (!SafeCopy(g_editorBase + kMainThreadIdRva, &mainThread,
                  sizeof(mainThread)) ||
        !mainThread || mainThread != GetCurrentThreadId()) return false;
    void* context = nullptr;
    if (!SafeCopy(g_editorBase + kProjectContextGlobalRva,
                  &context, sizeof(context)) || !context) return false;
    char projectFile[768] = {};
    char workspace[768] = {};
    if (!ReadBoundedTString12(static_cast<const UCHAR*>(context) + 0xE0,
                              projectFile) ||
        !ValidateProjectFile(projectFile, workspace, why) ||
        !ProjectFileExists(projectFile)) return false;
    const std::string expected = std::string(workspace) + safeDepot;
    if (expected.size() >= sizeof(workspace)) return false;
    key = FileKey(expected.c_str());
    return true;
}

void FinishFile(const std::string& key, bool invalid) {
    std::lock_guard<std::mutex> lock(g_fileStatesMutex);
    if (invalid) g_fileStates[key] = FileState::Invalid;
    else g_fileStates.erase(key);
}

bool SamePhysicalIdentity(const GateSnapshot& before,
                          const GateSnapshot& after) {
    return after.eligible && after.context == before.context &&
        after.depot == before.depot && after.file == before.file &&
        after.parent == before.parent &&
        after.physicalRoot == before.physicalRoot &&
        after.fileFlags == before.fileFlags &&
        after.loadFlags == before.loadFlags &&
        _stricmp(after.projectFile, before.projectFile) == 0 &&
        _stricmp(after.workspaceRoot, before.workspaceRoot) == 0 &&
        _stricmp(after.depotPath, before.depotPath) == 0 &&
        _stricmp(after.absolutePath, before.absolutePath) == 0;
}

// Only the guarded same-session path may compare a post-Reload busy file.
// EvaluateGate has already validated the active project and physical path
// before it rejects loadFlags=02; this comparison explicitly rechecks each
// available identity field without treating the busy state as clean.
bool SamePhysicalIdentityForQuarantine(const GateSnapshot& before,
                                       const GateSnapshot& after,
                                       bool allowInitialBusy = false) {
    return before.eligible &&
        before.loadFlags == (allowInitialBusy ? 0x02 : 0) &&
        after.threadId == before.threadId &&
        after.mainThreadId == before.mainThreadId &&
        after.contextReadable && after.projectPathReadable &&
        after.projectFileExists && after.depotReadable &&
        after.physicalRootMatched && after.absolutePathMatched &&
        after.fileVtable == g_editorBase + kDiskFileVtableRva &&
        after.context == before.context &&
        after.depot == before.depot && after.file == before.file &&
        after.parent == before.parent &&
        after.physicalRoot == before.physicalRoot &&
        after.fileFlags == before.fileFlags && after.loadFlags == 0x02 &&
        _stricmp(after.projectFile, before.projectFile) == 0 &&
        _stricmp(after.workspaceRoot, before.workspaceRoot) == 0 &&
        _stricmp(after.depotPath, before.depotPath) == 0 &&
        _stricmp(after.absolutePath, before.absolutePath) == 0;
}

// Reload can replace an initial-busy (02) cloth with a clean (00) attached
// cloth. This is a distinct identity gate; the 02->02 and clean->clean gates
// retain their original requirements.
bool SamePhysicalIdentityForInitialBusyClean(const GateSnapshot& before,
                                              const GateSnapshot& after) {
    return before.eligible && before.fileFlags == 0x04 &&
        before.loadFlags == 0x02 && after.eligible &&
        after.fileFlags == 0x04 && after.loadFlags == 0 &&
        after.threadId == before.threadId &&
        after.mainThreadId == before.mainThreadId &&
        after.contextReadable && after.projectPathReadable &&
        after.projectFileExists && after.depotReadable &&
        after.physicalRootMatched && after.absolutePathMatched &&
        after.fileVtable == g_editorBase + kDiskFileVtableRva &&
        after.context == before.context &&
        after.depot == before.depot && after.file == before.file &&
        after.parent == before.parent &&
        after.physicalRoot == before.physicalRoot &&
        _stricmp(after.projectFile, before.projectFile) == 0 &&
        _stricmp(after.workspaceRoot, before.workspaceRoot) == 0 &&
        _stricmp(after.depotPath, before.depotPath) == 0 &&
        _stricmp(after.absolutePath, before.absolutePath) == 0;
}

enum class PostReloadAttachment { Null, ValidReplacement, Invalid };

PostReloadAttachment CheckPostReloadAttachment(const GateSnapshot& snapshot) {
    void* resource = nullptr;
    const auto* file = static_cast<const UCHAR*>(snapshot.file);
    if (!SafeCopy(file + 0x10, &resource, sizeof(resource)))
        return PostReloadAttachment::Invalid;
    if (!resource) return PostReloadAttachment::Null;
    const auto* cloth = static_cast<const UCHAR*>(resource);
    void* vtable = nullptr;
    void* linkedFile = nullptr;
    void* apb = nullptr;
    unsigned int count = 0;
    UCHAR magic[4] = {};
    if (!SafeCopy(cloth, &vtable, sizeof(vtable)) ||
        vtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &linkedFile, sizeof(linkedFile)) ||
        linkedFile != snapshot.file ||
        !SafeCopy(cloth + 0x154, &apb, sizeof(apb)) ||
        !SafeCopy(cloth + 0x15C, &count, sizeof(count)) ||
        !apb || count < 4 || count > 64u * 1024u * 1024u ||
        !SafeCopy(apb, magic, sizeof(magic)) ||
        std::memcmp(magic, "\x5A\x5B\x5C\x5D", 4) != 0)
        return PostReloadAttachment::Invalid;
    return PostReloadAttachment::ValidReplacement;
}

struct QuarantineGateResult {
    bool allowed = false;
    const wchar_t* reason = L"quarantine gate not evaluated";
    QuarantineLookup map;
    bool sameObserved = false;
    void* file = nullptr;
    void* resource = nullptr;
    void* handle = nullptr;
    void* apb = nullptr;
    unsigned int apbCount = 0;
};

// This gate never edits editor state. Every expensive source
// and APB check precedes the final map snapshot. The map lookup samples the
// file without its custom lock, so this remains an experiment, not a public
// race-free fix. Native BeginLoad owns the actual transition when allowed.
QuarantineGateResult EvaluateQuarantineFallthrough(
    const GateSnapshot& before, const GateSnapshot& after,
    SourceGuard& source, bool reloadReturn,
    bool allowInitialBusy = false) {
    QuarantineGateResult result;
    result.file = after.file;
    if (!reloadReturn ||
        !SamePhysicalIdentityForQuarantine(before, after,
                                           allowInitialBusy)) {
        result.reason = L"physical identity or exact loadFlags=02 mismatch";
        return result;
    }
    if (!SourceStillIdentical(source)) {
        result.reason = L"held source changed after Reload";
        return result;
    }
    const auto* file = static_cast<const UCHAR*>(after.file);
    if (!SafeCopy(file + 0x10, &result.resource,
                  sizeof(result.resource)) || !result.resource) {
        result.reason = L"quarantined attachment absent or unreadable";
        return result;
    }
    const auto* cloth = static_cast<const UCHAR*>(result.resource);
    void* resourceVtable = nullptr;
    void* linkedFile = nullptr;
    void* apb = nullptr;
    unsigned int apbCount = 0;
    UCHAR loadByte = 0xFF;
    UCHAR magic[4] = {};
    std::uint32_t handleFlags = 0;
    if (!SafeCopy(cloth, &resourceVtable, sizeof(resourceVtable)) ||
        resourceVtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &linkedFile, sizeof(linkedFile)) ||
        linkedFile != after.file ||
        !SafeCopy(cloth + 0x60, &loadByte, sizeof(loadByte)) ||
        loadByte != 0 ||
        !SafeCopy(cloth + 0x08, &result.handle,
                  sizeof(result.handle)) ||
        !AlignedUserPointer(result.handle) ||
        !SafeCopy(static_cast<const UCHAR*>(result.handle) + 0x04,
                  &handleFlags, sizeof(handleFlags)) ||
        (handleFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x154, &apb, sizeof(apb)) ||
        !SafeCopy(cloth + 0x15C, &apbCount, sizeof(apbCount)) ||
        !apb || apbCount != before.sourceApb.apbSize ||
        !SafeCopy(apb, magic, sizeof(magic)) ||
        std::memcmp(magic, "\x5A\x5B\x5C\x5D", 4) != 0) {
        result.reason = L"attached cloth, handle, or APB precondition failed";
        return result;
    }
    if (CompareHeldSourceApb(before, source, apb, apbCount).status !=
        ApbEqualityStatus::Equal) {
        result.reason = L"attached APB differs from held saved source";
        return result;
    }

    UCHAR finalFileFlags = 0;
    UCHAR finalLoadFlags = 0;
    UCHAR finalLoadByte = 0xFF;
    void* finalAttached = nullptr;
    void* finalVtable = nullptr;
    void* finalLinkedFile = nullptr;
    void* finalHandle = nullptr;
    void* finalApb = nullptr;
    unsigned int finalApbCount = 0;
    std::uint32_t finalHandleFlags = 0;
    if (!SafeCopy(file + 0x4C, &finalFileFlags,
                  sizeof(finalFileFlags)) ||
        finalFileFlags != before.fileFlags ||
        (finalFileFlags & 0x02) != 0 ||
        !SafeCopy(file + 0x34, &finalLoadFlags,
                  sizeof(finalLoadFlags)) ||
        finalLoadFlags != 0x02 ||
        !SafeCopy(file + 0x10, &finalAttached,
                  sizeof(finalAttached)) ||
        finalAttached != result.resource ||
        !SafeCopy(cloth, &finalVtable, sizeof(finalVtable)) ||
        finalVtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &finalLinkedFile,
                  sizeof(finalLinkedFile)) ||
        finalLinkedFile != after.file ||
        !SafeCopy(cloth + 0x60, &finalLoadByte,
                  sizeof(finalLoadByte)) ||
        finalLoadByte != 0 ||
        !SafeCopy(cloth + 0x08, &finalHandle,
                  sizeof(finalHandle)) ||
        finalHandle != result.handle ||
        !SafeCopy(static_cast<const UCHAR*>(finalHandle) + 0x04,
                  &finalHandleFlags, sizeof(finalHandleFlags)) ||
        (finalHandleFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x154, &finalApb,
                  sizeof(finalApb)) ||
        finalApb != apb ||
        !SafeCopy(cloth + 0x15C, &finalApbCount,
                  sizeof(finalApbCount)) ||
        finalApbCount != apbCount ||
        !SourceStillIdentical(source)) {
        result.reason = L"file, attachment, handle, or saved source changed before map lookup";
        return result;
    }

    result.map = ProbeQuarantineMap(after.file, result.resource);
    result.sameObserved = result.map.beforeReadable &&
        result.map.afterReadable &&
        result.map.flagsBefore == 0x02 &&
        result.map.flagsAfter == 0x02 &&
        result.map.attachmentBefore == result.resource &&
        result.map.attachmentAfter == result.resource;
    if (result.map.status != QuarantineLookupStatus::Member ||
        !result.sameObserved) {
        result.reason = L"quarantine-map member or file-state snapshot not confirmed";
        return result;
    }
    result.apb = apb;
    result.apbCount = apbCount;
    result.allowed = true;
    result.reason = L"exact quarantine state confirmed for native fallthrough";
    return result;
}

QuarantineGateResult EvaluateInitialBusyReplacement(
    const GateSnapshot& before, const GateSnapshot& after,
    SourceGuard& source, bool reloadReturn) {
    QuarantineGateResult result = EvaluateQuarantineFallthrough(
        before, after, source, reloadReturn, true);
    if (!result.allowed) return result;
    result.allowed = false;
    if (result.resource == before.resource) {
        result.reason = L"Reload did not replace the initial empty cloth";
        return result;
    }
    std::uint32_t rootFlags = 0;
    const auto* cloth = static_cast<const UCHAR*>(result.resource);
    if (!SafeCopy(cloth + 0x54, &rootFlags, sizeof(rootFlags)) ||
        (rootFlags & 0x04) == 0) {
        result.reason = L"replacement cloth is not confirmed rooted";
        return result;
    }
    const FileLockObservation lock = ObserveFileLock(result.file);
    if (!lock.idle()) {
        result.reason = L"replacement file lock is not observed idle";
        return result;
    }
    // Final exact-pointer and handle checks after the full APB comparison.
    // The file lock is observational; native BeginLoad owns its transition.
    UCHAR fileFlags = 0;
    UCHAR loadFlags = 0;
    UCHAR resourceByte = 0xFF;
    void* attachment = nullptr;
    void* vtable = nullptr;
    void* linkedFile = nullptr;
    void* handle = nullptr;
    void* apb = nullptr;
    unsigned int apbCount = 0;
    std::uint32_t handleFlags = 0;
    std::uint32_t finalRootFlags = 0;
    if (!SafeCopy(static_cast<const UCHAR*>(result.file) + 0x4C,
                  &fileFlags, sizeof(fileFlags)) ||
        fileFlags != before.fileFlags ||
        !SafeCopy(static_cast<const UCHAR*>(result.file) + 0x34,
                  &loadFlags, sizeof(loadFlags)) ||
        loadFlags != 0x02 ||
        !SafeCopy(static_cast<const UCHAR*>(result.file) + 0x10,
                  &attachment, sizeof(attachment)) ||
        attachment != result.resource ||
        !SafeCopy(cloth, &vtable, sizeof(vtable)) ||
        vtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &linkedFile, sizeof(linkedFile)) ||
        linkedFile != result.file ||
        !SafeCopy(cloth + 0x60, &resourceByte, sizeof(resourceByte)) ||
        resourceByte != 0 ||
        !SafeCopy(cloth + 0x08, &handle, sizeof(handle)) ||
        handle != result.handle ||
        !SafeCopy(static_cast<const UCHAR*>(handle) + 0x04,
                  &handleFlags, sizeof(handleFlags)) ||
        (handleFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x54, &finalRootFlags, sizeof(finalRootFlags)) ||
        (finalRootFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x154, &apb, sizeof(apb)) ||
        apb != result.apb ||
        !SafeCopy(cloth + 0x15C, &apbCount, sizeof(apbCount)) ||
        apbCount != result.apbCount ||
        !SourceStillIdentical(source)) {
        result.reason = L"replacement file, handle, root, APB, or source changed";
        return result;
    }
    const QuarantineLookup finalMap = ProbeQuarantineMap(
        result.file, result.resource);
    const bool finalMapStable = finalMap.beforeReadable &&
        finalMap.afterReadable && finalMap.flagsBefore == 0x02 &&
        finalMap.flagsAfter == 0x02 &&
        finalMap.attachmentBefore == result.resource &&
        finalMap.attachmentAfter == result.resource;
    result.map = finalMap;
    result.sameObserved = finalMapStable;
    if (finalMap.status != QuarantineLookupStatus::Member ||
        !finalMapStable) {
        result.reason = L"final replacement quarantine-map member not confirmed";
        return result;
    }
    result.allowed = true;
    result.reason = L"exact populated rooted replacement ready for native handoff";
    return result;
}

struct CleanAttachmentGateResult {
    bool allowed = false;
    const wchar_t* reason = L"clean attachment gate not evaluated";
    void* file = nullptr;
    void* resource = nullptr;
    void* handle = nullptr;
    unsigned int apbCount = 0;
    std::uint32_t handleFlags = 0;
    std::uint32_t rootFlags = 0;
    QuarantineLookup map;
    bool sameObserved = false;
};

// Guard for Reload's clean load-state, non-null attachment outcome.
// The original ProcessFile should then use the editor's own Load/BeginLoad path.
// No editor flags, handles, map entries, or resource bytes are written.
CleanAttachmentGateResult EvaluateCleanAttachmentFallthrough(
    const GateSnapshot& before, const GateSnapshot& after,
    SourceGuard& source, bool reloadReturn,
    bool allowInitialBusy = false) {
    CleanAttachmentGateResult result;
    result.file = after.file;
    const bool sameIdentity = allowInitialBusy
        ? SamePhysicalIdentityForInitialBusyClean(before, after)
        : SamePhysicalIdentity(before, after) &&
            before.loadFlags == 0 && after.loadFlags == 0;
    if (!reloadReturn || !sameIdentity) {
        result.reason = L"physical identity or exact clean load state mismatch";
        return result;
    }
    if (!SourceStillIdentical(source)) {
        result.reason = L"held source changed after Reload";
        return result;
    }
    const auto* file = static_cast<const UCHAR*>(after.file);
    if (!SafeCopy(file + 0x10, &result.resource,
                  sizeof(result.resource)) || !result.resource) {
        result.reason = L"post-Reload attachment absent or unreadable";
        return result;
    }
    if (allowInitialBusy && result.resource == before.resource) {
        result.reason = L"post-Reload clean attachment reused initial-busy resource";
        return result;
    }
    const auto* cloth = static_cast<const UCHAR*>(result.resource);
    void* resourceVtable = nullptr;
    void* linkedFile = nullptr;
    void* apb = nullptr;
    UCHAR loadByte = 0xFF;
    UCHAR magic[4] = {};
    if (!SafeCopy(cloth, &resourceVtable, sizeof(resourceVtable)) ||
        resourceVtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &linkedFile, sizeof(linkedFile)) ||
        linkedFile != after.file ||
        !SafeCopy(cloth + 0x60, &loadByte, sizeof(loadByte)) ||
        loadByte != 0 ||
        !SafeCopy(cloth + 0x08, &result.handle,
                  sizeof(result.handle)) ||
        !AlignedUserPointer(result.handle) ||
        !SafeCopy(static_cast<const UCHAR*>(result.handle) + 0x04,
                  &result.handleFlags, sizeof(result.handleFlags)) ||
        (result.handleFlags & 0x04) != 0 ||
        !SafeCopy(cloth + 0x54, &result.rootFlags,
                  sizeof(result.rootFlags)) ||
        (result.rootFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x154, &apb, sizeof(apb)) ||
        !SafeCopy(cloth + 0x15C, &result.apbCount,
                  sizeof(result.apbCount)) ||
        !apb || result.apbCount != before.sourceApb.apbSize ||
        !SafeCopy(apb, magic, sizeof(magic)) ||
        std::memcmp(magic, "\x5A\x5B\x5C\x5D", 4) != 0) {
        result.reason = L"attached cloth, handle, rooted state, or APB precondition failed";
        return result;
    }
    if (CompareHeldSourceApb(before, source, apb,
                             result.apbCount).status !=
        ApbEqualityStatus::Equal) {
        result.reason = L"attached APB differs from held saved source";
        return result;
    }

    UCHAR finalFileFlags = 0;
    UCHAR finalLoadFlags = 0xFF;
    UCHAR finalLoadByte = 0xFF;
    void* finalAttached = nullptr;
    void* finalVtable = nullptr;
    void* finalLinkedFile = nullptr;
    void* finalHandle = nullptr;
    void* finalApb = nullptr;
    unsigned int finalApbCount = 0;
    std::uint32_t finalHandleFlags = 0;
    std::uint32_t finalRootFlags = 0;
    if (!SafeCopy(file + 0x4C, &finalFileFlags,
                  sizeof(finalFileFlags)) ||
        finalFileFlags != before.fileFlags ||
        (finalFileFlags & 0x02) != 0 ||
        !SafeCopy(file + 0x34, &finalLoadFlags,
                  sizeof(finalLoadFlags)) ||
        finalLoadFlags != 0 ||
        !SafeCopy(file + 0x10, &finalAttached,
                  sizeof(finalAttached)) ||
        finalAttached != result.resource ||
        !SafeCopy(cloth, &finalVtable, sizeof(finalVtable)) ||
        finalVtable != g_editorBase + kApexClothVtableRva ||
        !SafeCopy(cloth + 0x58, &finalLinkedFile,
                  sizeof(finalLinkedFile)) ||
        finalLinkedFile != after.file ||
        !SafeCopy(cloth + 0x60, &finalLoadByte,
                  sizeof(finalLoadByte)) ||
        finalLoadByte != 0 ||
        !SafeCopy(cloth + 0x08, &finalHandle,
                  sizeof(finalHandle)) ||
        finalHandle != result.handle ||
        !SafeCopy(static_cast<const UCHAR*>(finalHandle) + 0x04,
                  &finalHandleFlags, sizeof(finalHandleFlags)) ||
        (finalHandleFlags & 0x04) != 0 ||
        !SafeCopy(cloth + 0x54, &finalRootFlags,
                  sizeof(finalRootFlags)) ||
        (finalRootFlags & 0x04) == 0 ||
        !SafeCopy(cloth + 0x154, &finalApb,
                  sizeof(finalApb)) ||
        finalApb != apb ||
        !SafeCopy(cloth + 0x15C, &finalApbCount,
                  sizeof(finalApbCount)) ||
        finalApbCount != result.apbCount ||
        !SourceStillIdentical(source)) {
        result.reason = L"file, attachment, handle, rooted state, or saved source changed before map lookup";
        return result;
    }

    result.map = ProbeQuarantineMap(after.file, nullptr, false);
    result.sameObserved = result.map.beforeReadable &&
        result.map.afterReadable &&
        result.map.flagsBefore == 0 &&
        result.map.flagsAfter == 0 &&
        result.map.attachmentBefore == result.resource &&
        result.map.attachmentAfter == result.resource;
    if (result.map.status != QuarantineLookupStatus::Absent ||
        !result.sameObserved) {
        result.reason = L"clean attachment map or file-state snapshot not confirmed";
        return result;
    }
    if (allowInitialBusy && !ObserveFileLock(after.file).idle()) {
        result.reason = L"initial-busy clean attachment file lock not idle";
        return result;
    }
    result.allowed = true;
    result.reason = L"exact rooted clean attachment confirmed for native handoff";
    return result;
}

bool WINAPI TraceProcessFile(void* builder, void* database, void* fileId,
                              void* pathObject) {
    const auto original = reinterpret_cast<ProcessFileFn>(
        InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_processFileTrampoline),
            nullptr, nullptr));
    if (!original) return false;
    if (g_insideTrace) {
        if (g_interventionActive) {
            void* nestedVtable = nullptr;
            if (!SafeCopy(builder, &nestedVtable, sizeof(nestedVtable)))
                return false;
            if (nestedVtable != g_editorBase + kPhysicsBuilderVtableRva)
                return original(builder, database, fileId, pathObject);
            char nestedPath[768] = {};
            if (!ReadBoundedTString12(pathObject, nestedPath)) return false;
            NormalizeSlashes(nestedPath);
            if (_stricmp(nestedPath, g_activeDepotPath) == 0) return false;
        }
        return original(builder, database, fileId, pathObject);
    }
    g_insideTrace = true;
    struct ResetTraceFlag {
        ~ResetTraceFlag() {
            g_interventionActive = false;
            g_activeDepotPath[0] = '\0';
            g_insideTrace = false;
        }
    } reset;

    const LONG call = InterlockedIncrement(&g_traceCalls);
    void* vtable = nullptr;
    char depotPath[768] = {};
    bool isRedcloth = false;
    GateSnapshot snapshot;
    // The ordinary gate returns before source validation when loadFlags=02.
    // Retain the validated source metadata from the initial-busy gate.
    GateSnapshot busySourceSnapshot;
    LONG redclothCall = 0;
    SourceGuard source;
    std::string fileKey;
    bool claimed = false;
    bool reloadCalled = false;
    bool reloadReturn = false;
    bool abortOriginal = false;
    bool quarantineFallthrough = false;
    bool cleanAttachmentFallthrough = false;
    bool busyHandoff = false;
    bool busyCleanHandoff = false;
    bool busyReloadAttempted = false;
    void* cleanAttachmentFile = nullptr;
    void* cleanAttachmentResource = nullptr;
    void* cleanAttachmentHandle = nullptr;
    void* busyFile = nullptr;
    void* busyResource = nullptr;
    void* busyHandle = nullptr;
    PostReloadAttachment attachment = PostReloadAttachment::Invalid;
    const wchar_t* actionReason = L"gate did not pass; baseline ProcessFile";
    try {
        if (SafeCopy(builder, &vtable, sizeof(vtable)) &&
            vtable == g_editorBase + kPhysicsBuilderVtableRva &&
            ReadBoundedTString12(pathObject, depotPath)) {
            NormalizeSlashes(depotPath);
            isRedcloth = HasExtension(depotPath, ".redcloth");
            if (isRedcloth) {
                redclothCall = InterlockedIncrement(&g_redclothCalls);
                // Check sticky state before calling the editor's resolver or
                // GetAbsolutePath, since a prior ambiguous Reload may have
                // left even those operations unsafe on this file.
                if (CurrentActiveFileKey(depotPath, fileKey)) {
                    abortOriginal = HasFileState(fileKey, actionReason);
                } else if (AnyFileState()) {
                    actionReason = L"active file key unreadable while a Reload state exists";
                    abortOriginal = true;
                }
                if (!abortOriginal) snapshot = EvaluateGate(pathObject, depotPath);
                if (!abortOriginal && !snapshot.eligible) {
                    const std::string attemptedKey =
                        snapshot.absolutePath[0]
                            ? FileKey(snapshot.absolutePath)
                            : fileKey;
                    if (!attemptedKey.empty() &&
                        (HasQuarantineAttempt(attemptedKey) ||
                         HasCleanAttachmentAttempt(attemptedKey))) {
                        actionReason = L"native handoff already attempted; non-clean later file state blocked";
                        abortOriginal = true;
                    }
                }
                if (!abortOriginal && !snapshot.eligible &&
                    snapshot.file &&
                    snapshot.fileVtable ==
                        g_editorBase + kDiskFileVtableRva &&
                    snapshot.projectFileExists &&
                    snapshot.physicalRootMatched &&
                    snapshot.absolutePathMatched &&
                    snapshot.projectFile[0] &&
                    snapshot.absolutePath[0] &&
                    snapshot.fileFlags == 0x04 &&
                    snapshot.loadFlags == 0x02) {
                    // The normal gate stops on loadFlags=02 before reading the attachment.
                    // Re-run its exact physical and source checks for this active workspace cloth.
                    const GateSnapshot busy = EvaluateGate(
                        pathObject, depotPath, true, true);
                    UCHAR resourceByte = 0xFF;
                    void* handle = nullptr;
                    std::uint32_t handleFlags = 0;
                    std::uint32_t rootFlags = 0;
                    const auto* cloth = static_cast<const UCHAR*>(busy.resource);
                    const bool resourceReady = busy.eligible &&
                        busy.resource &&
                        SafeCopy(cloth + 0x60, &resourceByte,
                                 sizeof(resourceByte)) &&
                        resourceByte == 0 &&
                        SafeCopy(cloth + 0x08, &handle, sizeof(handle)) &&
                        AlignedUserPointer(handle) &&
                        SafeCopy(static_cast<const UCHAR*>(handle) + 0x04,
                                 &handleFlags, sizeof(handleFlags)) &&
                        (handleFlags & 0x04) != 0 &&
                        SafeCopy(cloth + 0x54, &rootFlags,
                                 sizeof(rootFlags)) &&
                        (rootFlags & 0x04) != 0;
                    const QuarantineLookup preMap = resourceReady
                        ? ProbeQuarantineMap(busy.file, busy.resource)
                        : QuarantineLookup{};
                    const bool mapStable = preMap.beforeReadable &&
                        preMap.afterReadable &&
                        preMap.flagsBefore == 0x02 &&
                        preMap.flagsAfter == 0x02 &&
                        preMap.attachmentBefore == busy.resource &&
                        preMap.attachmentAfter == busy.resource;
                    const FileLockObservation preLock =
                        ObserveFileLock(busy.file);
                    const bool sameFile = busy.eligible &&
                        busy.threadId == snapshot.threadId &&
                        busy.mainThreadId == snapshot.mainThreadId &&
                        busy.context == snapshot.context &&
                        busy.depot == snapshot.depot &&
                        busy.file == snapshot.file &&
                        busy.parent == snapshot.parent &&
                        busy.physicalRoot == snapshot.physicalRoot &&
                        busy.fileVtable == snapshot.fileVtable &&
                        busy.fileFlags == snapshot.fileFlags &&
                        busy.loadFlags == snapshot.loadFlags &&
                        _stricmp(busy.projectFile, snapshot.projectFile) == 0 &&
                        _stricmp(busy.workspaceRoot,
                                 snapshot.workspaceRoot) == 0 &&
                        _stricmp(busy.depotPath, snapshot.depotPath) == 0 &&
                        _stricmp(busy.absolutePath,
                                 snapshot.absolutePath) == 0;
                    const bool candidate = sameFile &&
                        busy.fileFlags == 0x04 &&
                        busy.loadFlags == 0x02 &&
                        !busy.apb && busy.apbCount == 0 &&
                        resourceReady && preLock.idle() &&
                        preMap.status == QuarantineLookupStatus::Member &&
                        mapStable;
                    Log(L"BUSY_HANDOFF preflight call=%ld candidate=%u "
                        L"sameFile=%u file=%p resource=%p apb=%p count=%u "
                        L"flags=%02X/%02X handle=%p handleFlags=%08X "
                        L"rootFlags=%08X map=%s mapStable=%u lockIdle=%u "
                        L"sourceValid=%u",
                        call, candidate ? 1u : 0u,
                        sameFile ? 1u : 0u, busy.file,
                        busy.resource, busy.apb, busy.apbCount,
                        busy.fileFlags, busy.loadFlags, handle,
                        handleFlags, rootFlags,
                        QuarantineLookupName(preMap.status),
                        mapStable ? 1u : 0u,
                        preLock.idle() ? 1u : 0u,
                        busy.sourceApb.valid() ? 1u : 0u);
                    if (candidate) {
                        fileKey = FileKey(busy.absolutePath);
                        if (!ClaimFile(fileKey, actionReason)) {
                            abortOriginal = true;
                        } else {
                            claimed = true;
                            if (!OpenSourceGuard(busy, source, actionReason) ||
                                !SourceStillIdentical(source)) {
                                actionReason = L"initial-busy source hold failed";
                                FinishFile(fileKey, false);
                                claimed = false;
                                abortOriginal = true;
                                ReleaseSourceGuard(source);
                            } else {
                                UCHAR finalFileFlags = 0;
                                UCHAR finalLoadFlags = 0;
                                UCHAR finalByte = 0xFF;
                                void* finalAttachment = nullptr;
                                void* finalVtable = nullptr;
                                void* finalLinkedFile = nullptr;
                                void* finalHandle = nullptr;
                                void* finalApb = nullptr;
                                unsigned int finalApbCount = 0;
                                std::uint32_t finalHandleFlags = 0;
                                std::uint32_t finalRootFlags = 0;
                                const auto* file =
                                    static_cast<const UCHAR*>(busy.file);
                                const bool finalFields =
                                    SafeCopy(file + 0x4C, &finalFileFlags,
                                             sizeof(finalFileFlags)) &&
                                    finalFileFlags == 0x04 &&
                                    SafeCopy(file + 0x34, &finalLoadFlags,
                                             sizeof(finalLoadFlags)) &&
                                    finalLoadFlags == 0x02 &&
                                    SafeCopy(file + 0x10, &finalAttachment,
                                             sizeof(finalAttachment)) &&
                                    finalAttachment == busy.resource &&
                                    SafeCopy(cloth, &finalVtable,
                                             sizeof(finalVtable)) &&
                                    finalVtable ==
                                        g_editorBase + kApexClothVtableRva &&
                                    SafeCopy(cloth + 0x58, &finalLinkedFile,
                                             sizeof(finalLinkedFile)) &&
                                    finalLinkedFile == busy.file &&
                                    SafeCopy(cloth + 0x154, &finalApb,
                                             sizeof(finalApb)) &&
                                    !finalApb &&
                                    SafeCopy(cloth + 0x15C, &finalApbCount,
                                             sizeof(finalApbCount)) &&
                                    finalApbCount == 0 &&
                                    SafeCopy(cloth + 0x60, &finalByte,
                                             sizeof(finalByte)) &&
                                    finalByte == 0 &&
                                    SafeCopy(cloth + 0x08, &finalHandle,
                                             sizeof(finalHandle)) &&
                                    finalHandle == handle &&
                                    SafeCopy(static_cast<const UCHAR*>(handle) + 0x04,
                                             &finalHandleFlags,
                                             sizeof(finalHandleFlags)) &&
                                    (finalHandleFlags & 0x04) != 0 &&
                                    SafeCopy(cloth + 0x54, &finalRootFlags,
                                             sizeof(finalRootFlags)) &&
                                    (finalRootFlags & 0x04) != 0 &&
                                    SourceStillIdentical(source);
                                const QuarantineLookup finalMap = finalFields
                                    ? ProbeQuarantineMap(busy.file,
                                                         busy.resource)
                                    : QuarantineLookup{};
                                const bool finalMapStable =
                                    finalMap.beforeReadable &&
                                    finalMap.afterReadable &&
                                    finalMap.flagsBefore == 0x02 &&
                                    finalMap.flagsAfter == 0x02 &&
                                    finalMap.attachmentBefore == busy.resource &&
                                    finalMap.attachmentAfter == busy.resource;
                                const bool ready = finalFields &&
                                    ObserveFileLock(busy.file).idle() &&
                                    finalMap.status ==
                                        QuarantineLookupStatus::Member &&
                                    finalMapStable;
                                Log(L"BUSY_HANDOFF final-pre call=%ld "
                                    L"ready=%u fields=%u file=%p resource=%p "
                                    L"map=%s mapStable=%u sourceSame=%u",
                                    call, ready ? 1u : 0u,
                                    finalFields ? 1u : 0u,
                                    busy.file, busy.resource,
                                    QuarantineLookupName(finalMap.status),
                                    finalMapStable ? 1u : 0u,
                                    SourceStillIdentical(source) ? 1u : 0u);
                                if (!ready) {
                                    actionReason = L"initial-busy final preflight changed";
                                    abortOriginal = true;
                                } else {
                                    busyReloadAttempted = true;
                                    reloadCalled = true;
                                    strcpy_s(g_activeDepotPath, depotPath);
                                    g_interventionActive = true;
                                    const auto reload =
                                        reinterpret_cast<ResourceReloadFn>(
                                            g_editorBase + kResourceReloadRva);
                                    reloadReturn = reload(busy.resource,
                                                          false);
                                    const GateSnapshot after = EvaluateGate(
                                        pathObject, depotPath, false, true);
                                    const QuarantineGateResult gate =
                                        EvaluateInitialBusyReplacement(
                                            busy, after, source,
                                            reloadReturn);
                                    Log(L"BUSY_HANDOFF postreload call=%ld "
                                        L"reloadReturn=%u allowed=%u "
                                        L"reason=%s file=%p old=%p new=%p "
                                        L"handle=%p apb=%p count=%u "
                                        L"flags=%02X/%02X map=%s stable=%u "
                                        L"sourceSame=%u",
                                        call, reloadReturn ? 1u : 0u,
                                        gate.allowed ? 1u : 0u,
                                        gate.reason, after.file,
                                        busy.resource, gate.resource,
                                        gate.handle, gate.apb,
                                        gate.apbCount, after.fileFlags,
                                        after.loadFlags,
                                        QuarantineLookupName(gate.map.status),
                                        gate.sameObserved ? 1u : 0u,
                                        SourceStillIdentical(source) ? 1u : 0u);
                                    if (gate.allowed &&
                                        g_borrowedCallPatched) {
                                        busyHandoff = true;
                                        busySourceSnapshot.sourceApbChecked =
                                            busy.sourceApbChecked;
                                        busySourceSnapshot.sourceApb =
                                            busy.sourceApb;
                                        busyFile = gate.file;
                                        busyResource = gate.resource;
                                        busyHandle = gate.handle;
                                        actionReason = gate.reason;
                                        abortOriginal = false;
                                    } else if (reloadReturn &&
                                               after.loadFlags == 0) {
                                        const CleanAttachmentGateResult cleanGate =
                                            EvaluateCleanAttachmentFallthrough(
                                                busy, after, source,
                                                reloadReturn, true);
                                        const bool lockIdle =
                                            ObserveFileLock(after.file).idle();
                                        Log(L"BUSY_CLEAN_HANDOFF gate call=%ld "
                                            L"reloadReturn=%u allowed=%u "
                                            L"reason=%s file=%p old=%p new=%p "
                                            L"handle=%p flags=%02X/%02X "
                                            L"handleFlags=%08X rootFlags=%08X "
                                            L"apbCount=%u map=%s stable=%u "
                                            L"lockIdle=%u sourceSame=%u",
                                            call, reloadReturn ? 1u : 0u,
                                            cleanGate.allowed ? 1u : 0u,
                                            cleanGate.reason, after.file,
                                            busy.resource, cleanGate.resource,
                                            cleanGate.handle,
                                            after.fileFlags, after.loadFlags,
                                            cleanGate.handleFlags,
                                            cleanGate.rootFlags,
                                            cleanGate.apbCount,
                                            QuarantineLookupName(
                                                cleanGate.map.status),
                                            cleanGate.sameObserved ? 1u : 0u,
                                            lockIdle ? 1u : 0u,
                                            SourceStillIdentical(source)
                                                ? 1u : 0u);
                                        if (cleanGate.allowed &&
                                            g_borrowedCallPatched &&
                                            ClaimCleanAttachmentAttempt(fileKey)) {
                                            busyCleanHandoff = true;
                                            cleanAttachmentFallthrough = true;
                                            busySourceSnapshot.sourceApbChecked =
                                                busy.sourceApbChecked;
                                            busySourceSnapshot.sourceApb =
                                                busy.sourceApb;
                                            cleanAttachmentFile = cleanGate.file;
                                            cleanAttachmentResource =
                                                cleanGate.resource;
                                            cleanAttachmentHandle =
                                                cleanGate.handle;
                                            actionReason = cleanGate.reason;
                                            abortOriginal = false;
                                            Log(L"BUSY_CLEAN_HANDOFF native-start "
                                                L"call=%ld file=%p resource=%p "
                                                L"handle=%p oneShot=1",
                                                call, cleanAttachmentFile,
                                                cleanAttachmentResource,
                                                cleanAttachmentHandle);
                                        } else {
                                            actionReason = !cleanGate.allowed
                                                ? cleanGate.reason
                                                : !g_borrowedCallPatched
                                                    ? L"borrowed cleanup callsite patch unavailable"
                                                    : L"native clean handoff already attempted for this file";
                                            abortOriginal = true;
                                        }
                                    } else {
                                        actionReason = gate.allowed
                                            ? L"borrowed cleanup callsite patch unavailable"
                                            : gate.reason;
                                        abortOriginal = true;
                                    }
                                }
                                if (abortOriginal) {
                                    FinishFile(fileKey, true);
                                    claimed = false;
                                }
                            }
                        }
                    }
                }
                if (snapshot.eligible && !abortOriginal) {
                    fileKey = FileKey(snapshot.absolutePath);
                    if (!ClaimFile(fileKey, actionReason)) {
                        // An earlier ambiguous Reload leaves this file unsafe
                        // for another ProcessFile in this editor process.
                        abortOriginal = true;
                    } else {
                        claimed = true;
                        if (!OpenSourceGuard(snapshot, source, actionReason) ||
                            !SourceStillIdentical(source)) {
                            actionReason = L"source guard failed before Reload; baseline ProcessFile";
                            FinishFile(fileKey, false);
                            claimed = false;
                            ReleaseSourceGuard(source);
                        } else {
                            Log(L"ACTIVE begin call=%ld file=%p resource=%p path=%S "
                                L"sourceSize=%llu sourceAPB=%u",
                                call, snapshot.file, snapshot.resource,
                                snapshot.absolutePath,
                                static_cast<unsigned long long>(snapshot.sourceApb.fileSize),
                                snapshot.sourceApb.apbSize);
                            reloadCalled = true;
                            strcpy_s(g_activeDepotPath, depotPath);
                            g_interventionActive = true;
                            const auto reload = reinterpret_cast<ResourceReloadFn>(
                                g_editorBase + kResourceReloadRva);
                            reloadReturn = reload(snapshot.resource, false);
                            GateSnapshot after = EvaluateGate(pathObject,
                                                              depotPath, false);
                            // Preserve the original short-circuit order.
                            // In particular, do not read the held source again
                            // if Reload or the physical identity check failed.
                            const bool sameAfterIdentity = reloadReturn &&
                                SamePhysicalIdentity(snapshot, after);
                            const bool checkedAfterSource = sameAfterIdentity;
                            const bool sameAfterSource = checkedAfterSource &&
                                SourceStillIdentical(source);
                            if (!reloadReturn ||
                                !sameAfterIdentity || !sameAfterSource) {
                                actionReason = L"Reload result, file identity, flags, or source changed";
                                abortOriginal = true;
                            } else {
                                attachment = CheckPostReloadAttachment(after);
                                if (attachment == PostReloadAttachment::Null) {
                                    actionReason = L"Reload detached resource; original ProcessFile will fresh-load";
                                } else {
                                    actionReason = attachment == PostReloadAttachment::ValidReplacement
                                        ? L"Reload installed a non-null attachment; source equality unproven, ProcessFile blocked"
                                        : L"Reload left an ambiguous attachment; ProcessFile blocked";
                                    abortOriginal = true;
                                }
                            }
                            if (abortOriginal && reloadReturn &&
                                after.loadFlags == 0x02 &&
                                after.file == snapshot.file) {
                                const QuarantineGateResult gate =
                                    EvaluateQuarantineFallthrough(
                                        snapshot, after, source,
                                        reloadReturn);
                                if (gate.allowed) {
                                    if (ClaimQuarantineAttempt(fileKey)) {
                                        Log(L"QUARANTINE native-fallthrough call=%ld file=%p resource=%p handle=%p map=%s sameObserved=%u; original ProcessFile next",
                                            call, gate.file,
                                            gate.resource, gate.handle,
                                            QuarantineLookupName(
                                                gate.map.status),
                                            gate.sameObserved ? 1u : 0u);
                                        quarantineFallthrough = true;
                                        attachment =
                                            PostReloadAttachment::ValidReplacement;
                                        actionReason = gate.reason;
                                        abortOriginal = false;
                                    } else {
                                        actionReason =
                                            L"quarantine intervention already attempted for this file";
                                        Log(L"QUARANTINE rejected call=%ld reason=%s",
                                            call, actionReason);
                                    }
                                } else {
                                    actionReason = gate.reason;
                                    Log(L"QUARANTINE rejected call=%ld reason=%s map=%s sameObserved=%u",
                                        call, actionReason,
                                        QuarantineLookupName(
                                            gate.map.status),
                                        gate.sameObserved ? 1u : 0u);
                                }
                            }
                            // A clean file can still retain a fully loaded
                            // cloth after Reload. This guarded branch checks
                            // the attachment and its saved APB before the
                            // editor's own ProcessFile reuses that handle.
                            if (abortOriginal && reloadReturn &&
                                after.eligible && after.loadFlags == 0 &&
                                after.file == snapshot.file &&
                                attachment ==
                                    PostReloadAttachment::ValidReplacement) {
                                const CleanAttachmentGateResult gate =
                                    EvaluateCleanAttachmentFallthrough(
                                        snapshot, after, source,
                                        reloadReturn);
                                if (gate.allowed && g_borrowedCallPatched) {
                                    if (ClaimCleanAttachmentAttempt(fileKey)) {
                                        Log(L"CLEAN_ATTACHMENT borrowed-root handoff call=%ld file=%p resource=%p handle=%p handleFlags=%08X rootFlags=%08X apbCount=%u map=%s sameObserved=%u; original ProcessFile next",
                                            call, gate.file,
                                            gate.resource, gate.handle,
                                            gate.handleFlags,
                                            gate.rootFlags,
                                            gate.apbCount,
                                            QuarantineLookupName(
                                                gate.map.status),
                                            gate.sameObserved ? 1u : 0u);
                                        cleanAttachmentFile = gate.file;
                                        cleanAttachmentResource = gate.resource;
                                        cleanAttachmentHandle = gate.handle;
                                        cleanAttachmentFallthrough = true;
                                        actionReason = gate.reason;
                                        abortOriginal = false;
                                    } else {
                                        actionReason = L"native handoff already attempted for this file";
                                        Log(L"CLEAN_ATTACHMENT rejected call=%ld reason=%s",
                                            call, actionReason);
                                    }
                                } else {
                                    actionReason = gate.allowed
                                        ? L"borrowed cleanup callsite patch unavailable"
                                        : gate.reason;
                                    Log(L"CLEAN_ATTACHMENT gate call=%ld allowed=0 "
                                        L"reason=%s file=%p resource=%p handle=%p "
                                        L"handleFlags=%08X apbCount=%u map=%s "
                                        L"sameObserved=%u",
                                        call, actionReason, gate.file,
                                        gate.resource, gate.handle,
                                        gate.handleFlags, gate.apbCount,
                                        QuarantineLookupName(gate.map.status),
                                        gate.sameObserved ? 1u : 0u);
                                }
                            }
                            if (abortOriginal) {
                                FinishFile(fileKey, true);
                                claimed = false;
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {
        if (claimed) {
            try { FinishFile(fileKey, reloadCalled); } catch (...) {}
            claimed = false;
        }
        if (!reloadCalled) ReleaseSourceGuard(source);
        bool unresolvedState = false;
        try { unresolvedState = AnyFileState(); } catch (...) { unresolvedState = true; }
        if (reloadCalled || unresolvedState) abortOriginal = true;
        actionReason = abortOriginal
            ? L"exception with possible Reload state; ProcessFile blocked"
            : L"preflight exception; baseline ProcessFile";
        OutputDebugStringW(L"REDkit general active: capture failed.\n");
    }
    bool nativeOriginalResult = false;
    BorrowedCleanupGuard borrowedOutcome{};
    if (!abortOriginal) {
        if (cleanAttachmentFallthrough || busyHandoff) {
            g_borrowedGuard = { true,
                                busyHandoff ? busyFile : cleanAttachmentFile,
                                busyHandoff ? busyResource : cleanAttachmentResource,
                                busyHandoff ? busyHandle : cleanAttachmentHandle,
                                snapshot.fileFlags,
                                GetCurrentThreadId() };
            g_borrowedGuard.failClosedOnRoot = busyHandoff ||
                busyCleanHandoff;
            struct ClearBorrowedGuard {
                ~ClearBorrowedGuard() { g_borrowedGuard = {}; }
            } clearBorrowedGuard;
            nativeOriginalResult = original(builder, database, fileId,
                                            pathObject);
            borrowedOutcome = g_borrowedGuard;
        } else {
            nativeOriginalResult = original(builder, database, fileId,
                                            pathObject);
        }
    }
    BorrowedPostState borrowedPost;
    if (cleanAttachmentFallthrough)
        borrowedPost = ObserveBorrowedPostState(
            cleanAttachmentFile, cleanAttachmentResource,
            cleanAttachmentHandle, snapshot.fileFlags);
    BusyHandoffPostState busyPost;
    if (busyHandoff)
        busyPost = ObserveBusyHandoffPostState(
            busyFile, busyResource, busyHandle, snapshot.fileFlags);
    const bool borrowedSkipValid = !cleanAttachmentFallthrough ||
        (borrowedOutcome.active && borrowedOutcome.skips == 1 &&
         borrowedOutcome.exactMatches == 1 &&
         borrowedOutcome.callsiteHits == 1 &&
         borrowedOutcome.failClosedSkips == 0 &&
         borrowedOutcome.forwards == 0 &&
         borrowedOutcome.rejectionBits == 0 && borrowedPost.valid);
    // A native success with one exact fail-closed cleanup skip and a
    // coherent re-quarantined cloth is accepted only after source/APB
    // verification of that exact 0x128 case.
    // The cleanup handler and every native editor call remain unchanged.
    const bool busyPostvalidateShape = busyHandoff && nativeOriginalResult &&
        borrowedOutcome.active && borrowedOutcome.callsiteHits == 1 &&
        borrowedOutcome.exactMatches == 0 && borrowedOutcome.skips == 0 &&
        borrowedOutcome.failClosedSkips == 1 &&
        borrowedOutcome.forwards == 0 &&
        borrowedOutcome.rejectionBits == 0x128 &&
        borrowedOutcome.callsiteLoadFlagsReadable &&
        borrowedOutcome.callsiteLoadFlags == 0x02 &&
        borrowedOutcome.callsiteHandleFlagsReadable &&
        (borrowedOutcome.callsiteHandleFlags & 0x04) != 0 &&
        busyPost.valid && busyPost.busy;
    bool busyPostvalidateSourceSame = false;
    ApbEquality busyPostvalidateApb;
    if (busyPostvalidateShape) {
        try {
            busyPostvalidateSourceSame = SourceStillIdentical(source);
            if (busyPostvalidateSourceSame)
                busyPostvalidateApb = CompareHeldSourceApb(
                    busySourceSnapshot, source, busyPost.apb,
                    busyPost.apbCount);
        } catch (...) {
            busyPostvalidateSourceSame = false;
        }
    }
    const bool busyPostvalidatedSkip = busyPostvalidateShape &&
        busyPostvalidateSourceSame &&
        busyPostvalidateApb.status == ApbEqualityStatus::Equal;
    const bool busySkipValid = !busyHandoff ||
        (borrowedOutcome.active && borrowedOutcome.skips == 1 &&
         borrowedOutcome.exactMatches == 1 &&
         borrowedOutcome.callsiteHits == 1 &&
         borrowedOutcome.failClosedSkips == 0 &&
         borrowedOutcome.forwards == 0 &&
         borrowedOutcome.rejectionBits == 0 && busyPost.valid) ||
        busyPostvalidatedSkip;
    // A clean attachment entering native ProcessFile may be re-quarantined
    // before its borrowed-root cleanup call. The exact fail-closed 0x128
    // shape is eligible only after the same full busy-state/source checks
    // already used by the separate 02->02 path.
    // Never forward this rooted attachment to native DiscardNoLock.
    BusyHandoffPostState busyCleanBusyPost;
    if (busyCleanHandoff)
        busyCleanBusyPost = ObserveBusyHandoffPostState(
            cleanAttachmentFile, cleanAttachmentResource,
            cleanAttachmentHandle, snapshot.fileFlags);
    const bool busyCleanBusyShape = busyCleanHandoff &&
        nativeOriginalResult && borrowedOutcome.active &&
        borrowedOutcome.callsiteHits == 1 &&
        borrowedOutcome.exactMatches == 0 &&
        borrowedOutcome.skips == 0 &&
        borrowedOutcome.failClosedSkips == 1 &&
        borrowedOutcome.forwards == 0 &&
        borrowedOutcome.rejectionBits == 0x128 &&
        borrowedOutcome.callsiteLoadFlagsReadable &&
        borrowedOutcome.callsiteLoadFlags == 0x02 &&
        borrowedOutcome.callsiteHandleFlagsReadable &&
        (borrowedOutcome.callsiteHandleFlags & 0x04) != 0 &&
        busyCleanBusyPost.valid && busyCleanBusyPost.busy;
    bool busyCleanBusySourceChecked = false;
    bool busyCleanBusySourceSame = false;
    bool busyCleanBusyApbChecked = false;
    ApbEquality busyCleanBusyApb;
    if (busyCleanHandoff) {
        try {
            busyCleanBusySourceChecked = true;
            busyCleanBusySourceSame = SourceStillIdentical(source);
            if (busyCleanBusyPost.valid && busyCleanBusyPost.busy &&
                busyCleanBusySourceSame) {
                busyCleanBusyApbChecked = true;
                busyCleanBusyApb = CompareHeldSourceApb(
                    busySourceSnapshot, source, busyCleanBusyPost.apb,
                    busyCleanBusyPost.apbCount);
            }
        } catch (...) {
            busyCleanBusySourceSame = false;
        }
    }
    const bool busyCleanBusyPromoted = busyCleanBusyShape &&
        busyCleanBusySourceSame &&
        busyCleanBusyApb.status == ApbEqualityStatus::Equal;
    bool busyCleanSourceSame = false;
    bool busyCleanMapStable = false;
    bool busyCleanLockIdle = false;
    void* busyCleanApbPointer = nullptr;
    unsigned int busyCleanApbCount = 0;
    ApbEquality busyCleanApb;
    QuarantineLookup busyCleanMap;
    if (busyCleanHandoff) {
        try {
            if (borrowedPost.valid) {
                const auto* cloth = static_cast<const UCHAR*>(
                    cleanAttachmentResource);
                const bool apbReadable =
                    SafeCopy(cloth + 0x154, &busyCleanApbPointer,
                             sizeof(busyCleanApbPointer)) &&
                    SafeCopy(cloth + 0x15C, &busyCleanApbCount,
                             sizeof(busyCleanApbCount));
                busyCleanMap = ProbeQuarantineMap(
                    cleanAttachmentFile, nullptr, false);
                busyCleanMapStable =
                    busyCleanMap.status == QuarantineLookupStatus::Absent &&
                    busyCleanMap.beforeReadable &&
                    busyCleanMap.afterReadable &&
                    busyCleanMap.flagsBefore == 0 &&
                    busyCleanMap.flagsAfter == 0 &&
                    busyCleanMap.attachmentBefore ==
                        cleanAttachmentResource &&
                    busyCleanMap.attachmentAfter ==
                        cleanAttachmentResource;
                busyCleanLockIdle =
                    ObserveFileLock(cleanAttachmentFile).idle();
                busyCleanSourceSame = SourceStillIdentical(source);
                if (apbReadable && busyCleanSourceSame &&
                    busyCleanMapStable && busyCleanLockIdle)
                    busyCleanApb = CompareHeldSourceApb(
                        busySourceSnapshot, source,
                        busyCleanApbPointer, busyCleanApbCount);
            }
        } catch (...) {
            busyCleanSourceSame = false;
        }
    }
    const bool busyCleanPostValid = !busyCleanHandoff ||
        (nativeOriginalResult && borrowedSkipValid &&
         borrowedPost.valid && busyCleanSourceSame &&
         busyCleanMapStable && busyCleanLockIdle &&
         busyCleanApb.status == ApbEqualityStatus::Equal) ||
        busyCleanBusyPromoted;
    const bool originalResult = nativeOriginalResult &&
        (borrowedSkipValid || busyCleanBusyPromoted) &&
        busySkipValid && busyCleanPostValid;
    if (busyCleanHandoff) {
        Log(L"BUSY_CLEAN_POSTVALIDATE result call=%ld "
            L"nativeResult=%u shape=%u "
            L"callsiteHits=%u exactMatches=%u skips=%u "
            L"failClosedSkips=%u forwards=%u rejectBits=%08X "
            L"callsiteLoadRead=%u callsiteLoad=%02X "
            L"callsiteHandleRead=%u callsiteHandle=%08X "
            L"postValid=%u postBusy=%u postClean=%u "
            L"file=%p attached=%p expected=%p "
            L"handle=%p expectedHandle=%p flags=%02X/%02X "
            L"rootFlags=%08X handleFlags=%08X "
            L"map=%s mapStable=%u lockIdle=%u "
            L"sourceChecked=%u sourceSame=%u "
            L"apbChecked=%u apb=%p apbCount=%u "
            L"apbStatus=%u promoted=%u effectiveResult=%u",
            call, nativeOriginalResult ? 1u : 0u,
            busyCleanBusyShape ? 1u : 0u,
            borrowedOutcome.callsiteHits, borrowedOutcome.exactMatches,
            borrowedOutcome.skips, borrowedOutcome.failClosedSkips,
            borrowedOutcome.forwards, borrowedOutcome.rejectionBits,
            borrowedOutcome.callsiteLoadFlagsReadable ? 1u : 0u,
            borrowedOutcome.callsiteLoadFlags,
            borrowedOutcome.callsiteHandleFlagsReadable ? 1u : 0u,
            borrowedOutcome.callsiteHandleFlags,
            busyCleanBusyPost.valid ? 1u : 0u,
            busyCleanBusyPost.busy ? 1u : 0u,
            busyCleanBusyPost.clean ? 1u : 0u,
            cleanAttachmentFile, busyCleanBusyPost.attachment,
            cleanAttachmentResource, busyCleanBusyPost.handle,
            cleanAttachmentHandle, busyCleanBusyPost.fileFlags,
            busyCleanBusyPost.loadFlags, busyCleanBusyPost.rootFlags,
            busyCleanBusyPost.handleFlags,
            QuarantineLookupName(busyCleanBusyPost.map.status),
            busyCleanBusyPost.mapStable ? 1u : 0u,
            busyCleanBusyPost.lockIdle ? 1u : 0u,
            busyCleanBusySourceChecked ? 1u : 0u,
            busyCleanBusySourceSame ? 1u : 0u,
            busyCleanBusyApbChecked ? 1u : 0u,
            busyCleanBusyPost.apb, busyCleanBusyPost.apbCount,
            static_cast<unsigned>(busyCleanBusyApb.status),
            busyCleanBusyPromoted ? 1u : 0u,
            originalResult ? 1u : 0u);
    }
    if (busyHandoff) {
        Log(L"BUSY_GENERAL result call=%ld nativeResult=%u "
            L"shape=%u callsiteLoadRead=%u callsiteLoad=%02X "
            L"callsiteHandleRead=%u callsiteHandle=%08X "
            L"sourceSame=%u sourceMetaValid=%u sourceApbSize=%u "
            L"apbStatus=%u apbEqual=%u "
            L"promoted=%u effectiveResult=%u",
            call, nativeOriginalResult ? 1u : 0u,
            busyPostvalidateShape ? 1u : 0u,
            borrowedOutcome.callsiteLoadFlagsReadable ? 1u : 0u,
            borrowedOutcome.callsiteLoadFlags,
            borrowedOutcome.callsiteHandleFlagsReadable ? 1u : 0u,
            borrowedOutcome.callsiteHandleFlags,
            busyPostvalidateSourceSame ? 1u : 0u,
            busySourceSnapshot.sourceApb.valid() ? 1u : 0u,
            busySourceSnapshot.sourceApb.apbSize,
            static_cast<unsigned>(busyPostvalidateApb.status),
            busyPostvalidateApb.status == ApbEqualityStatus::Equal ? 1u : 0u,
            busyPostvalidatedSkip ? 1u : 0u,
            originalResult ? 1u : 0u);
        Log(L"BORROWED_CLEANUP post-ProcessFile call=%ld nativeResult=%u "
            L"callsiteHits=%u exactMatches=%u skips=%u "
            L"failClosedSkips=%u forwards=%u rejectBits=%08X "
            L"postStateValid=%u skipValid=%u effectiveResult=%u",
            call, nativeOriginalResult ? 1u : 0u,
            borrowedOutcome.callsiteHits, borrowedOutcome.exactMatches,
            borrowedOutcome.skips, borrowedOutcome.failClosedSkips,
            borrowedOutcome.forwards, borrowedOutcome.rejectionBits,
            busyPost.valid ? 1u : 0u, busySkipValid ? 1u : 0u,
            originalResult ? 1u : 0u);
        Log(L"BUSY_HANDOFF postnative call=%ld nativeResult=%u "
            L"effectiveResult=%u stateValid=%u clean=%u busy=%u "
            L"file=%p attachment=%p expected=%p linkedFile=%p "
            L"handle=%p expectedHandle=%p flags=%02X/%02X "
            L"byte60=%02X rootFlags=%08X handleFlags=%08X "
            L"apb=%p apbCount=%u apbMagicRead=%u "
            L"apbMagic=%02X%02X%02X%02X map=%s mapBefore=%02X/%p "
            L"mapAfter=%02X/%p oneShot=1",
            call, nativeOriginalResult ? 1u : 0u,
            originalResult ? 1u : 0u,
            busyPost.valid ? 1u : 0u,
            busyPost.clean ? 1u : 0u, busyPost.busy ? 1u : 0u,
            busyFile, busyPost.attachment, busyResource,
            busyPost.linkedFile, busyPost.handle, busyHandle,
            busyPost.fileFlags, busyPost.loadFlags,
            busyPost.resourceByte, busyPost.rootFlags,
            busyPost.handleFlags, busyPost.apb, busyPost.apbCount,
            busyPost.apbMagicReadable ? 1u : 0u,
            busyPost.apbMagic[0], busyPost.apbMagic[1],
            busyPost.apbMagic[2], busyPost.apbMagic[3],
            QuarantineLookupName(busyPost.map.status),
            busyPost.map.flagsBefore, busyPost.map.attachmentBefore,
            busyPost.map.flagsAfter, busyPost.map.attachmentAfter);
    }
    bool sourceStillSame = true;
    if (claimed) {
        try { sourceStillSame = SourceStillIdentical(source); }
        catch (...) { sourceStillSame = false; }
        const bool success = originalResult && sourceStillSame;
        try { FinishFile(fileKey, busyReloadAttempted || !success); }
        catch (...) {
            // A state bookkeeping failure after mutation is unsafe to mask.
            sourceStillSame = false;
        }
        if (!sourceStillSame)
            actionReason = L"source identity/content changed during ProcessFile";
        else if (busyCleanHandoff && !busyCleanPostValid)
            actionReason = L"initial-busy clean handoff cleanup, APB, or post-state invalid; file blocked until editor restart";
        else if (busyHandoff && !busySkipValid)
            actionReason = L"busy handoff cleanup or post-state invalid; file blocked until editor restart";
        else if (cleanAttachmentFallthrough && !borrowedSkipValid &&
                 !busyCleanBusyPromoted)
            actionReason = L"borrowed cleanup count or post-state invalid; file blocked until editor restart";
        else if (busyHandoff && originalResult)
            actionReason = L"initial-busy Reload handoff succeeded; one-shot file blocked until editor restart";
        else if (busyCleanHandoff && originalResult)
            actionReason = busyCleanBusyPromoted
                ? L"initial-busy clean-transition handoff succeeded after exact busy postvalidation; one-shot file blocked until editor restart"
                : L"initial-busy clean-attachment handoff succeeded; one-shot file blocked until editor restart";
        else if (originalResult)
            actionReason = quarantineFallthrough
                ? L"native ProcessFile succeeded after guarded quarantine handoff"
                : cleanAttachmentFallthrough
                    ? L"native ProcessFile succeeded with one guarded borrowed-root cleanup skip"
                    : L"fresh-load ProcessFile succeeded; file is eligible for a later Publish";
        else
            actionReason = L"ProcessFile failed after Reload; file blocked until editor restart";
    }
    const bool result = originalResult && sourceStillSame;
    if (isRedcloth && (reloadCalled || abortOriginal || snapshot.eligible)) {
        try {
            Log(L"ACTIVE call=%ld tid=%lu path=%S gate=%u reloadCalled=%u "
                L"reloadReturn=%u attachment=%u quarantineFallthrough=%u "
                L"cleanAttachmentFallthrough=%u busyHandoff=%u "
                L"busyCleanHandoff=%u "
                L"busyReloadAttempted=%u failClosedSkips=%u "
                L"abort=%u result=%u reason=%s",
                call, GetCurrentThreadId(), depotPath, snapshot.eligible ? 1u : 0u,
                reloadCalled ? 1u : 0u, reloadReturn ? 1u : 0u,
                static_cast<unsigned>(attachment),
                quarantineFallthrough ? 1u : 0u,
                cleanAttachmentFallthrough ? 1u : 0u,
                busyHandoff ? 1u : 0u,
                busyCleanHandoff ? 1u : 0u,
                busyReloadAttempted ? 1u : 0u,
                borrowedOutcome.failClosedSkips,
                abortOriginal ? 1u : 0u,
                result ? 1u : 0u, actionReason);
        } catch (...) {
            OutputDebugStringW(L"REDkit general active: action logging failed.\n");
        }
    }
    if (isRedcloth && redclothCall <= 128) {
        try { LogGate(snapshot, call, redclothCall, result); }
        catch (...) {
            OutputDebugStringW(L"REDkit general active: gate logging failed.\n");
        }
    } else if (isRedcloth && redclothCall == 129) {
        try { Log(L"GATE detail logging capped at 128 redcloth calls; intervention continues."); }
        catch (...) {}
    }
    return result;
}
bool WriteBorrowedCallsite(const UCHAR* expected, const UCHAR* replacement,
                           wchar_t* error, size_t errorChars) {
    UCHAR* const callsite = g_editorBase + kBorrowedDiscardCallRva;
    UCHAR actual[kBorrowedDiscardCallBytes.size()] = {};
    if (!SafeCopy(callsite, actual, sizeof(actual)) ||
        std::memcmp(actual, expected, sizeof(actual)) != 0) {
        wcscpy_s(error, errorChars, L"Discard callsite signature changed.");
        return false;
    }
    DWORD oldProtection = 0;
    if (!VirtualProtect(callsite, sizeof(actual), PAGE_EXECUTE_READWRITE,
                        &oldProtection)) {
        wcscpy_s(error, errorChars, L"Discard callsite protection change failed.");
        return false;
    }
    if (!SafeCopy(callsite, actual, sizeof(actual)) ||
        std::memcmp(actual, expected, sizeof(actual)) != 0) {
        DWORD ignored = 0;
        const bool restored = VirtualProtect(
            callsite, sizeof(actual), oldProtection, &ignored) != 0;
        wcscpy_s(error, errorChars,
                 restored
                     ? L"Discard callsite changed while installing."
                     : L"Discard callsite changed and page protection restoration failed.");
        return false;
    }
    std::memcpy(callsite, replacement, sizeof(actual));
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), callsite,
                                               sizeof(actual)) != 0;
    DWORD ignored = 0;
    const bool restored = VirtualProtect(callsite, sizeof(actual),
                                          oldProtection, &ignored) != 0;
    if (flushed && restored) return true;

    // If installation was not fully successful, put back the exact original
    // bytes before leaving the editor. Never free the relay while a patched
    // callsite could still reach it.
    DWORD writable = 0;
    if (!VirtualProtect(callsite, sizeof(actual), PAGE_EXECUTE_READWRITE,
                        &writable)) {
        wcscpy_s(error, errorChars,
                 L"Discard callsite rollback could not reopen page; relay pinned.");
        return false;
    }
    std::memcpy(callsite, expected, sizeof(actual));
    const bool rollbackFlushed = FlushInstructionCache(
        GetCurrentProcess(), callsite, sizeof(actual)) != 0;
    const bool rollbackProtected = VirtualProtect(
        callsite, sizeof(actual), oldProtection, &ignored) != 0;
    wcscpy_s(error, errorChars,
             rollbackFlushed && rollbackProtected
                 ? L"Discard callsite flush/protection failed; bytes rolled back."
                 : L"Discard callsite rollback cache/protection uncertain; relay pinned.");
    return false;
}

void* AllocateBorrowedRelay(UCHAR* callsite) {
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);
    const std::uintptr_t granularity = info.dwAllocationGranularity;
    if (!granularity || (granularity & (granularity - 1)) != 0)
        return nullptr;
    const std::uintptr_t origin =
        reinterpret_cast<std::uintptr_t>(callsite) & ~(granularity - 1);
    constexpr std::uintptr_t kMaximumOffset = 0x7FFF0000u;
    for (std::uintptr_t distance = 0; distance <= kMaximumOffset;
         distance += granularity) {
        for (unsigned int direction = 0; direction < 2; ++direction) {
            if (distance == 0 && direction != 0) continue;
            if (direction == 0 && distance > origin) continue;
            const std::uintptr_t address = direction == 0
                ? origin - distance : origin + distance;
            if (direction != 0 && address < origin) continue;
            void* const relay = VirtualAlloc(
                reinterpret_cast<void*>(address), 0x1000,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!relay) continue;
            const auto displacement =
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(relay)) -
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(callsite + 5));
            if (displacement >= INT32_MIN && displacement <= INT32_MAX)
                return relay;
            VirtualFree(relay, 0, MEM_RELEASE);
        }
    }
    return nullptr;
}

bool InstallBorrowedDiscardCall(wchar_t* error, size_t errorChars) {
    UCHAR* const callsite = g_editorBase + kBorrowedDiscardCallRva;
    UCHAR actual[kBorrowedDiscardCallBytes.size()] = {};
    if (!SafeCopy(callsite, actual, sizeof(actual)) ||
        std::memcmp(actual, kBorrowedDiscardCallBytes.data(),
                    sizeof(actual)) != 0) {
        wcscpy_s(error, errorChars, L"Discard callsite is not E8 2B EB DE FF.");
        return false;
    }
    std::int32_t originalDisplacement = 0;
    std::memcpy(&originalDisplacement, actual + 1,
                sizeof(originalDisplacement));
    if (callsite + 5 + originalDisplacement !=
        g_editorBase + kDiscardNoLockRva) {
        wcscpy_s(error, errorChars, L"Discard call target differs from tested build.");
        return false;
    }
    void* const relay = AllocateBorrowedRelay(callsite);
    if (!relay) {
        wcscpy_s(error, errorChars, L"Could not reserve a near discard relay.");
        return false;
    }
    UCHAR relayBytes[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
    void* const handler = reinterpret_cast<void*>(&BorrowedDiscardCall);
    std::memcpy(relayBytes + 6, &handler, sizeof(handler));
    std::memcpy(relay, relayBytes, sizeof(relayBytes));
    DWORD priorProtection = 0;
    if (!VirtualProtect(relay, sizeof(relayBytes), PAGE_EXECUTE_READ,
                        &priorProtection) ||
        !FlushInstructionCache(GetCurrentProcess(), relay,
                               sizeof(relayBytes))) {
        VirtualFree(relay, 0, MEM_RELEASE);
        wcscpy_s(error, errorChars, L"Could not make discard relay executable.");
        return false;
    }
    const auto displacement =
        static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(relay)) -
        static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(callsite + 5));
    const std::int32_t relative = static_cast<std::int32_t>(displacement);
    UCHAR replacement[5] = { 0xE8, 0, 0, 0, 0 };
    std::memcpy(replacement + 1, &relative, sizeof(relative));
    g_discardNoLock = reinterpret_cast<DiscardNoLockFn>(
        g_editorBase + kDiscardNoLockRva);
    g_borrowedRelay = relay;
    if (!WriteBorrowedCallsite(kBorrowedDiscardCallBytes.data(),
                               replacement, error, errorChars))
        return false;
    g_borrowedCallPatched = true;
    return true;
}

bool RollbackBorrowedDiscardCall() {
    if (!g_borrowedCallPatched || !g_borrowedRelay) return false;
    UCHAR* const callsite = g_editorBase + kBorrowedDiscardCallRva;
    const auto displacement =
        static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(g_borrowedRelay)) -
        static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(callsite + 5));
    const std::int32_t relative = static_cast<std::int32_t>(displacement);
    UCHAR replacement[5] = { 0xE8, 0, 0, 0, 0 };
    std::memcpy(replacement + 1, &relative, sizeof(relative));
    wchar_t error[160] = {};
    if (!WriteBorrowedCallsite(replacement,
                               kBorrowedDiscardCallBytes.data(),
                               error, _countof(error))) {
        Log(L"Discard callsite rollback failed: %s", error);
        return false;
    }
    g_borrowedCallPatched = false;
    return true;
}

void InstallTrace() {
    wchar_t imagePath[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, imagePath, _countof(imagePath));
    if (length == 0 || length >= _countof(imagePath)) {
        Log(L"Cannot determine process image path; trace skipped.");
        return;
    }
    const wchar_t* basename = wcsrchr(imagePath, L'\\');
    basename = basename ? basename + 1 : imagePath;
    if (_wcsicmp(basename, L"editor.exe") != 0) {
        Log(L"Process is %s, not editor.exe; trace skipped.", basename);
        return;
    }

    std::array<UCHAR, 32> digest = {};
    if (!ComputeSha256(imagePath, digest)) return;
    if (digest != kExpectedSha256) {
        Log(L"Editor SHA-256 differs from tested build; trace skipped.");
        return;
    }

    g_editorBase = reinterpret_cast<UCHAR*>(GetModuleHandleW(nullptr));
    const UCHAR* clearBranch = g_editorBase + kPatchRva;
    if (clearBranch[0] != 0x74 || clearBranch[1] != 0x28) {
        Log(L"APB-clear branch is %02X %02X, not baseline 74 28; trace skipped.",
            clearBranch[0], clearBranch[1]);
        return;
    }
    wchar_t error[256] = {};
    UCHAR actualPrologue[kProcessFilePrologue.size()] = {};
    if (!SafeCopy(g_editorBase + kProcessFileRva, actualPrologue,
                  sizeof(actualPrologue)) ||
        std::memcmp(actualPrologue, kProcessFilePrologue.data(),
                    sizeof(actualPrologue)) != 0) {
        Log(L"ProcessFile prologue differs from tested build; vtable hook skipped.");
        return;
    }
    if (!InstallBorrowedDiscardCall(error, _countof(error))) {
        Log(L"Borrowed cleanup callsite patch was not installed: %s", error);
        return;
    }
    constexpr SIZE_T kProcessFileVtableSlot = 9;
    auto** slot = reinterpret_cast<void**>(
        g_editorBase + kPhysicsBuilderVtableRva +
        kProcessFileVtableSlot * sizeof(void*));
    if (!InstallVtableSlot(slot, g_editorBase + kProcessFileRva,
                           reinterpret_cast<void*>(&TraceProcessFile),
                           &g_processFileTrampoline, error, _countof(error))) {
        Log(L"ProcessFile vtable hook was not installed: %s", error);
        Log(L"Borrowed cleanup callsite rollback after vtable failure: %u",
            RollbackBorrowedDiscardCall() ? 1u : 0u);
        return;
    }
    Log(L"Installed 1090143 GENERAL_ACTIVE scoped-Reload vtable hook at RVA 0x%IX slot %zu "
        L"on thread %lu; only ProcessFile callsite +0x270 patched; APB clear remains 74 28.",
        kPhysicsBuilderVtableRva, kProcessFileVtableSlot,
        GetCurrentThreadId());
    Log(L"BORROWED_CLEANUP callsite=editor+0x%IX relay=%p original=editor+0x%IX handler=%p bytes=E8 2B EB DE FF",
        kBorrowedDiscardCallRva, g_borrowedRelay, kDiscardNoLockRva,
        reinterpret_cast<void*>(&BorrowedDiscardCall));
}

BOOL CALLBACK InitializeTrace(PINIT_ONCE, PVOID, PVOID*) {
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_PIN,
                            reinterpret_cast<LPCWSTR>(g_self), &pinned)) {
        Log(L"Could not pin ASI module (Win32 %lu); trace skipped.", GetLastError());
        return TRUE;
    }
    try { InstallTrace(); }
    catch (...) { OutputDebugStringW(L"REDkit APB trace: installation failed.\n"); }
    return TRUE;
}

void MaybeTrace() {
    InitOnceExecuteOnce(&g_traceOnce, InitializeTrace, nullptr, nullptr);
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = self;
    }
    return TRUE;
}

// Ultimate ASI Loader calls this after LoadLibrary returns and the loader lock
// has been released. DllMain deliberately does not install a hook.
extern "C" __declspec(dllexport) void InitializeASI() {
    Log(L"REDCLOTH_RELEASE_CLEAN startup; mode=1090143-release-clean-vtable.");
    Log(L"REDCLOTH_RELEASE_CLEAN guarded same-session cloth handoff active; editor 1090143.");
    MaybeTrace();
}
