#include <windows.h>
#include <bcrypt.h>
#include <dinput.h>
#include "vtable_slot_hook.h"
#include "source_apb_validator.h"

#include <array>
#include <cstdarg>
#include <cwchar>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>


namespace {

constexpr SIZE_T kPatchRva = 0x2957F27;
constexpr SIZE_T kProcessFileRva = 0x3C3FAA0;
constexpr SIZE_T kPhysicsBuilderVtableRva = 0x6F34CB0;
constexpr SIZE_T kDepotGlobalRva = 0xBF33600;
constexpr SIZE_T kMainThreadIdRva = 0xBF34160;
constexpr SIZE_T kProjectContextGlobalRva = 0xBF34780;
constexpr SIZE_T kFindFileUseLinksRva = 0x3A18BD0;
constexpr SIZE_T kGetAbsolutePathRva = 0x3A37AB0;
constexpr SIZE_T kTStringDestructorRva = 0x39DFEC0;
constexpr SIZE_T kResourceReloadRva = 0x39FCBA0;
constexpr SIZE_T kDiskFileVtableRva = 0x6EA5DD8;
constexpr SIZE_T kCachedDirectoryVtableRva = 0x6EB4EA8;
constexpr SIZE_T kPhysicalDirectoryVtableRva = 0x6EF85F0;
constexpr SIZE_T kVirtualDirectoryVtableRva = 0x6ED35B0;
constexpr SIZE_T kApexClothVtableRva = 0x6BEF270;
constexpr std::array<UCHAR, 15> kProcessFilePrologue = {
    0x48, 0x89, 0x5C, 0x24, 0x08,
    0x48, 0x89, 0x6C, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18
};
constexpr LONGLONG kExpectedEditorSize = 198202320;
constexpr std::array<UCHAR, 32> kExpectedSha256 = {
    0x42, 0x2C, 0xEB, 0xBC, 0xEF, 0xDE, 0x36, 0x37,
    0x59, 0x08, 0xCD, 0xD7, 0x8D, 0x09, 0x7A, 0x46,
    0x72, 0xEF, 0x26, 0xF2, 0x84, 0x94, 0xB2, 0xF1,
    0xDC, 0x09, 0xB6, 0x6B, 0x7A, 0x72, 0xAA, 0x46
};

using DirectInput8CreateFn = HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
using DllCanUnloadNowFn = HRESULT(WINAPI*)();
using DllGetClassObjectFn = HRESULT(WINAPI*)(REFCLSID, REFIID, LPVOID*);
using DllRegisterServerFn = HRESULT(WINAPI*)();
using DllUnregisterServerFn = HRESULT(WINAPI*)();
using GetdfDIJoystickFn = LPCDIDATAFORMAT(WINAPI*)();
using ProcessFileFn = bool(WINAPI*)(void*, void*, void*, void*);
using FindFileUseLinksFn = void*(WINAPI*)(void*, const void*, unsigned int);
using GetAbsolutePathFn = void*(WINAPI*)(void*, void*);
using TStringDestructorFn = void(WINAPI*)(void*);
using ResourceReloadFn = bool(WINAPI*)(void*, bool);

HMODULE g_self = nullptr;
HMODULE g_real = nullptr;
INIT_ONCE g_realOnce = INIT_ONCE_STATIC_INIT;
INIT_ONCE g_traceOnce = INIT_ONCE_STATIC_INIT;
void* g_processFileTrampoline = nullptr;
UCHAR* g_editorBase = nullptr;
volatile LONG g_traceCalls = 0;
volatile LONG g_redclothCalls = 0;
thread_local bool g_insideTrace = false;
thread_local bool g_interventionActive = false;
thread_local char g_activeDepotPath[768] = {};
// Only a Reload that has already changed a resource can make a file sticky
// invalid. A successful ProcessFile clears its entry for the next Publish.
enum class FileState { InProgress, Invalid };
std::mutex g_fileStatesMutex;
std::unordered_map<std::string, FileState> g_fileStates;

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

bool GetSystemDinputPath(std::wstring& path) {
    wchar_t systemDirectory[MAX_PATH] = {};
    const UINT count = GetSystemDirectoryW(systemDirectory, _countof(systemDirectory));
    if (count == 0 || count >= _countof(systemDirectory)) return false;
    path.assign(systemDirectory);
    path += L"\\dinput8.dll";
    return true;
}

BOOL CALLBACK InitializeReal(PINIT_ONCE, PVOID, PVOID*) {
    std::wstring path;
    if (!GetSystemDinputPath(path)) {
        Log(L"Could not determine the System32 dinput8.dll path; forwarding unavailable.");
        return TRUE;
    }
    HMODULE loaded = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!loaded) {
        Log(L"Could not load %s (Win32 %lu); forwarding unavailable.",
            path.c_str(), GetLastError());
        return TRUE;
    }
    wchar_t loadedPath[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(loaded, loadedPath, _countof(loadedPath));
    if (loaded == g_self || length == 0 || length >= _countof(loadedPath) ||
        _wcsicmp(loadedPath, path.c_str()) != 0) {
        Log(L"System32 load resolved to a different module (%s); forwarding unavailable.",
            length > 0 && length < _countof(loadedPath) ? loadedPath : L"unknown");
        return TRUE;
    }
    g_real = loaded;
    Log(L"Loaded real %s; mode=general-active-vtable.", path.c_str());
    return TRUE;
}

HMODULE RealDinput() {
    if (!InitOnceExecuteOnce(&g_realOnce, InitializeReal, nullptr, nullptr)) return nullptr;
    return g_real;
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
    LONG redclothCall = 0;
    SourceGuard source;
    std::string fileKey;
    bool claimed = false;
    bool reloadCalled = false;
    bool reloadReturn = false;
    bool abortOriginal = false;
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
                            if (!reloadReturn ||
                                !SamePhysicalIdentity(snapshot, after) ||
                                !SourceStillIdentical(source)) {
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
    const bool originalResult = abortOriginal ? false :
        original(builder, database, fileId, pathObject);
    bool sourceStillSame = true;
    if (claimed) {
        try { sourceStillSame = SourceStillIdentical(source); }
        catch (...) { sourceStillSame = false; }
        const bool success = originalResult && sourceStillSame;
        try { FinishFile(fileKey, !success); }
        catch (...) {
            // A state bookkeeping failure after mutation is unsafe to mask.
            sourceStillSame = false;
        }
        if (!sourceStillSame)
            actionReason = L"source identity/content changed during ProcessFile";
        else if (originalResult)
            actionReason = L"fresh-load ProcessFile succeeded; file is eligible for a later Publish";
        else
            actionReason = L"ProcessFile failed after Reload; file blocked until editor restart";
    }
    const bool result = originalResult && sourceStillSame;
    if (isRedcloth && (reloadCalled || abortOriginal || snapshot.eligible)) {
        try {
            Log(L"ACTIVE call=%ld tid=%lu path=%S gate=%u reloadCalled=%u "
                L"reloadReturn=%u attachment=%u abort=%u result=%u reason=%s",
                call, GetCurrentThreadId(), depotPath, snapshot.eligible ? 1u : 0u,
                reloadCalled ? 1u : 0u, reloadReturn ? 1u : 0u,
                static_cast<unsigned>(attachment), abortOriginal ? 1u : 0u,
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
    constexpr SIZE_T kProcessFileVtableSlot = 9;
    auto** slot = reinterpret_cast<void**>(
        g_editorBase + kPhysicsBuilderVtableRva +
        kProcessFileVtableSlot * sizeof(void*));
    if (!InstallVtableSlot(slot, g_editorBase + kProcessFileRva,
                           reinterpret_cast<void*>(&TraceProcessFile),
                           &g_processFileTrampoline, error, _countof(error))) {
        Log(L"ProcessFile vtable hook was not installed: %s", error);
        return;
    }
    Log(L"Installed general-active scoped-Reload vtable hook at RVA 0x%IX slot %zu "
        L"on thread %lu; ProcessFile code unchanged; APB clear remains 74 28.",
        kPhysicsBuilderVtableRva, kProcessFileVtableSlot,
        GetCurrentThreadId());
}

BOOL CALLBACK InitializeTrace(PINIT_ONCE, PVOID, PVOID*) {
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_PIN,
                            reinterpret_cast<LPCWSTR>(g_self), &pinned)) {
        Log(L"Could not pin proxy module (Win32 %lu); trace skipped.", GetLastError());
        return TRUE;
    }
    try { InstallTrace(); }
    catch (...) { OutputDebugStringW(L"REDkit APB trace: installation failed.\n"); }
    return TRUE;
}

void MaybeTrace() {
    InitOnceExecuteOnce(&g_traceOnce, InitializeTrace, nullptr, nullptr);
}

template <typename T>
T RealExport(const char* name) {
    HMODULE module = RealDinput();
    return module ? reinterpret_cast<T>(GetProcAddress(module, name)) : nullptr;
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = self;
    }
    return TRUE;
}

extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE instance, DWORD version,
                                                REFIID iid, LPVOID* output,
                                                LPUNKNOWN outer) {
    const auto real = RealExport<DirectInput8CreateFn>("DirectInput8Create");
    if (!real) return E_FAIL;
    MaybeTrace();
    return real(instance, version, iid, output, outer);
}

extern "C" HRESULT WINAPI DllCanUnloadNow() {
    const auto real = RealExport<DllCanUnloadNowFn>("DllCanUnloadNow");
    return real ? real() : E_FAIL;
}

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid,
                                               LPVOID* output) {
    const auto real = RealExport<DllGetClassObjectFn>("DllGetClassObject");
    return real ? real(clsid, iid, output) : E_FAIL;
}

extern "C" HRESULT WINAPI DllRegisterServer() {
    const auto real = RealExport<DllRegisterServerFn>("DllRegisterServer");
    return real ? real() : E_FAIL;
}

extern "C" HRESULT WINAPI DllUnregisterServer() {
    const auto real = RealExport<DllUnregisterServerFn>("DllUnregisterServer");
    return real ? real() : E_FAIL;
}

extern "C" LPCDIDATAFORMAT WINAPI GetdfDIJoystick() {
    const auto real = RealExport<GetdfDIJoystickFn>("GetdfDIJoystick");
    return real ? real() : nullptr;
}
