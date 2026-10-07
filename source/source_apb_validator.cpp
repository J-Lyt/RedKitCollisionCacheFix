#include "source_apb_validator.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace redkit {
namespace {

constexpr std::size_t kDirectoryOffset = 0x28;
constexpr std::size_t kDirectoryEntrySize = 12;
constexpr std::size_t kNameRecordSize = 8;
constexpr std::size_t kExportRecordSize = 24;
constexpr std::size_t kMinimumApbSize = 0x100;
constexpr std::uint8_t kApbMagic[] = {0x5a, 0x5b, 0x5c, 0x5d};
constexpr char kRootClass[] = "ClothingAssetParameters";

struct Table {
    std::uint32_t offset = 0;
    std::uint32_t count = 0;
};

struct Export {
    std::size_t start = 0;
    std::size_t end = 0;
};

SourceApbResult Reject(SourceApbStatus status, const char* reason,
                       std::size_t fileSize) noexcept {
    SourceApbResult result;
    result.status = status;
    result.reason = reason;
    result.fileSize = fileSize;
    return result;
}

bool InBounds(std::size_t offset, std::size_t size,
              std::size_t length) noexcept {
    return offset <= length && size <= length - offset;
}

std::uint16_t Le16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t Le32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t Be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

bool NameEquals(const std::uint8_t* bytes, std::size_t start,
                std::size_t length, const char* name,
                std::size_t nameLength) noexcept {
    return length == nameLength &&
           std::memcmp(bytes + start, name, length) == 0;
}

bool IsUint8ArrayType(const std::uint8_t* bytes, std::size_t start,
                      std::size_t length) noexcept {
    constexpr char prefix[] = "array:";
    constexpr char suffix[] = ",Uint8";
    constexpr auto prefixLength = sizeof(prefix) - 1;
    constexpr auto suffixLength = sizeof(suffix) - 1;
    return length >= prefixLength + suffixLength &&
           std::memcmp(bytes + start, prefix, prefixLength) == 0 &&
           std::memcmp(bytes + start + length - suffixLength,
                       suffix, suffixLength) == 0;
}

bool ContainsRootClass(const std::uint8_t* apb,
                       std::size_t apbSize) noexcept {
    constexpr std::size_t needleSize = sizeof(kRootClass);  // Includes NUL.
    const std::size_t limit = apbSize < 0x4000 ? apbSize : 0x4000;
    for (std::size_t pos = 0; pos + needleSize <= limit; ++pos) {
        if (std::memcmp(apb + pos, kRootClass, needleSize) == 0) return true;
    }
    return false;
}

// Both name and type indices in a CR2W property are u16. A bitmap avoids
// allocating a vector while scanning export data inside an editor hook.
void MarkType(std::array<std::uint8_t, 8192>& bitmap,
              std::uint16_t index) noexcept {
    bitmap[index / 8] |= static_cast<std::uint8_t>(1u << (index % 8));
}

bool IsType(const std::array<std::uint8_t, 8192>& bitmap,
            std::uint16_t index) noexcept {
    return (bitmap[index / 8] & (1u << (index % 8))) != 0;
}

}  // namespace

SourceApbResult ValidateSourceApbBytes(const std::uint8_t* bytes,
                                       std::size_t length) noexcept {
    if (!bytes || length < kDirectoryOffset ||
        std::memcmp(bytes, "CR2W", 4) != 0) {
        return Reject(SourceApbStatus::InvalidCr2w,
                      "CR2W header missing", length);
    }
    if (length > kMaximumSourceClothBytes ||
        length > std::numeric_limits<std::uint32_t>::max()) {
        return Reject(SourceApbStatus::FileTooLarge,
                      "source exceeds validator size cap", length);
    }

    const std::uint32_t version = Le32(bytes + 4);
    const std::uint32_t tableCount = Le32(bytes + 0x24);
    if (tableCount < 5 || tableCount > 32 ||
        !InBounds(kDirectoryOffset,
                  static_cast<std::size_t>(tableCount) * kDirectoryEntrySize,
                  length)) {
        return Reject(SourceApbStatus::UnsupportedLayout,
                      "unsupported CR2W table directory", length);
    }
    std::array<Table, 32> tables = {};
    for (std::uint32_t i = 0; i < tableCount; ++i) {
        const std::size_t at = kDirectoryOffset + i * kDirectoryEntrySize;
        tables[i] = {Le32(bytes + at), Le32(bytes + at + 4)};
    }

    const Table strings = tables[0];
    const Table names = tables[1];
    const Table exports = tables[4];
    if (strings.count == 0 || names.count == 0 || names.count > 65536 ||
        !InBounds(strings.offset, strings.count, length) ||
        !InBounds(names.offset,
                  static_cast<std::size_t>(names.count) * kNameRecordSize,
                  length)) {
        return Reject(SourceApbStatus::UnsupportedLayout,
                      "invalid CR2W string or name table", length);
    }
    if (exports.count == 0 || exports.count > 65536 ||
        !InBounds(exports.offset,
                  static_cast<std::size_t>(exports.count) * kExportRecordSize,
                  length)) {
        return Reject(SourceApbStatus::UnsupportedLayout,
                      "invalid CR2W export table", length);
    }

    std::array<std::uint8_t, 8192> typeBitmap = {};
    std::uint32_t apexNameIndex = 0;
    std::uint32_t apexNameCount = 0;
    std::uint32_t typeCount = 0;
    const std::size_t stringsEnd =
        static_cast<std::size_t>(strings.offset) + strings.count;
    for (std::uint32_t i = 0; i < names.count; ++i) {
        const std::size_t record =
            static_cast<std::size_t>(names.offset) +
            static_cast<std::size_t>(i) * kNameRecordSize;
        const std::uint32_t relative = Le32(bytes + record);
        if (relative >= strings.count) {
            return Reject(SourceApbStatus::UnsupportedLayout,
                          "name points outside CR2W string blob", length);
        }
        const std::size_t start =
            static_cast<std::size_t>(strings.offset) + relative;
        std::size_t end = start;
        while (end < stringsEnd && bytes[end] != 0) ++end;
        if (end == stringsEnd) {
            return Reject(SourceApbStatus::UnsupportedLayout,
                          "CR2W name lacks NUL terminator", length);
        }
        const std::size_t nameLength = end - start;
        if (NameEquals(bytes, start, nameLength,
                       "apexBinaryAsset", sizeof("apexBinaryAsset") - 1)) {
            apexNameIndex = i;
            ++apexNameCount;
        }
        if (IsUint8ArrayType(bytes, start, nameLength)) {
            MarkType(typeBitmap, static_cast<std::uint16_t>(i));
            ++typeCount;
        }
    }
    if (apexNameCount != 1 || typeCount == 0) {
        return Reject(SourceApbStatus::NoValidApb,
                      "unique apexBinaryAsset or Uint8 type absent", length);
    }

    SourceApbResult valid;
    valid.status = SourceApbStatus::Valid;
    valid.reason = "one validated apexBinaryAsset property";
    valid.fileSize = length;
    valid.cr2wVersion = version;
    std::uint32_t candidateCount = 0;
    for (std::uint32_t i = 0; i < exports.count; ++i) {
        const std::size_t record =
            static_cast<std::size_t>(exports.offset) +
            static_cast<std::size_t>(i) * kExportRecordSize;
        const std::uint32_t chunkSize = Le32(bytes + record + 8);
        const std::uint32_t chunkOffset = Le32(bytes + record + 12);
        if (!InBounds(chunkOffset, chunkSize, length)) {
            return Reject(SourceApbStatus::UnsupportedLayout,
                          "export chunk outside CR2W file", length);
        }
        const Export chunk = {chunkOffset,
                              static_cast<std::size_t>(chunkOffset) + chunkSize};
        for (std::size_t at = chunk.start;
             InBounds(at, 12, chunk.end); ++at) {
            if (Le16(bytes + at) != apexNameIndex ||
                !IsType(typeBitmap, Le16(bytes + at + 2))) {
                continue;
            }
            const std::uint32_t totalSize = Le32(bytes + at + 4);
            const std::uint32_t apbSize = Le32(bytes + at + 8);
            const std::size_t apbOffset = at + 12;
            if (apbSize < kMinimumApbSize ||
                static_cast<std::uint64_t>(totalSize) !=
                    static_cast<std::uint64_t>(apbSize) + 8 ||
                !InBounds(apbOffset, apbSize, chunk.end)) {
                continue;
            }
            const std::uint8_t* apb = bytes + apbOffset;
            if (std::memcmp(apb, kApbMagic, sizeof(kApbMagic)) != 0 ||
                Be32(apb + 0x10) != apbSize ||
                !ContainsRootClass(apb, apbSize)) {
                continue;
            }
            ++candidateCount;
            valid.apbOffset = static_cast<std::uint32_t>(apbOffset);
            valid.apbSize = apbSize;
            valid.exportIndex = i;
            valid.propertyOffset = static_cast<std::uint32_t>(at);
        }
    }
    if (candidateCount == 0) {
        return Reject(SourceApbStatus::NoValidApb,
                      "no validated apexBinaryAsset property", length);
    }
    if (candidateCount != 1) {
        return Reject(SourceApbStatus::AmbiguousApb,
                      "multiple validated apexBinaryAsset properties", length);
    }
    return valid;
}

SourceApbResult ValidateSourceApbFile(const wchar_t* absolutePath) noexcept {
    if (!absolutePath || !*absolutePath) {
        return Reject(SourceApbStatus::MissingPath, "source path missing", 0);
    }
    HANDLE file = CreateFileW(absolutePath, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return Reject(SourceApbStatus::OpenFailed,
                      "cannot open source file", 0);
    }

    SourceApbResult result;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
        result = Reject(SourceApbStatus::ReadFailed,
                        "cannot determine source file size", 0);
    } else if (size.QuadPart >
                   static_cast<LONGLONG>(kMaximumSourceClothBytes)) {
        result = Reject(SourceApbStatus::FileTooLarge,
                        "source exceeds validator size cap",
                        static_cast<std::size_t>(size.QuadPart));
    } else {
        try {
            const std::size_t length = static_cast<std::size_t>(size.QuadPart);
            std::vector<std::uint8_t> bytes(length);
            std::size_t cursor = 0;
            while (cursor < length) {
                const DWORD request = static_cast<DWORD>(
                    (length - cursor) < (1u << 20) ?
                        (length - cursor) : (1u << 20));
                DWORD received = 0;
                if (!ReadFile(file, bytes.data() + cursor, request,
                              &received, nullptr) || received == 0) {
                    result = Reject(SourceApbStatus::ReadFailed,
                                    "cannot read complete source file", length);
                    break;
                }
                cursor += received;
            }
            if (cursor == length) {
                LARGE_INTEGER after = {};
                if (!GetFileSizeEx(file, &after) ||
                    after.QuadPart != size.QuadPart) {
                    result = Reject(SourceApbStatus::ReadFailed,
                                    "source size changed during read", length);
                } else {
                    result = ValidateSourceApbBytes(bytes.data(), length);
                }
            }
        } catch (...) {
            result = Reject(SourceApbStatus::ReadFailed,
                            "cannot allocate source buffer",
                            static_cast<std::size_t>(size.QuadPart));
        }
    }
    CloseHandle(file);
    return result;
}

}  // namespace redkit
