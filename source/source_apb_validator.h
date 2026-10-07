#pragma once

#include <cstddef>
#include <cstdint>

namespace redkit {

// This is a deliberately conservative structural check, not an APEX decoder.
// In particular, Valid means that one well-formed apexBinaryAsset byte array
// exists in a CR2W export. It does not guarantee that the cloth can be cooked.
enum class SourceApbStatus {
    Valid,
    MissingPath,
    OpenFailed,
    FileTooLarge,
    ReadFailed,
    InvalidCr2w,
    UnsupportedLayout,
    NoValidApb,
    AmbiguousApb,
};

struct SourceApbResult {
    SourceApbStatus status = SourceApbStatus::InvalidCr2w;
    const char* reason = "not checked";
    std::uint64_t fileSize = 0;
    std::uint32_t cr2wVersion = 0;
    std::uint32_t apbOffset = 0;
    std::uint32_t apbSize = 0;
    std::uint32_t exportIndex = 0;
    std::uint32_t propertyOffset = 0;

    bool valid() const noexcept { return status == SourceApbStatus::Valid; }
};

// Rejects files above this cap before allocation. The local REDkit corpus has
// source cloths below 5 MiB; the larger limit leaves room for custom assets.
constexpr std::uint64_t kMaximumSourceClothBytes = 256ull * 1024ull * 1024ull;

// Pure parser for tests or an already-read source snapshot. It does not retain
// or mutate the input buffer. An empty/null buffer is rejected.
SourceApbResult ValidateSourceApbBytes(const std::uint8_t* bytes,
                                       std::size_t length) noexcept;

// Opens and reads one source file via a Windows handle, then runs the same
// parser. Never writes the source. A caller should apply its project-root and
// .redcloth path gates before calling this potentially expensive function.
SourceApbResult ValidateSourceApbFile(const wchar_t* absolutePath) noexcept;

}  // namespace redkit
