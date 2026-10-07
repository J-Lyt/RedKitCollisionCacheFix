#include "vtable_slot_hook.h"

#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>

#if !defined(_WIN64)
#error Vtable-slot hooks require 64-bit Windows.
#endif

namespace {

SRWLOCK g_installLock = SRWLOCK_INIT;

class ExclusiveLock {
public:
    explicit ExclusiveLock(SRWLOCK& lock) noexcept : lock_(lock) {
        AcquireSRWLockExclusive(&lock_);
    }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&lock_); }
    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

private:
    SRWLOCK& lock_;
};

void SetError(wchar_t* error, size_t count, const wchar_t* format, ...) noexcept {
    if (!error || count == 0) return;
    va_list arguments;
    va_start(arguments, format);
    _vsnwprintf_s(error, count, _TRUNCATE, format, arguments);
    va_end(arguments);
}

DWORD WritableProtection(DWORD protection) noexcept {
    if (protection & PAGE_GUARD) return 0;
    switch (protection & 0xff) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
        return PAGE_READWRITE;
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        return PAGE_EXECUTE_READWRITE;
    default:
        return 0;
    }
}

bool QuerySlot(void** slot, DWORD& writableProtection) noexcept {
    const uintptr_t address = reinterpret_cast<uintptr_t>(slot);
    if (address % alignof(void*) != 0 || address > UINTPTR_MAX - sizeof(void*))
        return false;

    MEMORY_BASIC_INFORMATION region = {};
    if (VirtualQuery(slot, &region, sizeof(region)) != sizeof(region) ||
        region.State != MEM_COMMIT)
        return false;

    const uintptr_t start = reinterpret_cast<uintptr_t>(region.BaseAddress);
    if (address < start || region.RegionSize > UINTPTR_MAX - start ||
        address + sizeof(void*) > start + region.RegionSize)
        return false;

    writableProtection = WritableProtection(region.Protect);
    return writableProtection != 0;
}

bool RestoreProtection(void** slot, DWORD originalProtection) noexcept {
    DWORD ignored = 0;
    return VirtualProtect(slot, sizeof(void*), originalProtection, &ignored) != 0;
}

}  // namespace

bool InstallVtableSlot(void** slot, void* expected, void* hook,
                       void** original, wchar_t* error, size_t errorChars) {
    if (error && errorChars) error[0] = L'\0';
    if (!slot || !expected || !hook || !original || expected == hook ||
        slot == original ||
        reinterpret_cast<uintptr_t>(original) % alignof(void*) != 0) {
        SetError(error, errorChars, L"Invalid vtable-slot hook arguments.");
        return false;
    }

    ExclusiveLock lock(g_installLock);
    DWORD writableProtection = 0;
    if (!QuerySlot(slot, writableProtection)) {
        SetError(error, errorChars,
                 L"Vtable slot is unaligned, unreadable, or unsupported.");
        return false;
    }

    DWORD originalProtection = 0;
    if (!VirtualProtect(slot, sizeof(void*), writableProtection,
                        &originalProtection)) {
        SetError(error, errorChars,
                 L"Making vtable slot writable failed (Win32 %lu).",
                 GetLastError());
        return false;
    }

    auto* const atomicSlot = reinterpret_cast<PVOID volatile*>(slot);
    auto* const atomicOriginal = reinterpret_cast<PVOID volatile*>(original);
    // This atomic no-op compare reads the slot after the page is writable.
    // A regular read of a concurrently changing slot would be a data race.
    if (InterlockedCompareExchangePointer(atomicSlot, expected, expected) !=
        expected) {
        const bool restored = RestoreProtection(slot, originalProtection);
        SetError(error, errorChars,
                 restored ? L"Vtable slot does not contain the expected function."
                          : L"Vtable slot mismatch; page protection could not be restored.");
        return false;
    }

    // Any thread that observes hook after the slot CAS must be able to call
    // expected through *original. Keep the published pointer even if the CAS
    // loses a race with an external writer.
    void* const priorOriginal =
        InterlockedCompareExchangePointer(atomicOriginal, expected, nullptr);
    if (priorOriginal != nullptr && priorOriginal != expected) {
        const bool restored = RestoreProtection(slot, originalProtection);
        SetError(error, errorChars,
                 restored ? L"Original pointer already names another function."
                          : L"Original pointer conflict; page protection could not be restored.");
        return false;
    }

    void* const previous =
        InterlockedCompareExchangePointer(atomicSlot, hook, expected);
    if (previous != expected) {
        const bool restored = RestoreProtection(slot, originalProtection);
        SetError(error, errorChars,
                 restored ? L"Vtable slot changed during installation."
                          : L"Vtable slot changed; page protection could not be restored.");
        return false;
    }

    if (RestoreProtection(slot, originalProtection)) return true;

    // The slot is live. If the page cannot be restored, atomically roll back
    // the new hook; never withdraw the published original pointer because a
    // caller may already be executing hook.
    const DWORD restoreError = GetLastError();
    void* const rollback =
        InterlockedCompareExchangePointer(atomicSlot, expected, hook);
    const bool protectionRestored = RestoreProtection(slot, originalProtection);
    if (rollback == hook) {
        SetError(error, errorChars,
                 protectionRestored
                     ? L"Page protection restore failed (Win32 %lu); hook rolled back."
                     : L"Page protection restore failed (Win32 %lu); hook rolled back, but page remains writable.",
                 restoreError);
        return false;
    }

    // An external writer changed the slot after our swap. Do not claim that
    // the hook remains installed, and retain *original for in-flight calls.
    SetError(error, errorChars,
             protectionRestored
                 ? L"Page protection restore failed (Win32 %lu); slot changed externally."
                 : L"Page protection restore failed (Win32 %lu); slot changed externally and page remains writable.",
             restoreError);
    return false;
}
