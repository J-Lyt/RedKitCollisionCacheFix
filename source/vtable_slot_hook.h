#pragma once

#include <stddef.h>

// Atomically replaces one aligned vtable entry after verifying its current
// value. The caller must already have verified the editor build, vtable, and
// slot index. The original function pointer is published before the swap and
// remains valid for the process lifetime; this helper has no uninstall path.
//
// Returns true only while the slot contains hook. On a failed installation,
// *original may still contain expected if a concurrent slot change occurred
// after the original was published. The caller must keep both functions live.
bool InstallVtableSlot(void** slot, void* expected, void* hook,
                       void** original, wchar_t* error, size_t errorChars);
