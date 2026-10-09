# RedKitCollisionCacheFix
Fixes an issue where the CollisionCache fails to cook when a workspace .redcloth has a valid APEX/APB in its source file, but REDkit's attached in-memory cloth resource has an empty APB.

This fix will Reload that resource, then lets the normal physics ProcessFile load it again.

## Build
With CMake 3.21 or newer and Visual Studio 2022 C++ x64 tools installed, extract the ZIP, open a **x64 Native Tools Command Prompt** window and run the following commands:
1. `cd /d "C:\Path\to\RedKitCollisionCacheFix\source\"`
2. `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release`
3. `cmake --build build --target dinput8_general_active_vtable`

Output: `"C:\Path\to\RedKitCollisionCacheFix\source\build\general_active_vtable\dinput8.dll"`
