cmake_minimum_required(VERSION 3.21)
project(redkit_redcloth_asi LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "This ASI must be built for 64-bit Windows.")
endif()
if(NOT MSVC)
  message(FATAL_ERROR "This source snapshot was validated with the MSVC toolchain.")
endif()

# Match the validated proxy's static C/C++ runtime choice.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(redkit_redcloth_asi_general_active_vtable SHARED
  general_active_proxy.cpp
  source_apb_validator.cpp
  vtable_slot_hook.cpp
)
set_target_properties(redkit_redcloth_asi_general_active_vtable PROPERTIES
  PREFIX ""
  OUTPUT_NAME "REDKit_CollisionCache_Fix"
  SUFFIX ".asi"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/asi_general_active_vtable"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/asi_general_active_vtable"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/asi_general_active_vtable"
)
target_compile_features(redkit_redcloth_asi_general_active_vtable PRIVATE cxx_std_17)
target_compile_definitions(redkit_redcloth_asi_general_active_vtable PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)
target_compile_options(redkit_redcloth_asi_general_active_vtable PRIVATE
  /W4 /permissive- /utf-8
)
target_link_libraries(redkit_redcloth_asi_general_active_vtable PRIVATE bcrypt)
