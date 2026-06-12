cmake_minimum_required(VERSION 3.21)
project(sembazuru-hooks LANGUAGES CXX)

# The hook layer is deliberately thin C++ on Win32; everything else is Rust.
# See docs/DESIGN.md §4.
if(NOT MSVC)
  message(FATAL_ERROR "The hook layer targets Windows/MSVC only.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Vendored Detours (MIT) — see third_party/detours/VENDORED.md -----------
# uimports.cpp is #included by creatwth.cpp, and the disol*.cpp files are
# #included by disasm.cpp; neither group may be compiled standalone.
set(DETOURS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/detours)
add_library(detours STATIC
  ${DETOURS_DIR}/detours.cpp
  ${DETOURS_DIR}/modules.cpp
  ${DETOURS_DIR}/disasm.cpp
  ${DETOURS_DIR}/image.cpp
  ${DETOURS_DIR}/creatwth.cpp
)
target_include_directories(detours PUBLIC ${DETOURS_DIR})
target_compile_definitions(detours PRIVATE WIN32_LEAN_AND_MEAN)

# --- M1 tracer: observe-only interceptor + injection launcher ---------------
# The DLL name must end in "64" (or "32"): Detours' cross-bitness child
# injection derives the sibling DLL name from that suffix.
add_library(sbz_interceptor64 SHARED
  src/interceptor.cpp
  src/trace_writer.cpp
  src/interceptor.def
)
target_link_libraries(sbz_interceptor64 PRIVATE detours)

add_executable(launcher src/launcher.cpp)
target_link_libraries(launcher PRIVATE detours)
