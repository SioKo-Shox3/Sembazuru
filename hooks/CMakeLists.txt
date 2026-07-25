cmake_minimum_required(VERSION 3.21)
project(sembazuru-hooks LANGUAGES CXX)
enable_testing()

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
# The DLL name must end in "64" (or "32"): when a process carrying the hook DLL
# spawns a child of the OTHER bitness, Detours derives the sibling DLL name from
# that suffix and injects it (M7.3 cross-bitness child injection). So we name the
# DLL by the build's target architecture: an x64 build yields sbz_interceptor64,
# an x86 build (cmake -A Win32) yields sbz_interceptor32. CI builds both and
# places them side by side so the sibling lookup finds the other bitness.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(SBZ_INTERCEPTOR sbz_interceptor64)
else()
  set(SBZ_INTERCEPTOR sbz_interceptor32)
endif()
add_library(${SBZ_INTERCEPTOR} SHARED
  src/interceptor.cpp
  src/vfs_attestation.cpp
  src/trace_writer.cpp
  src/interceptor.def
)
target_link_libraries(${SBZ_INTERCEPTOR} PRIVATE detours)

add_executable(launcher src/launcher.cpp src/vfs_attestation.cpp)
target_link_libraries(launcher PRIVATE detours)

# Cross-bitness injection probe (M7.3). A tiny target the 32-bit build turns into
# a 32-bit child for m7_inject32.ps1; no Detours dependency (it is the injectee).
add_executable(probe test/probe.cpp)

# Production-neutral child-injection failure probe. The integration script
# injects a temporary x64 hook without its x86 sibling, then proves a real
# cross-bitness injection failure cannot run an unhooked VFS child.
add_executable(process_injection_failure_probe
  test/process_injection_failure_probe.cpp
)

# Trace writer tests include the implementation directly with Win32 I/O seams
# substituted in the test translation unit.  This keeps the injected DLL free
# of test-only exports, globals, and runtime switches.
add_executable(trace_writer_faults test/trace_writer_faults.cpp)
add_test(NAME trace_writer_faults COMMAND trace_writer_faults)

add_executable(vfs_attestation_payload_faults
  test/vfs_attestation_payload_faults.cpp
  src/vfs_attestation.cpp
)
target_link_libraries(vfs_attestation_payload_faults PRIVATE detours)
target_include_directories(vfs_attestation_payload_faults PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME vfs_attestation_payload_faults COMMAND vfs_attestation_payload_faults)

add_executable(trace_write_probe test/trace_write_probe.cpp)
add_test(NAME trace_write_probe_help COMMAND trace_write_probe --help)
