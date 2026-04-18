cmake_minimum_required(VERSION 3.22)
project(opaquepp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Forcer le runtime MSVC (assure cohérence avec la crate Rust sur Windows)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING "" FORCE)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)
if(supported)
  message(STATUS "IPO / LTO enabled")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()

include(FetchContent)

# GoogleTest
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(googletest)

# Corrosion (Rust <-> CMake)
FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

# Import de la crate rust
corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/opaque_rust/Cargo.toml)

enable_testing()

# --- Bibliothèque statique C++ (code réutilisable) -------------------------
add_library(opaquepp STATIC
  src/opaque-rust.cpp
  src/opaque++.cpp
)

# Inclure les headers de la bibliothèque
target_include_directories(opaquepp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")

# Propager includes/options fournis par la crate Rust
target_include_directories(opaquepp
  PUBLIC
    $<TARGET_PROPERTY:opaque_rust,INTERFACE_INCLUDE_DIRECTORIES>
)

target_compile_definitions(opaquepp
  PUBLIC
    $<TARGET_PROPERTY:opaque_rust,INTERFACE_COMPILE_DEFINITIONS>
)

target_compile_options(opaquepp
  PUBLIC
    $<TARGET_PROPERTY:opaque_rust,INTERFACE_COMPILE_OPTIONS>
)

target_link_options(opaquepp
  PUBLIC
    $<TARGET_PROPERTY:opaque_rust,INTERFACE_LINK_OPTIONS>
)

# Lie la librairie Rust
target_link_libraries(opaquepp PUBLIC opaque_rust)

if(WIN32)
  target_link_libraries(opaquepp PUBLIC bcrypt)
endif()

# --- Exemples (chaque exécutable peut avoir son propre main) -------------
add_executable(example_class src/example-class.cpp)
target_link_libraries(example_class PRIVATE opaquepp)

add_executable(example_rust src/example-rust.cpp)
target_link_libraries(example_rust PRIVATE opaquepp)

# --- Tests ---------------------------------------------------------------
add_subdirectory(tests)

message(STATUS "Corrosion crate imported as target: opaque_rust")
