cmake_minimum_required(VERSION 3.22)
project(opaquepp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Forcer le runtime MSVC (assure cohérence avec la crate Rust sur Windows)
#if(MSVC)
#  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING "" FORCE)
#  #set_target_properties(opaquepp PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
#endif()

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

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(RUST_PROFILE "dev")
    set(CRATE_STRATEGY "cdylib")
else()
    set(RUST_PROFILE "release")
    set(CRATE_STRATEGY "staticlib")
endif()

# Import de la crate rust
corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/opaque_rust/Cargo.toml
    OVERRIDE_CRATE_TYPE opaque_rust=${CRATE_STRATEGY}
    CRATE_TYPES ${CRATE_STRATEGY}
    PROFILE ${RUST_PROFILE}
    FLAGS --crate-type=${CRATE_STRATEGY}
)

corrosion_add_cxxbridge(opaque_bridge
    CRATE opaque_rust
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/opaque_rust/Cargo.toml"
    FILES "lib.rs"
)

#corrosion_add_cxxbridge(opaque_bridge
#    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/opaque_rust/Cargo.toml"
#    FILES "src/lib.rs" # Path relative to the Cargo.toml
#)

enable_testing()

# --- Bibliothèque statique C++ (code réutilisable) -------------------------
add_library(opaquepp OBJECT
  src/opaque-rust.cpp
  src/opaque-rust.h
  src/opaque++.cpp
  src/opaque++.h
  "${CXX_SUPPORT_SOURCE}"
)

# Inclure les headers de la bibliothèque
target_include_directories(opaquepp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")

# Propager includes/options fournis par la crate Rust
target_include_directories(opaquepp
  PUBLIC
    $<TARGET_PROPERTY:opaque_rust,INTERFACE_INCLUDE_DIRECTORIES>
)

# Add this to ensure C++ knows where the cxx support headers are in Release
target_include_directories(opaquepp PUBLIC ${CORROSION_CXX_INCLUDE_DIR})

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
target_link_libraries(opaquepp PUBLIC opaque_rust opaque_bridge)

if(WIN32)
  target_link_libraries(opaquepp PUBLIC bcrypt)
endif()

# --- Exemples (chaque exécutable peut avoir son propre main) -------------
add_executable(example_class src/example-class.cpp)
target_link_libraries(example_class PRIVATE opaquepp opaque_bridge)

# If your examples/tests include your C++ headers, they need it too
target_include_directories(example_class PRIVATE ${CORROSION_CXX_INCLUDE_DIR})

add_executable(example_rust src/example-rust.cpp)
target_link_libraries(example_rust PRIVATE opaquepp)

#if(MSVC)
#  target_link_options(example_class PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:opaquepp>")
#  target_link_options(example_rust  PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:opaquepp>")
#endif()
    
# --- Tests ---------------------------------------------------------------
add_subdirectory(tests)

message(STATUS "Corrosion crate imported as target: opaque_rust")
