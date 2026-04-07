# Tests using GoogleTest

# Test executable
add_executable(tests_opaque
  test_opaque.cpp
)

# Link GoogleTest and the static library 'opaquepp'
target_link_libraries(tests_opaque
  PRIVATE
    gtest_main
    opaquepp
)

# Ensure Windows bcrypt is linked if needed (propagated by opaquepp)
if(WIN32)
  target_link_libraries(tests_opaque PRIVATE bcrypt)
endif()

# Propagate include dirs/compile options from the 'opaquepp' library
target_include_directories(tests_opaque PRIVATE $<TARGET_PROPERTY:opaquepp,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_definitions(tests_opaque PRIVATE $<TARGET_PROPERTY:opaquepp,INTERFACE_COMPILE_DEFINITIONS>)
target_compile_options(tests_opaque PRIVATE $<TARGET_PROPERTY:opaquepp,INTERFACE_COMPILE_OPTIONS>)
target_link_options(tests_opaque PRIVATE $<TARGET_PROPERTY:opaquepp,INTERFACE_LINK_OPTIONS>)

# Make sure the tests depend on the Rust target being built (via opaquepp -> opaque_rust)
add_dependencies(tests_opaque opaque_rust)

# Register test with CTest
include(GoogleTest)
gtest_discover_tests(tests_opaque)