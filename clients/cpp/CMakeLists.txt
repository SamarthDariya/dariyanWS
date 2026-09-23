# dariyanWS C++ client — the contract, in the language the data planes are written in.
#
# Dependency-free on purpose. This gets vendored into dariyakyu and the other C++ services, and
# none of them should inherit OpenSSL, a brew prefix, or a find_package dance in order to verify
# a signature. SHA-256 and HMAC are bundled and proved correct against published vectors plus the
# Go implementation's golden output.
cmake_minimum_required(VERSION 3.20)
project(dariya_client CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_library(dariya_client
  src/sha256.cpp
  src/hmac.cpp
  src/signer.cpp
)
target_include_directories(dariya_client PUBLIC include)
target_compile_options(dariya_client PRIVATE -Wall -Wextra -Wpedantic)
add_library(dariya::client ALIAS dariya_client)

# The golden vectors live with the Go implementation that generates them, three directories up.
# Passed as a compile definition so the test binary runs from anywhere, and overridable by argv[1]
# for the case where it does not.
set(DARIYA_VECTOR_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../internal/signing/testdata/signing_vectors.txt")

# The rig, vendored as a submodule exactly as dariyaraah vendors it. Optional: the signing client
# above has no dependency on it, so a service repo can vendor just the client. Only the Protocol
# adapter and the benchmark need the rig.
set(DARIYANAAP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/dariyanaap")
if(EXISTS "${DARIYANAAP_DIR}/CMakeLists.txt")
  add_subdirectory(vendor/dariyanaap EXCLUDE_FROM_ALL)

  add_library(dariya_client_load src/http11_signed.cpp)
  target_link_libraries(dariya_client_load PUBLIC dariya::client dariyanaap::load)
  target_compile_options(dariya_client_load PRIVATE -Wall -Wextra -Wpedantic)
  add_library(dariya::client_load ALIAS dariya_client_load)

  add_executable(bench_frontdoor apps/bench_frontdoor.cpp)
  target_link_libraries(bench_frontdoor PRIVATE dariya::client_load)
  target_compile_options(bench_frontdoor PRIVATE -Wall -Wextra -Wpedantic)
else()
  message(STATUS "vendor/dariyanaap absent — skipping the benchmark. "
                 "Run: git submodule update --init --recursive")
endif()

# Tests build only when this is the top-level project, so a service repo vendoring the client
# does not inherit them. dariyanaap establishes this convention and its vendor smoke test asserts
# it; the same rule applies here for the same reason.
if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_executable(vector_test tests/vector_test.cpp)
  target_link_libraries(vector_test PRIVATE dariya::client)
  target_compile_definitions(vector_test PRIVATE DARIYA_VECTOR_FILE="${DARIYA_VECTOR_FILE}")
  target_compile_options(vector_test PRIVATE -Wall -Wextra -Wpedantic)

  add_test(NAME cross_language_vectors COMMAND vector_test)
endif()
