cmake_minimum_required(VERSION 3.24)
project(pq_delivery_proposal_tests LANGUAGES CXX)
enable_testing()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
if(NOT DEFINED CORE_SRC OR NOT DEFINED CORE_BUILD)
  message(FATAL_ERROR "Pass the inspected Core source and matching Release library directory")
endif()
add_library(review_gtest STATIC "${CORE_SRC}/external/gtest/src/gtest-all.cc")
target_include_directories(review_gtest PUBLIC "${CORE_SRC}/external/gtest/include"
  PRIVATE "${CORE_SRC}/external/gtest")
function(review_target name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "${CORE_SRC}/include" "${CORE_SRC}/src"
    "${CORE_SRC}/external" "${CORE_SRC}/src/Platform/Windows"
    "${CORE_BUILD}/version" "${CORE_BUILD}/external/liboqs/include"
    "${CORE_SRC}/external/chacha20poly1305")
  target_compile_definitions(${name} PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0600
    WIN32_LEAN_AND_MEAN NOMINMAX __SSE4_1__ NDEBUG STATICLIB)
  target_compile_options(${name} PRIVATE /O2 /Ob2 /EHsc /bigobj)
  target_link_libraries(${name} PRIVATE review_gtest
    "${CORE_BUILD}/src/Release/CryptoPq.lib"
    "${CORE_BUILD}/external/chacha20poly1305/Release/chacha20poly1305.lib"
    "${CORE_BUILD}/src/Release/CryptoNoteCommon.lib"
    "${CORE_BUILD}/src/Release/Crypto.lib"
    "${CORE_BUILD}/external/liboqs/lib/Release/oqs.lib")
  add_test(NAME ${name} COMMAND ${name} "--gtest_output=xml:${CMAKE_BINARY_DIR}/${name}.xml")
endfunction()
review_target(existing_scan "${CORE_SRC}/tests/test_pq_scan.cpp")
review_target(existing_builder "${CORE_SRC}/tests/test_pq_output_builder.cpp")
review_target(existing_derive "${CORE_SRC}/tests/test_pq_derive.cpp")
review_target(v2_only_prototype prototype.cpp prototype_tests.cpp)
