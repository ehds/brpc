# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 3.16...3.28)
project(vmess_proxy C CXX)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/BrpcExample.cmake)
option(LINK_SO "Link dynamically" OFF)
brpc_example_find_common_deps(DYNAMIC_LIB)
if(OPENSSL_VERSION VERSION_LESS 3)
    message(FATAL_ERROR "The reused VMess codec requires OpenSSL 3 or newer")
endif()

add_library(vmess_codec STATIC
    codec/src/common.cpp codec/src/crypto.cpp codec/src/kdf.cpp
    codec/src/uuid.cpp codec/src/header.cpp codec/src/chunk.cpp
    codec/src/ws_frame.cpp)
target_include_directories(vmess_codec PUBLIC codec/include)
target_compile_features(vmess_codec PUBLIC cxx_std_20)
target_link_libraries(vmess_codec PUBLIC OpenSSL::Crypto)

add_executable(vmess_proxy server.cpp vmess_upstream.cpp ws_codec.cpp
               ../socks5_proxy/mixed_server.cpp)
brpc_example_configure_target(vmess_proxy)
target_include_directories(vmess_proxy BEFORE PRIVATE ${Protobuf_INCLUDE_DIRS})
target_compile_definitions(vmess_proxy PRIVATE BRPC_PROXY_EXAMPLE_NO_MAIN)
target_link_libraries(vmess_proxy PRIVATE vmess_codec ${BRPC_LIB} ${DYNAMIC_LIB})

include(CTest)
if(BUILD_TESTING)
    add_executable(vmess_fake_peer tests/fake_peer.cpp ws_codec.cpp)
    target_link_libraries(vmess_fake_peer PRIVATE vmess_codec)
    foreach(name crypto kdf header chunk chunk_reader ws_frame)
        add_executable(vmess_test_${name} codec/tests/test_${name}.cpp)
        target_link_libraries(vmess_test_${name} PRIVATE vmess_codec)
        add_test(NAME vmess_${name} COMMAND vmess_test_${name})
    endforeach()
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME vmess_proxy_smoke COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/smoke_test.py
            $<TARGET_FILE:vmess_proxy> $<TARGET_FILE:vmess_fake_peer>)
        set_tests_properties(vmess_proxy_smoke PROPERTIES TIMEOUT 90)
    endif()
endif()
