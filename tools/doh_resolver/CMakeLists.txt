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
project(doh_resolver C CXX)
include(${CMAKE_CURRENT_LIST_DIR}/../../example/cmake/BrpcExample.cmake)
option(LINK_SO "Link dynamically" OFF)
brpc_example_find_common_deps(DYNAMIC_LIB)
find_library(RESOLV_LIBRARY resolv)
if(NOT RESOLV_LIBRARY)
    message(FATAL_ERROR "DohResolver requires the system libresolv DNS parser")
endif()
add_library(doh_resolver STATIC doh_resolver.cpp)
brpc_example_configure_target(doh_resolver)
target_include_directories(doh_resolver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${BRPC_INCLUDE_PATH})
target_include_directories(doh_resolver BEFORE PRIVATE ${Protobuf_INCLUDE_DIRS})
target_link_libraries(doh_resolver PUBLIC ${BRPC_LIB} ${DYNAMIC_LIB} ${RESOLV_LIBRARY})

include(CTest)
if(BUILD_TESTING)
    add_executable(doh_resolver_test_client tests/client.cpp)
    brpc_example_configure_target(doh_resolver_test_client)
    target_include_directories(doh_resolver_test_client BEFORE PRIVATE ${Protobuf_INCLUDE_DIRS})
    target_link_libraries(doh_resolver_test_client PRIVATE doh_resolver)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME doh_resolver_https COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/https_test.py
            $<TARGET_FILE:doh_resolver_test_client>)
        set_tests_properties(doh_resolver_https PROPERTIES TIMEOUT 90)
    endif()
endif()
