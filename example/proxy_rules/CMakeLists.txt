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
project(proxy_rules C CXX)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/BrpcExample.cmake)
option(LINK_SO "Link dynamically" OFF)
brpc_example_find_common_deps(DYNAMIC_LIB)

add_library(proxy_rules STATIC matcher.cpp)
brpc_example_configure_target(proxy_rules)
target_include_directories(proxy_rules PUBLIC
    include ${BRPC_INCLUDE_PATH} ${GFLAGS_INCLUDE_PATH})
target_include_directories(proxy_rules BEFORE PRIVATE ${Protobuf_INCLUDE_DIRS})
target_compile_features(proxy_rules PUBLIC cxx_std_14)
target_link_libraries(proxy_rules PUBLIC ${BRPC_LIB} ${DYNAMIC_LIB})

include(CTest)
if(BUILD_TESTING)
    set(PROXY_RULES_GTEST_SOURCE_DIR "" CACHE PATH "Existing googletest source directory")
    if(PROXY_RULES_GTEST_SOURCE_DIR)
        add_subdirectory(${PROXY_RULES_GTEST_SOURCE_DIR} googletest EXCLUDE_FROM_ALL)
    else()
        find_package(GTest REQUIRED)
    endif()
    add_executable(proxy_rules_unittest ../../test/proxy_rules_unittest.cpp)
    target_link_libraries(proxy_rules_unittest PRIVATE proxy_rules GTest::gtest_main)
    add_test(NAME proxy_rules_unittest COMMAND proxy_rules_unittest)
endif()
