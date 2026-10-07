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
project(http_proxy C CXX)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/BrpcExample.cmake)
option(LINK_SO "Link dynamically" OFF)
brpc_example_find_common_deps(DYNAMIC_LIB)
add_executable(http_proxy server.cpp)
brpc_example_configure_target(http_proxy)
target_include_directories(http_proxy BEFORE PRIVATE ${Protobuf_INCLUDE_DIRS})
target_link_libraries(http_proxy PRIVATE ${BRPC_LIB} ${DYNAMIC_LIB})
