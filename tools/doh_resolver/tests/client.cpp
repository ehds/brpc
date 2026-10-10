// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Test driver exercises only the public resolver interface.
#include <cstdlib>
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include "doh_resolver.h"
#include "bthread/bthread.h"

int main(int argc, char** argv) {
    if (argc != 9) return 2;
    brpc_tools::DohOptions options;
    options.endpoint = argv[1];
    options.bootstrap_ip = argv[2];
    options.ca_file = argv[3];
    options.max_cache_entries = std::strtoul(argv[8], nullptr, 10);
    brpc_tools::DohResolver resolver;
    auto status = resolver.Init(options);
    if (!status.ok()) { std::cerr << status << std::endl; return 1; }
    const auto family = std::string(argv[5]) == "a" ? brpc_tools::AddressFamily::IPV4
        : (std::string(argv[5]) == "aaaa" ? brpc_tools::AddressFamily::IPV6
                                         : brpc_tools::AddressFamily::BOTH);
    const int timeout = std::atoi(argv[6]);
    const int repeat = std::atoi(argv[7]);
    if (repeat < 0) {
        std::atomic<int> failures{0};
        std::mutex output_mutex;
        std::vector<std::thread> threads;
        for (int i = 0; i < -repeat; ++i) {
            threads.emplace_back([&] {
                brpc_tools::ResolveResult result;
                const auto s = resolver.Resolve(argv[4], timeout, &result, family);
                if (!s.ok() || result.addresses.empty()) ++failures;
                else {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << result.addresses[0] << std::endl;
                }
            });
        }
        for (auto& thread : threads) thread.join();
        return failures ? 1 : 0;
    }
    const std::string repeats = argv[7];
    const auto colon = repeats.find(':');
    const int pause_ms = colon == std::string::npos ? 0 : std::atoi(repeats.c_str() + colon + 1);
    for (int i = 0; i < repeat; ++i) {
        if (i && pause_ms) bthread_usleep(int64_t(pause_ms) * 1000);
        brpc_tools::ResolveResult result;
        result.addresses = {"unchanged"};
        result.ttl_sec = 123;
        status = resolver.Resolve(argv[4], timeout, &result, family);
        if (!status.ok()) {
            if (result.addresses != std::vector<std::string>{"unchanged"} || result.ttl_sec != 123)
                return 3;
            std::cerr << status << std::endl;
            return 1;
        }
        std::cout << "ttl=" << result.ttl_sec;
        for (const auto& ip : result.addresses) std::cout << ' ' << ip;
        std::cout << std::endl;
    }
    return 0;
}
