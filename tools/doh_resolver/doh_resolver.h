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

#ifndef BRPC_TOOLS_DOH_RESOLVER_H
#define BRPC_TOOLS_DOH_RESOLVER_H

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include "butil/status.h"

namespace brpc_tools {
enum class AddressFamily { IPV4, IPV6, BOTH };

struct DohOptions {
    std::string endpoint;       // HTTPS URL, e.g. https://resolver.example/dns-query.
    std::string bootstrap_ip;   // Optional numeric IP; retain endpoint's TLS/Host name.
    std::string ca_file;        // Empty uses OpenSSL's default trust store.
    int connect_timeout_ms = 1000;
    size_t max_cache_entries = 256;  // 0 disables the positive-result cache.
};

struct ResolveResult {
    std::vector<std::string> addresses;  // Numeric IPv4 / IPv6, with no port.
    uint32_t ttl_sec = 0;  // Minimum remaining TTL across returned records/CNAMEs.
};

class DohResolver {
public:
    DohResolver();
    ~DohResolver();
    // Initialize once, before concurrent use.
    butil::Status Init(const DohOptions& options);
    // Requires successful Init, a non-null out and timeout_ms > 0.
    // family must be a declared AddressFamily value.
    // Thread-safe synchronous call, suitable for bthreads. A and AAAA share
    // one timeout budget. A successful family may be returned if the other
    // fails. IP literals bypass DNS/cache and have TTL 0. On error, out is unchanged.
    butil::Status Resolve(const std::string& host, int timeout_ms,
                          ResolveResult* out,
                          AddressFamily family = AddressFamily::BOTH);
    DohResolver(const DohResolver&) = delete;
    DohResolver& operator=(const DohResolver&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> _impl;
};
}  // namespace brpc_tools
#endif
