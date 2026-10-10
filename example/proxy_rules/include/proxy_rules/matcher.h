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

#ifndef BRPC_EXAMPLE_PROXY_RULES_MATCHER_H
#define BRPC_EXAMPLE_PROXY_RULES_MATCHER_H

#include "butil/containers/flat_map.h"
#include "butil/status.h"
#include "butil/strings/string_piece.h"
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace proxy_rules {
// IP bytes are in network order; IPv4 uses the first four bytes. No DNS or
// conversion between IPv4 and IPv4-mapped IPv6 is performed.
class IpAddress {
public:
  enum class Family { IPV4, IPV6 };
  // Bare numeric addresses only. Failure leaves output unchanged.
  static butil::Status Parse(butil::StringPiece text, IpAddress *output);
  Family family() const { return _family; }
  const std::array<uint8_t, 16> &bytes() const { return _bytes; }

private:
  Family _family = Family::IPV4;
  std::array<uint8_t, 16> _bytes{};
};

// Separate IPv4/IPv6 Patricia trees. AnyIp stops at the first match and
// performs no runtime allocation.
class IpPrefixIndex {
public:
  IpPrefixIndex();
  IpPrefixIndex(const IpPrefixIndex &) = delete;
  IpPrefixIndex &operator=(const IpPrefixIndex &) = delete;
  // Numeric IP, CIDR, or IPv4 with a contiguous dotted-decimal netmask.
  // Duplicate prefixes are merged. Invalid input leaves the index unchanged.
  // Insert must not run concurrently with queries or other insertions.
  butil::Status Insert(butil::StringPiece network);
  bool AnyIp(const IpAddress &ip) const;

private:
  using AddressBytes = std::array<uint8_t, 16>;
  struct Node {
    Node(const AddressBytes &address, unsigned length);
    AddressBytes network;
    unsigned prefix;
    uint32_t child[2] = {std::numeric_limits<uint32_t>::max(),
                         std::numeric_limits<uint32_t>::max()};
    bool matched = false;
  };
  uint32_t NewNode(const AddressBytes &network, unsigned prefix);
  uint32_t FindOrCreateNode(const AddressBytes &network, unsigned prefix,
                      uint32_t root);

  std::vector<Node> _nodes;
};

enum class HostnameMatch { EXACT, SUFFIX };

// Reverse-label Trie: com -> example -> api. SUFFIX includes the domain itself
// and descendants; EXACT only matches when the entire input has been consumed.
// ASCII LDH hostnames only; convert international names to IDNA ASCII upstream.
class HostnameTrie {
public:
  HostnameTrie();
  HostnameTrie(const HostnameTrie &) = delete;
  HostnameTrie &operator=(const HostnameTrie &) = delete;
  // Duplicate rules are merged. Invalid input leaves the index unchanged.
  // Insert must not run concurrently with queries or other insertions.
  butil::Status Insert(HostnameMatch match, butil::StringPiece hostname);
  // ASCII case-insensitive, with one optional terminal dot. Invalid input
  // is a non-match. Queries normalize into a stack buffer, without allocating.
  bool AnyHostname(butil::StringPiece hostname) const;

private:
  struct Node {
    bool suffix = false;
    bool exact = false;
  };
  struct EdgeHasher {
    size_t operator()(uint64_t key) const;
  };
  uint32_t FindOrCreateNode(butil::StringPiece hostname);

  // Share labels and edges across nodes, avoiding a hash table per node.
  butil::FlatMap<std::string, uint32_t> _labels;
  butil::FlatMap<uint64_t, uint32_t, EdgeHasher> _edges;
  std::vector<Node> _nodes;
};
} // namespace proxy_rules
#endif
