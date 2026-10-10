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

#include "proxy_rules/matcher.h"

#include "butil/strings/string_util.h"
#include "butil/sys_byteorder.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace proxy_rules {
namespace {
constexpr uint32_t kNoNode = std::numeric_limits<uint32_t>::max();
constexpr size_t kMaxHostname = 253;
using AddressBytes = std::array<uint8_t, 16>;

unsigned Bit(const AddressBytes &bytes, unsigned bit) {
  return (bytes[bit / 8] >> (7 - bit % 8)) & 1;
}
bool ParseDottedDecimal(butil::StringPiece text, uint8_t *bytes) {
  size_t start = 0;
  unsigned octets = 0;
  while (start < text.size()) {
    const size_t dot = text.find('.', start);
    const size_t end = dot == butil::StringPiece::npos ? text.size() : dot;
    const size_t length = end - start;
    if (length == 0 || length > 3 || (length > 1 && text[start] == '0'))
      return false;
    unsigned value = 0;
    for (size_t i = start; i < end; ++i) {
      if (!::IsAsciiDigit(text[i]))
        return false;
      value = value * 10 + (text[i] - '0');
    }
    if (value > 255 || ++octets > 4)
      return false;
    bytes[octets - 1] = static_cast<uint8_t>(value);
    if (dot == butil::StringPiece::npos)
      return octets == 4;
    start = dot + 1;
  }
  return false;
}
unsigned CommonBits(const AddressBytes &a, const AddressBytes &b,
                    unsigned begin, unsigned end) {
  if (begin >= end)
    return end;
  // memcpy permits unaligned addresses and avoids strict-aliasing violations.
  // XOR identifies differing bits; clz locates the first one in network order.
  uint64_t left, right;
  if (begin < 64) {
    memcpy(&left, a.data(), sizeof(left));
    memcpy(&right, b.data(), sizeof(right));
    const uint64_t diff =
        butil::NetToHost64(left ^ right) & (UINT64_MAX >> begin);
    if (diff != 0)
      return std::min(end, static_cast<unsigned>(__builtin_clzll(diff)));
    if (end <= 64)
      return end;
    begin = 64;
  }
  memcpy(&left, a.data() + 8, sizeof(left));
  memcpy(&right, b.data() + 8, sizeof(right));
  const uint64_t diff =
      butil::NetToHost64(left ^ right) & (UINT64_MAX >> (begin - 64));
  return diff == 0
             ? end
             : std::min(end,
                        64u + static_cast<unsigned>(__builtin_clzll(diff)));
}
AddressBytes NetworkBytes(AddressBytes address, unsigned bits) {
  unsigned byte = bits / 8;
  const unsigned remaining = bits % 8;
  if (remaining != 0) {
    address[byte] &= static_cast<uint8_t>(0xffu << (8 - remaining));
    ++byte;
  }
  std::fill(address.begin() + byte, address.end(), 0);
  return address;
}

// Parse either a numeric prefix length or an IPv4 dotted netmask.
// width is the address-family bit count (32 or 128).
butil::Status ParsePrefixLength(butil::StringPiece mask, unsigned width,
                                unsigned *prefix) {
  if (mask.empty())
    return butil::Status(EINVAL, "Missing IP prefix length");
  if (mask.find('.') != butil::StringPiece::npos) {
    std::array<uint8_t, 4> bytes;
    if (width != 32 || !ParseDottedDecimal(mask, bytes.data()))
      return butil::Status(EINVAL, "Invalid IPv4 netmask");
    const uint32_t value = (uint32_t(bytes[0]) << 24) |
                           (uint32_t(bytes[1]) << 16) |
                           (uint32_t(bytes[2]) << 8) | bytes[3];
    const uint32_t inverted = ~value;
    // A valid mask's inverse has only trailing ones, including /0 and /32.
    const uint32_t incremented = static_cast<uint32_t>(inverted + 1u);
    if ((inverted & incremented) != 0)
      return butil::Status(EINVAL, "Non-contiguous netmask");
    *prefix = __builtin_popcount(value);
    return butil::Status::OK();
  }
  unsigned value = 0;
  for (char c : mask) {
    if (!::IsAsciiDigit(c))
      return butil::Status(EINVAL, "Invalid IP prefix length");
    value = value * 10 + (c - '0');
    // Bound each step so an arbitrarily long input cannot overflow.
    if (value > width)
      return butil::Status(EINVAL, "IP prefix length out of range");
  }
  *prefix = value;
  return butil::Status::OK();
}

butil::Status ParseNetwork(butil::StringPiece input, IpAddress *address,
                           unsigned *prefix) {
  const size_t slash = input.find('/');
  const auto host = input.substr(0, slash);
  auto status = IpAddress::Parse(host, address);
  if (!status.ok())
    return status;
  const unsigned width =
      address->family() == IpAddress::Family::IPV4 ? 32 : 128;
  if (slash == butil::StringPiece::npos) {
    *prefix = width;
    return butil::Status::OK();
  }
  return ParsePrefixLength(input.substr(slash + 1), width, prefix);
}

bool NormalizeHostname(butil::StringPiece input,
                       std::array<char, kMaxHostname> *buffer, size_t *length) {
  if (!input.empty() && input.back() == '.')
    input.remove_suffix(1);
  if (input.empty() || input.size() > kMaxHostname)
    return false;
  size_t label_length = 0;
  char prev = '\0';
  for (size_t i = 0; i < input.size(); ++i) {
    unsigned char c = butil::ToLowerASCII(input[i]);
    if (!(::IsAsciiAlpha(c) || ::IsAsciiDigit(c) || c == '-' || c == '.')) {
      return false;
    }
    if (label_length == 0) {
      if (c == '.' || c == '-') {
        // - cannot be start of label
        // . cannot be start of label
        return false;
      }
    }
    if (c == '.') {
      // . cannot be start of label
      // - cannot be end of label
      if (prev == '-')
        return false;
      label_length = 0;
    } else {
      // label_length cannot be greater than 63
      if (++label_length > 63)
        return false;
    }
    (*buffer)[i] = c;
    prev = c;
  }
  // end of label cannot be . or -
  if (prev == '.' || prev == '-')
    return false;

  *length = input.size();
  return true;
}

// Return the next whole label from the right; a label is never split by a
// match.
butil::StringPiece PreviousLabel(butil::StringPiece hostname, size_t *end) {
  size_t begin = *end;
  while (begin > 0 && hostname[begin - 1] != '.')
    --begin;
  const auto label = hostname.substr(begin, *end - begin);
  *end = begin == 0 ? 0 : begin - 1;
  return label;
}

uint64_t EdgeKey(uint32_t parent, uint32_t label) {
  return (uint64_t(parent) << 32) | label;
}
} // namespace

butil::Status IpAddress::Parse(butil::StringPiece text, IpAddress *output) {
  if (output == nullptr)
    return butil::Status(EINVAL, "Missing IP address output");
  if (text.empty() || text.size() >= INET6_ADDRSTRLEN)
    return butil::Status(EINVAL, "Invalid numeric IP address");
  // inet_pton differs across platforms: some accept leading-zero IPv4
  // octets or IPv6 scope suffixes. Keep the rule syntax consistent here.
  const bool ipv6 = text.find(':') != butil::StringPiece::npos;
  IpAddress parsed;
  if (!ipv6) {
    // Validate and convert once; no second scan through inet_pton is needed.
    if (!ParseDottedDecimal(text, parsed._bytes.data()))
      return butil::Status(EINVAL, "Invalid dotted-decimal IPv4 address");
    parsed._family = Family::IPV4;
    *output = parsed;
    return butil::Status::OK();
  }
  if (ipv6) {
    for (unsigned char c : text) {
      if (!(::IsHexDigit(c) || c == ':' || c == '.'))
        return butil::Status(EINVAL, "Invalid bare IPv6 address");
    }
    if (text.find('.') != butil::StringPiece::npos) {
      std::array<uint8_t, 4> embedded;
      if (!ParseDottedDecimal(text.substr(text.rfind(':') + 1),
                              embedded.data()))
        return butil::Status(EINVAL, "Invalid embedded IPv4 address");
    }
  }
  char terminated[INET6_ADDRSTRLEN];
  memcpy(terminated, text.data(), text.size());
  terminated[text.size()] = '\0';
  // The character check above already rejects embedded NUL bytes.
  if (inet_pton(AF_INET6, terminated, parsed._bytes.data()) == 1)
    parsed._family = Family::IPV6;
  else
    return butil::Status(EINVAL, "Invalid numeric IP address");
  *output = parsed;
  return butil::Status::OK();
}

IpPrefixIndex::Node::Node(const AddressBytes &address, unsigned length)
    : network(NetworkBytes(address, length)), prefix(length) {}

IpPrefixIndex::IpPrefixIndex() {
  // Permanent /0 roots keep address families separate, including empty trees.
  _nodes.emplace_back(AddressBytes{}, 0);
  _nodes.emplace_back(AddressBytes{}, 0);
}

uint32_t IpPrefixIndex::NewNode(const AddressBytes &network, unsigned prefix) {
  if (_nodes.size() >= kNoNode)
    throw std::length_error("Too many IP nodes");
  const auto id = static_cast<uint32_t>(_nodes.size());
  _nodes.emplace_back(network, prefix);
  return id;
}

uint32_t IpPrefixIndex::FindOrCreateNode(const AddressBytes &network,
                                         unsigned prefix, uint32_t root) {
  uint32_t parent = root;
  if (prefix == 0)
    return parent;
  for (;;) {
    const unsigned direction = Bit(network, _nodes[parent].prefix);
    const uint32_t next = _nodes[parent].child[direction];
    if (next == kNoNode) {
      const uint32_t leaf = NewNode(network, prefix);
      _nodes[parent].child[direction] = leaf;
      return leaf;
    }
    // Copy before growing nodes: emplace_back can invalidate references.
    const Node existing = _nodes[next];
    const unsigned common =
        CommonBits(network, existing.network, _nodes[parent].prefix,
                   std::min(prefix, existing.prefix));
    if (common < existing.prefix) {
      const uint32_t branch = NewNode(network, common);
      _nodes[parent].child[direction] = branch;
      _nodes[branch].child[Bit(existing.network, common)] = next;
      if (prefix == common)
        return branch;
      const uint32_t leaf = NewNode(network, prefix);
      _nodes[branch].child[Bit(network, common)] = leaf;
      return leaf;
    }
    if (prefix == existing.prefix)
      return next;
    parent = next;
  }
}

bool IpPrefixIndex::AnyIp(const IpAddress &address) const {
  const unsigned width = address.family() == IpAddress::Family::IPV4 ? 32 : 128;
  uint32_t node = width == 32 ? 0 : 1;
  for (;;) {
    const Node &current = _nodes[node];
    if (current.matched)
      return true;
    if (current.prefix == width)
      break;
    const uint32_t next = current.child[Bit(address.bytes(), current.prefix)];
    if (next == kNoNode)
      break;
    const Node &candidate = _nodes[next];
    // Check the skipped bits on a compressed edge once, not all ancestor bits.
    if (CommonBits(address.bytes(), candidate.network, current.prefix,
                   candidate.prefix) != candidate.prefix)
      break;
    node = next;
  }
  return false;
}

butil::Status IpPrefixIndex::Insert(butil::StringPiece network) {
  IpAddress address;
  unsigned prefix;
  const auto status = ParseNetwork(network, &address, &prefix);
  if (!status.ok()) {
    return status;
  }

  const uint32_t root = address.family() == IpAddress::Family::IPV4 ? 0 : 1;
  const uint32_t node = FindOrCreateNode(address.bytes(), prefix, root);
  _nodes[node].matched = true;
  return butil::Status::OK();
}

size_t HostnameTrie::EdgeHasher::operator()(uint64_t key) const {
  // Mix both IDs: identity hashing with power-of-two buckets would put
  // every edge with the same label in one bucket, regardless of parent.
  key ^= key >> 33;
  key *= UINT64_C(0xff51afd7ed558ccd);
  key ^= key >> 33;
  key *= UINT64_C(0xc4ceb9fe1a85ec53);
  key ^= key >> 33;
  return static_cast<size_t>(key);
}

HostnameTrie::HostnameTrie() : _nodes(1) {}

uint32_t HostnameTrie::FindOrCreateNode(butil::StringPiece hostname) {
  uint32_t parent = 0;
  size_t end = hostname.size();
  while (end > 0) {
    const butil::StringPiece label = PreviousLabel(hostname, &end);
    const uint32_t *found_label = _labels.seek(label);
    uint32_t label_id;
    if (found_label)
      label_id = *found_label;
    else {
      if (_labels.size() >= kNoNode)
        throw std::length_error("Too many labels");
      label_id = static_cast<uint32_t>(_labels.size());
      if (!_labels.insert(label.as_string(), label_id))
        throw std::bad_alloc();
    }
    const uint64_t key = EdgeKey(parent, label_id);
    const uint32_t *found_edge = _edges.seek(key);
    if (found_edge)
      parent = *found_edge;
    else {
      if (_nodes.size() >= kNoNode)
        throw std::length_error("Too many domain nodes");
      const auto child = static_cast<uint32_t>(_nodes.size());
      _nodes.emplace_back();
      if (!_edges.insert(key, child))
        throw std::bad_alloc();
      parent = child;
    }
  }
  return parent;
}
bool HostnameTrie::AnyHostname(butil::StringPiece hostname) const {
  std::array<char, kMaxHostname> normalized;
  size_t length;
  if (!NormalizeHostname(hostname, &normalized, &length))
    return false;
  const butil::StringPiece input(normalized.data(), length);
  uint32_t parent = 0;
  size_t end = length;
  while (end > 0) {
    const auto label = PreviousLabel(input, &end);
    const uint32_t *label_id = _labels.seek(label);
    if (!label_id)
      break;
    const uint32_t *child = _edges.seek(EdgeKey(parent, *label_id));
    if (!child)
      break;
    parent = *child;
    const Node &node = _nodes[parent];
    if (node.suffix || (end == 0 && node.exact))
      return true;
  }
  return false;
}

butil::Status HostnameTrie::Insert(HostnameMatch match,
                                   butil::StringPiece hostname) {
  if (match != HostnameMatch::EXACT && match != HostnameMatch::SUFFIX) {
    return butil::Status(EINVAL, "Invalid hostname match type");
  }
  std::array<char, kMaxHostname> normalized;
  size_t length;
  if (!NormalizeHostname(hostname, &normalized, &length)) {
    return butil::Status(EINVAL, "Invalid hostname rule");
  }

  const uint32_t node = FindOrCreateNode({normalized.data(), length});
  if (match == HostnameMatch::EXACT) {
    _nodes[node].exact = true;
  } else {
    _nodes[node].suffix = true;
  }
  return butil::Status::OK();
}
} // namespace proxy_rules
