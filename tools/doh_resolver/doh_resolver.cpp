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

#include "doh_resolver.h"

#include "brpc/channel.h"
#include "brpc/controller.h"
#include "brpc/uri.h"
#include "bthread/mutex.h"
#include "butil/time.h"
#include <algorithm>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cerrno>
#include <climits>
#include <mutex>
#include <resolv.h>
#include <unordered_map>

namespace brpc_tools {
namespace {
std::string Canonical(std::string name) {
  if (!name.empty() && name.back() == '.')
    name.pop_back();
  for (char &c : name)
    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';
  return name;
}
std::string Literal(const std::string &host) {
  unsigned char bytes[16];
  char text[INET6_ADDRSTRLEN];
  for (int family : {AF_INET, AF_INET6}) {
    if (inet_pton(family, host.c_str(), bytes) == 1 &&
        inet_ntop(family, bytes, text, sizeof(text)))
      return text;
  }
  return {};
}
bool ValidName(const std::string &name) {
  if (name.empty() || name.size() > 253)
    return false;
  size_t label = 0;
  for (unsigned char c : name) {
    if (c == '.') {
      if (!label || label > 63)
        return false;
      label = 0;
    } else {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_'))
        return false;
      ++label;
    }
  }
  return label && label <= 63;
}
std::vector<uint16_t> QueryTypes(AddressFamily family) {
  switch (family) {
  case AddressFamily::IPV4:
    return {ns_t_a};
  case AddressFamily::IPV6:
    return {ns_t_aaaa};
  default:
    return {ns_t_a, ns_t_aaaa};
  }
}
std::string Query(const std::string &name, uint16_t type) {
  // ID=0, recursion desired, one IN question. HTTPS correlates responses.
  std::string wire("\0\0\1\0\0\1\0\0\0\0\0\0", 12);
  size_t start = 0;
  for (;;) {
    const size_t dot = name.find('.', start);
    const size_t end = dot == std::string::npos ? name.size() : dot;
    wire.push_back(static_cast<char>(end - start));
    wire.append(name, start, end - start);
    if (dot == std::string::npos)
      break;
    start = dot + 1;
  }
  wire.push_back(0);
  wire.push_back(static_cast<char>(type >> 8));
  wire.push_back(static_cast<char>(type));
  wire.append("\0\1", 2);
  return wire;
}
butil::Status Decode(const std::string &wire, const std::string &name,
                     uint16_t type, ResolveResult *out) {
  ns_msg message;
  const auto *bytes = reinterpret_cast<const unsigned char *>(wire.data());
  if (ns_initparse(bytes, wire.size(), &message) != 0)
    return butil::Status(EPROTO, "Malformed DNS response");
  if (ns_msg_id(message) != 0 || !ns_msg_getflag(message, ns_f_qr) ||
      ns_msg_getflag(message, ns_f_opcode) != ns_o_query ||
      ns_msg_getflag(message, ns_f_tc) || ns_msg_count(message, ns_s_qd) != 1)
    return butil::Status(EPROTO, "Invalid DNS response header");
  ns_rr question;
  if (ns_parserr(&message, ns_s_qd, 0, &question) != 0 ||
      Canonical(ns_rr_name(question)) != name || ns_rr_type(question) != type ||
      ns_rr_class(question) != ns_c_in)
    return butil::Status(EPROTO, "DNS response question mismatch");
  const int rcode = ns_msg_getflag(message, ns_f_rcode);
  if (rcode != ns_r_noerror)
    return butil::Status(rcode == ns_r_nxdomain ? ENOENT : EHOSTUNREACH,
                         "DNS response RCODE=%d", rcode);
  struct Record {
    std::string owner, value;
    uint32_t ttl;
    uint16_t type;
  };
  std::vector<Record> records;
  for (int i = 0; i < ns_msg_count(message, ns_s_an); ++i) {
    ns_rr rr;
    if (ns_parserr(&message, ns_s_an, i, &rr) != 0)
      return butil::Status(EPROTO, "Malformed DNS answer");
    if (ns_rr_class(rr) != ns_c_in)
      continue;
    char text[NS_MAXDNAME];
    const uint16_t kind = ns_rr_type(rr);
    if (kind == ns_t_cname) {
      // libresolv handles compression pointers, bounds and pointer loops.
      const int n = ns_name_uncompress(bytes, bytes + wire.size(),
                                       ns_rr_rdata(rr), text, sizeof(text));
      if (n < 0 || n != ns_rr_rdlen(rr))
        return butil::Status(EPROTO, "Malformed DNS CNAME");
    } else if (kind == type) {
      const bool ipv4 = type == ns_t_a;
      if (ns_rr_rdlen(rr) != (ipv4 ? 4 : 16) ||
          !inet_ntop(ipv4 ? AF_INET : AF_INET6, ns_rr_rdata(rr), text,
                     sizeof(text)))
        return butil::Status(EPROTO, "Malformed DNS address");
    } else
      continue;
    records.push_back(
        {Canonical(ns_rr_name(rr)), Canonical(text), ns_rr_ttl(rr), kind});
  }
  ResolveResult result;
  std::string owner = name;
  uint32_t ttl = UINT32_MAX;
  std::vector<std::string> visited;
  for (size_t depth = 0; depth <= records.size(); ++depth) {
    if (std::find(visited.begin(), visited.end(), owner) != visited.end())
      return butil::Status(EPROTO, "DNS CNAME loop");
    visited.push_back(owner);
    const Record *alias = nullptr;
    for (const auto &rr : records) {
      if (rr.owner != owner)
        continue;
      if (rr.type == ns_t_cname) {
        if (alias && alias->value != rr.value)
          return butil::Status(EPROTO, "Conflicting DNS CNAMEs");
        alias = &rr;
        ttl = std::min(ttl, rr.ttl);
      } else {
        if (std::find(result.addresses.begin(), result.addresses.end(),
                      rr.value) == result.addresses.end())
          result.addresses.push_back(rr.value);
        ttl = std::min(ttl, rr.ttl);
      }
    }
    if (alias && !result.addresses.empty())
      return butil::Status(EPROTO, "DNS owner has both CNAME and address");
    if (!result.addresses.empty()) {
      result.ttl_sec = ttl;
      *out = std::move(result);
      return butil::Status::OK();
    }
    if (!alias)
      break;
    owner = alias->value;
  }
  return butil::Status(ENOENT, "DNS response has no matching address");
}
} // namespace

struct DohResolver::Impl {
  struct Cached {
    ResolveResult result;
    int64_t expires_us;
  };
  brpc::Channel channel;
  DohOptions options;
  std::string host_header;
  bthread::Mutex mutex;
  std::unordered_map<std::string, Cached> cache;

  // Configure the channel and publish its matching request/cache options.
  butil::Status Init(const DohOptions &config);

  bool ReadCache(const std::string &key, ResolveResult *result) {
    std::lock_guard<bthread::Mutex> lock(mutex);
    const auto found = cache.find(key);
    if (found == cache.end())
      return false;
    const auto remaining =
        found->second.expires_us - butil::monotonic_time_us();
    if (remaining < 1000000) {
      cache.erase(found);
      return false;
    }
    *result = found->second.result;
    result->ttl_sec = remaining / 1000000;
    return true;
  }

  void StoreCache(const std::string &key, const ResolveResult &result,
                  int64_t expires_us) {
    if (!options.max_cache_entries || !result.ttl_sec)
      return;
    std::lock_guard<bthread::Mutex> lock(mutex);
    if (cache.size() >= options.max_cache_entries)
      cache.erase(cache.begin());
    cache[key] = {result, expires_us};
  }

  butil::Status Lookup(const std::string &name, uint16_t type, int timeout_ms,
                       ResolveResult *result) {
    brpc::Controller controller;
    controller.set_timeout_ms(timeout_ms);
    controller.http_request().uri() = options.endpoint;
    controller.http_request().set_method(brpc::HTTP_METHOD_POST);
    controller.http_request().set_content_type("application/dns-message");
    controller.http_request().SetHeader("Accept", "application/dns-message");
    controller.http_request().SetHeader("Host", host_header);
    controller.request_attachment().append(Query(name, type));
    channel.CallMethod(nullptr, &controller, nullptr, nullptr, nullptr);
    if (controller.Failed())
      return butil::Status(controller.ErrorCode(), "%s",
                           controller.ErrorText().c_str());
    if (controller.http_response().status_code() != brpc::HTTP_STATUS_OK)
      return butil::Status(EIO, "DoH HTTP status=%d",
                           controller.http_response().status_code());
    const auto &content_type = controller.http_response().content_type();
    auto media = content_type.substr(0, content_type.find(';'));
    const auto first = media.find_first_not_of(" \t");
    const auto last = media.find_last_not_of(" \t");
    media =
        first == std::string::npos ? "" : media.substr(first, last - first + 1);
    for (char &c : media)
      if (c >= 'A' && c <= 'Z')
        c += 'a' - 'A';
    if (media != "application/dns-message")
      return butil::Status(EPROTO, "Invalid DoH response Content-Type");
    if (controller.response_attachment().size() > 65535)
      return butil::Status(EMSGSIZE, "DoH DNS response exceeds 65535 bytes");
    auto status = Decode(controller.response_attachment().to_string(), name,
                         type, result);
    if (!status.ok())
      return status;
    if (const auto *age = controller.http_response().GetHeader("Age")) {
      uint64_t seconds = 0;
      if (age->empty())
        return butil::Status(EPROTO, "Invalid HTTP Age");
      for (char c : *age) {
        if (c < '0' || c > '9' || seconds > (UINT32_MAX - (c - '0')) / 10)
          return butil::Status(EPROTO, "Invalid HTTP Age");
        seconds = seconds * 10 + (c - '0');
      }
      result->ttl_sec =
          seconds >= result->ttl_sec ? 0 : result->ttl_sec - seconds;
    }
    return butil::Status::OK();
  }
};

DohResolver::DohResolver() : _impl(new Impl) {}
DohResolver::~DohResolver() = default;

butil::Status DohResolver::Impl::Init(const DohOptions &config) {
  brpc::URI uri;
  if (config.connect_timeout_ms <= 0 ||
      uri.SetHttpURL(config.endpoint) != 0 || uri.scheme() != "https" ||
      uri.host().empty() || !uri.user_info().empty() ||
      !uri.fragment().empty() || uri.port() == 0 || uri.port() > 65535) {
    return butil::Status(EINVAL, "Invalid DoH HTTPS endpoint/options");
  }
  std::string host = uri.host();
  // IPv6 literals in URLs are bracketed, e.g. [::1]. Remove the brackets for
  // IP parsing and certificate name checks; this does not validate IPv6.
  if (host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  brpc::ChannelOptions channel_options;
  channel_options.protocol = brpc::PROTOCOL_HTTP;
  channel_options.connect_timeout_ms = config.connect_timeout_ms;
  channel_options.max_retry = 0;
  auto *ssl = channel_options.mutable_ssl_options();
  ssl->sni_name = Literal(host).empty() ? host : "";
  ssl->verify.verify_depth = 10;
  ssl->verify.verify_mode = brpc::VerifyMode::VERIFY_PEER;
  ssl->verify.expected_peer_name = host;
  ssl->verify.ca_file_path = config.ca_file;
  if (!config.bootstrap_ip.empty() && Literal(config.bootstrap_ip).empty())
    return butil::Status(EINVAL, "DoH bootstrap_ip must be numeric");
  const int port = uri.port() < 0 ? 443 : uri.port();
  const std::string address =
      config.bootstrap_ip.empty() ? host : config.bootstrap_ip;
  if (channel.Init(address.c_str(), port, &channel_options) != 0)
    return butil::Status(EIO, "Fail to initialize DoH HTTPS channel");
  options = config;
  host_header = uri.host();
  if (uri.port() >= 0)
    host_header += ':' + std::to_string(port);
  return butil::Status::OK();
}

butil::Status DohResolver::Init(const DohOptions &options) {
  return _impl->Init(options);
}

butil::Status DohResolver::Resolve(const std::string &host, int timeout_ms,
                                   ResolveResult *out, AddressFamily family) {
  const auto ip = Literal(host);
  if (!ip.empty()) {
    const bool ipv6 = ip.find(':') != std::string::npos;
    if ((family == AddressFamily::IPV4 && ipv6) ||
        (family == AddressFamily::IPV6 && !ipv6))
      return butil::Status(EAFNOSUPPORT,
                           "IP literal does not match address family");
    out->addresses = {ip};
    out->ttl_sec = 0;
    return butil::Status::OK();
  }
  const auto name = Canonical(host);
  if (!ValidName(name))
    return butil::Status(EINVAL, "Invalid DNS name; use ASCII/punycode");
  const std::string key = name + '/' + std::to_string(static_cast<int>(family));
  const int64_t deadline =
      butil::monotonic_time_us() + int64_t(timeout_ms) * 1000;
  if (_impl->ReadCache(key, out))
    return butil::Status::OK();
  ResolveResult combined;
  int64_t expires_us = INT64_MAX;
  butil::Status last(ENOENT, "No DNS address");
  for (uint16_t type : QueryTypes(family)) {
    const int64_t remaining = deadline - butil::monotonic_time_us();
    if (remaining <= 0) {
      last = butil::Status(ETIMEDOUT, "DoH query timed out");
      break;
    }
    ResolveResult answer;
    last = _impl->Lookup(name, type, std::max<int64_t>(1, remaining / 1000),
                         &answer);
    if (last.ok()) {
      combined.addresses.insert(combined.addresses.end(),
                                answer.addresses.begin(),
                                answer.addresses.end());
      expires_us = std::min(expires_us, butil::monotonic_time_us() +
                                            int64_t(answer.ttl_sec) * 1000000);
    }
  }
  if (combined.addresses.empty())
    return last;
  // The first family's TTL continues running while the second is queried.
  combined.ttl_sec =
      std::max<int64_t>(0, expires_us - butil::monotonic_time_us()) / 1000000;
  _impl->StoreCache(key, combined, expires_us);
  *out = std::move(combined);
  return butil::Status::OK();
}
} // namespace brpc_tools
