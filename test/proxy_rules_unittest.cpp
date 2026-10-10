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

#include <algorithm>
#include <atomic>
#include <arpa/inet.h>
#include <cstring>
#include <random>
#include <thread>
#include <gtest/gtest.h>

namespace proxy_rules {
namespace {
IpAddress Address(const std::string& text) {
    IpAddress result;
    EXPECT_TRUE(IpAddress::Parse(text, &result).ok()) << text;
    return result;
}
std::string NumericAddress(const std::array<uint8_t, 16>& bytes, bool ipv6) {
    char text[INET6_ADDRSTRLEN];
    EXPECT_NE(nullptr, inet_ntop(ipv6 ? AF_INET6 : AF_INET, bytes.data(), text, sizeof(text)));
    return text;
}

// Batch loops belong to callers; these helpers only shorten test setup.
butil::Status InsertRules(IpPrefixIndex& index, const std::vector<std::string>& rules) {
    for (const auto& rule : rules) {
        auto status = index.Insert(rule);
        if (!status.ok()) return status;
    }
    return butil::Status::OK();
}
struct HostnameRule {
    HostnameMatch match;
    std::string hostname;
};
butil::Status InsertRules(HostnameTrie& trie, const std::vector<HostnameRule>& rules) {
    for (const auto& rule : rules) {
        auto status = trie.Insert(rule.match, rule.hostname);
        if (!status.ok()) return status;
    }
    return butil::Status::OK();
}

TEST(ProxyRulesIp, NumericParsingAndFailurePreservesOutput) {
    IpAddress address = Address("192.0.2.1");
    EXPECT_EQ(IpAddress::Family::IPV4, address.family());
    EXPECT_EQ(192, address.bytes()[0]);
    EXPECT_EQ(1, address.bytes()[3]);
    for (size_t i = 4; i < 16; ++i) EXPECT_EQ(0, address.bytes()[i]);
    const auto original = address.bytes();
    for (const auto& bad : {"", "example.com", "127.1", "192.168.001.1",
                           "256.0.0.1", "[::1]", "fe80::1%en0", "1.2.3.4:80",
                           "1.2.3.4.", "::ffff:192.0.02.1"}) {
        EXPECT_FALSE(IpAddress::Parse(bad, &address).ok()) << bad;
        EXPECT_EQ(original, address.bytes());
        EXPECT_EQ(IpAddress::Family::IPV4, address.family());
    }
    EXPECT_FALSE(IpAddress::Parse(std::string("192.0.2.1\0suffix", 15), &address).ok());
    EXPECT_FALSE(IpAddress::Parse(std::string("2001:db8::1\0", 12), &address).ok());
    EXPECT_TRUE(IpAddress::Parse("2001:db8::1", &address).ok());
    EXPECT_EQ(IpAddress::Family::IPV6, address.family());
    EXPECT_FALSE(IpAddress::Parse("127.0.0.1", nullptr).ok());
    EXPECT_FALSE(IpAddress::Parse("::1", nullptr).ok());
}

TEST(ProxyRulesIp, EmptyIndexAndInvalidAddress) {
    IpPrefixIndex index;
    EXPECT_FALSE(index.AnyIp(Address("1.2.3.4")));
    EXPECT_FALSE(index.AnyIp(IpAddress{}));
    EXPECT_FALSE(index.AnyIp(Address("::1")));
}

TEST(ProxyRulesIp, OverlapCanonicalNetworkAndDuplicates) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"10.1.2.3", "10.1.99.9/16", "10.99.88.77/8",
                             "10.1.0.0/16", "10.1.2.3"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("10.1.2.3")));
    EXPECT_TRUE(index.AnyIp(Address("10.1.255.255")));
    EXPECT_TRUE(index.AnyIp(Address("10.255.255.255")));
    EXPECT_FALSE(index.AnyIp(Address("11.0.0.0")));
    ASSERT_TRUE(InsertRules(index, {"192.168.1.1/24", "192.168.1.2/24"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("192.168.1.0")));
    EXPECT_TRUE(index.AnyIp(Address("192.168.1.255")));
    EXPECT_FALSE(index.AnyIp(Address("192.168.2.1")));
}

TEST(ProxyRulesIp, PrefixBoundariesAndNonByteAlignedPrefixes) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"192.0.2.127/25", "192.0.2.129/31",
                             "255.255.255.255/32"}).ok());
    for (const auto& ip : {"192.0.2.0", "192.0.2.127", "192.0.2.128",
                           "192.0.2.129", "255.255.255.255"}) {
        EXPECT_TRUE(index.AnyIp(Address(ip))) << ip;
    }
    EXPECT_FALSE(index.AnyIp(Address("192.0.2.130")));
    EXPECT_FALSE(index.AnyIp(Address("255.255.255.254")));
}

TEST(ProxyRulesIp, IPv6OverlapAndFamilySeparation) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"2001:db8::8000/113", "2001:db8::8001/128",
                             "192.0.2.1", "::ffff:192.0.2.2"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("2001:db8::8001")));
    EXPECT_TRUE(index.AnyIp(Address("2001:db8::ffff")));
    EXPECT_FALSE(index.AnyIp(Address("2001:db8::7fff")));
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.1")));
    EXPECT_FALSE(index.AnyIp(Address("::ffff:192.0.2.1")));
    EXPECT_TRUE(index.AnyIp(Address("::ffff:192.0.2.2")));
    EXPECT_FALSE(index.AnyIp(Address("192.0.2.2")));
}

TEST(ProxyRulesIp, ZeroPrefixesAreFamilySpecific) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"255.255.255.255/0"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("0.0.0.0")));
    EXPECT_TRUE(index.AnyIp(Address("255.255.255.255")));
    EXPECT_FALSE(index.AnyIp(Address("::")));
    IpPrefixIndex ipv6;
    ASSERT_TRUE(ipv6.Insert("ffff::/0").ok());
    EXPECT_TRUE(ipv6.AnyIp(Address("::")));
    EXPECT_TRUE(ipv6.AnyIp(Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    EXPECT_FALSE(ipv6.AnyIp(Address("0.0.0.0")));
    EXPECT_FALSE(ipv6.AnyIp(IpAddress{}));
}

TEST(ProxyRulesIp, ContiguousDottedNetmask) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"172.16.2.3/255.255.0.0"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("172.16.255.255")));
    EXPECT_FALSE(index.AnyIp(Address("172.17.0.0")));
    IpPrefixIndex exact;
    ASSERT_TRUE(exact.Insert("172.16.2.3/255.255.255.255").ok());
    EXPECT_TRUE(exact.AnyIp(Address("172.16.2.3")));
    EXPECT_FALSE(exact.AnyIp(Address("172.16.2.4")));
}

TEST(ProxyRulesIp, InvalidInsertKeepsExistingMatches) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"192.0.2.0/24"}).ok());
    for (const auto& bad : {"192.0.2.0/33", "::/129", "1.2.3.4/", "1.2.3.4/-1",
                           "1.2.3.4/+1", "1.2.3.4/99999999999999", "1.2.3.4/1/2",
                           "1.2.3.4/255.0.255.0", "::/255.255.0.0", "example.com/24"}) {
        EXPECT_FALSE(index.Insert(bad).ok()) << bad;
        EXPECT_TRUE(index.AnyIp(Address("192.0.2.99")));
        EXPECT_FALSE(index.AnyIp(Address("10.0.0.1")));
    }
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.1")));
}

TEST(ProxyRulesIp, IncrementalInsertionRetainsEarlierRules) {
    IpPrefixIndex index;
    ASSERT_TRUE(index.Insert("10.0.0.0/8").ok());
    EXPECT_TRUE(index.AnyIp(Address("10.1.2.3")));
    EXPECT_FALSE(index.Insert("192.0.2.0/33").ok());
    EXPECT_TRUE(index.AnyIp(Address("10.1.2.3")));
    EXPECT_FALSE(index.AnyIp(Address("192.0.2.1")));
    ASSERT_TRUE(index.Insert("192.0.2.0/24").ok());
    EXPECT_TRUE(index.AnyIp(Address("10.1.2.3")));
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.1")));
}

TEST(ProxyRulesIp, BranchNodesDoNotMatchUntilGivenARule) {
    IpPrefixIndex index;
    // The two leaves share a /24 branch that must not itself match.
    ASSERT_TRUE(InsertRules(index, {"192.0.2.1", "192.0.2.129"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.1")));
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.129")));
    EXPECT_FALSE(index.AnyIp(Address("192.0.2.2")));
    EXPECT_FALSE(index.AnyIp(Address("192.0.2.128")));
    ASSERT_TRUE(InsertRules(index, {"192.0.2.1", "192.0.2.129", "192.0.2.0/24"}).ok());
    EXPECT_TRUE(index.AnyIp(Address("192.0.2.2")));
    EXPECT_FALSE(index.AnyIp(Address("192.0.3.2")));
}

TEST(ProxyRulesIp, EveryDottedNetmaskMatchesCidr) {
    std::mt19937 random(20261010);
    for (unsigned prefix = 0; prefix <= 32; ++prefix) {
        std::array<uint8_t, 16> mask{};
        for (unsigned bit = 0; bit < prefix; ++bit) mask[bit / 8] |= uint8_t(1u << (7 - bit % 8));
        IpPrefixIndex dotted, cidr;
        ASSERT_TRUE(InsertRules(dotted, {"203.0.113.123/" + NumericAddress(mask, false)}).ok());
        ASSERT_TRUE(InsertRules(cidr, {"203.0.113.123/" + std::to_string(prefix)}).ok());
        EXPECT_TRUE(dotted.AnyIp(Address("203.0.113.123")));
        for (unsigned i = 0; i < 100; ++i) {
            std::array<uint8_t, 16> bytes{};
            for (unsigned j = 0; j < 4; ++j) bytes[j] = random();
            const auto ip = Address(NumericAddress(bytes, false));
            EXPECT_EQ(cidr.AnyIp(ip), dotted.AnyIp(ip)) << prefix;
        }
    }
}

TEST(ProxyRulesIp, DottedMasksRejectHolesAndIsolatedLowBits) {
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, {"192.0.2.0/24"}).ok());
    for (unsigned bit = 1; bit < 32; ++bit) {
        for (uint32_t value : {UINT32_MAX ^ (1u << bit), 1u << (bit - 1)}) {
            std::array<uint8_t, 16> bytes{};
            for (unsigned j = 0; j < 4; ++j) bytes[j] = value >> (24 - j * 8);
            EXPECT_FALSE(InsertRules(index, {"192.0.2.1/" + NumericAddress(bytes, false)}).ok());
            EXPECT_TRUE(index.AnyIp(Address("192.0.2.1")));
        }
    }
}

TEST(ProxyRulesIp, EveryIpv6PrefixAndDivergenceBit) {
    std::array<uint8_t, 16> original;
    original.fill(255);
    const std::string host = NumericAddress(original, true);
    // No /0 ancestor hides the misses: test every prefix in isolation.
    for (unsigned prefix = 0; prefix <= 128; ++prefix) {
        IpPrefixIndex index;
        ASSERT_TRUE(InsertRules(index, {host + '/' + std::to_string(prefix)}).ok());
        EXPECT_TRUE(index.AnyIp(Address(host)));
        for (unsigned bit = 0; bit < 128; ++bit) {
            auto bytes = original;
            bytes[bit / 8] ^= uint8_t(1u << (7 - bit % 8));
            EXPECT_EQ(bit >= prefix, index.AnyIp(Address(NumericAddress(bytes, true))))
                << "prefix=" << prefix << " bit=" << bit;
        }
    }
    std::vector<std::string> leaves{host};
    for (unsigned bit = 0; bit < 128; ++bit) {
        auto bytes = original;
        bytes[bit / 8] ^= uint8_t(1u << (7 - bit % 8));
        leaves.push_back(NumericAddress(bytes, true));
    }
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, leaves).ok());
    for (const auto& leaf : leaves) EXPECT_TRUE(index.AnyIp(Address(leaf)));
    auto miss = original;
    miss[0] ^= 0x80;
    miss[8] ^= 0x80;
    EXPECT_FALSE(index.AnyIp(Address(NumericAddress(miss, true))));
}

struct ReferenceNetwork {
    std::array<uint8_t, 16> bytes;
    unsigned prefix;
    bool ipv6;
};
bool ReferenceMatch(const ReferenceNetwork& rule, const IpAddress& ip) {
    if (rule.ipv6 != (ip.family() == IpAddress::Family::IPV6)) return false;
    const unsigned whole = rule.prefix / 8;
    if (memcmp(rule.bytes.data(), ip.bytes().data(), whole) != 0) return false;
    const unsigned remaining = rule.prefix % 8;
    if (remaining == 0) return true;
    const uint8_t mask = static_cast<uint8_t>(0xffu << (8 - remaining));
    return (rule.bytes[whole] & mask) == (ip.bytes()[whole] & mask);
}
TEST(ProxyRulesIp, RandomizedAgainstLinearReference) {
    std::mt19937 random(20261009);
    std::vector<ReferenceNetwork> reference;
    std::vector<std::string> rules;
    for (unsigned i = 0; i < 700; ++i) {
        ReferenceNetwork rule{};
        rule.ipv6 = i % 2;
        rule.prefix = rule.ipv6 ? 32 + random() % 97 : 8 + random() % 25;
        for (auto& byte : rule.bytes) byte = random();
        rules.push_back(NumericAddress(rule.bytes, rule.ipv6) + '/' + std::to_string(rule.prefix));
        reference.push_back(rule);
    }
    std::shuffle(rules.begin(), rules.end(), random);
    IpPrefixIndex index;
    ASSERT_TRUE(InsertRules(index, rules).ok());
    unsigned hits = 0, misses = 0;
    for (unsigned i = 0; i < 2400; ++i) {
        std::array<uint8_t, 16> bytes;
        const bool ipv6 = i % 2;
        for (auto& byte : bytes) byte = random();
        if (i < reference.size()) bytes = reference[i].bytes;
        const auto ip = Address(NumericAddress(bytes, ipv6));
        const bool expected = std::any_of(reference.begin(), reference.end(),
            [&](const ReferenceNetwork& rule) { return ReferenceMatch(rule, ip); });
        EXPECT_EQ(expected, index.AnyIp(ip)) << i;
        expected ? ++hits : ++misses;
    }
    EXPECT_GT(hits, 0u);
    EXPECT_GT(misses, 0u);
}

TEST(ProxyRulesDomain, ExactAndSuffixBoundaries) {
    HostnameTrie exact, suffix;
    ASSERT_TRUE(InsertRules(exact, {{HostnameMatch::EXACT, "api.example.com"}}).ok());
    EXPECT_TRUE(exact.AnyHostname("api.example.com"));
    EXPECT_FALSE(exact.AnyHostname("x.api.example.com"));
    EXPECT_FALSE(exact.AnyHostname("example.com"));
    ASSERT_TRUE(InsertRules(suffix, {{HostnameMatch::SUFFIX, "example.com"}}).ok());
    for (const auto& domain : {"example.com", "api.example.com", "x.api.example.com"})
        EXPECT_TRUE(suffix.AnyHostname(domain));
    for (const auto& domain : {"badexample.com", "example.com.net", "com"})
        EXPECT_FALSE(suffix.AnyHostname(domain));
}

TEST(ProxyRulesDomain, NormalizationAndDuplicateRules) {
    HostnameTrie trie;
    ASSERT_TRUE(InsertRules(trie, {{HostnameMatch::EXACT, "API.Example.COM."},
                            {HostnameMatch::EXACT, "api.example.com"},
                            {HostnameMatch::SUFFIX, "example.COM"},
                            {HostnameMatch::SUFFIX, "EXAMPLE.com."}}).ok());
    EXPECT_TRUE(trie.AnyHostname("Api.EXAMPLE.Com."));
    EXPECT_TRUE(trie.AnyHostname("x.example.com"));
    EXPECT_FALSE(trie.AnyHostname("badexample.com"));
    // Both flags on the same node remain effective.
    ASSERT_TRUE(InsertRules(trie, {{HostnameMatch::EXACT, "example.com"},
                            {HostnameMatch::SUFFIX, "example.com"}}).ok());
    EXPECT_TRUE(trie.AnyHostname("example.com"));
    EXPECT_TRUE(trie.AnyHostname("x.example.com"));
}

TEST(ProxyRulesDomain, SharedLabelsAndIntermediateNodesDoNotMatch) {
    HostnameTrie trie;
    ASSERT_TRUE(InsertRules(trie, {{HostnameMatch::EXACT, "api.example.com"},
                            {HostnameMatch::EXACT, "www.example.net"},
                            {HostnameMatch::EXACT, "api.other.net"}}).ok());
    EXPECT_TRUE(trie.AnyHostname("api.example.com"));
    EXPECT_TRUE(trie.AnyHostname("www.example.net"));
    for (const auto& domain : {"com", "example.com", "api.example.net",
                               "www.other.net", "api.other.com"})
        EXPECT_FALSE(trie.AnyHostname(domain)) << domain;
}

TEST(ProxyRulesDomain, LengthBoundariesAndAsciiIdna) {
    const std::string maximum = std::string(63, 'a') + '.' + std::string(63, 'b') +
                               '.' + std::string(63, 'c') + '.' + std::string(61, 'd');
    ASSERT_EQ(253u, maximum.size());
    HostnameTrie trie;
    ASSERT_TRUE(InsertRules(trie, {{HostnameMatch::EXACT, maximum},
                            {HostnameMatch::SUFFIX, "xn--bcher-kva.example"}}).ok());
    EXPECT_TRUE(trie.AnyHostname(maximum + '.'));
    EXPECT_FALSE(trie.AnyHostname(maximum + 'd'));
    EXPECT_TRUE(trie.AnyHostname("www.xn--bcher-kva.example"));
    EXPECT_FALSE(trie.AnyHostname("www.bücher.example"));
    EXPECT_FALSE(trie.Insert(HostnameMatch::EXACT, std::string(64, 'a') + ".com").ok());
}

TEST(ProxyRulesDomain, InvalidInsertKeepsExistingMatches) {
    HostnameTrie trie;
    ASSERT_TRUE(InsertRules(trie, {{HostnameMatch::SUFFIX, "example.com"}}).ok());
    for (const auto& bad : {"", ".", ".example.com", "x..example.com", "example.com..",
                           "-x.example.com", "x-.example.com", "x_.example.com",
                           "*.example.com", "https://example.com", "example.com:80",
                           " x.example.com", "x.example.com ", "bücher.example.com"}) {
        EXPECT_FALSE(trie.AnyHostname(bad)) << bad;
        EXPECT_FALSE(trie.Insert(HostnameMatch::EXACT, bad).ok()) << bad;
        EXPECT_TRUE(trie.AnyHostname("www.example.com"));
        EXPECT_FALSE(trie.AnyHostname("new.com"));
    }
    EXPECT_FALSE(trie.AnyHostname(std::string("x\0.example.com", 14)));
    EXPECT_FALSE(trie.Insert(static_cast<HostnameMatch>(99), "a.com").ok());
    EXPECT_TRUE(trie.AnyHostname("www.example.com"));
}

TEST(ProxyRulesDomain, IncrementalInsertionAndFreshIndexes) {
    for (int round = 0; round < 3; ++round) {
        HostnameTrie trie;
        EXPECT_FALSE(trie.AnyHostname("example.com"));
        for (unsigned i = 0; i < 200; ++i) {
            const auto host = "host" + std::to_string(i) + ".example.com";
            ASSERT_TRUE(trie.Insert(HostnameMatch::EXACT, host).ok());
            EXPECT_TRUE(trie.AnyHostname(host));
            EXPECT_TRUE(trie.AnyHostname("host0.example.com"));
            EXPECT_FALSE(trie.AnyHostname("example.com"));
        }
        EXPECT_FALSE(trie.AnyHostname("small.net"));
        ASSERT_TRUE(trie.Insert(HostnameMatch::SUFFIX, "small.net").ok());
        EXPECT_TRUE(trie.AnyHostname("www.small.net"));
        EXPECT_TRUE(trie.AnyHostname("host0.example.com"));
    }
}

bool ReferenceHostname(const HostnameRule& rule, const std::string& query) {
    if (rule.hostname == query) return true;
    if (rule.match == HostnameMatch::EXACT || query.size() <= rule.hostname.size()) return false;
    const size_t suffix = query.size() - rule.hostname.size();
    return query[suffix - 1] == '.' && query.compare(suffix, rule.hostname.size(), rule.hostname) == 0;
}
TEST(ProxyRulesDomain, RandomizedAgainstLinearReference) {
    std::mt19937 random(1977);
    std::vector<HostnameRule> rules;
    for (unsigned i = 0; i < 500; ++i) {
        std::string domain = "zone" + std::to_string(random() % 100) + ".test";
        if (random() % 2) domain = "api." + domain;
        rules.push_back({random() % 2 ? HostnameMatch::EXACT : HostnameMatch::SUFFIX, domain});
    }
    HostnameTrie trie;
    ASSERT_TRUE(InsertRules(trie, rules).ok());
    for (unsigned i = 0; i < 2000; ++i) {
        std::string query = "zone" + std::to_string(random() % 130) + ".test";
        switch (i % 4) {
        case 0: query = "www.api." + query; break;
        case 1: query = "api." + query; break;
        case 2: query = "bad" + query; break;
        default: break;
        }
        const bool expected = std::any_of(rules.begin(), rules.end(),
            [&](const HostnameRule& rule) { return ReferenceHostname(rule, query); });
        EXPECT_EQ(expected, trie.AnyHostname(query)) << query;
    }
}

TEST(ProxyRules, ConcurrentImmutableQueries) {
    IpPrefixIndex ips;
    HostnameTrie domains;
    ASSERT_TRUE(InsertRules(ips, {"10.0.0.0/8", "2001:db8::/32"}).ok());
    ASSERT_TRUE(InsertRules(domains, {{HostnameMatch::SUFFIX, "example.com"},
                               {HostnameMatch::EXACT, "api.example.net"}}).ok());
    const auto ip4 = Address("10.1.2.3"), ip6 = Address("2001:db8::1"), miss = Address("192.0.2.1");
    std::atomic<bool> passed(true);
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            for (int j = 0; j < 2000; ++j) {
                if (!ips.AnyIp(ip4) || !ips.AnyIp(ip6) || ips.AnyIp(miss) ||
                    !domains.AnyHostname("API.Example.NET.") ||
                    !domains.AnyHostname("x.example.com") ||
                    domains.AnyHostname("x.api.example.net") ||
                    domains.AnyHostname("badexample.com")) passed = false;
            }
        });
    }
    for (auto& thread : threads) thread.join();
    EXPECT_TRUE(passed.load());
}
}  // namespace
}  // namespace proxy_rules
