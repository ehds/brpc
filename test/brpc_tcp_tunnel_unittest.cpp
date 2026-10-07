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

#include <atomic>
#include <cerrno>
#include <functional>
#include <mutex>
#include <sys/socket.h>
#include <vector>
#include <gtest/gtest.h>
#include "bthread/bthread.h"
#include "bthread/countdown_event.h"
#include "brpc/details/proxy_socket.h"
#include "brpc/details/tcp_tunnel.h"
#include "butil/fd_guard.h"
#include "butil/time.h"

namespace {
bool WaitUntil(const std::function<bool()>& condition) {
    const auto deadline = butil::gettimeofday_us() + 5000000;
    while (!condition()) {
        if (butil::gettimeofday_us() >= deadline) return false;
        bthread_usleep(1000);
    }
    return true;
}

class SocketUpstream : public brpc::ProxyUpstream {
public:
    SocketUpstream(const brpc::ProxyTunnel& tunnel, brpc::SocketId id)
        : ProxyUpstream(tunnel), socket(id) {}
    void WriteUpstream(butil::IOBuf* data, Done done) override {
        done(brpc::details::WriteProxyData(socket, data) ? 0 : EIO);
    }
    brpc::SocketId socket;
};

class TcpTunnelWriteTest : public testing::Test {
protected:
    void SetUp() override {
        brpc::SocketId* destinations[] = {&tunnel->client, &upstream_socket};
        for (int i = 0; i < 2; ++i) {
            int fds[2];
            ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
            butil::fd_guard sender(fds[0]);
            peers[i].reset(fds[1]);
            timeval timeout = {1, 0};
            ASSERT_EQ(0, setsockopt(peers[i], SOL_SOCKET, SO_RCVTIMEO,
                                   &timeout, sizeof(timeout)));
            brpc::SocketOptions options;
            options.fd = sender;
            ASSERT_EQ(0, brpc::Socket::Create(options, destinations[i]));
            sender.release();
        }
        ASSERT_TRUE(brpc::details::TcpTunnel::CreateUpstream(tunnel,
            [this](const brpc::ProxyTunnel& context) {
                output.reset(new brpc::ProxyTunnel(context));
                return std::unique_ptr<brpc::ProxyUpstream>(
                    new SocketUpstream(context, upstream_socket));
            }));
    }
    void TearDown() override {
        for (const auto& gate : gates) gate->Open();
        if (tunnel) {
            tunnel->Close();
            brpc::Socket::SetFailed(tunnel->client);
        }
        brpc::Socket::SetFailed(upstream_socket);
    }
    struct Gate {
        void Open() { if (!opened.exchange(true)) release.signal(); }
        std::atomic<bool> opened{false};
        bthread::CountdownEvent started;
        bthread::CountdownEvent release;
    };
    std::shared_ptr<Gate> BlockConsumer() {
        auto gate = std::make_shared<Gate>();
        gates.push_back(gate);
        EXPECT_TRUE(tunnel->Submit(nullptr, nullptr, 0, nullptr, [gate] {
            gate->started.signal();
            gate->release.wait();
            return true;
        }).ok());
        EXPECT_EQ(0, gate->started.timed_wait(butil::seconds_from_now(5)));
        return gate;
    }
    std::vector<std::shared_ptr<Gate>> gates;
    std::shared_ptr<brpc::details::TcpTunnel> tunnel = std::make_shared<brpc::details::TcpTunnel>();
    std::unique_ptr<brpc::ProxyTunnel> output;
    brpc::SocketId upstream_socket = brpc::INVALID_SOCKET_ID;
    butil::fd_guard peers[2];
};

TEST_F(TcpTunnelWriteTest, WritesToTheCorrectPeer) {
    butil::IOBuf client_data;
    client_data.append("client", 6);
    int completions = 0;
    output->WriteClient(&client_data, [&](int error) {
        EXPECT_EQ(0, error);
        ++completions;
    });
    EXPECT_EQ(1, completions);
    EXPECT_TRUE(client_data.empty());
    char received[8] = {};
    ASSERT_EQ(6, recv(peers[0], received, 6, MSG_WAITALL));
    EXPECT_EQ("client", std::string(received, 6));
    butil::IOBuf upstream_data;
    upstream_data.append("upstream", 8);
    ASSERT_TRUE(tunnel->WriteUpstream(&upstream_data));
    ASSERT_EQ(8, recv(peers[1], received, 8, MSG_WAITALL));
    EXPECT_EQ("upstream", std::string(received, 8));
}

TEST_F(TcpTunnelWriteTest, ClosedSessionRejectsWritesWithoutConsumingData) {
    // Keep both sockets healthy to distinguish session rejection from a
    // low-level write failure. Closing the session must gate both directions.
    tunnel->closed = true;
    butil::IOBuf data;
    data.append("pending", 7);
    EXPECT_FALSE(tunnel->WriteClient(&data));
    EXPECT_FALSE(tunnel->WriteUpstream(&data));
    int completions = 0;
    output->WriteClient(&data, [&](int error) {
        EXPECT_EQ(EIO, error);
        ++completions;
    });
    EXPECT_EQ(1, completions);
    EXPECT_EQ("pending", data.to_string());
    EXPECT_TRUE(brpc::details::WriteProxyData(tunnel->client, &data));
    char received[7];
    ASSERT_EQ(7, recv(peers[0], received, 7, MSG_WAITALL));
    EXPECT_EQ("pending", std::string(received, 7));
}

TEST_F(TcpTunnelWriteTest, PublicOutputReportsSocketFailure) {
    brpc::Socket::SetFailed(tunnel->client);
    EXPECT_FALSE(output->is_closed());
    butil::IOBuf data;
    data.append("pending");
    int completions = 0;
    output->WriteClient(&data, [&](int error) {
        EXPECT_EQ(EIO, error);
        ++completions;
    });
    EXPECT_EQ(1, completions);
    EXPECT_EQ("pending", data.to_string());
}

TEST_F(TcpTunnelWriteTest, PublicOutputRejectsExpiredSession) {
    tunnel->Close();
    tunnel.reset();
    EXPECT_TRUE(output->is_closed());
    butil::IOBuf data;
    data.append("pending");
    int completions = 0;
    output->WriteClient(&data, [&](int error) {
        EXPECT_EQ(EIO, error);
        ++completions;
    });
    EXPECT_EQ(1, completions);
    EXPECT_EQ("pending", data.to_string());
}

TEST_F(TcpTunnelWriteTest, DuplicateCreationPreservesInstalledAdapter) {
    auto installed = tunnel->GetUpstream();
    int factory_calls = 0;
    const auto duplicate = brpc::details::TcpTunnel::CreateUpstream(tunnel,
        [&](const brpc::ProxyTunnel& context) {
            ++factory_calls;
            return std::unique_ptr<brpc::ProxyUpstream>(
                new brpc::ProxyUpstream(context));
        });
    EXPECT_FALSE(duplicate);
    EXPECT_EQ(0, factory_calls);
    EXPECT_EQ(installed, tunnel->GetUpstream());
}

TEST_F(TcpTunnelWriteTest, ClosedSessionSkipsFactory) {
    tunnel->Close();
    int factory_calls = 0;
    const auto rejected = brpc::details::TcpTunnel::CreateUpstream(tunnel,
        [&](const brpc::ProxyTunnel& context) {
            ++factory_calls;
            return std::unique_ptr<brpc::ProxyUpstream>(
                new brpc::ProxyUpstream(context));
        });
    EXPECT_FALSE(rejected);
    EXPECT_EQ(0, factory_calls);
    EXPECT_FALSE(tunnel->GetUpstream());
}

TEST(TcpTunnelOwnershipTest, ClosureDuringFactoryCancelsUninstalledAdapter) {
    class TrackingUpstream : public brpc::ProxyUpstream {
    public:
        TrackingUpstream(const brpc::ProxyTunnel& context, int* closes)
            : ProxyUpstream(context), close_calls(closes) {}
        void Close() override {
            ++*close_calls;
            // Both factory and cleanup callbacks must run outside session mutex.
            EXPECT_TRUE(tunnel().is_closed());
            ProxyUpstream::Close();
        }
        int* close_calls;
    };
    auto session = std::make_shared<brpc::details::TcpTunnel>();
    int close_calls = 0;
    const auto rejected = brpc::details::TcpTunnel::CreateUpstream(session,
        [&](const brpc::ProxyTunnel& context) {
            EXPECT_FALSE(context.is_closed());
            std::unique_ptr<brpc::ProxyUpstream> adapter(
                new TrackingUpstream(context, &close_calls));
            context.Close();
            return adapter;
        });
    EXPECT_FALSE(rejected);
    EXPECT_FALSE(session->GetUpstream());
    EXPECT_EQ(1, close_calls);
}

TEST_F(TcpTunnelWriteTest, DirectUpstreamSubmissionWaitsForHandshake) {
    auto gate = BlockConsumer();
    auto session = tunnel;
    ASSERT_TRUE(tunnel->Submit(nullptr, nullptr, 0, nullptr, [session] {
        butil::IOBuf reply;
        reply.append("ready");
        return session->WriteClient(&reply);
    }).ok());
    butil::IOBuf payload;
    payload.append("upstream");
    const auto result = tunnel->GetUpstream()->ParseUpstreamData(&payload, nullptr, false);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(nullptr, result.message());  // No Process/Dispatch step follows.
    EXPECT_TRUE(payload.empty());
    char received[13];
    EXPECT_EQ(-1, recv(peers[0], received, 1, MSG_DONTWAIT));
    EXPECT_EQ(EWOULDBLOCK, errno);
    gate->Open();
    ASSERT_EQ(13, recv(peers[0], received, sizeof(received), MSG_WAITALL));
    EXPECT_EQ("readyupstream", std::string(received, sizeof(received)));
}

TEST_F(TcpTunnelWriteTest, ClientAndCustomUpstreamUseTheSameQueue) {
    auto gate = BlockConsumer();
    butil::IOBuf client_data;
    client_data.append("request");
    ASSERT_TRUE(tunnel->ReceiveClient(nullptr, &client_data).ok());
    butil::IOBuf upstream_data;
    upstream_data.append("response");
    ASSERT_TRUE(output->Receive(&upstream_data));
    EXPECT_TRUE(client_data.empty());
    EXPECT_TRUE(upstream_data.empty());
    gate->Open();
    char received[8];
    ASSERT_EQ(7, recv(peers[1], received, 7, MSG_WAITALL));
    EXPECT_EQ("request", std::string(received, 7));
    ASSERT_EQ(8, recv(peers[0], received, 8, MSG_WAITALL));
    EXPECT_EQ("response", std::string(received, 8));
}

TEST_F(TcpTunnelWriteTest, QueuedTasksKeepSubmissionOrder) {
    auto gate = BlockConsumer();
    auto session = tunnel;
    for (int i = 1; i <= 3; ++i) {
        auto data = std::make_shared<butil::IOBuf>();
        butil::IOBuf source;
        source.append(std::to_string(i));
        ASSERT_TRUE(tunnel->Submit(nullptr, &source, source.size(), data.get(),
            [session, data] { return session->WriteClient(data.get()); }).ok());
    }
    gate->Open();
    char received[3];
    ASSERT_EQ(3, recv(peers[0], received, sizeof(received), MSG_WAITALL));
    EXPECT_EQ("123", std::string(received, sizeof(received)));
    EXPECT_TRUE(WaitUntil([session] {
        std::lock_guard<bthread::Mutex> lock(session->mutex);
        return session->pending_bytes == 0;
    }));
}

TEST_F(TcpTunnelWriteTest, CloseDiscardsQueuedTasksAndReleasesTheirData) {
    auto gate = BlockConsumer();
    auto data = std::make_shared<butil::IOBuf>();
    std::weak_ptr<butil::IOBuf> weak = data;
    auto calls = std::make_shared<std::atomic<int>>(0);
    butil::IOBuf source;
    source.append("pending");
    ASSERT_TRUE(tunnel->Submit(nullptr, &source, source.size(), data.get(),
        [data, calls] { ++*calls; return true; }).ok());
    data.reset();
    tunnel->Close();
    gate->Open();
    EXPECT_TRUE(WaitUntil([weak] { return weak.expired(); }));
    EXPECT_EQ(0, calls->load());
    auto session = tunnel;
    EXPECT_TRUE(WaitUntil([session] {
        std::lock_guard<bthread::Mutex> lock(session->mutex);
        return session->pending_bytes == 0;
    }));
}

TEST_F(TcpTunnelWriteTest, TaskFailureCancelsFollowingTasks) {
    auto gate = BlockConsumer();
    ASSERT_TRUE(tunnel->Submit(nullptr, nullptr, 0, nullptr, [] { return false; }).ok());
    auto data = std::make_shared<butil::IOBuf>();
    std::weak_ptr<butil::IOBuf> weak = data;
    auto calls = std::make_shared<std::atomic<int>>(0);
    butil::IOBuf source;
    source.append("pending");
    ASSERT_TRUE(tunnel->Submit(nullptr, &source, source.size(), data.get(),
        [data, calls] { ++*calls; return true; }).ok());
    data.reset();
    gate->Open();
    EXPECT_TRUE(WaitUntil([weak] { return weak.expired(); }));
    EXPECT_TRUE(output->is_closed());
    EXPECT_EQ(0, calls->load());
}

TEST_F(TcpTunnelWriteTest, PendingLimitPreservesRejectedInputAndClosesSession) {
    auto gate = BlockConsumer();
    tunnel->max_pending_bytes = 4;
    butil::IOBuf first;
    first.append("four");
    const auto result = tunnel->GetUpstream()->ParseUpstreamData(&first, nullptr, false);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(nullptr, result.message());
    butil::IOBuf overflow;
    overflow.append("x");
    const auto rejected = tunnel->GetUpstream()->ParseUpstreamData(&overflow, nullptr, false);
    EXPECT_EQ(brpc::PARSE_ERROR_TOO_BIG_DATA, rejected.error());
    EXPECT_TRUE(output->is_closed());
    EXPECT_EQ("x", overflow.to_string());
    gate->Open();
}

TEST_F(TcpTunnelWriteTest, ClosedSubmissionPreservesInput) {
    auto upstream = tunnel->GetUpstream();
    tunnel->Close();
    butil::IOBuf source;
    source.append("pending");
    auto data = std::make_shared<butil::IOBuf>();
    const auto status = tunnel->Submit(nullptr, &source, source.size(), data.get(),
                                      [data] { return true; });
    EXPECT_EQ(ECANCELED, status.error_code());
    EXPECT_EQ("pending", source.to_string());
    EXPECT_TRUE(data->empty());
    const auto result = upstream->ParseUpstreamData(&source, nullptr, false);
    EXPECT_EQ(brpc::PARSE_ERROR_ABSOLUTELY_WRONG, result.error());
}

TEST_F(TcpTunnelWriteTest, UpstreamEOFWaitsForQueuedOutput) {
    auto gate = BlockConsumer();
    brpc::SocketUniquePtr input;
    ASSERT_EQ(0, brpc::Socket::Address(upstream_socket, &input));
    input->EnableDeferredEOF();
    brpc::details::TcpTunnel::WatchFailure(upstream_socket, tunnel);
    butil::IOBuf source;
    source.append("tail");
    ASSERT_TRUE(tunnel->ReceiveUpstream(input.get(), &source).ok());
    input->SetEOF();
    brpc::SocketUniquePtr probe;
    EXPECT_EQ(0, brpc::Socket::Address(upstream_socket, &probe));
    gate->Open();
    char received[4];
    ASSERT_EQ(4, recv(peers[0], received, sizeof(received), MSG_WAITALL));
    EXPECT_EQ("tail", std::string(received, sizeof(received)));
    EXPECT_TRUE(WaitUntil([this] { return output->is_closed(); }));
    EXPECT_NE(0, brpc::Socket::Address(upstream_socket, &probe));
}

TEST_F(TcpTunnelWriteTest, ClientEOFWaitsForQueuedUpstreamWrite) {
    auto gate = BlockConsumer();
    brpc::SocketUniquePtr input;
    ASSERT_EQ(0, brpc::Socket::Address(tunnel->client, &input));
    input->EnableDeferredEOF();
    brpc::details::TcpTunnel::WatchFailure(tunnel->client, tunnel);
    butil::IOBuf source;
    source.append("tail");
    ASSERT_TRUE(tunnel->ReceiveClient(input.get(), &source).ok());
    input->SetEOF();
    gate->Open();
    char received[4];
    ASSERT_EQ(4, recv(peers[1], received, sizeof(received), MSG_WAITALL));
    EXPECT_EQ("tail", std::string(received, sizeof(received)));
    EXPECT_TRUE(WaitUntil([this] { return output->is_closed(); }));
}
}  // namespace
