# SOCKS5 protocol example

正式的 brpc 服务端协议扩展：无认证 SOCKS5 TCP CONNECT，支持 IPv4、IPv6、
域名目标及双向字节转发。两侧网络读写都由 brpc 管理。

## 构建与运行

必须先重新构建修改后的 brpc，不能链接改动前的库或混用头文件。
在仓库根目录执行（Protobuf、OpenSSL 等依赖需要预先安装）：

```sh
cmake -S . -B build -DBUILD_UNIT_TESTS=OFF
cmake --build build -j6
cmake -S example/socks5_proxy -B example/socks5_proxy/build \
  -DBRPC_INCLUDE_PATH="$PWD/build/output/include" \
  -DBRPC_LIB="$PWD/build/output/lib/libbrpc.a"
cmake --build example/socks5_proxy/build --clean-first -j6
./example/socks5_proxy/build/socks5_proxy 127.0.0.1:1080
```

启动本地 HTTP 服务，再通过代理访问。`--noproxy ""` 防止 NO_PROXY 绕过代理：

```sh
python3 -m http.server 8000 --bind 127.0.0.1
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 http://localhost:8000/
```

运行集成测试（会自动启动和关闭临时代理及本地 HTTP/echo 服务）：

```sh
python3 example/socks5_proxy/smoke_test.py example/socks5_proxy/build/socks5_proxy
```

构建还会生成 `socks5_custom_service`，它使用用户实现的处理器接受逻辑目标并
回显数据，不建立上游连接，也不生成 HTTP 响应。运行两个示例的集成测试：

```sh
python3 example/socks5_proxy/smoke_test.py \
  example/socks5_proxy/build/socks5_proxy \
  example/socks5_proxy/build/socks5_custom_service
```

## 同一 Server、同一端口支持 HTTP CONNECT 与 SOCKS5

构建会同时生成 `socks5_http_proxy`，源码为 `mixed_server.cpp`。代理 Server 在同一
端口上处理两个协议，并支持普通 HTTP 正向代理；同一进程另外启动一个独立
brpc Server，提供原有内建网页工具。

```sh
./example/socks5_proxy/build/socks5_http_proxy 127.0.0.1:1080
```

## 独立网页工具 Server

组合示例默认同时监听：

- `127.0.0.1:1080`：SOCKS5、HTTP CONNECT 和普通 HTTP 代理。
- `127.0.0.1:8080`：brpc 内建网页工具，普通 HTTP/h2 协议，无代理 master service。

浏览器直接打开 `http://127.0.0.1:8080/`。常用页面包括 `/status`、`/vars`、
`/flags`、`/connections`、`/rpcz`、`/bthreads`、`/sockets`、`/brpc_metrics` 等。
可更换工具 Server 的监听地址，例如：

```sh
./example/socks5_proxy/build/socks5_http_proxy 127.0.0.1:1080 \
  --admin_address=127.0.0.1:8081
```

网页工具和代理处于同一进程，`/vars`、`/brpc_metrics` 可查看进程全局 bvar 和两个
Server 的指标。代理 Server 的指标前缀为 `rpc_server_proxy`，工具 Server 为
`rpc_server_proxy_admin`。`/status` 和 `/connections` 的服务端部分对应工具
Server 自身；独立 Server 不会自动列出代理 Server 的所有入站隧道。
`/sockets/<SocketId>` 可以查看同进程 Socket 的调试信息。

程序收到 SIGINT/SIGTERM 时先停止两个 Server，再等待活动任务结束。工具端口
启动失败会停止已启动的代理 Server，返回非零退出码。代理端口上的 origin-form
`/status` 等请求仍不会进入内建网页路由。两个 Server 的连接数上限独立：代理 128，
工具 64。工具 Server 空闲超时为 30 秒，不受代理 `--idle_timeout_sec` 参数影响。

## 组合示例启动参数

组合示例支持以下启动参数，时间单位见表：

| 参数 | 默认值 | 作用 |
|---|---|---|
| `--admin_address` | `127.0.0.1:8080` | 独立网页工具 Server 的监听地址 |
| `--upstream_host` / `--upstream_port` | 空 / 0 | 可选固定实际上游；两者一起设置，仅作用于 SOCKS5 和 HTTP CONNECT |
| `--connect_timeout_ms` | 15000 毫秒 | SOCKS5、HTTP CONNECT 及普通 HTTP 转发到上游的 TCP 建连等待 |
| `--handshake_timeout_ms` | 30000 毫秒 | SOCKS5 整个握手，包括等待客户端报文和连接上游 |
| `--request_timeout_ms` | 30000 毫秒 | 普通 HTTP 转发的整个请求，包括 TCP 建连和等待响应 |
| `--idle_timeout_sec` | 60 秒 | 客户端连接空闲超时；小于等于 0 时关闭空闲检查 |

例如把 TCP 建连等待延长到 30 秒，同时给其他阶段留出时间：

```sh
./example/socks5_proxy/build/socks5_http_proxy 127.0.0.1:1080 \
  --connect_timeout_ms=30000 \
  --handshake_timeout_ms=60000 \
  --request_timeout_ms=60000 \
  --idle_timeout_sec=120
```

提高建连超时时，SOCKS5 握手和普通 HTTP 请求的总超时应更长；空闲检查也不要
先于建连等待关闭客户端连接。CONNECT 成功后的隧道没有上述 HTTP 请求总超时。
TCP 建连超时不包括系统 DNS 查询，也不控制隧道内客户端的 TLS 握手及 curl 自身的
`--max-time`。参数无须修改 brpc 核心源码；其他示例及公共 Options 的默认值不变。

另一个终端启动前述本地 HTTP 服务，然后分别通过 SOCKS5 和 HTTP CONNECT 访问：

```sh
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 http://localhost:8000/
curl --noproxy "" -x http://127.0.0.1:1080 --proxytunnel http://localhost:8000/
```

HTTPS 使用 `curl -x http://127.0.0.1:1080 https://example.com/` 会自动发起
CONNECT；普通 HTTP 不加 `--proxytunnel` 时走正向转发。

核心配置如下，两种代理也可以分别传入自定义处理器：

```cpp
#include "brpc/http_proxy.h"
#include "brpc/server.h"
#include "brpc/socks5.h"

brpc::Socks5Options socks5_options;
socks5_options.connect_timeout_ms = 15000;
socks5_options.handshake_timeout_ms = 30000;
brpc::HttpProxyOptions http_options;
http_options.connect_timeout_ms = 15000;
http_options.request_timeout_ms = 30000;

brpc::ServerOptions options;
options.socks5_service = std::make_shared<brpc::Socks5Service>(socks5_options);
options.http_master_service = brpc::NewHttpProxyMasterService(
    std::make_shared<brpc::HttpProxyService>(http_options));
options.enabled_protocols = "socks5 http_proxy";
options.strict_enabled_protocols = true;
options.idle_timeout_sec = 60;

brpc::Server server;
server.Start("127.0.0.1:1080", &options);
```

SOCKS5 的首字节为 `0x05`，HTTP CONNECT 以 `CONNECT` 开始。协议探测只在
握手阶段进行；建立隧道后，连接继续通过已选协议的会话状态转发原始字节。
严格白名单排除普通 `http/h2` 和其他隐式协议，避免普通 HTTP 入口先接走 CONNECT。

## 自定义上游及实际连接地址

两种隧道协议的 Options 都支持 `upstream_factory`，每条连接创建独立的
`brpc::ProxyUpstream`。空 factory 保留默认 brpc TCP 直连实现。连接、客户端数据
处理、上游发送、上游返回数据处理、上游解析及关闭均可覆盖，客户端读取和写回
仍由框架负责。完整接口、回调约定及示例见
[HTTP proxy README](../http_proxy/README.md#自定义隧道上游)。

自定义 OnUpstreamData 处理完上游返回数据后，调用
`tunnel().WriteClient(data, std::move(done))` 写回客户端，无需委托父类实现。
WriteClient 不再触发 OnUpstreamData；自定义传输的原始读取回调仍调用 Receive，
由框架保持握手回复和数据处理顺序。输出接口和完成回调约定见上述文档。

组合示例中的 `FixedUpstream` 演示连接独立于客户端目标的实际地址：

```sh
python3 -m http.server 8000 --bind 127.0.0.1
./example/socks5_proxy/build/socks5_http_proxy 127.0.0.1:1080 \
  --upstream_host=127.0.0.1 --upstream_port=8000
```

客户端请求的目标可以是无法解析的逻辑地址，两种隧道都会实际连接本机 8000：

```sh
curl --noproxy "" --socks5-hostname 127.0.0.1:1080 http://logical.invalid:1234/
curl --noproxy "" -x http://127.0.0.1:1080 --proxytunnel http://logical.invalid:1234/
```

这只是固定 TCP 目标示例，未自动实现其他代理的认证或握手。若实际连接到 SOCKS5、
HTTP CONNECT 或其他网关，用户 Connect 实现必须完成该上游的协商再报告成功，
可通过 ParseUpstreamData 在客户端握手期间处理上游控制帧。普通 HTTP 正向转发
继续由 HttpProxyService::Forward 定制，不受固定上游参数影响。
组合示例未启用 RDMA 握手。原 `socks5_proxy` 和自定义回显示例保留各自配置。

组合集成测试复用 HTTP 代理测试与 SOCKS5 握手/转发测试，额外覆盖同一端口的
两种协议并发、HTTP/HTTPS 经 SOCKS5，以及同时停止活动隧道和未完成的握手：

```sh
python3 example/socks5_proxy/mixed_smoke_test.py \
  example/socks5_proxy/build/socks5_http_proxy
```

本次只新增组合示例和集成测试，修改示例的 CMake 配置及本文档；无需修改 brpc
核心源码即可同时启用两种协议。依赖上一轮已实现的 HTTP proxy 和 SOCKS5 协议。
组合集成测试覆盖可配置 SOCKS5 握手及 HTTP 请求超时，详情见 mixed_smoke_test.py。
组合测试还覆盖内建网页和静态资源访问、两个 Server 同时停止以及工具端口占用时的启动回滚。
本地组合集成测试 35/35 通过。

### 自定义回显示例与 curl

对 `socks5_custom_service` 执行 `curl --http0.9 --socks5 ... http://baidu.com/`
会等待响应结束：示例把收到的 `GET / HTTP/1.1...` 原样写回。`--http0.9`
允许 curl 将这些没有 HTTP 响应头的字节作为正文，连接关闭才表示正文结束。
停止服务会关闭连接，所以此时 curl 才结束。curl 默认缓冲输出，也可能让已经
收到的内容直到结束才显示。这里不需要调整 `done` 或 brpc 的写入/EOF 流程。

观察回显可以加 `-N` 关闭 curl 输出缓冲，并设置超时（超时退出是预期行为）：

```sh
./example/socks5_proxy/build/socks5_custom_service 127.0.0.1:1081
curl -N --max-time 2 --noproxy "" --http0.9 \
  --socks5 127.0.0.1:1081 http://127.0.0.1:9/
```

要访问真实网站，请运行默认代理 `socks5_proxy`，再执行：

```sh
curl --noproxy "" --socks5 127.0.0.1:1080 http://baidu.com/ -vvv
```

自定义服务若要继续转发到目标，应将 CONNECT 和 DATA 委托给
`brpc::Socks5Service::Process`，如下面的 `MySocks5Service`。若要自行响应 HTTP，
需累计 DATA 分片并解析请求，返回合法 HTTP 响应及明确的正文长度或结束标志；
不能把每个 DATA 回调当作完整请求并直接关闭连接。

新增单元测试遵循仓库的 Google Test 构建流程：

```sh
cmake -S . -B build -DBUILD_UNIT_TESTS=ON
cmake --build build --target brpc_socks5_unittest -j6
./build/test/brpc_socks5_unittest
```

## 服务接入

```cpp
#include "brpc/server.h"
#include "brpc/socks5.h"

brpc::Socks5Options proxy_options;
proxy_options.max_pending_bytes = 1024 * 1024;
proxy_options.handshake_timeout_ms = 10000;
proxy_options.connect_timeout_ms = 3000;
if (!proxy_options.IsValid()) {
    return -1;
}

brpc::ServerOptions options;
options.socks5_service = std::make_shared<brpc::Socks5Service>(proxy_options);
options.enabled_protocols = "socks5";
options.max_connections = 128;

brpc::Server server;
server.Start("127.0.0.1:1080", &options);
// ...
server.Stop(0);
server.Join();
```

`socks5_service` 默认为空，协议默认关闭；仅设置 enabled_protocols 不会自动
开启代理。配置检查在协议解析器和会话创建中完成，Server::Start 不做 SOCKS5
专用校验；应用可通过 Socks5Options::IsValid 提前检查参数。
Socks5Service 不需要单独 Start/Stop/Join，同一个实例可以由多个 Server 共享，
每个 Server 停止时只关闭其自身连接，也支持停止后重启。
它是服务端协议，未实现 Channel 的 SOCKS5 客户端支持。

HTTP/h2 内建协议遵循 brpc 原有规则，即使 enabled_protocols="socks5" 也仍存在。
RDMA 握手也按原有规则保留。必须显式选择该监听端口的协议，例如 "socks5"
或 "baidu_std socks5"，不要为代理使用空的 enabled_protocols（空值启用默认集合）。
默认集合中的 nshead 要等到偏移 24 的 magic 到达才能排除自身，可能阻塞只有
3 字节的 SOCKS5 协商。当前采用原有协议探测流程，没有额外的优先协议机制。

## 用户扩展

`Socks5Service` 保留默认无认证 TCP 代理实现。继承它并覆盖 `Process`，即可
自定义 METHOD、CONNECT 和 DATA 的处理；也可以修改目标地址后调用基类实现：

```cpp
#include "brpc/closure_guard.h"

class MySocks5Service : public brpc::Socks5Service {
public:
    void Process(brpc::Socks5Connection* connection, brpc::Socks5Request* request,
                 google::protobuf::Closure* done) override {
        if (request->type == brpc::Socks5Request::CONNECT) {
            if (request->port == 25) {
                brpc::ClosureGuard guard(done);
                connection->ReplyConnect(2);  // 策略拒绝，回复后关闭
                return;
            }
            // 可以在这里改写 request->host / request->port，实现自定义路由。
        }
        brpc::Socks5Service::Process(connection, request, done);
    }
};

options.socks5_service = std::make_shared<MySocks5Service>();
```

消息内容：

| 类型 | 可读取/修改的内容 | 处理要求 |
|---|---|---|
| METHOD | methods：客户端提供的认证方法列表 | 调用 ReplyMethod(0) 接受无认证，或 ReplyMethod(255) 拒绝 |
| CONNECT | address_type、host、port | 调用 ReplyConnect；可以委托默认实现，也可自行处理逻辑目标 |
| DATA | data：IOBuf 字节块 | 自行消费、修改、转发或通过 connection->Write 写回客户端 |

DATA 不是完整的应用报文，用户若解析 HTTP 等内容，需自行处理 TCP 分片。
当前认证流程仍只支持方法 0；不支持用户名密码、BIND 或 UDP。报文格式错误
由协议层回复并关闭，不会作为有效请求交给用户。请勿修改 request->type。
`ReplyConnect(0)` 不会自动建立上游连接，只会回复成功并进入数据处理阶段。

`Socks5Connection` 提供 socket_id、is_closed、ReplyMethod、ReplyConnect、Write、
Close，以及 set_user_data/user_data。用户状态使用 shared_ptr<void> 保存，每个
连接独立；连接句柄可复制并在回调之外保留，关闭后读写失败。回复和写入函数
返回 bool，并等待 brpc 写入完成；Write 会消费传入的 IOBuf。

`done` 的约定与 brpc 的异步服务类似：

- 每次 Process 必须恰好调用一次 done->Run，或用 ClosureGuard 保证调用。
  委托基类时直接把 done 传入，不能再自行调用它。
- 可以异步处理；connection/request 指针在 Run 之前保持有效，Run 是最后一次
  使用这些指针的时点。不要删除 done。需要长期保存时复制连接句柄或请求数据。
- 同连接的下一条消息等本次 done 完成才会交付，不同连接可以并发处理。
  修改请求数据不改变框架所统计的原始待处理字节数，额外分配由用户管理。
- 连接关闭不会自动替用户调用 done。异步任务必须在失败或取消后也完成；
  Server::Join 等待未完成任务，不能在本连接的 Process 中调用 Server::Join。
- 框架保留任务及 Socket 引用到 done 完成，客户端和默认上游均启用 EOF 延迟，
  避免 EOF 抢先清理尚未处理的数据。这不等同于完整的双向 TCP 半关闭。

完整的自行处理示例见本目录 `custom_server.cpp`；异步处理、顺序及停止等待
示例见 `test/brpc_socks5_unittest.cpp` 中的 AsyncEchoService。

## 实现结构

```text
客户端 Socket → ParseSocks5Message → ExecutionQueue → Socks5Service::Process
                                                        ↓ 默认 DATA 实现
                                                  ProxyUpstream::OnClientData
                                                        ↓
                                                  WriteUpstream → 上游

上游 Socket → ParseUpstreamData → ExecutionQueue → OnUpstreamData → WriteClient
自定义上游  → ProxyTunnel::Receive ───────┘
```

解析完成后直接通过 `TcpTunnel::Submit()` 提交完整处理函数，按解析顺序执行。
复用 bthread::ExecutionQueue 的单消费者调度，不再维护 Action、派发消息、ready
标记或手写 drain。Connect、客户端数据和上游数据共用队列，保证握手回复先于数据。
普通 HTTP 正向代理仍使用原有 HTTP 解析和服务派发流程。

数据使用 IOBuf::cutn 转移，避免 IOBuf→string 复制；发送使用 Socket::Write。
Submit 在消费输入前检查关闭状态和积压上限，失败不消费数据。任务持有输入 Socket
的 PostponeEOF/CheckEOF 保护及客户端 Socket 引用，直到处理或异步 done 完成；
因此 EOF 不会丢失尾部数据，Acceptor::Join 也会等待未完成任务。

默认上游 `ParseUpstreamData(IOBuf*, Socket*, bool)` 直接提交数据并返回
MakeMessage(nullptr)，不再创建 UpstreamDataMessage，也没有 Process/Dispatch 阶段。
用户处理上游协商帧时仍可返回 NOT_ENOUGH_DATA 或消费帧后返回空消息；负载数据
委托基类处理。Socket 参数供调度入口保留 EOF 保护；自定义传输继续使用 Receive。

会话与上游适配器的关系如下，HTTP CONNECT 使用相同结构：

```text
Socks5Session / HttpProxySession（继承 TcpTunnel）
    │ shared_ptr：持有该连接的一个上游适配器
    ▼
ProxyUpstream（用户可覆盖的上游处理）
    │ 持有客户端操作句柄
    ▼
ProxyTunnel ── weak_ptr ──→ 原会话
```

`TcpTunnel` 是内部会话，管理客户端 Socket、任务顺序和关闭状态；
`ProxyUpstream` 是上游适配器，管理上游连接与数据处理；`ProxyTunnel` 是公开的
客户端操作句柄，提供 Receive、WriteClient、Close 等操作。它不拥有另一条连接，
也不延长会话生命周期，因此不会与会话持有的适配器形成强引用环。

协议处理 CONNECT 时仅调用 `TcpTunnel::CreateUpstream()`：创建句柄、调用用户
factory、将适配器存入会话，随后才调用适配器的 Connect。原来的
`ProxyTunnelAccess::Bind()` 和 `AttachUpstream()` 已删除。默认 Socket 的读取回调
从会话取得同一个适配器，不再维护单独的 owner 绑定。处理中的回调临时持有
适配器的 shared_ptr；会话关闭后拒绝取得新适配器，并取消正在进行的上游操作。

Socket::NotifyOnFailed 关联两侧关闭。上游启用 defer_eof，输入 Socket 的 EOF 保护保留到
其数据写出后再释放，避免收到数据后紧接着 EOF 时丢失尾部数据。
客户端首次解析时同样启用延迟 EOF，异步处理器的 done 完成后才释放任务。
解析器调用已有的 Socket::fail_me_at_server_stop，与 RTMP 的流式连接一致。
Server::Stop 通过 Acceptor 使客户端连接失败，失败通知关闭上游并清理会话。
队列任务持有客户端 Socket 引用，原有 Acceptor::Join 等待引用释放，保证任务
结束后再返回；Server 中没有 SOCKS5 专用判断或生命周期调用。
会话状态和运行时注册表均使用 bthread::Mutex，运行时完成等待使用配套的
bthread::ConditionVariable；网络等待、用户回调及关闭 Socket 均在这些锁外执行。

SOCKS5 和 HTTP CONNECT 的串行队列、Socket 引用、上游创建和双侧清理
统一使用 `src/brpc/details/tcp_tunnel.{h,cpp}`，连接/写入/失败通知复用
`src/brpc/details/proxy_socket.{h,cpp}`。METHOD/CONNECT 的报文和用户 Process/done
接口仍由 SOCKS5 模块处理。HTTP 代理接入及本次原始源码改动列表见
[HTTP proxy README](../http_proxy/README.md)。

本轮调度简化修改此前新增的代理模块和相关测试。**原始 brpc 源码改动**：
`src/brpc/policy/http_rpc_protocol.h/.cpp` 抽出接收 HttpContext、Server、Socket 的
VerifyHttpRequest 重载，供直接调度的 CONNECT 握手复用现有认证；原消息入口委托
该重载，保留 HTTP/HTTP2 原有认证行为。未修改 Server、Socket、InputMessenger
或 bthread::ExecutionQueue 的实现。

## 原始 brpc 源码改动标注

本次修改了下列 **8 个已有源码文件**：

| 文件 | 修改原因 |
|---|---|
| src/brpc/options.proto | 增加 PROTOCOL_SOCKS5=30，已有编号不变 |
| src/brpc/global.cpp | 注册服务端 socks5 Protocol |
| src/brpc/server.h | 增加显式 socks5_service 配置 |
| src/brpc/rdma/rdma_handshake_server.cpp | TCP fallback 握手在 magic 不完整时比较已有前缀，不匹配立即尝试其他协议 |
| src/brpc/rdma/rdma_endpoint.cpp | RDMA 模式的握手使用相同的部分前缀检查 |
| src/brpc/socket.h | 增加默认关闭的 defer_eof 选项、内部状态，以及首次解析时的 EnableDeferredEOF 方法 |
| src/brpc/socket.cpp | 初始化 defer_eof 状态 |
| src/brpc/socket_inl.h | 自定义 messenger 可选择延迟 EOF 至消息处理完成 |

RDMA 的 "RDMA" / "RDM3" magic 在不足 4 字节时也检查已有前缀：不匹配立即
返回 TRY_OTHERS；空输入和匹配的部分前缀仍返回 NOT_ENOUGH_DATA。这样不会阻塞
3 字节 SOCKS5 方法协商，完整握手及等待 ACK 的处理保持原有流程。
此前添加的 prefer_initial、SetInitialProtocol 和初始探测索引已移除，
此前 SOCKS5 探测对 server.cpp、protocol.h 和 InputMessenger 的改动已移除。
后续 HTTP proxy 的通用严格白名单改动另见 HTTP proxy README。
Server 未启用 SOCKS5 时其解析器直接返回 TRY_OTHERS。
defer_eof 默认关闭，原有 EOF 行为保持不变。

本次扩展接口在此前实现上修改 src/brpc/socks5.h（公开请求、连接及虚函数）、
src/brpc/policy/socks5_protocol.cpp（默认处理及异步派发），并为原始 brpc 文件
src/brpc/socket.h 增加 EnableDeferredEOF。server.cpp、Protocol、InputMessenger
及其处理器不需要新改动。未修改其他协议的处理行为。

新增文件：src/brpc/socks5.h、src/brpc/policy/socks5_protocol.h/.cpp、
test/brpc_socks5_unittest.cpp；已有 CMake/Make/Bazel 源码收集规则会纳入新源文件。
另修改了 4 个原有测试文件：test/brpc_socket_unittest.cpp、
test/brpc_input_messenger_unittest.cpp、test/brpc_channel_unittest.cpp、
test/brpc_ssl_unittest.cpp。它们之前硬编码协议编号 30 作为测试 dummy 协议，
现改为 ProtocolType_MAX + 1，避免与新增正式协议冲突。

另更新了本目录的 demo、构建及集成测试。工作区先前的 echo、test/CMakeLists.txt
和 test/find_cstr_unittest.cpp 修改未动。

## 当前范围

- 不再使用每连接系统线程或裸 socket 的 poll/send/recv 循环；建连和发送等待由
  bthread/brpc 调度。域名解析仍调用系统 getaddrinfo，DNS 查询不受 TCP 建连期限限制。
- 有界缓存包含已出队但尚未写完的数据；超限关闭，未实现暂停读取的完整背压。
- 上游 EOF 前已解析数据会完成转发，但尚未实现 TCP 半关闭及两方向完整 drain。
- 不支持用户名密码、BIND、UDP ASSOCIATE。DNS 失败返回 REP=4，其余建连失败
  返回 REP=5，暂未细分所有 SOCKS5 错误。
- 示例空闲超时为 30 秒、连接上限 128，默认监听回环地址；尚无目标访问控制。

## 本机验证环境

macOS arm64，AppleClang 21，Protobuf 3.21.12，OpenSSL 3.6.4。
本机默认 Protobuf/Abseil 存在版本不匹配，验证使用已安装的 protobuf@21，brpc
构建目录为 /tmp/brpc-socks5-build。当前 demo 的本地 CMake 缓存已指向该构建。

若清理临时构建，请为 brpc 和 demo 配置同一套 Protobuf 库、头文件及 protoc；
在此 Homebrew 环境中还需避免 /opt/homebrew/include 的新版 Protobuf 头文件优先于
protobuf@21。所有这些设置都位于本地 CMake 缓存，没有写入源码构建配置。

## 本次验证结果

- 新增 Google Test：20/20 通过，包括自定义 METHOD/CONNECT/DATA、连接用户状态、
  目标改写后委托默认实现、异步顺序、客户端 EOF 和 Server::Join 等待，以及
  RDMA 匹配/不匹配的部分 magic、共享服务的两个
  Server 独立停止及重启（同时启用 baidu_std 和 socks5）。
- SOCKS5 集成测试：13/13 通过，包含默认代理的 12 项及自定义服务示例的 1 项；包括
  RDMA fallback 后同连接 SOCKS5 协商、HTTP
  同端口共存、上游 EOF 尾部数据、大数据双向转发、活动会话停止，以及 IPv4/IPv6/域名。
- 本次重跑原有 InputMessenger 测试通过；Server 启停、协议选择、混合协议连接
  限制等 6 项测试通过。
- 此前实现验证中，SSL connect_on_create 和选定的 3 项 Channel 初始化测试通过；
  原有 Server 测试 44/45 通过，bind_client_host_and_network_device 因本机没有
  Linux 网卡名 lo 而失败。
- 此前原有 Socket 测试 19/21 通过；socket_buffer_options_before_connect 和
  socket_buffer_options_before_accept 的接收缓冲区精确值断言失败，期望 262144，
  实际为 277644。这 3 项平台相关断言未修改，未宣称完整回归全部通过。
- 本机构建 WITH_RDMA=OFF，验证覆盖 TCP fallback 路径；RDMA 模式的同样前缀
  改动尚未在启用 RDMA 的构建及硬件上验证。
