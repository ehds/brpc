# HTTP forward proxy and CONNECT example

独立注册 `http_proxy` 服务端协议，支持 HTTP/1.1 普通请求转发及 CONNECT
双向 TCP 隧道。握手复用 HTTP parser；普通转发通过原有 `http_master_service`
派发和响应流程；CONNECT 与 SOCKS5 共享 TCP 隧道模块。HTTPS 经隧道转发，
代理不解密 TLS。示例默认只监听本机。

## 构建与运行

在仓库根目录重新构建修改后的 brpc。新增严格白名单、HTTP context 扩展点及上游工厂字段改变了 C++ ABI，
必须重编译调用方并使用同一次构建导出的头文件和库，不能混用旧 brpc。

```sh
cmake -S . -B build -DBUILD_UNIT_TESTS=OFF
cmake --build build -j6
cmake -S example/http_proxy -B example/http_proxy/build \
  -DBRPC_INCLUDE_PATH="$PWD/build/output/include" \
  -DBRPC_LIB="$PWD/build/output/lib/libbrpc.a"
cmake --build example/http_proxy/build --clean-first -j6
./example/http_proxy/build/http_proxy 127.0.0.1:8080
```

依赖版本需与 brpc 构建一致。macOS 使用 Homebrew protobuf@21/OpenSSL 时，
可在两个 CMake 配置命令中加上对应的 Protobuf_INCLUDE_DIR、Protobuf_LIBRARY、
Protobuf_PROTOC_EXECUTABLE、OPENSSL_ROOT_DIR；使用仓库已有构建目录时保留其配置。

另一个终端执行。`--noproxy ""` 防止环境中的 NO_PROXY 绕过代理：

```sh
curl --noproxy "" -x http://127.0.0.1:8080 http://example.com/ -v
curl --noproxy "" -x http://127.0.0.1:8080 https://example.com/ -v
curl --noproxy "" -x http://127.0.0.1:8080 --proxytunnel http://example.com/ -v
```

## 接入与用户扩展

```cpp
#include "brpc/http_proxy.h"
#include "brpc/server.h"

brpc::HttpProxyOptions proxy_options;
proxy_options.connect_timeout_ms = 3000;
proxy_options.request_timeout_ms = 10000;
proxy_options.max_pending_bytes = 1024 * 1024;
if (!proxy_options.IsValid()) return -1;

brpc::ServerOptions options;
options.http_master_service = brpc::NewHttpProxyMasterService(
    std::make_shared<brpc::HttpProxyService>(proxy_options));
options.enabled_protocols = "http_proxy";
options.strict_enabled_protocols = true;
options.idle_timeout_sec = 30;
options.max_connections = 128;
brpc::Server server;
if (server.Start("127.0.0.1:8080", &options) != 0) return -1;
// ...
server.Stop(0);
server.Join();
```

`NewHttpProxyMasterService` 创建 protobuf service 适配器，由 Server 通过已有的
`http_master_service` 所有权规则销毁；适配器保留传入的 shared_ptr。可传入自定义
HttpProxyService 子类。没有新增代理专用的 ServerOptions 字段或 Start/Stop/Join。

必须显式选择 `http_proxy` 并开启严格白名单。HTTP RPC 与 HTTP proxy 使用相同的
HTTP 文本格式，不能靠 magic 区分用途；这个配置保证端口只注册一个 HTTP 入口。
`strict_enabled_protocols` 是通用选项，默认 false，保留 brpc 自动启用 HTTP/h2 和
RDMA handshake 的原行为；为 true 且白名单非空时只启用列出的协议。

独立 internal_port 使用同一白名单；http_proxy 在该端口继续通过共享 HTTP 流程处理
内建服务，不调用转发钩子、不建立 CONNECT 隧道。此配置不提供 internal_port 的 h2
入口。公共代理端口上的 `/health` 等 origin-form 请求不会进入内建服务路由。
不要同时在同一端口启用 `http` 和 `http_proxy`；如需普通 RPC，使用另一个 Server。

```cpp
class MyProxy : public brpc::HttpProxyService {
public:
    // CONNECT 策略或目标改写；返回 false 时默认回复 403 并关闭。
    bool RouteConnect(std::string* host, int* port) override {
        if (*port == 25) return false;
        // 可修改 *host、*port。
        return true;
    }

    // 普通 HTTP 请求：可读取/修改 controller->http_request() 和请求正文，
    // 自行生成响应，也可以修改后继续委托默认转发。
    void Forward(brpc::Controller* controller,
                 google::protobuf::Closure* done) override {
        brpc::HttpProxyService::Forward(controller, done);
    }
};
```

Forward 必须恰好调用一次 done；可以异步完成。委托基类时不能再自行调用 done。
controller 在 done 之前有效，完成后不能继续访问；框架保留处理器到异步完成。
RouteConnect 在 bthread 上同步调用，不能保留传入指针。不同连接的钩子可能并发，
用户共享状态需要同步。RouteConnect 必须最终返回，Server::Join 等待活动隧道任务。
默认没有代理认证；默认允许 CONNECT 目标，公开部署前应按应用需求实现策略。

## 处理流程和复用

普通 HTTP：http_proxy → 共享 HTTP 解析 → ProcessHttpRequest → http_master_service
适配器 → Forward → HTTP Channel → 原状态码、响应正文。上游连接失败回复 502，
请求超时回复 504。
默认实现清理 Connection 指定的字段和逐跳头，按目标 URL 重建 Host，按解码后的
正文重新生成传输长度。支持 POST、HEAD、HTTP 错误响应、chunked 请求和 gzip 响应。
普通 HTTP 继续使用 brpc 的响应发送流程，响应结束按 HTTP framing 判断。

CONNECT：解析 authority → 立即安装连接级状态 → RouteConnect → 连接上游 → 单次回复。
成功的 200 响应没有 Content-Length/Transfer-Encoding；写完后才处理原始字节队列。
CONNECT 同一次读取后的数据及连接建立期间的数据直接入队，不再交给 HTTP parser。
解析阶段直接将完整处理函数提交给 `TcpTunnel::Submit()`，复用
bthread::ExecutionQueue 按提交顺序执行。没有 Action、派发消息、ready 标记或手写
串行 drain。握手、客户端数据和上游数据共用队列，上游提前发送的数据也排在
CONNECT 回复之后；用户的异步 done 完成后才执行下一项任务。
Submit 返回 butil::Status：成功为 OK，关闭为 ECANCELED，积压超限为 ENOBUFS
（同时关闭会话）；失败不消费输入。解析入口将失败状态转换成 ParseResult。

`src/brpc/details/tcp_tunnel.{h,cpp}` 管理会话、字节上限和调度。每个任务持有
客户端 Socket 引用及输入 Socket 的 EOF 保护，直到处理完成，避免 EOF 丢失尾部
数据，并让 Server::Stop/Join 继续使用原有 Acceptor 机制。Close 停止接收任务、
取消上游并跳过排队任务；不会等待消费者，因而可以在处理回调中调用。

```text
客户端 Socket → HTTP CONNECT/原始数据解析 → ExecutionQueue → Connect/OnClientData
上游 Socket   → ParseUpstreamData ───────────────────┘     → OnUpstreamData
自定义上游    → ProxyTunnel::Receive ────────────────┘     → WriteClient
```

默认 `ParseUpstreamData(IOBuf*, Socket*, bool)` 直接提交上游数据并返回空消息，
不再创建 UpstreamDataMessage 或经过 Process/Dispatch。自定义解析器可消费控制帧，
或对未完整的帧返回 NOT_ENOUGH_DATA；负载数据委托基类处理。新增的 Socket 参数
用于保留本次输入的 EOF 保护。ProxyTunnel::Receive 直接提交自定义传输的数据。

ProxyTunnel::Impl 只持有会话的弱引用。客户端输出通过 WriteClient，上游输出通过
WriteUpstream 调用适配器的 OnClientData；默认适配器使用 brpc Socket 写出。
会话锁只保护状态和入队，不覆盖网络等待或用户处理函数。

共享的 `src/brpc/details/proxy_socket.{h,cpp}` 提供：

- ConnectProxySocket：系统 DNS 解析、地址尝试、共同连接截止时间、brpc Socket 创建。
- WriteProxyData：写入 IOBuf 并等待写入完成。
- WatchProxySocketFailure：基于 NotifyOnFailed 的一次性失败通知。

SOCKS5 和 HTTP CONNECT 都复用以上函数及隧道队列实现。普通 HTTP RPC 的
HttpContext 不包含代理会话字段，HTTP parser/dispatch 中也没有代理专用分支。

## 自定义隧道上游

`brpc/proxy_upstream.h` 提供两种隧道协议共用的上游接口。SOCKS5 和 HTTP CONNECT
Options 的 `upstream_factory` 每条连接创建一个独立实例；不设置时采用默认 brpc TCP
实现。普通 HTTP 转发仍使用 `Forward`，不经过字节隧道上游接口。

| 接口 | 默认行为 | 可定制内容 |
|---|---|---|
| Connect | 连接 request.route 的 TCP 地址 | 选择其他实际地址、上游代理协商、其他传输 |
| OnClientData | 调用虚函数 WriteUpstream | 缓存、解析、变换、封装客户端数据 |
| WriteUpstream | brpc Socket 写入并等待完成 | 自定义发送方式 |
| ParseUpstreamData | 原始字节进入隧道队列 | 默认 brpc 读流程上的控制帧、分帧、上游握手 |
| OnUpstreamData | 调用 tunnel().WriteClient 写回客户端 | 返回数据变换、解码、过滤 |
| Close | 关闭默认上游 Socket | 取消自定义任务、清理资源 |

`ProxyConnectRequest.target` 保留客户端请求目标；`route` 是原有 RouteConnect 钩子
产生的连接建议，默认等于 target。两者都不强制实际连接地址。ConnectTcp 接收独立
的实际 TCP 目标；它不改写原始 target。Connect 返回 error=0 表示自定义上游已经
能够处理客户端数据；bound 用于 SOCKS5 回复，不要求等于客户端目标。

```cpp
class GatewayUpstream : public brpc::ProxyUpstream {
public:
    explicit GatewayUpstream(const brpc::ProxyTunnel& tunnel)
        : ProxyUpstream(tunnel) {}

    void Connect(const brpc::ProxyConnectRequest& request, ConnectDone done) override {
        // request.target 保留逻辑目标，可用于选路或上游协商。
        brpc::ProxyTarget actual;
        actual.host = "127.0.0.1";
        actual.port = 9000;
        ConnectTcp(actual, request.timeout_ms, std::move(done));
    }

    void OnClientData(butil::IOBuf* data, Done done) override {
        // 这里可以处理客户端数据，再委托默认发送。
        ProxyUpstream::OnClientData(data, std::move(done));
    }

    void OnUpstreamData(butil::IOBuf* data, Done done) override {
        // 这里可以处理上游返回数据，再通过公开输出接口写回客户端。
        tunnel().WriteClient(data, std::move(done));
    }
};

brpc::ProxyUpstreamFactory factory = [](const brpc::ProxyTunnel& tunnel) {
    return std::unique_ptr<brpc::ProxyUpstream>(new GatewayUpstream(tunnel));
};
socks5_options.upstream_factory = factory;
http_options.upstream_factory = factory;
```

ConnectTcp 的完成只表示 TCP 连接建立。若实际目标是另一台代理，还需要完成其认证
和代理协议协商后，才能调用外层 Connect 的 done。`ParseUpstreamData` 在独立的
brpc Socket 读流程中执行，包括 Connect 尚未完成时；可消费控制帧并返回
MakeMessage(nullptr)，不完整帧返回 NOT_ENOUGH_DATA，协商后的负载委托基类处理。
该钩子不要等待隧道队列，也不要返回与协议处理器不兼容的自定义消息类型。

完全自定义传输可以覆盖 Connect、WriteUpstream、Close，不创建 TCP Socket。
自己的读取/RPC 回调获得数据后调用 `tunnel().Receive(&data)`，由框架入队并调用
OnUpstreamData。Receive 消费 IOBuf，返回 true 表示已接纳，不表示客户端写入完成；
返回数据始终排在客户端握手回复之后。按流顺序提交数据，分片不等于完整业务消息。

`ProxyTunnel::WriteClient(data, done)` 是处理后数据的客户端输出接口，不再调用
OnUpstreamData，也不再入队。在 OnUpstreamData 中调用它，并在写出完成后才完成
该钩子的 done，以保留握手和数据处理顺序；读取/RPC 回调的原始数据仍使用 Receive。
WriteClient 可能等待 Socket 写出，完成回调可能在调用返回前执行，恰好调用一次：
0 表示已写入 Socket，EIO 表示写入失败或会话已关闭/释放，不表示客户端应用已收到。
传入 IOBuf 必须存活到完成回调执行，可能在失败时也被消费。可以直接把钩子的 done
传给 WriteClient，完成后不要再访问该钩子的 data 或实例，也不要再次调用 done。
默认 OnUpstreamData 同样委托 WriteClient，自定义处理无需调用父类实现。

Connect/OnClientData/OnUpstreamData 按会话串行执行，允许异步完成；ParseUpstreamData
和 Close 可与它们并发，用户状态需加锁。每次 done 必须恰好调用一次，包括关闭后；
传入 request/data 和实例在完成前有效，完成后不得继续访问。发送完成不要求等到
目标应用回复；不要等待同一串行队列中的后续动作。自定义实现应遵守 timeout_ms，
Close 幂等并取消/完成未结束操作，停止自己的读取任务，不能等待串行队列来执行关闭。
异步读取回调可以保留 ProxyTunnel 副本和独立的共享状态；会话关闭后 Receive 返回
false。框架使用弱会话引用，Server::Join 等待当前连接/处理回调完成。

## 原始源码改动标注

| 文件 | 改动 |
|---|---|
| src/brpc/server.h / server.cpp | 新增通用 strict_enabled_protocols，调整白名单筛选；未增加代理专用生命周期逻辑 |
| src/brpc/options.proto / global.cpp | 添加 PROTOCOL_HTTP_PROXY=31，按标准方式注册服务端 parse/process/verify handler |
| src/brpc/policy/http_rpc_protocol.h / .cpp | 抽出可自定义 context 的通用解析入口，允许 context 定制 progressive-read 判断；增加显式上下文的 VerifyHttpRequest 重载供 CONNECT 复用认证；保留原 HTTP 派发及响应行为 |
| src/brpc/details/http_message.h | 提供原始 request-target 的只读访问，用于校验无效端口，避免 URI 归一化后变成默认端口 |
| src/brpc/policy/socks5_protocol.cpp | 握手和客户端 Process 扩展接口接入通用队列；删除上游专属 Parse、TO_CLIENT 和协议派发分支；处理任务直接提交 ExecutionQueue 并持有用户服务，握手超时任务保留运行时计数 |
| src/brpc/socks5.h | Socks5Options 增加每连接 upstream_factory；与 HTTP CONNECT 共用公开上游接口 |
| CMakeLists.txt | 将新增 http_proxy.proto 纳入 protobuf 生成列表 |

新增文件：`http_proxy.{h,cpp,proto}`、`policy/http_proxy_protocol.{h,cpp}`、
`details/tcp_tunnel.{h,cpp}`、`details/proxy_socket.{h,cpp}`、`proxy_upstream.{h,cpp}`、
`details/proxy_upstream.h`、本目录示例及 HTTP proxy / TCP tunnel / proxy upstream
单元测试。Make/Bazel 的现有收集规则自动包含新增源码和 proto。

此前客户端输出接口调整修改 `src/brpc/proxy_upstream.h / .cpp`（此前新增的代理
模块），公开 WriteClient 并让默认 OnUpstreamData 委托它；同步修改测试和示例
文档。当时未修改原始 brpc 的 server、socket 或已有协议解析/派发源码。

后续上游调度重构新增 `details/tcp_tunnel.cpp`，调整通用隧道和 ProxyTunnel 绑定，
并修改上述 SOCKS5 协议源码及此前新增的 HTTP proxy 协议模块。原始 Server、Socket、
InputMessenger 源码未改动。Connect、数据处理钩子和 WriteClient 用法不变；ParseUpstreamData 的新签名为
`ParseUpstreamData(IOBuf*, Socket*, bool)`，自定义解析器需增加 Socket 参数。

## 验证与当前范围

```sh
python3 example/http_proxy/smoke_test.py example/http_proxy/build/http_proxy
cmake --build build --target brpc_http_proxy_unittest -j6
./build/test/brpc_http_proxy_unittest
```

集成测试使用临时本地 HTTP、HTTPS 和 echo 服务，无需外网；TLS 测试使用仓库测试
证书及 curl --insecure，仅用于自签名证书验证。测试会自动关闭启动的进程。

当前是 HTTP/1.1 代理底座示例：普通请求和响应整体缓冲；没有流式大正文、WebSocket
upgrade、HTTP/2 CONNECT、HTTP pipelining 顺序保证或完整 TCP 半关闭支持。GET 请求
带正文会返回 400，不属于此示例的支持范围。隧道待转发字节有上限，超限关闭连接；不是完整的
读侧反压机制。系统 DNS 查询暂不受 connect_timeout_ms 限制。

回归覆盖：严格协议白名单、普通 HTTP master 复用、CONNECT 钩子分流、独立
internal_port、握手粘包/分片、HTTPS、并发隧道、尾部数据加立即 EOF、失败单次回复、
服务器停止、SOCKS5 自定义同步/异步处理，以及原有 HTTP/InputMessenger/Server 流程。

本次本地验证：HTTP 代理单元测试 11/11、集成测试 21/21；SOCKS5 单元测试 20/20、
默认及自定义处理器集成测试 13/13；原有 HTTP 选定测试 9/9、Server 选定测试 6/6
及 InputMessenger 测试通过。

本轮调度简化对 **原始 brpc 源码** 的修改为
`src/brpc/policy/http_rpc_protocol.h/.cpp`：抽出显式接收 HttpContext、Server、Socket
的 VerifyHttpRequest 重载，直接调度的 CONNECT 握手复用原 HTTP 认证逻辑。
原 VerifyHttpRequest(InputMessageBase*) 委托该重载。其余本轮实现改动均在此前
新增的代理模块中；Server、Socket、InputMessenger 和 ExecutionQueue 无需修改。
