# SOCKS5 / HTTP CONNECT → VMess

同一端口接收 SOCKS5 和 HTTP CONNECT，通过 VMess AEAD（AES-128-GCM）
转发到原始目标地址。支持 VMess raw TCP 和普通 WebSocket。

## 编译

依赖 C++20 编译器、OpenSSL ≥ 3，以及构建 brpc 时使用的 Protobuf、
gflags、LevelDB。先完成 brpc 构建，例如从仓库根目录执行：

```sh
cmake -S . -B build
cmake --build build --target brpc-static -j6

cmake -S example/vmess_proxy -B example/vmess_proxy/build \
  -DBRPC_INCLUDE_PATH="$PWD/build/output/include" \
  -DBRPC_LIB="$PWD/build/output/lib/libbrpc.a"
cmake --build example/vmess_proxy/build -j6
```

如果已有 brpc 构建，只需替换后两个参数，直接构建 example。
Protobuf 必须与该 brpc 构建一致；依赖不在默认搜索路径时指定
`CMAKE_PREFIX_PATH` 或 `Protobuf_INCLUDE_DIR` / `Protobuf_LIBRARY`。

macOS/Homebrew 可在 example 的配置命令后增加：

```sh
-DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

程序为 `example/vmess_proxy/build/vmess_proxy`。不依赖原 `vmess_client`
仓库的目录，也不需要原 demo 的网络传输库。

## 启动

```sh
# VMess raw TCP
./example/vmess_proxy/build/vmess_proxy 127.0.0.1:1080 \
  --vmess_host=<gateway-host> --vmess_port=<gateway-port> \
  --vmess_uuid=<user-uuid> --admin_address=127.0.0.1:8080

# VMess WebSocket
./example/vmess_proxy/build/vmess_proxy 127.0.0.1:1080 \
  --vmess_host=<gateway-host> --vmess_port=<gateway-port> \
  --vmess_uuid=<user-uuid> \
  --vmess_ws_path=/images --vmess_ws_host=<websocket-host> \
  --admin_address=127.0.0.1:8080
```

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
curl --proxy http://127.0.0.1:1080 https://example.com
# 对 HTTP URL 也显式使用 CONNECT：
curl --proxy http://127.0.0.1:1080 --proxytunnel http://example.com
```

`http://127.0.0.1:8080` 提供 brpc 原有网页工具。

| 参数 | 默认值 / 用途 |
|---|---|
| `vmess_host`, `vmess_port`, `vmess_uuid` | 必填：网关及 AEAD 用户 UUID |
| `vmess_ws_path` | 空：raw TCP；非空：WebSocket 路径 |
| `vmess_ws_host` | 空：使用网关 host:port |
| `vmess_timestamp_offset_sec` | 0：认证时间戳偏移，单位秒 |
| `connect_timeout_ms` | 15000：连接/升级共享超时，单位毫秒 |
| `handshake_timeout_ms` | 30000：整个 SOCKS5 握手超时 |
| `idle_timeout_sec` | 60：客户端空闲超时；≤0 关闭此限制 |
| `admin_address` | `127.0.0.1:8080`：独立网页工具监听地址 |

WebSocket TCP 连接和等待升级响应共用一个 deadline；DNS 和 Socket 写入
沿用当前 `ConnectTcp` / `WriteUpstream` 的行为，不另行保证被该 deadline 中断。

## 接入方式

`MakeUpstreamFactory(options)` 返回普通 `brpc::ProxyUpstreamFactory`。
可以将同一个 factory 赋给任意 server 的：

```cpp
socks5_options.upstream_factory = factory;
http_options.upstream_factory = factory;
```

`VmessUpstream` 的职责：

- `Connect`：为原始 `request.target` 构造 VMess 头，通过 `ConnectTcp`
  连接配置的网关，完成可选 WS 升级并发送请求头。
- `OnClientData`：分块加密，经过可选 WS 掩码封装，交给基类
  `WriteUpstream`，复用 brpc Socket 写入和完成通知。
- `ParseUpstreamData`：仅处理 WS 升级控制信息；后续原始字节交给基类，
  复用串行队列、背压和 EOF 保护。升级字节也经队列保留 EOF 保护，
  处理时丢弃，保证失败回复先于关闭。
- `OnUpstreamData`：增量解 WS 帧、校验 VMess 响应头、解密 chunk，
  通过 `tunnel().WriteClient` 写回客户端；Ping 在同一队列中回复 Pong。
- `Close`：唤醒待完成的升级操作，然后关闭基类的 brpc Socket。

VMess 服务端可能等目标返回首批数据才发送认证响应，因此 `Connect`
不等待 VMess 响应头。否则客户端等待 CONNECT 成功、服务器等待客户端
payload，会互相等待。认证或解密错误在数据阶段关闭隧道。

## 范围

与原 demo 一样，HTTP 入口支持 CONNECT。普通绝对 URI HTTP 转发返回 405，
避免继承默认 HTTP forwarding 后绕过 VMess；HTTP URL 可用 `--proxytunnel`。

当前不支持 TLS/WSS、UDP、Mux 或其他 VMess security 类型。客户端 EOF
沿用当前代理底座的关闭行为，没有移植原 demo 的双向半关闭 relay，
也不在取消连接时发送 VMess termination chunk；接收服务端 termination
chunk / WS Close 时，先写完已经解密的数据再关闭。

## 验证

```sh
ctest --test-dir example/vmess_proxy/build --output-on-failure
# 单独运行端到端测试：
python3 example/vmess_proxy/smoke_test.py \
  example/vmess_proxy/build/vmess_proxy \
  example/vmess_proxy/build/vmess_fake_peer
```

复用 6 组协议测试，并用本地测试 peer 验证 SOCKS5/CONNECT、原始目标编码、
raw TCP/WS、分片响应、256 KiB 双向数据、Ping/Pong、尾部数据与 EOF、
认证回显/加密标签错误、升级失败/超时和服务退出。
测试 peer 只用于测试，不能作为 VMess 服务端部署。

## 修改范围

VMess 相关实现全部在本 example，编解码来源见 [codec/README.md](codec/README.md)。
已有 `example/socks5_proxy/mixed_server.cpp` 抽出 `RunProxyServer`，复用
监听端口、协议配置、独立网页工具 server 和退出流程；原 mixed demo 行为保持。
本次移植未修改 `src/brpc`、`src/bthread` 或其他 brpc-core 源码。
