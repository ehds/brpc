# VMess codec 来源

从用户提供的 `vmess_client` 仓库提交
`afb429cf138f85ca4a669f1a3fe795bf53b74492` 移植。

仅复用 `common`、`crypto`、`kdf`、`uuid`、`header`、`chunk`、`ws_frame`
及对应的 6 组协议测试；这些文件的协议逻辑保持原样。
其中 KDF 和请求头测试包含原 demo 对照 Xray-core 生成的黄金向量。

原 demo 的入站 SOCKS5/HTTP 解析、TCP transport、阻塞式 session、relay
和 brpc transport 均未移植。网络连接、收发、队列和连接生命周期由当前
brpc 的 `ProxyUpstream` 实现提供。

`../ws_codec.cpp` 从原 `src/websocket.cpp` 抽取掩码帧编码及
SHA1/Base64 握手计算，去掉 Socket I/O；升级响应复用 brpc 的 HTTP 解析器。

编译不依赖原仓库路径，也不读取原仓库中的配置或凭据。
