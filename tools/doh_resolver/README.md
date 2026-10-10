# DohResolver

独立的 DoH 工具类，不注册 brpc 协议，也不接入代理或 upstream。
HTTPS 使用 brpc `Channel`，DNS 响应使用系统 `libresolv` 解析。

## 使用

```cpp
#include "doh_resolver.h"

brpc_tools::DohOptions options;
options.endpoint = "https://resolver.example/dns-query";
options.bootstrap_ip = "192.0.2.53";  // 替换为真实服务地址；可留空。
// options.ca_file = "/path/to/trusted-ca.pem";

brpc_tools::DohResolver resolver;
auto status = resolver.Init(options);
if (!status.ok()) { /* 处理初始化错误 */ }

brpc_tools::ResolveResult result;
status = resolver.Resolve("example.com", 3000, &result);
if (status.ok()) {
    // result.addresses: 不带端口的 IPv4 / IPv6 字符串。
    // result.ttl_sec: 返回记录和 CNAME 的最小剩余 TTL。
}
```

只查询某一地址类型：

```cpp
resolver.Resolve("example.com", 3000, &result,
                 brpc_tools::AddressFamily::IPV4);
```

成功完成 `Init` 后可以并发调用 `Resolve`，包括在 bthread 中调用。
初始化和析构不能与查询并发；实例需保持到所有调用结束。

## 行为

- 使用 RFC 8484 的 HTTPS POST / `application/dns-message`，不使用厂商 JSON 接口。
- 严格启用 CA 和服务端名称校验。bootstrap IP 只改变连接地址，
  HTTP Host、TLS SNI 和证书名称仍使用 endpoint 的域名。
- bootstrap IP 留空时，DoH 服务地址由 brpc 初始化时通过系统 DNS 解析；
  设置 bootstrap IP 可避免此依赖。bootstrap 只配置一个地址。
- 目标 IP 字面量直接返回，不发送查询；TTL 为 0。域名支持 ASCII/punycode，
  统一小写并移除末尾的点，不执行 Unicode IDNA 转换。
- 默认顺序查询 A、AAAA，共用一个总超时预算；某个类型成功、另一个失败时，
  返回成功类型的地址。DNS 解析、缓存处理占用的少量 CPU 时间不保证可中断。
- 只采用与问题匹配的答案及同一响应中的 CNAME 链，拒绝压缩指针错误、
  CNAME 环、地址长度错误、问题不匹配和截断响应。
- TLS、HTTP、DNS 错误通过 `butil::Status` 返回；失败时不改变输出参数。
- 正结果按 DNS TTL 缓存，扣除 HTTP `Age` 和后续查询耗时。缓存命中时
  返回剩余 TTL，TTL 秒数向下取整。默认最多 256 项，容量满时淘汰一项。
  设置 `max_cache_entries=0` 关闭缓存。不做负缓存或并发重复请求合并。

## 编译

依赖已构建的 brpc、对应的 Protobuf/gflags/LevelDB/OpenSSL，以及
Linux/macOS 的系统 `libresolv`。从仓库根目录执行：

```sh
cmake -S tools/doh_resolver -B tools/doh_resolver/build \
  -DBRPC_INCLUDE_PATH="$PWD/build/output/include" \
  -DBRPC_LIB="$PWD/build/output/lib/libbrpc.a"
cmake --build tools/doh_resolver/build -j6
```

将两个 brpc 路径替换为实际构建输出；依赖搜索路径可通过
`CMAKE_PREFIX_PATH` / `OPENSSL_ROOT_DIR` 等参数设置。
产出静态库 `libdoh_resolver.a`。作为 CMake 子目录使用时，链接
`doh_resolver` target 即可获得传递依赖。

## 测试

```sh
ctest --test-dir tools/doh_resolver/build --output-on-failure
```

测试需要 Python 3 和 `openssl` 命令。测试自行生成临时证书，启动本地
HTTPS DoH 服务，验证解析、缓存、并发、超时和证书校验；不访问公网。

本次新增文件均在 `tools/doh_resolver`，没有修改其他模块。
