# 代理规则索引

应用侧的独立匹配模块，复用 `butil::FlatMap`、`StringPiece` 和 `Status`。
只判断 IP 或域名是否命中，不执行 DNS、连接或路由操作。

## 数据结构及接口

- `IpPrefixIndex`：IPv4 / IPv6 分开的 Patricia 压缩前缀树。
  `Insert(StringPiece)` 插入具体 IP、CIDR 或 IPv4 连续点分掩码；
  `AnyIp(IpAddress)` 返回是否命中。
- `HostnameTrie`：按域名 label 倒序插入，例如 `com → example → api`。
  `Insert(HostnameMatch, StringPiece)` 插入 exact / suffix 规则；
  `AnyHostname(StringPiece)` 返回是否命中。
  suffix 包含域名本身和子域名；exact 只匹配完整域名。

IP 节点仅保存一个匹配标记，域名节点保存 exact / suffix 两个标记。
相同规则或规范化后相同的前缀、域名会合并，不保存规则 ID 或规则列表。
节点存储在 vector 中，以整数 NodeId 连接。域名使用共享 label 字典和
`(ParentId, LabelId)` 边表，不为每个节点分配哈希表。不使用 Pimpl。

查询首次命中即返回，不分配内存。IP 查询成本为 `O(W)`，W 为 32 / 128；
域名查询预期为 `O(L)`，L 为输入长度。
IPv4 校验时直接生成字节；点分掩码用位运算检查连续性。
IP 公共前缀使用最多两个 64 位 XOR / 前导零计数，主机位按字节清零。

## 使用

```cpp
#include "proxy_rules/matcher.h"

proxy_rules::IpPrefixIndex ips;
for (const auto& network : {"10.0.0.0/8", "10.1.2.3", "2001:db8::/32"}) {
    const auto status = ips.Insert(network);
    if (!status.ok()) { /* handle error */ break; }
}

proxy_rules::IpAddress address;
auto status = proxy_rules::IpAddress::Parse("10.1.2.3", &address);
if (!status.ok()) { /* handle invalid IP */ }
bool matched = ips.AnyIp(address);  // true

proxy_rules::HostnameTrie domains;
status = domains.Insert(proxy_rules::HostnameMatch::SUFFIX, "example.com");
if (!status.ok()) { /* handle error */ }
status = domains.Insert(proxy_rules::HostnameMatch::EXACT, "api.example.net");
if (!status.ok()) { /* handle error */ }
matched = domains.AnyHostname("API.Example.NET.");  // true
matched = domains.AnyHostname("x.example.com");     // true
matched = domains.AnyHostname("badexample.com");    // false
matched = domains.AnyHostname("x.api.example.net"); // false
```

## 输入及并发约定

- 调用方逐条调用 `Insert`，每次成功插入立即生效；重复规则自动合并。
  语法错误在修改索引前拒绝。循环中某条规则失败，之前成功的插入仍保留。
  需要一份空索引时创建新实例；需要整批替换时由调用方管理新旧实例。
- IP 只接受数字地址，不接受端口、方括号、IPv6 scope 或主机名。
  IPv4 多位数字不允许前导零。`Parse` 失败时不修改输出地址。
- CIDR 自动清除主机位。IPv4-mapped IPv6 保留 IPv6 地址族，
  与 IPv4 分开匹配，不做隐式转换。
- hostname 转 ASCII 小写，允许末尾一个 `.`，校验 label 和整体长度。
  支持 LDH（字母、数字、连字符）及 ASCII IDNA 名称；
  Unicode、通配符、下划线、URL 和端口形式被拒绝。
  非法 hostname 查询返回 false。
- 完成构建后可以并发执行 const 查询。不允许同时执行 `Insert` 或析构；
  更新时构建新实例，再发布 `shared_ptr<const ...>` 快照。

`Insert` 允许逐条读取输入，无需在内存中保存整批规则。索引节点仍保存在
内存中，NodeId 为 32 位；上千亿条规则仍需另行设计分片。

## 编译和测试

从 brpc 仓库根目录执行，替换 brpc 构建输出路径：

```sh
cmake -S example/proxy_rules -B example/proxy_rules/build \
  -DBRPC_INCLUDE_PATH="$PWD/build/output/include" \
  -DBRPC_LIB="$PWD/build/output/lib/libbrpc.a" \
  -DBUILD_TESTING=OFF
cmake --build example/proxy_rules/build -j6
```

如依赖不在默认搜索路径，使用与 brpc 构建一致的 Protobuf / OpenSSL 路径。
产物为 `libproxy_rules.a`；通过 CMake 的 `proxy_rules` target 链接可继承
头文件路径和 brpc 依赖。其他 example 可用 `add_subdirectory` 引入本模块。

单元测试在仓库 `test/proxy_rules_unittest.cpp`，由本模块的 CMake 编译。
使用已安装的 GTest，或指定已有 googletest 源码目录，不自动联网下载：

```sh
cmake -S example/proxy_rules -B example/proxy_rules/build \
  -DBUILD_TESTING=ON \
  -DPROXY_RULES_GTEST_SOURCE_DIR=<googletest-source-directory>
cmake --build example/proxy_rules/build -j6
ctest --test-dir example/proxy_rules/build --output-on-failure
```

测试覆盖 IP 边界、非字节对齐 CIDR、重叠及重复规则、IPv6、地址族隔离、压缩边、
域名 exact/suffix、边界和规范化、增量插入及非法输入处理、并发查询，以及随机查询与
逐条扫描参考实现的对比。
