# TLS-Anvil 合规性分析报告（中文版）

> 本文件是 [`tls-anvil-analysis-report.md`](./tls-anvil-analysis-report.md) 的中文译本。
> **以英文版为准**；如英文版更新，请同步本译本。

**状态：收口汇总（2026-06-30 整理）。** 将原本散落在 `DEV_LOG.md` / `PROMPT_LOG.md`
的 I185–I196 各相、以及 `tls-anvil-run-native` 工作笔记中的多轮 TLS-Anvil 分析，
汇成一份可审计记录：跑了什么、失败面如何逐轮收敛、每一处修复、以及确认的非问题。

TLS-Anvil 与精选的 [tlsfuzzer](./tls-test-coverage-contract.md) 套件互补：
tlsfuzzer 针对性地探测协议变异，TLS-Anvil 则是一个广覆盖的 RFC 合规性测试框架
（基于 TLS-Attacker，约 437 个 TLS 1.2/1.3 测试），对每个类目按规范计分。

---

## 1. 如何运行（以及为何用原生方式）

| 项 | 取值 |
|---|---|
| 测试框架 | TLS-Anvil（TLS-Attacker），约 437 个 TLS 1.2/1.3 合规性测试 |
| 执行方式 | **原生** —— 提取出的 JAR + arm64 Temurin 21 JDK（**不**用 emulated-amd64 的 Docker 镜像） |
| 被测服务端 | `hitls s-server --tls auto -p 4470`，**RSA-2048** 证书 |
| 运行命令 | `java -jar TLS-Anvil.jar -outputFolder <dir> -parallelTests 2 -parallelHandshakes 1 -strength 1 -connectionTimeout 4000 -disableTcpDump -identifier 127.0.0.1:4470 server -connect 127.0.0.1:4470` |
| 墙钟耗时 | 约 3.3 小时 / 437 测试（strength-1）；约 11 小时 / 18,897 个两两组合用例（strength-2） |
| 输出 | `<dir>/report.json`（各类目得分）+ `<dir>/results/<id>/_testRun.json`（逐测试；`FailureInducingCombinations` 指出致因参数） |

**为何用原生而非 Docker。** 最初一次尝试用了 TLS-Anvil 的 emulated-amd64 Docker
镜像。在 arm64 Mac 上它跑在 qemu 之下，产生了 **约 66% 的假失败** —— 大量
`TransportHandler` 连接噪声（来自模拟 + 跨虚拟机网络），与干净的原生 tlsfuzzer
（6213/0）、testssl.sh、sslyze 结果直接矛盾。JAR 是平台无关字节码（只有*镜像*是
amd64），因此把它提取出来在原生 arm64 JDK 下运行以获得真实信号。注意事项：传入
`-disableTcpDump`（pcap 的 ioctl 在容器附近失败）；必须用 RSA 证书（Anvil 的
sigalg 测试假设 RSA 签名，纯 EC 证书会扭曲结果）；macOS 没有 `timeout` —— 端口
检查用 `nc -z`。

计分口径（每类目）：**STRICTLY_SUCCEEDED**（严格符合）、**PARTIALLY**（符合但有
可容忍的偏差）、**FULLY_FAILED**（完全失败）。

---

## 2. 服务端模式：失败面逐轮收敛

共 6 轮。每个修复都会为下一轮去噪，暴露出噪声之下真正的残留。

| # | 运行 | 结果 | 产出的相 |
|---|------|------|----------|
| 0 | Docker（emulated amd64） | **弃用** —— 约 66% 的 qemu/网络假噪声，被原生 tlsfuzzer/testssl/sslyze 反驳 | —（改用原生） |
| 1 | 原生基线 | 在噪声之下暴露两个真 bug | **I185**、**I186** |
| 2 | 原生，修完 I185/I186 后 | STRICTLY 113→154，PARTIALLY 81→45；RecordLayer 64→80，Interop 59→77，Handshake 64→79，DeprecatedFeature→100。**754 个残留失败用例中 100% 都带一个小 `RECORD_LENGTH`（1/50/111）；0 个是纯逻辑问题** → 锁定了最大的那个发现 | **I187**（约 734 个用例） |
| 3 | 原生，修完 I187 后 | STRICTLY 154→**202**，PARTIALLY 45→**5**；RecordLayer→97，Interop→95，Handshake→94。残留去噪为 4 个清晰的严格性分组 | **I188**（A）、**I189**（B）、**I190**（C）、**I191**（D） |
| 4 | 原生确认运行，修完 I188–I191 后 | STRICTLY 113→**213**，PARTIALLY 81→**0**，FULLY 5→**3**；4 个类目满 100，其余 98–99.7。3 个 FULLY 中：1 个真 bug，2 个非问题 | **I192**（那 1 个真 bug） |
| 5 | 深度运行，strength-2 `-ignoreCache` | 18,897 个两两组合用例，约 11 小时 → **PARTIALLY 0，FULLY 2**（即同样那两个非问题）；`invalidEllipticCurve` 确认为 STRICTLY。**零新问题** —— 修复在组合覆盖下稳健，并非对 strength-1 过拟合 | —（仅验证） |

**结论：** strength-1（约 3 小时）足以用于例行回归复查；strength-2 留给深度审计。

---

## 3. 服务端修复（I185–I192）

三个**主要发现**（I185–I187）是高波及面的 bug；四个**严格性分组**（I188–I191）
是去噪后的残留；**I192** 是最终 3 个 FULLY 中唯一的真 bug。

| 相 | 发现 | RFC | 修复 |
|---|---|---|---|
| **I185** | `ServerHello.random` 缺少 TLS 1.2 降级保护哨兵 | RFC 8446 §4.1.3 | 协商到低于最高支持版本时，在 `ServerHello.random` 末 8 字节写入 `DOWNGRD\x01` / `\x00` 哨兵 |
| **I186** | 当对端协商了更小分片时，`seal_record` *拒绝*（而非拆分）超过该分片的明文 | RFC 6066 `max_fragment_length` / RFC 8449 `record_size_limit` | 按协商的 `max_fragment_size` 把出站明文拆分到多条记录，而非报错 |
| **I187** | `--tls auto` 把**记录层分片的** ClientHello 误路由到 TLS 1.2 处理器 → `handshake_failure`（**最大的单一发现，约 734 个用例**） | RFC 8446 §5.1 | 基于*重组后*的 CH 做版本路由，而非第一个分片 |
| **I188** | TLS 1.3 服务端对畸形/欠规范的 ClientHello 完成握手而非中止（A 组）：`legacy_version` ≤ 0x0300；`legacy_compression_methods` ≠ `[0x00]`；带 `key_share` 却省略 `supported_groups` | §4.1.2、§9.2 | 分别 → `protocol_version` / `illegal_parameter` / `missing_extension` |
| **I189** | 缺入站记录分片长度强制（B 组） | RFC 6066 §4 / RFC 8449 / §5.2 | *解密后*明文超过协商 MFL 时拒绝并 `record_overflow`（已证明是明文长度路径，而非 `bad_record_mac`） |
| **I190** | 扩展解析器静默丢弃 off-by-one 尾字节（C 组；波及面最大 —— 1.2/1.3/TLCP/DTLS 共用解析器） | §6.2 | `parse_extensions_from` / `parse_extensions_list` 严格精确消费 → `decode_error` |
| **I191** | 零长 Handshake/Alert 分片未被拒绝 → 重组循环阻塞而非中止（D 组） | §5.1 | `pt.is_empty() && ct ∈ {Handshake, Alert}` → `unexpected_message`；零长 ApplicationData 仍放行 |
| **I192** | 非 ECC 套件（`DHE_RSA`）+ 仅含不可用曲线的 `supported_groups` → `handshake_failure` 而非回退到 DHE（最终 3 个 FULLY 中唯一真 bug） | RFC 8422 §4 / RFC 7919 §4 | I105 的 `kx_group_satisfiable` DHE 门控与 `negotiate_ffdhe_group` 的 FFDHE2048 回退矛盾；改用 RFC 7919 §4 码点**范围**（`0x0100..=0x01ff`）修复 |

### 确认的非问题（勿再调查）

最终 3 个 FULLY 中有两个**不是 bug**：

- **`tls12 closeNotify`** —— 我方 TLS 1.2 服务端发送的是正确的 **warning 级（1）**
  `close_notify`，已通过 `openssl s_client -trace` 在所有 cipher 上验证。框架判定
  的 "level 2" 对真实客户端不可复现 —— 属框架自身的假象。
- **`ecdsaNoSignatureAlgorithmsExtension`** —— 在 RSA 服务端证书下 N/A；需要 ECDSA
  证书才有意义（而纯 EC 证书会扭曲 Anvil 其余的 RSA-签名 sigalg 测试，故默认用
  RSA-2048）。

---

## 4. 邻接发现（专项测试，非 Anvil）—— I193

在审计"还有哪些专项测试"时，一次 **ECDSA 证书**运行立即暴露了一个真 bug，因属于
同一轮合规性加固而记录于此：

| 相 | 发现 | RFC | 修复 |
|---|---|---|---|
| **I193** | TLS 1.2 套件选择只按版本 + 密钥交换组可满足性过滤候选，**从不**检查套件的**认证**算法是否匹配服务端密钥 —— 仅持 EC 证书的服务端会（按服务端优先）选中 RSA-认证套件（`ECDHE_RSA` / `DHE_RSA`）、发出 EC 证书，客户端因类型不符拒绝（`wrong certificate type`）。这也是 Anvil 始终用 RSA 证书的原因。 | RFC 5246 §7.4.2 | 在套件选择中加入 `auth_satisfiable(auth, key)` 门控 |

---

## 5. 客户端模式（约 223 个测试）—— I194–I196

TLS-Anvil 也能驱动**客户端**合规性：`client -port <p> -triggerScript <cmd>`，
其中触发脚本在后台启动 `hitls s-client 127.0.0.1:<p> --insecure --quiet`。这是
**此前最大的未测面**（服务端模式运行从不触及客户端消息处理），并发现了三个真实
客户端 bug：

| 相 | 发现 | RFC | 修复 |
|---|---|---|---|
| **I194** | HRR 之后的 ClientHello 重新随机化了 `client_random` 并发出空的 `legacy_session_id` —— 二者都 MUST 与原始 CH 一致 | RFC 8446 §4.1.2 | 存下初始 `client_random` + `legacy_session_id`，在重试 CH 中原样复用 |
| **I195** | 客户端对若干畸形服务端消息未中止：`legacy_session_id_echo` 不符 / 非零 `legacy_compression_method` / ServerHello 含不允许的扩展 / EncryptedExtensions 含仅属 CH/SH 的扩展 | §4.1.3、§4.2 | `illegal_parameter`（SH session_id/压缩 + 扩展白名单）、`unsupported_extension`；EE 黑名单 |
| **I196** | 客户端未校验 HRR 之后的 ServerHello `cipher_suite` 与 HRR 一致 —— 服务端/MITM 可在 HRR 后悄悄换套件而不被发现 | §4.1.4 | 一次性检查：`hrr_done` 时 SH 套件 ≠ 存下的 HRR 套件 → `illegal_parameter` |

**注意 —— CertificateVerify 类测试受到混淆。** 用 `--insecure` 运行触发用的
s-client 会让客户端因被告知而跳过验证；由此产生的 CertificateVerify "失败"是
**测试假象，而非 bug**（当 `verify_peer=true` 时验证是正确的）。请勿重新定性这些。

---

## 6. DTLS 模式不可用（TLS-Attacker 限制，非我方 bug）

`java -jar JAR -dtls ... server -connect <host:port>` 对 `hitls s-server --dtls`
在特征提取阶段失败：
`FeatureExtractionFailedException: unable to determine SUPPORTED_CIPHERSUITES`。

这是 **TLS-Attacker DTLS 扫描器成熟度的限制，而非我方服务端缺陷**：我方 DTLS
服务端能完成 5/5 次顺序 `openssl s_client -dtls1_2` 握手（ECDHE-RSA-AES128-GCM），
并在扫描器的畸形探测下保持稳健（记录 "too short" / "cookie mismatch" 后继续）。
**勿再尝试通过 TLS-Anvil 跑 DTLS** —— DTLS 改用 openssl / dtlsfuzzer。

---

## 7. 最终状态

- **服务端模式线：已完全收口（2026-06-26）。** 8 个修复（I185–I192）。最终
  strength-1：STRICTLY 213，PARTIALLY 0，FULLY 3（1 个已修 → 2 个确认非问题）。
  strength-2 深度运行：零新问题。
- **客户端模式线：修复 3 个真实 bug（I194–I196）。** CertVerify 假象已厘清。
- **DTLS 模式：无法通过 Anvil 运行**（TLS-Attacker 限制）；改由 openssl +
  dtlsfuzzer 覆盖。
- **邻接：I193**（套件认证类型门控），来自专项 ECDSA 证书测试。

例行回归用 strength-1 原生运行（约 3 小时）即可；strength-2（约 11 小时）留给深度
审计。逐相实现细节见 `../DEV_LOG.md`（I185–I196）；运行操作指南见 `tls-anvil-run-native`
记忆笔记。
