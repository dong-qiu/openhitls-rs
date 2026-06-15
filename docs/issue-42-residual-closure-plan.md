# C→Rust 测试迁移 — 残余收口计划（v1.0）

**状态**：规划阶段（2026-06-16）
**主跟踪 issue**：[#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**前序**：`docs/issue-42-phase-{a..i}-*.md` + `docs/issue-42-phase-jklm-plan.md`（Phase A–J 完成；K/L 经 ground-truth 评估为已由 Phase C/I 达成；M-1 完成）
**DEV_LOG 命名**：接续 T277 → **T278+**，Implementation 接续 I160 → **I161+**

---

## 0. 为什么有这份计划

2026-06-16 的全量 ground-truth 分析（C 8 类 ~24,567 数据行 vs Rust ~4,674 迁移测试 / 9,245 总测试）得出一个明确结论：

> **迁移已结构性完成。** 24,567 C 行里"未字节级迁移"的 96%+ 是**架构上 N/A**（EAL ctx CRUD、provider 框架、SAL/内存模型层、C-app helper、随机化 sign 无 hook、上游数据缺陷），**没有忠实的 Rust 1:1**。

把 N/A-by-design 与冗余剔除后，**真正还能产出"新覆盖"而非冗余的只剩 4 项**。本计划只覆盖这 4 项，并在 §5 显式列出所有 out-of-scope 的 N/A 类别，把范围钉死，避免未来再次对已闭环的类别返工。

### 0.1 四项残余（按 ROI 排序）

| WP | 项 | 类型 | 解锁 | 工作量 | 风险 |
|---|---|---|---|---|---|
| **C** | TLS Phase M-2…M-5（承接 M-1 wire-alert 基建） | 🧪 测试脚手架（零产品代码） | MODIFIED_* 真 wire-`Alert::*` + DTLS UDP + 0-RTT/PSK | 大 | 低 |
| **A** | SPAKE2+ RFC 9383 byte-exact 解锁 | 🔧 产品代码 + 测试 | 最多 14 个 RFC 9383 向量字节级 | 中-大 | **中-高**（多 suite + KDF 一致性待验证） |
| **B** | Privacy Pass RFC 9474 byte-exact 解锁 | 🔧 产品代码 + 测试 | 1 个 VECTOR 的 request/response/token 字节级 | 中 | 中 |
| **D** | PKI x509 emitter 恢复（56 unknown + 69 unsupported） | 🧪 emitter 工作 | ~modest Hex-ambiguous DN / dotted-OID 属性 | 小-中 | 低，**收益边际** |

**推荐执行序**：**C → A → B → D**（C 零风险、零产品代码、承接已落地基建；A 字节级产出最高但需先做一致性 probe 去风险；B 中等；D 收益边际，可选/最后）。

---

## 1. WP-C — TLS Phase M-2…M-5（测试脚手架，承接 M-1）

**核心判断**：M-1（T276）已落地 client wire-level Alert 捕获基建（`derive_client_handshake_keys` + `capture_client_alert` + `drive_client_capture_wire_alert`，在 `tests/interop/tests/transcript_mutation_encrypted_e2e.rs`）。M-2…M-5 在此之上把 Phase H §8 剩余 4 项关闭。**零产品代码**（复用 public `KeySchedule`/`TrafficKeys`/`AesGcmAead`/签名 API，T186/T219 方法学）。

### 1.1 子 PR 拆分

| # | T | 来源（H §8） | 估计 | 做法 |
|---|---|---|---:|---|
| M-2 | T278 | rogue-server cert+私钥 loader → `MODIFIED_CERT_VERIFY_*` 真 wire Alert | ~10 | PEM→DER→PKCS#8 加载 server cert+key；rogue server 发**有效签名的** Certificate + CertVerify（RFC 8446 §4.4.3 signing buffer）+ Finished（让 client 过 cert 校验，client 配 `verify_peer` 信任该 cert）；篡改 CV 签名 → 捕获 client 的 `decrypt_error`(51) |
| M-3 | T279 | `MODIFIED_FINISHED_*` 真 wire Alert | ~10 | 在 M-2 valid-handshake 基础上篡改 Finished `verify_data` → 捕获 `decrypt_error`/`bad_record_mac`；乱序 Finished → `unexpected_message`(10) |
| M-4 | T280 | DTLS 1.3 UDP rogue server（RFC 9147 §4） | ~10 | UDP socket + RFC 9147 统一头（epoch + 截断 seq 加密）；先 wire-format pin（参照 T227 scope-cut），有余力再 E2E |
| M-5 | T281 | 0-RTT 接受 E2E + PSK 预热（T119 deferred PSK_ONLY） | ~10 | early-data 路径：PSK warm-up → 0-RTT data → 捕获 client 行为 |
| closeout | T282 | custom-alert variant 收紧 + 系列 rollup | ~6 | 把现存 E2E 断言全部从"client errored"收紧到具体 `Alert::*`；H §8 4 项标 RESOLVED |

### 1.2 关键前置（M-2 的难点）
- **server cert + 私钥 fixture**：需要 CA 证书 + CA 签的 server 证书 + server 私钥；client 配 `verify_peer(true)` + 信任该 CA（或 self-signed + 信任）。可从 `tests/vectors/c-asn1-fixtures/` 或 integration-test 现有 cert 复用，或离线生成后内联。
- **CertVerify 签名**：rogue server 用 server 私钥对 RFC 8446 §4.4.3 的 signing buffer（`0x20*64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ transcript_hash`）签名。复用 hitls-crypto 的 RSA/ECDSA sign API。
- **Finished MAC**：复用 `KeySchedule::compute_finished_verify_data`（Phase G 已用）。
- **+~200 LoC**（H §8 估计）的测试 harness，零产品代码。

### 1.3 验收
- [ ] `transcript_mutation_encrypted_e2e.rs` 所有断言收紧到具体 `Alert::*`
- [ ] H §8 的 4 项 still-pending 全部 RESOLVED
- [ ] DEV_LOG **T278–T282**

---

## 2. WP-A — SPAKE2+ RFC 9383 byte-exact 解锁（产品代码 + 测试）

**核心判断**：J-3（T257）已用 P-256 向量的 `(w0,w1,L)` 做 round-trip pin，并把 byte-exact 记为 na-list Structural Gap。本 WP 关闭该 gap。**最高字节级产出（最多 14 向量）但风险最高**，故先做一致性 probe 去风险。

### 2.1 子 PR 拆分

| # | I/T | 内容 | 估计 | 做法 |
|---|---|---|---:|---|
| **A-0 probe** | （并入 A-1） | RFC 9383 KDF/confirm 一致性验证 | — | **先验**：给 Rust `Spake2Plus` 注入向量的 `x`，看 `shareP`/`kShared`/`confirmP` 是否字节级命中 RFC 9383 P-256 向量。Rust 现用自有 `ke/kc_a/kc_b` 推导，**可能不匹配 RFC 9383 transcript-based confirm** —— 若不匹配，A-1 升级为 conformance-fix（flywheel，参照 Phase A 的 I137 ML-DSA） |
| A-1 | I161 + T278★ | 标量注入 hook + P-256-SHA256-HMAC 向量字节级 | ~6 | 新 `kat-nonce`-gated `generate_share_with_scalar(x)`（参照 ECDSA `sign_with_nonce` I134 模式）；emit `shareP`/`kShared`/`confirmP`/`confirmV` 字节级（1 个 suite，1 向量）|
| A-2 | I162 + T279★ | 多 suite：P-384/P-521 + SHA-512 + CMAC-AES | ~13 | 泛化 `Spake2Plus` 的 group/hash/MAC（去掉硬编码 P-256+SHA256+HMAC）；迁移剩余 13 向量。**LARGE** —— 多曲线 SPAKE2+ M/N 点 + decompress + KDF；可按曲线再拆 |

★ T 编号与 WP-C 的 T278/T279 冲突 —— 实际落地时按合并顺序重新分配连续 T 号；此处仅示意 I+T 配对。

### 2.2 风险与去风险
- **A-0 probe 是 go/no-go 闸**：若 Rust SPAKE2+ confirm 构造 ≠ RFC 9383，则 A-1 先要把 Rust 实现对齐 RFC 9383 §3.3（transcript `TT` → `K_main` → `K_confirmP/V`），这是真 conformance 修复（有价值但工作量上升）。
- **A-2 多 suite 是大头**：Rust 现仅 P-256 decompress 硬编码（`decompress_point` 写死 P-256 `p ≡ 3 mod 4`）。P-384 同理可做，P-521 需 `p ≡ 3 mod 4` 验证；SHA-512 + CMAC-AES MAC 需接入。可只做 P-384（再 +若干向量）止步，P-521/CMAC 作 follow-up。

### 2.3 验收
- [ ] A-0 probe 结论记录在 DEV_LOG（命中 / 需 conformance-fix）
- [ ] `generate_share_with_scalar` `kat-nonce`-gated + `#[deprecated]`（test-only）
- [ ] 至少 P-256 suite 的 1 向量字节级；多 suite 按实际落地数记
- [ ] na-list SPAKE2+ Structural Gap 行更新（resolved / 部分 resolved）

---

## 3. WP-B — Privacy Pass RFC 9474 byte-exact 解锁（产品代码 + 测试）

**核心判断**：J-2（T256）已用 C 向量 RSA-2048 密钥做 round-trip pin，byte-exact 记为 na-list Structural Gap（Rust `privpass` 是简化版 blind-RSA：直接盲化 `SHA-256(token_input)`，无 EMSA-PSS）。本 WP 关闭该 gap。

### 3.1 子 PR 拆分

| # | I/T | 内容 | 估计 | 做法 |
|---|---|---|---:|---|
| B-1 | I163 | RFC 9474 EMSA-PSS RSABSSA + 确定性 hooks + TokenChallenge codec | ~产品 | `hitls_auth::privpass`:盲化 **EMSA-PSS-encode(msg, salt)** 而非 raw hash（RFC 9474 §5）；`kat-nonce`-gated 确定性 `nonce`/`salt`/`blind` 注入；RFC 9577 TokenChallenge `serialize`/`deserialize` |
| B-2 | T280★ | 迁移 VECTOR request/response/token 字节级 | ~8 | `VECTOR_TEST_TC001` 的 `request`/`response`/`token` 字节级；challenge round-trip |

### 3.2 验收
- [ ] EMSA-PSS RSABSSA 实现命中 RFC 9474 Appendix（独立第三方向量）
- [ ] C `VECTOR_TEST_TC001` 的 request/response/token 字节级
- [ ] na-list Privacy Pass Structural Gap 行 resolved

---

## 4. WP-D — PKI x509 emitter 恢复（测试，可选 / 最后）

**核心判断**：`migrated_x509_parse.rs` 1073/1588，剩 56 unknown（Hex-ambiguous DN 值 + header 行）+ 69 unsupported（dotted-OID DN 属性 + 严格性 gap）。**收益边际**（本会话实测扩 sig-alg map recover 0 行），列为可选。

### 4.1 子 PR（单个）
| # | T | 内容 | 估计 | 做法 |
|---|---|---|---:|---|
| D-1 | T281★ | 恢复 Hex-ambiguous DN + dotted-OID DN 属性 | ~小 | xtask `x509.rs`:对偶长十进制 DN 值用位置信息消歧；对未知 DN 属性类型按 dotted-OID 比较（Rust parser 存 dotted OID）|

### 4.2 验收
- [ ] `migrated_x509_parse.rs` emitted 计数提升；`--check` drift 门通过
- [ ] **若实测仍 recover < ~10 行，则放弃并文档化为永久 N/A**（不值得 fiddly 投入）

---

## 5. Out-of-scope（显式 N/A-by-design，钉死范围）

以下类别**不在任何收口 WP 内**，是架构性 N/A 或上游问题或冗余，未来不应再返工：

| 类别 | 行数级 | 为什么 N/A |
|---|---|---|
| crypto EAL ctx CRUD / provider 重复行 | ~3,800 | Rust 无状态一次性 API + 无 provider 概念 |
| crypto 随机化 sign（无 nonce hook 的算法） | — | 不可复现（除非加 kat-nonce hook，按需单独评估）|
| crypto unknown 边界行 | 240 | 解析失败 / repeat-count 工作流 / header 行 |
| SM4-HCTR / SM4-GCM-decrypt | 7 | **上游 C SDV 数据缺陷**（`memcmp(len=0)` / 缺 auth tag）|
| pki x509 API-surface（负面 / 无 Rust 对应） | 390 | 刻意（已计数）|
| pki CMS/PKCS#12 深度负面变体 | — | Phase C 已迁代表性族，1:1 = 冗余 |
| tls 一致性/状态机 1:1 | ~3,000 | 已由 audit-pin + tlsfuzzer(46 脚本) + transcript-mutation E2E 覆盖（抽样口径，刻意）|
| apps C-app-helper API 单测 | ~1,000 | Rust 用 clap + std，无 1:1（conf SplitString 已迁）|
| bsl SAL/uio/list/hash/err/log | ~600 | C 系统/内存模型层，std 替代 |
| cmvp 逐算法 Selftest 粒度 | — | Rust 聚合 `run_self_tests`，无 public 逐算法入口（已集成 pin）|
| codecs provider 框架 | — | Rust 无 provider 概念（base64/PEM 已 byte-exact 迁）|
| keymgmt / sm CLI | — | 刻意 deferral（GM operator mode，README 文档化）|

---

## 6. 总验收 & 度量

| 指标 | 当前 | 收口后（全 WP 完成，预期）|
|---|---:|---:|
| workspace 总测试 | 9,245 | ~9,290+ |
| SPAKE2+ 字节级向量 | 0（仅 round-trip） | 1–14（按 A-2 落地数）|
| Privacy Pass 字节级 | 0（仅 round-trip） | 1 VECTOR |
| na-list Structural Gap（未 resolved） | 2（SPAKE2+ / Privacy Pass） | 0–1 |
| TLS H §8 still-pending | 3（M-2/3/4/5）| 0 |

- [ ] 完成的 WP 对应 na-list Structural Gap 行翻 resolved
- [ ] DEV_LOG / PROMPT_LOG 同步
- [ ] 每个子 PR：独立 review → pre-push AI review → CI Gate → squash-merge（[[merge-before-next-task]]）

---

## 7. 一句话

**做完这 4 个 WP，C→Rust 测试迁移就真正 100% 收口**——剩下的全是 §5 列的 N/A-by-design。若只挑一个，**WP-C / M-2**（零产品代码、零风险、承接已落地基建）是最稳的起点；**WP-A / SPAKE2+ 标量 hook** 是字节级产出最高的起点（但先跑 A-0 probe 去风险）。
