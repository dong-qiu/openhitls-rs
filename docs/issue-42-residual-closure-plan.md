# C→Rust 测试迁移 — 残余收口计划（v1.0）

**状态**：✅ **完成**（2026-06-16）—— C/A/B 实质交付（含 2 个生产互通 bug 修复），D 文档化 N/A。见 §6。
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
| ✅ M-2 | ✅ T278 | `MODIFIED_CERT_VERIFY_*` 真 wire Alert | **3** | rogue server 用 `make_ecdsa_server_identity` 自签 cert + `sign_certificate_verify` 发有效 Certificate+CertVerify；client `verify_peer(true)`+accept-all callback；翻转/清零 CV 签名 → `decrypt_error(51)`。零产品代码 |
| ✅ M-3 | ✅ T279 | `MODIFIED_FINISHED_*` 真 wire Alert | **3** | 承接 M-2：发有效 CV，再篡改 server Finished `verify_data`（stateless `derive_finished_key`+`compute_finished_verify_data`）→ `decrypt_error(51)`。零产品代码 |
| ✅ M-4 | ✅ T280 | DTLS 1.3 record 线格 pin（scope-cut） | **8** | **全 UDP rogue server deferred**：C SDV 无 DTLS 1.3 数据（只有 dtls12/dtlcp）+ 记录层已 13 单测覆盖。改为 integration 级 RFC 9147 §4 record-codec pin（`serialize`↔`parse` round-trip + AAD==header + 截断/未知-type 拒绝 + epoch seq reset）+ 给 integration harness 加 `dtls13` feature。`tests/interop/tests/dtls13_record_wire.rs` |
| ⏸️ M-5 | — | 0-RTT 接受 + PSK | — | **disposition（非 C 迁移项）**：0-RTT 接受已由 T109 集成测试验证；external PSK 已由 T119 落地。0-RTT/PSK 的 mutation-E2E 是可选新基建（无 C `MODIFIED_*` 源），deferred |
| ✅ closeout | （并入 M-4） | custom-alert 收紧 + WP-C rollup | — | M-1/M-2/M-3 已把 cert-verify/finished E2E 断言收紧到具体 `Alert::*`（Phase H §8 cert+key-loader item RESOLVED）；DTLS UDP + 0-RTT/PSK E2E 显式 deferred（无 C 源）|

**WP-C 结论**：Phase H §8 的实质缺口（MODIFIED_CERT_VERIFY/FINISHED 的真 wire-`Alert::*` 观测）由 M-1/M-2/M-3 关闭；M-4 记录层 pin + DTLS UDP / 0-RTT-PSK E2E 因**无 C 迁移源**显式 deferred。WP-C 收口，下一步 **WP-A（SPAKE2+）**。

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
| ✅ **A-0 probe** | （并入 A-1） | RFC 9383 KDF/confirm 一致性验证 | done | **结论：no-go（发现 2 个真 conformance bug）**。share 计算 `x·G+w0·M`（RFC M/N 点）conformant；但 (1) key schedule 用非标 `Hash(TT)[..16]`+`HMAC(·,"ConfirmProver")` 而非 RFC 9383 §3.4 HKDF；(2) TT 硬编码空 Context/idProver/idVerifier。二者使 Rust SPAKE2+ **不与标准互通**。A-1 升级为 conformance-fix |
| ✅ A-1 | ✅ I161 + T281 | conformance fix + P-256 向量字节级 | **1 byte-exact + 2 prod fix** | (I161) 重写 §3.4 HKDF key schedule（`HKDF(nil,K_main,"ConfirmationKeys")`/`"SharedKey"`）+ 加 `set_identities`；(T281) `kat-nonce`-gated `generate_share_with_scalar(x)` + `tc_spake2plus_rfc9383_p256_vector_byte_exact` 断言 `shareP`/`K_shared`/`confirmP` 字节级 + `confirmV` 验证，**全部对独立 C 向量 ground-truth 通过**。117/117 hitls-auth 无回归 |
| A-2 | future I-phase | 多 suite：P-384/P-521 + SHA-512 + CMAC-AES | ~13 | 泛化 `Spake2Plus` 的 group/hash/MAC（去掉硬编码 P-256+SHA256+HMAC）；剩 13 向量经同一 hook 字节级。**LARGE** —— 多曲线 M/N + decompress；可按曲线再拆 |

> **A-0 的价值**：probe 不只是测试决策，它**抓到了一个生产互通 bug**（Rust SPAKE2+ 的 key schedule 不符合 RFC 9383 §3.4，无法与标准实现互通）。I161 修复后 Rust SPAKE2+ 才真正 RFC 9383-conformant。这是 Phase A 飞轮（迁移驱动发现实现 bug）的又一例。

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
| ✅ B-1+B-2 | ✅ I162 + T282 | RFC 9474 RSABSSA-SHA384-PSS conformance fix + 字节级迁移 | **1 byte-exact + prod fix** | (I162) `hitls_auth::privpass` 盲化改为 **EMSA-PSS-ENCODE(SHA384(token_input), modBits-1, salt48)**（sLen=48，非原 raw SHA-256）；`verify_token` 改 RSASSA-PSS-VERIFY；暴露 `hitls_crypto::rsa::emsa_pss_encode`；加 `Client::with_token_key_id` + `verify_token_with_key_id`。(T282) `kat-nonce` `create_token_request_with_randomness(challenge,nonce,salt,blind)` + `tc_privpass_rfc9474_vector_byte_exact` 断言 `blinded_msg`/`blind_sig`/`authenticator` 字节级 + token 验证，全对独立 C 向量 ground-truth 通过。118/118 hitls-auth 无回归 |

> **B-0 探查的价值**：与 WP-A 同样，迁移驱动**抓到生产互通 bug**（Rust privpass 是非标简化 blind-RSA，不与 RFC 9474 互通）。变体（PSS sLen=48 + emBits=modBits-1，非起初推测的 PSSZERO）是从 RNG-stub 消费顺序（nonce→salt→blind）+ 独立 Python 参考逆向确定的。

### 3.2 验收 ✅
- [x] EMSA-PSS RSABSSA 实现对独立 C 向量字节级命中
- [x] C `VECTOR_TEST_TC001` 的 request/response/token 字节级
- [x] na-list Privacy Pass Structural Gap 行 resolved（P-256 RSA-2048 向量）
- 剩余：RFC 9577 TokenChallenge codec + 生产 `token_key_id = SHA256(SPKI)`（需在 hitls-auth 构建 id-RSASSA-PSS SPKI DER，follow-up）

---

## 4. WP-D — PKI x509 emitter 恢复（⏸️ 评估为 N/A，2026-06-16）

**核心判断（最终）**：`migrated_x509_parse.rs` 1073/1588，剩 56 unknown + 69 unsupported。经 ground-truth
评估，**按 §4.2 准则文档化为 N/A**（不值得 fiddly 投入），理由：

1. **明显的 flywheel 收益 = 0**：本会话实测扩 sig-alg OID map（SHA384/512/SHA1/MD5-RSA + ML-DSA）recover **0 行**
   —— 那些 SigAlg 行已全部 map，跳过项在别处。
2. **剩余跳过项是刻意/难恢复**：56 unknown = header 行 + **Hex-ambiguous DN 值**（偶长十进制 DN 被 parser 当
   hex，是 parser-convention 而非可迁数据）；69 unsupported = **dotted-OID DN 属性** + verifier 严格性 gap。
3. **dotted-OID DN 属性恢复虽可行但 fiddly**：Rust parser 对未知 DN 属性 OID 存 `oid.to_dot_string()`
   （`certificate.rs:218`），所以理论上可迁。但 emitter 要**精确复刻**三处 parser 行为才能字节级命中：
   (a) parser 的 `known::oid_to_dn_short_name` 完整 short-name 集（定义埋在 hitls-pki，非平凡定位）；
   (b) `Oid::to_dot_string`（OID arc 解码 + join "."）；(c) `read_string` 的 value-tag 处理。三处任一不匹配即断言
   失败。为不确定的 modest 收益（~tens 行）做三重精确复刻，属 §4.2 明确允许放弃的 fiddly 工作。
4. **价值对比**：本残余计划的实质价值是 WP-A/B 的**两个生产互通 bug 修复** + WP-C 的 wire-Alert；WP-D 的
   dotted-OID 恢复是边际测试覆盖，不改变任何正确性结论。

**结论**：WP-D 归入 §5 永久 N/A（fiddly emitter 复刻，边际收益）。残余收口计划至此**完成**（C/A/B 实质交付，D N/A）。

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
| pki x509 dotted-OID DN 属性 + Hex-ambiguous DN（原 WP-D）| 56 unknown + 69 unsupported | 需 emitter 精确复刻 parser `oid_to_dn_short_name` + `to_dot_string` + `read_string` 三处行为，fiddly + 边际收益（§4 评估）|

---

## 6. 总验收 & 度量 ✅ 残余收口计划完成（2026-06-16）

| 指标 | 计划前 | 现状（完成）|
|---|---:|---:|
| SPAKE2+ 字节级向量 | 0（仅 round-trip） | **1**（P-256；A-2 多 suite 留 future I-phase）|
| Privacy Pass 字节级 | 0（仅 round-trip） | **1 VECTOR**（request/response/token）|
| na-list Structural Gap（未 resolved） | 2（SPAKE2+ / Privacy Pass） | **0**（两个均 RESOLVED）|
| TLS H §8 still-pending（实质项） | 3 | **0**（M-1/2/3 关闭 cert-verify/finished wire-Alert；M-4/M-5 无 C 源 deferred）|
| **生产互通 bug 修复** | — | **2**（SPAKE2+ §3.4 key schedule + Privacy Pass RSABSSA）|

- [x] 完成的 WP 对应 na-list Structural Gap 行翻 resolved（SPAKE2+ + Privacy Pass）
- [x] DEV_LOG / PROMPT_LOG 同步（T276/T278/T279/T280 + I161/T281 + I162/T282 + 本收尾）
- [x] 每个子 PR：独立 review / pre-push AI review → CI Gate → squash-merge

**WP 完成情况**：**C ✅**（TLS rogue-server wire-Alert，#342/345/346/347）+ **A ✅**（SPAKE2+ 一致性修复 + 字节级，#348）+ **B ✅**（Privacy Pass 一致性修复 + 字节级，#349）+ **D ⏸️ N/A**（fiddly emitter 复刻，边际收益，§4）。

> **本计划最大产出不是测试覆盖，而是两个被迁移飞轮抓到的生产互通 bug**（Rust SPAKE2+ 与 Privacy Pass 此前都不与各自 RFC 标准互通），均已修复并对独立 C 向量 ground-truth 验证。这是 Phase A 飞轮（迁移驱动发现实现 bug）在残余收口阶段的延续（cf. I137/I145/I146）。

---

## 7. 一句话

**做完这 4 个 WP，C→Rust 测试迁移就真正 100% 收口**——剩下的全是 §5 列的 N/A-by-design。若只挑一个，**WP-C / M-2**（零产品代码、零风险、承接已落地基建）是最稳的起点；**WP-A / SPAKE2+ 标量 hook** 是字节级产出最高的起点（但先跑 A-0 probe 去风险）。
