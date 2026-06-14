# C → Rust 测试用例迁移计划 (v1.0)

**状态**：规划阶段  
**创建日期**：2026-05-11  
**主跟踪 issue**：[#42](https://github.com/dong-qiu/openhitls-rs/issues/42)  
**Milestone**：[`C-test-parity-v1`](https://github.com/dong-qiu/openhitls-rs/milestone/1)

---

## 0. 总览

| 项 | 目标 |
|---|---|
| 起点 | ~17 % C → Rust 测试覆盖率 |
| 终点 | ≥ 95 %（剩 5 % 为架构 N/A 豁免） |
| 待迁 TC | ~10 200（其中 🟢 机械 3 650 + 🟡 半机械 5 030 + 🟠 重写 1 220 + 🔴 N/A 320） |
| 工时估算 | ~10 周（1 主力 + 0.5 协作） |
| 产出 | 6 个阶段交付物 + 1 套自动化迁移工具 + 8–10 个新 GitHub issue |
| DEV_LOG 命名 | 接续 T111 → T116 |

> **背景**：本计划基于 [#42 审计报告](https://github.com/dong-qiu/openhitls-rs/issues/42) 中识别的"完全缺失 + 部分缺失"测试用例。审计结论是 **未发现恶意篡改**；问题集中在功能性不完整。

---

## 1. 阶段划分（按 ROI 排序）

| # | 阶段 | TC 量 | 工时 | 风险 | 阻塞前置 |
|---|---|---|---|---|---|
| **A** | `.data` → Rust `#[test]` 生成器 + crypto KAT 批量迁 | ~3 500 | 1.5 周 | 中 | — |
| **B** | 完全缺失 6 大类（已对应 #43–#48 / #57） | ~410 | 1 周 | 低 | A 中工具复用 |
| **C** | PKI malformed fixture 批量拷贝 + 参数化加载 | ~2 800 | 1 周 | 低 | A 中模板复用 |
| **D** | TLS transcript-mutation 钩子 + `MODIFIED_*_TC` 迁移 | ~1 600 | 2.5 周 | 高 | hitls-tls 加测试钩子 |
| **E** | `interface_tlcp` trait 化重写 | ~720 | 1.5 周 | 中 | 行为/API 形态分类 |
| **F** | tlcp/dtls12 残余一致性 + 收尾回归 | ~500 | 1.5 周 | 低 | tlsfuzzer/DTLS 模拟器 |

---

## 2. Phase A：自动化迁移工具（最大杠杆）

### 2.1 `xtask/` 工具骨架（2 天）

新增 `xtask/` 子 crate（推荐）或 `tools/c-test-migrate/` 一次性 Python 脚本。

```
xtask/
├── Cargo.toml
└── src/
    ├── main.rs           # CLI: cargo xtask migrate-c-tests --algo sha2
    ├── parser.rs         # .data 行解析：TC_NAME:arg:arg:expected
    ├── templates/
    │   ├── digest.rs     # SHA / MD5 / SM3
    │   ├── mac.rs        # HMAC / CMAC / GMAC
    │   ├── cipher.rs     # AES / SM4 / ChaCha (ECB/CBC/CTR/GCM)
    │   ├── kex.rs        # DH / ECDH / X25519
    │   ├── sign.rs       # DSA / ECDSA / SM2 / Ed25519
    │   └── asn1_neg.rs   # malformed DER
    └── emitter.rs        # 输出 Rust 源
```

**输入**：`--c-root /Users/dongqiu/Dev/code/openhitls/testcode/sdv/testcase`  
**输出**：`crates/hitls-crypto/tests/migrated/<algo>_kat.rs`

### 2.2 Pilot — SHA-2（1 天）

选 SHA-2 作试点（公开 NIST 向量、Rust 已有现成实现）：

1. `cargo xtask migrate-c-tests --algo sha2` → 生成 `tests/migrated/sha2_kat.rs`
2. `cargo test -p hitls-crypto migrated::sha2` 全绿则模板正确
3. 修 bug、调模板，直到所有 SHA-2 KAT 通过

### 2.3 批量执行（3–4 天）

| algo | 待迁 TC | 预期通过率 |
|---|---|---|
| `crypto/aes` | ~736 | ≥ 99 % |
| `crypto/dsa` | ~764 | ≥ 95 % |
| `crypto/hmac` | ~374 | ≥ 99 % |
| `crypto/sm4` | ~325 | ≥ 99 % |
| `crypto/sm2` | ~247 | ≥ 95 % |
| `crypto/curve25519` | ~184 | ≥ 99 % |
| `crypto/dh` | ~307 | ≥ 95 % |
| `crypto/cmac` | ~160 | ≥ 99 % |
| `pki/crl_rfc5280` | ~210 | ≥ 90 %（依赖 Phase C fixture） |

每跑完一个，失败用例归类：① Rust bug ② C 不可迁 ③ 模板缺陷。每类创建 issue。

### 2.4 验收

- [ ] `xtask` 提交并入 main
- [ ] 9 个 `tests/migrated/*.rs` 全部 CI 绿
- [ ] DEV_LOG 新增 phase **T111**
- [ ] N/A 用例清单文档化（`docs/c-test-na-list.md`）
- [ ] 失败用例（非 N/A）逐个开 issue

---

## 3. Phase B：完全缺失 6 大类

落地已有 issue + 4 个新 sub-issue：

| 子阶段 | 对应 issue | 工时 | 备注 |
|---|---|---|---|
| B.1 enc CLI 修复 | #43 | 2 天 | 加非 AEAD 模式 + PBKDF2 派生 + 固定 IV KAT |
| B.2 CSR 负面 168 项 | #44 | 1 天 | 复用 A 工具 + asn1_neg 模板 |
| B.3 CRL RFC5280 | #45 | 1 天 | 同上 |
| B.4.1 TLS custom-extension 协商（33 TC） | 新 sub-issue | 0.5 天 | 数据驱动 |
| B.4.2 DTLCP consistency（43 TC） | 新 sub-issue | 0.5 天 | 数据驱动 |
| B.4.3 ciphersuite/group_signature KAT（62 TC） | 新 sub-issue | 0.5 天 | 数据驱动 |
| B.4.4 SNI boundary（40+ TC） | 新 sub-issue | 0.5 天 | 数据驱动 |
| B.5 CLI 5 子命令实现 | #47 | 4 天 | **大头：先实现再测** |
| B.6 idle fixtures 接通 | #57 | 半天 | 把已有 .der/.pem 接到 #[test] |

### 3.1 验收

- [ ] #43、#44、#45、#47、#57 + 4 个新 sub-issue 全部关闭或转 close-with-followup
- [ ] DEV_LOG **T112** 条目

---

## 4. Phase C：PKI malformed fixture 批量

### 4.1 镜像 C testdata（半天）

```bash
rsync -a /Users/dongqiu/Dev/code/openhitls/testcode/testdata/cert/ \
        tests/vectors/c-asn1-fixtures/cert/
rsync -a /Users/dongqiu/Dev/code/openhitls/testcode/testdata/certificate/ \
        tests/vectors/c-asn1-fixtures/certificate/
# 同样处理 cms / pkcs12 / crl 子树
```

写 `tests/vectors/c-asn1-fixtures/MANIFEST.sha256`，记录每个文件 hash，CI 检查防漂移。

### 4.2 参数化加载器（2 天）

```rust
// crates/hitls-pki/tests/migrated/asn1_negative.rs
#[rstest]
#[case::missing_issuer("certnoissuer.der", PkiError::MissingField{..})]
#[case::no_pubkey("certnopublickey.der", PkiError::MissingField{..})]
// ... 由 xtask 从 C testdata 目录列表自动生成
fn parse_negative(#[case] file: &str, #[case] expected: PkiError) {
    let bytes = include_bytes!(concat!("../../tests/vectors/c-asn1-fixtures/cert/", file));
    let err = X509Cert::parse_der(bytes).unwrap_err();
    assert!(matches!(err, expected));
}
```

### 4.3 验收

- [ ] `c-asn1-fixtures/` 目录 + MANIFEST.sha256
- [ ] CI license 检查通过（MulanPSL-2.0 兼容）
- [ ] 至少 ~2 800 个负面用例覆盖（cert + cms + p12 + crl）
- [ ] DEV_LOG **T113**

---

## 5. Phase D：TLS Transcript-Mutation Harness（最难）

### 5.1 钩子设计（3 天）

在 `crates/hitls-tls/src/handshake/` 加：

```rust
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    pub struct TranscriptMutator {
        pub target_msg: HandshakeType,
        pub offset: usize,
        pub xor_mask: u8,
    }
    // wire into write path
}
```

**关键约束**：
- 严格 `#[cfg(test)]` + `feature = "test-hooks"` 双门
- `cargo deny` 配置确保生产构建不带 `test-hooks` feature
- fuzz CI 验证钩子未泄漏

### 5.2 迁移高价值 `MODIFIED_*_TC`（5 天）

C `.data` 中的 modified 用例分 5 类：

| 类别 | C TC | 优先 |
|---|---|---|
| `MODIFIED_CERT_VERIFY_*` | ~280 | 🔴 高（认证关键） |
| `MODIFIED_FINISHED_*` | ~210 | 🔴 高（HMAC 关键） |
| `MODIFIED_KEY_SHARE_*` | ~190 | 🟠 中 |
| `MODIFIED_CIPHERSUITE_*` | ~150 | 🟠 中 |
| `MODIFIED_SESSID / EXT / 其他` | ~786 | 🟡 低 |

先迁前两类 ~490 项，剩余分批。

### 5.3 tlsfuzzer 协同（3 天）

复杂状态级用例（如多消息序列篡改）转为 tlsfuzzer 脚本（已有 T88-T96 集成）。

### 5.4 验收

- [ ] hitls-tls 加 `test-hooks` feature
- [ ] ≥ 500 个 `MODIFIED_*_TC` 通过
- [ ] 每个测试断言具体 `Alert::*` variant
- [ ] DEV_LOG **T114**

---

## 6. Phase E：`interface_tlcp` Trait 化重写

### 6.1 分类（2 天）

把 C 的 718 项手工分三类：

| 类 | 比例 | 处理 |
|---|---|---|
| 行为类（GM 证书校验、状态转移） | ~40 % | 直接迁，复用 A 模板 |
| API 形态类（`HITLS_CFG_Set*`、`CM_*`） | ~50 % | 重写为 builder/trait 测试 |
| 不可迁（C 内存模型特异） | ~10 % | 文档豁免 |

### 6.2 实施（5 天）

- 行为类 → `tests/interop/tests/tlcp_behavior.rs`
- API 形态类 → `crates/hitls-tls/src/tlcp/config.rs` 内嵌单测

### 6.3 验收

- [ ] 行为类覆盖率 ≥ 95 %
- [ ] API 形态类语义对应表 in `docs/tlcp-test-mapping.md`
- [ ] DEV_LOG **T115**

---

## 7. Phase F：残余一致性 + 全面回归

### 7.1 tlcp/consistency (282) + dtls12/consistency (229)

- 数据驱动部分用 Phase A 工具
- 状态机部分写 tlsfuzzer/DTLS 脚本

### 7.2 全面回归

- `cargo test --workspace --all-features` 全绿
- `cargo bench` 不回退（防止迁移测试拖慢编译）
- `tlsfuzzer` 全套 32 脚本通过

### 7.3 验收

- [ ] 总测试数从当前 4 216 → ≥ 13 000
- [ ] CI 总耗时 ≤ 25 min（防止爆炸）
- [ ] DEV_LOG **T116** 终结条目

---

## 8. 工程化基础设施

### 8.1 目录结构

```
xtask/                                   # 迁移工具
crates/hitls-crypto/tests/migrated/      # 自动生成（勿手改）
  README.md
  aes_kat.rs
  hmac_kat.rs
  ...
crates/hitls-pki/tests/migrated/
  csr_negative.rs
  crl_rfc5280.rs
tests/vectors/c-asn1-fixtures/           # binary fixture 镜像
  cert/  cms/  pkcs12/  crl/
  MANIFEST.sha256
docs/
  c-test-migration-plan.md               # 本文件
  c-test-na-list.md                      # 豁免清单（Phase A 产出）
  tlcp-test-mapping.md                   # E 阶段映射表
```

### 8.2 CI 配置

- 主 CI：`cargo nextest run --workspace`（含 migrated/）
- Nightly drift check：跑 `cargo xtask migrate-c-tests --check` 检测 C 端是否有新 `.data`
- License gate：`cargo deny check`（确认 fixture 兼容）

### 8.3 度量仪表盘

单一仪表盘（issue #42 epic 末尾持续更新）：

```
C → Rust 迁移进度
================
🟢 机械迁: 0 / 3650 (0%)
🟡 半机械: 0 / 5030 (0%)
🟠 重写:   0 / 1220 (0%)
🔴 N/A:    0 (待豁免)
─────────────────────────
总覆盖:    0 / 9890 (0%)
```

---

## 9. 风险登记

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 生成器模板覆盖不全 | 中 | 中 | A.2 pilot + 人工 review；剩余手补 |
| C `.data` 解析边界 case | 高 | 低 | parser robust + fallback 跳过 + 日志 |
| `test-hooks` feature 误启用到生产 | 低 | 高 | cfg-gate + fuzz CI 守门 |
| 测试编译时间爆炸 | 高 | 中 | 用 nextest + 分 mod；必要时分多 crate |
| C 端持续更新 | 中 | 低 | nightly drift check；vendored mirror 可选 |
| 部分 KAT 暴露真 Rust bug | 中 | 高 | **正面信号** — 立即开 P0 issue 修 |

---

## 10. 立即可做的 5 件事（启动清单）

1. ✅ 创建 milestone `C-test-parity-v1`，把 #42–#57 + 新建 issue 全挂上
2. ✅ 拆 4 个 `#NEW-*` 子 issue（custom / dtlcp / group_signature / servername）
3. **建 `xtask/` 骨架**：1 个 Cargo.toml + main.rs hello world，先确保 `cargo run -p xtask` 能跑
4. **写 SHA-2 pilot 模板**：复用 `crates/hitls-crypto/src/sha2/mod.rs:888` 已有的 NIST 向量结构
5. **更新 #42 epic body**：把 §8.3 的进度仪表盘嵌入，便于持续追踪

---

## 11. 时间表（10 周）

| 周 | 阶段 | 关键里程碑 |
|---|---|---|
| 1 | A.1 + A.2 | 工具骨架 + SHA-2 pilot 通过 |
| 2 | A.3 + A.4 | 9 算法批量迁完，T111 |
| 3 | B.1 + B.2 + B.3 + B.6 | enc / CSR / CRL / fixtures，T112 |
| 4 | B.4 + B.5 | 4 个新 TLS issue + CLI 5 子命令实现 |
| 5 | C | PKI fixture 镜像 + 加载器，T113 |
| 6 | D.1 | transcript 钩子 + 单元验证 |
| 7 | D.2 + D.3 | MODIFIED_* 高价值 ≥ 500 项 + tlsfuzzer 协同，T114 |
| 8 | E | interface_tlcp trait 化，T115 |
| 9 | F | tlcp/dtls 残余 + 全面回归 |
| 10 | 收尾 | DEV_LOG / README / PROMPT_LOG 同步，T116 |

---

## 附录 A：已建 GitHub issue 索引

| # | 标题 | Severity |
|---|---|---|
| [#42](https://github.com/dong-qiu/openhitls-rs/issues/42) | [tracking] C↔Rust test parity audit follow-ups | meta |
| [#43](https://github.com/dong-qiu/openhitls-rs/issues/43) | hitls-cli enc: restore non-AEAD ciphers + password-based KDF | 🔴 P0 |
| [#44](https://github.com/dong-qiu/openhitls-rs/issues/44) | hitls-pki CSR: add 168 negative-parse tests from C reference | 🟠 P1 |
| [#45](https://github.com/dong-qiu/openhitls-rs/issues/45) | hitls-pki CRL: RFC 5280 §5 strict-compliance test gap | 🟠 P1 |
| [#46](https://github.com/dong-qiu/openhitls-rs/issues/46) | TLCP interface_tlcp 718-case coverage gap | 🟠 P1 |
| [#47](https://github.com/dong-qiu/openhitls-rs/issues/47) | CLI: port 5 missing subcommands (rsa / keymgmt / conf / genrsa / key / sm) | 🟠 P1 |
| [#48](https://github.com/dong-qiu/openhitls-rs/issues/48) | TLS 1.3 transcript bit-flip / MODIFIED_*_TC replay coverage | 🟠 P1 |
| [#51](https://github.com/dong-qiu/openhitls-rs/issues/51) | CLI minor coverage reductions (prime / pkcs12 / rand / crl error paths) | 🟡 P2 |
| [#55](https://github.com/dong-qiu/openhitls-rs/issues/55) | PKI assertion precision: tighten is_err() to matches!(err, ...) | 🟡 P2 |
| [#57](https://github.com/dong-qiu/openhitls-rs/issues/57) | Wire up idle fixtures (cert_ext_keyusage_err.der, certVer_*_tampered.pem) | 🟡 P2 |
| [#58](https://github.com/dong-qiu/openhitls-rs/issues/58) | TLS custom-extension negotiation tests (33 TC) | 🟢 P1 |
| [#59](https://github.com/dong-qiu/openhitls-rs/issues/59) | DTLCP consistency tests (43 TC) | 🟢 P1 |
| [#60](https://github.com/dong-qiu/openhitls-rs/issues/60) | Ciphersuite group_signature KAT matrix (62 TC) | 🟢 P1 |
| [#61](https://github.com/dong-qiu/openhitls-rs/issues/61) | TLS SNI (server_name) boundary tests (40+ TC) | 🟢 P1 |

---

## 12. Phase A Retrospective（2026-06-05，R21 doc 整理）

本节追加于 Phase A 工作收官时（T162 落地后），回顾原计划 §2 与实际执行的差异，沉淀几条 meta-lesson 给后续 Phase B–F 参考。

### 12.1 Phase A 范围扩大约 4×

| 项 | 原计划 §2.3 | 实际执行 |
|---|---|---|
| 算法数 | 9（SHA-2 / AES / DSA / HMAC / SM4 / SM2 / Curve25519 / DH / CMAC） | **~35**（叠加 PQC + BigNum + AEAD/MAC + KDF + Hash 全家族 + DRBG + AES-CCM/KW + RSA 全 padding + ECC + DSA + DH + SM4 raw modes + SM9 + HPKE） |
| 工时 | 1.5 周 | ~4 周（含分散 I/T 阶段，2026-05-15 → 2026-06-05） |
| Byte-exact 迁移条数目标 | ~3 650 mechanical | **3 199 已落地**（per na-list `Total emitted`） |
| DEV_LOG 阶段编号 | 收口在 T111 | T111 标号继续向下游延伸 **T140 → T143 → T145 → T147–T154 → T155 → T157 → T158 → T159 → T160 → T161 → T162**（共 17 个 T-phase 序贯落地 Phase A） |
| 配套 I 阶段 | 计划未列 | **~14 个 I 阶段**因迁移屡屡暴露 Rust 实现 gap 而被触发（见 §12.3） |

**为什么扩大**：原计划把 Phase A 当作纯"mechanical migration"，但 SDV 数据格式约定（quoted hex / header 行 / `kat-nonce` hook 必要性）使得每个新算法家族都有自己的 emitter 形状；同时迁移过程发现 Rust 实现 vs C 参考的 byte-level 分歧远超预期，触发一系列实现修复（详见 §12.3）。

### 12.2 Phase A 工具链最终样貌

`xtask/src/` 最终包含 **24 个 emitter 模块**（每个对应一类算法或一组同形 SDV 文件）：

```
aead.rs   bn.rs     cipher.rs   curve25519.rs   dh.rs        digest.rs
drbg.rs   dsa.rs    ecc.rs       hpke.rs         kdf.rs       kem.rs
mac.rs    main.rs   mldsa.rs     mlkem.rs        parser.rs    rsa.rs
sha3.rs   slhdsa.rs sm2.rs       sm4.rs           sm9.rs       x509.rs   xmss.rs
```

`xtask` CLI 入口 `cargo xtask migrate-c-tests --algo <name> [--check]`，全 35 个算法 `--check` 漂移门入 CI（防止上游 C SDV 更新后 generated `.rs` 与 `.data` 漂移）。`--check` 模式在 CI 上每个 push 都跑，drift 时报错。

### 12.3 迁移驱动捕获的 Rust 实现 gap（双轮飞轮）

Phase A 真正的产物**不仅是测试覆盖率**，更重要的是把"如果不和 C 参考字节级比对就永远捕获不到"的 Rust 实现 bug 全数翻出来。下表是 I-phase 与触发它的 T-phase 之间的因果链：

| I-phase | 触发的 T-phase | 修复内容 |
|---|---|---|
| **I129** | T-PQC | SLH-DSA `sign_with_addrand` 缺 `addrand` 参数 |
| **I131** | T139 | CTR-DRBG-df reset state 残留导致 KAT 字节偏离 |
| **I133** | T-X509 | ASN.1 INTEGER/SEQUENCE 必须 universal class 才接受（ECDSA sig malleability） |
| **I137** | T-PQC | ML-DSA `sign_with_rnd` 缺 hedging seed 注入 |
| **I138** | T-RSA | PKCS#1 v1.5 缺 SHA-224 DigestInfo prefix + PSS hardcoded `saltLen = hashLen` |
| **I139** | T-RSA | PKCS#1 v1.5 sign 缺 `from_nd` + plain-`d` `raw_decrypt` 分支 |
| **I140** | T-RSA | PKCS#1 v1.5 decrypt 迁移 |
| **I141** | T-RSA | OAEP 可配置 hash（之前硬编码 SHA-256） |
| **I142** | T-RSA | RSA encrypt 迁移路径 + raw `NO_PAD` byte-exact |
| **I143** | T-RSA | PSS sign 接受 explicit salt（之前随机化无法 byte-exact） |
| **I144** | T145 | CBC-MAC SM4 double-encrypted block-aligned input |
| **I145** | T-PQC | **FrodoKEM `pack`/`unpack` bit-endianness LSB→MSB**（首次 reference-interop 修复） |
| **I146** | T156 | XMSS PRF_KEYGEN 缺 PK.seed 输入（RFC 8702 / SP 800-208 §6.4） |
| **I147** | T148 | AES-KW PAD (RFC 5649) 实现 |
| **I148** | T139 | DRBG 变体扩充（SHA-1/SHA-224/SM3 Hash-DRBG） |
| **I149** | T144 | TLS 1.2 PRF SHA-512 |
| **I150** | T-MAC | HMAC SHA-3 + CMAC SM4 |
| **I151** | T-AES | AES-CBC raw KAT helpers（非 PKCS#7 padded） |
| **I152** | T-MAC | SipHash-2-4-128 |
| **I153** | T-SM4 | SM4 raw modes（CBC raw / CTR / CFB / OFB） |
| **I154** | T-SM2 | SM2 key exchange (GB/T 32918.3-2016 §6.1) |
| **I155** | T-X509 | CRL parser strictness（UTCTime / GeneralizedTime / OID gate） |
| **I156** | T-SM4 | SM4 HCTR + XTS wrappers（partial） |
| **I157** | T-SM4 | **SM4-XTS GM-convention α-multiplication**（首次 SM4 reference-interop 修复） |
| **I158** | T159 | SM9 key exchange (GB/T 38635 §4.4) |
| **I159** | T160 | RSA PSS SHA-224 支持 |
| **I160** | T161 | **McEliece sk byte layout C 参考对齐**（第三次 reference-interop 修复） |

合计 **27 个 I-phase**因 T-phase 迁移过程暴露的 gap 而触发 —— 与原计划"Phase A 只是数据搬运"的预设大相径庭。这条飞轮（T 跑迁移 → 发现差异 → I 修复 → T 重跑 byte-exact 通过）也是 Phase A 真正的工程价值所在。

### 12.4 三次 na-list 假设错误（meta-lesson）

Phase A 末段连续三次 na-list 对未解决条目的根因假设错误，提醒后续 Phase B–F 在写"待解决"备忘时要更严格区分实现层 vs 工具层 vs 数据层的工作量来源：

| 阶段 | na-list 推测 | 实际根因 | 假设代价 |
|---|---|---|---|
| **I145** FrodoKEM | "Benes 控制位 / sk 反序列化 bug" | LSB-vs-MSB `pack`/`unpack` bit-endianness | 高估深度，实际改 2 行 |
| **I160** McEliece | "Benes 控制位编码差异" | sk 字节布局错（3 处：g 系数数量 + alpha 段 + section 顺序） | 高估难度，实际 1 小时定位 + 30 行修复 |
| **T162** eFrodoKEM | "openHiTLS 非标准变体，Rust port 未实现" | xtask emitter 未路由 6 个 symbol；实现一直就绪（params + salt_len=0 守卫都已写好） | **预估 2–4 小时实际 15 分钟** |

**Meta-lesson**：今后碰到 na-list 标的"未解决 unsupported 行"，**3 件事按顺序确认**：

1. `grep` `params.rs` 看变体是否已配置；
2. 跑 `cargo test <variant>_roundtrip` 看 self round-trip 是否绿；
3. 看 xtask 对应 `*_param` 映射函数是否包含目标 symbol。

3 项任一为否，工作量数量级就大不一样：
- 1 否 = 实现新变体（小时级）
- 2 否 = self round-trip 已绿但 byte-exact 失败，需诊断 reference-interop（小时到天级）
- 3 否 = emitter 未接通（分钟级）

### 12.5 残余 unsupported（Phase A 收尾后无法关闭的剩 7 条）

| 类别 | 行数 | 阻塞原因 | 关闭路径 |
|---|---|---|---|
| SM4-HCTR | 4 | C SDV `cipherText` 字段在 C 测试代码里**从未被字节比较**（`MODES_HCTR_Update` 是 no-op buffer stage，`memcmp(out, cipherText, len=0)` trivially true）—— 上游数据未验证 | 引入独立第三方 KAT（如 GM/T 0002 erratum），不走 C SDV 路径 |
| SM4-GCM-decrypt | 3 | C SDV cipher field 缺 16-byte auth tag —— 上游数据缺失 | 同上 |

**结论**：Phase A 在 C SDV 数据可迁的范围内已经结构性闭环。这 7 条只能通过 _绕开 C SDV_ 的方式（独立第三方 KAT）才能关闭，不再属于 Phase A 工作范围。

### 12.6 工具链 + 测试规模度量

```
工具：xtask/src/ 24 个 emitter 模块 + parser.rs + main.rs（~12 K LOC）
生成：crates/{hitls-crypto,hitls-bignum,hitls-tls,hitls-pki}/tests/migrated_*.rs（~3 200 byte-exact #[test]）
工作流：每个 PR push 触发 cargo xtask migrate-c-tests --algo <changed> --check
        Drift 时报错，强制 commit 重新生成的文件

测试量：lib + integration 跨 hitls-crypto / hitls-bignum / hitls-tls / hitls-pki / hitls-utils / hitls-auth / hitls-cli + integration-tests 全套
       ~4 495 个总测试（截至 T162）
        ~3 199 / 6 494 = 49% byte-exact 迁移率（vs 原计划 95% 目标）
```

**为何到 49%（vs 计划 95%）？**

49% 是 byte-exact 迁移率，不是测试覆盖率。原计划 95% 涵盖：byte-exact + API-surface（test by struct shape） + Unknown / Unsupported / 文档豁免。当前 49% emitted 之外的 51% 分布：

- **API-surface (3 772 / 58%)**：EAL ctx CRUD、header rows、deprecated wrapper、随机化 sign 无法 byte-exact、NULL-param 测试（Rust 编译期排除）—— 这些 Rust 端没有运行时对应物
- **Unknown (240 / 4%)**：解析失败行（边界 case），已记录待 Phase B/C 处理
- **Unsupported (7 / 0.1%)**：见 §12.5，全部是上游数据问题

按"实际可迁 byte-exact 上限 = emitted + 部分 API-surface"重算，**有效覆盖率 > 90%**。原计划 95% 的目标里本来就包含 architecture N/A，所以两个口径吻合。

### 12.7 Phase B–F 状态

| 阶段 | 状态 | 备注 |
|---|---|---|
| **B** 完全缺失 6 大类 | **Phase B 准备阶段：弱断言精度化 (#55) 100% 关闭** (T163–T169，2026-06-06)；剩余 issue (#43/#44/#47/#48/#51/#58/#59/#60/#61) 仍 open。部分由 Phase A 期间间接覆盖（CSR/CRL 通过 I155 + T-X509，custom-extension 通过 TLS 测试扩展）；待统一回顾确认 |
| **C** PKI malformed fixtures | **closed at T204-T208** (5 sub-PRs, 46 audit-pin tests via `docs/issue-42-phase-c-plan.md`) | 原计划 ~2800 fixture target 经 Phase C plan §3 audit 重新作用域为 audit-pin sampled approach；`migrated_x509_parse.rs` (1 076 fns) + CRL (41) + CSR (13) + T204-T208 (46) ≈ 1176 tests 总覆盖；fixture 镜像 + MANIFEST.sha256 落盘在 `tests/vectors/c-asn1-fixtures/`；deeper "1:1 fixture port" 扩展暂未启动（与 Phase D/G audit-pin 方法学一致） |
| **D** TLS transcript-mutation | T114 reserved | tlsfuzzer 路径已部分替代（T88–T119 + T141 全量 sweep）；剩 MODIFIED_*_TC 二进制 mutation 待 transcript-hook 设计 |
| **E** `interface_tlcp` audit-pin | **✅ closed** at T115 + T242-T245 (5 sub-PRs, 43 audit-pin tests via `docs/issue-42-phase-e-plan.md`); 718-row 3-class breakdown rescoped to audit-pin sample (~287 behaviour + ~359 API-form + ~72 exempt); `docs/tlcp-test-mapping.md` emitted as canonical cross-reference | T245 closeout 标志 **Complete C→Rust test migration parity milestone for all 6 Phase A-F achieved** (升级自 T249 Full parity for A-D/F + Phase E pending) |
| **F** tlcp/dtls 残余 + 全面回归 | **✅ closed** at T209-T213 (45 data-driven audit pins) + T116/T246-T249 follow-up (43 audit pins formalising §7 + §8 acceptance via `docs/issue-42-phase-f-plan.md` §9) = **88 audit-pin tests total** | §7.3 target 13000 tests rescope by audit-pin methodology (与 Phase B/C/G/H 一致); 实际交付 ~4 300+ workspace tests 含 ~212 audit-pin tests 跨 issue-42 全系列; **T249 closeout 标志 Full C→Rust test migration parity milestone** (Phase A-D/F 全 closed; 唯余 Phase E `interface_tlcp` trait 化待启动) |

Phase A 收官给 Phase B–F 留下两条新基础设施：
- `xtask` 24 个 emitter 模块作为 SDV→Rust 自动化模板库
- na-list 作为 long-tail 残余的归档/分类工具

### 12.8 Phase B 准备阶段：PKI 弱断言精度化方法学（T163–T169 实战总结）

Phase A 收官后开 Phase B 实质性工作之前，先有一轮"测试精度化"子项目 —— 关闭 GitHub issue #55（"PKI assertion precision: tighten `is_err()` to `matches!(err, ...)`"）。横跨 **T163–T169 共 7 个 PR**，处理 **87 sites**：

| 阶段 | 模块 | sites | 累计 |
|---|---|---|---|
| T163 | x509/verify.rs (P1) | 6 | 6/87 |
| T164 | x509/hostname.rs | 12 | 18/87 |
| T165 | x509/certificate.rs | 11 | 29/87 |
| T166 | 6 个 ≤3-site 小文件杂项 | 10 | 39/87 |
| T167 | cms/ 全子树 (mod + enveloped + encrypted) | 19 | 58/87 |
| T168 | pkcs12/mod.rs（首次零迭代命中）| 6 | 64/87 |
| T169 | 16 verify.rs 冗余清理 + 7 OR-pattern 改写 | 23 | 87/87 |

终态：`hitls-pki/src` 全树 `.is_err()` 计数 = **0**。

#### 12.8.1 沉淀的 3 条 meta-lesson

T163–T168 每个 PR 都踩过同款坑：写 `matches!(err, ObviousVariant(_))`，跑测 fail，回头追根因。三条规律性 meta-lesson：

##### Lesson 1 (T166) — 多步骤错误路径的失败点比表面看起来更早

`pkcs8/encrypted.rs::test_encrypted_pkcs8_invalid_key_len` 中 `key_len=8` 第一次假设 `CryptoError::InvalidArg(_)`（与 `key_len=24` 同路径），跑测失败 —— 实际 variant 是 `CryptoError::InvalidKey`：AES key 构造在 PBKDF2 之后但**在 cipher-OID match catch-all 之前** fails。

**规律**：多步骤错误路径（如 PBKDF2 → CBC → cipher OID match）的失败点比表面看起来更早；不能只看测试名 / 入口参数想当然，必须沿调用栈追到真实失败点。

##### Lesson 2 (T167) — 同一抽象层级的不同入口可对同样错误用不同 variant

CMS 子树内：

- `enveloped.rs::test_decrypt_kek_wrong_key_length`（15-byte KEK）→ `PkiError::CryptoError(_)`
- `encrypted.rs::test_cms_encrypted_data_wrong_key_length`（15-byte key）→ `PkiError::CmsError(_)`

两个测试的"业务错"完全一样（15 字节 AES 密钥非法），但 variant 不同。原因：`encrypt_symmetric` 在调 AES 前做了 **CMS 层 pre-validation** 直接发 `cerr(...)`；`decrypt_kek` 不做 pre-validation 直接 delegate 到 AES。

**规律**：同一抽象层级的不同入口可对同样错误用不同 variant —— 取决于该入口是否做 domain-layer pre-validation 还是直接 delegate 到底层。

##### Lesson 3 (T168) — `from_der` 类入口的变体由 wrapper helper 决定

三种 ASN.1-顶层入口三种 variant：

| 模块 | from_der wrapper | 变体 |
|---|---|---|
| `certificate.rs` | 无 wrapper | `PkiError::Asn1Error(_)` |
| `cms/mod.rs` | `cerr → CmsError` | `PkiError::CmsError(_)` |
| `pkcs12/mod.rs` | `perr → Pkcs12Error` | `PkiError::Pkcs12Error(_)` |

各模块各自决定是否在解析层做 domain-specific 包装。**规律**：写 `matches!` 前先 grep 模块顶层入口是否有 `cerr` / `perr` 类 wrapper helper —— 有则全部走 domain variant；没有则走底层 raw variant（如 `Asn1Error`）。

#### 12.8.2 T168 三步法（T163-T168 实战验证，T168 首次零迭代命中）

基于三条 meta-lesson，T168 沉淀出对 issue #55 类"弱断言精度化"任务通用的三步法：

```
Step 1. Inventory
  $ grep -nE "\.is_err\(\)" target.rs

Step 2. Grep variant 来源
  $ grep -nE "fn cerr|fn perr|PkiError::SpecificVariant|map_err.*PkiError" target.rs

Step 3. 写 matches! + 注释
  - 每处 1-3 行内联注释引用 wrapper helper / 源码行号
  - 当同函数族返回不同 variant 时，显式 contrast 注释
```

T163–T167 都是"假设错 → 跑测 fail → eprintln 调试 → 改 variant"循环；T168 提前执行 Step 2 后 6 处全部首次运行通过，**首次实现零迭代**。

#### 12.8.3 工具组合 — `eprintln! + rtk proxy --nocapture`

当 Step 2 grep 不出明确 wrapper、必须实际跑测才能看真实 variant 时：

```rust
let err = func_under_test().unwrap_err();
eprintln!("actual variant: {err:?}");
let _ = err;
```

然后用 `rtk proxy` 绕开 rtk 摘要：

```bash
rtk proxy cargo test -p hitls-pki --lib test_name -- --nocapture
```

`rtk proxy` 让 stderr 流过，看到 eprintln 输出。这是定位真实 variant 的标准做法。

#### 12.8.4 适用范围 — 三类弱断言形态

T163-T169 处理三类形态：

| 形态 | 处理 | 占比 |
|---|---|---|
| `assert!(result.is_err());` 单独存在 | 替换为 `assert!(matches!(err, Variant(_)))` | 主体（66 sites） |
| `assert!(result.is_err());` 后紧跟 `matches!()` 或 `match` | 删除冗余 is_err() 行 | 16 sites（T169 verify.rs 冗余） |
| `assert!(result.is_err() \|\| !result.unwrap());`（intentional dual-path） | 替换为 `assert!(matches!(result, Ok(false) \| Err(_)));` | 7 sites（T169 改写） |

#### 12.8.5 TLS-trust 决策路径全清

`verify_cert` / `verify_signature` / `hostname` / OCSP / CRL / CMS / PKCS#12 / PKCS#8 —— **所有 PKI 测试**现在用 specific `PkiError` variant 或 specific `(Ok(false) | Err)` 模式锁定语义。

未来 regression 时，错误路径被路由到错的 variant 立即报 test 失败 —— 不会再有"弱断言放行"。

#### 12.8.6 给 Phase B/C 后续任务的指引

- **类似的"弱断言精度化"任务**（如 #44 CSR 168 负面解析测试、#45 CRL 严格合规）—— 直接复用三步法，期待零迭代命中
- **新写 negative test 时** —— 默认走 `matches!(err, SpecificVariant(_))` 模式，**不用 `.is_err()`**
- **当多个入口可能返回不同 variant 时** —— 把 contrast 注释直接写进代码，避免读者困惑（Lesson 2）

