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
