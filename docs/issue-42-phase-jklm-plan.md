# Phase J–M — Remaining C→Rust Test Migration Closure (v1.0)

**状态**：规划阶段（2026-06-15）
**主跟踪 issue**：[#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**前序**：Phase A–I 已关闭（`docs/c-test-migration-plan.md` §12.7 + `docs/issue-42-phase-{b..i}-*.md`）
**DEV_LOG 命名**：接续 T254 → **T255–T281**

---

## 0. 为什么还有 Phase J–M

Phase A–I 在 **crypto / pki(部分)/ tls-tlcp-dtls(audit-pin)** 三域达成 parity 里程碑，但
存在两类结构性遗留：

1. **从未纳入 A–F 计划的 4 个 C 测试类** —— `auth / cmvp / codecs / bsl`。A–F 的范围定义
   只覆盖 crypto + pki + tls，这 4 类被整体遗漏。它们只靠 Rust 原生测试覆盖，**未对齐 C 向量**。
2. **抽样口径与全量口径的落差** —— PKI 负面 fixture（计划 §4.3 的 ~2800 目标改为 audit-pin
   46 项）、apps/CLI（#43/#47 仍 open）、TLS 一致性/状态机（~3000 行只抽样 ~310 项）。

本计划把这些遗留拆成 4 个新阶段，**逐项按"可字节级则字节级、否则 audit-pin"的既定双轨方法学**收口。

### 0.1 缺口量化（基于 2026-06-15 实测）

| 域 | C 数据行 | 现状 | 本计划阶段 | 迁移口径 |
|---|---:|---|---|---|
| `auth/otp` (HOTP/TOTP) | 168 | 仅 hitls-auth 原生 | **J** | 字节级 KAT |
| `auth/privpass_token` | 163 | 仅原生 | **J** | 字节级 KAT |
| `auth/pake` (SPAKE2+) | 13 | 仅原生 | **J** | 字节级 + round-trip |
| `cmvp` (FIPS 自测) | 70 | 散落 | **J** | 字节级 KAT |
| `codecs/decode` | 23 | 散落 | **J** | 字节级 |
| `bsl` (ASN.1/Base64/PEM/list) | 770 | hitls-utils 原生 80 测试 | **J(尾)** | audit-pin（多为 C 内存层） |
| `pki/cert/x509_cert` | 2298 | x509_parse 1073 | **K** | 字节级 + fixture 1:1 |
| `pki/{common,crl,cms,csr,pkcs12,vfy,check}` | ~2050 | audit-pin ~120 | **K** | fixture 1:1 + 数据驱动 |
| `apps/*` (CLI 端到端) | 1078 | hitls-cli 原生 317 | **L** | implement-then-test |
| `tls/*` rogue-server 收尾 | H §8 4 项 | 已 audit-pin | **M** | E2E 升级 |

---

## 1. 阶段总览（按 ROI 排序）

| 阶段 | 主题 | 口径 | T 区间 | 工时 | 风险 | 阻塞 |
|---|---|---|---|---|---|---|
| **J** | auth/cmvp/codecs/bsl 纳入 | 字节级（xtask 扩展） | T255–T260 | 1 周 | 低 | 复用 Phase A 工具 |
| **K** | PKI 深度 fixture 1:1 | 字节级 + fixture 镜像 | T261–T268 | 1.5 周 | 中 | Phase C 模板 |
| **L** | apps/CLI 对齐 + 关闭 #43/#47 | implement-then-test | T269–T275 | 2 周 | 高 | 需先实现 CLI 子命令 |
| **M** | TLS rogue-server E2E 收尾 | E2E 升级 | T276–T281 | 1.5 周 | 中 | H §8 cert-loader |

**推荐执行序**：J → K → M → L（J/K 是高 ROI 机械迁移先行；M 收尾已有 G/H 基础设施；L 含
实现工作量最大，放最后）。

---

## 2. Phase J — auth / cmvp / codecs / bsl 纳入（T255–T260）

**核心判断**：这 4 类**从未进过迁移计划**，但 auth/cmvp/codecs 的 `*_VECTOR_*` / `*_FUNC_*`
行是真 KAT，Rust 已有对应 API（HOTP/TOTP、SPAKE2+、Privacy Pass、FIPS 自测、ASN.1 decode）。
直接复用 Phase A 的 `xtask` 模板即可字节级迁移。bsl 多为 C 内存层测试，走 audit-pin。

### 2.1 子 PR 拆分

| # | T | 来源 | 估计测试 | 做法 |
|---|---|---|---:|---|
| ✅ plan + J-1 | ✅ T255 | 本文档 + `xtask/src/otp.rs` emitter | **52 delivered** | HOTP RFC 4226 + TOTP RFC 6238 KAT；输出 `hitls-auth/tests/migrated_otp.rs`；零新增产品代码，52/52 首次通过 |
| ✅ J-2 | ✅ T256 | round-trip pins（byte-exact **blocked**） | **5 delivered** | Privacy Pass `VECTOR_TEST_TC001` byte-exact 被实现缺口阻塞（Rust privpass 无 EMSA-PSS/salt/hooks）→ na-list Structural Gap + 用 C vector RSA-2048 密钥跑 round-trip（SM9/T158 法）；未来 I-phase 解锁字节级 |
| ✅ J-3 | ✅ T257 | round-trip pins（byte-exact **blocked**） | **3 delivered** | SPAKE2+ `SPAKE2PLUS_TC001` byte-exact 阻塞（Rust 只支持 1/14 suite + 无 x/y 标量注入）→ na-list Structural Gap + 用 P-256 向量 (w0,w1,L) 跑 round-trip（SM9/T158 法）；未来 I-phase 解锁 |
| ✅ J-4 | ✅ T258 | integration pins | **4 delivered** | CMVP 是 `(void)` FIPS 自检框架（无数据驱动 KAT）→ 迁移为集成 pin：`FipsModule::run_self_tests()` 聚合 KAT+PCT + `check_integrity` 成功/篡改/缺失；C 逐算法 `Selftest*` 粒度 = API-surface |
| J-5 | T259 | `xtask/src/codecs.rs` | ~15 | ASN.1 decode 正/负面 |
| closeout | T260 | bsl audit-pin + 系列收尾 | ~15 | bsl 内存层走 audit-pin；`migrated_bsl_audit.rs` |

### 2.2 验收
- [ ] `xtask --algo {otp,privpass,pake,cmvp,codecs}` 全部 `--check` 入 CI
- [ ] `hitls-auth/tests/migrated_*.rs` 全绿；`*_API_TC*`（ctx CRUD）按既定约定路由 API-surface 并计数
- [ ] na-list 追加 5 个新算法的 per-algo tally 行
- [ ] DEV_LOG **T255–T260**

> **预期飞轮**：迁移可能暴露 HOTP/TOTP 截断算法、SPAKE2+ 标量约定、Privacy Pass 序列化的
> byte-level 分歧（参照 Phase A 的 27 个 I-phase 飞轮）。每发现一个开 I-phase。

---

## 3. Phase K — PKI 深度 fixture 1:1（T261–T268）

**核心判断**：Phase C 把 §4.3 的 ~2800 fixture 目标降级为 46 audit-pin。本阶段**真正落地
计划 §4.1-4.3 的 fixture 镜像 + rstest 参数化加载器**，对最大的 `x509_cert.data`(2298) 和
负面解析子树做 1:1 字节级移植。

### 3.1 子 PR 拆分

| # | T | C 源 | C 行 | 估计 | 做法 |
|---|---|---|---:|---:|---|
| plan + K-1 | T261 | fixture 镜像 + MANIFEST.sha256 | — | 基建 | `rsync` C `testdata/cert\|cms\|pkcs12\|crl` → `tests/vectors/c-asn1-fixtures/` + hash 漂移门 |
| K-2 | T262 | `pki/cert/x509_cert.data` | 2298 | ~600 | `xtask --algo x509-parse` 扩展覆盖剩余 ~1200 行 |
| K-3 | T263 | `pki/crl/x509_crl_rfc5280.data` | 212 | ~120 | RFC 5280 §5 严格合规负面 |
| K-4 | T264 | `pki/csr/x509_csr.data`（#44） | 168 | ~150 | CSR 负面解析（复用 asn1_neg 模板） |
| K-5 | T265 | `pki/cms/cms_sign.data` + `cms.data` | 280 | ~120 | CMS SignedData/EnvelopedData |
| K-6 | T266 | `pki/pkcs12/*` | 161 | ~90 | PKCS#12 解析 + MAC 校验 |
| K-7 | T267 | `pki/verify/x509_vfy.data` + `cert/x509_check.data` | 486 | ~150 | 证书链/路径校验 |
| closeout | T268 | `pki/common/*`(992) audit-pin + 收尾 | ~30 | 共性行抽样 + 系列 rollup |

### 3.2 验收
- [ ] `c-asn1-fixtures/` + `MANIFEST.sha256` + CI license 门（MulanPSL-2.0 兼容）
- [ ] 负面用例统一用 `matches!(err, PkiError::SpecificVariant(_))`（复用 §12.8 三步法，期待零迭代）
- [ ] DEV_LOG **T261–T268**

---

## 4. Phase L — apps/CLI 对齐 + 关闭 #43/#47（T269–T275）

**核心判断**：apps/ 1078 行测 CLI 子命令端到端。#43（enc 非 AEAD + PBKDF2）、#47（5 个缺失
子命令 rsa/keymgmt/conf/genrsa/key/sm）**仍 open** —— 必须**先实现再测**，是本计划最大实现工作量。

### 4.1 子 PR 拆分

| # | T | 内容 | 估计 | 做法 |
|---|---|---|---:|---|
| plan + L-1 | T269 | 本文档 + #43 enc 非 AEAD + PBKDF2 派生 | ~15 | 恢复 CBC/CTR/CFB/OFB + 固定 IV/盐 KAT |
| L-2 | T270 | #47 `genrsa` / `rsa` 子命令实现 | ~20 | 实现 + apps/ rsa 行对齐 |
| L-3 | T271 | #47 `keymgmt` / `key` / `sm` 子命令 | ~20 | 实现 + 对齐 |
| L-4 | T272 | #47 `conf` 子命令 + 配置解析 | ~10 | 实现 + 对齐 |
| L-5 | T273 | apps/ 剩余命令端到端对齐 | ~30 | x509/req/verify/dgst/pkeyutl 等 CLI golden-output 测试 |
| L-6 | T274 | #51 小覆盖（prime/pkcs12/rand/crl 错误路径） | ~15 | audit-pin |
| closeout | T275 | 系列收尾 + #43/#47/#51 关闭 | ~5 | rollup |

### 4.2 验收
- [ ] #43 / #47 / #51 关闭或转 close-with-followup
- [ ] CLI golden-output 测试（stdin/stdout/exit-code 三元组）
- [ ] DEV_LOG **T269–T275**

---

## 5. Phase M — TLS rogue-server E2E 收尾（T276–T281）

**核心判断**：Phase H §8 列出 4 项"still-pending follow-up"。本阶段**关闭其中 3 项**（第 4 项
custom-alert 并入各 E2E）。这是把 audit-pin 升级为真 wire-format `Alert::*` 观测的收尾。

### 5.1 子 PR 拆分

| # | T | 来源（H §8） | 估计 | 做法 |
|---|---|---|---:|---|
| plan + M-1 | T276 | rogue-server cert + 私钥加载器 | ~10 | PEM→DER→PKCS#8 签 CertVerify（+~200 LoC over 现有 loader） |
| M-2 | T277 | `MODIFIED_CERT_VERIFY_*` 真 wire Alert | ~12 | CV 签名校验阶段观测 `decrypt_error` |
| M-3 | T278 | `MODIFIED_FINISHED_*` 真 wire Alert | ~12 | Finished MAC 校验阶段观测 |
| M-4 | T279 | DTLS 1.3 UDP rogue server（RFC 9147 §4） | ~10 | epoch+seq 加密统一头 |
| M-5 | T280 | 0-RTT 接受 E2E + PSK 预热（T119 deferred PSK_ONLY） | ~10 | early-data 路径 |
| closeout | T281 | custom-alert variant 收紧 + 系列收尾 | ~6 | 所有 E2E 断言精确 `Alert::*` |

### 5.2 验收
- [ ] `transcript_mutation_encrypted_e2e.rs` 所有断言从"client errors"收紧到具体 `Alert::*`
- [ ] H §8 的 4 项 still-pending 全部 RESOLVED
- [ ] DEV_LOG **T276–T281**

---

## 6. 方法学决策（双轨口径）

沿用 Phase A–I 既定原则，**按"能否字节级复现"分轨**：

| 口径 | 适用 | 阶段 |
|---|---|---|
| **字节级 1:1**（xtask emitter） | 有公开向量 + Rust 有确定性 API 的 KAT | J（otp/privpass/pake/cmvp/codecs）、K（PKI fixture） |
| **implement-then-test** | Rust 端功能缺失，需先实现 | L（CLI 子命令） |
| **audit-pin 抽样** | C 内存模型特异 / 状态机需 harness | J 尾（bsl）、K 尾（common）、M（TLS E2E） |

**不做的事**（显式 out-of-scope，非静默缺口）：
- crypto API-surface（3772）/ provider 重复行 —— Rust 无运行时对应物，永久豁免
- C 内存对齐 / NULL-param 测试 —— Rust 编译期排除
- 上游数据有缺陷的 7 条 unsupported（SM4-HCTR / GCM-decrypt）—— 需独立第三方 KAT

---

## 7. 总验收 & 度量

| 指标 | 当前 | Phase J–M 后（预期） |
|---|---:|---:|
| 字节级迁移测试 | ~3199 | ~4000+ |
| audit-pin 测试 | ~310 | ~400 |
| workspace 总测试 | ~8647 | ~9200+ |
| xtask emitter | 24 模块 / 37 algo | +5 模块（otp/privpass/pake/cmvp/codecs） |
| 遗留 open issue | #43/#44/#45/#47/#48/#51/#58-61 | 全部关闭或转 followup |

- [ ] `cargo test --workspace --all-features` 全绿
- [ ] CI 总耗时 ≤ 25 min（防膨胀，用 nextest 分片）
- [ ] DEV_LOG / na-list / PROMPT_LOG 同步至 T281
- [ ] `docs/c-test-migration-plan.md` §12.7 状态表追加 Phase J–M 行

---

## 8. 风险登记

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| auth/cmvp 向量格式与 crypto SDV 不同形 | 中 | 中 | 每类先 pilot 1 行验证 emitter 形状 |
| PKI fixture license 不兼容 | 低 | 高 | K-1 先跑 `cargo deny` license 门 |
| CLI 子命令实现拖工期 | 高 | 中 | L 放最后；子命令可独立 PR 增量交付 |
| DTLS 1.3 UDP harness 复杂度 | 中 | 中 | M-4 可降级为 wire-format pin（参照 T227） |
| 迁移暴露真 Rust bug | 中 | 高 | **正面信号** —— 立即开 I-phase 修（Phase A 飞轮已验证） |
</content>
</invoke>
