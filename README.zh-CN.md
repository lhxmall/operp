[English](README.md) | 简体中文

# ODEX — 乐观 DAG 侧链永续 DEX，结算到 Obyte

ODEX 是一个**永续合约交易所**的研究/MVP 实现：交易在高吞吐的乐观 DAG
侧链上执行，周期性把状态根结算到 [Obyte](https://obyte.org) 账本（通过
autonomous agent 金库）。金库提款受 **Merkle 证明门控**——必须出示针对
已最终化根的余额证明才能取钱。

> **状态：测试网就绪 MVP。** workspace 30 个测试全绿；AA 全生命周期
> （deposit → submit → lock → challenge → finalize → proof 提款）已在
> aa-testkit devnet 上端到端验证。主网部署需先补齐
> [局限与主网就绪度](#局限与主网就绪度)所列缺口。

```
cargo test --workspace          # 30 个测试全绿
cargo run --release -p odex-exec --example bench_raw        # ~5.5k ops/s
cargo run --release -p odex-exec --example hft_onedag -- 20000 8 4   # ~9k TPS, 零拒绝
cd obyte-local && node test_vault_aa.js    # devnet 上完整 AA 生命周期
cd obyte-local && node deploy_testnet.js   # 把 vault AA 部署到 Obyte 测试网
```

## 架构

```
                    ┌─────────────────────────────────────────────┐
 用户（ed25519）    │            侧链（Rust）                      │
 ──── Place ───────►│  DAG（unit，最多 2 个父单元）                │
 ──── Cancel ──────►│   └─ 确定性字典序执行                        │
 ──── Deposit ─────►│       ├─ CLOB 订单簿（价格-时间优先 FIFO）   │
 ──── Withdraw ────►│       ├─ 全仓 + IM/MM 风险引擎               │
 ──── Liquidate ───►│       └─ 保险基金 + keeper 清算奖励          │
                    │  每个批次产出：                              │
                    │   checkpoint = {height, prev_state_hash,    │
                    │                 state_root, aa_root, ...}   │
                    └────────────────┬────────────────────────────┘
                                     │ temp_data 单元（批次数据上链）
                                     ▼
                    ┌─────────────────────────────────────────────┐
                    │         OBYTE VAULT AA（Oscript）           │
                    │  submit   → 候选根（lock 前可替换）          │
                    │  lock     → 600s 稳定窗后锁定               │
                    │  challenge → 冻结（bond ≥ 20000 bytes）     │
                    │  respond  → operator 应诉，没收挑战者 bond  │
                    │  finalize → 根成为提款依据                  │
                    │  withdraw → 针对 aa_root 的 Merkle 证明     │
                    └─────────────────────────────────────────────┘
```

### Workspace crate 一览

| Crate | 职责 |
|---|---|
| `odex-types` | 常量（单一权威来源）、id（`AccountId = sha256(pubkey)`）、整数定值运算 |
| `odex-book` | 限价订单簿：价格-时间优先、部分成交、IOC/GTC、自成交拦截 |
| `odex-account` | 每账户抵押/仓位、VWAP 入场价、已实现 PnL、风险快照 |
| | `liquidatable`：equity·10000 ≤ mm·10500；`reduce_only`：≤ 12000 |
| `odex-state` | ChainState：账户/簿/mark/提款记录，字节域 Merkle 树（`state_root`）+ 字符串域树（`aa_root`，供 AA 验证） |
| `odex-dag` | unit DAG、签名严格校验（`verify_strict`）、orphan 缓冲（4096 FIFO）、按 unit id 确定性线性化 |
| `odex-exec` | 引擎本体：ingest → apply → 事件流；place/cancel/deposit/withdraw/liquidate 全量入口校验 |
| `odex-settle` | 批次 checkpoint、`validate_against` 重放审计、`temp_data` 载荷、提款证明生成 |

协议设计原理详见 [docs/PROTOCOL.md](docs/PROTOCOL.md)（中文深入篇：
确定性全序、双 Merkle 根、AA 状态机、威胁模型）。

## 快速上手

```bash
# 引擎测试（无需网络）
cargo test --workspace

# 单节点吞吐探针
cargo run --release -p odex-exec --example bench_raw
# 单 DAG 多市场压测：<时长ms> <市场数> <生成器线程数>
cargo run --release -p odex-exec --example hft_onedag -- 60000 8 4

# 导出真实批次载荷
cargo run -p odex-settle --example export_batch

# AA 生命周期集成测试（本地 devnet，使用 vendored aa-testkit）
cd obyte-local && node test_vault_aa.js

# 部署 vault AA 到 Obyte 测试网
cd obyte-local && node deploy_testnet.js
```

实测数据（开发机）：`bench_raw` ≈ 5 500 ops/s；
`hft_onedag`（8 市场、4 生成器线程）聚合 ≈ 9 000–9 200 TPS、零拒绝。

## 安全审计修复一览

本仓库经过一轮完整安全/治理审计并修复（见提交历史）：

- **proof 门控出金**：AA 提款只认最终化 `aa_root` 的 Merkle 证明，
  余额权威是证明叶子而非可变内部账本
- **存款绑定链上事件**：`deposits_allowed` 白名单 + replay 交叉注入，
  杜绝存款凭空铸造
- **溢出防护**：qty/名义额入口 checked-mul，杜绝算术回绕 DoS
- **自我清算禁止**：Liquidate op 内含 `caller` 且验签绑定 keeper
- **keeper 奖励 + 坏账封顶**：清算奖励 1% 名义额由保险基金支付；
  破产缺口社会化进保险基金，不转嫁对手方
- **市场白名单 / DuplicateNonce 分类 / verify_strict 签名 /
  orphan 缓冲 / 日志按批裁剪 / level 缓存**

## 局限与主网就绪度

当前代码达到"可部署 Obyte 测试网"标准，**尚未达到主网标准**。已知缺口
（按优先级）：

1. **欺诈证明尚不完整。** `respond` 只校验 operator 重发已承诺根——恶意
   operator 重发自己的假根即可通过挑战。真正的争议解决需要争议批次的
   链上重放或有效性证明式承诺。
2. **无费用/资金费率模型。** keeper 激励来自有限保险种子金；耗尽后坏账
   无资金来源。
3. **无 TWAP/多源预言机。** mark 来自近期成交（有 100 USD 名义额下限），
   大额自成交仍可偏置 mark。
4. **单一 operator** 提交批次 = 中心化排序者。
5. `respond` 无身份门槛（任何人都可替 operator 应诉）；失败高度资金暂无
   恢复路径。
6. AA 未做正式安全审计；Oscript 复杂度预算迫使逻辑拆散为多个辅助函数。

## 许可证

MIT
