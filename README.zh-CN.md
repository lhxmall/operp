[English](README.md) | 简体中文

# OPERP — 乐观 DAG 侧链永续 DEX，结算到 Obyte

OPERP 是一个**永续合约交易所**的研究/MVP 实现：交易在高吞吐的乐观 DAG
侧链上执行，周期性把状态根结算到 [Obyte](https://obyte.org) 账本（通过
autonomous agent 金库）。金库提款受 **Merkle 证明门控**——必须出示针对
已最终化根的余额证明才能取钱。

> **状态：结算 v2 已落地，尚未发主网。** workspace 测试全绿；devnet E2E
> （`test_settlement_aa.js`）覆盖 submit → 谓词揭发 → finalize → 证明提款。
> 主网脚本是 `deploy_mainnet.js`（需助记词）；用户资金前须 AA 审计与独立 watcher。

```
cargo test --workspace          # 测试全绿
cargo run --release -p operp-exec --example bench_raw        # ~5.5k ops/s
cargo run --release -p operp-exec --example hft_onedag -- 20000 8 4   # ~9k TPS, 零拒绝
cd obyte-local && node test_settlement_aa.js  # Linux/CI：三门 AA 生命周期（win32 skip）
cd obyte-local && node deploy_mainnet.js      # 主网发四个 AA（需 OPERP_DEPLOY_MNEMONIC）
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
                    │  OBYTE 结算（Oscript，CHAIN_ID=operp-v2）     │
                    │  rollup  submit/finalize/force/verdict      │
                    │  dispute 一枪谓词（充提/漏单/成交/ghost/skip）│
                    │  vault   只托管：deposit / withdraw         │
                    └─────────────────────────────────────────────┘
```

### Workspace crate 一览

| Crate | 职责 |
|---|---|
| `operp-types` | 常量（单一权威来源）、id（`AccountId = sha256(pubkey)`）、整数定值运算 |
| `operp-book` | 限价订单簿：价格-时间优先、部分成交、IOC/GTC、自成交拦截 |
| `operp-account` | 每账户抵押/仓位、VWAP 入场价、已实现 PnL、风险快照 |
| | `liquidatable`：equity·10000 ≤ mm·10500；`reduce_only`：≤ 12000 |
| `operp-state` | ChainState：账户/簿/mark/提款记录，字节域 Merkle 树（`state_root`）+ 字符串域森林（`aa_root`，供 AA 验证）；重启持久化（快照 + gov-nonce WAL） |
| `operp-dag` | unit DAG、签名严格校验（`verify_strict`）、orphan 缓冲（4096 上限，盐化驱逐）、确定性字典序线性化（`ready_linearized`，已去盐） |
| `operp-exec` | 引擎本体：ingest → apply → 事件流；place/cancel/deposit/withdraw/liquidate 全量入口校验 |
| `operp-settle` | 批次 checkpoint、`validate_against` 重放审计（含独立充值证据验证）、`temp_data` 载荷、提款证明生成 |
| `operp-gossip` | operator 之间 WantUnits/HaveUnits 按需孤儿同步（纯 P2P 层，传输无关，绝不进共识） |
| `operp-watch` | 独立 rollup watcher：重放 `da_unit_<h>`，组谓词 proof.json，经 `post_challenge.js` 打 dispute（与 poster 分钥） |

## 协议设计原理

### 1. 一个 DAG，一个全序

每个用户操作都是引用至多 2 个父单元的签名 **unit**。引擎按 `unit_id`
升序执行 pending 单元——任何副本无需共识流量即可复现的规范确定性全序。
乱序投递可容忍：父母未知的单元进入缓冲（上限 4096，按盐化序
`argmin(sha256(salt ‖ id))` 驱逐——盐由最后最终化根派生并随驱逐 epoch
轮换），同一 id 携带不同 canonical 字节的重试被拒
（`DagError::RetryMismatch`），Deposit/GovDeposit 的地址在任何缓冲之前即
受 128 字符上限约束（`DagError::AddrTooLong`）。缺失单元可通过
WantUnits/HaveUnits gossip 层（`operp-gossip`）按需补齐——它同时服务已
链接单元与缓冲孤儿，不触碰共识。

签名采用 ed25519 **严格校验**（拒绝可延展签名）。每个 op 绑定持有者
密钥：充值/下单/撤单必须由其账户签名；清算必须由 *keeper* 签名
（`Op::Liquidate { caller, .. }`），自我清算因此不可能。

默认排序保持 UnitId 字典序；叠加式 v2 commit-reveal 路径
（`Op::Commit` / `Op::Reveal`，激活门控）启用后允许用户盲序下单规避
MEV——见[局限与主网就绪度](#局限与主网就绪度)。

### 2. 确定性撮合，纯整数运算

订单簿是 `BTreeMap` 价档上的经典价格-时间 CLOB。全部资金运算为整数
定值：

- `Price`、`Qty`：u64，缩放 `1e8`
- `Usd`（抵押/PnL）：i128，缩放 `1e6`
- 名义额 = qty·price / PRICE_SCALE · USD_SCALE / QTY_SCALE

入口防护在一切算术回绕之前拒绝：`qty > i64::MAX` 或 `qty·price` 溢出
i128 → 以 `Risk` 拒绝。每价档增量维护的 `visible_qty` 缓存使最优买卖价
读取保持 O(log depth)。自成交永不成交：taker 遇到自己挂单时 maker 被撤
（`canceled_maker`），撮合以 taker 剩余量继续对下一单进行。

### 3. 风险模型（全仓）

每笔成交同时更新两腿（开仓用 VWAP 入场价）；**平仓瞬间已实现 PnL 即时
结算进 collateral**，赢利者立刻可提利润，提款证明叶子（承诺
`collateral`）反映真实偿付能力。快照计算维持保证金（名义额绝对值 5%）与
初始保证金（10%）。清算由 keeper 发起，从保险基金支付成交名义额 1% 的
keeper 奖励；若清算后账户仍为负，权益精确钳零、缺口记入保险基金——
绝不转嫁对手方。保险基金创世注入（10 000 USD），自身永不被清算、也永不
自我清算。

mark 价格只在名义额 ≥ 100 USD **且相对旧 mark 偏移 ≤ ±10%** 的成交上
移动（无 mark 市场的首个合格成交直接定价）——最小操纵抗性；预言机/资金费
TWAP 环与连续偏移罚没已上线（激活门控），外部锚为可选启用。

### 4. 结算：每批双根

每批（约 512 units / 2 s）产出 `Checkpoint`：

```text
{ height, prev_state_hash, state_root, aa_root, last_unit, seq,
  unit_ids, fills_hash, fill_count }
```

  - `state_root` — 账户叶、簿叶与 meta 叶构成的 Merkle 树。meta 叶提交
  `height`、`seq`、`last_unit`、治理游标、每市场的 `(mark, 资金费 index)`
  及其 TWAP 环、全套预言机状态（债券、解锁队列、最新报价、每记者历史、
  罚没 nonce、每市场配置）、在途提案及其投票快照、镜像 PERP
  余额/流通量/烧毁、pending commit-reveal 承诺、外部价环与白名单、资金源
  选择器——账户树之外的任何共识状态重放都无法分叉。根跨批次成链，重组
  必然断链可见。只有*已应用*单元推进全局 `seq`；被拒操作不消耗序号。
  - `aa_root` — 第二重承诺，十六进制字符串域，打包为 **16 棵分片树组成
  的森林**：账户按地址划入 16 个 shard；shard 内
  `leaf = sha256("acct:" + address + ":" + collateral + ":" + perp + ":" +
  withdrawn)`，`node = sha256(left ‖ right)`；每批把 16 个 shard 根拼接成
  一个恰好 1024 hex 的 `aa_forest` 字符串提交，正好命中 Oscript 的
  `MAX_STATE_VAR_VALUE_LENGTH`。存在原因是 Oscript 的 `sha256()` 对 UTF-8
  文本哈希：金库 AA 在所声明的 shard 内折叠提款证明并用 substring 取出该
  shard 的根——承诺完全相同的余额，包括 `W`（账户累计侧链提款总额，支撑
  AA 侧防重放上限）。空 shard 提交哨兵根
  （`hex(sha256("empty:<shard>"))`），零证明无法跨 shard 跳动。只有绑定
  了 Obyte 地址的账户（经 `Op::Deposit { addr }` / `Op::GovDeposit { addr }`，
  ≤ 128 字符）进入森林；绑定为首见即定、入口强制。
  `Batch::validate_against` 另外把重算的森林对 checkpoint 校验。
- `fills_hash`/`fill_count` — 对执行成交流的承诺。

`Batch::validate_against` 用全新引擎重放披露的单元，校验 chain id、前根、
重算 fills hash/count、终根；并且**独立验证充值证据**：批次内任何
Deposit/GovDeposit 都必须携带证据——对其 Obyte joint 复算哈希
（`get_unit_hash`），确认 joint 实际向预期 vault 地址支付了所报金额的所报
资产（`verify_all`，vault 地址与 PERP asset id 由调用方提供绑定；watcher
经 `evidences_from_payload` 从披露的 `temp_data` 取回证据）。根比对之前，
重放态按与批次应用完全相同的窗口规则剪枝——任何诚实副本都能审计
operator。

### 5. 结算 AA：乐观最终性 + 证明门控出金

三个 AA（`CHAIN_ID=operp-v2`）。**没有 lock，没有付钱否决。** 保证金是 GBYTE。

1. **submit（rollup）** — 组合单元 `temp_data` + `{submit, height, 双根, trace/units/ops/fills 根}`，附 1000 GBYTE 提交债。`h == last_submitted+1`；已占位且未 `frozen=2` → `height taken`。窗从 `submitted_at` 起算 3600 s。
2. **揭发（dispute / dispute_fill）** — 窗内任何人提交一枪谓词（deposit/withdraw/omit/fill_math/ghost/skip）。验不过 bounce `no fraud`，高度不动；验过则 `{verdict:'fraud'}`，rollup 罚没一半提交债、高度重开。无应诉回合。
3. **finalize（rollup）** — `submitted_at+3600` 且未冻结 → `last_finalized=h`，退提交债，竞速奖 20000 bytes。`{escape_finalize}` 为 7 天停滞门。
4. **withdraw（vault）** — 只读 `var[ROLLUP]['aa_forest_'||last_finalized]`，原 16 深 Merkle 折叠与 W 防重放不变。`{escape_withdraw}` 仍弹 `no escape withdraw`。
5. **force（rollup inbox）** — `{force, unit_id}` 抗审查；漏收可 P-omit。

| 门 | 原点 | 时长 |
|---|---|---|
| 揭发 / finalize | `submitted_at_h` | 3600 s |
| escape_finalize | `submitted_at_h` | 604800 s |

无 owner key。升级 = 新 AA + 同一 finalized 提款路径迁资金。


## 仓库布局

```
crates/                  Rust workspace（9 crates，见表）
obyte-local/
  agents/operp_vault.aa          金库（deposit/withdraw）
  agents/operp_rollup.aa         主张链
  agents/operp_dispute.aa        充提/漏单谓词
  agents/operp_dispute_fill.aa   成交谓词
  test_settlement_aa.js          三门 AA E2E（Linux/CI；win32 skip）
  deploy_mainnet.js / issue_perp.js  主网发 AA / 发 PERP
  post_batch.js                  组合 temp_data+submit → finalize → claim
  post_challenge.js              谓词揭发 CLI（`--pred --proof`）
docs/PROTOCOL.md / MECHANISMS.md / ROLLUP-UPGRADE.md
```

## 构建前提

- Rust >= **1.85**（workspace 钉死 `rust-version = "1.85"`；经
  [rustup](https://rustup.rs) 安装：
  `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`）
- Node.js >= 20（`obyte-local` 脚本与 AA devnet E2E 所需）
- Windows 下需 C++ 工具链以编译原生 `rocksdb`/`sqlite3`（vendored
  aa-testkit 依赖）：安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  并勾选 **"Desktop development with C++"** 工作负载，随后在
  `obyte-local` 与 `vendor/aa-testkit` 下 `npm install` 即可；缺失时
  `node-gyp` 报 `find VS` 错误，E2E 无法运行

## 运行

```bash
# 引擎测试（无需网络）
cargo test --workspace

# 单节点吞吐探针
cargo run --release -p operp-exec --example bench_raw
# 单 DAG 多市场压测：<时长ms> <市场数> <生成器线程数>
cargo run --release -p operp-exec --example hft_onedag -- 60000 8 4

# 导出真实批次载荷
cargo run -p operp-settle --example export_batch

# AA 生命周期集成测试（本地 devnet；需 node + C++ 工具链以编译
# vendored aa-testkit 的原生 rocksdb/sqlite3——见「验证状态」）
cd obyte-local && node test_vault_aa.js

# 部署 vault AA 到 Obyte 测试网
cd obyte-local && node deploy_testnet.js

# operator 完整流程：temp_data 全量披露 + submit + lock + finalize + 领奖
cd obyte-local && node post_batch.js
```

实测数据（开发机）：`bench_raw` ≈ 5 500 ops/s；`hft_onedag`（8 市场、
4 生成器线程）聚合 ≈ 9 000–9 200 TPS、零拒绝。

## 局限与主网就绪度

当前代码达到“可部署 Obyte 测试网”标准，**尚未达到主网标准**。已知缺口
（按优先级大致排序）：

1. ~~**付钱即可杀掉诚实根。**~~ **已关闭（结算 v2）。** 揭发必须过 dispute
   谓词；`{challenge:1}` 在 rollup/vault 上没有 case。假证明 bounce `no fraud`。
   仍未关闭：保险钳制链上不验；fill_math ±1 容差；`temp_data` 24h 删正文；
   充值 joint 仍主要在链下 `validate_against`（`OPERP_VAULT_AA` 空且带 evidence 会拒）。
2. **资金费质量受价格锚限制。** 资金费保持 mark-premium 模型（±50 bps/tick
   封顶）。默认 `BondedMedianTwap` index 来自债券报价者价格；外部锚接线已经
   落地（`Op::UpdateExternalPrice`，tag 17，白名单门控，
   `AggregatedExternal` 模式带过期回退 外部 TWAP → 债券中位数 TWAP →
   即时中位数），但只有在治理切换模式且白名单 keeper 持续喂价后才真正生效。
3. **预言机操纵需要债券多数。** 报价无许可、只需 50 000 PERP 债券；
   TWAP 连续偏移罚没已经落地（高度 0 起生效），但合谋的债券多数仍能在两次罚没
   之间偏置中位数 mark；TWAP 只是平滑而非消除。
4. **默认执行序是 UnitId 字典序、可磨队**（插队 MEV）。v2 commit-reveal
   已叠加落地（`Op::Commit`/`Op::Reveal`，tag 18/19，TTL 16 高度、每账户
   8 个存活 commit、`reveal_commit_hash = sha256(op_bytes ‖ salt)`），但与其
   他 v2 路径现已高度 0 生效。费率竞速与确定性
   撮合无论何时都在压缩磨队可榨取的空间。
5. **孤儿驱逐在副本间留下瞬时分叉窗口。** 驱逐盐按 `(finalized_root,
   epoch)` 每 epoch 轮换，但观测到 finalize 的时刻不同的副本在收敛前可能
   驱逐不同的缓冲孤儿；DA 层自愈——`temp_data` 全量重放可确定性重建缺失
   单元，WantUnits gossip 也可点对点索取。（盐刻意不再影响执行序——见 #13。）
6. **烧毁的 PERP 永久滞留 vault AA。** 烧毁只扣减 `perp_supply`，对应代币
   仍托管在 AA 中（永久超额抵押）——审计时须把「AA 持有量 − perp_supply」
   视为累计烧毁额。
7. ~~**在任 operator 免费重启稳定计时器。**~~ **已关闭**：单候选组合单元，
   后续 submit bounce `height taken`。欺诈成立才重开。
8. AA 未做正式安全审计。各 AA 复杂度须 ≤100（fill AA 实测约 21）。探针：
   `node obyte-local/tools/check_aa_complexity.js agents/*.aa`。
9. **重放去重窗口 2048**（`REPLAY_ACTIVATION_HEIGHT = 0`）。窗口外重复操作
   逃过侧链去重；AA 侧 `wd_`/`wp_` 仍封顶。
10. AA 强制 `amount + wd_ <= min(collateral, withdrawn)`，且叶子数字字段
    上限为 15 位十进制（< 2^53）。
11. 单账户分片证明生成必须先注册 PAD 诱饵绑定，否则
    `aa_sharded_proof_for_account` 返回 `None`。
12. 批次 JSON 的 `perp_burned` 是十进制字符串。
13. 当前执行序是确定性字典序；盐只用于孤儿驱逐。盐化执行序将在
    finalize-batch 确定性设计落地后回归。
14. gov nonce WAL 在批次提交（`from_applied`）时持久化；未提交的批次
    不烧毁 nonce。
15. 快照携带格式版本头（当前 v1）；跨版本的快照/日志互不兼容
    （主网前不做迁移）。

近期关闭：存款白名单、溢出防护、市场白名单、严格签名、孤儿恢复
（确定性驱逐 + 缺失父反向索引）、日志按批裁剪、已实现 PnL 即时结算进
抵押（盈利可提）、债券注册制中位数报价与偏差帽、多空互付资金费
（抵押感知钳幅）、多 operator 费率竞速加固与可转让提交债券（移除安慰
奖）、respond 身份门、Final 状态提升、链上批次数据发布、非队首撤单深度
正确性**与 deque 幽灵清理**、maker 队列弹出回归、提款证明与诊断 `bal_`
账本解耦、height 绑定 `state_root`（meta 叶提交批次高度/mark/资金费
index）、全簿承诺、全局累计提款防重放（`W` 进入每个 aa 树叶）、claim
取回债券（frozen 高度门控）、有界提款/AA 单元/gov-nonce 账本（256 高度
重放窗口）、反手单初始保证金门、create-market bps 上限、tick-size 强制、
仅应用态 `seq` 计账、自成交 cancel-maker 续拍、taker 与 maker 双侧坏账
钳入保险基金、提案清理与创建时投票权重快照、充值绑定 Obyte 地址
（`addr` 字段、首见即定）、资产类别绑定充值背书、`MAX_AA_TREE_DEPTH`
证明上限、AA 侧 claim-reward 清零、单一在途挑战债券、`frozen == 2` 高度
恢复——以及 PERP 治理：侧链镜像 PERP 充值/提款（两棵 Merkle 叶均含
perp 字段）、烧毁上架费的无许可市场上架（每市场风险参数）、链上参数提案
投票（quorum 快照 + 快照权重投票）。

本轮关闭了剩余审计发现与路线图缺口：`validate_against` 剪枝对齐
（withdrawals / seen-AA-units / deposits_allowed 与 `from_applied` 完全一致
地剪枝）、`validate_against` 内独立充值证据验证、epoch 盐化孤儿驱逐
（salt = `sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`；执行序已去盐为
确定性字典序——局限 #13）、先乘后除的
PnL 定标、`RetryMismatch`/`AddrTooLong` DAG 防护、meta 叶对全部共识映射的
承诺扩展（`state_root` 格式破坏性变更）、canonical `data_hash`/`data_length`
经 ocore `getJsonSource` 在 Rust/JS 两侧统一、充值证据携带完整 joint 单元、
`PERP_ASSET_ID` 未设置的 fail-fast、lock 债券门（`active_bond_` 在位）、
分片 aa 森林、`escape_finalize`/`escape_withdraw`、commit-reveal v2、
WantUnits gossip、资金费外部锚接线。

审计后追加：恢复 `{deposit_perp}` 入账（vault 保留 PERP 并镜像记入
`pperp_<addr>`；已证明叶子仍是唯一提款权威），并通过缓存 ed25519 密钥
展开 + release LTO 把裸引擎吞吐从 5199 提到 7316 ops/s。

## 主网路线图（已实现）

[`docs/mainnet/`](docs/mainnet/) 的十一个设计全部实现（按 v1 保守版 +
v2 扩展分期；偏差与延期积压见下）：

- [x] **01 欺诈罚没** — `01-fraud-slashing.md`：50%/50% 烧毁/奖励劈分 +
  `validity_proof_hash` 插槽，Oscript 不做撮合重执行 *（AA 失败 finalize 把
  提交债券劈成 `slash_reward_` + 烧毁半）*
- [x] **02 充值独立验证** — `temp_data.deposit_evidences` 携带完整 Obyte
  joint 单元；`unit_hash(joint)` 在 `validate_against` 内经
  `operp_settle::obyte_hash::get_unit_hash` 复算；收款人/资产以调用方提供的
  `expected_vault`/`perp_asset` 绑定核对，失败映射
  `SettleError::DepositEvidence`；watcher 经 `evidences_from_payload` 取回
- [x] **03 commit-reveal 排序** — v1 盐化排序早前已发、**本轮去盐**（执行序
  为确定性字典序，盐仅用于孤儿驱逐——局限 #13）；**v2 叠加落地**：
  `Op::Commit`（tag 18）/ `Op::Reveal`（tag 19），TTL
  `COMMIT_TTL_HEIGHTS = 16`、每账户 ≤ 8 个存活 commit、
  `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`，高度 0 起生效
- [x] **04 盐化孤儿驱逐 + WantUnits gossip** — `argmin sha256(salt‖unit_id)`，
  `Engine::note_finalized` 每 epoch 轮换盐
  （`sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`）；**gossip 本轮落地**：
  新 `crates/operp-gossip`（WantUnits/HaveUnits、去抖扇出、请求/响应限额），
  纯 operator/P2P 层——传输载体按 doc OQ5 接线
- [x] **05 预言机罚没 + TWAP** — 50k PERP 质押/解锁（256 高度排队）/罚没、
  TWAP 环、500 bps ×3 连续采样双条件、`SlashOracle` tag 16、高度 0 起生效
- [x] **06 资金费外部锚** — 资金 index 抽象 + 激活高度 0（创世即生效）；**本轮 operator
  接线落地**：`Op::UpdateExternalPrice`（tag 17）、来源白名单、
  `AggregatedExternal` 模式、过期回退 外部 TWAP → 债券中位数 TWAP →
  即时中位数（`FUNDING_EXTERNAL_MAX_STALENESS = 32`）
- [x] **07 逃生舱** — **本轮落地**，为预算并入既有分支：`{escape_finalize: 1}`
  搭载 finalize 分支（任意调用者，`ESCAPE_STALL_SECS = 604800` 主网 /
  3600 testnet)；`{escape_withdraw}` 已移除（弹回 `no escape withdraw`）；偏差（doc07 §4 豁免）：escape_finalize
  只做本地停滞门
  只做本地停滞门
- [x] **08 烧毁记账（Rust + checkpoint）** — `meta_leaf` 中 `perp_burned`，
  经 `Checkpoint.perp_burned` / `temp_data` 披露；AA 侧镜像变量为预算删除，
  `holdings−supply==burned` 保持 watcher 可验证
- [x] **09 复杂度审计** — 单 sha256 折叠、统一 claim 分发（`claim:'kind'`）、
  lock-merge 重构；探针：`node tools/check_aa_complexity.js`。当前 **76/100**
  （ops 976/2000）——≤85 门以内
- [x] **10 AA 树分片（v2）** — 本轮干净切换：单个 1024-hex `aa_forest` 变量 =
  16 个拼接的 shard 根（恰好命中 `MAX_STATE_VAR_VALUE_LENGTH`）、空 shard
  哨兵根、深度保持 16 → 每批约 100 万账户；doc 的 v1 depth-18 路径按其
  OpenQ3 被取代
- [x] **11 重放持久化（v1）** — `256→2048` 常量 + 泛化剪枝；`GovNonceJournal`
  WAL——批次提交（`Batch::from_applied`）时落盘、重启 max-merge——外加带
  版本头的 bincode 快照 `chainstate.<height>.snap`
  （`Engine::load_or_genesis` / `flush_snapshot` / `maybe_flush_snapshot`，
  每 64 高度）。RocksDB（`persist-rocksdb`）保持文档声明的 v1.1 积压

**已知偏差 / 延期积压：**

- **重放窗口 2048** 已从高度 0 生效（`REPLAY_ACTIVATION_HEIGHT = 0`）。
- **结算 v2**：无 lock / 无付钱挑战；谓词揭发；claim 在 rollup（`reward|sbond|slash`）。
- **单 shard 深度 16**；提案表并发上限 64。

见 [`docs/mainnet/`](docs/mainnet/)（历史 11 篇）与 [ROLLUP-UPGRADE.md](docs/ROLLUP-UPGRADE.md)。
验证：`cargo test --workspace`、`check_aa_complexity.js`、`node test_settlement_aa.js`（Linux/CI）。

## 验证状态

- **Rust / js-checks / e2e**：CI 跑 workspace 测试、四份 AA 复杂度、golden vector、`test_settlement_aa.js`（win32 skip）。
- **Watcher：** `operp-watch` 组 `proof.json` 打 dispute（`--pred --proof`，需 `OPERP_WATCH_MNEMONIC` 与 `--vault/--rollup`）。未设助记词仅报警。须与 poster 分钥。

## 许可证

MIT
