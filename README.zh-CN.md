[English](README.md) | 简体中文

# OPERP — 乐观 DAG 侧链永续 DEX，结算到 Obyte

OPERP 是一个**永续合约交易所**的研究/MVP 实现：交易在高吞吐的乐观 DAG
侧链上执行，周期性把状态根结算到 [Obyte](https://obyte.org) 账本（通过
autonomous agent 金库）。金库提款受 **Merkle 证明门控**——必须出示针对
已最终化根的余额证明才能取钱。

> **状态：测试网就绪 MVP。** workspace 测试全绿；AA 全生命周期
> （deposit → submit → lock → challenge → finalize → proof 提款）已在
> aa-testkit devnet 上端到端验证。主网部署需先补齐
> [局限与主网就绪度](#局限与主网就绪度)所列缺口。

```
cargo test --workspace          # 测试全绿
cargo run --release -p operp-exec --example bench_raw        # ~5.5k ops/s
cargo run --release -p operp-exec --example hft_onedag -- 20000 8 4   # ~9k TPS, 零拒绝
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
                    │  submit   → 单候选（首个稳定组合单元胜出；da_unit 钉死；height taken；frozen==1 应诉）│
                    │  lock     → 600s 稳定窗后锁定（钟只设一次）               │
                    │  challenge → 仅已 lock 高度可冻（stable_at+3600；bond ≥ 20000）│
                    │  resubmit → 原 bond 持有人应诉（解冻；不改 da_unit/钟/不另收 50k）│
                    │  finalize → 根成为提款依据                  │
                    │  withdraw → 针对 aa_root 的 Merkle 证明     │
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
| `operp-watch` | 独立 vault-AA watcher：读 `da_unit_<h>`、重放批次、用自己的密钥挑战根不匹配（与 poster 分离） |

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

### 5. 金库 AA：乐观最终性 + 证明门控出金

每个高度 *h* 的生命周期：

1. **submit** — operator 发布**一笔组合单元**：OIP-0007 `temp_data` 加
   `{height: h, prev_state_hash, state_root, aa_root}` data 消息，附 ≥ 60 000
   bytes：10 000 bounce 余量加 **50 000-byte `SUBMIT_BOND_NET`**。高度必须
   等于 `last_locked + 1`（frozen==1 应诉例外见下）；前根必须匹配；三个哈希
   字段各恰 64 hex，`aa_forest` 恰 1024 hex。高度**单候选**：首个稳定组合
   单元胜出，AA 记下 `da_unit_<h>` = 该 unit hash（根钉死在这份数据包上）；
   此后该高度任何 submit 一律 bounce `height taken`，直到 finalize 或失败。
   600 s 稳定钟由胜出 submit 设一次，不可重置。
2. **lock** — 仅在 600 s 稳定窗（`OBYTE_STABILITY_SECS`）之后、且候选的
   提交债券持有人记录（`active_bond_<h>`）在位时允许：失败 finalize 会
   没收并清零该记录，故被回滚的高度在新的带债券 submit 重建候选之前无法
   re-lock。锁定会清除此前的永久失败标记，挑战失败（`frozen = 2`）的高度
   靠重新提交恢复而不是卡死链条。锁定后的根不可变。`stable_at_<h>` 在
   lock 时写入，是挑战窗、应诉窗、finalize/失败扫荡窗的**同一原点**
   （一律 `stable_at+3600`）。
3. **challenge** — `stable_at_<h>` 起 3600 s 内（post-lock；`CHALLENGE_SECS`
   从 `stable_at` 起算），任何人可以 ≥ 20 000 byte 债券冻结**已锁定**高度
   *h*（`h ≤ last_locked`，`stable_at_<h>` 已在）；未 lock 的
   `last_locked+1` 不可被挑战——走正常 `submit/lock`，无法预 freeze。有在途
   债券者不可开第二枪，被挑战高度仍冻结时 `{claim: "bond"}` 拒绝支付。
4. **respond（重发应诉）** — 无独立 respond 触发器：原 bond 持有人在
   `stable_at+3600` 内重发**同一份 `state_root` + `aa_forest`**（单候选门
   唯一放行的重提交；不创建新 `da_unit_<h>`、不重置 600 s / escape 钟、
   **不另收 50k**——只需 10000 bounce 余量）。成功则解冻并没收记录在案的
   挑战者债券（两个账本键清零）；冒充者或森林不一致 bounce `not operator`。
   无人应诉超窗后，finalize 将高度标记永久失败（`frozen = 2`）、清根、
   `last_locked` 回滚到 h−1、没收提交债券——**50/50 劈半**：一半计入
   挑战者的 `{claim: "slash"}`，一半留在金库烧毁；失败扫荡清掉
   `active_bond_<h>` 以便新组合单元重新占位；挑战者另经 `{claim: "bond"}`
   取回自己的债券。
5. **finalize** — 干净度过 `stable_at+3600` 窗口后根成为提款依据
   （`last_finalized`），严格按高度顺序；提交债券释放给持有人，首个稳定
   提交者累积 20 000-byte 竞速奖励（`{claim: "reward"}` 一次性支付并清零
   账本）。
   - 提款携带 `{amount, withdrawn, leaf_account, collateral, perp, shard,
     proof[], perp_amount?}`；
   - `perp_amount`（可选）声明少于全部未领 PERP 余额——纯抵押退出不再
     强行清空已证明的 PERP；缺省仍是全额余额；
   - `shard`（0..15）选择证明必须折入的 shard 根；AA 从 1024-hex 森林中
     经 `substring(shard*64, 64)` 取出，且只信任叶子前像——错报 shard 会
     折到错误的根上；
   - AA 重算
     `sha256("acct:"‖address‖":"‖collateral‖":"‖perp‖":"‖withdrawn)` 并
     折叠兄弟路径，要求结果等于 `var['aa_root_' ‖ last_finalized]` 中所
     声明 shard 的根；
   - `leaf_account == trigger.address`（只能证明自己的地址）；
   - 兄弟路径以定深 `reduce(..., 16, ...)` 折叠，单证明覆盖一棵最多
     2^16 账户的 shard 树（16 shard ≈ 每批承诺约 100 万账户）；空 shard
     哨兵根阻止零证明跳 shard。
   - 提款**以证明的 W 防重放**：全局累计标记 `wd_<addr>` / `wp_<addr>`
     把历史累计抵押/PERP 提款（跨所有高度）封顶在叶子承诺的 `W` /
     `perp` 余额——任何高度的重放都 bounce。
   余额权威是**证明叶子**，不是可变 AA 变量。
6. **逃生舱** — 若 finalization 彻底停摆（operator 全部消失），
   `{escape_finalize: 1}` 在 `ESCAPE_STALL_SECS` 后（主网 7 天、devnet
   timetravel；任意调用者；绝不越过 live challenge——frozen 高度必须走
   正常失败清扫以退还挑战者）停滞最终化最老的锁定高度；
   `{escape_withdraw: 1, ...claim 字段}` 在 `h = last_finalized + 1` 从未
   锁定或已被 `frozen = 2` 回滚时，针对**陈旧候选**的森林支付证明。两条
   入口共享 withdraw 路径的 `wd_`/`wp_` 防重放键。按 doc07 §4 豁免，
   escape_finalize 只做本地停滞门。

时钟原点——3600 s 窗口只有**一个**原点（`stable_at`），从不看 `submitted_at`：

| 门 | 原点 | 时长 |
|---|---|---|
| lock | `submitted_at_<h>` | 600 s（`OBYTE_STABILITY_SECS`） |
| challenge / respond / finalize / 失败扫荡 | `stable_at_<h>` | 3600 s（`CHALLENGE_SECS`） |
| escape_finalize | `stable_at_<h>` | 604800 s（`ESCAPE_STALL_SECS`） |
| escape_withdraw（候选停滞） | `submitted_at_<h>` | 604800 s |
| escape_withdraw（链条停滞） | `stable_at_<last_finalized>` | 604800 s |

证明由 `crates/operp-settle/examples/gen_withdraw_proof.rs` 离线生成
（JSON 供 JS 工具链消费）。

刻意**没有 owner key**：升级意味着部署新 AA 并经由同样的 finalized-root
提款路径迁移资金。AA 中全部协议常量都标注了 Rust 对应物
（`CHAIN_ID`、`OBYTE_STABILITY_SECS`、`CHALLENGE_SECS`……），Rust 是
单一权威来源。

## 仓库布局

```
crates/                  Rust workspace（9 crates，见表）
obyte-local/
  agents/operp_vault.aa   金库 autonomous agent（安全加固）
  test_vault_aa.js       完整生命周期集成测试（devnet via aa-testkit）
  deploy_testnet.js      测试网部署脚本（+ 冒烟充值）
  post_batch.js          operator 提交流程（一笔组合 temp_data+submit
                         单元、lock、finalize、claim）。提交前自检
                         （data_hash/aa_shard_roots/chain_id）只是自检，
                         不是独立 watcher——互相牵制需要单独的
                         `crates/operp-watch` 二进制与自己的密钥。
  gen_withdraw_proof     见 crates/operp-settle/examples
vendor/aa-testkit/       Obyte autonomous-agent testkit（vendored）
docs/PROTOCOL.md         协议设计叙事
  docs/MECHANISMS.md     完整机制参考（中文）：每条规则、常量、边界情况
                         与威胁模型矩阵
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

1. **欺诈响应是冻结-回滚，不是链上重执行。** 全部交易数据会上链
   （`post_batch.js` 以 `temp_data` 披露每个 unit，任何 watcher 都能本地
   重放并检出坏根），检出的欺诈触发 challenge → freeze → 高度回滚，并伴随
   50/50 提交债券罚没（一半计 `{claim: "slash"}`、一半烧毁）。充值背书现在
   在 `validate_against` 内做密码学独立验证，不再听信 operator 自述。
   仍然做不到的：Oscript 无法链上重跑撮合器、也没有有效性证明，所以非
   充值状态的执法仍依赖 live watcher 加竞争 operator。
2. **资金费质量受价格锚限制。** 资金费保持 mark-premium 模型（±50 bps/tick
   封顶）。默认 `BondedMedianTwap` index 来自债券报价者价格；外部锚接线已经
   落地（`Op::UpdateExternalPrice`，tag 17，白名单门控，
   `AggregatedExternal` 模式带过期回退 外部 TWAP → 债券中位数 TWAP →
   即时中位数），但只有在治理切换模式且白名单 keeper 持续喂价后才真正生效。
3. **预言机操纵需要债券多数。** 报价无许可、只需 50 000 PERP 债券；
   TWAP 连续偏移罚没已经落地（激活门控），但合谋的债券多数仍能在两次罚没
   之间偏置中位数 mark；TWAP 只是平滑而非消除。
4. **默认执行序是 UnitId 字典序、可磨队**（插队 MEV）。v2 commit-reveal
   已叠加落地（`Op::Commit`/`Op::Reveal`，tag 18/19，TTL 16 高度、每账户
   8 个存活 commit、`reveal_commit_hash = sha256(op_bytes ‖ salt)`），但与其
   他 v2 路径一样激活门控——激活高度翻转之前排序不变。费率竞速与确定性
   撮合无论何时都在压缩磨队可榨取的空间。
5. **孤儿驱逐在副本间留下瞬时分叉窗口。** 驱逐盐按 `(finalized_root,
   epoch)` 每 epoch 轮换，但观测到 finalize 的时刻不同的副本在收敛前可能
   驱逐不同的缓冲孤儿；DA 层自愈——`temp_data` 全量重放可确定性重建缺失
   单元，WantUnits gossip 也可点对点索取。（盐刻意不再影响执行序——见 #13。）
6. **烧毁的 PERP 永久滞留 vault AA。** 烧毁只扣减 `perp_supply`，对应代币
   仍托管在 AA 中（永久超额抵押）——审计时须把「AA 持有量 − perp_supply」
   视为累计烧毁额。
7. ~~**在任 operator 免费重启稳定计时器。**~~
   **已关闭**（组合 da_unit）：submit 单候选——首个稳定的组合
   `temp_data`+submit 单元赢得高度，AA 把 `da_unit_<h>` 钉在其上，其余
   submit 一律 bounce `height taken`（仅 frozen==1 时原 bond 持有人的
   应诉重提交能过，且不碰钟）。不存在在任者免费清钟。
8. AA 未做正式安全审计。Oscript 复杂度门恰在其上限（**85/100**，ops
   1101/2000——运行 `node tools/check_aa_complexity.js`），后续任何改动
   都必须先腾出等额预算。
9. **重放去重窗口按高度有界**——旧版 256 高度，`state.height ≥
   REPLAY_ACTIVATION_HEIGHT`（1 000 000；部署期翻转）后扩展为
   `REPLAY_WINDOW = 2048`。窗口外的重复操作逃过侧链去重（AA 侧全局
   `wd_`/`wp_` 封顶仍然有效）。gov nonce 另用严格水位线，在批次提交时
   落盘（见 #14），乱序低 nonce 永久拒绝——包括跨重启。
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
  `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`，1 000 000 激活门控
- [x] **04 盐化孤儿驱逐 + WantUnits gossip** — `argmin sha256(salt‖unit_id)`，
  `Engine::note_finalized` 每 epoch 轮换盐
  （`sha256(ORDERING_SALT_DOMAIN ‖ root ‖ epoch_le)`）；**gossip 本轮落地**：
  新 `crates/operp-gossip`（WantUnits/HaveUnits、去抖扇出、请求/响应限额），
  纯 operator/P2P 层——传输载体按 doc OQ5 接线
- [x] **05 预言机罚没 + TWAP** — 50k PERP 质押/解锁（256 高度排队）/罚没、
  TWAP 环、500 bps ×3 连续采样双条件、`SlashOracle` tag 16、激活门控
- [x] **06 资金费外部锚** — 资金 index 抽象 + 激活门早前已发；**本轮 operator
  接线落地**：`Op::UpdateExternalPrice`（tag 17）、来源白名单、
  `AggregatedExternal` 模式、过期回退 外部 TWAP → 债券中位数 TWAP →
  即时中位数（`FUNDING_EXTERNAL_MAX_STALENESS = 32`）
- [x] **07 逃生舱** — **本轮落地**，为预算并入既有分支：`{escape_finalize: 1}`
  搭载 finalize 分支（任意调用者，`ESCAPE_STALL_SECS = 604800` 主网 /
  3600 testnet），`{escape_withdraw: 1}` 搭载 withdraw 针对
  `last_finalized + 1` 的陈旧候选森林；偏差（doc07 §4 豁免）：escape_finalize
  只做本地停滞门
- [x] **08 烧毁记账（Rust + checkpoint）** — `meta_leaf` 中 `perp_burned`，
  经 `Checkpoint.perp_burned` / `temp_data` 披露；AA 侧镜像变量为预算删除，
  `holdings−supply==burned` 保持 watcher 可验证
- [x] **09 复杂度审计** — 单 sha256 折叠、统一 claim 分发（`claim:'kind'`）、
  lock-merge 重构；探针：`node tools/check_aa_complexity.js`。当前 **85/100**
  （ops 1101/2000）——恰在门槛
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

- **重放窗口 256→2048**：已实现但激活门控（`REPLAY_WINDOW`、
  `REPLAY_ACTIVATION_HEIGHT` 定在 1 000 000），现有测试保持旧版确定性。
  部署时翻转常量。
- **逃生舱**：已落地（见 07）。respond 路径保持*重发应诉*——operator 重发
  同一根应诉；冒充者在 submit init bounce `not operator`。
- **Claim API 破坏性变更**：`{claim_reward|claim_bond|claim_submit_bond}`
  布尔字段替换为单一 `{claim: "reward"|"bond"|"sbond"|"slash"}`；
  `post_batch.js` / `test_vault_aa.js` 已同步迁移。
- **单 shard 深度保持 16**：分片 v2 在每 shard 深度 16 下交付每批约 100 万
  账户；原计划的全局 16→18 提升保持被取代。
- **提案表并发上限 64**（`create_proposal` → `Risk`），封堵无界状态 DoS。

见 [`docs/mainnet/README.md`](docs/mainnet/README.md) 的 11 篇文档索引。
以上每一项的验证门：`cargo test --workspace`、
`cd obyte-local && node tools/check_aa_complexity.js`（≤85）、
`node test_vault_aa.js`，以及
`cargo run --release -p operp-exec --example bench_raw`。

## 验证状态

- **Rust 套件（CI 覆盖）**：`.github/workflows/ci.yml` 在 push/PR 上运行
  `cargo test --workspace`（stable 工具链；MSRV 钉在 1.85）。覆盖 gossip
  上限、journal CRC + 物理截断、快照版本/回退、canonical-number 哈希规则、
  批次提交式 gov-nonce WAL（含 H2 回归）。
- **AA 复杂度门（CI `js-checks`）**：`node obyte-local/tools/check_aa_complexity.js`
  ——当前 **85/100**（ops 1101/2000），恰在 ≤85 CI 门上。同 job 还跑
  `golden_vector_check.js`。
- **Golden vector（CI `js-checks`）**：`node obyte-local/golden_vector_check.js`
  打印固定输入（含 >2^53 的 `big` 字符串与 `eps: 0.001`）的 canonical
  Obyte JSON source 与 data_hash；Rust 侧单元测试
  `golden_vector_matches_ocore_get_json_source` 钉住同一哈希
  （`4efa7a37…`），每次 CI 都验证 JS/Rust `get_data_hash` 一致。
- **AA devnet E2E（CI `e2e` job）**：每次 `main` push **以及**每个
  pull request 都会跑。无 Visual Studio Build Tools 的 Windows 开发机
  仍编不过 vendored aa-testkit 的 `rocksdb`/`sqlite3`；完整生命周期以 CI
  为准，不在本机证明。
- **Watcher 局限：** 独立 watcher crate（`crates/operp-watch`）已存在、可
  离线重放 `da_unit_<h>`，但尚未以独立于 poster 的密钥部署——互相牵制
  跑通前不对外宣称已具备。

提交历史记录了本仓库经历的完整安全审计整改（proof 门控出金、存款白名单、
溢出防护、市场白名单、严格签名、孤儿恢复、有界日志、keeper 奖励、坏账
社会化）。

## 许可证

MIT
