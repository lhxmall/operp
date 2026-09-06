# OPERP 机制详解（Mechanism Reference）

本文是 OPERP 所有运行机制的完整参考，面向需要理解或复现每一层内部行为
的读者。概览见 [README](../README.md)；设计动机叙事版见
[PROTOCOL.md](PROTOCOL.md)。本文按"机制 → 精确规则 → 边界情况"逐层展开，
所有数字均可在 `crates/operp-types/src/lib.rs` 找到对应常量。

---

## 目录

1. [账本与定值体系](#1-账本与定值体系)
2. [DAG 与单元](#2-dag-与单元)
3. [订单簿撮合](#3-订单簿撮合)
4. [账户与风险引擎](#4-账户与风险引擎)
5. [清算、keeper 与保险基金](#5-清算keeper-与保险基金)
6. [手续费与资金费率](#6-手续费与资金费率)
7. [预言机与 mark 价格](#7-预言机与-mark-价格)
8. [批次与结算验证](#8-批次与结算验证)
9. [双 Merkle 树](#9-double-merkle-树)
10. [结算 AA 状态机](#10-结算-aa-状态机chain_idoperp-v2)
11. [Witness 树与谓词承诺](#11-witness-树与谓词承诺)
12. [多 operator 手续费竞速](#12-multi-operator-手续费竞速)
13. [Optimistic / Final 状态提升](#13-optimistic--final-状态提升)
14. [威胁模型对照表](#14-威胁模型对照表)
15. [明确的已知边界](#15-明确的已知边界)
16. [PERP 治理](#16-perp-治理)

---

## 1. 账本与定值体系

### 1.1 三种数量纲

| 类型 | 底层 | 缩放 | 例子 |
|---|---|---|---|
| `Price` | u64 | 1e8 | BTC 价格 $100,000 = `10_000_000_000_000` |
| `Qty` | u64 | 1e8 | 1 BTC = `100_000_000` |
| `Usd` | i128 | 1e6 | $1 = `1_000_000`（微美元） |

全程整数运算，无浮点。名义额：

```
notional_usd(qty, price) =
    i128(qty) × i128(price) / PRICE_SCALE × USD_SCALE / QTY_SCALE
```

例：1 BTC @ $100,000 → `1e8 × 1e13 / 1e8 × 1e6 / 1e8 = 1e11`（= $100,000）。

### 1.2 标识符推导

| 标识 | 推导 |
|---|---|
| `AccountId` | `sha256(ed25519 公钥)`，32 字节 |
| `OrderId` | `sha256(account32 ‖ market_u32le ‖ client_seq_u64le)` |
| `UnitId` | `sha256(canonical_bytes)`，canonical 前缀为 ASCII `"ODX1"` |
| 清算单 id | `sha256(b"liq" ‖ unit_id_32)` |

### 1.3 入口溢出防护（DoS 防线）

place() 在任何算术前拒绝：

```
qty > i64::MAX                    → Risk（仓位以 i64 存储）
price·qty 溢出 i128               → Risk（名义额计算前置校验）
market 不存在或已 delisted       → Risk（无许可市场，见 §16）
client_seq ≠ last+1               → DuplicateClientSeq
```

### 1.4 client_seq 连续性

每账户的 Place 携带严格递增 client_seq（首笔必须 = 1）。作用：订单幂等
（重复 seq 被拒）、重放安全（无法重发历史订单）、缺口检测（跳号即丢单）。
client_seq 是账户级全局计数（跨市场），非每市场独立。

---

## 2. DAG 与单元

### 2.1 单元结构

```rust
Unit {
    parents: Vec<UnitId>,   // 1..=2 个，升序、去重
    op: Op,                 // 业务操作
    pubkey: [u8; 32],       // ed25519 公钥
    sig: [u8; 64],          // 对 UnitId 的签名
}
```

操作类型与 canonical 编码 tag：

| op | tag | 字段序 |
|---|---|---|
| Place | 1 | account, market_le4, side_u8, typ_u8, tif_u8, price_le8, qty_le8, client_seq_le8 |
| Cancel | 2 | account, order_id |
| Deposit | 3 | account, amount_le16, aa_unit_32 |
| Withdraw | 4 | account, amount_le16, nonce_le8 |
| ReportPrice | 6 | oracle, market_le4, price_le8 |
| Liquidate | 7 | caller, target, market_le4 |
| GovDeposit | 8 | account, amount_le16, aa_unit_32 |
| GovWithdraw | 9 | account, amount_le16, nonce_le8 |
| CreateMarket | 10 | creator, symbol16, tick_size_le8, im_bps_le8, mm_bps_le8, taker_fee_bps_le8, keeper_reward_bps_le8 |
| CreateProposal | 11 | creator, market_le4, key_u8（ParamKey）, value_le8 |
| Vote | 12 | voter, proposal_id_le8, approve_u8（0/1） |
| FinalizeProposal | 13 | caller, proposal_id_le8 |
后续轮次追加的 v2 操作使用新的 canonical 前缀 `ODX2`（与上表 `ODX1`
区分）：StakeOracle(tag 14)、UnstakeOracle(15)、SlashOracle(16)、
UpdateExternalPrice(17，外部喂价锚，§6.2 末)、Commit(18)/Reveal(19)
（v2 commit-reveal 排序，§2.5）。
canonical 尾部追加 pubkey。签名验证用 ed25519 **verify_strict**：
拒绝可延展签名（非规范 s 值、小阶分量）。

### 2.2 身份绑定

每个 op 的关键字段必须与签名者一致：

- Place/Cancel/Deposit/Withdraw：account == sha256(pubkey)
- Liquidate：caller == sha256(pubkey) —— keeper 身份密码学绑定，
  自我清算在验证层即被拒（caller == target → BadAccount）
- ReportPrice/GovDeposit/GovWithdraw/CreateMarket/CreateProposal/Vote/
  FinalizeProposal：首字段（oracle/account/creator/voter/caller）
  == sha256(pubkey)

### 2.3 插入与乱序恢复

```
insert(unit):
  EmptyParents / TooManyParents(>2) / BadParents(未排序或重复) → 拒绝
  UnitId 已存在            → Duplicate
  存在未知父单元:
    首次见到               → 写入 orphan 缓冲，返回 MissingParent
    已在缓冲中             → 返回 Ok(id)（幂等）
  全部父母已知             → link 进 DAG，进 pending 集
```

orphan 缓冲容量 4096。驱逐按**盐化序**执行：对缓冲单元取
`argmin(sha256(salt ‖ unit_id))`，其中
`salt = sha256(ORDERING_SALT_DOMAIN ‖ 最后最终化根 ‖ epoch_le)`，
`epoch = height / ORDERING_EPOCH_UNITS(512)`——引擎在 `note_finalized`
时轮换盐（`Dag::set_eviction_salt`），同 epoch 内稳定、跨 epoch 轮换。
同一 id 的重复重试若携带不同 canonical 字节，返回
`DagError::RetryMismatch`；Deposit/GovDeposit 的 Obyte 地址超过
`MAX_ADDR_LEN = 128` 字符时，在任何缓冲/验签之前即拒绝
（`DagError::AddrTooLong`）。mark_executed 时做不动点扫描：所有"父母已
全部已知"的孤儿链式解锁。残余边界：各副本观测 finalize 的时刻不同，
收敛前可能驱逐不同的孤儿——DA 层自愈：temp_data 全量重放可确定性重建
缺失单元，WantUnits gossip（`crates/operp-gossip`，§2.6）可按需向同伴
索取。

### 2.4 确定性线性化（去盐）

`Dag::ready_linearized()`：收集 pending 中父母均已执行的单元，按
`unit_id` 字典序升序返回（审计修复后已**去盐**——盐不再参与执行序，
仅用于 §2.3 的孤儿驱逐；原因：观测 finalize 时刻不同的副本会派生不同
排序盐而互不认同执行序，盐化执行序待 finalize 批内确定性设计落地后
回归）。这是唯一公开全序——任何副本对同一 pending 集算出同一执行
顺序，无需通信。该排序即撮合"价格时间优先"中的时间。

### 2.5 v2 commit-reveal 排序（additive，激活门控）

默认排序仍可被"签名多个候选挑最小 id"磨队（MEV）。v2 追加两条操作：

- **Commit(tag 18)** `{account, commit, ttl_height}`：提交
  `reveal_commit_hash = sha256(inner_op_bytes ‖ salt)`，不含内容 MEV；
  每账户同时存活的未揭示 commit 上限 `MAX_PENDING_COMMITS_PER_ACCOUNT
  = 8`，过期期限 `COMMIT_TTL_HEIGHTS = 16` 个高度（~32 s），meta 叶承诺
  全部 pending commitments（§9.1）。
- **Reveal(tag 19)** `{account, commit_ref, op, salt}`：必须引用自己的
  Commit 单元为父，重算哈希一致后才执行内层 op；TTL 过期未揭示的
  commit 作废并剪枝。

与确定性字典序叠加：Commit 阶段外界看不到 op 内容，揭示后按既有全序
执行。`COMMIT_REVEAL_ACTIVATION_HEIGHT = 0`，部署期翻转。

### 2.6 WantUnits gossip（纯 P2P 层）

`crates/operp-gossip` 实现 doc 04 §2.4 的按需孤儿同步：节点观测到缺失
父单元后以 `WANT_FANOUT` 扇出 WantUnits（每 (peer, id) 去抖
`WANT_DEBOUNCE_MS = 500`，单请求 ≤ 64 个 id）；收到请求的一方从 DAG 与
orphan 缓冲两侧服务，单响应 ≤ 64 个单元且限频。本层不进共识、不影响
执行确定性，传输载体按 doc OQ5 留待接线。

---

## 3. 订单簿撮合

### 3.1 数据结构

```
bids: BTreeMap<Reverse<Price>, VecDeque<OrderId>>   # Reverse 使最高价居首
asks: BTreeMap<Price, VecDeque<OrderId>>
orders: HashMap<OrderId, Order>                      # O(1) 查询/撤单
bid_qty / ask_qty: BTreeMap<..., Qty>                # level 可见量缓存
```

### 3.2 撮合循环规则

```
while taker.remaining > 0:
  head = 对手方向队列头（taker 为 Bid → 取 ask 头；反之 bid 头）
  无对手头 → break

  crosses:
    Limit Bid: maker_price ≤ order.price
    Limit Ask: maker_price ≥ order.price
    Market:    无条件

  fill_qty = min(taker.remaining, maker.remaining)
  双方 remaining -= fill_qty；可见量缓存 -= fill_qty（maker level）
  记录 Fill（成交价 = maker_price）

  maker_done → orders.remove(maker_id); pop_head(maker 自己所在侧)
  maker.account == taker.account → self_trade，停止撮合，
  taker 剩余作废不挂单
```

TIF：GTC Limit 余量回挂队尾（缓存 += remaining）；IOC/Market 余量丢弃。

### 3.3 可见量缓存不变量

任意时刻 `bid_qty[p] == Σ remaining(bids[p] 中活单)`。维护点：
挂单 += remaining；成交 −= fill_qty（maker 侧）；撤单（任意位置）
−= remaining。非队首撤单留 ghost id 在 deque 中，next_*_head 匹配时
惰性弹出——O(1) 撤单且深度始终正确。best_bid/best_ask 读缓存首元素：
O(log depth)。

### 3.4 价格时间优先的正确含义

"时间"由 §2.4 确定性线性化赋予：同价位先后就是 unit_id 排序中先执行者。
跨副本永远一致。

---

## 4. 账户与风险引擎

### 4.1 成交应用（apply_fill）

每笔成交同时更新 taker/maker 两腿：

- 开仓/加仓（旧仓零或同向）：VWAP 入场价
  entry' = (|pos|·entry + qty·price) / (|pos|+qty)，u128 中间量
- 平仓/反手：实现 PnL
  多头 pnl = close × (exit − entry)/PRICE_SCALE × USD_SCALE/QTY_SCALE；
  空头符号翻转。PnL 即时结算进 collateral（§4.3）；反手余量按成交价开新仓
- 仓位数量 checked_add（防累计溢出 → Overflow）

### 4.2 风险快照

```
upnl   = Σ signed_notional(qty, mark) − signed_notional(qty, entry)
mm     = Σ bps(|qty·mark|, 500)          # 5%
im     = Σ bps(|qty·mark|, 1000)         # 10%
equity = collateral + upnl               # PnL 已结算进 collateral
liquidatable : mm>0 ∧ equity×10000 ≤ mm×10500   # ≤1.05
reduce_only  : has_unmarked ∨ (mm>0 ∧ equity×10000 ≤ mm×12000)  # ≤1.20
```
IM/MM 为**每市场参数**（创世市场默认 500/1000 bps，新市场随 CreateMarket
提交，§16.2）。

无 mark 仓位：不计入 upnl/mm/im 且强制 reduce_only。否则 mark=0 给多头
记全额虚亏（可提光）、给空头记全额虚利（可无限加仓）。

### 4.3 PnL 结算模型

平仓瞬间已实现 PnL 进入 collateral：collateral += pnl（checked）；
realized_pnl 仅作统计累加。效果：赢利者立刻可提取全部利润；提款证明
叶子（只承诺 collateral）反映真实偿付能力。

### 4.4 提款

debit(amount)：amount>0；collateral 足额；debit 后快照落入 reduce-only
带则回滚报 Insufficient。重复 nonce 返回 DuplicateNonce。

引擎侧 withdrawals 映射（防重复 nonce 的提款记录）容量上限
65 536 条目，防止无界状态增长。

---

## 5. 清算、keeper 与保险基金

### 5.1 清算流程

```
Liquidate { caller, target, market }（caller 签名绑定）:
  caller == target                      → BadAccount（自我清算禁止）
  target/caller ∈ {INSURANCE_ACCOUNT}   → NotLiquidatable
  target 不满足 liquidatable            → NotLiquidatable
  target 无仓位                         → NotLiquidatable

  Market IOC 单：平仓方向，qty=|pos.qty|，account=target
  吃对手盘至干净；残余仍 liquidatable → 以 mark 与保险基金对敲强平
  （合成 fill，maker_id = OrderId([0;32])）
```

### 5.2 keeper 奖励

reward = Σ bps(每笔成交名义额, KEEPER_REWARD_BPS=100)
pay    = min(reward, max(insurance.collateral, 0))
基金枯竭时清算仍发生，keeper 暂无酬但不阻塞清算。
keeper 奖励 bps 为**每市场参数**（创世市场默认 100，新市场随 CreateMarket
提交，§16.2）。

### 5.3 坏账钳零

apply_fill_pair 后 taker snapshot.equity < 0:
  shortfall = −equity
  taker.collateral   −= shortfall      # equity 精确归零
  insurance.collateral −= shortfall    # 基金吸收

守恒：总权益减少恰为缺口。归零后不会重复触发。保险余额可为负 =
显式社会化债务，由手续费回补。保险永不被清算/不自我清算（双向排除）。

### 5.4 保险基金

创世注入 INSURANCE_SEED = 10,000 USD。收入腿：taker 手续费（§6.1）。
支出腿：坏账吸收 + keeper 奖励。

---

## 6. 手续费与资金费率

### 6.1 Taker 手续费（保险收入腿）

每笔成交后：fee = bps(notional, TAKER_FEE_BPS=5)  # 0.05%
taker.collateral −= fee；insurance.collateral += fee。
走 Account 结算路径自动进入证明叶子承诺的 collateral。
taker fee bps 为**每市场参数**（创世市场默认 5，新市场随 CreateMarket 提交，
§16.2）。

### 6.2 资金费率（多空互付）
每次预言机报告触发结算（该市场有效报告数 ≥ 2 时，§7）：
index = 该市场全部已质押报价者最新报价的**中位数**（未钳位）
spot  = 钳位后的 marks[market]
diff_bps = clamp((spot−index)×10000/index, ±FUNDING_CAP_BPS=50)
每账户 payment = signed_notional(pos.qty, oracle_a) × diff_bps / 10000
payer.collateral  −= payment（钳在上限 = 可用抵押内）   # 借记钳在可用抵押内
receiver.credit   ≤ Σ 实际借记总额                      # 贷记以总借记封顶

spot > index：正 payment → 多头付，空头收；反向镜像。
守恒语义：付款方借记先按其可用抵押钳住，收款方入账总额不超过实际扣减
总额——严格守恒、不产生负余额，截断残差为亚单位灰尘（设计允许）。
保险基金作为普通账户参与资金费（可持有清算对冲仓位）。±50bps 钳幅防
极端偏差抽干一方。
资金费 index 锚可选接入外部价（doc 06）：`Op::UpdateExternalPrice`
(tag 17) 仅接受 `external_sources` 白名单内的 keeper，且仅在市场资金源
切到 `FundingSourceKind::AggregatedExternal` 后生效。index 取外部环的
TWAP；环空或最新样本超过 `FUNDING_EXTERNAL_MAX_STALENESS = 32` 个高度
即视为过期，逐级回退 债券中位数 TWAP → 即时中位数——喂价死亡不会冻结
资金费。环与白名单、资金源选择器均进 meta 叶承诺（§9.1）。

### 6.3 dust 说明

整数除法截断产生亚微美元残差，随交易数线性累积，经济上可忽略。
系统性 dust 归集属 Phase 2 卫生项。

---

## 7. 预言机与 mark 价格

### 7.1 mark 的三重防线

| 防线 | 规则 | 目的 |
|---|---|---|
| 名义额门槛 | notional ≥ 100 USD 的成交才有资格动 mark | 灰尘单无法操纵 |
| 偏离帽 | 新价相对旧 mark 偏移 ≤ ±10%（旧价 > 0 时） | 单笔巨价无法跳变 |
| 预言机权威 | 一旦市场有任一有效预言机报价，成交永久失去 mark 定价权 | 撮合层与定价层解耦 |

### 7.2 债券注册制 + 中位数定价

```
Op::ReportPrice { oracle, market, price }        # canonical tag 6
```

无许可注册：任何人向侧链质押 `ORACLE_BOND_PERP = 50_000` PERP 即成为
报价者；债券记入 `oracle_bonds`，无白名单、无审批。退出走
`UnstakeOracle`(tag 15) 的 `ORACLE_UNBOND_HEIGHTS = 256` 高度解锁排队，
期间报价即失效；`SlashOracle`(tag 16) 对 TWAP 连续偏移达标者罚没
（500 bps 偏移 ×3 连续采样双条件，激活门控），罚没 = 债券 ×
slash_reward_bps 归挑战者、余下烧毁。

规则：

- `price == 0` 或 `(market, oracle)` 无债券的报价被忽略（exec 层前置
  校验，state 层防御性忽略）
- 最新报价存入 `oracle_reports[(market, oracle)]`——每记者每市场一价，
  新报价覆盖旧报价
- 有效报价者集合 = 有债券且有最新报价的账户；对同一市场取全部价格的
  **中位数**：奇数取正中，偶数取较小中间值（确定性，任何副本一致）
- `last_index[market] = 中位数`（未钳位，资金费率 index 用）
- spot 写入 `marks[market]` 前过 ±10% 帽（首个报价无条件设定）
- 该市场有效报告数 ≥ 2 时，每次 report 触发一次资金费结算（§6.2）

解锁到期的债券经 unstake 路径回到 `perp_balances`，走与其他 PERP 相同的
双币种 Merkle 证明出金路径（§10.5）。`(market, oracle)` 一旦无债券，
其后续报价自动失效。

### 7.3 残余操纵风险

±10% 帽允许攻击者以每 tick 10% 步进逐渐走偏 mark；中位数要求腐化按
债券计的多数报价者配合。TWAP 平滑（oracle/funding 双环）与连续偏移罚没
已落地，但合谋多数仍可在两次罚没之间施压；外部多源锚（§6.2 末）需
治理启用后才提供第二意见。

---

## 8. 批次与结算验证

### 8.1 批次切分

operator 从线性化执行流中切出前缀（≤ BATCH_MAX_UNITS=512 units），
调用 `Batch::from_applied(prev_state, engine, applied)`：

```
applied 为空                    → Empty
applied.len() > 512             → TooManyUnits
checkpoint.height               = prev.height + 1
prev_state_hash                 = prev.state_root()
engine.state.height ← height    （先推进再取根，meta_leaf 绑定高度）
state_root                      = engine.state.state_root()
aa_root                         = aa_forest_hash(aa_sharded_roots)
wit_root / trace_root / units_root / units_set_root /
ops_root / fills_root / counts_root = obyte_merkle（见 §11）
unit_count / wit_count          = applied.len() / wit_leaves.len()
```

高度进入 meta_leaf ⇒ state_root 跨批次成链：`prev_state_hash` 断链
即重组可见。

### 8.2 temp_data 全量披露

`temp_data_payload()` 把**全部 unit（含签名）+ 所有根/哈希**序列化为
OIP-0007 `temp_data` 消息发上 Obyte。意义：

- 数据可用性：任何观察者可在 1 天保留窗口内下载并本地重放
- 重放结果与 checkpoint 逐字段比对 → 欺诈必然可被检测
- 检测后的执行依赖 §10 的谓词揭发机制

`data_hash`/`data_length` 采用与 ocore 一致的**单一规范形**：
`source = getJsonSource(data)`（递归字典序排序对象键的 minified JSON；
Rust 侧移植于 `operp_settle::obyte_hash::get_json_source`），
`data_hash = hex(sha256(source))`，`data_length = source 的 UTF-8 字节长`。
Rust `temp_data_payload` 与 JS 工具链（post_batch.js 的
`obyteDataHash`/`obyteDataLength`）使用同一定义，黄金向量测试对拍同一
嵌套对象得到相同 hash/length。注意区分：**链上 OIP-0007 信封**仍须满足
ocore 校验器（base64 `getBase64Hash(data, true)` / `object_length`），
post_batch.js 把信封两字段直接委托给 ocore，不手写副本。

### 8.3 validate_against（任何人可审计）

```
chain_id ≠ CHAIN_ID                          → ChainMismatch
replay 初始 root ≠ prev_root                 → PrevMismatch
批次含 Deposit/GovDeposit → 独立验证充值证据（不再自证）：
  evidences_from_payload(data) 从 temp_data 取回证据，verify_all 以
  (expected_vault, perp_asset) 为绑定逐条复算 unit_hash(joint)，
  并确认 joint 实际向该 vault 地址支付所报金额/资产
                                              → 失败 DepositEvidence
注入 deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集
逐 unit ingest（BadSig 等）                  → Replay
重放事件聚合 fills_root/counts_root 等承诺不符  → RootMismatch
checkpoint.height ≠ replay.height + 1        → RootMismatch（高度绑定）
engine.state.height 推进至 checkpoint.height 后按窗口剪枝
(withdrawals / seen_aa_units / deposits_allowed / commits —— 与
from_applied 完全一致的剪枝集)
last_unit 不符 ∨ state_root 不符 ∨ 承诺根不符  → RootMismatch
```

---

## 9. 双 Merkle 树

侧链维护两棵承诺同一组余额的 Merkle 树，原因见 §9.3。

### 9.1 字节域树（state_root）

叶子（排序后两两合并，奇数复制末位，父 = sha256(left‖right)）：

```
account_leaf = sha256("acct" ‖ id32 ‖ collateral_i128le16
                      ‖ realized_i128le16 ‖ pos_count_u32le ‖ positions…
                      ‖ perp_u128le16)
               # perp 取自 perp_balances（PERP 治理余额，§16），
               # 与 collateral 并列进入承诺
book_leaf    = sha256(params_57B ‖ b"book" ‖ market_le4 ‖ [price_le8 ‖
               (order_id32 ‖ remaining_le8)*]*)
               # params_57B = symbol16 ‖ tick_size_le8 ‖ im_bps_le8
               #   ‖ mm_bps_le8 ‖ taker_fee_bps_le8 ‖ keeper_reward_bps_le8
               #   ‖ delisted_u8（定宽 57 字节）——市场参数本身成为被承诺
               #   的共识状态；同时提交每一个价格档与每个活单，
               #   簿深度与参数都逃不过审计
meta_leaf    = sha256(b"meta" ‖ height ‖ seq ‖ last_unit
                      ‖ perp_burned ‖ next_market_id ‖ next_proposal_id
                      ‖ Σ_market(mark, funding_index)
                      ‖ oracle_bonds ‖ oracle_unbonding ‖ oracle_slash_nonce
                      ‖ oracle_twap ‖ funding_twap ‖ funding_index_twap
                      ‖ external_price_ring ‖ external_sources
                      ‖ commits(commit-reveal) ‖ funding_source
                      ‖ oracle_configs ‖ oracle_reports
                      ‖ oracle_report_history
                      ‖ proposals(含投票集合与权重快照)
                      ‖ perp_balances ‖ perp_supply)
               # 每个 BTreeMap/Set 均带 u32 len 前缀 + 排序迭代写入；
               # TWAP 样本携带 seq；HashSet（voted）排序后提交。
               # 覆盖账户树之外的全部共识状态，重放无法在价格/资金费/
               # 治理/承诺状态上分叉。此为 state_root 格式的破坏性变更。
```

meta_leaf 绑定 height（from_applied 先把 engine.state.height 推到
checkpoint.height 再取根），使 state_root 跨批次成链：改历史高度必然断链。
meta_leaf **不含** finalized_height——Final 提升只影响本地节点视图，
不属于被承诺的共识状态（见 §12）。

### 9.2 hex 字符串域森林（aa_forest，16 分片）

Oscript 的 `sha256()` 对参数 UTF-8 文本哈希且默认输出 base64——字节域树
无法在 AA 内复算。因此另建同构字符串域承诺，并按 doc 10 的 v2 方案**分片**：
账户按地址划入 16 个 shard，每个 shard 内：

```
leaf = sha256_hex("acct:" + address + ":" + collateral十进制串
                  + ":" + perp十进制串 + ":" + withdrawn十进制串)
node = sha256_hex(left_hex + right_hex)      # 每 shard 深度 ≤ 16
```

每批提交 16 个 shard 根**拼接为一个 1024-hex 字符串 `aa_forest`**
(shard i 位于偏移 i*64)，恰好命中 Oscript `MAX_STATE_VAR_VALUE_LENGTH
= 1024`，submit/lock/失败清扫保持单变量操作。空 shard 提交离线生成的
哨兵根 `hex(sha256("empty:<shard>"))`，零证明无法跨 shard 跳动。Rust
侧构造分片森林与证明；AA 用 `substring(shard*64, 64)` 取出所声明的
shard 根后折叠兄弟路径比对——AA **信任 shard 标签**，但叶子前像保证
可靠性：错报 shard 只会折到错误的根上。经探针 AA 对拍验证 root 逐字节
一致。

### 9.3 为什么提款用字符串域森林

AA 只能做字符串拼接与 sha256——它无法解析 i128 LE、无法遍历仓位数组。
字符串域森林把"证明我有多少钱"压缩成 AA 能完成的两次 sha256 调用
（叶子重算 + 兄弟折叠）。字节域树则继续承担完整状态承诺（撮合簿、仓位、
进度），供 Rust 观察者全量审计。

---

## 10. 结算 AA 状态机（CHAIN_ID=operp-v2）

三个 AA：`operp_rollup.aa`（主张链）、`operp_dispute.aa`（充提/漏单谓词）、
`operp_dispute_fill.aa`（成交谓词）、`operp_vault.aa`（托管）。金库无
owner key，claim 在 rollup。

rollup 状态变量（`<h>` 为高度后缀）：

```
last_submitted, last_finalized, dispute_aa, dispute_fill_aa
submitted_at_h, state_root_h, aa_forest_h(1024 hex), prev_h
wit_root_h, trace_root_h, units_root_h, units_set_root_h
ops_root_h, fills_root_h, unit_count_h, wit_count_h
da_unit_h, active_bond_h, fee_winner_h
frozen_h ∈ {∅/0=live, 2=failed}
inbox_<unit_id_hex>, inbox_upto_h
sbond_<addr>, reward_<addr>, slash_reward_<addr>
```

时钟：

| 门 | 原点 | 时长 |
|---|---|---|
| 谓词揭发 / finalize | `submitted_at_h` | 3600 s（CHALLENGE_SECS） |
| escape_finalize | `submitted_at_h` | 604800 s |

### 10.1 submit(h) — rollup

前置：`chain_id=='operp-v2'` ∧ `assertion_version==1` ∧ h == last_submitted+1
∧ prev == `state_root_{h-1}`（上一高度 frozen=2 时豁免）
∧ state_root/prev 64 hex ∧ aa_forest 1024 hex ∧ 六个承诺根 44 b64
∧ 组合单元（temp_data 在同一 unit，`da_unit_h=trigger.unit`）
∧ 输出-10000 ≥ 1e12（SUBMIT_BOND_NET）
→ 写全部 <h> 键 + `inbox_upto_h = timestamp` + last_submitted=h；
  已占位且 frozen≠2 → bounce('height taken')。无 lock。

### 10.2 谓词揭发 — dispute / dispute_fill

| 谓词 | AA | 证明什么 |
|---|---|---|
| deposit / withdraw（含 D/W gov） | dispute | op 前后余额算术（含 pre_absent 非成员） |
| omit | dispute | inbox 强收 id 不在 units_set_root（三段几何非成员） |
| fill_math | dispute_fill | apply_fill 全分支（同向 VWAP / 减仓 / 反手 / 平完）± taker fee；±1 Decimal 容差；claimed-absent 仓位带前缀区间非成员 |
| ghost | dispute_fill | 成交的 maker 订单 id 前缀区间不在 pre_wit |
| skip | dispute_fill | pre_wit 中存在更优活单未成交 |

公共门：`frozen`/`submitted_at+3600`、stale-root 对比 rollup 变量、
所有成员证明 `.root` 必须等于对应 pre_wit/post_wit/roots。
验不过 bounce('no fraud')；验过 → 付 10000 bytes + data
`{verdict:'fraud', height, challenger}` 给 rollup。

### 10.3 verdict(h) — rollup

`trigger.address ∈ {dispute_aa, dispute_fill_aa}` ∧ verdict=='fraud'
∧ 高度 live ∧ 窗内 ∧ challenger 是合法 32 字符地址
→ frozen_h=2、清 state_root/aa_forest/active_bond/fee_winner、
  last_submitted=h-1、slash_reward_<challenger> += 5e11。

### 10.4 finalize / escape_finalize(h) — rollup

`{finalize}`：!frozen ∧ root 在 ∧ h == last_finalized+1
∧ now ≥ submitted_at_h + 3600 → last_finalized=h、sbond += 1e12、
reward_<fee_winner> += 20000。`{escape_finalize}` 窗口阈值 604800，
任意账户，不越过未结欺诈（frozen≠0 bounce 'challenged'）。

### 10.5 withdraw — vault

`$lf = var[ROLLUP]['last_finalized']`；`$src = var[ROLLUP]['aa_forest_'||$lf]`。
叶子 `acct:addr:col:perp:W`（hex 域），16 深折叠，
`amount + wd_ <= min(collateral, withdrawn)`，`perp_amount` 可选部分领取，
`wp_` 封顶。`{escape_withdraw}` 弹 `no escape withdraw`。

### 10.6 force / claim — rollup

`{force, unit_id 64hex}` ≥10000 bytes → `inbox_<id>=timestamp`（重复 bounce
`already forced`）。claim 三态：`reward|sbond|slash`。

---

## 11. Witness 树与谓词承诺

每批 checkpoint 额外携带（`operp_settle`）：`wit_root`（执行完最后单元的
witness 叶根）、`trace_root`（每单元 post wit_root 的 Obyte 原生 Merkle，
按批序）、`units_root` / `units_set_root`（unit_id hex 批序/排序）、
`ops_root`（op 描述串）、`fills_root`（成交描述串）、`counts_root`
（每单元叶数）、`unit_count` / `wit_count`。

witness 叶（`operp_state::wit_leaves`，排序后 Obyte 原生 Merkle）：

```
acct:{acct_hex}:{collateral}:{perp}:{W}
pos:{acct_hex}:{market}:{qty}:{entry}
ord:{order_hex}:{market}:{side}:{price}:{seq}:{remaining}:{acct_hex}
meta:{market}:{tick}:{im}:{mm}:{taker_fee_bps}:{keeper}:{delisted}:{mark}
```

`temp_data` 另带 `trace`/`ops`/`fills`/`counts`/`leaf_trace` 数组（DA 给
watcher；`leaf_trace` 超 4MB 省略）。`validate_against` 重放复算全部根。
`is_valid_merkle_proof` 是 ocore 内建（复杂度 1），格式 `{root, siblings, index}`。

## 12. Multi-operator 手续费竞速


多个 operator 并行观察侧链、各自向 AA 提交组合单元（temp_data + submit
同一 unit）。赢家判定利用 Obyte 原生性质：**AA 只被稳定单元触发，触发按
稳定序生效**。因此"最先稳定"天然等价于"AA 最先处理"——height 归属 =
第一笔被 AA 处理的该 height 组合单元；未冻结的后续提交一律
bounce('height taken')（占位门），不产生安慰金（现状无补贴；输家的
60000 bytes 原样退回，仅损失 bounce 费）：

```
submit(h) 竞速:
  if (!active_bond_h): 处理（首交者胜）
  else: bounce('height taken')            # 单候选, 占用窗内无替换
  da_unit_h ← trigger.unit                # 根↔数据绑定
  if (!fee_winner_h): fee_winner_h ← trigger.address   # 首个稳定者赢
```

- 同批一起稳定的平局由 ocore 内建单元排序裁决；Rust 侧
  `pick_stable_winner`（operp-settle, mci→unit_id 双键）语义一致
- 赢家奖励在 finalize 成功路径累加（失败高度不发放），{claim:"reward"} 提取
- "交易按第一个稳定的填充下一个"由 prev_state_hash 链保证：
  h+1 必须引用赢家的 root_h
- 高度失败回滚后重新竞速（verdict 清空 active_bond_h，组合单元可重新首占；
  fee_winner_h 保持首个处理者不变）

---


## 13. Optimistic / Final 状态提升
引擎事件生命周期：

```
ingest → Applied{status: Optimistic}     # 立即执行、立即成交
   │
   ├─ 批次切出（settle 层）                # 数据准备提交
   ├─ temp_data 上链 + submit             # 数据可用 + 进竞速
   ├─ 谓词揭发（窗内可选）                 # 假账被杀、高度重开
   ├─ finalize（submitted_at+3600 后）     # 根成为提款依据
   └─ 操作者观测到 finalize 事件后调用
      Engine::promote_finalized(unit_ids)
      → 该高度所有 Applied 状态翻转为 ExecStatus::Final
```

- `promote_finalized` 幂等：重复调用返回 0
- 日志状态**不是** state_root 的一部分——提升只影响本地节点视图，
  重放确定性无损。每个节点依据自己观测到的 AA finalize 事件独立推进
- 客户端职责：同时展示 Optimistic（可挑战推翻）与 Final（已成定局）

---

## 14. 威胁模型对照表

| 攻击 | 防线 |
|---|---|
| 伪造成交 / 假根 | 双 Merkle 根 + validate_against 全量重放 + 一枪谓词（含 fill_math/ghost/skip） |
| 偷 AA 资金 | 提款只认 finalized 分片森林的 Merkle 证明；leaf 绑定提款人地址；wd_/wp_ 累计标记防证明重放 |
| 付钱杀根 | 已删除：`{challenge:1}` 无 case；假证明 bounce `no fraud` |
| 审查用户单元 | rollup inbox `{force}` + P-omit 非成员证明 |
| 存款凭空铸造 | deposits_allowed 白名单 + replay 交叉校验 + evidence 绑定 `OPERP_VAULT_AA` |

## 15. 明确的已知边界

- 保险钳制不在链上验（watcher 对钳制侧跳过）；fill_math 带 ±1 Decimal 容差
- `temp_data` 正文 24h 后被节点剥除——揭发必须自带那一笔与证明
- 充值 joint 主要在链下 `validate_against` 核（`OPERP_VAULT_AA` 空且带
  evidence 会被 `validate_against` 拒）
- 预言机为债券注册制（ORACLE_BOND_PERP = 50_000 PERP，无许可）；按债券计
  的多数合谋仍可在两次罚没之间偏置中位数；外部价锚需治理切换 + keeper 喂价
- 大载荷内联 temp_data 会触发 ocore 校验器双回调崩溃：post_batch.js 的
  链上信封字段已直接委托 ocore；devnet E2E 跳过内联揭示
- 无第三方安全审计；各 AA ≤100 复杂度（探针 `check_aa_complexity.js`）
- 独立 watcher 已可组谓词 proof；须以与 poster 分离的密钥部署后，
  互相牵制才算跑通

---

## 16. PERP 治理

PERP 是 Obyte 原生治理资产，围绕它实现三件事：无许可市场上架、债券
注册制预言机（§7）、链上提案投票改参。资产 ID 在发币前未知，全部以
占位常量落地：Rust 侧 `PERP_ASSET: AssetId = [0u8; 32]`，Oscript/JS 侧
字面量 `'PERP_ASSET_ID_HERE'`，部署脚本加载 .aa 后做字符串替换写入真实
asset id。发币时只需改一个常量并重新部署 AA。

### 16.1 记账模型：侧链镜像

不新建第二个 AA——扩展现有 vault AA 接收 PERP 充值：

- **GovDeposit**（tag 8）：镜像现有 deposit——`seen_aa_units` 去重、
  `deposits_allowed` 白名单（同一集合，replay 时由批次内 GovDeposit ops
  注入交叉校验），入账 `perp_balances[account] += amount`，
  `perp_supply += amount`
- **GovWithdraw**（tag 9）：共享 withdrawals 表与 65 536 条目上限；
  无 reduce-only 检查；AA 侧走扩展后的双币种 Merkle 证明提款
  （§10.5，叶子含 perp 字段）

`perp_supply` 定义为可赎回流通量：Σ 充值 − 提款 − 烧毁。

### 16.2 无许可市场上架

**CreateMarket**（tag 10）：任何人可上架，代价是烧毁
`CREATE_MARKET_FEE_PERP = 10_000` PERP 上架费。市场参数随 op 提交
（symbol、tick_size、im_bps、mm_bps、taker_fee_bps、keeper_reward_bps），
存入 `markets[market_id]`——IM/MM/taker fee/keeper 奖励从全局常量变为
**每市场参数**（§4.2/§5.2/§6.1 相应改为读参数）。tick_size 或任一 bps
为 0 → Risk 拒绝。簿不预建，沿用 `book_mut` 惰性创建。

delisted 市场（见 16.3 Delist 提案）拒绝新挂单；撤单与清算平仓仍允许
(清算路径不经 place 校验)。MVP 不做强制拍卖：存量仓位只能平仓或被清算。

### 16.3 提案投票

**CreateProposal**（tag 11）：创建者对指定市场提交参数修改提案，`key` 取
`ParamKey`（ImBps/MmBps/TakerFeeBps/KeeperRewardBps/Delist）；bps 键的
value ≤ 10 000、Delist 键的 value 必须为 0，否则 Risk 拒绝。创建门槛：
创建者 PERP 余额 ≥ `PROPOSAL_MIN_STAKE_PERP = 1_000`（仅门槛检查，
质押不锁定）。提案登记即固定两个快照：`created_seq` 与 quorum 分母
`supply_at_create = perp_supply`——期限与法定人数在创建时刻确定，任何副本
重放得出相同的通过判定。

**Vote**（tag 12）：权重 = **投票 unit 执行时刻**的 PERP 余额。MVP 不存
创建时的余额快照映射——余额随充值/提款/烧毁实时变化，文档如实表述；
拆分账户不放大总权重（§13）。每账户一票（`voted` 集合去重）；期限
`seq < deadline_seq = created_seq + PROPOSAL_DURATION_SEQS
= created_seq + 20_000 seqs`。

**FinalizeProposal**（tag 13）：任何人可触发，须 `seq ≥ deadline_seq` 且
未 finalized。通过条件：

```
yes > no  ∧  yes × PROPOSAL_QUORUM_DEN(100)
              ≥ supply_at_create × PROPOSAL_QUORUM_NUM(10)
```

即赞成票超过流通量快照的 **10%**。分母用创建时快照而非当前 supply：
烧毁/提款导致的后续流通量变化不会改写历史提案的通过判定（重放确定性的
另一面）。通过后立即应用：bps 键写回 `markets[m]` 对应字段；Delist 键置
`delisted = true`——delisted 市场拒绝新挂单，存量仓位只能平仓或被清算
（§16.2）。

### 16.4 烧毁语义

烧毁统一走 `burn_perp`：入口为 CreateMarket 的上架费
`CREATE_MARKET_FEE_PERP = 10_000` 与 `SlashOracle`(tag 16) 罚没中的
烧毁份额（§7.2）。
烧毁 = 从 `perp_balances` 扣除并累计 `perp_burned` 统计量，**同时等额扣减
`perp_supply`**：supply 定义为可赎回流通量，通缩使后续提案的 quorum
分母随之收缩。

审计对账口径：侧链烧毁只动镜像账本，对应的真实 PERP **永久滞留在 vault
AA 中、不做链上销毁 sweep**——AA 对 PERP 处于超抵押状态。这是有意设计：
可赎回总量按 `perp_supply` 通缩，而链上 AA 余额不减少。对账时切勿把
"AA 持有 > Σ 可赎回"误判为资损缺口；差额恰等于 `perp_burned`。

### 16.5 债券解锁

预言机债券记入 `oracle_bonds`，与可自由支配的 `perp_balances` 分离：进入
债券的 PERP 不计投票权重、不可直接提款。退出走 `UnstakeOracle`(tag 15)：
进入 `ORACLE_UNBOND_HEIGHTS = 256` 高度的解锁排队（`oracle_unbonding`，
meta 叶承诺），到期后债券回到 `perp_balances`，再经双币种 Merkle 证明
出金（§10.5）。排队期间 `(market, oracle)` 已无债券——最新报价立即退出
中位数集合、后续报价被防御性忽略（§7.2）。
