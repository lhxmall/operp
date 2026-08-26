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
10. [vault AA 状态机](#10-vault-aa-状态机)
11. [多 operator 手续费竞速](#11-multi-operator-手续费竞速)
12. [Optimistic / Final 状态提升](#12-optimistic--final-状态提升)
13. [威胁模型对照表](#13-威胁模型对照表)
14. [明确的已知边界](#14-明确的已知边界)
15. [PERP 治理](#15-perp-治理)

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
market 不存在或已 delisted       → Risk（无许可市场，见 §15）
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
执行。`COMMIT_REVEAL_ACTIVATION_HEIGHT = 1_000_000`，部署期翻转。

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
提交，§15.2）。

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
提交，§15.2）。

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
§15.2）。

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
双币种 Merkle 证明出金路径（§10.6）。`(market, oracle)` 一旦无债券，
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
aa_root                         = aa_root_of(engine)
fills_hash / fill_count         = sha256(fills_bytes) / Σlen
```

高度进入 meta_leaf ⇒ state_root 跨批次成链：`prev_state_hash` 断链
即重组可见。

### 8.2 temp_data 全量披露

`temp_data_payload()` 把**全部 unit（含签名）+ 所有根/哈希**序列化为
OIP-0007 `temp_data` 消息发上 Obyte。意义：

- 数据可用性：任何观察者可在 1 天保留窗口内下载并本地重放
- 重放结果与 checkpoint 逐字段比对 → 欺诈必然可被检测
- 检测后的执行依赖 §10 的挑战机制

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
重放事件聚合 fills_hash/fill_count 不符      → FillsMismatch
checkpoint.height ≠ replay.height + 1        → RootMismatch（高度绑定）
engine.state.height 推进至 checkpoint.height 后按窗口剪枝
(withdrawals / seen_aa_units / deposits_allowed / commits —— 与
from_applied 完全一致的剪枝集)
last_unit 不符 ∨ state_root 不符             → RootMismatch
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
               # perp 取自 perp_balances（PERP 治理余额，§15），
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

## 10. vault AA 状态机

AA 地址上的状态变量（`<h>` 为高度数字后缀）：

```
boot, chain_id='operp-mvp-1', last_locked, last_finalized
submitted_at_h, cand_root_h, cand_aa_root_h, cand_prev_h,
  cand_fills_h, cand_who_h                    # 候选（lock 前可替换）
active_bond_<h>                              # 现任候选的 50000-byte 提交
                                             # 债券持有人地址（被替换者的
                                             # 债券转入 sbond_<old>）
root_h, aa_root_h, stable_at_h               # 已锁定；aa_root_ 存 1024-hex
                                             # 分片森林
frozen_h ∈ {∅/0=正常, 1=已挑战, 2=永久失败}
challenger_h, bond_<addr>, fee_winner_h,
reward_<addr>, sbond_<addr>(可回收提交债券),
slash_reward_<addr>(罚没分成, {claim:"slash"} 领取),
wd_<h>_<addr>                                # 抵押提款累计标记（防证明重放）
wp_<h>_<addr>                                # PERP 提款累计标记（语义与 wd_ 对称）
pperp_<addr>                                 # PERP 入账镜像：{deposit_perp} 触发把
                                             # 资产支付记入 trigger.address 名下
```
`pperp_` 是对账镜像（键与 `wd_`/`wp_` 同为 trigger.address），**不是**支付
上限——提款权威始终是已证明叶子的 perp 值；不设上限是为了不搁浅从未经过
`deposit_perp` 的侧链收益 PERP。诊断账本 `bal_` 已在复杂度腾挪中删除。
所有领取统一为单一 `{claim:"reward"|"bond"|"sbond"|"slash"}` 字段。

### 10.1 submit(h)

前置：chain_id 正确 ∧ h == last_locked+1 ∧ prev 匹配 root_{h−1}
∧ 有 64-hex 的 state_root/prev_state_hash ∧ aa_forest 恰 1024 hex
∧ 未锁定。新候选须附 ≥ 60 000 bytes（10 000 bounce 余量 +
50 000 `SUBMIT_BOND_NET`）；**在任候选**重发（respond-by-resubmit）免债
券——身份经 `active_bond_<h>` 判定，冒充者 bounce('not operator')。

副作用：写候选五元组 + active_bond_<h> + submitted_at_h（每次 submit 都
重启稳定计时）；被替换候选的债券移入 sbond_<old>；竞速判定（§11）。

### 10.2 lock(h)

候选存在 ∧ 未锁 ∧ h == last_locked+1 ∧ now ≥ submitted_at_h + 600
∧ **active_bond_<h> 在位**（H1 债券门：失败 finalize 会没收并清零该键，
故回滚后的高度在新的带债券 submit 重建候选之前无法被重新 lock）
→ root/aa_forest/winner/stable_at 落定，last_locked = h。锁后不可变。

600s 是 OBYTE_STABILITY_SECS 的模拟（devnet 用 timetravel 测试）。

### 10.3 challenge(h)

root 已锁 ∧ 未冻结 ∧ now < stable_at_h + 3600 ∧ 输出 ≥ 20000 base
→ frozen_h = 1，记录 challenger，收 bond。

### 10.4 respond(h)

无独立触发器：operator 通过**重发同一根**应诉（submit 路径内识别）。
身份门：`trigger.address == var['active_bond_' || h]`（frozen==1 期间恒
等于现任候选人）∧ 窗口内 ∧ 重发根一致 → 解冻，没收 bond_<challenger>
记录的恰好数额并清零（归 AA 库）。

已知边界：应诉只校验重发根一致，不能证明根正确——真欺诈 operator
重复自己的假根即可通过。完整方案需要链上重放或有效性证明（README
Limitations #1）。

### 10.5 finalize / escape_finalize(h)

`{finalize}` 与 `{escape_finalize: 1}` 共用同一处理分支：

```
失败路: frozen_h == 1 ∧ 已超窗（operator 未应诉）
        → frozen_h = 2（永久）、root_/aa_root_/active_bond_ 清零、
          last_locked 回退 h−1；50 000 提交债券对半劈：
          slash_reward_<challenger> += 25000（{claim:"slash"} 领取），
          另一半留在金库（烧毁）；挑战者自身债券经 {claim:"bond"} 取回
正常路: 根存在 ∧ 未冻结 ∧ 超窗 ∧ h == last_finalized+1
        → last_finalized = h；sbond_<持有人> += 50000 可回收；
          fee_winner 累加 20000 bytes 奖励（§11）
escape: trigger.data.escape_finalize 时窗口阈值改为
        ESCAPE_STALL_SECS = 604800（主网 7 天 / devnet timetravel）；
        任意账户可调用；绝不越过 live challenge（frozen==1 必须走
        失败清扫以退还挑战者）。按 doc07 §4 豁免，只做本地停滞门。
```

### 10.6 withdraw / escape_withdraw

普通 withdraw 验证对象为 `aa_root_last_finalized`；`{escape_withdraw:1}`
验证对象为 **陈旧候选** `cand_aa_root_(last_finalized+1)`——仅当该高度
从未锁定或已 frozen==2 回滚时可用，且不推进 finalization。两者共享
wd_/wp_ 防重放累计。

```
未冻结（escape_withdraw 另要求目标高度无 root_ 且候选森林存在）
$shard ∈ [0,15] 整数（AA 信任标签；错报 shard 折到错误根上必然失败）
amount > 0 ∧ leaf_account == trigger.address
wd_ 累计上限：wd_<h>_<addr> 已提累计 + amount
             ≤ 该高度证明叶子的 collateral（同一证明不可重放，
               多次提款共享同一累计上限；映射上限 65 536 条目）
$perp 为必填 claim 字段（可为 0）；wp_ 累计上限与 wd_ 完全对称：
             wp_<h>_<addr> 累计 + perp_claimed ≤ 叶子声明的 PERP，
             超出 bounce('bad perp claim')；$perp_claimed > 0 才发
             PERP asset 输出
proof 深度 ≤ 16（reduce(...,16,...)，每 shard 最多 2^16 账户 ×
             16 shard ≈ 每批 ~1M 账户）
leaf  = sha256('acct:'+address+':'+collateral+':'+perp+':'+withdrawn,'hex')
fold proof[]: right ? sha256(acc‖sib,'hex') : sha256(sib‖acc,'hex')
结果 == substring($src, $shard*64, 64)   否则 bounce('bad merkle root')
→ 支付 trigger.address amount（+ $perp_claimed 的 PERP）
```

### 10.7 统一 claim 入口

`{claim: "reward"|"bond"|"sbond"|"slash"}` 四态分发（替代旧的三个布尔
字段）：reward = 竞速累积奖励；bond = 失败高度 challenger 的记录债券；
sbond = 被替换/正常完结候选的提交债券返还；slash = 确认欺诈后的罚没
分成。均需随单元附带 ≥10000 bytes 支付费用。AA 临时缺币时单元 bounce，
记账保留，稍后重试即可——finalize 流程不会因付款失败而卡死。

---

## 11. Multi-operator 手续费竞速

多个 operator 并行观察侧链、各自向 AA submit 批次。赢家判定利用
Obyte 原生性质：**AA 只被稳定单元触发，触发按稳定序生效**。因此
"最先稳定"天然等价于"AA 最先处理"：

```
submit(h) 竞速:
  $is_loser = fee_winner_h 已设置 ∧ ≠ trigger.address
  if (!fee_winner_h): fee_winner_h ← trigger.address   # 首个稳定者赢
  else: 立即支付安慰金 5000 bytes 给后来者
```

- 输家刷补贴无利可图：每次提交净成本 10000 bytes（留存处理费）> 补贴
- 赢家奖励在 finalize 成功路径累加（失败高度不发放），{claim:"reward"} 提取
- "交易按第一个稳定的填充下一个"由 prev_state_hash 链保证：
  h+1 必须引用赢家的 root_h
- 高度失败回滚后重新竞速（fee_winner/cand_* 随回滚语义自然重置）

---

## 12. Optimistic / Final 状态提升

引擎事件生命周期：

```
ingest → Applied{status: Optimistic}     # 立即执行、立即成交
   │
   ├─ 批次切出（settle 层）                # 数据准备提交
   ├─ temp_data 上链 + submit             # 数据可用 + 进竞速
   ├─ lock（稳定窗后）                     # 根锁定
   ├─ finalize（挑战窗后）                 # 根成为提款依据
   └─ 操作者观测到 finalize 事件后调用
      Engine::promote_finalized(unit_ids)
      → 该高度所有 Applied 状态翻转为 ExecStatus::Final
```

- `promote_finalized` 幂等：重复调用返回 0
- 日志状态**不是** state_root 的一部分——提升只影响本地节点视图，
  重放确定性无损。每个节点依据自己观测到的 AA finalize 事件独立推进
- 客户端职责：同时展示 Optimistic（可挑战推翻）与 Final（已成定局）

---

## 13. 威胁模型对照表

| 攻击 | 防线 |
|---|---|
| 伪造成交 / 锁假根 | 双 Merkle 根 + validate_against 全量重放审计 + fills_hash |
| 偷 AA 资金 | 提款只认 finalized 分片森林的 Merkle 证明；leaf 绑定提款人地址；wd_/wp_ 累计标记防证明重放；escape_withdraw 只认陈旧候选森林且不推进 finalization |
| 冒名应诉挑战 | respond 身份门（active_bond_ 绑定，frozen==1 期间恒为现任候选人） |
| 存款凭空铸造 | deposits_allowed 白名单 + replay 注入交叉校验 + validate_against 内独立充值证据验证（unit_hash(joint) 复算 + 实付 vault/资产核对） |
| qty/名义额溢出 DoS | 入口 checked-mul + i64 上限 |
| 签名延展 | ed25519 verify_strict |
| 乱序投递丢单元 | orphan 缓冲（4096，epoch 盐化驱逐）+ 不动点解锁 + WantUnits gossip 按需补单元 |
| 自我清算 | caller 密码学绑定 + BadAccount 拒绝 |
| 灰尘单操纵 mark | 100 USD 名义额门槛 |
| 单笔巨价操纵 mark | ±10% 偏离帽 |
| 撮合簿深度造假 | visible_qty 缓存三路增量维护 + 幽灵惰性清理（回归测试覆盖） |
| 盈利不可提 / 亏损超提 | PnL 即时结算进 collateral + reduce-only 提款带 |
| 坏账转嫁对手方 | 钳零 + 保险基金等额吸收（守恒） |
| 保险基金枯竭 | taker 手续费收入腿 + 负值显式记账 |
| 无 mark 市场风险失真 | 无 mark 仓位强制 reduce_only 且剔除出快照 |
| 乱序投递 | orphan 缓冲自动恢复 |
| 日志无限增长 | prune_below 按批裁剪 |
| 伪造提案操纵市场参数 | 法定人数 = 流通量快照（supply_at_create）的 10% 且 yes > no 多数 + 提案期限（20 000 seqs） |
| 女巫账户刷投票 | 投票权重 = 投票执行时刻的 PERP 余额，拆分账户不放大总权重 |
| 回滚高度无债券重锁（H1） | lock 要求 active_bond_<h> 在位；失败 finalize 清零该键 |

## 14. 明确的已知边界

- respond 不能证明根正确（Oscript 无法重放撮合）；作恶 operator 只能
  造成停摆，配合 fee race 由诚实 operator 接管
- 预言机为债券注册制（ORACLE_BOND_PERP = 50_000 PERP，无许可）；
  TWAP 连续偏移罚没已落地（激活门控），但按债券计的多数合谋仍可在两次
  罚没之间偏置中位数；外部价锚（§6.2 末）需治理切到 AggregatedExternal
  且白名单 keeper 持续喂价才生效
- 在任 operator 每次 resubmit 免费重启稳定计时（M5 处置：接受的活性
  权衡——只拖延自家高度，竞争者可花债券夺走该高度）
- 大载荷内联 temp_data 会触发 ocore 校验器双回调崩溃：post_batch.js 的
  链上信封字段已直接委托 ocore，但 devnet E2E（test_vault_aa.js）仍跳过
  内联揭示；数据可用性正确性由 Rust 侧 settle 测试覆盖
- 无第三方安全审计；Oscript 复杂度门恰在上限 **85/100**
  （ops 1086/2000，`node tools/check_aa_complexity.js`），后续任何 AA
  改动必须先腾出等额预算

---

## 15. PERP 治理

PERP 是 Obyte 原生治理资产，围绕它实现三件事：无许可市场上架、债券
注册制预言机（§7）、链上提案投票改参。资产 ID 在发币前未知，全部以
占位常量落地：Rust 侧 `PERP_ASSET: AssetId = [0u8; 32]`，Oscript/JS 侧
字面量 `'PERP_ASSET_ID_HERE'`，部署脚本加载 .aa 后做字符串替换写入真实
asset id。发币时只需改一个常量并重新部署 AA。

### 15.1 记账模型：侧链镜像

不新建第二个 AA——扩展现有 vault AA 接收 PERP 充值：

- **GovDeposit**（tag 8）：镜像现有 deposit——`seen_aa_units` 去重、
  `deposits_allowed` 白名单（同一集合，replay 时由批次内 GovDeposit ops
  注入交叉校验），入账 `perp_balances[account] += amount`，
  `perp_supply += amount`
- **GovWithdraw**（tag 9）：共享 withdrawals 表与 65 536 条目上限；
  无 reduce-only 检查；AA 侧走扩展后的双币种 Merkle 证明提款
  （§10.6，叶子含 perp 字段）

`perp_supply` 定义为可赎回流通量：Σ 充值 − 提款 − 烧毁。

### 15.2 无许可市场上架

**CreateMarket**（tag 10）：任何人可上架，代价是烧毁
`CREATE_MARKET_FEE_PERP = 10_000` PERP 上架费。市场参数随 op 提交
（symbol、tick_size、im_bps、mm_bps、taker_fee_bps、keeper_reward_bps），
存入 `markets[market_id]`——IM/MM/taker fee/keeper 奖励从全局常量变为
**每市场参数**（§4.2/§5.2/§6.1 相应改为读参数）。tick_size 或任一 bps
为 0 → Risk 拒绝。簿不预建，沿用 `book_mut` 惰性创建。

delisted 市场（见 15.3 Delist 提案）拒绝新挂单；撤单与清算平仓仍允许
(清算路径不经 place 校验)。MVP 不做强制拍卖：存量仓位只能平仓或被清算。

### 15.3 提案投票

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
（§15.2）。

### 15.4 烧毁语义

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

### 15.5 债券解锁

预言机债券记入 `oracle_bonds`，与可自由支配的 `perp_balances` 分离：进入
债券的 PERP 不计投票权重、不可直接提款。退出走 `UnstakeOracle`(tag 15)：
进入 `ORACLE_UNBOND_HEIGHTS = 256` 高度的解锁排队（`oracle_unbonding`，
meta 叶承诺），到期后债券回到 `perp_balances`，再经双币种 Merkle 证明
出金（§10.6）。排队期间 `(market, oracle)` 已无债券——最新报价立即退出
中位数集合、后续报价被防御性忽略（§7.2）。
