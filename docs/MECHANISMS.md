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

orphan 缓冲容量 4096，超出时驱逐 **UnitId 最小**的缓冲单元——驱逐决策
只依赖缓冲内容（对同一内容集确定），但哪些单元进入缓冲仍取决于各副本
的到达顺序。mark_executed 时做不动点扫描：所有"父母已全部已知"的孤儿
链式解锁。效果：乱序投递不丢单元，最终全部恢复执行。

### 2.4 确定性线性化

ready_linearized()：收集 pending 中父母均已执行的单元，按 UnitId 字节
升序返回。这是唯一公开全序——任何副本对同一批单元算出同一执行顺序，
无需通信。该排序即撮合"价格时间优先"中的时间。

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
报价者；债券记入 `oracle_bonds`，无白名单、无审批。

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

解除资格 = 通过 GovWithdraw 提走债券；`(market, oracle)` 一旦无债券，
其后续报价自动失效。MVP 不设解锁延迟。

### 7.3 无 TWAP 时的残余风险

±10% 帽允许攻击者以每 tick 10% 步进逐渐走偏 mark；中位数要求腐化按
债券计的多数报价者配合。完整解法是 TWAP 或外部多源——Phase 2。

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

`data_hash` 为 sha256(serde_json bytes)，注明是侧链内部值；
正式上主网时 poster 需换用 Obyte getBase64Hash。

### 8.3 validate_against（任何人可审计）

```
chain_id ≠ CHAIN_ID                          → ChainMismatch
replay 初始 root ≠ prev_root                 → PrevMismatch
注入 deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集
逐 unit ingest（BadSig 等）                  → Replay
重放事件聚合 fills_hash/fill_count 不符      → FillsMismatch
checkpoint.height ≠ replay.height + 1        → RootMismatch（高度绑定）
engine.state.height 推进至 checkpoint.height 后
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
meta_leaf    = sha256(b"meta" ‖ height_le ‖ seq_le ‖ last_unit
                      ‖ perp_burned_le16 ‖ next_market_id_le4
                      ‖ next_proposal_id_le8)
               # 新游标承诺治理计数器，防重放歧义
```

meta_leaf 绑定 height（from_applied 先把 engine.state.height 推到
checkpoint.height 再取根），使 state_root 跨批次成链：改历史高度必然断链。
meta_leaf **不含** finalized_height——Final 提升只影响本地节点视图，
不属于被承诺的共识状态（见 §12）。

### 9.2 hex 字符串域树（aa_root）

Oscript 的 `sha256()` 对参数 UTF-8 文本哈希且默认输出 base64——字节域树
无法在 AA 内复算。因此另建同构字符串树：

```
leaf = sha256_hex("acct:" + address + ":" + collateral十进制串
                  + ":" + perp十进制串)
node = sha256_hex(left_hex + right_hex)
```
Rust `aa_root_of(pairs)` / `aa_proof_for(pairs, addr)` 构造（pairs 三元组
`(地址, 抵押, PERP 余额)`）；AA 用 `sha256(x, 'hex')` 复算。两树承诺相同
(地址, 抵押, PERP) 集。经探针 AA 对拍验证 root 逐字节一致。

### 9.3 为什么提款用 aa_root

AA 只能做字符串拼接与 sha256——它无法解析 i128 LE、无法遍历仓位数组。
字符串域树把"证明我有多少钱"压缩成 AA 能完成的两次 sha256 调用。
字节域树则继续承担完整状态承诺（撮合簿、仓位、进度），供 Rust 观察者
全量审计。

---

## 10. vault AA 状态机

AA 地址上的状态变量（`<h>` 为高度数字后缀）：

```
boot, chain_id='operp-mvp-1', last_locked, last_finalized
submitted_at_h, cand_root_h, cand_aa_root_h, cand_prev_h,
  cand_fills_h, cand_who_h                    # 候选（lock 前可替换）
root_h, aa_root_h, stable_at_h               # 已锁定
frozen_h ∈ {∅/0=正常, 1=已挑战, 2=永久失败}
challenger_h, bond_<addr>, fee_winner_h,
reward_<addr>, bal_<addr>(诊断影子账本),
pperp_<addr>(PERP 影子账本，与 bal_ 同地位),
wd_<h>_<addr>                                # 抵押提款累计标记（防证明重放）
wp_<h>_<addr>                                # PERP 提款累计标记（语义与 wd_ 对称）
```

### 10.1 submit(h)

前置：chain_id 正确 ∧ h == last_locked+1 ∧ prev 匹配 root_{h−1}
∧ 有 state_root/aa_root/fills_hash ∧ 未锁定。

副作用：写候选五元组 + submitted_at_h；竞速判定（§11）。

### 10.2 lock(h)

候选存在 ∧ 未锁 ∧ h == last_locked+1 ∧ now ≥ submitted_at_h + 600
→ root/aa_root/winner/stable_at 落定，last_locked = h。锁后不可变。

600s 是 OBYTE_STABILITY_SECS 的模拟（devnet 用 timetravel 测试）。

### 10.3 challenge(h)

root 已锁 ∧ 未冻结 ∧ now < stable_at_h + 3600 ∧ 输出 ≥ 20000 base
→ frozen_h = 1，记录 challenger，收 bond。

### 10.4 respond(h)

身份门：`trigger.address == cand_who_h`（只有提交该候选的账户能应诉）
∧ frozen == 1 ∧ 窗口内 ∧ root_confirmed == root_h
→ 解冻，没收 bond_<challenger> 记录的恰好数额并清零（归 AA 库）。

已知边界：MVP 应诉只校验重发根一致，不能证明根正确——真欺诈 operator
重复自己的假根即可通过。完整方案需要链上重放或有效性证明（README
Limitations #1）。

### 10.5 finalize(h)

两条路：

```
失败路: frozen_h == 1 ∧ 已超窗（operator 未应诉）
        → frozen_h = 2（永久）、root_h/aa_root_h 清零、
          last_locked 回退 h−1；不自动退款——challenger 之后通过
          新的 claim_bond 领回记录在案的 bond
正常路: 根存在 ∧ 未冻结 ∧ 超窗 ∧ h == last_finalized+1
        → last_finalized = h；fee_winner 累加 20000 bytes 奖励（§11）
```

### 10.6 withdraw(h = last_finalized)

```
未冻结 ∧ (height 参数若给必须等于 last_finalized)
amount > 0 ∧ leaf_account == trigger.address
wd_ 累计上限：wd_<h>_<addr> 已提累计 + amount
             ≤ 该高度证明叶子的 collateral（同一证明不可重放，
               多次提款共享同一累计上限；映射上限 65 536 条目）
$perp 为必填 claim 字段（可为 0）；wp_ 累计上限与 wd_ 完全对称：
             wp_<h>_<addr> 累计 + perp_claimed ≤ 叶子声明的 PERP，
             超出 bounce('bad perp claim')；$perp_claimed > 0 才发
             PERP asset 输出
proof 深度 ≤ 16（reduce(...,16,...)，覆盖 2^16 账户）
leaf  = sha256('acct:'+address+':'+collateral+':'+perp, 'hex')
fold proof[]: right ? sha256(acc‖sib,'hex') : sha256(sib‖acc,'hex')
结果 == var['aa_root_' || h]   否则 bounce('bad merkle root')
→ 支付 trigger.address amount（+ $perp_claimed 的 PERP）；
  bal_/pperp_ 同步扣减（仅诊断）
```

余额权威是 **证明叶子**，不是 bal_/pperp_。bal_ 移除门控的原因：
它与 aa_root 是永不严格同步的双账本（费扣口径、批次延迟、回滚都会漂移），
只会产生错误拒付；支付本身由 AA 原生余额机械兜底。

### 10.7 claim_bond / claim_reward

claim_bond：失败高度（frozen = 2）的 challenger 领回记录在案的 bond
——需随单元附带 ≥10000 bytes 支付费用。
claim_reward：领取竞速累积奖励（§11），同样要求附带 ≥10000 bytes。
AA 临时缺币时单元 bounce，记账保留，稍后重试即可——finalize 流程不会
因付款失败而卡死。

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
- 赢家奖励在 finalize 成功路径累加（失败高度不发放），claim_reward 提取
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
| 偷 AA 资金 | 提款只认 finalized aa_root 的 Merkle 证明；leaf 绑定提款人地址；wd_ 累计标记防证明重放 |
| 冒名应诉挑战 | respond 身份门（cand_who 绑定） |
| 存款凭空铸造 | deposits_allowed 白名单 + replay 注入交叉校验 |
| qty/名义额溢出 DoS | 入口 checked-mul + i64 上限 |
| 签名延展 | ed25519 verify_strict |
| 乱序投递丢单元 | orphan 缓冲（4096，最小 UnitId 确定性驱逐）+ 不动点解锁 |
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

## 14. 明确的已知边界

- respond 不能证明根正确（Oscript 无法重放撮合）；作恶 operator 只能
  造成停摆，配合 fee race 由诚实 operator 接管
- 预言机为债券注册制（ORACLE_BOND_PERP = 50_000 PERP，无许可）；报价
  质量取决于质押者的诚实度——按债券计的多数仍可合谋偏置中位数
- 无第三方安全审计；Oscript 复杂度预算迫使逻辑拆分为辅助函数

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

烧毁统一走 `burn_perp`：目前唯一入口是 CreateMarket 的上架费
`CREATE_MARKET_FEE_PERP = 10_000`（预言机罚没为规划项，MVP 未实现）。
烧毁 = 从 `perp_balances` 扣除并累计 `perp_burned` 统计量，**同时等额扣减
`perp_supply`**：supply 定义为可赎回流通量，通缩使后续提案的 quorum
分母随之收缩。

审计对账口径：侧链烧毁只动镜像账本，对应的真实 PERP **永久滞留在 vault
AA 中、不做链上销毁 sweep**——AA 对 PERP 处于超抵押状态。这是有意设计：
可赎回总量按 `perp_supply` 通缩，而链上 AA 余额不减少。对账时切勿把
"AA 持有 > Σ 可赎回"误判为资损缺口；差额恰等于 `perp_burned`。

### 15.5 债券解锁

预言机债券记入 `oracle_bonds`，与可自由支配的 `perp_balances` 分离：进入
债券的 PERP 不计投票权重、不可直接提款。解锁 = 通过 GovWithdraw 提走债券
金额，走与其他 PERP 完全相同的双币种 Merkle 证明出金路径（§10.6）。
`(market, oracle)` 一旦无债券，其最新报价立即退出中位数集合、后续报价被
防御性忽略（§7.2）。MVP 不设解锁延迟/退出排队：撤债即时生效，报价者抽走
债券即同时放弃全部市场的报价资格。
