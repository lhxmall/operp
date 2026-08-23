# ODEX 协议原理

本文深入说明 ODEX（乐观 DAG 侧链永续 DEX，结算到 Obyte）的设计原理与安全机制。
README 是概览；这里是"为什么这样设计"。

术语：

| 符号 | 含义 |
|---|---|
| unit | 用户操作的最小单元：`{parents, op, pubkey, sig}`，id = sha256(canonical bytes) |
| height | 批次序号；每个批次把侧链推进一个高度 |
| operator | 把侧链批次提交到 Obyte AA 的角色（当前为单一 operator） |
| keeper | 触发清算的账户，收取清算奖励 |

---

## 1. 共识层：乐观 DAG + 确定性全序

### 1.1 为什么是 DAG

侧链不跑 BFT 共识。用户把操作签成 unit，引用最多 2 个父单元，形成 DAG。
引擎对"父母都已执行"的 pending 单元按 `unit_id` 字典序执行——这是**确定性全序**：
任何副本拿到同一批单元，无需任何通信即可重放出完全相同的状态。

- **签名即准入**：ed25519 `verify_strict` 拒绝可延展签名；每个 op 的字段与
  签名者公钥绑定（`account_matches`），Deposit/Place/Cancel/Withdraw 必须由
  账户本人签名，Liquidate 由 keeper 签名——自我清算在密码学层就不可能。
- **乱序容忍（orphan 缓冲）**：收到父母未知的子单元时不再丢弃，而是进入
  orphan 缓冲（容量 4096，FIFO 驱逐）。父母到达后自动链接进 pending 集合，
  多级孤儿链按不动点迭代解锁。

### 1.2 执行语义

```
ingest(unit):
  verify_sig(unit)                      # 严格 ed25519
  dag.insert(unit)                      # 校验/缓冲/链接
  apply_ready()                         # 对所有 ready 单元按 id 序 dispatch
```

每个 op 的拒绝原因都是显式枚举值（`DuplicateClientSeq`、`UnbackedDeposit`、
`DuplicateNonce`、`Risk`、`BadAccount`…），全部进入事件日志，重放时可逐条比对。

**client_seq 连续性**：每个账户的 Place 操作携带严格递增的 client_seq
（首笔必须为 1）。这使订单幂等、重放攻击无效，也让"漏发/重发"可被精确检测。

## 2. 撮合层：CLOB 与整数定值

### 2.1 定点数

| 类型 | 缩放 | 说明 |
|---|---|---|
| Price, Qty | u64 × 1e8 | 价格 100_000 USD/BTC = `10_000_000_000_000` |
| Usd (collateral/PnL) | i128 × 1e6 | 微美元精度 |

notional = qty · price / PRICE_SCALE · USD_SCALE / QTY_SCALE

全程无浮点。入口处双重防护：
`qty > i64::MAX` 直接拒；`qty·price` 在 i128 域 checked-mul，溢出即 `Risk`。
这封死了审计中的溢出 DoS：`Place{qty: u64::MAX}` 得到的是干净拒绝而非 panic。

### 2.2 订单簿

价格-时间优先 CLOB：

- 买卖两侧各一棵 `BTreeMap<Price, VecDeque<OrderId>>`（bid 用 Reverse 包装）；
- 同价 FIFO；部分成交后余量留在原队列头部；
- IOC/GTC；taker 与 maker 同账户 = self-trade，取消 taker；
- 每个 price level 维护增量更新的 `visible_qty` 缓存：
  成交扣减、挂单累加、撤单扣减，best_bid/best_ask 读缓存头 → O(log depth)，
  消除了原来 O(深度×队列长) 的扫描。

### 2.3 风险引擎（全仓）

每次成交同时更新 taker/maker 两腿：开仓 VWAP 入场价，平仓实现 PnL。

快照（`Account::snapshot`）计算：

```
mm (maintenance) = 5%   of Σ|qty|·mark     (MM_RATE_BPS = 500)
im (initial)     = 10%  of Σ|qty|·mark     (IM_RATE_BPS = 1000)
equity           = collateral + realized_pnl + unrealized_pnl
liquidatable     : equity·10000 ≤ mm·10500
reduce_only      : equity·10000 ≤ mm·12000
```

开仓前检查 `equity ≥ im + 新增名义额×IM`；提款后检查不得落入 reduce-only。

### 2.4 清算、keeper 与保险基金

- Liquidate 由 keeper 发起（op 内含 `caller` 且验签绑定）；`caller == target`
  返回 `BadAccount` —— 自我清算禁止。
- 清算单是 Market IOC 单吃掉对手盘；仍不干净时剩余仓位以 mark 价与保险基金
  对敲平仓。
- keeper 奖励 = Σ bps(每笔成交名义额, 100)，从保险基金支付。
  保险基金在创世时注入 10 000 USD 种子金，永不参与清算判定（不可被清算、
  不自我清算）。
- **坏账封顶**：清算后若目标账户 equity < 0，缺口记入保险基金 `realized_pnl`
  （负值），同时从该账户扣除等额——损失社会化到基金，绝不转嫁给对手方。
- **mark 名义额门槛**：只有 notional ≥ 100 USD 的成交才更新 mark，
  防止灰尘单操纵清算触发（完整 TWAP 属于 Phase 2）。

### 2.5 市场与存款白名单

- `allowed_markets: HashSet<MarketId>` 默认仅 BTC_USD；place() 在惰性建簿之前
  校验，任意 `MarketId(u32)` 无法撑爆 books / Merkle 叶子集合。
- `deposits_allowed: HashSet<aa_unit>`：deposit op 引用的 AA 存款事件必须出现在
  本批次窗口的白名单里，否则 `UnbackedDeposit` 拒绝——存款不能凭空铸造。
  生产路径中该集合来自真实 Obyte AA 存款事件；replay 时由
  `validate_against` 从批次自身声明的 deposit ops 注入并交叉校验。

## 3. 结算层：双根承诺

每 ~512 units / 2 秒切一个批次，产出 Checkpoint：

```text
{ height, prev_state_hash, state_root, aa_root,
  last_unit, seq, unit_ids, fills_hash, fill_count }
```

### 3.1 state_root（字节域 Merkle 树）

叶子 = 账户叶 ∥ 订单簿叶 ∥ meta 叶，排序后两两合并（奇数复制末位）：

```
account_leaf = sha256("acct" ‖ id32 ‖ collateral_le16 ‖ realized_le16
                      ‖ pos_count_u32 ‖ [market_le4 qty_le8 entry_le8]*)
meta_leaf    = sha256("meta" ‖ height_le ‖ seq_le ‖ last_unit)
```

**meta_leaf 包含 height**，且 `from_applied` 执行后会把 `engine.state.height`
推到 checkpoint.height 再取根——于是 state_root 与高度绑定，
`prev_state_hash` 链条真正具备防重组性质：改历史高度必然断链。

### 3.2 aa_root（字符串域 Merkle 树，专为 AA 设计）

Oscript 的 `sha256()` 对参数的 UTF-8 文本做哈希（默认输出 base64！）。
字节级树无法在 AA 内复算，因此另建一棵**同构但键为字符串**的树：

```
leaf = sha256_hex("acct:" ++ address ++ ":" ++ collateral十进制串)
node = sha256_hex(left ++ right)
```

Rust 侧 `aa_root_of(pairs)` / `aa_proof_for(pairs, addr)` 构造与证明；
AA 侧用纯字符串拼接 + `sha256(x, 'hex')` 复算。两棵树承诺完全相同的
(地址, 抵押) 集合。这个设计经过探针 AA 对拍验证：两边 root 逐字节一致。

### 3.3 fills_hash / fill_count

成交流的规范编码（taker_id‖maker_id‖price‖qty‖seq）哈希。`from_applied` 与
`validate_against` 共享 `fills_bytes()`，replay 时重算比对——operator 漏报/
谎报成交会被直接抓住。

### 3.4 validate_against：任何人可审计

```
assert chain_id == CHAIN_ID          # ChainMismatch
assert replay.state_root == prev     # PrevMismatch
inject deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集合
ingest(units…)                       # BadSig → Replay
recompute fills_hash/fill_count      # FillsMismatch
set replay.height = checkpoint.height
assert replay.state_root == root     # RootMismatch
```

TooManyUnits 上限（512）在 from_applied 就挡住超大批次。

## 4. 治理层：vault AA

状态变量（Oscript）：

```
boot, chain_id, last_locked, last_finalized
submitted_at_h, cand_root_h, cand_aa_root_h, cand_prev_h, cand_fills_h,
  cand_unit_h, cand_who_h        # 候选（lock 前可被替换）
root_h, aa_root_h, winner_h, stable_at_h   # 已锁定根
frozen_h ∈ {∅/0=正常, 1=已挑战, 2=永久失败}
challenger_h, bond_<address>               # 挑战 bond 记账
```

### 生命周期（高度 h）

```
submit(h)    h == last_locked+1 ∧ prev==root_{h-1} ∧ 有根
             → 写 cand_*，记 submitted_at_h = now
             （lock 前允许覆盖：front-run 一个坏候选无法 brick 链）

lock(h)      cand 存在 ∧ 未锁 ∧ now ≥ submitted_at_h + 600s
             → root_h ← cand，stable_at_h = now，last_locked = h
             （模拟 Obyte 稳定窗口；主网上对应真实的 finality）

challenge(h) root_h 锁定 ∧ 未冻结 ∧ now < stable_at_h + 3600s
             ∧ 输出 ≥ 20000 base（含 bounce 费）
             → frozen_h = 1，记 challenger，收 bond

respond(h,r) frozen_h == 1 ∧ 窗口内 ∧ r == root_h
             → 解冻；challenger bond 没收归 AA 库

finalize(h)  分两条路：
             a) frozen_h == 1 且已超窗（operator 未应诉）
                → frozen_h = 2（永久）、root_h/aa_root_h 清空、
                  last_locked 回退 h−1、bond 全额退还 challenger
             b) 正常：!frozen ∧ 超窗 ∧ h == last_finalized+1
                → last_finalized = h（该根成为提款依据，严格按序）

withdraw     h = last_finalized；!frozen_h；
             leaf_account == trigger.address；
             amount ≤ collateral（proof 叶子声明值）∧ amount ≤ bal_;
             leaf = sha256('acct:'+address+':'+collateral, 'hex')
             fold proof[]: right ? sha256(acc‖sib) : sha256(sib‖acc)
             结果 == var['aa_root_' || h] 否则 bounce
             → 支付 trigger.address，bal_ 相应扣减
```

关键安全性质：

- **余额权威是 proof 叶子，不是 bal_ 变量**——即使 operator 或内部账本被腐化，
  提款上限仍被最终化的 Merkle 根钉死。
- **leaf_account == trigger.address**：只能为自己证明，看到别人的证明也无法盗用。
- **无 owner key**：升级 = 部署新 AA + 通过同样的 finalized-root 出金路径迁移。
- 常量注释映射 Rust 权威定义（CHAIN_ID / OBYTE_STABILITY_SECS / CHALLENGE_SECS /
  BOUNCE_FEES / challenge bond），避免双源漂移。

Oscript 实现细节（踩过的坑）：

- `sha256()` 默认输出 **base64**，必须显式 `'hex'` 才能与 Rust hex 域一致；
- `reduce(arr, count, f, init)` 回调签名是 `(acc, index, value)` 三元；
- count 必须是静态字面量（复杂度 = count × 回调复杂度），故证明深度上限 16
  （覆盖 2^16 账户），超出直接 bounce；
- init 里禁止写 state var，只能通过 state message 落盘。

## 5. 威胁模型小结

| 攻击 | 防线 |
|---|---|
| 伪造成交/假根 | 双 Merkle 根 + validate_against 重放审计 + fills_hash |
| 偷 AA 资金 | 提款只认 finalized aa_root 的 Merkle 证明；leaf 绑定提款人地址 |
| operator 锁假根 | 600s 稳定窗 + 3600s 挑战窗 + bond 经济（见 README 局限节） |
| 存款自铸 | deposits_allowed 白名单 + replay 交叉注入 |
| 溢出 DoS | 入口 checked-mul + qty 上限；book 层零量/零价拒绝 |
| 签名延展 | verify_strict |
| 乱序/丢包丢单元 | orphan 缓冲 |

## 6. 已知局限

见 README「Limitations & mainnet readiness」。核心三条：respond 只校验
operator 重发的根（真欺诈证明缺失）、无费用/资金费率模型、mark 来自近期成交
（TWAP 缺位）。主网部署前需解决并做正式 oscript 审计。
