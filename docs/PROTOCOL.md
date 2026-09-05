# OPERP 协议原理

> 本文是设计动机的叙事版。逐条规则的精确参考（常量、边界情况、
> 威胁模型矩阵）见 [MECHANISMS.md](MECHANISMS.md)。


本文深入说明 OPERP（乐观 DAG 侧链永续 DEX，结算到 Obyte）的设计原理与安全机制。
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
  orphan 缓冲（容量 4096，超出按盐化序 `argmin(sha256(salt ‖ unit_id))`
  驱逐；盐由最后最终化根与 epoch 派生。执行序本身是 `unit_id` 字典序、
  已去盐）。父母到达后自动链接进 pending 集合，多级孤儿链按不动点迭代解锁。

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
equity           = collateral + unrealized_pnl
                   （已实现 PnL 平仓即结算进 collateral）
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
- **坏账封顶**：成交后若 taker equity < 0，其 equity 被钳到恰好 0
  （collateral 吸收缺口），保险基金 collateral 等额扣减——守恒、且后续
  成交不会重复触发。损失社会化到基金，绝不转嫁对手方。
- **mark 三重防线**：① notional ≥ 100 USD 才可更新；② 新价相对旧 mark
  偏离不得超过 ±10%；③ 一旦市场有债券注册报价者的报价（`Op::ReportPrice`，
  全部已质押报价者最新价的**中位数**，§7），成交价即失去 mark 定价权。
  资金费率：有效报告数 ≥ 2 时每次 report 触发一次结算，按
  (spot − index)/index（钳 ±50bps）在多空之间转移。付款方借记被钳在其
  可用抵押内，收款方入账以实际扣减总额封顶——严格守恒、不产生负余额；
  保险基金作为普通账户参与（可持有清算对冲仓位）。

### 2.5 市场准入与存款白名单

- 市场无许可上架：`markets: BTreeMap<MarketId, MarketParams>` 创世仅含
  BTC_USD，其余任何人可经 CreateMarket 烧毁 `CREATE_MARKET_FEE_PERP` 上架费
  创建（IM/MM/费率成为每市场参数）——上架有真实成本，任意 `MarketId(u32)`
  无法撑爆 books / Merkle 叶子集合。
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
account_leaf = sha256("acct" ‖ id32 ‖ collateral_i128le16 ‖ realized_i128le16
                      ‖ pos_count_u32 ‖ [market_le4 qty_le8 entry_le8]*
                      ‖ perp_u128le16)
               # perp = PERP 治理余额（§7），与抵押并列进入承诺
book_leaf    = sha256(params_57B ‖ 簿承诺)
               # params_57B = symbol16‖tick_le8‖im_le8‖mm_le8‖taker_le8
               #   ‖keeper_le8‖delisted1B——市场参数本身成为被承诺状态
meta_leaf    = sha256("meta" ‖ height_le ‖ seq_le ‖ last_unit
                      ‖ perp_burned_le16 ‖ next_market_id_le4
                      ‖ next_proposal_id_le8)
               # 治理游标一并承诺，防重放歧义
```

**meta_leaf 包含 height**，且 `from_applied` 执行后会把 `engine.state.height`
推到 checkpoint.height 再取根——于是 state_root 与高度绑定，
`prev_state_hash` 链条真正具备防重组性质：改历史高度必然断链。

### 3.2 aa_root（字符串域分片森林，专为 AA 设计）

Oscript 的 `sha256()` 对参数的 UTF-8 文本做哈希（默认输出 base64！）。
字节级树无法在 AA 内复算，因此另建一棵**同构但键为字符串**的树，并打成
**16 棵 shard 树拼接的 1024-hex `aa_forest`**：

```
leaf = sha256_hex("acct:" ++ address ++ ":" ++ collateral十进制串
                  ++ ":" ++ perp十进制串 ++ ":" ++ withdrawn十进制串)
node = sha256_hex(left ++ right)
aa_forest = shard0_root ‖ … ‖ shard15_root     # 恰好 1024 hex
```

Rust 侧 `aa_sharded_forest` / `aa_sharded_proof_for_account` 构造与证明；
AA 侧用纯字符串拼接 + `sha256(x, 'hex')` 在声明的 shard 内复算，再
`substring(shard*64, 64)` 取出该 shard 根。两棵承诺完全相同的
(地址, 抵押, PERP, W) 集合。空 shard 提交哨兵根
`hex(sha256("empty:<shard>"))`，零证明无法跨 shard 跳动。

### 3.3 fills_hash / fill_count

成交流的规范编码（taker_id‖maker_id‖price‖qty‖seq）哈希。`from_applied` 与
`validate_against` 共享 `fills_bytes()`，replay 时重算比对——operator 漏报/
谎报成交会被直接抓住。

```
assert chain_id == CHAIN_ID          # ChainMismatch
assert replay.state_root == prev     # PrevMismatch
inject deposits_allowed ← batch 内 Deposit ops 的 aa_unit 集合
ingest(units…)                       # BadSig → Replay
recompute fills_hash/fill_count      # FillsMismatch
assert checkpoint.height == replay.height + 1
set replay.height = checkpoint.height
assert last_unit 一致 ∧ replay.state_root == root   # RootMismatch
```

TooManyUnits 上限（512）在 from_applied 就挡住超大批次。

## 4. 结算层：三个 AA（CHAIN_ID=operp-v2）

状态变量（rollup AA；`<h>` 为高度后缀）：

```
last_submitted, last_finalized, dispute_aa, dispute_fill_aa
submitted_at_h, state_root_h, aa_forest_h (1024 hex), prev_h,
  wit_root_h, trace_root_h, units_root_h, units_set_root_h,
  ops_root_h, fills_root_h, unit_count_h, wit_count_h
da_unit_h                     # DA 绑定 = 组合单元 hash
active_bond_h, fee_winner_h, frozen_h ∈ {∅=live, 2=failed}
inbox_<unit_id_hex>, inbox_upto_h
sbond_<addr>, reward_<addr>, slash_reward_<addr>
```

侧链 ChainState（PERP 治理，§7）不变：markets、perp_balances/supply/burned、
proposals、oracle 账本。金库 vault AA 只有 `deposit` / `withdraw`，提款读
`var[ROLLUP]['aa_forest_'||last_finalized]`。

### 生命周期（高度 h）

```
submit(h)    h == last_submitted+1 ∧ chain_id='operp-v2' ∧ 双根 + 六个 44-char
             承诺根 ∧ 组合单元（temp_data 在同一 unit）
             ∧ 输出-10000 ≥ 1000000000000（SUBMIT_BOND_NET）
             → 写全部 <h> 键、da_unit_h=trigger.unit、last_submitted=h；
               已占位且 frozen≠2 → bounce('height taken')；
               prev 必须等于上一高度 state_root（除非上一高度已 frozen=2）

fraud(h)     窗内（submitted_at+3600）任何人打 dispute / dispute_fill：
             deposit | withdraw | omit | fill_math | ghost | skip
             验不过 → bounce('no fraud')，高度不动；
             验过 → dispute 付 10000 bytes + {verdict:'fraud',height,challenger}
               → rollup frozen_h=2、清根、last_submitted=h-1、
                 slash_reward_<challenger> += 500000000000

finalize(h)  !frozen ∧ h == last_finalized+1 ∧ now ≥ submitted_at_h+3600
             （escape_finalize 用 604800）
             → last_finalized=h；sbond_<active_bond> += 1e12；reward += 20000

withdraw     vault：leaf_account==trigger.address；
             amount + wd_<addr> ≤ min(collateral, withdrawn)；
             leaf = sha256('acct:'+address+':'+collateral+':'+perp+':'+withdrawn,'hex')
             reduce(...,16,...) == substring(aa_forest_h, shard*64, 64)
             → 支付并累加 wd_/wp_

force(id)    rollup：{force, unit_id 64hex} → inbox_<id>=timestamp；
             主张必须把 inbox_upto 之前的 id 全收进 units_set_root，
             漏收 = P-omit 欺诈
```

**没有 lock，没有 `{challenge:1}`，没有应诉。** 揭发必须算对那一笔；
诚实根杀不掉。债券是资本门槛，不是许可名单。

关键安全性质：

- **余额权威是 proof 叶子**——operator 腐化也改不了提款上限。
- **leaf_account == trigger.address**：只能为自己证明。
- **无 owner key**：升级 = 部署新 AA + 同一 finalized 提款路径迁资金。
- 常量注释映射 Rust 权威定义（CHAIN_ID / SUBMIT_BOND_NET / CHALLENGE_SECS /
  ESCAPE_STALL_SECS），避免双源漂移。

Oscript 实现细节（踩过的坑）：

- `sha256()` 默认输出 **base64**，必须显式 `'hex'` 才能与 Rust hex 域一致；
- `reduce(arr, count, f, init)` 回调签名是 `(acc, index, value)` 三元；
- count 必须是静态字面量（复杂度 = count × 回调复杂度），故证明深度上限 16
  （覆盖 2^16 账户），超出直接 bounce；
- init 里禁止写 state var，只能通过 state message 落盘。

## 5. 威胁模型小结

| 攻击 | 防线 |
|---|---|
| 伪造成交/假根 | 双 Merkle 根 + validate_against 重放 + 一枪谓词（含 fill_math/ghost/skip） |
| 偷 AA 资金 | 提款只认 finalized 森林的 Merkle 证明；leaf 绑定地址；wd_/wp_ 防重放 |
| 付钱杀根 | 已删除：challenge 无 case；假证明 bounce `no fraud` |
| 审查 | rollup inbox `{force}` + P-omit |
| 存款自铸 | deposits_allowed 白名单 + replay 交叉注入 + evidence 绑定 `OPERP_VAULT_AA` |
| 溢出 DoS / 签名延展 / 乱序 | 入口 checked-mul / verify_strict / orphan 缓冲 |

## 6. 已知局限

见 README「局限与主网就绪度」。付钱否决已删；仍未链上验：保险钳制、
fill_math ±1 容差、24h temp_data 正文。默认执行序 UnitId 字典序
（v2 commit-reveal 高度 0 生效）；报价质量受债券多数约束。
主网部署前需正式 oscript 审计。「纯永续 → 图灵完备」升级路径见
[ROLLUP-UPGRADE.md](ROLLUP-UPGRADE.md)。

## 7. 治理动机：PERP

把白名单换成资产。协议最初的三处中心化硬编码——市场准入
（`allowed_markets`）、预言机来源（`trusted_oracles`）、风险费率——分别由
PERP 的三个机制接管：

- **无许可市场上架**：上架成本 = 烧毁 10 000 PERP。烧毁而非收费，意味着
  上架费不流向任何受益人（没有"收钱上架"的寻租空间），而是让全体持有者
  的流通量通缩；同时给垃圾市场一个真实价格门槛。
- **债券注册制预言机**：报价资格 = 质押 50 000 PERP 债券。债券是皮肤在
  游戏里的押金——为未来的罚没路径预留；中位数聚合让单点操纵无效，腐化
  必须收买按债券计的多数。
- **链上提案投票**：参数修改（IM/MM/费率/Delist）走 CreateProposal → Vote →
  FinalizeProposal，全部是普通签名 unit、按 DAG 确定性线性化执行——治理
  不需要新的共识机制，重放即审计。投票权重取投票执行时刻的余额（MVP
  语义，避免存整份快照映射）；quorum 分母用创建时的 `supply_at_create`
  快照，保证通过判定与重放时刻的流通量无关。

记账上 PERP 走侧链镜像（复用 vault AA 与双 Merkle 树，叶子各加一段 perp
字段），烧毁只在镜像账本进行——对应真实 PERP 永久滞留 AA，协议整体对
PERP 超抵押。精确规则见 [MECHANISMS.md](MECHANISMS.md) §15。

> **Watcher：** `crates/operp-watch` 离线重放 `da_unit_<h>`，定位第一处分歧后组
> `proof.json`，经 `post_challenge.js` 打 dispute AA（`--pred --proof`；
> `OPERP_WATCH_MNEMONIC`，与 poster 分钥）。
