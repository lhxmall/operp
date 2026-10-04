# OPERP 结算层：现在（纯永续）与以后升级

> 状态：**§2「现在」已实现**（三类职责、四个 AA 实例；`CHAIN_ID=operp-v2`）。
> 精确规则见 [MECHANISMS.md](MECHANISMS.md) §10–11。主网部署脚本
> `deploy_mainnet.js` 就绪，实发待助记词 + 审计。
> 本文记录：纯永续阶段把乐观结算做成什么样，以及以后若做成图灵完备侧链怎么升级。
> 现行实现有 rollup、两个 dispute AA 和 vault；付费否决已删。注意：§1 是旧版背景，
> §3 是未来提案、§6 是历史实施清单；§4 是当前约束、§5 是明确的非目标，均不是
> 当前可自动执行的升级流程。`{force}` 只钉时间戳，
> P-omit 目前恒 bounce `no fraud`，不能作为有效漏单挑战。

---

## 0. 一句话

- **现在（纯永续）：** 谁先稳定谁贴账；揭发必须指出算错的那一笔；主网用哈希 + 加减法当场核对；对不上才罚，对得上动不了真账。
- **以后（提案，尚未实现）：** 金库和提款树不动；换执行引擎、换裁判；若采用，用户需从旧金库按同一套证明提款后再存入新金库。没有自动迁移工具。

金库只认「已敲定的余额树」，不认永续、不知道成交、不参与升级。

---

## 1. 历史背景：移除旧付费否决

早期 v1 的 `challenge`（旧 `operp_vault.aa`）：已 lock、窗内、付 1000 GBYTE
即可立刻 `frozen=2`、清根、回滚高度；AA 不读数据包、不比对根、不要证明。
该付费否决已从当前 v2 移除；当前 `{challenge:1}` 在 rollup/vault 无对应 case。

旧设计的问题是诚实根也能被杀。交易所引擎（DAG、撮合、清算、PERP）没有这个问题——执行已经是确定性的。要重做的是 **贴到 Obyte 之后怎么敲定、怎么抓假账**。

引擎留下。结算层重做。

---

## 2. 现在：纯永续乐观结算

### 2.1 三类职责、四个 AA 实例（第一天就拆开）

Oscript 单次复杂度上限 100，现行金库已占约 76。共识不能再塞进托管。

| 门 | AA | 现在干什么 | 以后换什么 |
|---|---|---|---|
| 金库 | `operp_vault.aa` | 充、提、只认 finalized 的 `aa_forest` | **几乎不改** |
| 记账 | `operp_rollup.aa`（新） | 谁先稳定谁贴根、开窗、收判决 | 主张加 `version`，争议改派 |
| 裁判 | `operp_dispute.aa` + `operp_dispute_fill.aa` | 充提/漏单与成交谓词分别验证 | **两扇均可换掉** 或加新 case |

金库用 `var[ROLLUP_AA]['aa_forest_'||last_finalized]` 读根，自己不记候选、不挑战、不判刑。

没有 owner key、没有 `operators[]`、没有「只有原贴账人能应诉」。

### 2.2 贴批次（based，无许可）

任何人可发一笔 **组合单元**：`temp_data` + `{submit}`。poster 必须已有
`pool_<addr> >= 1e12`（1000 GBYTE）；submit 另付 10000 bytes bounce 费，
不是逐高度提交债。Obyte 上谁先稳定，这个高度就是谁的。已有未失败主张 → `height taken`。

链上主张只存这类字段（不存仓位、不成交）：

```
version = 1
height, prev, state_root, aa_forest,
trace_root, units_root, fills_root,
inbox_upto, da_unit = trigger.unit,
poster, submitted_at = timestamp
```

- 没有独立 `lock`。主网 AA 只被稳定单元触发，submit 到达时已经稳定。窗从 `submitted_at` 起算（`CHALLENGE_SECS`）。
- 没有 `OCCUPANCY_SECS` 替换诚实根。只有裁判判定欺诈，高度才重开。
- `state_root`（字节域）给节点重放、链 `prev`。AA 不验。
- `aa_forest`（hex 域）是 **提款权威**，叶子只承诺钱：`地址 + 抵押 + PERP + 已提`。仓位、挂单不进这棵树。

`temp_data` 里公开：本批 unit、每执行完一笔的 witness 根（≤512，约 32KB）、成交序列。链上只存 §2.2 所列的紧凑承诺根与状态字段，不存完整撮合状态。`TEMP_DATA_PURGE_TIMEOUT = 24h`，揭发时必须把那一笔和证明再交一遍，不能靠 `unit[]` 读已剥掉的 `data`。

### 2.3 主网怎么验（指到那一笔）

主网 **不重跑交易所**。AA 会的只有：sha256、加减乘除、`is_valid_merkle_proof`（复杂度 1）。

揭发者链下用 `Batch::validate_against` 定位第一处分歧，链上只核对他指的那一处。任一可用谓词成立 → 裁判通知记账：`{verdict:'fraud', h}`，主张作废、operator 常备池扣减、高度重开。不成立 → bounce，诚实根不动。

**没有应诉回合。** 贴账的人贴完可以下线。数据已在 L1。

| 谓词 | 证明什么 | 链上做什么 |
|---|---|---|
| P-trace | 第 k 笔的前后根属于 `trace_root`，unit k 属于 `units_root` | 三次 `is_valid_merkle_proof` |
| P-deposit | 充值后该账户抵押不是 +amount | 前后叶子 + 加法 |
| P-withdraw | 提款减法 / nonce 错 | 前后叶子 + 减法 |
| P-escrow | Cancel 退款与抵押变化不符 | 精确核对 post collateral = pre collateral + pre-order `margin_left`；Place escrow 无此分支 |
| P-fill-math | 这一笔成交的抵押/仓位/VWAP 算错 | 2 个账户叶 + 1 个挂单叶 + 算术 |
| P-ghost | 成交打在前状态不存在的挂单上 | 挂单成员证明失败即成立 |
| P-skip | 有更优价时序的活单没吃 | 出示那张更好的活单叶子，比价、比 seq |
| P-omit（禁用） | 设计目标：证明 inbox 中的 unit 未纳入本批 | 当前无可用证明；`force` 只钉时间戳、不能证明 unit 存在，该 case 恒 bounce `no fraud` |

P-skip 替代「在 AA 里重放订单簿」：不必证明「这是最优」，只要证明「存在更优却没成交」。

仓位和挂单放在 **witness 树**（`trace[k]`），不放进提款用的 `aa_forest`。两棵树由同一状态派生，绑在同一主张上：一处假，整高失败。

举例（P-fill-math）：在可验证的普通成交分支中，第 17 笔后 collateral 若应为 480、提交为 500，可用账户/订单证明核对恒等式。不等才构成欺诈；但任何负的预期 collateral 会直接 bounce `no fraud`，ADL kind-2 成交也没有该链上证明分支，不能声称可用此谓词证明。

### 2.4 inbox（记录入口；当前不能证明漏单）

用户可给记账 AA：`{force:1, unit_id}`，inbox 只记录时间戳。该触发不证明
`unit_id` 曾存在，因此当前 P-omit 恒 bounce `no fraud`；这还不是可用的抗审查漏单证明。

当前主张仍记录 `inbox_upto`，但不能据此断言所有时间戳较早的 inbox id 已有可验证存在性；P-omit 的重新启用需先设计该存在性证明。

### 2.5 常备池（资本门槛，不是逐高度债券或许可名单）

| | 当前规则 |
|---|---|
| 提交资格 | `{pool:1}` 为 poster 累积常备池；提交前须 `pool >= 1e12`，无逐高度 submit bond |
| 提交费用 | submit 支付 10000 bytes bounce 费；finalize 不退还所谓提交债 |
| 假揭发 | 谓词不成立即 bounce `no fraud`，**不能冻结诚实根** |
| 成功揭发 | rollup 从 operator 常备池扣 5e11（不足时归零），并记入 challenger 的 `slash_reward`，高度重开 |
| 取回资金 | `{claim:'pool'}` 仅在 `last_submitted == last_finalized` 时可取常备池 |
| 名单 | 无 |

旧版「付 1000 G 即可杀根」与逐高度提交债均非当前机制。

### 2.6 生命周期（高度 h）

```
任何人：先使自己的常备池达到 1e12，再提交组合单元 + 10000 bytes 费用
  → 已有未失败主张？bounce height taken
  → 写下根，3600 秒挑战窗开始（不锁逐高度债券）

窗内任何人：打裁判，带一条谓词
  → bounce：账不动
  → fraud：operator 常备池扣减，主张清掉，h 重开

窗后任何人：{finalize} → last_finalized=h（无提交债退款）
             金库从此对该 aa_forest 付款

7 天无进展：{escape_finalize} 仍在，任意人，不越过未结欺诈
链空闲后 poster 才可 `{claim:'pool'}` 取回常备池
```

---

## 3. 以后：升到图灵完备侧链

「指到那一笔、那个账户」依赖死公式（充值 = 旧 + 金额，成交 = 旧 ± 盈亏）。任意合约没有这种公式，主网算不出「该是多少」，账户级一枪验算就断了。

乐观验证还能用，但「一步」从「一笔成交」变成「一条 VM 指令」：贴账的人承诺指令级（或可二分的）内存根；揭发先对到那一笔，再对到那一条指令；主网只验读格子、加减、写回。这是 Arbitrum / Cannon 那一套。工程量大，需要内存也是树的小虚拟机，不是在现在的 CLOB 引擎上打补丁。

Obyte 单次复杂度仍是 100：验一条指令做得到，验整段程序做不到。图灵完备阶段通常要 **多轮二分**（找到那一条指令），并允许 **任何人代打** 防守，不能绑原贴账人。

**现在不要做 WASM/MIPS。** 纯永续用账户级谓词更简单，揭发也不依赖对方在线。

### 3.1 升级时换什么、不换什么

| | 现在（version=1，纯永续） | 以后（version=2，任意合约） |
|---|---|---|
| 执行 | 现有永续引擎 | 新 VM，新 crate，不是改 CLOB |
| 金库 | 认 `aa_forest` 提款 | 新金库同样只认余额树；旧金库仍能提 |
| 记账 | version=1 + 当前结算承诺根集合 | version=2，争议改派新裁判 |
| 裁判 | P-deposit / P-fill-math / P-skip / P-omit | 换成单指令验证 |
| 提款叶子 | `地址 + 抵押 + PERP + 已提` | 仍是「地址 → 钱」，不加仓位、不加合约存储 |

### 3.2 升级步骤（无管理员一键切）

无 owner。没有原地升级或自动迁移；若部署新 AA，用户需从旧部署按 finalized-root
证明提款，再自行存入新部署。这是可行的用户操作路径，不是内置升级工具。

1. 部署新裁判（和如需要的新记账 / 新金库）。
2. 旧链停在某个高度：不再接受 `submit`，或只许把已过窗的主张 `finalize`。
3. 用户用 **已经 finalize 的证明** 从旧金库提出来，存进新金库（同一套 Merkle 提款）。
4. 新侧链创世 = 旧余额快照，或用户自己再充。

可另做迁移辅助：用户签一次，旧金库付给新金库并在新树记同一余额——仍是用户授权，不是后门。

旧高度永远能按旧规则提。不要在旧 AA 里「热切换」裁判逻辑（复杂度、审计、已锁定主张会对不上）。

### 3.3 主张带版本，别带业务

`version` 决定争议交给哪扇裁判。金库永远只读 `aa_forest`，不读 `version` 的业务含义。

以后加现货、加合约，都是新裁判 + 可选新记账，不是给金库加 `if`。

---

## 4. 去不掉的下限

| 层 | 为什么还在 |
|---|---|
| Obyte 约 12 个 Order Provider | L1 排序；主张等稳定。基于它做「谁先稳定谁贴」 |
| 常备池 | `pool_<addr> >= 1e12` 是提交资本门槛；不是逐高度债券，也不是地址名单 |
| `temp_data` 24h 后删正文 | 揭发必须自带那一笔 |
| 复杂度 100 | 主网验不了整批撮合 / 整段程序，只能验谓词或单指令 |

---

## 5. 明确不做

- 继续「付钱即处决」
- 委员会签根、指定 operator、只有原 poster 应诉
- 链下 DA（IPFS 当数据可用性）
- 把争议塞回现行 `operp_vault.aa`
- 把仓位 / 挂单写进提款叶子
- 现在做 VM、现在做指令级二分
- 靠 `validity_proof_hash` 空槽「以后接 ZK」（Oscript 没有 pairing；升级靠拆门）
- 给金库加 owner 以便升级

---

## 6. 落地顺序（实现时，本文不改代码）

1. 记账 / 裁判 / 金库三拆；提款树只承诺钱；主张带 `version=1`。
2. `wit_root` / `trace_root` / `units_root` / `fills_root` 生成与 `validate_against` 复算。
3. 裁判谓词 + watcher 改打证明，不再广播 `{challenge:1}`。
4. inbox + P-omit。
5. 金库删 submit/lock/challenge；只托管 + 读记账门的 finalized 森林。
6. **以后真要任意合约时：** 新 VM crate、新裁判、新 `CHAIN_ID`、用户迁资金。不要在 1–5 里预埋虚拟机。

`CHAIN_ID` 在结算层切到新协议时换新值。旧金库资金走现有 finalized 提款迁出。
