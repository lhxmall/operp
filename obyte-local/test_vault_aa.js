"use strict";

const path = require("path");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
process.env.devnet = "1";

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata"),
  NETWORK_PORT: 16612,
});

async function main() {
  const network = await Network.create()
    .with.agent({ vault: path.join(__dirname, "agents/odex_vault.aa") })
    .with.wallet({ alice: 1e9 })
    .with.wallet({ bob: 1e9 })
    .run();

  const vault = network.agent.vault;
  const alice = network.wallet.alice;
  const bob = network.wallet.bob;
  console.log("vault", vault);
  console.log("alice", await alice.getAddress());

  let { unit, error } = await alice.triggerAaWithData({
    toAddress: vault,
    amount: 1e6,
    data: { deposit: 1 },
  });
  if (error) throw new Error("deposit: " + error);
  await network.witnessUntilStable(unit);
  console.log("deposited", unit);

  const vars1 = await alice.readAAStateVars(vault);
  console.log("vars after deposit", vars1);

  const root1 = "root_height_1_example";
  ({ unit, error } = await bob.triggerAaWithData({
    toAddress: vault,
    amount: 10000,
    data: {
      submit: 1,
      chain_id: "odex-mvp-1",
      height: 1,
      prev_state_hash: "0",
      state_root: root1,
      fills_hash: "fills1",
    },
  }));
  if (error) throw new Error("submit: " + error);
  await network.witnessUntilStable(unit);
  console.log("submitted", unit);

  ({ unit, error } = await bob.triggerAaWithData({
    toAddress: vault,
    amount: 10000,
    data: { lock: 1, height: 1 },
  }));
  if (error) throw new Error("lock: " + error);
  await network.witnessUntilStable(unit);
  console.log("locked", unit);

  const vars2 = await alice.readAAStateVars(vault);
  console.log("vars after lock", vars2);
  if (!vars2.vars && !vars2["root_1"] && !(vars2 && (vars2.root_1 || (vars2.vars && vars2.vars.root_1)))) {
    console.log("raw vars2 keys", Object.keys(vars2));
  }

  const aliceAddr = await alice.getAddress();
  const balKey = "bal_" + aliceAddr;
  const state = vars2.vars || vars2;
  const bal = state[balKey];
  console.log("alice vault bal", bal);

  ({ unit, error } = await alice.triggerAaWithData({
    toAddress: vault,
    amount: 10000,
    data: { withdraw: 1, amount: 1000 },
  }));
  if (error) throw new Error("withdraw: " + error);
  await network.witnessUntilStable(unit);
  console.log("withdrew", unit);

  const vars3 = await alice.readAAStateVars(vault);
  console.log("vars after withdraw", vars3);
  console.log("OK: vault AA deposit/submit/lock/withdraw");
  await network.stop();
}

main().catch((e) => {
  console.error("FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
