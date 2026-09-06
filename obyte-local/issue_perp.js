"use strict";

// OPERP PERP issuance helper — Obyte MAINNET.
//
// Posts app:"asset" defining the PERP governance asset (capless issue,
// transferable, public) from the deployer mnemonic and prints the new
// asset unit id — that id IS `PERP_ASSET_ID` for deploy_mainnet.js.
//
//   OPERP_DEPLOY_MNEMONIC="word word ... " node obyte-local/issue_perp.js
//
// Runs a light headless wallet against the default mainnet hub
// (obyte.org/bb). Needs funded GBYTE for fees. No mint beyond the
// issuer's initial capless issue (mint later with the issuer wallet).

const { boot } = require("./mainnet_wallet.js");

async function main() {
  const { wallet, address, composer, network, objectHash } = await boot();
  console.log("issuer address:", address);

  // Asset definition per vendor/ocore/test/samples/create_an_asset.oscript
  // and validation.js: uncapped = ABSENT cap field (a present cap must be
  // a positive integer <= MAX_CAP 9e15). Issuer mints on demand later.
  const definition = {
    is_private: false,
    is_transferrable: true,
    auto_destroy: false,
    fixed_denominations: false,
    issued_by_definer_only: true,
    cosigned_by_definer: false,
    spender_attested: false,
  };

  const objJoint = await new Promise((resolve, reject) => {
    const message = {
      app: "asset",
      payload_location: "inline",
      payload_hash: objectHash.getBase64Hash(definition),
      payload: definition,
    };
    composer.composeJoint({
      paying_addresses: [address],
      outputs: [{ address, amount: 0 }],
      messages: [message],
      signer: wallet.signer,
      callbacks: composer.getSavingCallbacks({
        ifNotEnoughFunds: reject,
        ifError: reject,
        ifOk: resolve,
      }),
    });
  });
  network.broadcastJoint(objJoint);
  const unit = objJoint.unit.unit;
  console.log("asset definition unit:", unit);
  // The asset id is the unit hash of the definition unit.
  console.log("PERP_ASSET_ID=" + unit);
  process.exit(0);
}

main().catch((e) => {
  console.error("ISSUE FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
