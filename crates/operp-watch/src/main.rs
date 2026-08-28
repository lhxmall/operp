//! `operp-watch` — independent OPERP vault-AA watcher binary.
//!
//! Polls a live Obyte hub for the vault's `last_locked` / `stable_at_<h>` /
//! `frozen_<h>` state, then for every locked height inside its `stable_at+3600`
//! challenge window (and not already frozen) fetches `da_unit_<h>`, verifies
//! the unit↔data binding, and replays the batch. A replay/verify failure is a
//! mismatched root that a watcher-owned wallet should challenge on-chain.
//!
//! The watch contract is read-only: the only AA transaction a watcher may
//! eventually emit is `{challenge:1, height:h}`. The Obyte signing/unit
//! construction backend for that broadcast is a separate deployment concern
//! (the workspace README + MECHANISMS declare the watcher as not-yet-verified
//! until it is run with an independent key against a live hub).

use operp_exec::Engine;
use operp_watch::{
    fetch_da_unit, replay_and_check, verify_da_binding, HubClient, WatchConfig, WatchError,
    CHALLENGE_BOND_GROSS, DEFAULT_POLL_INTERVAL_SECS,
};
use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// HTTP-backed hub client over Obyte's JSON-RPC (`getAaStateVars`,
/// `getJoint`), matching the hub call shapes used by `post_batch.js`.
///
/// Zero new dependencies: a minimal HTTP/1.1 client over `std::net::TcpStream`
/// (the plan's `std` fallback). V1 targets the `http://` testkit hub — no TLS
/// backend is wired; use an https gateway/SSH tunnel for a remote hub.
struct HttpHubClient {
    host: String,
    port: u16,
}

impl HttpHubClient {
    fn new(base: &str) -> Result<Self, anyhow::Error> {
        let rest = base
            .strip_prefix("http://")
            .or_else(|| base.strip_prefix("https://"))
            .unwrap_or(base);
        let rest = rest.split('/').next().unwrap_or("");
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(6611)),
            None => (rest.to_string(), 6611),
        };
        if host.is_empty() {
            return Err(anyhow::anyhow!("invalid hub url: {}", base));
        }
        Ok(Self { host, port })
    }

    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        })
        .to_string();

        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.host,
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&resp).to_string();

        // Split headers from body; honor Content-Length when present.
        let (headers, body) = match text.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => ("", text.as_str()),
        };
        let mut clen = None;
        for line in headers.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    clen = v.trim().parse::<usize>().ok();
                }
            }
        }
        let body = match clen {
            Some(n) if body.len() >= n => body[..n].to_string(),
            _ => body.to_string(),
        };

        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        if let Some(err) = v.get("error").and_then(|e| e.get("message")) {
            return Err(err.as_str().unwrap_or("rpc error").to_string());
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

impl HubClient for HttpHubClient {
    fn get_aa_state_var(
        &self,
        address: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let result = self.rpc("getAaStateVars", serde_json::json!([address, key]))?;
        match result {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::Object(map) => Ok(map.get(key).cloned()),
            other => Ok(Some(other)),
        }
    }

    fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String> {
        let result = self.rpc("getJoint", serde_json::json!([unit_hash]))?;
        if result.is_null() {
            return Err(format!("404: no joint {}", unit_hash));
        }
        Ok(result)
    }
}

struct Args {
    vault: String,
    hub: String,
    from_height: u64,
    poll_interval_secs: u64,
    bond: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut vault = None;
    let mut hub = None;
    let mut from_height = 1u64;
    let mut poll_interval_secs = DEFAULT_POLL_INTERVAL_SECS;
    let mut bond = CHALLENGE_BOND_GROSS;

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--vault" => vault = Some(it.next().ok_or("--vault needs a value")?),
            "--hub" => hub = Some(it.next().ok_or("--hub needs a value")?),
            "--from-height" => {
                from_height = it
                    .next()
                    .ok_or("--from-height needs a value")?
                    .parse()
                    .map_err(|_| "--from-height must be u64")?
            }
            "--poll-interval" => {
                poll_interval_secs = it
                    .next()
                    .ok_or("--poll-interval needs a value")?
                    .parse()
                    .map_err(|_| "--poll-interval must be u64")?
            }
            "--bond" => {
                bond = it
                    .next()
                    .ok_or("--bond needs a value")?
                    .parse()
                    .map_err(|_| "--bond must be u64")?
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {}", other)),
        }
    }

    Ok(Args {
        vault: vault.ok_or("missing --vault")?,
        hub: hub.ok_or("missing --hub")?,
        from_height,
        poll_interval_secs,
        bond,
    })
}

fn print_usage() {
    eprintln!(
        "operp-watch --vault <aa-addr> --hub <hub-url> [--from-height <u64>] \
[--poll-interval <secs>] [--bond <gross-bytes>]\n\
\n\
Polls the vault's da_unit_<h> batches, replays each locked height, and flags any\n\
root mismatch inside the stable_at+3600 challenge window for a watcher-owned\n\
wallet to challenge. Wallet key/start-stop are intentionally separate from\n\
post_batch.js (OPERP_WATCH_MNEMONIC / a separate process)."
    );
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Replay one height and advance the engine; surface only actionable alerts.
/// Returns `Ok(None)` = nothing actionable (no da_unit, or replay clean),
/// `Ok(Some(alert))` = a mismatch worth surfacing.
fn check_height(
    hub: &HttpHubClient,
    config: &WatchConfig,
    engine: &mut Engine,
    h: u64,
    now: u64,
) -> anyhow::Result<Option<String>> {
    let sa_key = format!("stable_at_{}", h);
    let frozen_key = format!("frozen_{}", h);
    let sa = hub
        .get_aa_state_var(&config.vault_address, &sa_key)
        .map_err(|e| anyhow::anyhow!("hub: {}", e))?;
    let frozen = hub
        .get_aa_state_var(&config.vault_address, &frozen_key)
        .map_err(|e| anyhow::anyhow!("hub: {}", e))?;
    let sa_val = sa.and_then(|v| v.as_u64()).unwrap_or(0);
    let frozen_val = frozen.and_then(|v| v.as_u64()).unwrap_or(0);
    let in_window = sa_val != 0 && now < sa_val + 3600 && frozen_val == 0;

    let da = match fetch_da_unit(hub, &config.vault_address, h) {
        Ok(None) => return Ok(None),
        Ok(Some(da)) => da,
        Err(WatchError::HubUnavailable(_)) => return Ok(None), // backoff, never mis-challenge
        Err(WatchError::BindingMismatch(msg)) => {
            let alert = format!("h={} BINDING MISMATCH: {}", h, msg);
            if in_window {
                maybe_post_challenge(config, h, &alert);
            }
            return Ok(Some(alert));
        }
        Err(e) => return Ok(Some(format!("h={} WATCH ERROR: {}", h, e))),
    };

    if let Err(e) = verify_da_binding(&da) {
        let alert = format!("h={} BINDING MISMATCH: {}", h, e);
        if in_window {
            maybe_post_challenge(config, h, &alert);
        }
        return Ok(Some(alert));
    }

    let prev_root = engine.state.state_root();
    match replay_and_check(&da, prev_root, engine) {
        Ok(()) => Ok(None),
        Err(e) => {
            if in_window {
                let alert = format!(
                    "h={} ROOT MISMATCH ({}): watcher should challenge with {} bytes bond",
                    h, e, config.challenge_bond_gross
                );
                maybe_post_challenge(config, h, &alert);
                Ok(Some(alert))
            } else {
                Ok(Some(format!(
                    "h={} ROOT MISMATCH ({}): outside challenge window (informational)",
                    h, e
                )))
            }
        }
    }
}

/// If `OPERP_WATCH_MNEMONIC` is set, spawn `obyte-local/post_challenge.js`.
/// Unset mnemonic → print-only (caller already prints the alert).
fn maybe_post_challenge(config: &WatchConfig, h: u64, alert: &str) {
    if env::var_os("OPERP_WATCH_MNEMONIC").is_none() {
        eprintln!(
            "WATCH ALERT (print-only, no OPERP_WATCH_MNEMONIC): {}",
            alert
        );
        return;
    }
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local/post_challenge.js");
    let hub = config
        .hub_url
        .clone()
        .unwrap_or_else(|| "127.0.0.1:6611".into());
    let h_s = h.to_string();
    eprintln!(
        "spawning: node {} --vault {} --height {} --hub {}",
        script.display(),
        config.vault_address,
        h,
        hub
    );
    match Command::new("node")
        .args([
            script.as_os_str(),
            std::ffi::OsStr::new("--vault"),
            std::ffi::OsStr::new(&config.vault_address),
            std::ffi::OsStr::new("--height"),
            std::ffi::OsStr::new(&h_s),
            std::ffi::OsStr::new("--hub"),
            std::ffi::OsStr::new(&hub),
        ])
        .status()
    {
        Ok(st) if st.success() => {}
        Ok(st) => eprintln!("post_challenge.js exited {}", st),
        Err(e) => eprintln!("post_challenge.js spawn failed: {}", e),
    }
}

fn main() -> anyhow::Result<()> {
    let args = parse_args().map_err(|e| anyhow::anyhow!(e))?;
    let hub = HttpHubClient::new(&args.hub)?;
    let config = WatchConfig {
        vault_address: args.vault.clone(),
        hub_url: Some(args.hub.clone()),
        poll_interval_secs: args.poll_interval_secs,
        challenge_bond_gross: args.bond,
    };
    // Replay engine starts at genesis; heights above a replay gap fail with
    // PrevMismatch until the earlier chain has been replayed — exactly the
    // mismatch surfaced to the caller.
    let mut engine = Engine::new();

    println!(
        "operp-watch: watching {} via {} — every {}s, challenge window stable_at+3600, bond {}",
        config.vault_address, args.hub, config.poll_interval_secs, config.challenge_bond_gross
    );

    loop {
        let now = now_ms();
        let ll = hub
            .get_aa_state_var(&config.vault_address, "last_locked")
            .map_err(|e| anyhow::anyhow!("hub last_locked: {}", e))?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        for h in args.from_height..=ll {
            match check_height(&hub, &config, &mut engine, h, now) {
                Ok(None) => {}
                Ok(Some(msg)) => println!("WATCH ALERT: {}", msg),
                Err(e) => println!("WATCH ERROR at h={}: {}", h, e),
            }
        }

        std::thread::sleep(Duration::from_secs(config.poll_interval_secs));
    }
}
