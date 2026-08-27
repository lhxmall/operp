use serde_json::Value;
use sha2::{Digest, Sha256};

fn is_legacy_version(v: &str) -> bool {
    v == "1.0" || v == "1.0t" || v == "1.0dev"
}

fn version_is_legacy(unit: &Value) -> bool {
    if let Some(v) = unit.get("version").and_then(|x| x.as_str()) {
        is_legacy_version(v)
    } else {
        // missing version considered not legacy (use json)
        false
    }
}

// ---- getSourceString (legacy) ----
fn get_source_string(v: &Value) -> Result<String, String> {
    let mut comps: Vec<String> = Vec::new();
    fn extract(val: &Value, comps: &mut Vec<String>, root: &Value) -> Result<(), String> {
        if val.is_null() {
            return Err(format!("null value in {}", root));
        }
        match val {
            Value::String(s) => {
                if s.contains('\x00') {
                    return Err(format!("00 byte in string value in {}", root));
                }
                comps.push("s".to_string());
                comps.push(s.clone());
            }
            Value::Number(n) => {
                comps.push("n".to_string());
                comps.push(canonical_number(n)?);
            }
            Value::Bool(b) => {
                comps.push("b".to_string());
                comps.push(b.to_string());
            }
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Err(format!("empty array in {}", root));
                }
                comps.push("[".to_string());
                for el in arr {
                    extract(el, comps, root)?;
                }
                comps.push("]".to_string());
            }
            Value::Object(map) => {
                if map.is_empty() {
                    return Err(format!("empty object in {}", root));
                }
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    if k.contains('\x00') {
                        return Err(format!("00 byte in object key in {}", root));
                    }
                    if map.get(k).is_none() {
                        return Err(format!("undefined at {} of {}", k, root));
                    }
                    comps.push(k.clone());
                    extract(map.get(k).unwrap(), comps, root)?;
                }
            }
            Value::Null => unreachable!(),
        }
        Ok(())
    }
    extract(v, &mut comps, v)?;
    Ok(comps.join("\x00"))
}

// ---- getJsonSourceString ----
fn to_well_formed_json_string(s: &str) -> String {
    // serde_json correctly escapes; lone surrogate replacement not needed for valid UTF-8
    // Use serde_json to quote the string
    serde_json::to_string(s).unwrap()
}

/// Ocore's JS number-to-string rules, fail-closed. JS observers and this
/// Rust port must never disagree on hash input, so any Number whose serde
/// textual form could diverge from JavaScript's output is rejected outright:
/// - integers representable as i64/u64 print as bare decimal digits;
/// - non-integral f64 within safe range prints via `to_string()`;
/// - everything else (`1.0` → JS `"1"`, `-0.0`, |x| > 2^53 precision loss,
///   |x| >= 1e21 exponential-form divergence) is an error.
fn canonical_number(n: &serde_json::Number) -> Result<String, String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    let f = n.as_f64().ok_or_else(|| format!("invalid number: {n}"))?;
    if !f.is_finite() || f.fract() == 0.0 || f.abs() > 9_007_199_254_740_992.0 || f.abs() >= 1e21 {
        return Err(format!("number {n} has no unambiguous JS canonical string"));
    }
    Ok(f.to_string())
}

fn get_json_source_string(v: &Value) -> Result<String, String> {
    fn stringify(val: &Value, root: &Value, allow_empty: bool) -> Result<String, String> {
        if val.is_null() {
            return Err(format!("null value in {}", root));
        }
        match val {
            Value::String(s) => Ok(to_well_formed_json_string(s)),
            Value::Number(n) => Ok(canonical_number(n)?),
            Value::Bool(b) => Ok(b.to_string()),
            Value::Array(arr) => {
                if arr.is_empty() && !allow_empty {
                    return Err(format!("empty array in {}", root));
                }
                let mut parts = Vec::with_capacity(arr.len());
                for el in arr {
                    parts.push(stringify(el, root, allow_empty)?);
                }
                Ok(format!("[{}]", parts.join(",")))
            }
            Value::Object(map) => {
                if map.is_empty() && !allow_empty {
                    return Err(format!("empty object in {}", root));
                }
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut parts = Vec::with_capacity(keys.len());
                for k in keys {
                    let v = map.get(k).unwrap();
                    let ks = to_well_formed_json_string(k);
                    let vs = stringify(v, root, allow_empty)?;
                    parts.push(format!("{}:{}", ks, vs));
                }
                Ok(format!("{{{}}}", parts.join(",")))
            }
            Value::Null => unreachable!(),
        }
    }
    stringify(v, v, false)
}

fn get_base64_hash(obj: &Value, b_json_based: bool) -> Result<Vec<u8>, String> {
    let source = if b_json_based {
        get_json_source_string(obj)?
    } else {
        get_source_string(obj)?
    };
    let hash = Sha256::digest(source.as_bytes());
    Ok(hash.to_vec())
}

/// Canonical Obyte JSON source of `v` (ocore `string_utils.getJsonSource`):
/// object keys recursively sorted lexicographically, arrays order-preserving,
/// minified, numbers via ocore's toString rules. Panics on values the Obyte
/// canonical form rejects (nulls, empty containers) — temp_data payloads are
/// always well-formed.
pub fn get_json_source(v: &Value) -> String {
    get_json_source_string(v).expect("value has an Obyte canonical JSON source")
}

/// data_hash = sha256(get_json_source(v)), hex-encoded by callers.
pub fn get_data_hash(v: &Value) -> [u8; 32] {
    Sha256::digest(get_json_source(v).as_bytes()).into()
}

// ---- naked / stripped ----
fn get_naked_unit(unit: &Value) -> Value {
    let mut naked = unit.clone();
    if let Value::Object(ref mut map) = naked {
        map.remove("unit");
        map.remove("headers_commission");
        map.remove("payload_commission");
        map.remove("oversize_fee");
        map.remove("actual_tps_fee");
        map.remove("main_chain_index");
        // version check uses original unit's version, not naked's
        let is_legacy = version_is_legacy(unit);
        if is_legacy {
            map.remove("timestamp");
        }
        if let Some(messages) = map.get_mut("messages") {
            if let Value::Array(ref mut arr) = messages {
                for msg in arr.iter_mut() {
                    if let Value::Object(ref mut m) = msg {
                        m.remove("payload");
                        m.remove("payload_uri");
                    }
                }
            }
        }
    }
    naked
}

fn get_unit_content_hash(unit: &Value) -> Result<String, String> {
    let naked = get_naked_unit(unit);
    let b_version2 = !version_is_legacy(unit);
    let hash_bytes = get_base64_hash(&naked, b_version2)?;
    // base64 standard encoding with padding
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&hash_bytes);
    Ok(b64)
}

fn get_stripped_unit(unit: &Value) -> Result<Value, String> {
    let b_version2 = !version_is_legacy(unit);
    let content_hash = get_unit_content_hash(unit)?;
    let mut map = serde_json::Map::new();
    map.insert("content_hash".to_string(), Value::String(content_hash));
    if let Some(v) = unit.get("version") {
        map.insert("version".to_string(), v.clone());
    }
    if let Some(a) = unit.get("alt") {
        map.insert("alt".to_string(), a.clone());
    }
    if let Some(authors) = unit.get("authors").and_then(|x| x.as_array()) {
        let mut new_authors = Vec::new();
        for a in authors {
            let addr = a.get("address").cloned().unwrap_or(Value::Null);
            let mut m = serde_json::Map::new();
            m.insert("address".to_string(), addr);
            new_authors.push(Value::Object(m));
        }
        map.insert("authors".to_string(), Value::Array(new_authors));
    }
    if let Some(wlu) = unit.get("witness_list_unit") {
        map.insert("witness_list_unit".to_string(), wlu.clone());
    } else if let Some(w) = unit.get("witnesses") {
        map.insert("witnesses".to_string(), w.clone());
    }
    if let Some(pu) = unit.get("parent_units") {
        map.insert("parent_units".to_string(), pu.clone());
        if let Some(lb) = unit.get("last_ball") {
            map.insert("last_ball".to_string(), lb.clone());
        }
        if let Some(lbu) = unit.get("last_ball_unit") {
            map.insert("last_ball_unit".to_string(), lbu.clone());
        }
    }
    if b_version2 {
        if let Some(ts) = unit.get("timestamp") {
            map.insert("timestamp".to_string(), ts.clone());
        }
    }
    Ok(Value::Object(map))
}

/// Compute Obyte unit hash bytes (32) from a joint or unit value.
/// Accepts either `{ unit: {...}, ...}` or the unit object itself.
pub fn get_unit_hash(joint: &Value) -> Result<[u8; 32], String> {
    let unit = if let Some(u) = joint.get("unit") {
        u
    } else {
        joint
    };
    if !unit.is_object() {
        return Err("unit is not an object".to_string());
    }
    let b_version2 = !version_is_legacy(unit);
    let hash_bytes = if unit.get("content_hash").is_some() {
        // already stripped
        let naked = get_naked_unit(unit);
        get_base64_hash(&naked, b_version2)?
    } else {
        let stripped = get_stripped_unit(unit)?;
        get_base64_hash(&stripped, b_version2)?
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_source_sorts_keys() {
        let v = json!({"b":2, "a":1});
        let s = get_json_source_string(&v).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn source_string_simple() {
        let v = json!({"a":"x"});
        let s = get_source_string(&v).unwrap();
        // a + \x00 + s + \x00 + x
        assert_eq!(s, "a\x00s\x00x");
    }

    #[test]
    fn unit_hash_deterministic() {
        // Minimal unit with version 4.0dev (json-based hash path).
        // parent_units must be non-empty: ocore getJsonSourceString rejects
        // empty arrays (string_utils.js bAllowEmpty falsy), so a real unit
        // always references at least one parent.
        let unit = json!({
            "version":"4.0dev",
            "alt":"3",
            "authors":[{"address":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],
            "messages":[{"app":"payment","payload":{"outputs":[{"address":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","amount":10000}]}}],
            "parent_units":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "last_ball":"abc",
            "last_ball_unit":"def",
            "timestamp": 1234567890
        });
        let h1 = get_unit_hash(&unit).unwrap();
        // Provide minimal required fields: but our naked will strip payload -> messages becomes [{app:"payment"}]
        // hash should be stable and not error
        let h1 = get_unit_hash(&unit).unwrap();
        let h2 = get_unit_hash(&unit).unwrap();
        assert_eq!(h1, h2);
        // Different content -> different hash
        let mut unit2 = unit.clone();
        if let Value::Object(ref mut m) = unit2 {
            m.insert("timestamp".to_string(), json!(1234567891));
        }
        let h3 = get_unit_hash(&unit2).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn golden_vector_matches_ocore_get_json_source() {
        // Cross-checked against obyte-local/golden_vector_check.js, whose
        // fixed input now also carries a big decimal STRING (>2^53 travels
        // as a string: bare numbers that size are rejected Rust-side) and a
        // short decimal number. The JS output for this exact input must stay
        // byte-identical with `get_data_hash` — re-run both sides together.
        let v: Value = serde_json::from_str(
            r#"{"zeta":1,"alpha":{"k2":[1,2.5,true],"k1":"v"},"mid":false,"s":"hello","big":"12345678901234567890","eps":0.001}"#,
        )
        .unwrap();
        assert_eq!(
            get_json_source(&v),
            r#"{"alpha":{"k1":"v","k2":[1,2.5,true]},"big":"12345678901234567890","eps":0.001,"mid":false,"s":"hello","zeta":1}"#
        );
        assert_eq!(get_json_source(&v).len(), 112);
        let h = get_data_hash(&v);
        assert_eq!(
            hex::encode(h),
            "4efa7a37d070cbd34ac38b44ce5dfd0fc70f99fb62f3c619529cecb08a5f5180"
        );
    }

    #[test]
    fn canonical_number_rejects_ambiguous_forms() {
        // `1.0` would print "1.0" in Rust but "1" in JS: fail closed.
        assert!(canonical_number(&json!(1.0).as_number().unwrap()).is_err());
        assert!(canonical_number(&serde_json::Number::from_f64(-0.0).unwrap()).is_err());
        assert!(canonical_number(&json!(1e21).as_number().unwrap()).is_err());
        assert!(
            canonical_number(&serde_json::Number::from_f64(9_007_199_254_740_994.0).unwrap())
                .is_err()
        );
        // Short decimals and exact integers are fine.
        assert_eq!(
            canonical_number(&json!(2.5).as_number().unwrap()).as_deref(),
            Ok("2.5")
        );
        assert_eq!(
            canonical_number(&json!(0.001).as_number().unwrap()).as_deref(),
            Ok("0.001")
        );
        assert_eq!(
            canonical_number(&json!(12345678901234567u64).as_number().unwrap()).as_deref(),
            Ok("12345678901234567")
        );
        // Both hash entry points propagate the rejection.
        let bad = json!({"x": 1.0});
        assert!(get_source_string(&bad).is_err());
        assert!(get_json_source_string(&bad).is_err());
    }
}
