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
                if let Some(f) = n.as_f64() {
                    if !f.is_finite() {
                        return Err(format!("invalid number: {}", f));
                    }
                }
                comps.push("n".to_string());
                comps.push(n.to_string());
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

fn get_json_source_string(v: &Value) -> Result<String, String> {
    fn stringify(val: &Value, root: &Value, allow_empty: bool) -> Result<String, String> {
        if val.is_null() {
            return Err(format!("null value in {}", root));
        }
        match val {
            Value::String(s) => Ok(to_well_formed_json_string(s)),
            Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    if !f.is_finite() {
                        return Err(format!("invalid number: {}", f));
                    }
                }
                Ok(n.to_string())
            }
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
}
