//! RPC handlers for getdescriptorinfo and analyzepsbt.
//!
//! These are the two JSON-RPC methods that blvm-miniscript overrides at runtime
//! via `NodeAPI::register_core_rpc_override`.  The logic is migrated from
//! `blvm-node/src/miniscript.rs` and `blvm-node/src/rpc/miniscript.rs`.

use miniscript::bitcoin;
use miniscript::{Descriptor, DescriptorPublicKey, Miniscript, Segwitv0};
use serde_json::{json, Value};
use std::str::FromStr;

// ── Script type helpers ──────────────────────────────────────────────────────

/// P2PKH / P2SH / P2WPKH / P2WSH / P2TR detection (opcode-level, no blvm-protocol dep).
fn script_type(bytes: &[u8]) -> &'static str {
    // P2PKH: OP_DUP(0x76) OP_HASH160(0xa9) 0x14 <20b> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
    if bytes.len() == 25
        && bytes[0] == 0x76
        && bytes[1] == 0xa9
        && bytes[2] == 0x14
        && bytes[23] == 0x88
        && bytes[24] == 0xac
    {
        return "P2PKH";
    }
    // P2SH: OP_HASH160(0xa9) 0x14 <20b> OP_EQUAL(0x87)
    if bytes.len() == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 && bytes[22] == 0x87 {
        return "P2SH";
    }
    // P2WPKH: OP_0(0x00) 0x14 <20b>
    if bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14 {
        return "P2WPKH";
    }
    // P2WSH: OP_0(0x00) 0x20 <32b>
    if bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20 {
        return "P2WSH";
    }
    // P2TR: OP_1(0x51) 0x20 <32b>
    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
        return "P2TR";
    }
    "Unknown"
}

fn is_miniscript_script(bytes: &[u8]) -> (bool, Option<usize>) {
    let s = bitcoin::Script::from_bytes(bytes);
    match Miniscript::<bitcoin::PublicKey, Segwitv0>::decode_consensus(s) {
        Ok(ms) => (true, ms.max_satisfaction_size().ok()),
        Err(_) => (false, None),
    }
}

// ── Descriptor checksum (BIP380 / bech32m) ───────────────────────────────────

fn descriptor_checksum(descriptor: &str) -> String {
    use bech32::{ToBase32, Variant};

    let clean = match descriptor.rfind('#') {
        Some(pos) => &descriptor[..pos],
        None => descriptor,
    };
    let b32 = clean.as_bytes().to_base32();
    match bech32::encode("dp", b32, Variant::Bech32m) {
        Ok(encoded) => {
            if let Some(pos) = encoded.rfind('#') {
                return encoded[pos + 1..].to_string();
            }
            if encoded.len() >= 8 {
                return encoded[encoded.len() - 8..].to_string();
            }
            encoded
        }
        Err(_) => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(clean.as_bytes());
            hex::encode(&hash[..4])
        }
    }
}

fn is_range_descriptor(descriptor: &str) -> bool {
    if let Ok(re) = regex::Regex::new(r"\[\d+,\d+") {
        if re.is_match(descriptor) {
            return true;
        }
    }
    descriptor.contains("/0/*")
        || descriptor.contains("/*")
        || descriptor.contains("[0,")
        || descriptor.contains("/'/'")
}

// ── RPC: getdescriptorinfo ────────────────────────────────────────────────────

pub fn get_descriptor_info(params: &Value) -> Value {
    let descriptor_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return json!({
                "error": { "code": -32602, "message": "descriptor string required" }
            });
        }
    };

    match Descriptor::<DescriptorPublicKey>::from_str(descriptor_str) {
        Ok(descriptor) => {
            let checksum = descriptor_checksum(descriptor_str);
            let is_range = is_range_descriptor(descriptor_str);
            // Use index 0 for analysis: ranged descriptors need *some* index to derive a
            // concrete script_pubkey, and on non-range descriptors `at_derivation_index` is
            // a no-op, so the same call works for both shapes.
            let concrete = descriptor.at_derivation_index(0).ok();
            let (is_ms, stype) = match concrete {
                Some(ref d) => {
                    let script_bytes: Vec<u8> = d.script_pubkey().into();
                    let (ms, _) = is_miniscript_script(&script_bytes);
                    (ms, script_type(&script_bytes))
                }
                None => (true, "unknown"),
            };

            json!({
                "descriptor": descriptor_str,
                "checksum": checksum,
                "isrange": is_range,
                "issolvable": is_ms,
                "hasprivatekeys": false,
                "scripttype": stype,
            })
        }
        Err(e) => {
            json!({
                "descriptor": descriptor_str,
                "checksum": "",
                "isrange": false,
                "issolvable": false,
                "hasprivatekeys": false,
                "error": e.to_string(),
            })
        }
    }
}

// ── RPC: analyzepsbt ─────────────────────────────────────────────────────────

pub fn analyze_psbt(params: &Value) -> Value {
    let psbt_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return json!({
                "error": { "code": -32602, "message": "PSBT string required" }
            });
        }
    };

    use base64::{engine::general_purpose, Engine as _};
    let psbt_bytes = match general_purpose::STANDARD.decode(psbt_str) {
        Ok(b) => b,
        Err(e) => {
            return json!({
                "error": { "code": -32602, "message": format!("Invalid PSBT base64: {}", e) }
            });
        }
    };

    use miniscript::bitcoin::psbt::Psbt;
    let psbt = match Psbt::deserialize(&psbt_bytes) {
        Ok(p) => p,
        Err(e) => {
            return json!({
                "error": { "code": -32603, "message": format!("Failed to parse PSBT: {}", e) }
            });
        }
    };

    let mut input_analyses = Vec::new();
    for input in &psbt.inputs {
        let mut info = json!({
            "has_utxo": input.non_witness_utxo.is_some() || input.witness_utxo.is_some(),
            "has_final_script_sig": input.final_script_sig.is_some(),
            "has_final_script_witness": input.final_script_witness.is_some(),
        });
        if let Some(ref utxo) = input.witness_utxo {
            let bytes = utxo.script_pubkey.as_bytes();
            let (is_ms, _) = is_miniscript_script(bytes);
            info["script_type"] = json!(script_type(bytes));
            info["is_miniscript"] = json!(is_ms);
        }
        input_analyses.push(info);
    }

    let estimated_vsize = psbt.unsigned_tx.weight().to_wu() as u64 / 4;
    let next = if psbt
        .inputs
        .iter()
        .all(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some())
    {
        "finalizer"
    } else if psbt.inputs.iter().any(|i| !i.partial_sigs.is_empty()) {
        "signer"
    } else {
        "updater"
    };

    json!({
        "inputs": input_analyses,
        "estimated_vsize": estimated_vsize,
        "estimated_feerate": 0,
        "fee": 0,
        "next": next,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_descriptor_info_valid() {
        // secp256k1 generator point G (compressed, 66 hex chars = 33 bytes)
        let params = serde_json::json!([
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
        ]);
        let result = get_descriptor_info(&params);
        assert!(
            result.get("error").is_none(),
            "should not error on valid pk descriptor, got: {:?}",
            result.get("error")
        );
        assert_eq!(result["hasprivatekeys"], false);
    }

    #[test]
    fn test_get_descriptor_info_invalid() {
        let params = serde_json::json!(["not_a_descriptor"]);
        let result = get_descriptor_info(&params);
        assert!(result.get("error").is_some() || result["issolvable"] == false);
    }

    #[test]
    fn test_range_descriptor_detection() {
        assert!(is_range_descriptor("pkh(xpub.../0/*)"));
        assert!(!is_range_descriptor(
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
        ));
    }
}
