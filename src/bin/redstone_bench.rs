//! Bench a real RedStone data-package verification inside the NSSA-wrapped
//! LEZ guest: the RFP-020 adaptor verification core (parse + keccak256 +
//! M-of-N ECDSA recovery + signer-set check + median), measured end-to-end
//! through the RISC0 prover on live gateway payloads.
//!
//! Usage:
//!   RISC0_DEV_MODE=0 cargo run --release --bin redstone_bench -- \
//!     --json fixtures/redstone-latest.json --feed XMR --n 3 --threshold 3

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use risc0_zkvm::{ExecutorEnv, default_prover};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use lez_signature_bench_methods::REDSTONE_ELF;

const FEED_ID_BS: usize = 32;
const VALUE_BS: usize = 32;
const DEFAULT_DECIMALS: u32 = 8;

/// Wire-compatible mirror of the guest's `redstone::RedstonePackage`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct RedstonePackage {
    signed_bytes: Vec<u8>,
    signature: Vec<u8>,
}

/// Wire-compatible mirror of the guest's `redstone::RedstoneVerifyInput`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct RedstoneVerifyInput {
    packages: Vec<RedstonePackage>,
    authorized_signers: Vec<[u8; 20]>,
    threshold: u8,
    expected_feed_id: Vec<u8>,
    current_timestamp_ms: u64,
    max_age_ms: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GatewayDataPoint {
    data_feed_id: String,
    value: f64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GatewayPackage {
    timestamp_milliseconds: u64,
    signature: String,
    signer_address: String,
    data_points: Vec<GatewayDataPoint>,
}

#[derive(Parser, Debug)]
#[command(about = "Prove real RedStone payload verification inside a LEZ guest.")]
struct Cli {
    /// Path to the gateway JSON (data-packages/latest/<dataServiceId> response).
    #[arg(long)]
    json: PathBuf,
    /// Feed identifier, e.g. XMR.
    #[arg(long, default_value = "XMR")]
    feed: String,
    /// Number of data packages (distinct signers) to include.
    #[arg(long, default_value_t = 3)]
    n: usize,
    /// M-of-N threshold enforced in the guest.
    #[arg(long, default_value_t = 3)]
    threshold: u8,
    /// maxAge accepted by the guest, relative to the newest package timestamp.
    #[arg(long, default_value_t = 600_000)]
    max_age_ms: u64,
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(bytes);
    h.finalize(&mut out);
    out
}

/// Reconstruct the exact byte serialization the data node signed.
fn serialize_signed_bytes(pkg: &GatewayPackage) -> Vec<u8> {
    let mut out = Vec::new();
    for dp in &pkg.data_points {
        let feed_id = dp.data_feed_id.as_bytes();
        assert!(feed_id.len() <= FEED_ID_BS, "feed id too long");
        out.extend_from_slice(feed_id);
        out.resize(out.len() + (FEED_ID_BS - feed_id.len()), 0);
        let value = (dp.value * 10f64.powi(DEFAULT_DECIMALS as i32)).round() as u128;
        let mut value_be = [0u8; VALUE_BS];
        value_be[VALUE_BS - 16..].copy_from_slice(&value.to_be_bytes());
        out.extend_from_slice(&value_be);
    }
    out.extend_from_slice(&pkg.timestamp_milliseconds.to_be_bytes()[2..]); // 6 bytes
    out.extend_from_slice(&(VALUE_BS as u32).to_be_bytes()); // 4 bytes
    let count = pkg.data_points.len() as u32;
    out.extend_from_slice(&count.to_be_bytes()[1..]); // 3 bytes
    out
}

fn recover_address(digest: &[u8; 32], sig65: &[u8]) -> Result<[u8; 20], String> {
    let sig = Signature::from_slice(&sig65[..64]).map_err(|e| format!("sig: {e}"))?;
    let v = sig65[64];
    let rec_id = RecoveryId::try_from(if v >= 27 { v - 27 } else { v })
        .map_err(|e| format!("recid: {e}"))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
        .map_err(|e| format!("recover: {e}"))?;
    let uncompressed = vk.to_encoded_point(false);
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, b) in TABLE.iter().enumerate() {
        lookup[*b as usize] = i as u8;
    }
    let raw: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    for chunk in raw.chunks(4) {
        let mut acc: u32 = 0;
        for b in chunk {
            let v = lookup[*b as usize];
            if v == 255 {
                return Err(format!("invalid base64 byte {b}"));
            }
            acc = (acc << 6) | u32::from(v);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                acc <<= 6;
                out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]);
            }
            2 => {
                acc <<= 12;
                out.push((acc >> 16) as u8);
            }
            _ => return Err("truncated base64".into()),
        }
    }
    Ok(out)
}

fn main() {
    let cli = Cli::parse();
    if std::env::var("RISC0_DEV_MODE").as_deref() == Ok("1") {
        eprintln!("warning: RISC0_DEV_MODE=1 — numbers below are NOT real measurements.");
    }

    let raw = std::fs::read_to_string(&cli.json).expect("read gateway json");
    let all: std::collections::HashMap<String, Vec<GatewayPackage>> =
        serde_json::from_str(&raw).expect("parse gateway json");
    let feed_packages = all
        .get(&cli.feed)
        .unwrap_or_else(|| panic!("feed {} not in gateway response", cli.feed));

    // Full roster (N in M-of-N) = every signer the gateway returned for this feed.
    let mut authorized_signers: Vec<[u8; 20]> = Vec::new();
    for pkg in feed_packages {
        let hex_addr = pkg.signer_address.trim_start_matches("0x");
        let bytes = hex::decode(hex_addr).expect("signer address hex");
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        if !authorized_signers.contains(&addr) {
            authorized_signers.push(addr);
        }
    }

    // Host-side pre-verification: keep the first n packages whose reconstructed
    // serialization recovers to the advertised signer address.
    let mut packages: Vec<RedstonePackage> = Vec::new();
    let mut newest_ts = 0u64;
    for pkg in feed_packages {
        if packages.len() == cli.n {
            break;
        }
        let signed_bytes = serialize_signed_bytes(pkg);
        let signature = decode_base64(&pkg.signature).expect("decode signature");
        assert_eq!(signature.len(), 65, "unexpected signature length");
        let digest = keccak256(&signed_bytes);
        match recover_address(&digest, &signature) {
            Ok(addr) if authorized_signers.contains(&addr) => {
                println!(
                    "host pre-check OK: signer 0x{} ts={} bytes={}",
                    hex::encode(addr),
                    pkg.timestamp_milliseconds,
                    signed_bytes.len(),
                );
                newest_ts = newest_ts.max(pkg.timestamp_milliseconds);
                packages.push(RedstonePackage {
                    signed_bytes,
                    signature,
                });
            }
            Ok(addr) => println!(
                "host pre-check SKIP: recovered 0x{} not in advertised roster",
                hex::encode(addr),
            ),
            Err(e) => println!("host pre-check SKIP: {e}"),
        }
    }
    assert_eq!(
        packages.len(),
        cli.n,
        "not enough host-verifiable packages for feed {}",
        cli.feed,
    );

    let input = RedstoneVerifyInput {
        packages,
        authorized_signers,
        threshold: cli.threshold,
        expected_feed_id: cli.feed.clone().into_bytes(),
        current_timestamp_ms: newest_ts,
        max_age_ms: cli.max_age_ms,
    };

    let self_program_id: [u32; 8] = [0; 8];
    let caller_program_id: Option<[u32; 8]> = None;
    let pre_states: Vec<nssa_core::account::AccountWithMetadata> = Vec::new();
    let instruction_data: Vec<u32> =
        risc0_zkvm::serde::to_vec(&input).expect("encode RedstoneVerifyInput");
    let env = ExecutorEnv::builder()
        .write(&self_program_id)
        .unwrap()
        .write(&caller_program_id)
        .unwrap()
        .write(&pre_states)
        .unwrap()
        .write(&instruction_data)
        .unwrap()
        .build()
        .unwrap();

    let t0 = Instant::now();
    let prove_info = default_prover().prove(env, REDSTONE_ELF).expect("prove");
    let prove_seconds = t0.elapsed().as_secs_f64();
    let receipt_bytes = bincode::serialize(&prove_info.receipt)
        .expect("receipt bincode")
        .len();
    let stats = &prove_info.stats;
    println!(
        "redstone feed={} n={} threshold={} cycles(total/user/paging)={}/{}/{} segs={} prove={:.2}s (~{}:{:02}) receipt={}B",
        cli.feed,
        cli.n,
        cli.threshold,
        stats.total_cycles,
        stats.user_cycles,
        stats.paging_cycles,
        stats.segments,
        prove_seconds,
        (prove_seconds / 60.0) as u64,
        (prove_seconds % 60.0) as u64,
        receipt_bytes,
    );
}
