//! Shared types + per-scheme verifier modules for guest binaries.
//!
//! Each scheme has a `verify_all(&VerifyInput) -> Result<(), &'static str>`
//! function. Guest binaries are thin shells that call the matching one.
//!
//! Wire format mirrors the host crate's `lez_signature_bench::VerifyInput`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignerVerification {
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifyInput {
    pub message: Vec<u8>,
    pub signers: Vec<SignerVerification>,
}

pub mod verifier {
    pub mod ecdsa_k256 {
        use super::super::VerifyInput;
        use alloc::string::{String, ToString};
        use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        use tiny_keccak::{Hasher, Keccak};

        fn keccak256(bytes: &[u8]) -> [u8; 32] {
            let mut h = Keccak::v256();
            let mut out = [0u8; 32];
            h.update(bytes);
            h.finalize(&mut out);
            out
        }

        pub fn verify_all(input: &VerifyInput) -> Result<(), String> {
            let digest = keccak256(&input.message);
            for s in &input.signers {
                let vk =
                    VerifyingKey::from_sec1_bytes(&s.pubkey).map_err(|_| "pubkey".to_string())?;
                let sig = Signature::from_slice(&s.signature).map_err(|_| "sig".to_string())?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|_| "verify".to_string())?;
            }
            Ok(())
        }
    }

    pub mod schnorr_k256 {
        use super::super::VerifyInput;
        use alloc::string::{String, ToString};
        use k256::schnorr::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        use sha2::{Digest, Sha256};

        pub fn verify_all(input: &VerifyInput) -> Result<(), String> {
            let digest: [u8; 32] = Sha256::digest(&input.message).into();
            for s in &input.signers {
                let vk = VerifyingKey::from_bytes(&s.pubkey).map_err(|_| "pubkey".to_string())?;
                let sig =
                    Signature::try_from(s.signature.as_slice()).map_err(|_| "sig".to_string())?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|_| "verify".to_string())?;
            }
            Ok(())
        }
    }

    pub mod ed25519 {
        use super::super::VerifyInput;
        use alloc::string::{String, ToString};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        pub fn verify_all(input: &VerifyInput) -> Result<(), String> {
            for s in &input.signers {
                let pk_arr: [u8; 32] = s
                    .pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| "pubkey-len".to_string())?;
                let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| "pubkey".to_string())?;
                let sig = Signature::from_slice(&s.signature).map_err(|_| "sig".to_string())?;
                vk.verify(&input.message, &sig)
                    .map_err(|_| "verify".to_string())?;
            }
            Ok(())
        }
    }

    pub mod ecdsa_p256 {
        use super::super::VerifyInput;
        use alloc::string::{String, ToString};
        use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        use sha2::{Digest, Sha256};

        pub fn verify_all(input: &VerifyInput) -> Result<(), String> {
            let digest: [u8; 32] = Sha256::digest(&input.message).into();
            for s in &input.signers {
                let vk =
                    VerifyingKey::from_sec1_bytes(&s.pubkey).map_err(|_| "pubkey".to_string())?;
                let sig = Signature::from_slice(&s.signature).map_err(|_| "sig".to_string())?;
                vk.verify_prehash(&digest, &sig)
                    .map_err(|_| "verify".to_string())?;
            }
            Ok(())
        }
    }

    pub mod lms {
        use super::super::VerifyInput;
        use alloc::string::{String, ToString};
        use hbs_lms::{Sha256_256, verify};

        pub fn verify_all(input: &VerifyInput) -> Result<(), String> {
            for s in &input.signers {
                verify::<Sha256_256>(&input.message, &s.signature, &s.pubkey)
                    .map_err(|_| "verify".to_string())?;
            }
            Ok(())
        }
    }
}

/// RedStone data-package verification: the RFP-020 adaptor core path.
///
/// Each package carries the exact byte serialization the RedStone data node
/// signed (`dataPoints || timestamp_ms(6) || value_byte_size(4) || count(3)`),
/// plus a 65-byte recoverable ECDSA signature. Verification recovers each
/// signer address (keccak256(pubkey)[12..]), enforces the authorised signer
/// set and M-of-N threshold, rejects stale / mismatched / non-positive
/// packages, and aggregates the surviving values by median.
pub mod redstone {
    use alloc::{string::String, vec::Vec};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use serde::{Deserialize, Serialize};
    use tiny_keccak::{Hasher, Keccak};

    pub const FEED_ID_BS: usize = 32;
    pub const TIMESTAMP_BS: usize = 6;
    pub const VALUE_SIZE_BS: usize = 4;
    pub const POINTS_COUNT_BS: usize = 3;
    pub const SIGNATURE_BS: usize = 65;
    /// Packages timestamped ahead of `current_timestamp_ms` by more than this
    /// are rejected (clock drift allowance, mirrors RedStone EVM connector).
    pub const MAX_FUTURE_DRIFT_MS: u64 = 60_000;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct RedstonePackage {
        /// Exact signed byte serialization from the data node.
        pub signed_bytes: Vec<u8>,
        /// 65-byte recoverable signature (r || s || v).
        pub signature: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct RedstoneVerifyInput {
        pub packages: Vec<RedstonePackage>,
        /// Authorised signer set (20-byte addresses), admin-configured per feed.
        pub authorized_signers: Vec<[u8; 20]>,
        /// M in M-of-N.
        pub threshold: u8,
        /// Expected feed identifier, e.g. b"XMR".
        pub expected_feed_id: Vec<u8>,
        pub current_timestamp_ms: u64,
        pub max_age_ms: u64,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct VerifiedPrice {
        /// Median of valid package values, 8 implied decimals.
        pub value: u128,
        /// Oldest timestamp among the packages that formed the median.
        pub timestamp_ms: u64,
    }

    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Keccak::v256();
        let mut out = [0u8; 32];
        h.update(bytes);
        h.finalize(&mut out);
        out
    }

    fn be_u64(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
    }

    /// Parsed single data point plus package timestamp.
    struct ParsedPackage {
        value: u128,
        timestamp_ms: u64,
    }

    fn parse_package(signed_bytes: &[u8], expected_feed_id: &[u8]) -> Result<ParsedPackage, &'static str> {
        let meta = TIMESTAMP_BS + VALUE_SIZE_BS + POINTS_COUNT_BS;
        if signed_bytes.len() < meta {
            return Err("malformed: too short");
        }
        let (points_area, tail) = signed_bytes.split_at(signed_bytes.len() - meta);
        let timestamp_ms = be_u64(&tail[..TIMESTAMP_BS]);
        let value_size = be_u64(&tail[TIMESTAMP_BS..TIMESTAMP_BS + VALUE_SIZE_BS]) as usize;
        let count = be_u64(&tail[TIMESTAMP_BS + VALUE_SIZE_BS..]) as usize;
        if value_size != 32 {
            return Err("malformed: unexpected value byte size");
        }
        if count == 0 || points_area.len() != count * (FEED_ID_BS + value_size) {
            return Err("malformed: data points length mismatch");
        }
        for point in points_area.chunks_exact(FEED_ID_BS + value_size) {
            let feed_id = &point[..FEED_ID_BS];
            let trimmed = feed_id
                .iter()
                .position(|b| *b == 0)
                .map_or(feed_id, |end| &feed_id[..end]);
            if trimmed != expected_feed_id {
                continue;
            }
            let value_bytes = &point[FEED_ID_BS..];
            if value_bytes[..16].iter().any(|b| *b != 0) {
                return Err("value overflows u128");
            }
            let value = value_bytes[16..]
                .iter()
                .fold(0u128, |acc, b| (acc << 8) | u128::from(*b));
            if value == 0 {
                return Err("zero or negative value");
            }
            return Ok(ParsedPackage {
                value,
                timestamp_ms,
            });
        }
        Err("asset identifier mismatch")
    }

    fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20], &'static str> {
        if signature.len() != SIGNATURE_BS {
            return Err("malformed signature length");
        }
        let sig = Signature::from_slice(&signature[..64]).map_err(|_| "malformed signature")?;
        let v = signature[64];
        let rec_id = RecoveryId::try_from(if v >= 27 { v - 27 } else { v })
            .map_err(|_| "invalid recovery id")?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
            .map_err(|_| "invalid signature")?;
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Ok(address)
    }

    /// Verify all packages and aggregate: the adaptor's verification core.
    pub fn verify(input: &RedstoneVerifyInput) -> Result<VerifiedPrice, String> {
        let mut seen_signers: Vec<[u8; 20]> = Vec::new();
        let mut values: Vec<u128> = Vec::new();
        let mut oldest_ts = u64::MAX;

        for pkg in &input.packages {
            let parsed = parse_package(&pkg.signed_bytes, &input.expected_feed_id)?;
            if parsed.timestamp_ms + input.max_age_ms < input.current_timestamp_ms {
                return Err(String::from("stale data package"));
            }
            if parsed.timestamp_ms > input.current_timestamp_ms + MAX_FUTURE_DRIFT_MS {
                return Err(String::from("data package timestamp in the future"));
            }
            let digest = keccak256(&pkg.signed_bytes);
            let signer = recover_signer(&digest, &pkg.signature)?;
            if !input.authorized_signers.contains(&signer) {
                return Err(String::from("signer not in authorised set"));
            }
            if seen_signers.contains(&signer) {
                return Err(String::from("duplicate signer"));
            }
            seen_signers.push(signer);
            values.push(parsed.value);
            oldest_ts = oldest_ts.min(parsed.timestamp_ms);
        }

        if values.len() < usize::from(input.threshold) {
            return Err(String::from("signer threshold not met"));
        }

        values.sort_unstable();
        let mid = values.len() / 2;
        let value = if values.len() % 2 == 1 {
            values[mid]
        } else {
            values[mid - 1].midpoint(values[mid])
        };

        Ok(VerifiedPrice {
            value,
            timestamp_ms: oldest_ts,
        })
    }
}
