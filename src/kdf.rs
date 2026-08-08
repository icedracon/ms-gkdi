//! SP800-108 counter-mode KDF — the one MS-GKDI uses to walk the key tree.
//!
//! Each iteration is `HMAC(key, i_be32 ‖ label ‖ 0x00 ‖ context ‖ bitlen_be32)`, concatenated
//! until `length` bytes are produced.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{GkdiError, Result};

/// Hash algorithm named in a `KdfParameters` blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Parse the `SHA512`-style name Windows stores in the KDF parameters.
    pub fn from_name(name: &str) -> Result<HashAlg> {
        match name.trim_end_matches('\0').to_ascii_uppercase().as_str() {
            "SHA1" => Ok(HashAlg::Sha1),
            "SHA256" => Ok(HashAlg::Sha256),
            "SHA384" => Ok(HashAlg::Sha384),
            "SHA512" => Ok(HashAlg::Sha512),
            other => Err(GkdiError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha1 => "SHA1",
            HashAlg::Sha256 => "SHA256",
            HashAlg::Sha384 => "SHA384",
            HashAlg::Sha512 => "SHA512",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
}

macro_rules! hmac_with {
    ($hash:ty, $key:expr, $data:expr) => {{
        let mut m = <Hmac<$hash>>::new_from_slice($key).expect("HMAC takes any key length");
        m.update($data);
        m.finalize().into_bytes().to_vec()
    }};
}

fn hmac_once(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => hmac_with!(Sha1, key, data),
        HashAlg::Sha256 => hmac_with!(Sha256, key, data),
        HashAlg::Sha384 => hmac_with!(Sha384, key, data),
        HashAlg::Sha512 => hmac_with!(Sha512, key, data),
    }
}

/// SP800-108 counter-mode KDF with a 32-bit big-endian counter and length in **bits**.
pub fn sp800_108_counter(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let bit_len = ((length * 8) as u32).to_be_bytes();
    let mut out = Vec::with_capacity(length + alg.output_len());
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut data = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(label);
        data.push(0x00);
        data.extend_from_slice(context);
        data.extend_from_slice(&bit_len);
        out.extend_from_slice(&hmac_once(alg, secret, &data));
        counter += 1;
    }
    out.truncate(length);
    out
}

/// Legacy short name — kept so callers ported from `dpapi-ng` still compile.
pub use sp800_108_counter as kdf;

/// `"KDS service\0"` in UTF-16LE — the label every GKDI derivation uses.
pub fn kds_service_label() -> Vec<u8> {
    "KDS service\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect()
}
