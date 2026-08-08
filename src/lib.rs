//! MS-GKDI — Group Key Distribution.
//!
//! Extracted from `dpapi-ng` so the tree walk, KDF, and `ISDKey` RPC caller can be reused
//! without pulling in the DPAPI-NG CMS layer. The three public modules are:
//!
//! * [`gkdi`] — `KEY_IDENTIFIER` / `GROUP_KEY_ENVELOPE` parsers and the L0/L1/L2 walk.
//! * [`kdf`]  — SP800-108 counter-mode KDF and the `"KDS service"` label.
//! * [`rpc`]  — `ISDKey::GetKey` over sealed ncacn_ip_tcp (via the `dcerpc` crate).
//!
//! **UNVALIDATED CRYPTO — DO NOT PUBLISH.** See `README.md`: this 0.1.0-dev tag is local
//! only. The derivation has not been cross-checked against a live Server 2022 DC or against
//! Microsoft's reference `dpapi-ng.py`. Ship after the KAT harness lands.

pub mod gkdi;
pub mod kdf;
pub mod rpc;

mod cursor;

/// Errors surfaced by the parsers and the tree walk. Kept as a plain enum so callers can
/// `match` on the specific failure without stringly inspecting a message.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GkdiError {
    #[error("truncated: {0}")]
    Truncated(&'static str),
    #[error("bad {what} magic: {got:#010x}")]
    BadMagic { what: &'static str, got: u32 },
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("the envelope carries a public key, not seed keys — ask the DC for the private half")]
    PublicKeyEnvelope,
    #[error("the envelope has no {0} seed key")]
    MissingSeedKey(&'static str),
    #[error("tree index out of range: l1={l1} l2={l2}")]
    BadTreeIndex { l1: i32, l2: i32 },
}

pub type Result<T> = std::result::Result<T, GkdiError>;
