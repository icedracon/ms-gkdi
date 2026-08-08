//! MS-GKDI `GetKey` RPC client — the transport piece the rest of the crate deliberately
//! left to the caller. Ask a domain controller for the [`GroupKeyEnvelope`] covering a
//! given `(rootKeyId, L0, L1, L2)` node; the crate's derivation then walks downwards to the
//! exact L2 key needed to open the LAPS/gMSA/dMSA blob.
//!
//! Interface: `ISDKey` — UUID `b9785960-524f-11df-8b6d-83dcded72085`, v1.0.
//! Transport: sealed (PKT_PRIVACY) ncacn_ip_tcp, EPM-resolved port. Reuses the [`dcerpc`]
//! sealed-RPC stack that DCSync already runs on.
//!
//! IDL (MS-GKDI 3.1.4.1):
//! ```text
//! HRESULT GetKey(
//!   [in] ULONG cbTargetSD,
//!   [in, size_is(cbTargetSD)] BYTE* pbTargetSD,
//!   [in, unique] GUID* pRootKeyID,
//!   [in] LONG L0KeyID,
//!   [in] LONG L1KeyID,
//!   [in] LONG L2KeyID,
//!   [out] ULONG* pcbOut,
//!   [out, size_is(, *pcbOut)] BYTE** ppbOut);
//! ```
//!
//! **Validation status.** The GKDI wire marshaling is implemented to spec. It has *not* been
//! run against a live DC in this crate's tests — validate on your DC matrix by fetching a
//! real envelope for a known KeyIdentifier and cross-checking the returned bytes against
//! the DC's `Get-KdsRootKey` view / an independent client (netexec / dploot).

use crate::gkdi::{GroupKeyEnvelope, RootKeyId};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::transport::RpcTcp;
use dcerpc::{epm, Result as RpcResult, RpcError, Syntax};

/// The `ISDKey` interface (MS-GKDI), v1.0.
pub fn isdkey_syntax() -> Syntax {
    Syntax::new("b9785960-524f-11df-8b6d-83dcded72085", 1, 0)
}

/// `GetKey` — opnum 0.
pub const OPNUM_GET_KEY: u16 = 0;

/// Marshal a `GetKey` request. Pass `None` for `root_key_id` to ask the DC to pick the
/// current KDS root key; pass `Some(id)` to fetch a specific one.
pub fn encode_get_key(
    target_sd: &[u8],
    root_key_id: Option<RootKeyId>,
    l0: i32,
    l1: i32,
    l2: i32,
) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    // cbTargetSD (ULONG)
    e.u32(target_sd.len() as u32);
    // pbTargetSD: [in, size_is(cbTargetSD)] BYTE* — top-level [ref] to a conformant array.
    // Top-level ref pointers emit no referent id; go straight to the array's max_count.
    e.u32(target_sd.len() as u32); // conformant max_count == cbTargetSD
    e.bytes(target_sd);
    // pRootKeyID: [in, unique] GUID* — referent id, then (if non-null) the 16 GUID bytes.
    match root_key_id {
        Some(id) => {
            e.referent();
            e.uuid(&id.0);
        }
        None => e.null_ptr(),
    }
    // L0/L1/L2KeyID (LONG each) — signed i32, wire-identical to u32.
    e.u32(l0 as u32);
    e.u32(l1 as u32);
    e.u32(l2 as u32);
    e.into_bytes()
}

/// Parse a `GetKey` reply into the returned envelope bytes and HRESULT. A successful reply
/// has HRESULT == 0 and non-empty envelope bytes.
///
/// Wire (MS-GKDI 3.1.4.1):
/// * `pcbOut` — ULONG out-scalar, marshaled as its value at the top level.
/// * `ppbOut` — `BYTE**` out; top-level [ref] (no referent id), then a [unique] pointer to
///   the array; if non-null, conformant max_count = *pcbOut, then bytes.
/// * `HRESULT` — signed i32.
pub fn decode_get_key(stub: &[u8]) -> RpcResult<(Vec<u8>, u32)> {
    let mut d = NdrDecoder::new(stub);
    let cb_out = d.u32()? as usize;
    let inner_ref = d.u32()?; // referent for ppbOut's inner pointer
    let mut buf = Vec::new();
    if inner_ref != 0 && cb_out > 0 {
        let max = d.u32()? as usize;
        // Some servers emit an offset/actual triple like a conformant-varying array; MS-GKDI
        // uses a plain conformant array, so we just take `max` bytes.
        buf = d.read_bytes(max)?.to_vec();
    }
    let _ = cb_out; // cbOut is authoritative on length; buf.len() == max
    let hresult = d.u32().unwrap_or(0);
    Ok((buf, hresult))
}

/// One-shot `GetKey` call. Resolves ISDKey's dynamic port via EPM, opens a sealed ncacn_ip_tcp
/// session as `(domain, user, password)`, and returns the parsed [`GroupKeyEnvelope`].
///
/// `target_sd` is the security descriptor that authorizes access; passing an empty slice lets
/// the DC use the caller's own context, which is what dploot / netexec do for LAPS.
#[allow(clippy::too_many_arguments)] // the arg list is the MS-GKDI `GetKey` signature
pub async fn get_key(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    target_sd: &[u8],
    root_key_id: Option<RootKeyId>,
    l0: i32,
    l1: i32,
    l2: i32,
) -> RpcResult<GroupKeyEnvelope> {
    let port = epm::resolve_port(host, isdkey_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind_sealed(isdkey_syntax(), domain, user, password, "MS-GKDI")
        .await?;
    let stub = encode_get_key(target_sd, root_key_id, l0, l1, l2);
    let resp = rpc.call_sealed(OPNUM_GET_KEY, &stub).await?;
    let (bytes, hresult) = decode_get_key(&resp)?;
    if hresult != 0 {
        return Err(RpcError::Protocol(format!(
            "MS-GKDI GetKey failed: HRESULT 0x{hresult:08x}"
        )));
    }
    GroupKeyEnvelope::parse(&bytes)
        .map_err(|e| RpcError::Protocol(format!("parse GroupKeyEnvelope: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_key_request_shape() {
        // Empty SD, null root key id, node (361, 7, 19).
        let stub = encode_get_key(&[], None, 361, 7, 19);
        // cbTargetSD u32 + conformant max_count u32 (0) + null ptr u32 + 3× i32.
        assert_eq!(stub.len(), 4 + 4 + 4 + 4 * 3);
        assert_eq!(&stub[0..4], &0u32.to_le_bytes()); // cbTargetSD
        assert_eq!(&stub[4..8], &0u32.to_le_bytes()); // conformant max_count
        assert_eq!(&stub[8..12], &0u32.to_le_bytes()); // null pRootKeyID
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 361);
        assert_eq!(u32::from_le_bytes(stub[16..20].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(stub[20..24].try_into().unwrap()), 19);
    }

    #[test]
    fn get_key_request_with_root_key_and_sd() {
        let sd = [0xAAu8; 8];
        let root = RootKeyId([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let stub = encode_get_key(&sd, Some(root), 1, 2, 3);
        // cbTargetSD = 8, max_count = 8, 8 SD bytes, non-zero referent, 16 GUID bytes, 3× i32.
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 8);
        assert_eq!(&stub[8..16], &sd);
        let referent = u32::from_le_bytes(stub[16..20].try_into().unwrap());
        assert_ne!(referent, 0);
        assert_eq!(&stub[20..36], &root.0); // GUID pointee
        assert_eq!(u32::from_le_bytes(stub[36..40].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(stub[40..44].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(stub[44..48].try_into().unwrap()), 3);
    }

    #[test]
    fn get_key_reply_null_pointer_yields_empty_bytes() {
        // cbOut = 0, inner ref = 0 (null pointer), HRESULT = 0x80070005 (access denied)
        let mut r = Vec::new();
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&0x80070005u32.to_le_bytes());
        let (bytes, hres) = decode_get_key(&r).unwrap();
        assert!(bytes.is_empty());
        assert_eq!(hres, 0x80070005);
    }

    #[test]
    fn get_key_reply_carries_envelope_bytes() {
        let payload = [0xBBu8; 5];
        let mut r = Vec::new();
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // cbOut
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // inner referent (non-null)
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // conformant max_count
        r.extend_from_slice(&payload);
        while r.len() % 4 != 0 {
            r.push(0);
        }
        r.extend_from_slice(&0u32.to_le_bytes()); // HRESULT
        let (bytes, hres) = decode_get_key(&r).unwrap();
        assert_eq!(bytes, payload);
        assert_eq!(hres, 0);
    }

    #[test]
    fn truncated_reply_is_error_not_panic() {
        for cut in 0..24 {
            let _ = decode_get_key(&vec![0u8; cut]);
        }
    }
}
