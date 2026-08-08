# ms-gkdi

MS-GKDI Group Key Distribution primitives in pure Rust — the L0/L1/L2 seed-key tree walk,
the SP800-108 counter-mode KDF Windows uses to derive it, and the `ISDKey::GetKey` RPC
client for fetching envelopes from a domain controller.

Extracted from [`dpapi-ng`](https://github.com/icedracon/dpapi-ng) so that the tree walk
and RPC can be reused independently of the DPAPI-NG CMS layer (LAPS/gMSA/dMSA blob
unwrapping still lives in `dpapi-ng` itself).

## ⚠ CRYPTO UNVALIDATED

**This 0.1.0-dev tag is LOCAL ONLY, do not publish.** A KAT (Known Answer Test) harness is
required before 0.1.0 release. The three items blocking the publish gate:

1. **KAT vs a live Server 2022 DC** — fetch a real `GROUP_KEY_ENVELOPE` via `ISDKey::GetKey`
   for a known root key, walk it down to a chosen `(L0, L1, L2)` node, and compare the L2
   seed byte-for-byte against the value the DC itself computes for the same node.
2. **Cross-check vs Microsoft's reference [`dpapi-ng.py`](https://github.com/microsoft/dpapi-ng)** —
   feed the same envelope + target `(L1, L2)` to both implementations and diff the L2 output.
3. **Documented answer for the KDF context byte-order.** The current `kdf_context()`
   emits the root-key GUID as raw bytes followed by three little-endian `i32` indices. MS-GKDI
   3.1.4.1.2 does not spell out endianness explicitly for the context blob; other
   implementations agree in practice, but the choice needs a written reference before this
   crate ships as "conformant".

The `Cargo.toml` carries `[package.metadata.publish_gate] status = "unvalidated-crypto"` as
a machine-readable reminder for anyone who tries to `cargo publish`.

## What is here

- `gkdi` — `KEY_IDENTIFIER`, `GROUP_KEY_ENVELOPE`, `KdfParameters`, `RootKeyId`,
  `compute_l2_key`, `kdf_context`.
- `kdf`  — `sp800_108_counter` (aliased as `kdf` for callers ported from `dpapi-ng`),
  `HashAlg`, `kds_service_label`.
- `rpc`  — `isdkey_syntax`, `encode_get_key`, `decode_get_key`, `get_key` (sealed
  ncacn_ip_tcp against a DC, via the `dcerpc` crate).

## Dependencies

Minimal and pure Rust: `thiserror`, `hmac`, `sha1`, `sha2`, `aes-kw`, and (for the RPC path)
the sibling `dcerpc` + `ms-ndr` crates.

## Tests

`tests/self_roundtrip.rs` is **synthetic** — round-trips against data this crate generated,
not against any Windows-produced fixtures. See the "CRYPTO UNVALIDATED" section above.

## License

MIT — see `LICENSE`.
