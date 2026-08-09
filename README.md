# ms-gkdi

[![Crates.io](https://img.shields.io/crates/v/ms-gkdi.svg)](https://crates.io/crates/ms-gkdi)
[![Docs.rs](https://docs.rs/ms-gkdi/badge.svg)](https://docs.rs/ms-gkdi)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust [MS-GKDI](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/) (Group Key Distribution) primitives — the L0/L1/L2 seed-key tree walk, the SP800-108 counter-mode KDF Windows uses to derive it, and the `ISDKey::GetKey` RPC caller for fetching envelopes from a domain controller. Extracted from [`dpapi-ng`](https://github.com/icedracon/dpapi-ng) so the tree walk and RPC can be reused independently of the DPAPI-NG CMS layer (LAPS-v2, gMSA, and dMSA blob unwrapping still live in `dpapi-ng`). Part of the [icedracon](https://github.com/icedracon) offensive-AD Rust ecosystem.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. **CRYPTO UNVALIDATED — do not publish to crates.io until the KAT harness lands.** The `Cargo.toml` carries `[package.metadata.publish_gate] status = "unvalidated-crypto"` as a machine-readable reminder for anyone who tries `cargo publish`.

Three items block the publish gate:

1. **KAT vs a live Server 2022 DC** — fetch a real `GROUP_KEY_ENVELOPE` via `ISDKey::GetKey` for a known root key, walk it down to a chosen `(L0, L1, L2)` node, and diff the L2 seed byte-for-byte against the DC's own computation.
2. **Cross-check vs Microsoft's reference [`dpapi-ng.py`](https://github.com/microsoft/dpapi-ng)** — feed the same envelope + target `(L1, L2)` to both implementations and diff the L2 output.
3. **Documented answer for the KDF context byte-order.** Current `kdf_context()` emits the root-key GUID as raw bytes followed by three little-endian `i32` indices. MS-GKDI 3.1.4.1.2 does not spell out endianness explicitly for the context blob; the choice needs a written reference before this crate can ship as "conformant".

## What it does

Parses `KEY_IDENTIFIER` and `GROUP_KEY_ENVELOPE` (the wire structs MS-GKDI 3.1.4.1 defines), walks the L0/L1/L2 tree with `compute_l2_key`, and exposes the SP800-108 counter-mode KDF with the `"KDS service"` label as `sp800_108_counter`. The `rpc` module drives `ISDKey::GetKey` over a sealed `ncacn_ip_tcp` bind (via the sibling `dcerpc` crate) so callers can request envelopes from a DC directly. Once a `GROUP_KEY_ENVELOPE` is in hand, the tree walk hands back the L2 seed that downstream code (typically `dpapi-ng`) unwraps CMS-encrypted secrets with.

## Usage

```rust,no_run
use ms_gkdi::gkdi::{GroupKeyEnvelope, compute_l2_key};

let envelope_bytes: &[u8] = fetch_envelope_from_dc();
let envelope = GroupKeyEnvelope::parse(envelope_bytes)?;

// Walk from the seed the DC handed us down to the (L1, L2) node we need.
let l2_seed = compute_l2_key(&envelope, envelope.l1_index, envelope.l2_index)?;

// l2_seed feeds the DPAPI-NG CMS unwrap upstream (see dpapi-ng).
# fn fetch_envelope_from_dc() -> Vec<u8> { unimplemented!() }
# Ok::<(), ms_gkdi::GkdiError>(())
```

The async RPC path is `rpc::get_key(target, root_key_id, l0, l1, l2).await`, returning the same `GROUP_KEY_ENVELOPE` bytes fresh from the DC.

## What works / what does not (this version)

- ✅ Working: `KEY_IDENTIFIER` + `GROUP_KEY_ENVELOPE` + `KdfParameters` + `RootKeyId` parsers, `compute_l2_key` L0/L1/L2 walk, `sp800_108_counter` (SHA-1/SHA-256/SHA-384/SHA-512), `kds_service_label`, `ISDKey::GetKey` async client, AES-KW key unwrap, synthetic self-roundtrip tests.
- ⚠ Blocked on validation: no KAT against a live Server 2022 DC; no cross-check vs Microsoft's reference `dpapi-ng.py`; KDF context endianness undocumented (see Status). `tests/self_roundtrip.rs` round-trips this crate's own output — it is not a conformance test.

## Related icedracon crates

- [`dpapi-ng`](https://github.com/icedracon/dpapi-ng) — CMS unwrap layer that consumes the L2 seed for LAPS-v2 / gMSA / dMSA blobs.
- [`dcerpc`](https://crates.io/crates/dcerpc) + [`ms-ndr`](https://crates.io/crates/ms-ndr) — transport and NDR layers the `ISDKey::GetKey` client is built on.
- [`ms-pac-forge`](https://github.com/icedracon/ms-pac-forge) — once a gMSA/dMSA key is recovered here, feed it as the service-account key to a Silver-ticket forge.
- [`credssp`](https://github.com/icedracon/credssp), [`ms-nrpc`](https://github.com/icedracon/ms-nrpc) — sibling crates in the Kerberos + credential-auth cluster.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
