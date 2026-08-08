//! MS-GKDI: the Group Key Distribution structures and the L0/L1/L2 key-tree walk.
//!
//! A DPAPI-NG blob does not carry a key — it carries a *key identifier*: which KDS root key,
//! and which (L0, L1, L2) node of that root's tree. A domain controller hands out a
//! [`GroupKeyEnvelope`] for some node at or above the one you asked for; deriving downwards
//! to the exact node is [`compute_l2_key`], and it is pure computation — no network.

use crate::cursor::Cursor;
use crate::kdf::{kdf, kds_service_label, HashAlg};
use crate::{GkdiError, Result};

/// `KDSK` — the magic in a key-identifier blob.
pub const KEY_IDENTIFIER_MAGIC: u32 = 0x4B53_444B;
/// `KDSK` — the magic in a group-key envelope.
pub const ENVELOPE_MAGIC: u32 = 0x4B53_444B;
/// The tree is 32-ary: L1 and L2 indices run 0..=31.
pub const TREE_ARITY: i32 = 32;

/// A 16-byte GUID in its on-wire (mixed-endian) form, kept as raw bytes because that is
/// exactly what the KDF context wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootKeyId(pub [u8; 16]);

impl RootKeyId {
    pub fn from_bytes(b: &[u8]) -> Result<RootKeyId> {
        Ok(RootKeyId(
            b.get(..16)
                .ok_or(GkdiError::Truncated("root key identifier"))?
                .try_into()
                .unwrap(),
        ))
    }
}

impl std::fmt::Display for RootKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
            b[3],
            b[2],
            b[1],
            b[0],
            b[5],
            b[4],
            b[7],
            b[6],
            b[8],
            b[9],
            b[10..16]
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        )
    }
}

/// `KDF_PARAMETERS` — names the hash the key tree is derived with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParameters {
    pub hash: HashAlg,
}

impl KdfParameters {
    pub fn parse(b: &[u8]) -> Result<KdfParameters> {
        let mut c = Cursor::new(b);
        // Two fixed u32 headers, then the length of the NUL-terminated UTF-16LE name,
        // then another fixed u32, then the name itself.
        c.skip(8, "kdf parameters header")?;
        let name_len = c.u32le("kdf hash name length")? as usize;
        c.skip(4, "kdf parameters padding")?;
        let raw = c.take(name_len, "kdf hash name")?;
        Ok(KdfParameters {
            hash: HashAlg::from_name(&utf16_lossy(raw))?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let name: Vec<u8> = format!("{}\0", self.hash.name())
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut out = Vec::with_capacity(20 + name.len());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&name);
        out
    }
}

/// The `KEY_IDENTIFIER` carried in a protected blob: which root key and which tree node the
/// content was encrypted for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyIdentifier {
    pub version: u32,
    pub flags: u32,
    pub l0: i32,
    pub l1: i32,
    pub l2: i32,
    pub root_key_id: RootKeyId,
    pub kdf_algorithm: String,
    pub kdf_parameters: Vec<u8>,
    pub secret_algorithm: String,
    pub secret_parameters: Vec<u8>,
    pub private_key_length: u32,
    pub public_key_length: u32,
    pub domain_name: String,
    pub forest_name: String,
}

impl KeyIdentifier {
    /// `true` when the blob was protected with the public-key half of the node (the
    /// key-agreement path) rather than the seed key directly.
    pub fn is_public_key(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub fn parse(b: &[u8]) -> Result<KeyIdentifier> {
        let mut c = Cursor::new(b);
        let version = c.u32le("version")?;
        let magic = c.u32le("magic")?;
        if magic != KEY_IDENTIFIER_MAGIC {
            return Err(GkdiError::BadMagic {
                what: "key identifier",
                got: magic,
            });
        }
        let flags = c.u32le("flags")?;
        let l0 = c.i32le("l0 index")?;
        let l1 = c.i32le("l1 index")?;
        let l2 = c.i32le("l2 index")?;
        let root_key_id = RootKeyId::from_bytes(c.take(16, "root key identifier")?)?;
        let kdf_alg_len = c.u32le("kdf algorithm length")? as usize;
        let kdf_param_len = c.u32le("kdf parameters length")? as usize;
        let secret_alg_len = c.u32le("secret algorithm length")? as usize;
        let secret_param_len = c.u32le("secret parameters length")? as usize;
        let private_key_length = c.u32le("private key length")?;
        let public_key_length = c.u32le("public key length")?;
        let domain_len = c.u32le("domain name length")? as usize;
        let forest_len = c.u32le("forest name length")? as usize;

        let kdf_algorithm = utf16_lossy(c.take(kdf_alg_len, "kdf algorithm")?);
        let kdf_parameters = c.take(kdf_param_len, "kdf parameters")?.to_vec();
        let secret_algorithm = utf16_lossy(c.take(secret_alg_len, "secret algorithm")?);
        let secret_parameters = c.take(secret_param_len, "secret parameters")?.to_vec();
        let domain_name = utf16_lossy(c.take(domain_len, "domain name")?);
        let forest_name = utf16_lossy(c.take(forest_len, "forest name")?);

        Ok(KeyIdentifier {
            version,
            flags,
            l0,
            l1,
            l2,
            root_key_id,
            kdf_algorithm,
            kdf_parameters,
            secret_algorithm,
            secret_parameters,
            private_key_length,
            public_key_length,
            domain_name,
            forest_name,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let kdf_alg = utf16z(&self.kdf_algorithm);
        let secret_alg = utf16z(&self.secret_algorithm);
        let domain = utf16z(&self.domain_name);
        let forest = utf16z(&self.forest_name);

        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&KEY_IDENTIFIER_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.l0.to_le_bytes());
        out.extend_from_slice(&self.l1.to_le_bytes());
        out.extend_from_slice(&self.l2.to_le_bytes());
        out.extend_from_slice(&self.root_key_id.0);
        out.extend_from_slice(&(kdf_alg.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.kdf_parameters.len() as u32).to_le_bytes());
        out.extend_from_slice(&(secret_alg.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.secret_parameters.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.private_key_length.to_le_bytes());
        out.extend_from_slice(&self.public_key_length.to_le_bytes());
        out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
        out.extend_from_slice(&(forest.len() as u32).to_le_bytes());
        out.extend_from_slice(&kdf_alg);
        out.extend_from_slice(&self.kdf_parameters);
        out.extend_from_slice(&secret_alg);
        out.extend_from_slice(&self.secret_parameters);
        out.extend_from_slice(&domain);
        out.extend_from_slice(&forest);
        out
    }

    /// The hash the key tree for this blob is derived with.
    pub fn hash(&self) -> Result<HashAlg> {
        Ok(KdfParameters::parse(&self.kdf_parameters)?.hash)
    }
}

/// `GROUP_KEY_ENVELOPE` — what `GetKey` returns: seed key material for one node of the tree,
/// at or above the node you asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyEnvelope {
    pub version: u32,
    pub flags: u32,
    pub l0: i32,
    pub l1: i32,
    pub l2: i32,
    pub root_key_id: RootKeyId,
    pub kdf_algorithm: String,
    pub kdf_parameters: Vec<u8>,
    pub secret_algorithm: String,
    pub secret_parameters: Vec<u8>,
    pub private_key_length: u32,
    pub public_key_length: u32,
    pub domain_name: String,
    pub forest_name: String,
    pub l1_key: Vec<u8>,
    pub l2_key: Vec<u8>,
}

impl GroupKeyEnvelope {
    /// `true` if this envelope carries the public key rather than seed keys.
    pub fn is_public_key(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub fn hash(&self) -> Result<HashAlg> {
        Ok(KdfParameters::parse(&self.kdf_parameters)?.hash)
    }

    pub fn parse(b: &[u8]) -> Result<GroupKeyEnvelope> {
        let mut c = Cursor::new(b);
        let version = c.u32le("version")?;
        let magic = c.u32le("magic")?;
        if magic != ENVELOPE_MAGIC {
            return Err(GkdiError::BadMagic {
                what: "group key envelope",
                got: magic,
            });
        }
        let flags = c.u32le("flags")?;
        let l0 = c.i32le("l0 index")?;
        let l1 = c.i32le("l1 index")?;
        let l2 = c.i32le("l2 index")?;
        let root_key_id = RootKeyId::from_bytes(c.take(16, "root key identifier")?)?;
        let kdf_alg_len = c.u32le("kdf algorithm length")? as usize;
        let kdf_param_len = c.u32le("kdf parameters length")? as usize;
        let secret_alg_len = c.u32le("secret algorithm length")? as usize;
        let secret_param_len = c.u32le("secret parameters length")? as usize;
        let private_key_length = c.u32le("private key length")?;
        let public_key_length = c.u32le("public key length")?;
        let l1_key_len = c.u32le("l1 key length")? as usize;
        let l2_key_len = c.u32le("l2 key length")? as usize;
        let domain_len = c.u32le("domain name length")? as usize;
        let forest_len = c.u32le("forest name length")? as usize;

        let kdf_algorithm = utf16_lossy(c.take(kdf_alg_len, "kdf algorithm")?);
        let kdf_parameters = c.take(kdf_param_len, "kdf parameters")?.to_vec();
        let secret_algorithm = utf16_lossy(c.take(secret_alg_len, "secret algorithm")?);
        let secret_parameters = c.take(secret_param_len, "secret parameters")?.to_vec();
        let domain_name = utf16_lossy(c.take(domain_len, "domain name")?);
        let forest_name = utf16_lossy(c.take(forest_len, "forest name")?);
        let l1_key = c.take(l1_key_len, "l1 key")?.to_vec();
        let l2_key = c.take(l2_key_len, "l2 key")?.to_vec();

        Ok(GroupKeyEnvelope {
            version,
            flags,
            l0,
            l1,
            l2,
            root_key_id,
            kdf_algorithm,
            kdf_parameters,
            secret_algorithm,
            secret_parameters,
            private_key_length,
            public_key_length,
            domain_name,
            forest_name,
            l1_key,
            l2_key,
        })
    }
}

/// The KDF context for one tree node: root key GUID followed by the three indices.
pub fn kdf_context(root: RootKeyId, l0: i32, l1: i32, l2: i32) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(28);
    ctx.extend_from_slice(&root.0);
    ctx.extend_from_slice(&l0.to_le_bytes());
    ctx.extend_from_slice(&l1.to_le_bytes());
    ctx.extend_from_slice(&l2.to_le_bytes());
    ctx
}

/// Walk an envelope down to the exact `(l1, l2)` node the blob was encrypted for.
///
/// The DC returns the key for the node it is willing to hand out; every step from there to
/// the requested node is a one-way KDF, which is what makes the tree useful — a key for a
/// later node cannot recover an earlier one.
pub fn compute_l2_key(env: &GroupKeyEnvelope, want_l1: i32, want_l2: i32) -> Result<Vec<u8>> {
    if env.is_public_key() {
        return Err(GkdiError::PublicKeyEnvelope);
    }
    if !(0..TREE_ARITY).contains(&want_l1) || !(0..TREE_ARITY).contains(&want_l2) {
        return Err(GkdiError::BadTreeIndex {
            l1: want_l1,
            l2: want_l2,
        });
    }
    let hash = env.hash()?;
    let label = kds_service_label();
    let key_len = 64;

    let mut l1 = env.l1;
    let mut l1_key = env.l1_key.clone();
    let mut l2 = env.l2;
    let mut l2_key = env.l2_key.clone();

    // The L2 chain only runs downwards. A fully-seeded node (l2 == 31), a move to a different
    // L1 branch, or a request for a *later* L2 than we hold all mean the chain has to be
    // re-seeded from the L1 key — the tree is one-way, so a later node is not reachable from
    // an earlier one.
    let mut reseed_l2 = l2 == TREE_ARITY - 1 || env.l1 != want_l1 || want_l2 > l2;
    if l2 != TREE_ARITY - 1 && env.l1 != want_l1 {
        l1 -= 1;
    }
    while l1 != want_l1 {
        if l1_key.is_empty() {
            return Err(GkdiError::MissingSeedKey("L1"));
        }
        reseed_l2 = true;
        l1 -= 1;
        l1_key = kdf(
            hash,
            &l1_key,
            &label,
            &kdf_context(env.root_key_id, env.l0, l1, -1),
            key_len,
        );
    }
    if reseed_l2 {
        if l1_key.is_empty() {
            return Err(GkdiError::MissingSeedKey("L1"));
        }
        l2 = TREE_ARITY - 1;
        l2_key = kdf(
            hash,
            &l1_key,
            &label,
            &kdf_context(env.root_key_id, env.l0, l1, l2),
            key_len,
        );
    }
    if l2 < want_l2 {
        // Only reachable if the envelope carried no L1 key to re-seed from.
        return Err(GkdiError::MissingSeedKey("L1"));
    }
    while l2 != want_l2 {
        if l2_key.is_empty() {
            return Err(GkdiError::MissingSeedKey("L2"));
        }
        l2 -= 1;
        l2_key = kdf(
            hash,
            &l2_key,
            &label,
            &kdf_context(env.root_key_id, env.l0, l1, l2),
            key_len,
        );
    }
    Ok(l2_key)
}

pub(crate) fn utf16_lossy(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed = match units.iter().rposition(|&u| u != 0) {
        Some(i) => &units[..=i],
        None => &[][..],
    };
    String::from_utf16_lossy(trimmed)
}

pub(crate) fn utf16z(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    out
}
