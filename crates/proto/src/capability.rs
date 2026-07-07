pub const CAPABILITY_VERSION: u8 = 1;
pub const CAPABILITY_TTL_SECS: u64 = 300;

const CAP_MAGIC: &[u8; 4] = b"SBZC";
const CLOCK_SKEW_SECS: u64 = 60;
const COMMAND_DIGEST_DOMAIN: &[u8] = b"sembazuru command-digest v1";
const VFS_DIGEST_DOMAIN: &[u8] = b"sembazuru vfs-execution v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionCapability {
    pub version: u8,
    pub worker_id: String,
    pub action_id: String,
    pub session_id: String,
    pub command_digest: [u8; 32],
    pub vfs_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    TooShort,
    BadMac,
    BadMagic,
    BadVersion,
    Truncated,
    Expired,
    NotYetValid,
}

impl CapError {
    pub fn reason(&self) -> &'static str {
        match self {
            CapError::TooShort => "capability too short",
            CapError::BadMac => "capability signature invalid",
            CapError::BadMagic => "capability magic invalid",
            CapError::BadVersion => "capability version invalid",
            CapError::Truncated => "capability truncated",
            CapError::Expired => "capability expired",
            CapError::NotYetValid => "capability not yet valid",
        }
    }
}

pub fn cap_key(cluster_token: &str) -> [u8; 32] {
    blake3::derive_key("sembazuru action-capability v1", cluster_token.as_bytes())
}

pub fn command_digest(
    argv: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMAND_DIGEST_DOMAIN);

    hash_count(&mut hasher, argv.len());
    for arg in argv {
        hash_len_prefixed(&mut hasher, arg.as_bytes());
    }

    let mut entries: Vec<(&String, &String)> = env.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    hash_count(&mut hasher, entries.len());
    for (key, value) in entries {
        hash_len_prefixed(&mut hasher, key.as_bytes());
        hash_len_prefixed(&mut hasher, value.as_bytes());
    }

    hash_len_prefixed(&mut hasher, cwd.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn vfs_digest(vfs: Option<&crate::v0::VfsExecution>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(VFS_DIGEST_DOMAIN);

    match vfs {
        None => {
            hasher.update(&[0]);
        }
        Some(v) => {
            hasher.update(&[1]);
            hash_len_prefixed(&mut hasher, v.agent_fileserver.as_bytes());
            hash_len_prefixed(&mut hasher, v.vfs_root.as_bytes());
            hash_len_prefixed(&mut hasher, v.trace_dir.as_bytes());
            hasher.update(&[v.strict as u8]);
            hasher.update(&[v.allow_original_cwd as u8]);
        }
    }

    *hasher.finalize().as_bytes()
}

fn hash_count(hasher: &mut blake3::Hasher, len: usize) {
    let len = u32::try_from(len).expect("capability field count exceeds u32");
    hasher.update(&len.to_le_bytes());
}

fn hash_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("capability field length exceeds u32");
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
}

fn signing_bytes(cap: &ActionCapability) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(CAP_MAGIC);
    out.push(cap.version);
    append_len_prefixed(&mut out, cap.worker_id.as_bytes());
    append_len_prefixed(&mut out, cap.action_id.as_bytes());
    append_len_prefixed(&mut out, cap.session_id.as_bytes());
    out.extend_from_slice(&cap.vfs_digest);
    out.extend_from_slice(&cap.command_digest);
    out.extend_from_slice(&cap.issued_at.to_le_bytes());
    out.extend_from_slice(&cap.expires_at.to_le_bytes());
    out.extend_from_slice(&cap.nonce);
    out
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("capability field length exceeds u32");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

impl ActionCapability {
    pub fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
        let body = signing_bytes(self);
        let mac = blake3::keyed_hash(key, &body);
        let mut out = body;
        out.extend_from_slice(mac.as_bytes());
        out
    }
}

pub fn decode_and_verify(
    bytes: &[u8],
    key: &[u8; 32],
    now: u64,
) -> Result<ActionCapability, CapError> {
    if bytes.len() < 32 {
        return Err(CapError::TooShort);
    }

    let (body, mac) = bytes.split_at(bytes.len() - 32);
    let expected = blake3::keyed_hash(key, body);
    let mac_arr: [u8; 32] = mac.try_into().map_err(|_| CapError::TooShort)?;
    if expected != blake3::Hash::from_bytes(mac_arr) {
        return Err(CapError::BadMac);
    }

    let mut cursor = Cursor::new(body);
    let magic = cursor.fixed::<4>()?;
    if &magic != CAP_MAGIC {
        return Err(CapError::BadMagic);
    }

    let version = cursor.byte()?;
    if version != CAPABILITY_VERSION {
        return Err(CapError::BadVersion);
    }

    let worker_id = cursor.string()?;
    let action_id = cursor.string()?;
    let session_id = cursor.string()?;
    let vfs_digest = cursor.fixed::<32>()?;
    let command_digest = cursor.fixed::<32>()?;
    let issued_at = cursor.u64()?;
    let expires_at = cursor.u64()?;
    let nonce = cursor.fixed::<16>()?;

    if !cursor.is_empty() {
        return Err(CapError::Truncated);
    }

    let cap = ActionCapability {
        version,
        worker_id,
        action_id,
        session_id,
        command_digest,
        vfs_digest,
        issued_at,
        expires_at,
        nonce,
    };

    if now > cap.expires_at {
        return Err(CapError::Expired);
    }
    if cap.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(CapError::NotYetValid);
    }

    Ok(cap)
}

struct Cursor<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, CapError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, CapError> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, CapError> {
        Ok(u64::from_le_bytes(self.fixed::<8>()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CapError> {
        let bytes = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn string(&mut self) -> Result<String, CapError> {
        let len = self.u32()? as usize;
        let bytes = self.bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| CapError::Truncated)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], CapError> {
        let end = self.pos.checked_add(len).ok_or(CapError::Truncated)?;
        let bytes = self.body.get(self.pos..end).ok_or(CapError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.pos == self.body.len()
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn sample_cap() -> ActionCapability {
        ActionCapability {
            version: CAPABILITY_VERSION,
            worker_id: "worker-a".to_string(),
            action_id: "action-1".to_string(),
            session_id: "session-1".to_string(),
            command_digest: [9; 32],
            vfs_digest: [5; 32],
            issued_at: 1_000,
            expires_at: 1_300,
            nonce: [7; 16],
        }
    }

    #[test]
    fn round_trip_encode_decode_verifies_every_field() {
        let key = cap_key("cluster-secret");
        let cap = sample_cap();
        let encoded = cap.encode(&key);

        let decoded = decode_and_verify(&encoded, &key, 1_010).unwrap();

        assert_eq!(decoded.version, cap.version);
        assert_eq!(decoded.worker_id, cap.worker_id);
        assert_eq!(decoded.action_id, cap.action_id);
        assert_eq!(decoded.session_id, cap.session_id);
        assert_eq!(decoded.command_digest, cap.command_digest);
        assert_eq!(decoded.vfs_digest, cap.vfs_digest);
        assert_eq!(decoded.issued_at, cap.issued_at);
        assert_eq!(decoded.expires_at, cap.expires_at);
        assert_eq!(decoded.nonce, cap.nonce);
    }

    #[test]
    fn vfs_digest_binds_presence_and_all_fields() {
        let v = crate::v0::VfsExecution {
            agent_fileserver: "127.0.0.1:1234".to_string(),
            vfs_root: "C:\\src".to_string(),
            trace_dir: "C:\\trace".to_string(),
            strict: true,
            allow_original_cwd: false,
        };

        assert_ne!(vfs_digest(None), vfs_digest(Some(&v)));

        let same = v.clone();
        assert_eq!(vfs_digest(Some(&v)), vfs_digest(Some(&same)));

        let mut changed_agent = v.clone();
        changed_agent.agent_fileserver = "127.0.0.1:5678".to_string();
        assert_ne!(vfs_digest(Some(&v)), vfs_digest(Some(&changed_agent)));

        let mut changed_root = v.clone();
        changed_root.vfs_root = "C:\\other".to_string();
        assert_ne!(vfs_digest(Some(&v)), vfs_digest(Some(&changed_root)));

        let mut changed_trace = v.clone();
        changed_trace.trace_dir = "C:\\other-trace".to_string();
        assert_ne!(vfs_digest(Some(&v)), vfs_digest(Some(&changed_trace)));

        let mut changed_strict = v.clone();
        changed_strict.strict = false;
        assert_ne!(vfs_digest(Some(&v)), vfs_digest(Some(&changed_strict)));

        let mut changed_allow_original_cwd = v.clone();
        changed_allow_original_cwd.allow_original_cwd = true;
        assert_ne!(
            vfs_digest(Some(&v)),
            vfs_digest(Some(&changed_allow_original_cwd))
        );
    }

    #[test]
    fn wrong_key_is_rejected_with_bad_mac() {
        let cap = sample_cap();
        let encoded = cap.encode(&cap_key("right"));

        assert_eq!(
            decode_and_verify(&encoded, &cap_key("wrong"), 1_010),
            Err(CapError::BadMac)
        );
    }

    #[test]
    fn body_tamper_is_rejected_with_bad_mac() {
        let key = cap_key("cluster-secret");
        let mut encoded = sample_cap().encode(&key);
        encoded[5] ^= 0x55;

        assert_eq!(
            decode_and_verify(&encoded, &key, 1_010),
            Err(CapError::BadMac)
        );
    }

    #[test]
    fn expired_and_future_capabilities_are_rejected() {
        let key = cap_key("cluster-secret");
        let expired = sample_cap().encode(&key);
        assert_eq!(
            decode_and_verify(&expired, &key, 1_301),
            Err(CapError::Expired)
        );

        let mut future = sample_cap();
        future.issued_at = 2_000;
        future.expires_at = 2_300;
        let future = future.encode(&key);
        assert_eq!(
            decode_and_verify(&future, &key, 1_939),
            Err(CapError::NotYetValid)
        );
    }

    #[test]
    fn truncated_and_foreign_bytes_never_panic() {
        let key = cap_key("cluster-secret");

        assert_eq!(decode_and_verify(&[], &key, 1_010), Err(CapError::TooShort));
        assert_eq!(
            decode_and_verify(&[0u8; 31], &key, 1_010),
            Err(CapError::TooShort)
        );

        let mut valid_mac_truncated = signing_bytes(&sample_cap());
        valid_mac_truncated.truncate(valid_mac_truncated.len() - 1);
        let mac = blake3::keyed_hash(&key, &valid_mac_truncated);
        valid_mac_truncated.extend_from_slice(mac.as_bytes());
        assert_eq!(
            decode_and_verify(&valid_mac_truncated, &key, 1_010),
            Err(CapError::Truncated)
        );

        for len in [32usize, 33, 48, 64, 95, 128] {
            let mut bytes = Vec::with_capacity(len);
            for i in 0..len {
                bytes.push((i as u8).wrapping_mul(37).wrapping_add(11));
            }
            let _ = decode_and_verify(&bytes, &key, 1_010);
        }
    }

    #[test]
    fn command_digest_is_env_order_invariant() {
        let mut a = HashMap::new();
        a.insert("INCLUDE".to_string(), "C:\\include".to_string());
        a.insert("PATH".to_string(), "C:\\bin".to_string());

        let mut b = HashMap::new();
        b.insert("PATH".to_string(), "C:\\bin".to_string());
        b.insert("INCLUDE".to_string(), "C:\\include".to_string());

        assert_eq!(
            command_digest(&["cl".into(), "a.cc".into()], &a, "C:\\src"),
            command_digest(&["cl".into(), "a.cc".into()], &b, "C:\\src")
        );
    }

    #[test]
    fn command_digest_changes_when_bound_inputs_change() {
        let mut env = HashMap::new();
        env.insert("A".to_string(), "1".to_string());
        let base = command_digest(&["cl".into(), "a.cc".into()], &env, "C:\\src");

        assert_ne!(
            base,
            command_digest(&["cl".into(), "b.cc".into()], &env, "C:\\src")
        );

        env.insert("A".to_string(), "2".to_string());
        assert_ne!(
            base,
            command_digest(&["cl".into(), "a.cc".into()], &env, "C:\\src")
        );

        env.insert("A".to_string(), "1".to_string());
        assert_ne!(
            base,
            command_digest(&["cl".into(), "a.cc".into()], &env, "C:\\other")
        );
    }
}
