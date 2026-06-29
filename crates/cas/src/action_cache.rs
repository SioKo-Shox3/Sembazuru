//! The action cache (M4.3): "this exact action already ran; here is its result,
//! skip the work." Built on the same disk root as the [`BlobStore`](crate::
//! BlobStore) — output bytes live in the CAS, this cache stores the small
//! metadata that ties an action to them.
//!
//! **Two-phase fingerprint** (BuildXL's design, for on-demand inputs):
//!   * the **weak** key — [`weak_fingerprint`] over the command line, canonical
//!     environment, and toolchain digest — is known before the action runs and
//!     maps to the *input manifest* a prior run observed (stored opaquely here;
//!     the agent owns its encoding);
//!   * the **strong** key — [`strong_fingerprint`] over the weak key and the
//!     hash of those inputs' *current* content — maps to the [`ActionResult`].
//!
//! On a rebuild: look up the weak key → manifest, re-hash the manifest's inputs,
//! derive the strong key, and if it resolves to a result, publish the cached
//! outputs and skip execution. Any changed input moves the strong key, so a
//! stale result can never be served — correctness over speed.

use std::io;
use std::path::{Path, PathBuf};

use crate::store::write_atomic;
use crate::{Digest, DigestError};

/// Environment variables excluded from the weak fingerprint: per-process or
/// per-machine noise that does not change a compiler's output. Matched
/// case-insensitively; `VSCMD_`/`__VSCMD` catch the VS dev-shell's volatile set.
/// Conservative on purpose — anything not listed *is* part of the key, so a
/// missed entry costs a spurious miss (safe), never a false hit.
const VOLATILE_ENV: &[&str] = &[
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERNAME",
    "USERPROFILE",
    "USERDOMAIN",
    "HOMEPATH",
    "HOMEDRIVE",
    "COMPUTERNAME",
    "LOGONSERVER",
    "SESSIONNAME",
    "PROMPT",
    "RANDOM",
];

fn is_volatile(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("VSCMD_")
        || upper.starts_with("__VSCMD")
        || VOLATILE_ENV.iter().any(|v| *v == upper)
}

/// Weak-key schema version (ADR 0014). Folded into every weak fingerprint, so
/// bumping it invalidates ALL existing cache entries at once (they miss and
/// re-run, producing byte-identical output — safe). Bump this whenever the weak
/// key's *meaning* changes (a new keyed dimension, a changed normalization), so a
/// mixed on-disk cache can never serve an entry computed under different rules.
/// v3 (COR-004): the record policy tightened to a verified-deterministic tool
/// profile (arbitrary tools are now distributed but never recorded). The key
/// meaning is unchanged, but a cache populated under the prior looser policy
/// could still hold an entry for an arbitrary tool whose output depends on
/// un-keyed vectors; bumping the schema retires those entries so the tightened
/// policy applies retroactively.
const WEAK_KEY_SCHEMA: u32 = 3;

/// The weak fingerprint: everything statically known about an action before it
/// runs. A schema tag, `argv` in order, the action's working directory, the
/// non-volatile environment sorted by name, and the toolchain binary's content
/// digest (so a compiler upgrade invalidates the cache automatically — sccache's
/// approach).
///
/// `cwd` is folded (ADR 0014 / COR-005 problem B): the same argv+env run in a
/// different directory can embed that directory in its output (e.g. a process
/// that records its own `getcwd()`), so two such runs must not share a key. It is
/// case/separator-normalized (Windows paths are case-insensitive) so incidental
/// spelling does not cause spurious misses; folding it can only *refine* the key
/// (more misses), never widen it (no false hit).
pub fn weak_fingerprint(
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    toolchain: &Digest,
) -> Digest {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"sbz-weak\0");
    blob.extend_from_slice(&WEAK_KEY_SCHEMA.to_le_bytes());
    blob.extend_from_slice(b"\0argv\0");
    for a in argv {
        blob.extend_from_slice(a.as_bytes());
        blob.push(0);
    }
    blob.extend_from_slice(b"\0cwd\0");
    blob.extend_from_slice(cwd.replace('/', "\\").to_ascii_lowercase().as_bytes());
    let mut kept: Vec<(String, &str)> = env
        .iter()
        .filter(|(k, _)| !is_volatile(k))
        // Normalize the *name* case (Windows env names are case-insensitive);
        // values are kept verbatim.
        .map(|(k, v)| (k.to_ascii_uppercase(), v.as_str()))
        .collect();
    kept.sort();
    blob.extend_from_slice(b"\0env\0");
    for (k, v) in kept {
        blob.extend_from_slice(k.as_bytes());
        blob.push(b'=');
        blob.extend_from_slice(v.as_bytes());
        blob.push(0);
    }
    blob.extend_from_slice(b"\0tool\0");
    blob.extend_from_slice(toolchain.canonical().as_bytes());
    Digest::of(&blob)
}

/// The strong fingerprint: the weak key bound to the hash of the inputs' current
/// content (`input_hash`, e.g. from `sembazuru_tracer::action_key::manifest_hash`).
pub fn strong_fingerprint(weak: &Digest, input_hash: &str) -> Digest {
    let mut blob = Vec::with_capacity(weak.canonical().len() + 1 + input_hash.len());
    blob.extend_from_slice(weak.canonical().as_bytes());
    blob.push(0);
    blob.extend_from_slice(input_hash.as_bytes());
    Digest::of(&blob)
}

/// One produced output: where to publish it (build-root-relative logical path,
/// so a result built under one root can be rehomed under another) and the CAS
/// digest of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFile {
    pub logical_path: String,
    pub digest: Digest,
}

/// The cached result of running an action. Output bytes live in the CAS; this
/// records their digests plus the exit code and (optionally) captured streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionResult {
    pub exit_code: i32,
    pub outputs: Vec<OutputFile>,
    pub stdout: Option<Digest>,
    pub stderr: Option<Digest>,
}

// --- ActionResult codec (hand-rolled, dependency-free, stable on disk) -----

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn get_str(buf: &[u8], pos: &mut usize) -> Result<String, CacheCodecError> {
    let len = get_u32(buf, pos)? as usize;
    let end = pos.checked_add(len).ok_or(CacheCodecError)?;
    let slice = buf.get(*pos..end).ok_or(CacheCodecError)?;
    let s = String::from_utf8(slice.to_vec()).map_err(|_| CacheCodecError)?;
    *pos = end;
    Ok(s)
}

fn get_u32(buf: &[u8], pos: &mut usize) -> Result<u32, CacheCodecError> {
    let end = pos.checked_add(4).ok_or(CacheCodecError)?;
    let slice = buf.get(*pos..end).ok_or(CacheCodecError)?;
    *pos = end;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn get_opt_digest(buf: &[u8], pos: &mut usize) -> Result<Option<Digest>, CacheCodecError> {
    let s = get_str(buf, pos)?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Digest::parse(&s).map_err(|_| CacheCodecError)?))
    }
}

/// A stored ActionResult could not be decoded (corruption / format drift). The
/// cache treats this as a miss, never a panic.
#[derive(Debug)]
pub struct CacheCodecError;

/// Magic + version for the on-disk ActionResult codec (ADR 0014). An
/// unrecognized magic/version decodes to an error → a cache miss, so a format
/// change can never be silently misread as a valid result (COR-005 "codec に
/// version なし"). Bump `RESULT_CODEC_VERSION` whenever the layout below changes.
const RESULT_CODEC_MAGIC: &[u8; 4] = b"SBZR";
const RESULT_CODEC_VERSION: u8 = 1;

impl ActionResult {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(RESULT_CODEC_MAGIC);
        buf.push(RESULT_CODEC_VERSION);
        buf.extend_from_slice(&self.exit_code.to_le_bytes());
        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            put_str(&mut buf, &o.logical_path);
            put_str(&mut buf, &o.digest.canonical());
        }
        put_str(
            &mut buf,
            &self
                .stdout
                .as_ref()
                .map(|d| d.canonical())
                .unwrap_or_default(),
        );
        put_str(
            &mut buf,
            &self
                .stderr
                .as_ref()
                .map(|d| d.canonical())
                .unwrap_or_default(),
        );
        buf
    }

    fn decode(buf: &[u8]) -> Result<ActionResult, CacheCodecError> {
        // Magic + version gate: a mismatch (old/foreign/corrupt format) is a
        // decode error → cache miss, never a misread result.
        if buf.get(0..4) != Some(RESULT_CODEC_MAGIC.as_slice()) {
            return Err(CacheCodecError);
        }
        if buf.get(4) != Some(&RESULT_CODEC_VERSION) {
            return Err(CacheCodecError);
        }
        let mut pos = 5;
        let exit_code = {
            let end = pos + 4;
            let slice = buf.get(pos..end).ok_or(CacheCodecError)?;
            pos = end;
            i32::from_le_bytes(slice.try_into().unwrap())
        };
        let n = get_u32(buf, &mut pos)? as usize;
        let mut outputs = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let logical_path = get_str(buf, &mut pos)?;
            let digest = Digest::parse(&get_str(buf, &mut pos)?).map_err(|_| CacheCodecError)?;
            outputs.push(OutputFile {
                logical_path,
                digest,
            });
        }
        let stdout = get_opt_digest(buf, &mut pos)?;
        let stderr = get_opt_digest(buf, &mut pos)?;
        if pos != buf.len() {
            return Err(CacheCodecError); // trailing junk → treat as corrupt
        }
        Ok(ActionResult {
            exit_code,
            outputs,
            stdout,
            stderr,
        })
    }
}

/// Keyed (not content-addressed) store for the two cache layers. Lives under
/// `<root>/ac/`, beside the CAS's `<root>/cas/`.
pub struct ActionCache {
    weak_root: PathBuf,   // weak key  → opaque input-manifest bytes
    strong_root: PathBuf, // strong key → ActionResult bytes
}

impl ActionCache {
    /// Opens (creating if needed) the action cache under `root`.
    pub fn open(root: impl AsRef<Path>) -> io::Result<ActionCache> {
        let ac = root.as_ref().join("ac");
        let weak_root = ac.join("weak");
        let strong_root = ac.join("strong");
        std::fs::create_dir_all(&weak_root)?;
        std::fs::create_dir_all(&strong_root)?;
        Ok(ActionCache {
            weak_root,
            strong_root,
        })
    }

    fn key_path(root: &Path, key: &Digest) -> PathBuf {
        let hex = key.hex();
        root.join(&hex[0..2]).join(hex)
    }

    /// Records the input manifest a run observed under its weak key. The bytes
    /// are opaque to the cache — the agent chooses the manifest encoding.
    pub fn put_manifest(&self, weak: &Digest, manifest_bytes: &[u8]) -> io::Result<()> {
        write_atomic(&Self::key_path(&self.weak_root, weak), manifest_bytes)
    }

    /// The manifest observed for a weak key, or `None` if this command/env/
    /// toolchain combination has not been seen.
    pub fn get_manifest(&self, weak: &Digest) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(Self::key_path(&self.weak_root, weak)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Records the result for a strong key.
    pub fn put_result(&self, strong: &Digest, result: &ActionResult) -> io::Result<()> {
        write_atomic(&Self::key_path(&self.strong_root, strong), &result.encode())
    }

    /// The result for a strong key, or `None` if absent. A stored-but-corrupt
    /// entry is also `None` (treated as a miss → the action re-runs), never an
    /// error that would block the build.
    pub fn get_result(&self, strong: &Digest) -> io::Result<Option<ActionResult>> {
        match std::fs::read(Self::key_path(&self.strong_root, strong)) {
            Ok(b) => Ok(ActionResult::decode(&b).ok()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl From<DigestError> for CacheCodecError {
    fn from(_: DigestError) -> Self {
        CacheCodecError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};

    mod fuzz {
        use super::*;

        proptest! {
            #[test]
            fn action_result_decode_never_panics(bytes in any::<Vec<u8>>()) {
                let _ = ActionResult::decode(&bytes);
            }
        }
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmp_root() -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sbz-ac-test.{}.{seq}", process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn weak_fingerprint_ignores_volatile_env_and_order() {
        let tool = Digest::of(b"clang-cl v18");
        let a = weak_fingerprint(
            &argv(&["clang-cl", "/c", "a.cpp"]),
            &[
                ("PATH".into(), "c:\\one".into()),
                ("INCLUDE".into(), "c:\\sdk".into()),
                ("TEMP".into(), "c:\\users\\a\\tmp".into()),
            ],
            "c:\\proj",
            &tool,
        );
        let b = weak_fingerprint(
            &argv(&["clang-cl", "/c", "a.cpp"]),
            &[
                // PATH/TEMP differ and are reordered — must not change the key.
                ("include".into(), "c:\\sdk".into()), // name case-insensitive
                ("PATH".into(), "c:\\two".into()),
                ("TEMP".into(), "d:\\other".into()),
            ],
            "C:/Proj", // same dir, different case/separators — must not change the key
            &tool,
        );
        assert_eq!(
            a, b,
            "volatile env, name case/order, and cwd spelling must not affect the key"
        );
    }

    #[test]
    fn weak_fingerprint_changes_with_meaningful_inputs() {
        let tool = Digest::of(b"clang-cl v18");
        let base = weak_fingerprint(&argv(&["clang-cl", "/c", "a.cpp"]), &[], "c:\\proj", &tool);
        // A different arg, a different non-volatile env var, a different toolchain,
        // and a different working directory each move the key.
        assert_ne!(
            base,
            weak_fingerprint(&argv(&["clang-cl", "/c", "b.cpp"]), &[], "c:\\proj", &tool)
        );
        assert_ne!(
            base,
            weak_fingerprint(
                &argv(&["clang-cl", "/c", "a.cpp"]),
                &[("INCLUDE".into(), "c:\\sdk".into())],
                "c:\\proj",
                &tool
            )
        );
        assert_ne!(
            base,
            weak_fingerprint(
                &argv(&["clang-cl", "/c", "a.cpp"]),
                &[],
                "c:\\proj",
                &Digest::of(b"clang-cl v19")
            )
        );
        // ADR 0014 / COR-005 problem B: a different working directory moves the key
        // (a process can embed its cwd in its output), so they must not share one.
        assert_ne!(
            base,
            weak_fingerprint(&argv(&["clang-cl", "/c", "a.cpp"]), &[], "c:\\other", &tool),
            "cwd must be part of the weak key"
        );
    }

    #[test]
    fn strong_fingerprint_binds_weak_and_input_hash() {
        let tool = Digest::of(b"t");
        let weak = weak_fingerprint(&argv(&["cc"]), &[], "c:\\proj", &tool);
        let s1 = strong_fingerprint(&weak, "inputhash-AAA");
        let s2 = strong_fingerprint(&weak, "inputhash-BBB");
        assert_ne!(s1, s2, "different input content → different strong key");
        assert_eq!(s1, strong_fingerprint(&weak, "inputhash-AAA"), "stable");
    }

    #[test]
    fn action_result_round_trips() {
        let root = tmp_root();
        let cache = ActionCache::open(&root).unwrap();
        let strong = Digest::of(b"strong");
        let result = ActionResult {
            exit_code: 0,
            outputs: vec![
                OutputFile {
                    logical_path: "a.obj".into(),
                    digest: Digest::of(b"obj-bytes"),
                },
                OutputFile {
                    logical_path: "sub\\b.obj".into(),
                    digest: Digest::of(b"other"),
                },
            ],
            stdout: Some(Digest::of(b"stdout")),
            stderr: None,
        };
        assert!(cache.get_result(&strong).unwrap().is_none());
        cache.put_result(&strong, &result).unwrap();
        assert_eq!(cache.get_result(&strong).unwrap().as_ref(), Some(&result));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn action_result_decode_gates_on_magic_and_version() {
        // ADR 0014: the codec magic+version makes a foreign/old/corrupt format a
        // decode error → cache miss, never a misread result.
        let r = ActionResult {
            exit_code: 7,
            outputs: vec![],
            stdout: None,
            stderr: None,
        };
        let good = r.encode();
        assert_eq!(
            ActionResult::decode(&good).unwrap(),
            r,
            "good blob round-trips"
        );
        // An old pre-magic blob (the body without the 5-byte magic+version header)
        // is rejected, not parsed as a valid result.
        assert!(
            ActionResult::decode(&good[5..]).is_err(),
            "missing magic → miss"
        );
        // Wrong magic / wrong version → rejected.
        let mut wrong_magic = good.clone();
        wrong_magic[0] = b'X';
        assert!(
            ActionResult::decode(&wrong_magic).is_err(),
            "wrong magic → miss"
        );
        let mut wrong_ver = good.clone();
        wrong_ver[4] = 0xff;
        assert!(
            ActionResult::decode(&wrong_ver).is_err(),
            "wrong version → miss"
        );
    }

    #[test]
    fn manifest_bytes_round_trip_opaquely() {
        let root = tmp_root();
        let cache = ActionCache::open(&root).unwrap();
        let weak = Digest::of(b"weak");
        assert!(cache.get_manifest(&weak).unwrap().is_none());
        let bytes = b"\x00\x01 opaque agent-chosen manifest \xff".to_vec();
        cache.put_manifest(&weak, &bytes).unwrap();
        assert_eq!(
            cache.get_manifest(&weak).unwrap().as_deref(),
            Some(&bytes[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_result_is_a_miss_not_an_error() {
        let root = tmp_root();
        let cache = ActionCache::open(&root).unwrap();
        let strong = Digest::of(b"k");
        cache
            .put_result(
                &strong,
                &ActionResult {
                    exit_code: 0,
                    outputs: vec![],
                    stdout: None,
                    stderr: None,
                },
            )
            .unwrap();
        // Corrupt the stored bytes behind the cache's back.
        std::fs::write(
            ActionCache::key_path(&cache.strong_root, &strong),
            b"garbage",
        )
        .unwrap();
        assert!(
            cache.get_result(&strong).unwrap().is_none(),
            "corrupt entry must read as a miss, not crash or false-hit"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
