//! Agent-side action cache orchestration (M4.3): the glue that turns a traced
//! run into a cache entry, and a later identical action into a skipped
//! execution with its outputs republished from the CAS.
//!
//! It ties two crates together:
//!   * `sembazuru_tracer::action_key` — turns a run's trace into an
//!     [`InputManifest`] (the paths it read) and re-hashes that manifest's
//!     *current* content ([`manifest_hash`]) for the strong fingerprint;
//!   * `sembazuru_cas` — the [`ActionCache`] (weak→manifest, strong→result) and
//!     the [`BlobStore`] holding output bytes.
//!
//! Flow (two-phase, `docs/decisions/0003` + plan M4.3):
//!   1. [`AgentCache::resolve`] — weak key → stored manifest → re-hash inputs →
//!      strong key → result. On a hit, publish the cached outputs atomically and
//!      return the exit code; **the action does not run**.
//!   2. On a miss the caller runs the action (traced), then
//!      [`AgentCache::record`] ingests the produced outputs into the CAS and
//!      stores the manifest + result so the next build hits.
//!
//! The trace→manifest adapter ([`AgentCache::manifest_from_trace_dir`]) is a thin
//! wrapper over the tracer; the real launcher-driven traced compile is exercised
//! by the M4.6 rebuild gate. Correctness rule: any changed input moves the
//! strong key, so a stale result is never served.

use std::io;
use std::path::Path;

use sembazuru_cas::{ActionCache, ActionResult, BlobStore, Digest, OutputFile};
use sembazuru_tracer::action_key::{self, InputEntry, InputManifest};

/// Owns the on-disk CAS + action cache rooted at one directory.
pub struct AgentCache {
    store: BlobStore,
    cache: ActionCache,
}

/// The outcome of a cache lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheLookup {
    /// The action was cached: its outputs were republished and it exited with
    /// this code. The action must NOT be executed.
    Hit { exit_code: i32 },
    /// Not cached (or its inputs changed): the caller must run the action.
    Miss,
}

impl AgentCache {
    /// Opens (creating if needed) the agent CAS + action cache under `root`.
    pub fn open(root: impl AsRef<Path>) -> io::Result<AgentCache> {
        Ok(AgentCache {
            store: BlobStore::open(&root)?,
            cache: ActionCache::open(&root)?,
        })
    }

    /// The weak fingerprint of an action: argv + non-volatile env + the
    /// toolchain binary's content digest. `argv[0]` is hashed by content when it
    /// is a readable file (so a compiler upgrade invalidates the cache), else by
    /// its name as a fallback.
    pub fn weak_key(&self, argv: &[String], env: &[(String, String)]) -> Digest {
        let toolchain = toolchain_digest(argv.first().map(String::as_str).unwrap_or(""));
        sembazuru_cas::weak_fingerprint(argv, env, &toolchain)
    }

    /// Phase 1: try to resolve an action from cache. On a hit the cached outputs
    /// are published under `build_root` (atomically) and `Hit{exit_code}` is
    /// returned; the action then must not run.
    pub fn resolve(&self, weak: &Digest, build_root: &Path) -> io::Result<CacheLookup> {
        let Some(manifest_bytes) = self.cache.get_manifest(weak)? else {
            return Ok(CacheLookup::Miss);
        };
        let Some(manifest) = decode_manifest(&manifest_bytes) else {
            return Ok(CacheLookup::Miss); // corrupt manifest → re-run
        };
        let strong = sembazuru_cas::strong_fingerprint(weak, &action_key::manifest_hash(&manifest));
        let Some(result) = self.cache.get_result(&strong)? else {
            return Ok(CacheLookup::Miss);
        };
        // Fetch every output blob FIRST, before writing any. If a blob is
        // missing from the CAS (e.g. evicted), fail the lookup as a miss without
        // touching the build tree — otherwise an early write followed by a late
        // miss would leave a partial result for the re-run to clean up.
        let mut fetched = Vec::with_capacity(result.outputs.len());
        for out in &result.outputs {
            let Some(bytes) = self.store.get(&out.digest)? else {
                return Ok(CacheLookup::Miss);
            };
            fetched.push((&out.logical_path, bytes));
        }
        // All present: now publish atomically. (A mid-publish I/O error can
        // still leave some files, but that is a hard failure surfaced to the
        // caller, not a silent partial hit.)
        for (logical, bytes) in fetched {
            publish_atomically(&build_root.join(logical), &bytes)?;
        }
        Ok(CacheLookup::Hit {
            exit_code: result.exit_code,
        })
    }

    /// Phase 2: record a just-run action. `manifest` is its observed inputs (from
    /// [`AgentCache::manifest_from_trace_dir`]); `output_logical_paths` are the
    /// produced outputs relative to `build_root`. Their bytes are ingested into
    /// the CAS and the manifest + result stored so the next identical build hits.
    pub fn record(
        &self,
        weak: &Digest,
        manifest: &InputManifest,
        build_root: &Path,
        output_logical_paths: &[String],
        exit_code: i32,
    ) -> io::Result<()> {
        self.cache.put_manifest(weak, &encode_manifest(manifest))?;

        let mut outputs = Vec::with_capacity(output_logical_paths.len());
        for logical in output_logical_paths {
            let bytes = std::fs::read(build_root.join(logical))?;
            let digest = self.store.put(&bytes)?;
            outputs.push(OutputFile {
                logical_path: logical.clone(),
                digest,
            });
        }
        let strong = sembazuru_cas::strong_fingerprint(weak, &action_key::manifest_hash(manifest));
        self.cache.put_result(
            &strong,
            &ActionResult {
                exit_code,
                outputs,
                stdout: None,
                stderr: None,
            },
        )
    }

    /// Loads a trace directory and extracts the observed-input manifest. Thin
    /// wrapper over the tracer; returns an error string on an unreadable trace.
    pub fn manifest_from_trace_dir(&self, trace_dir: &str) -> Result<InputManifest, String> {
        let (graph, cwd) = action_key::load_run_from_dir(trace_dir)?;
        Ok(action_key::input_manifest(&graph, &cwd))
    }
}

/// Content digest of the toolchain binary, or a name-based digest if it cannot
/// be read (e.g. a bare `cl` resolved via PATH that we can't open here).
fn toolchain_digest(argv0: &str) -> Digest {
    match std::fs::read(argv0) {
        Ok(bytes) => Digest::of(&bytes),
        Err(_) => Digest::of(format!("toolchain-name:{argv0}").as_bytes()),
    }
}

/// Publishes `bytes` at `final_path` atomically (temp sibling + rename), so a
/// build never observes a half-written cached output.
fn publish_atomically(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = final_path.to_path_buf();
    let mut name = final_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sbz-cache-tmp");
    tmp.set_file_name(name);
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// --- InputManifest codec (agent-owned; opaque to the cache) ----------------

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn get_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    let len = get_u32(buf, pos)? as usize;
    let end = pos.checked_add(len)?;
    let s = String::from_utf8(buf.get(*pos..end)?.to_vec()).ok()?;
    *pos = end;
    Some(s)
}

fn get_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let v = u32::from_le_bytes(buf.get(*pos..end)?.try_into().ok()?);
    *pos = end;
    Some(v)
}

fn encode_manifest(m: &InputManifest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(m.inputs.len() as u32).to_le_bytes());
    for e in &m.inputs {
        put_str(&mut buf, &e.logical);
        put_str(&mut buf, &e.absolute);
    }
    buf.extend_from_slice(&(m.cmds.len() as u32).to_le_bytes());
    for c in &m.cmds {
        put_str(&mut buf, c);
    }
    buf
}

fn decode_manifest(buf: &[u8]) -> Option<InputManifest> {
    let mut pos = 0;
    let n_inputs = get_u32(buf, &mut pos)? as usize;
    let mut inputs = Vec::with_capacity(n_inputs.min(65536));
    for _ in 0..n_inputs {
        let logical = get_str(buf, &mut pos)?;
        let absolute = get_str(buf, &mut pos)?;
        inputs.push(InputEntry { logical, absolute });
    }
    let n_cmds = get_u32(buf, &mut pos)? as usize;
    let mut cmds = Vec::with_capacity(n_cmds.min(65536));
    for _ in 0..n_cmds {
        cmds.push(get_str(buf, &mut pos)?);
    }
    if pos != buf.len() {
        return None; // trailing junk → corrupt
    }
    Some(InputManifest { inputs, cmds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmp(tag: &str) -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("sbz-agentcache-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn manifest_for(inputs: &[(&str, &Path)]) -> InputManifest {
        InputManifest {
            inputs: inputs
                .iter()
                .map(|(logical, abs)| InputEntry {
                    logical: (*logical).to_string(),
                    absolute: abs.to_string_lossy().into_owned(),
                })
                .collect(),
            cmds: vec!["clang-cl /c a.cpp".into()],
        }
    }

    #[test]
    fn manifest_codec_round_trips() {
        let m = InputManifest {
            inputs: vec![
                InputEntry {
                    logical: "a.cpp".into(),
                    absolute: "c:\\w\\a.cpp".into(),
                },
                InputEntry {
                    logical: "h\\b.h".into(),
                    absolute: "c:\\w\\h\\b.h".into(),
                },
            ],
            cmds: vec!["cc /c a.cpp".into(), "link a.obj".into()],
        };
        assert_eq!(decode_manifest(&encode_manifest(&m)), Some(m));
        // Trailing junk is rejected.
        let mut bytes = encode_manifest(&InputManifest {
            inputs: vec![],
            cmds: vec![],
        });
        bytes.push(0);
        assert_eq!(decode_manifest(&bytes), None);
    }

    #[test]
    fn second_identical_build_hits_and_republishes_output() {
        let root = tmp("hit");
        let build = tmp("hit-build");
        let cache = AgentCache::open(&root).unwrap();

        // An input file and a produced output, as a first build would leave them.
        let input = build.join("a.cpp");
        std::fs::write(&input, b"int main(){return 0;}").unwrap();
        let out_logical = "a.obj";
        std::fs::write(build.join(out_logical), b"OBJECT-BYTES-v1").unwrap();

        let argv = vec!["clang-cl".to_string(), "/c".into(), "a.cpp".into()];
        let env: Vec<(String, String)> = vec![];
        let weak = cache.weak_key(&argv, &env);
        let manifest = manifest_for(&[("a.cpp", &input)]);

        // Phase 2: record the first build.
        cache
            .record(&weak, &manifest, &build, &[out_logical.to_string()], 0)
            .unwrap();

        // Simulate a clean rebuild dir: the output is gone, the input unchanged.
        let build2 = tmp("hit-build2");
        std::fs::write(build2.join("a.cpp"), b"int main(){return 0;}").unwrap();
        // The manifest's absolute path points at the original input (unchanged),
        // so the strong key matches.
        let lookup = cache.resolve(&weak, &build2).unwrap();
        assert_eq!(lookup, CacheLookup::Hit { exit_code: 0 });
        // The cached output was republished into build2.
        assert_eq!(
            std::fs::read(build2.join(out_logical)).unwrap(),
            b"OBJECT-BYTES-v1"
        );
    }

    #[test]
    fn changed_input_misses() {
        let root = tmp("miss");
        let build = tmp("miss-build");
        let cache = AgentCache::open(&root).unwrap();

        let input = build.join("a.cpp");
        std::fs::write(&input, b"version one").unwrap();
        std::fs::write(build.join("a.obj"), b"OBJ-v1").unwrap();

        let argv = vec!["clang-cl".to_string(), "/c".into(), "a.cpp".into()];
        let weak = cache.weak_key(&argv, &[]);
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(&weak, &manifest, &build, &["a.obj".to_string()], 0)
            .unwrap();

        // First resolve hits.
        assert_eq!(
            cache.resolve(&weak, &tmp("miss-r1")).unwrap(),
            CacheLookup::Hit { exit_code: 0 }
        );
        // Edit the input: the strong key moves → miss (must re-run).
        std::fs::write(&input, b"version TWO is different").unwrap();
        assert_eq!(
            cache.resolve(&weak, &tmp("miss-r2")).unwrap(),
            CacheLookup::Miss
        );
    }

    #[test]
    fn missing_output_blob_misses_without_partial_publish() {
        // If one of several cached output blobs is gone from the CAS (evicted),
        // resolve must publish NONE of them and report Miss — no half-built tree.
        let root = tmp("partial");
        let build = tmp("partial-build");
        let cache = AgentCache::open(&root).unwrap();

        let input = build.join("a.cpp");
        std::fs::write(&input, b"src").unwrap();
        std::fs::write(build.join("a.obj"), b"OBJ-1-bytes").unwrap();
        std::fs::write(build.join("b.obj"), b"OBJ-2-bytes").unwrap();

        let weak = cache.weak_key(&["cc".to_string()], &[]);
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".into(), "b.obj".into()],
                0,
            )
            .unwrap();

        // Delete the second output's blob from the CAS (white-box: digest→path).
        let d2 = Digest::of(b"OBJ-2-bytes");
        let blob = root
            .join("cas")
            .join("blake3")
            .join(&d2.hex()[0..2])
            .join(d2.hex());
        std::fs::remove_file(&blob).unwrap();

        let fresh = tmp("partial-r");
        assert_eq!(cache.resolve(&weak, &fresh).unwrap(), CacheLookup::Miss);
        // Neither output was published — not even the present first blob.
        assert!(
            !fresh.join("a.obj").exists(),
            "must not partially publish a.obj"
        );
        assert!(!fresh.join("b.obj").exists());
    }

    #[test]
    fn unknown_weak_key_misses() {
        let root = tmp("unknown");
        let cache = AgentCache::open(&root).unwrap();
        let weak = cache.weak_key(&["never-seen".to_string()], &[]);
        assert_eq!(
            cache.resolve(&weak, &tmp("u-b")).unwrap(),
            CacheLookup::Miss
        );
    }
}
