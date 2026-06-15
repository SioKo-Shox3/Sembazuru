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
use sembazuru_tracer::action_key::{self, InputEntry, InputKind, InputManifest};
use sembazuru_tracer::normalize_for_compare;

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
        // Defense-in-depth: a manifest marked uncacheable (a real read whose
        // content the strong key could not cover) must never resolve to a hit,
        // even if one was somehow stored. `record` already refuses to store these.
        if !manifest.cacheable {
            return Ok(CacheLookup::Miss);
        }
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
            // Scope guard (BLOCK-B): never publish a stored output outside the
            // build root. A stored logical that fails the guard means a corrupt
            // or tampered entry — fail closed (hard error), do not publish any.
            if !action_key::is_under_build_root(&out.logical_path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to publish cached output outside the build root: {:?}",
                        out.logical_path
                    ),
                ));
            }
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
        // Input-side fail-closed (ADR 0007 §b.3): if the strong key cannot be
        // guaranteed to cover a real content read, decline the action rather
        // than risk a stale hit. Store nothing so a later resolve simply misses.
        if !manifest.cacheable {
            return Ok(());
        }
        // Output-side scope guard (BLOCK-B): every output must publish *under*
        // the build root. `output_logical_paths` may come from the launcher's
        // own declaration (`SEMBAZURU_OUTPUTS` / `/Fo`), which is not run through
        // `cacheable_outputs`, so re-validate here. A `..`/rooted/absolute path
        // is a hard error — never read-from or store an out-of-scope output.
        for logical in output_logical_paths {
            if !action_key::is_under_build_root(logical) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing to cache output outside the build root: {logical:?}"),
                ));
            }
        }

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

    /// The agent-side logical paths a prior build of this action read, for
    /// dependency-prediction prefetch (M5.4, `ExecuteRequest.predicted_paths`).
    /// Empty when the action has no cached manifest yet — a first build has
    /// nothing to predict, so prefetch is simply skipped. NOTE: returns the
    /// manifest's *logical* paths; reconciling those with the paths the worker
    /// hydrates under the deployed `PathMap` is part of the M5.5 daemon wiring.
    pub fn predicted_paths(&self, weak: &Digest) -> io::Result<Vec<String>> {
        let Some(bytes) = self.cache.get_manifest(weak)? else {
            return Ok(Vec::new());
        };
        let Some(manifest) = decode_manifest(&bytes) else {
            return Ok(Vec::new()); // corrupt manifest → no prediction
        };
        Ok(manifest.inputs.into_iter().map(|e| e.logical).collect())
    }

    /// Loads a trace directory and extracts the observed-input manifest. Thin
    /// wrapper over the tracer; returns an error string on an unreadable trace.
    ///
    /// `root_override` is the action's declared input root (e.g. a solution root
    /// spanning `obj\` and `bin\`); when empty/`None`, the run's working
    /// directory is used. Inputs are anchored and relativized against this same
    /// root so the manifest's logical paths match the outputs published under it.
    pub fn manifest_from_trace_dir(
        &self,
        trace_dir: &str,
        root_override: Option<&str>,
    ) -> Result<InputManifest, String> {
        let (graph, cwd) = action_key::load_run_from_dir(trace_dir)?;
        let root = effective_root(root_override, &cwd);
        Ok(action_key::input_manifest(&graph, &root))
    }

    /// The build-root-relative output paths a traced run produced (observed
    /// writes/renames), for trace-based output discovery when the launcher could
    /// not declare them (ADR 0007 §b; the M8.1 compiler-independence path). This
    /// reuses the exact output set the determinism harness compares, so a cached
    /// output is byte-identical to what `verify-determinism` checks.
    ///
    /// **Fail-closed:** if the run produced *any* output outside the build root,
    /// the whole action is declined for caching (returns empty). Such an output
    /// is not build-root-relative, so [`record`] cannot store it and [`resolve`]
    /// cannot republish it — caching only the under-root subset would silently
    /// serve an incomplete result on the next hit (ADR 0007 §b.3: 推論不能なら
    /// 無キャッシュ). See [`cacheable_outputs`].
    ///
    /// [`record`]: AgentCache::record
    /// [`resolve`]: AgentCache::resolve
    pub fn outputs_from_trace_dir(
        &self,
        trace_dir: &str,
        root_override: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let (graph, cwd) = action_key::load_run_from_dir(trace_dir)?;
        let root = effective_root(root_override, &cwd);
        Ok(cacheable_outputs(action_key::logical_outputs(
            &graph, &root,
        )))
    }
}

/// The action's effective build root: the declared input root (normalized once,
/// the same value used to relativize and to publish — closing the record/resolve
/// asymmetry of BLOCK-B), or the run's working directory when none is declared.
fn effective_root(root_override: Option<&str>, trace_cwd: &str) -> String {
    match root_override {
        Some(r) if !r.trim().is_empty() => normalize_for_compare(r),
        _ => trace_cwd.to_string(),
    }
}

/// Applies the cacheability rule to a traced run's logical outputs: if any output
/// is outside the build root (an absolute/UNC path that cannot be stored or
/// republished as a build-root-relative cache output), the whole action is
/// uncacheable — return empty so the caller skips recording rather than caching a
/// partial set (ADR 0007 §b.3). Otherwise return all outputs.
fn cacheable_outputs(outputs: impl IntoIterator<Item = String>) -> Vec<String> {
    let all: Vec<String> = outputs.into_iter().collect();
    if all.iter().any(|p| !action_key::is_under_build_root(p)) {
        Vec::new()
    } else {
        all
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

fn kind_byte(k: InputKind) -> u8 {
    match k {
        InputKind::Content => 0,
        InputKind::Absent => 1,
    }
}

fn kind_from_byte(b: u8) -> Option<InputKind> {
    match b {
        0 => Some(InputKind::Content),
        1 => Some(InputKind::Absent),
        _ => None, // unknown discriminant → corrupt/format drift → miss
    }
}

fn encode_manifest(m: &InputManifest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(m.cacheable as u8);
    buf.extend_from_slice(&(m.inputs.len() as u32).to_le_bytes());
    for e in &m.inputs {
        put_str(&mut buf, &e.logical);
        put_str(&mut buf, &e.absolute);
        buf.push(kind_byte(e.kind));
    }
    buf.extend_from_slice(&(m.cmds.len() as u32).to_le_bytes());
    for c in &m.cmds {
        put_str(&mut buf, c);
    }
    buf
}

fn decode_manifest(buf: &[u8]) -> Option<InputManifest> {
    let mut pos = 0;
    let cacheable = *buf.get(pos)? != 0;
    pos += 1;
    let n_inputs = get_u32(buf, &mut pos)? as usize;
    let mut inputs = Vec::with_capacity(n_inputs.min(65536));
    for _ in 0..n_inputs {
        let logical = get_str(buf, &mut pos)?;
        let absolute = get_str(buf, &mut pos)?;
        let kind = kind_from_byte(*buf.get(pos)?)?;
        pos += 1;
        inputs.push(InputEntry {
            logical,
            absolute,
            kind,
        });
    }
    let n_cmds = get_u32(buf, &mut pos)? as usize;
    let mut cmds = Vec::with_capacity(n_cmds.min(65536));
    for _ in 0..n_cmds {
        cmds.push(get_str(buf, &mut pos)?);
    }
    if pos != buf.len() {
        return None; // trailing junk → corrupt
    }
    Some(InputManifest {
        inputs,
        cmds,
        cacheable,
    })
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
                    kind: InputKind::Content,
                })
                .collect(),
            cmds: vec!["clang-cl /c a.cpp".into()],
            cacheable: true,
        }
    }

    #[test]
    fn cacheable_outputs_declines_when_any_output_is_outside_root() {
        // All under root → all cacheable.
        assert_eq!(
            cacheable_outputs(["a.dxil".to_string(), "sub\\b.obj".to_string()]),
            vec!["a.dxil".to_string(), "sub\\b.obj".to_string()]
        );
        // One output outside the root (absolute drive path) → the WHOLE action is
        // uncacheable; we must not cache only the under-root subset and silently
        // omit the outside one on a later hit (verifier M8.1 Finding 1).
        assert!(
            cacheable_outputs(["a.dxil".to_string(), "c:\\symbols\\a.pdb".to_string()]).is_empty(),
            "an outside-root output must make the action uncacheable, not partially cached"
        );
        // A UNC output is also outside the root.
        assert!(
            cacheable_outputs(["a.dxil".to_string(), "\\\\srv\\share\\x".to_string()]).is_empty()
        );
        // No outputs at all → nothing to cache (also empty).
        assert!(cacheable_outputs(std::iter::empty()).is_empty());
    }

    #[test]
    fn manifest_codec_round_trips() {
        let m = InputManifest {
            inputs: vec![
                InputEntry {
                    logical: "a.cpp".into(),
                    absolute: "c:\\w\\a.cpp".into(),
                    kind: InputKind::Content,
                },
                InputEntry {
                    logical: "missing.h".into(),
                    absolute: "c:\\w\\missing.h".into(),
                    kind: InputKind::Absent,
                },
            ],
            cmds: vec!["cc /c a.cpp".into(), "link a.obj".into()],
            cacheable: true,
        };
        assert_eq!(decode_manifest(&encode_manifest(&m)), Some(m));
        // Trailing junk is rejected.
        let mut bytes = encode_manifest(&InputManifest {
            inputs: vec![],
            cmds: vec![],
            cacheable: true,
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

    #[test]
    fn predicted_paths_come_from_the_recorded_manifest() {
        let root = tmp("predict");
        let build = tmp("predict-build");
        let cache = AgentCache::open(&root).unwrap();
        let input = build.join("a.cpp");
        std::fs::write(&input, b"src").unwrap();
        std::fs::write(build.join("a.obj"), b"obj").unwrap();

        let argv = vec!["clang-cl".to_string(), "/c".into(), "a.cpp".into()];
        let weak = cache.weak_key(&argv, &[]);

        // No manifest yet → nothing to predict (a first build skips prefetch).
        assert!(cache.predicted_paths(&weak).unwrap().is_empty());

        // After recording, the manifest's input logical paths are the prediction.
        let header = build.join("h.h");
        std::fs::write(&header, b"#pragma once").unwrap();
        let manifest = manifest_for(&[("a.cpp", &input), ("h.h", &header)]);
        cache
            .record(&weak, &manifest, &build, &["a.obj".to_string()], 0)
            .unwrap();

        let mut predicted = cache.predicted_paths(&weak).unwrap();
        predicted.sort();
        assert_eq!(predicted, vec!["a.cpp".to_string(), "h.h".to_string()]);

        // An unknown action still predicts nothing.
        let other = cache.weak_key(&["other".to_string()], &[]);
        assert!(cache.predicted_paths(&other).unwrap().is_empty());
    }
}
