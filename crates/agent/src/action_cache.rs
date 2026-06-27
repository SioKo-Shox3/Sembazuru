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

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use sembazuru_cas::{
    ActionCache, ActionResult, BlobStore, CasError, Digest, DigestHasher, OutputFile,
};
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
    /// The action was cached: its outputs were republished and it exited with this
    /// code. `stdout`/`stderr` are the recorded console output to replay (COR-007)
    /// so a cached build shows the same diagnostics a fresh run did; empty when the
    /// recorded run produced none or its blob was evicted/corrupt (console output is
    /// advisory, so a missing replay blob never demotes the hit). The action must
    /// NOT be executed.
    Hit {
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
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

    /// Current total size of the CAS on disk, in bytes. A full blob scan (O(N)
    /// blobs, ADR 0003 simple version), so callers run it off the async runtime.
    /// Surfaced for the status dashboard and the disk-eviction work (M9.1/M9.2).
    pub fn cas_size(&self) -> io::Result<u64> {
        self.store.total_size()
    }

    /// Evicts least-recently-modified output blobs until the CAS is at or below
    /// `max_bytes`, returning the bytes freed (M9.2 / deferred #8). Eviction is
    /// **correctness-safe**: a wrongly-evicted blob only turns a later cache
    /// lookup into a miss (the action re-runs and produces byte-identical output),
    /// never a wrong result — `resolve` already treats a missing blob as a miss.
    /// The action-cache index entries (weak→manifest, strong→result) are left in
    /// place; they self-heal into misses when their blobs are gone. Like
    /// [`cas_size`] this is a full blob scan, so callers run it off the runtime.
    pub fn evict_to(&self, max_bytes: u64) -> io::Result<u64> {
        self.store.evict_to(max_bytes)
    }

    /// The weak fingerprint of an action: argv + `cwd` + non-volatile env + the
    /// toolchain binary's content digest (ADR 0014). `cwd` is folded so two runs
    /// with the same argv/env in different directories don't share a key (COR-005
    /// problem B). `argv[0]` is **PATH-resolved** (against the submitted `env`'s PATH
    /// and `cwd`) and hashed by content, so a same-named compiler upgrade
    /// (cl.exe v1→v2) moves the key and invalidates the cache instead of serving a
    /// stale hit; an argv0 that cannot be resolved/read falls back to its name.
    pub fn weak_key(&self, argv: &[String], env: &[(String, String)], cwd: &str) -> Digest {
        // PATH is excluded from the KEY (volatile), but is read here to resolve a
        // bare argv0 to the actual binary, whose content digest IS the identity.
        let path_env = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
            .map(|(_, v)| v.as_str());
        let toolchain = toolchain_digest(
            argv.first().map(String::as_str).unwrap_or(""),
            path_env,
            cwd,
        );
        sembazuru_cas::weak_fingerprint(argv, env, cwd, &toolchain)
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
        // Recompute the strong key from the inputs' *current* content. A re-read
        // I/O error other than a clean deletion (which `manifest_hash` folds into
        // the key) means we cannot prove the inputs are unchanged → miss, re-run.
        let Ok(input_hash) = action_key::manifest_hash(&manifest) else {
            return Ok(CacheLookup::Miss);
        };
        let strong = sembazuru_cas::strong_fingerprint(weak, &input_hash);
        let Some(result) = self.cache.get_result(&strong)? else {
            return Ok(CacheLookup::Miss);
        };
        // Two-pass set-atomic publish (COR-007). Pass 1 fetches + VERIFIES each
        // output blob and stages it to a robust temp SIBLING of its final path;
        // pass 2 renames the staged temps onto their finals. All staging happens
        // before any rename, so a missing/corrupt blob aborts with NOTHING
        // published (present-all-or-miss); only one blob is resident in memory at a
        // time (bounded — no whole-set buffering, so a multi-GB output set is fine);
        // and a corrupt-on-disk blob is a miss (re-run) rather than served verbatim.
        let mut staged: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(result.outputs.len());
        let unstage = |staged: &[(PathBuf, PathBuf)]| {
            for (tmp, _) in staged {
                let _ = std::fs::remove_file(tmp);
            }
        };
        for out in &result.outputs {
            // Scope guard (BLOCK-B): never publish a stored output outside the
            // build root. A stored logical that fails the guard means a corrupt
            // or tampered entry — fail closed (hard error), publish nothing.
            if !action_key::is_under_build_root(&out.logical_path) {
                unstage(&staged);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to publish cached output outside the build root: {:?}",
                        out.logical_path
                    ),
                ));
            }
            // get_VERIFIED, not get: a blob whose on-disk bytes no longer hash to
            // its digest (corruption/tamper) must NOT be published — treat it as a
            // miss so the action re-runs and produces a correct output (cache
            // corruption → miss, never a wrong byte). An evicted/absent blob is
            // likewise a miss; both abort before any final rename.
            let bytes = match self.store.get_verified(&out.digest) {
                Ok(Some(b)) => b,
                // A genuine I/O error reading the CAS (disk fault, sharing
                // violation) is NOT a normal miss: surface it as a hard error (the
                // pre-rewrite behaviour) so a failing cache is visible instead of
                // self-healing into endless silent re-runs.
                Err(CasError::Io(e)) => {
                    unstage(&staged);
                    return Err(e);
                }
                // Evicted/absent blob, a corrupt-on-disk blob, or any other
                // CAS-layer error → miss + re-run (correctness-safe; the action
                // re-runs and produces a correct output, never a wrong byte).
                Ok(None) | Err(_) => {
                    unstage(&staged);
                    return Ok(CacheLookup::Miss);
                }
            };
            let final_path = build_root.join(&out.logical_path);
            match stage_sibling(&final_path, &bytes) {
                Ok(tmp) => staged.push((tmp, final_path)),
                Err(e) => {
                    unstage(&staged);
                    return Err(e);
                }
            }
        }
        // Pass 2: commit. The renames are the only non-atomic window; a mid-commit
        // I/O failure is surfaced as a hard error (not a silent partial hit), and
        // any temps not yet committed are cleaned up.
        for (i, (tmp, final_path)) in staged.iter().enumerate() {
            if let Err(e) = commit_staged(tmp, final_path) {
                unstage(&staged[i + 1..]);
                return Err(e);
            }
        }
        // Replay the recorded console output on a hit (COR-007). Best-effort and
        // VERIFIED (`get_verified`): a missing or corrupt stdout/stderr blob degrades
        // to empty rather than forcing a re-run — the hit already served the correct
        // output files + exit code, and console output is advisory, not a correctness
        // boundary, so replaying nothing is safer than replaying corrupt bytes.
        let stdout = result
            .stdout
            .as_ref()
            .and_then(|d| self.store.get_verified(d).ok().flatten())
            .unwrap_or_default();
        let stderr = result
            .stderr
            .as_ref()
            .and_then(|d| self.store.get_verified(d).ok().flatten())
            .unwrap_or_default();
        Ok(CacheLookup::Hit {
            exit_code: result.exit_code,
            stdout,
            stderr,
        })
    }

    /// Diagnostic (gate/test only, NOT on the hot path): explain stage-by-stage why
    /// [`resolve`] hits or misses for `weak` — a weak-key miss, an uncacheable
    /// manifest, which stored input's *current* re-read moved the strong key, or a
    /// strong-key (result) miss. Re-reads inputs exactly as [`manifest_hash`] does.
    /// `cache_cli` prints this on a miss so a CI gate can pinpoint a cache
    /// regression without re-running the compiler.
    pub fn explain_miss(&self, weak: &Digest) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let manifest_bytes = match self.cache.get_manifest(weak) {
            Ok(Some(b)) => b,
            Ok(None) => return "weak MISS: no manifest stored for this weak key".into(),
            Err(e) => return format!("weak lookup error: {e}"),
        };
        let Some(manifest) = decode_manifest(&manifest_bytes) else {
            return "manifest decode FAILED (corrupt)".into();
        };
        let _ = writeln!(
            out,
            "weak HIT: stored manifest has {} inputs, cacheable={}",
            manifest.inputs.len(),
            manifest.cacheable
        );
        if !manifest.cacheable {
            let _ = writeln!(out, "=> UNCACHEABLE manifest -> miss");
            return out;
        }
        let mut changed = 0usize;
        for inp in &manifest.inputs {
            let (token, flag) = match inp.kind {
                InputKind::Content => match std::fs::read(&inp.absolute) {
                    Ok(b) => (format!("content({} bytes)", b.len()), ""),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (
                        "<missing>".to_string(),
                        "  <-- CHANGED: was content, now MISSING",
                    ),
                    Err(e) => (format!("<ioerr:{:?}>", e.kind()), "  <-- IO ERROR"),
                },
                InputKind::Absent => match std::fs::read(&inp.absolute) {
                    Ok(_) => (
                        "appeared".to_string(),
                        "  <-- CHANGED: was absent, now APPEARED",
                    ),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => ("absent".to_string(), ""),
                    Err(e) => (format!("<ioerr:{:?}>", e.kind()), "  <-- IO ERROR"),
                },
            };
            if !flag.is_empty() {
                changed += 1;
            }
            let _ = writeln!(
                out,
                "  [{:?}] {} = {}{}",
                inp.kind, inp.absolute, token, flag
            );
        }
        match action_key::manifest_hash(&manifest) {
            Ok(input_hash) => {
                let strong = sembazuru_cas::strong_fingerprint(weak, &input_hash);
                match self.cache.get_result(&strong) {
                    Ok(Some(_)) => {
                        let _ = writeln!(out, "=> strong HIT (resolve would hit)");
                    }
                    Ok(None) => {
                        let _ = writeln!(
                            out,
                            "=> strong MISS: {changed} input(s) changed since record"
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(out, "=> result lookup error: {e}");
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(out, "=> manifest_hash IO error: {:?} -> miss", e.kind());
            }
        }
        out
    }

    /// Phase 2: record a just-run action. `manifest` is its observed inputs (from
    /// [`AgentCache::manifest_from_trace_dir`]); `output_logical_paths` are the
    /// produced outputs relative to `build_root`. Their bytes are ingested into
    /// the CAS and the manifest + result stored so the next identical build hits.
    /// `stdout`/`stderr` are the run's captured console output (COR-007): they are
    /// ingested into the CAS and replayed by [`resolve`](Self::resolve) on a hit, so
    /// a cached build shows the same diagnostics a fresh run did. Pass empty slices
    /// when there is nothing to capture (e.g. an inherited-stdio run).
    // The params are the cohesive set describing one action's recording (keys,
    // outputs, exit, console output); bundling them would not aid clarity, so the
    // arity lint is allowed.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        weak: &Digest,
        manifest: &InputManifest,
        build_root: &Path,
        output_logical_paths: &[String],
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
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
        // If the strong key cannot be recomputed (an input became unreadable for
        // a reason other than a clean deletion), decline to store a result rather
        // than store one under an unreliable key. The manifest + already-ingested
        // blobs are harmless without a result entry; a later resolve simply misses.
        let Ok(input_hash) = action_key::manifest_hash(manifest) else {
            return Ok(());
        };
        let strong = sembazuru_cas::strong_fingerprint(weak, &input_hash);
        // Ingest the run's console output (COR-007) so a later hit replays the same
        // diagnostics. Empty → None (nothing stored, the common case for a tool that
        // printed no warnings). Shadows the byte-slice params with their digests.
        let stdout = if stdout.is_empty() {
            None
        } else {
            Some(self.store.put(stdout)?)
        };
        let stderr = if stderr.is_empty() {
            None
        } else {
            Some(self.store.put(stderr)?)
        };
        self.cache.put_result(
            &strong,
            &ActionResult {
                exit_code,
                outputs,
                stdout,
                stderr,
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

/// The toolchain identity folded into the weak key: the **content digest of the
/// actual compiler binary** `argv0` resolves to (so a same-named upgrade moves the
/// key, ADR 0014), or — when `argv0` cannot be resolved or read — a name-based
/// constant identical to the pre-resolution behavior (so unresolvable actions keep
/// their existing key and existing on-disk cache entries, and the rebuild-hit gate
/// is unchanged).
///
/// `path_env` is the submitted PATH and `cwd` the submitted working directory; both
/// are used only to RESOLVE `argv0` to a path (PATH is excluded from the key
/// itself). The resolution is agent-side and faithful for a bare `cl`/`clang-cl`
/// found on the vcvars PATH; a heterogeneous worker running a *different* binary at
/// the same PATH location is an accepted residual (closed later by the ADR 0014
/// worker re-verify), no worse than the previous constant which collided all
/// versions.
fn toolchain_digest(argv0: &str, path_env: Option<&str>, cwd: &str) -> Digest {
    let name_constant = || Digest::of(format!("toolchain-name:{argv0}").as_bytes());
    match resolve_program(argv0, path_env, cwd) {
        Some(resolved) => digest_file_memoized(&resolved).unwrap_or_else(name_constant),
        None => name_constant(),
    }
}

/// Resolves `argv0` to the file `CreateProcess` would launch, for content
/// digesting. Returns `None` for a bare name not found on PATH (the caller then
/// folds the name constant). Faithful for the compiler use case (a bare
/// `cl`/`clang-cl` found via the vcvars PATH, not in cwd/app-dir); the App-Paths
/// registry, `.bat` shims, and full PATHEXT breadth are intentionally out of scope
/// for the verified-profile compilers (documented residual).
fn resolve_program(argv0: &str, path_env: Option<&str>, cwd: &str) -> Option<PathBuf> {
    if argv0.is_empty() {
        return None;
    }
    let has_sep =
        argv0.contains('\\') || argv0.contains('/') || argv0.as_bytes().get(1) == Some(&b':'); // drive-qualified (e.g. C:...)
    if has_sep {
        // Relative paths resolve against cwd; join is a no-op for an absolute path.
        let base = if cwd.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(cwd)
        };
        return candidate_with_exe(&base.join(argv0));
    }
    // Bare name: the first PATH directory containing `dir\argv0[.exe]`, matching
    // CreateProcess's first-match-in-PATH order for a name not present in cwd/app-dir.
    for dir in path_env.unwrap_or("").split(';').filter(|s| !s.is_empty()) {
        if let Some(found) = candidate_with_exe(&Path::new(dir).join(argv0)) {
            return Some(found);
        }
    }
    None
}

/// Accepts `p` if it is a file, else `p` with `.exe` **appended** if THAT is a file.
/// Appends rather than `with_extension`, which would TRUNCATE a dotted name
/// (`foo.bar` → `foo.exe`); PATHEXT appends, so `cl` → `cl.exe`, `foo.bar` →
/// `foo.bar.exe`. (`.exe` alone is enough for the verified-profile compilers;
/// broader PATHEXT is a documented residual.)
fn candidate_with_exe(p: &Path) -> Option<PathBuf> {
    if p.is_file() {
        return Some(p.to_path_buf());
    }
    let mut exe = p.as_os_str().to_os_string();
    exe.push(".exe");
    let exe = PathBuf::from(exe);
    exe.is_file().then_some(exe)
}

/// Memoized content digests of resolved toolchain binaries, so a ~100 MB compiler is
/// hashed once per distinct version across a multi-TU build (incl. an all-hit
/// rebuild) rather than once per `weak_key`/TU. Keyed by `(path, mtime-nanos, len)`:
/// a NORMAL upgrade (installer/MSI) advances mtime → key miss → re-hash → the new
/// digest invalidates the cache immediately.
///
/// **Correctness — why `(mtime, len)` alone is not trusted:** mtime can be RESTORED
/// (backup-restore, `robocopy /COPYALL`, `touch -r`, a timestamp-preserving deploy)
/// and Windows mtime has only ~100 ns granularity, so a same-length content change
/// that does not advance mtime would otherwise be a permanent false memo hit = a
/// stale cache hit (violating "a stale result is never served"). So each entry also
/// carries the time it was hashed, and a hit older than [`TOOL_DIGEST_TTL`] is
/// **re-hashed** — bounding any mtime-defeating staleness to that window (seconds),
/// not the daemon's lifetime. The window is reached only by a content change that
/// (a) keeps the exact byte length, (b) restores/freezes mtime, AND (c) lands within
/// TTL of a build — practically a non-event for a compiler, but bounded regardless.
/// Process-global (a daemon's lifetime); content-addressed; no eviction needed.
type ToolDigestCache = Mutex<HashMap<(PathBuf, u128, u64), (Digest, std::time::Instant)>>;
static TOOL_DIGESTS: LazyLock<ToolDigestCache> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// How long a memoized toolchain digest is trusted before a stat-unchanged entry is
/// re-hashed. Small enough that an mtime-preserving same-length swap is reflected
/// within seconds (correctness bound); large enough that a build's burst of TUs
/// re-uses one hash (the perf win). Tunable.
const TOOL_DIGEST_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// The content digest of the file at `path`, memoized by `(path, mtime-nanos, len)`
/// with a [`TOOL_DIGEST_TTL`] re-hash safety net (see [`TOOL_DIGESTS`]). `None` if the
/// file cannot be stat'd or opened (→ the caller folds the name constant). The hash
/// runs OUTSIDE the lock (a ~100 MB stream under the Mutex would serialize the whole
/// build), via the streaming [`DigestHasher`] so the binary is never loaded whole.
fn digest_file_memoized(path: &Path) -> Option<Digest> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0u128, |d| d.as_nanos());
    let key = (path.to_path_buf(), mtime, meta.len());
    // Fast path: same (path, mtime, len) AND hashed within the TTL → trust the memo.
    // A stale (older-than-TTL) entry falls through and is re-hashed, so an
    // mtime-preserving content change can never serve a stale digest for longer
    // than the TTL.
    if let Some((digest, hashed_at)) = TOOL_DIGESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        && hashed_at.elapsed() < TOOL_DIGEST_TTL
    {
        return Some(digest.clone());
    }
    // Stream-hash outside the lock (compute-then-insert).
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = DigestHasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    TOOL_DIGESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, (digest.clone(), std::time::Instant::now()));
    Some(digest)
}

/// Per-process sequence for unique staging temp names, so two concurrent
/// resolves of the same output never collide on a fixed temp name (COR-007).
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Stages `bytes` to a uniquely-named temp SIBLING of `final_path` (same volume,
/// so the later rename is atomic) and returns the temp path. Created with
/// `create_new` (O_EXCL / CREATE_NEW), NOT a plain write: the name is otherwise
/// predictable and a plain write would truncate — and follow — a symlink a
/// co-located actor might pre-plant to redirect the cached bytes. `create_new`
/// refuses an existing path, so a planted target makes us retry with the next seq
/// rather than write through it (the same discipline as `cas::store::write_atomic`).
/// The caller renames the temp onto `final_path` with [`commit_staged`] only after
/// ALL of an action's outputs have staged, so a missing/corrupt blob leaves NO
/// output published (set-atomic publish).
fn stage_sibling(final_path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let stem = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    loop {
        let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(
            ".sbz-cache.{}.{seq}.{stem}.tmp",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(bytes)?;
                return Ok(tmp);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Renames a staged temp onto its final path (atomic within a volume), removing
/// the temp on failure so a failed commit leaves no `.sbz-cache.*.tmp` residue.
fn commit_staged(tmp: &Path, final_path: &Path) -> io::Result<()> {
    match std::fs::rename(tmp, final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
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
    fn manifest_codec_rejects_malformed_input_without_panicking() {
        // TEST-001 (action-cache codec robustness, deterministic fuzz): a corrupt,
        // truncated, or adversarial manifest must decode to None (→ a cache miss /
        // re-run), NEVER panic and NEVER half-decode. The codec is bounds-checked end
        // to end and caps the inputs/cmds pre-allocation, so a huge length prefix
        // cannot OOM either.
        let valid = encode_manifest(&InputManifest {
            inputs: vec![InputEntry {
                logical: "a.cpp".into(),
                absolute: "c:\\w\\a.cpp".into(),
                kind: InputKind::Content,
            }],
            cmds: vec!["cc /c a.cpp".into()],
            cacheable: true,
        });
        // Every strict prefix of a valid encoding is incomplete → None, no panic.
        for n in 0..valid.len() {
            assert_eq!(
                decode_manifest(&valid[..n]),
                None,
                "truncated at {n} must miss"
            );
        }
        // A sweep of hand-crafted malformed buffers (oversized length prefixes,
        // garbage) plus a byte-flip at every position. The contract is NO PANIC; a
        // buffer that still decodes must round-trip consistently (never half-decode).
        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![1],                                     // cacheable byte only
            vec![1, 0xff, 0xff, 0xff, 0xff],             // huge n_inputs
            vec![0xff; 64],                              // garbage
            vec![1, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], // 1 input, huge logical len
        ];
        for i in 0..valid.len() {
            let mut b = valid.clone();
            b[i] ^= 0xff;
            cases.push(b);
        }
        for (j, b) in cases.iter().enumerate() {
            if let Some(m) = decode_manifest(b) {
                assert_eq!(
                    decode_manifest(&encode_manifest(&m)),
                    Some(m),
                    "case {j} decoded, so it must round-trip (no half-decode)"
                );
            }
        }
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
        let weak = cache.weak_key(&argv, &env, "");
        let manifest = manifest_for(&[("a.cpp", &input)]);

        // Phase 2: record the first build.
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &[out_logical.to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // Simulate a clean rebuild dir: the output is gone, the input unchanged.
        let build2 = tmp("hit-build2");
        std::fs::write(build2.join("a.cpp"), b"int main(){return 0;}").unwrap();
        // The manifest's absolute path points at the original input (unchanged),
        // so the strong key matches.
        let lookup = cache.resolve(&weak, &build2).unwrap();
        assert_eq!(
            lookup,
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );
        // The cached output was republished into build2.
        assert_eq!(
            std::fs::read(build2.join(out_logical)).unwrap(),
            b"OBJECT-BYTES-v1"
        );
    }

    #[test]
    fn eviction_caps_the_cas_and_is_correctness_safe() {
        // M9.2 / deferred #8: evicting the CAS down to a cap must (a) actually
        // shrink it, (b) only ever turn a later lookup into a MISS — never a wrong
        // or partial result — and (c) leave determinism intact: re-running the
        // (deterministic) action reproduces the identical bytes. This is exactly
        // what lets the daemon's periodic eviction sweep run against a live cache
        // without threatening the determinism gate.
        let root = tmp("evict");
        let build = tmp("evict-build");
        let cache = AgentCache::open(&root).unwrap();

        let input = build.join("a.cpp");
        std::fs::write(&input, b"int main(){return 0;}").unwrap();
        let out_logical = "a.obj";
        let out_bytes = b"OBJECT-BYTES-deterministic";
        std::fs::write(build.join(out_logical), out_bytes).unwrap();

        let argv = vec!["clang-cl".to_string(), "/c".into(), "a.cpp".into()];
        let weak = cache.weak_key(&argv, &[], "");
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &[out_logical.to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // The output blob is in the CAS and a fresh build hits.
        assert!(
            cache.cas_size().unwrap() > 0,
            "the recorded output occupies the CAS"
        );
        assert_eq!(
            cache.resolve(&weak, &tmp("evict-r1")).unwrap(),
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );

        // (a) Evict everything (cap 0): the CAS shrinks to empty. The action-cache
        // index entries remain but their output blobs are gone.
        let freed = cache.evict_to(0).unwrap();
        assert!(freed > 0, "eviction freed the output blob");
        assert_eq!(cache.cas_size().unwrap(), 0, "the CAS is now empty");

        // (b) Correctness-safe: the now-blobless action resolves to a MISS (re-run)
        // — never a wrong or half-published result.
        assert_eq!(
            cache.resolve(&weak, &tmp("evict-r2")).unwrap(),
            CacheLookup::Miss,
            "an evicted action must miss, never serve a wrong result"
        );

        // (c) Determinism after eviction: re-running reproduces the same output,
        // re-records, and the next resolve republishes the byte-identical bytes.
        std::fs::write(build.join(out_logical), out_bytes).unwrap();
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &[out_logical.to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();
        let r3 = tmp("evict-r3");
        assert_eq!(
            cache.resolve(&weak, &r3).unwrap(),
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );
        assert_eq!(
            std::fs::read(r3.join(out_logical)).unwrap(),
            out_bytes,
            "republished bytes are byte-identical after eviction + re-run"
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
        let weak = cache.weak_key(&argv, &[], "");
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // First resolve hits.
        assert_eq!(
            cache.resolve(&weak, &tmp("miss-r1")).unwrap(),
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );
        // Edit the input: the strong key moves → miss (must re-run).
        std::fs::write(&input, b"version TWO is different").unwrap();
        assert_eq!(
            cache.resolve(&weak, &tmp("miss-r2")).unwrap(),
            CacheLookup::Miss
        );
    }

    #[test]
    fn appearing_absent_input_invalidates_the_cache() {
        // COR-002 end-to-end: a recorded action whose manifest carries an Absent
        // input (an include-search miss) must MISS once that file appears. The
        // pre-fix `manifest_hash` folded a constant `"absent"`, so a generated
        // header materializing between builds left the strong key unchanged and a
        // stale object was served. After the fix the appearance moves the key.
        let root = tmp("appear");
        let build = tmp("appear-build");
        let cache = AgentCache::open(&root).unwrap();

        let input = build.join("a.cpp");
        std::fs::write(&input, b"#include \"gen.h\"\nint main(){return 0;}").unwrap();
        std::fs::write(build.join("a.obj"), b"OBJ-compiled-without-gen").unwrap();

        // gen.h is absent at record time. It lives outside the build tree, so it
        // is a genuine Absent dependency (not a dropped under-root transient).
        let inc = tmp("appear-inc");
        let gen_h = inc.join("gen.h");
        let _ = std::fs::remove_file(&gen_h);

        let argv = vec!["clang-cl".to_string(), "/c".into(), "a.cpp".into()];
        let weak = cache.weak_key(&argv, &[], "");
        let manifest = InputManifest {
            inputs: vec![
                InputEntry {
                    logical: "a.cpp".into(),
                    absolute: input.to_string_lossy().into_owned(),
                    kind: InputKind::Content,
                },
                InputEntry {
                    logical: "gen.h".into(),
                    absolute: gen_h.to_string_lossy().into_owned(),
                    kind: InputKind::Absent,
                },
            ],
            cmds: vec!["clang-cl /c a.cpp".into()],
            cacheable: true,
        };
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // Still absent → hit (nothing changed).
        assert_eq!(
            cache.resolve(&weak, &tmp("appear-r1")).unwrap(),
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );

        // A code-gen step creates gen.h. The cached object was compiled WITHOUT
        // it, so the result is now stale: resolve MUST miss and re-run.
        std::fs::write(&gen_h, b"#define X 1").unwrap();
        assert_eq!(
            cache.resolve(&weak, &tmp("appear-r2")).unwrap(),
            CacheLookup::Miss,
            "an absent include that appears must invalidate the cached result (COR-002)"
        );

        let _ = std::fs::remove_file(&gen_h);
    }

    #[test]
    fn recorded_stdout_stderr_replay_on_a_hit() {
        // COR-007: a cached action replays the recorded console output, so a hit shows
        // the same compiler diagnostics a fresh run did. The blob is content-addressed,
        // so a second resolve replays it again (not consumed).
        let root = tmp("stdio");
        let build = root.join("build");
        std::fs::create_dir_all(&build).unwrap();
        let src = build.join("a.cpp");
        std::fs::write(&src, b"int main(){}").unwrap();
        let out = build.join("a.obj");
        std::fs::write(&out, b"OBJ").unwrap();

        let cache = AgentCache::open(&root).unwrap();
        let weak = Digest::of(b"weak-stdio");
        let manifest = manifest_for(&[("a.cpp", &src)]);
        let warn = b"a.cpp(1): warning C4101: unused variable\n".to_vec();
        let errs = b"a.cpp(2): error C2065: 'x': undeclared identifier\n".to_vec();
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &warn,
                &errs,
            )
            .unwrap();

        std::fs::remove_file(&out).unwrap();
        match cache.resolve(&weak, &build).unwrap() {
            CacheLookup::Hit {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout, warn, "the recorded stdout is replayed verbatim");
                assert_eq!(stderr, errs, "the recorded stderr is replayed verbatim");
            }
            CacheLookup::Miss => panic!("expected a hit"),
        }
        // A second hit replays the same bytes (content-addressed, not consumed).
        std::fs::remove_file(&out).unwrap();
        match cache.resolve(&weak, &build).unwrap() {
            CacheLookup::Hit { stdout, .. } => assert_eq!(stdout, warn, "replayable again"),
            CacheLookup::Miss => panic!("expected a second hit"),
        }
    }

    #[test]
    fn an_evicted_stdout_blob_degrades_to_empty_without_demoting_the_hit() {
        // COR-007 best-effort replay: console output is advisory, so if its CAS blob
        // is evicted/corrupt the hit is STILL served (correct output files + exit
        // code) with an empty replay — never demoted to a miss like an output blob is.
        let root = tmp("stdio-evict");
        let build = tmp("stdio-evict-build");
        let cache = AgentCache::open(&root).unwrap();
        let src = build.join("a.cpp");
        std::fs::write(&src, b"src").unwrap();
        std::fs::write(build.join("a.obj"), b"OBJ").unwrap();

        let weak = cache.weak_key(&["cc".to_string()], &[], "");
        let manifest = manifest_for(&[("a.cpp", &src)]);
        let warn = b"a warning to lose\n".to_vec();
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &warn,
                b"",
            )
            .unwrap();

        // Evict the stdout blob (white-box: digest→path), leaving the output blob.
        let d = Digest::of(&warn);
        let blob = root
            .join("cas")
            .join("blake3")
            .join(&d.hex()[0..2])
            .join(d.hex());
        std::fs::remove_file(&blob).unwrap();

        let fresh = tmp("stdio-evict-r");
        match cache.resolve(&weak, &fresh).unwrap() {
            CacheLookup::Hit {
                exit_code, stdout, ..
            } => {
                assert_eq!(exit_code, 0, "the hit is still served");
                assert!(stdout.is_empty(), "the missing stdout blob replays empty");
                assert!(
                    fresh.join("a.obj").exists(),
                    "the output file is still published"
                );
            }
            CacheLookup::Miss => panic!("an evicted *stdout* blob must NOT demote the hit"),
        }
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

        let weak = cache.weak_key(&["cc".to_string()], &[], "");
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".into(), "b.obj".into()],
                0,
                &[],
                &[],
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
    fn corrupt_output_blob_misses_instead_of_serving_wrong_bytes() {
        // COR-007: a cached output blob corrupted on disk (its bytes no longer hash
        // to its digest) must NOT be published — `resolve` re-verifies and treats it
        // as a miss so the action re-runs, never serving a wrong byte. Pre-fix the
        // republish used the non-verifying `store.get` and would have served it.
        let root = tmp("corrupt");
        let build = tmp("corrupt-build");
        let cache = AgentCache::open(&root).unwrap();

        let input = build.join("a.cpp");
        std::fs::write(&input, b"src").unwrap();
        std::fs::write(build.join("a.obj"), b"GOOD-OBJECT-BYTES").unwrap();

        let weak = cache.weak_key(&["cc".to_string()], &[], "");
        let manifest = manifest_for(&[("a.cpp", &input)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // First resolve hits (good blob).
        assert_eq!(
            cache.resolve(&weak, &tmp("corrupt-r1")).unwrap(),
            CacheLookup::Hit {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new()
            }
        );

        // Corrupt the output blob on disk (white-box: digest→path), keeping the
        // file at the same path so it is "present but wrong".
        let d = Digest::of(b"GOOD-OBJECT-BYTES");
        let blob = root
            .join("cas")
            .join("blake3")
            .join(&d.hex()[0..2])
            .join(d.hex());
        std::fs::write(&blob, b"TAMPERED-DIFFERENT-BYTES!!").unwrap();

        // Now resolve must MISS and publish nothing — the corrupt blob is rejected.
        let fresh = tmp("corrupt-r2");
        assert_eq!(
            cache.resolve(&weak, &fresh).unwrap(),
            CacheLookup::Miss,
            "a corrupt cached blob must miss, never serve wrong bytes (COR-007)"
        );
        assert!(
            !fresh.join("a.obj").exists(),
            "nothing is published when a cached blob is corrupt"
        );
    }

    #[test]
    fn unknown_weak_key_misses() {
        let root = tmp("unknown");
        let cache = AgentCache::open(&root).unwrap();
        let weak = cache.weak_key(&["never-seen".to_string()], &[], "");
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
        let weak = cache.weak_key(&argv, &[], "");

        // No manifest yet → nothing to predict (a first build skips prefetch).
        assert!(cache.predicted_paths(&weak).unwrap().is_empty());

        // After recording, the manifest's input logical paths are the prediction.
        let header = build.join("h.h");
        std::fs::write(&header, b"#pragma once").unwrap();
        let manifest = manifest_for(&[("a.cpp", &input), ("h.h", &header)]);
        cache
            .record(
                &weak,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        let mut predicted = cache.predicted_paths(&weak).unwrap();
        predicted.sort();
        assert_eq!(predicted, vec!["a.cpp".to_string(), "h.h".to_string()]);

        // An unknown action still predicts nothing.
        let other = cache.weak_key(&["other".to_string()], &[], "");
        assert!(cache.predicted_paths(&other).unwrap().is_empty());
    }

    // --- ADR 0014: resolved-compiler-digest --------------------------------

    #[test]
    fn resolve_program_finds_a_path_binary() {
        // A bare name resolves to the first PATH dir holding `name.exe`.
        let dir = tmp("rp-bin");
        std::fs::write(dir.join("cl.exe"), b"FAKE-CL").unwrap();
        let path_env = dir.to_string_lossy().into_owned();
        assert_eq!(
            resolve_program("cl", Some(&path_env), "").as_deref(),
            Some(dir.join("cl.exe").as_path())
        );
        // A bare name not on PATH does not resolve.
        assert!(resolve_program("nope", Some(&path_env), "").is_none());
        // A separator'd (here absolute) argv0 resolves as a path, ignoring PATH.
        let abs = dir.join("cl.exe");
        let abs_str = abs.to_string_lossy().into_owned();
        assert_eq!(
            resolve_program(&abs_str, None, "").as_deref(),
            Some(abs.as_path())
        );
        // A dotted bare name APPENDS .exe (does not truncate): foo.bar → foo.bar.exe.
        std::fs::write(dir.join("foo.bar.exe"), b"X").unwrap();
        assert_eq!(
            resolve_program("foo.bar", Some(&path_env), "").as_deref(),
            Some(dir.join("foo.bar.exe").as_path()),
            "PATHEXT appends .exe; it must not become foo.exe"
        );
    }

    #[test]
    fn memo_rehashes_after_ttl_so_an_mtime_preserving_change_is_not_permanently_stale() {
        // The memo trusts (mtime,len) only within TOOL_DIGEST_TTL. A same-length,
        // mtime-RESTORED content change (backup-restore / robocopy /COPYALL / touch
        // -r) keeps the key unchanged and would otherwise be a permanent stale
        // digest; the TTL re-hash bounds it to the window (a correctness guard).
        let dir = tmp("ttl");
        let p = dir.join("cl.exe");
        std::fs::write(&p, b"AAAAAAAA").unwrap(); // len 8
        let mt1 = std::fs::metadata(&p).unwrap().modified().unwrap();
        let d1 = digest_file_memoized(&p).unwrap();
        assert_eq!(d1, Digest::of(b"AAAAAAAA"));

        // Same length, different content, mtime RESTORED → memo key is unchanged.
        std::fs::write(&p, b"BBBBBBBB").unwrap(); // len 8
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mt1)
            .unwrap();
        // Within the TTL the (bounded) stale digest is still served...
        assert_eq!(
            digest_file_memoized(&p).unwrap(),
            d1,
            "stale within the TTL (the accepted bounded window)"
        );
        // ...but after the TTL the entry is re-hashed and the change is reflected.
        std::thread::sleep(TOOL_DIGEST_TTL + std::time::Duration::from_millis(250));
        assert_eq!(
            digest_file_memoized(&p).unwrap(),
            Digest::of(b"BBBBBBBB"),
            "after the TTL the memo re-hashes and tracks the new content"
        );
    }

    #[test]
    fn bare_unfound_falls_back_to_constant() {
        // The fallback MUST stay byte-identical to the pre-resolution behavior, so
        // unresolvable actions keep their existing key + on-disk cache entries.
        assert_eq!(
            toolchain_digest("never-seen", Some(""), ""),
            Digest::of(b"toolchain-name:never-seen")
        );
    }

    #[test]
    fn toolchain_digest_hashes_resolved_binary_and_tracks_content() {
        let dir = tmp("td-bin");
        let exe = dir.join("cl.exe");
        std::fs::write(&exe, b"COMPILER-V1").unwrap();
        let path_env = dir.to_string_lossy().into_owned();
        let v1 = toolchain_digest("cl", Some(&path_env), "");
        // It hashed the actual file content, NOT the name constant.
        assert_ne!(v1, Digest::of(b"toolchain-name:cl"));
        assert_eq!(v1, Digest::of(b"COMPILER-V1"));
        // An upgrade (different length → different memo key) moves the digest.
        std::fs::write(&exe, b"COMPILER-VERSION-2").unwrap();
        let v2 = toolchain_digest("cl", Some(&path_env), "");
        assert_ne!(v1, v2, "a compiler upgrade must move the toolchain digest");
        assert_eq!(v2, Digest::of(b"COMPILER-VERSION-2"));
    }

    #[test]
    fn digest_memo_is_stable_and_content_addressed() {
        let dir = tmp("memo");
        std::fs::write(dir.join("a.exe"), b"SAME-BYTES").unwrap();
        std::fs::write(dir.join("b.exe"), b"SAME-BYTES").unwrap();
        let d1 = digest_file_memoized(&dir.join("a.exe")).unwrap();
        // Same file twice → same digest (stable across the memo).
        assert_eq!(d1, digest_file_memoized(&dir.join("a.exe")).unwrap());
        // Different path, same content → same digest (content-addressed).
        assert_eq!(d1, digest_file_memoized(&dir.join("b.exe")).unwrap());
        assert_eq!(d1, Digest::of(b"SAME-BYTES"));
        // A missing file → None (caller folds the name constant).
        assert!(digest_file_memoized(&dir.join("gone.exe")).is_none());
    }

    #[test]
    fn record_and_resolve_agree_for_same_resolved_toolchain() {
        // Unit-level mirror of the M4 gate: the same resolved compiler → HIT; an
        // upgrade (new content+len at the same PATH location) → MISS (invalidation).
        let root = tmp("tc-cache");
        let build = tmp("tc-build");
        let tooldir = tmp("tc-tool");
        let exe = tooldir.join("cl.exe");
        std::fs::write(&exe, b"CL-ORIGINAL").unwrap();
        let src = build.join("a.cpp");
        std::fs::write(&src, b"int main(){}").unwrap();
        std::fs::write(build.join("a.obj"), b"OBJ").unwrap();

        let cache = AgentCache::open(&root).unwrap();
        let env = vec![("PATH".to_string(), tooldir.to_string_lossy().into_owned())];
        let argv = vec!["cl".to_string(), "/c".to_string(), "a.cpp".to_string()];
        let manifest = manifest_for(&[("a.cpp", &src)]);

        let weak1 = cache.weak_key(&argv, &env, "");
        cache
            .record(
                &weak1,
                &manifest,
                &build,
                &["a.obj".to_string()],
                0,
                &[],
                &[],
            )
            .unwrap();

        // Same toolchain → same weak key → HIT.
        std::fs::remove_file(build.join("a.obj")).unwrap();
        let weak_same = cache.weak_key(&argv, &env, "");
        assert_eq!(weak1, weak_same, "same compiler → same weak key");
        assert!(matches!(
            cache.resolve(&weak_same, &build).unwrap(),
            CacheLookup::Hit { .. }
        ));

        // Upgrade the compiler (new content + length) → new weak key → MISS.
        std::fs::write(&exe, b"CL-UPGRADED-AND-LONGER").unwrap();
        let weak2 = cache.weak_key(&argv, &env, "");
        assert_ne!(weak1, weak2, "a compiler upgrade must move the weak key");
        assert_eq!(
            cache.resolve(&weak2, &build).unwrap(),
            CacheLookup::Miss,
            "the upgraded compiler must not serve the old cache entry"
        );
    }
}
