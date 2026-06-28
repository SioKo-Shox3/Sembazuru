//! Toolchain resolution and content-digest helpers, shared by the
//! agent (and later the worker).
//!
//! The primary entry point is [`toolchain_digest`]; all other items are private.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use crate::{Digest, DigestHasher};

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
pub fn toolchain_digest(argv0: &str, path_env: Option<&str>, cwd: &str) -> Digest {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sembazuru-cas-toolchain-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
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
}
