//! Sembazuru control-plane protocol, v0 (see `docs/protocol/v0.md` §3).
//!
//! gRPC service definitions (`Coordination`, `Execution`) generated from
//! `proto/sembazuru/v0/control.proto`. **Protobuf appears only in this crate.**
//! The latency-critical file-supply data plane (v0 §4) is hand-rolled binary
//! framing in `sembazuru-dataplane`, with no protobuf on the hot path (§4.2).

/// Generated types and gRPC stubs for protocol version 0.
pub mod v0 {
    tonic::include_proto!("sembazuru.v0");

    /// The protocol version this build speaks (v0 §6), negotiated at Register
    /// time. v0 makes no compatibility promises until M3 ships.
    pub const PROTOCOL_VERSION: u32 = 0;
}

/// Shared-token authentication for the LAN-trusted trust model (ADR 0006, M7,
/// `docs/protocol/v0.md` §5). A cluster shares one secret, distributed
/// out-of-band via the [`CLUSTER_TOKEN_ENV`] env var. Workers present it on
/// `Register` (control plane, `RegisterRequest.auth_token`) and on the
/// data-plane session handshake; the agent matches it. When no token is
/// configured the agent accepts unconditionally — back-compat with the M5/M6
/// unauthenticated LAN start (ADR 0004 §6).
///
/// This lives in the protocol crate because both the control plane
/// (`sembazuru-proto` consumers: agent, worker) and the data plane share the
/// exact same env var, comparison, and accept/reject decision; a second copy
/// would be a place for them to drift.
pub mod auth {
    /// Env var carrying the cluster shared secret. Unset or empty means "no
    /// auth configured" — the agent then accepts unconditionally.
    pub const CLUSTER_TOKEN_ENV: &str = "SEMBAZURU_CLUSTER_TOKEN";

    /// The configured cluster token, or `None` when unset/empty (auth disabled).
    /// Both the agent (to know what to require) and the worker (to know what to
    /// present) read it through this one function so they cannot disagree.
    ///
    /// Read with `var_os` (not `var`) and lossy-convert, EXACTLY as the agent and
    /// worker config readers do (`agent::config` / `worker::config`, which use
    /// `var_os` + `to_string_lossy`). `std::env::var` would return `Err` on a
    /// non-UTF-8 value — yielding `None` (auth silently OFF) here while the config
    /// readers keep a (lossy) token, so the two sides would disagree on whether
    /// auth is on, a fail-open split (the M9.3a class of bug). Going through the
    /// same `var_os` + lossy path keeps all three readers identical. Empty == unset.
    pub fn cluster_token_from_env() -> Option<String> {
        std::env::var_os(CLUSTER_TOKEN_ENV)
            .map(|v| v.to_string_lossy().into_owned())
            .filter(|v| !v.is_empty())
    }

    /// Constant-time byte comparison of two tokens. Avoids a timing oracle that
    /// could let an attacker recover the secret a byte at a time. Length is not
    /// treated as secret (an early unequal-length return is fine for a shared
    /// cluster token whose length is not sensitive).
    pub fn token_eq(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// Server-side accept/reject decision. `expected` is the agent's configured
    /// token (`None` = auth disabled); `presented` is what the peer sent. The
    /// returned reason is safe to log or return on the wire — it carries no
    /// secret material and no internal paths (M7 error-sanitization, §5).
    pub fn check(expected: Option<&str>, presented: &str) -> Result<(), &'static str> {
        match expected {
            None => Ok(()),
            Some(exp) if presented.is_empty() => {
                let _ = exp;
                Err("missing cluster auth token")
            }
            Some(exp) if token_eq(exp, presented) => Ok(()),
            Some(_) => Err("invalid cluster auth token"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn disabled_accepts_anything() {
            assert!(check(None, "").is_ok());
            assert!(check(None, "whatever").is_ok());
        }

        #[test]
        fn enabled_requires_exact_match() {
            assert!(check(Some("s3cret"), "s3cret").is_ok());
            assert!(check(Some("s3cret"), "").is_err());
            assert!(check(Some("s3cret"), "wrong").is_err());
            assert!(check(Some("s3cret"), "s3cre").is_err());
        }

        #[test]
        fn token_eq_is_length_then_content() {
            assert!(token_eq("abc", "abc"));
            assert!(!token_eq("abc", "abd"));
            assert!(!token_eq("abc", "ab"));
        }

        // A non-UTF-8 cluster token must still be read (via var_os + lossy), not
        // dropped to None — otherwise the proto reader would silently disable auth
        // while the agent/worker config readers (which already use var_os + lossy)
        // keep a token, a fail-open split (task_eba5301f). Windows-only: this is a
        // Windows project, and constructing a non-UTF-8 env value needs OsString
        // from a lone UTF-16 surrogate. No other test in this crate touches
        // CLUSTER_TOKEN_ENV, so the env mutation cannot race intra-crate.
        #[cfg(windows)]
        #[test]
        fn token_from_env_reads_non_utf8_via_var_os() {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            // "s3" + lone high surrogate U+D800 + "t": valid UTF-16 env storage,
            // INVALID UTF-8 — std::env::var would Err on it.
            let bad = OsString::from_wide(&[0x73, 0x33, 0xD800, 0x74]);
            // SAFETY: serialized in practice (sole reader/writer of this var here);
            // set, read, then immediately remove.
            unsafe {
                std::env::set_var(CLUSTER_TOKEN_ENV, &bad);
            }
            let got = cluster_token_from_env();
            unsafe {
                std::env::remove_var(CLUSTER_TOKEN_ENV);
            }
            assert_eq!(
                got,
                Some(bad.to_string_lossy().into_owned()),
                "a non-UTF-8 token must be read via var_os + lossy (not dropped to None)"
            );
        }
    }
}
