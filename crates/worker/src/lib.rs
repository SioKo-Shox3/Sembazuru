//! Sembazuru worker: executes intercepted processes in a sandbox on a remote
//! machine, backed by an on-demand VFS and a local cache.
//!
//! M0 placeholder — see `docs/DESIGN.md` for the architecture.

/// Crate version, reported in the control-plane capability exchange
/// (see `docs/protocol/v0.md`).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_nonempty() {
        assert!(!super::version().is_empty());
    }
}
