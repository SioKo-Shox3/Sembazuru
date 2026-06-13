//! Sembazuru CAS: content-addressable storage for dedup file transfer and the
//! action cache (input hash → output).
//!
//! The store is digest-addressed: a blob's identity *is* the hash of its bytes
//! (ADR 0003: BLAKE3). That makes three things fall out for free —
//! deduplication (identical content has one path), integrity (the path proves
//! the content), and an end-to-end cache key shared by the data plane, the
//! worker-local cache, and the action cache (`docs/protocol/v0.md` §4.1).
//!
//! This module is the blob store and its [`Digest`] type. The action cache
//! (digest → `ActionResult`) builds on top of it (M4.3).

mod store;

pub use store::{BlobStore, CasError};

use std::fmt;

/// Crate version, reported in the control-plane capability exchange
/// (see `docs/protocol/v0.md`).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The content-hash algorithm. ADR 0003 selects BLAKE3; the enum exists so the
/// wire/on-disk form is self-describing and a future second algorithm is a
/// non-breaking addition rather than a silent reinterpretation of old hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgo {
    Blake3,
}

impl DigestAlgo {
    /// The hex length this algorithm's digest must have (BLAKE3 default output
    /// is 32 bytes → 64 lowercase hex chars).
    const fn hex_len(self) -> usize {
        match self {
            DigestAlgo::Blake3 => 64,
        }
    }

    /// The short tag used in the `algo:hex` canonical string.
    const fn tag(self) -> &'static str {
        match self {
            DigestAlgo::Blake3 => "blake3",
        }
    }

    fn from_tag(tag: &str) -> Option<DigestAlgo> {
        match tag {
            "blake3" => Some(DigestAlgo::Blake3),
            _ => None,
        }
    }
}

/// A content digest: an algorithm tag plus the lowercase-hex hash. Equality is
/// by (algo, hex), so two `Digest`s match iff they name the same content under
/// the same algorithm.
///
/// The hex is validated on construction (correct length, lowercase hex only),
/// which is also the path-safety boundary: a `Digest` can never carry a path
/// separator, `..`, or anything else that would escape the store directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algo: DigestAlgo,
    hex: String,
}

/// Why a hex string could not become a [`Digest`].
#[derive(Debug, PartialEq, Eq)]
pub enum DigestError {
    /// The hex length did not match the algorithm's digest size.
    WrongLength { expected: usize, got: usize },
    /// A character outside `[0-9a-f]` appeared (uppercase included, so the form
    /// is canonical and two spellings of one digest cannot diverge).
    NotLowerHex,
    /// The `algo:` tag in a canonical string named no known algorithm.
    UnknownAlgo,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestError::WrongLength { expected, got } => {
                write!(f, "digest hex length {got}, expected {expected}")
            }
            DigestError::NotLowerHex => write!(f, "digest hex has non-lowercase-hex characters"),
            DigestError::UnknownAlgo => write!(f, "unknown digest algorithm tag"),
        }
    }
}

impl std::error::Error for DigestError {}

impl Digest {
    /// The digest of `bytes` under the default algorithm (BLAKE3).
    pub fn of(bytes: &[u8]) -> Digest {
        let hash = blake3::hash(bytes);
        Digest {
            algo: DigestAlgo::Blake3,
            hex: hash.to_hex().to_string(),
        }
    }

    /// Builds a digest from an explicit algorithm and hex, validating that the
    /// hex is the right length and lowercase hex. This is how a digest arriving
    /// over the wire becomes a trusted, path-safe value.
    pub fn from_hex(algo: DigestAlgo, hex: &str) -> Result<Digest, DigestError> {
        let expected = algo.hex_len();
        if hex.len() != expected {
            return Err(DigestError::WrongLength {
                expected,
                got: hex.len(),
            });
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DigestError::NotLowerHex);
        }
        Ok(Digest {
            algo,
            hex: hex.to_string(),
        })
    }

    /// Parses the canonical `algo:hex` string (e.g. `blake3:ab12…`). The
    /// data plane and on-disk action cache use this self-describing form.
    pub fn parse(s: &str) -> Result<Digest, DigestError> {
        match s.split_once(':') {
            Some((tag, hex)) => {
                let algo = DigestAlgo::from_tag(tag).ok_or(DigestError::UnknownAlgo)?;
                Digest::from_hex(algo, hex)
            }
            None => Err(DigestError::UnknownAlgo),
        }
    }

    pub fn algo(&self) -> DigestAlgo {
        self.algo
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The canonical self-describing string, `algo:hex`.
    pub fn canonical(&self) -> String {
        format!("{}:{}", self.algo.tag(), self.hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo.tag(), self.hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }

    #[test]
    fn digest_of_is_stable_and_content_addressed() {
        // Same content → same digest; different content → different digest.
        assert_eq!(Digest::of(b"hello"), Digest::of(b"hello"));
        assert_ne!(Digest::of(b"hello"), Digest::of(b"hellp"));
    }

    #[test]
    fn blake3_known_answer() {
        // BLAKE3 of the empty input (official test vector).
        assert_eq!(
            Digest::of(b"").hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn from_hex_validates_length_and_charset() {
        let good = Digest::of(b"x").hex().to_string();
        assert!(Digest::from_hex(DigestAlgo::Blake3, &good).is_ok());

        assert_eq!(
            Digest::from_hex(DigestAlgo::Blake3, "abcd"),
            Err(DigestError::WrongLength {
                expected: 64,
                got: 4
            })
        );
        // Uppercase is rejected so the form stays canonical.
        let upper = good.to_uppercase();
        assert_eq!(
            Digest::from_hex(DigestAlgo::Blake3, &upper),
            Err(DigestError::NotLowerHex)
        );
        // A path-traversal attempt cannot pass validation (wrong charset/length).
        assert!(Digest::from_hex(DigestAlgo::Blake3, "../../etc/passwd").is_err());
    }

    #[test]
    fn from_hex_rejects_full_length_path_payloads() {
        // The real intrusion surface: a string that is *exactly* 64 bytes (so
        // the length check passes) but smuggles path metacharacters. Every one
        // must be rejected by the charset check, since the validated hex is what
        // becomes a filesystem path with no further sanitization.
        let pad = |s: &str| {
            let mut out = String::from(s);
            while out.len() < 64 {
                out.push('a');
            }
            out.truncate(64);
            out
        };
        for payload in [
            pad("../"),              // parent-dir
            pad("..\\"),             // backslash parent-dir
            pad("/etc/"),            // absolute (posix)
            pad("c:\\windows\\"),    // drive + backslash (uppercase too)
            pad("\\\\unc\\share\\"), // UNC
            pad("a/b"),              // embedded separator
            pad("a:b"),              // colon (NTFS ADS / drive)
            pad("a.b"),              // dot
            pad("AABB"),             // uppercase hex
            pad("zzzz"),             // out-of-range letters
            "é".repeat(32),          // 64 bytes of multibyte UTF-8
            {
                // 64 bytes, all valid hex except an embedded NUL — exercises the
                // charset check, not the length check.
                let mut s = "a".repeat(64);
                s.replace_range(2..3, "\u{0}");
                s
            },
        ] {
            assert!(
                Digest::from_hex(DigestAlgo::Blake3, &payload).is_err(),
                "must reject path-bearing payload: {payload:?}"
            );
        }
    }

    #[test]
    fn canonical_round_trips() {
        let d = Digest::of(b"round trip");
        let s = d.canonical();
        assert!(s.starts_with("blake3:"));
        assert_eq!(Digest::parse(&s).unwrap(), d);
    }

    #[test]
    fn parse_rejects_unknown_algo_and_bare_hex() {
        assert_eq!(
            Digest::parse("sha256:00").unwrap_err(),
            DigestError::UnknownAlgo
        );
        // Bare hex with no algo tag is not canonical.
        assert_eq!(
            Digest::parse(Digest::of(b"x").hex()).unwrap_err(),
            DigestError::UnknownAlgo
        );
    }
}
