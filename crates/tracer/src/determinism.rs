//! Determinism-harness primitives (`docs/DESIGN.md` §7, M2).
//!
//! Three jobs, all pure (bytes in, results out) so they unit-test without a
//! compiler or the filesystem:
//!   * content hashing — SHA-256, std-only, no third-party crate (matching the
//!     CLI's hand-rolled-argument-parsing ethos);
//!   * normalization — masks the documented non-deterministic regions of build
//!     outputs (PE-image and COFF-object timestamps, the PE Rich header);
//!   * comparison — raw byte compare first, then a normalized compare, yielding
//!     a verdict that records *why* two outputs were considered equal.
//!
//! Strategy is the **hybrid** of `docs/DESIGN.md` §7: compare raw bytes; on a
//! difference, mask the known fields and compare again. A residual difference
//! is *unexplained* and fails the gate. The recommended deterministic
//! compiler/linker flags (`/Brepro`, `SOURCE_DATE_EPOCH`, …) live in
//! `docs/determinism.md`; this module is the post-hoc guard paired with them.
//!
//! Scope (M2): `.obj` (COFF) byte determinism is the primary target; PE images
//! are secondary. PDB and PE debug-directory / CodeView regions are out of
//! scope here (they need RVA→file-offset mapping and carry the PDB GUID, which
//! M2 documents rather than normalizes).

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), std-only.
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 of `data`, lowercase hex. Used for content addressing in the
/// input-hash and output-hash mapping the M2 "Done when" requires.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut s = String::with_capacity(64);
    for byte in digest {
        // Two lowercase hex nibbles per byte; no allocation per byte.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0xf) as usize] as char);
    }
    s
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = SHA256_H0;

    // Pre-process: append 0x80, pad with zeros to 56 mod 64, then the 64-bit
    // big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Normalization of known non-deterministic regions.
// ---------------------------------------------------------------------------

/// Why a normalizer touched the bytes, surfaced in the verdict so an operator
/// sees *why* two outputs were judged equal (and can audit the masking).
pub const REASON_COFF_TIMESTAMP: &str = "coff-timestamp";
pub const REASON_PE_TIMESTAMP: &str = "pe-timestamp";
pub const REASON_PE_RICH_HEADER: &str = "pe-rich-header";

/// A normalized copy of an artifact and the list of regions that were masked.
pub struct Normalized {
    pub bytes: Vec<u8>,
    pub reasons: Vec<&'static str>,
}

/// Masks the documented non-deterministic regions of a build artifact. A PE
/// image (`MZ`) gets its file-header timestamp and Rich header zeroed; a COFF
/// object gets its file-header timestamp zeroed. Anything unrecognized is
/// returned byte-for-byte with no reasons.
pub fn normalize(input: &[u8]) -> Normalized {
    let mut bytes = input.to_vec();
    let mut reasons = Vec::new();

    if bytes.starts_with(b"MZ") {
        normalize_pe(&mut bytes, &mut reasons);
    } else if let Some(off) = coff_timestamp_offset(&bytes)
        && zero_u32(&mut bytes, off)
    {
        reasons.push(REASON_COFF_TIMESTAMP);
    }

    reasons.sort_unstable();
    reasons.dedup();
    Normalized { bytes, reasons }
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Zeros the 4 bytes at `off`; returns false (no-op) if they are out of bounds.
fn zero_u32(b: &mut [u8], off: usize) -> bool {
    match b.get_mut(off..off + 4) {
        Some(s) => {
            s.fill(0);
            true
        }
        None => false,
    }
}

fn is_known_machine(m: u16) -> bool {
    matches!(
        m,
        0x8664   // AMD64
        | 0x014c // I386
        | 0xAA64 // ARM64
        | 0x01c4 // ARMNT
        | 0x0200 // IA64
    )
}

/// File offset of the `TimeDateStamp` in a COFF object, or `None` if the bytes
/// are not a COFF object we recognize. A standard object begins with
/// `IMAGE_FILE_HEADER` (Machine, NumberOfSections, then TimeDateStamp at +4);
/// a bigobj/anonymous object begins with `0x0000,0xFFFF` and carries its
/// TimeDateStamp at +8 (`ANON_OBJECT_HEADER_BIGOBJ`). PE images are handled
/// elsewhere and never reach here (they start with `MZ`).
fn coff_timestamp_offset(b: &[u8]) -> Option<usize> {
    let machine = read_u16(b, 0)?;
    let second = read_u16(b, 2)?;
    if machine == 0x0000 && second == 0xFFFF {
        return Some(8); // bigobj / anonymous object
    }
    if is_known_machine(machine) {
        return Some(4); // standard COFF object
    }
    None
}

/// Masks a PE image's `IMAGE_FILE_HEADER.TimeDateStamp` and Rich header.
fn normalize_pe(b: &mut [u8], reasons: &mut Vec<&'static str>) {
    let Some(e_lfanew) = read_u32(b, 0x3c).map(|v| v as usize) else {
        return;
    };
    // "PE\0\0" must sit at e_lfanew; otherwise this is an MS-DOS or malformed
    // image we won't touch.
    if b.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
        return;
    }
    // IMAGE_FILE_HEADER follows the 4-byte signature; TimeDateStamp is at +4.
    let coff = e_lfanew + 4;
    if zero_u32(b, coff + 4) {
        reasons.push(REASON_PE_TIMESTAMP);
    }
    mask_rich_header(b, e_lfanew, reasons);
}

/// Zeros the Rich header (the MSVC linker's tool-version array between the DOS
/// stub and the PE header). It is bracketed by an XOR-encoded `DanS` start and
/// a `Rich` tag followed by the XOR key; the per-tool *use counts* inside can
/// vary. Masking the `[DanS .. Rich+8)` span removes it as a non-determinism
/// source even where toolchain pinning would already make it stable.
fn mask_rich_header(b: &mut [u8], e_lfanew: usize, reasons: &mut Vec<&'static str>) {
    let area = e_lfanew.min(b.len());
    // Find the last "Rich" tag before the PE header.
    let mut rich_pos = None;
    let mut i = 0;
    while i + 4 <= area {
        if &b[i..i + 4] == b"Rich" {
            rich_pos = Some(i);
        }
        i += 1;
    }
    let Some(rich) = rich_pos else {
        return;
    };
    let Some(key) = read_u32(b, rich + 4) else {
        return;
    };
    // The header opens with the DWORD "DanS" (0x536e6144 LE) XORed with `key`.
    // Walk back in 4-byte steps to find it, bounded to a sane window.
    let dans_encoded = 0x536e6144u32 ^ key;
    let mut start = None;
    let mut p = rich;
    while p >= 4 {
        p -= 4;
        if read_u32(b, p) == Some(dans_encoded) {
            start = Some(p);
            break;
        }
        if rich - p > 0x400 {
            break;
        }
    }
    let Some(s) = start else {
        return;
    };
    let end = (rich + 8).min(b.len()); // through the key DWORD
    for x in &mut b[s..end] {
        *x = 0;
    }
    reasons.push(REASON_PE_RICH_HEADER);
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

/// The result of comparing the same logical artifact from two runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Byte-for-byte identical with no normalization.
    Identical,
    /// Differed raw, but equal after masking the listed known regions.
    NormalizedEqual(Vec<&'static str>),
    /// Differed even after normalization — an *unexplained* difference.
    Differs,
}

/// Compares two artifacts: raw first, then normalized (the hybrid strategy).
pub fn compare(a: &[u8], b: &[u8]) -> Verdict {
    if a == b {
        return Verdict::Identical;
    }
    let na = normalize(a);
    let nb = normalize(b);
    if na.bytes == nb.bytes {
        let mut reasons = na.reasons;
        for r in nb.reasons {
            if !reasons.contains(&r) {
                reasons.push(r);
            }
        }
        reasons.sort_unstable();
        reasons.dedup();
        Verdict::NormalizedEqual(reasons)
    } else {
        Verdict::Differs
    }
}

// ---------------------------------------------------------------------------
// Logical-path mapping.
// ---------------------------------------------------------------------------

/// Maps an output path to a workroot-relative logical path so the same
/// artifact built under two different working directories compares as one
/// (and hashes identically). Paths outside `workroot` are returned unchanged —
/// they are already machine-stable on one host. Both arguments must already be
/// normalized as `graph` emits them (lowercased, `\`-separated).
pub fn relativize(path: &str, workroot: &str) -> String {
    let w = workroot.trim_end_matches('\\');
    if !w.is_empty()
        && let Some(rest) = path.strip_prefix(w)
        // The match must end on a separator boundary, or `c:\work\a` would
        // wrongly swallow the sibling `c:\work\ab\...` and collide two
        // unrelated files into one logical entry.
        && let Some(tail) = rest.strip_prefix('\\')
        && !tail.is_empty()
    {
        return tail.trim_start_matches('\\').to_string();
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SHA-256 known-answer vectors (FIPS 180-4) -----------------------

    #[test]
    fn sha256_empty_string() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_multiblock() {
        // 56 bytes forces a second padding block (length straddles the 448-bit
        // boundary) — exercises the multi-chunk path.
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha256_hex(msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // --- COFF object timestamp -------------------------------------------

    /// A minimal AMD64 COFF object header with a nonzero TimeDateStamp at +4.
    fn coff_obj(timestamp: u32) -> Vec<u8> {
        let mut b = vec![0u8; 20]; // IMAGE_FILE_HEADER is 20 bytes
        b[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = AMD64
        b[2..4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        b[4..8].copy_from_slice(&timestamp.to_le_bytes()); // TimeDateStamp
        b
    }

    #[test]
    fn coff_timestamp_is_masked() {
        let n = normalize(&coff_obj(0xdead_beef));
        assert_eq!(read_u32(&n.bytes, 4), Some(0));
        assert!(n.reasons.contains(&REASON_COFF_TIMESTAMP));
    }

    #[test]
    fn two_objs_differing_only_in_timestamp_are_normalized_equal() {
        let v = compare(&coff_obj(111), &coff_obj(222));
        assert_eq!(v, Verdict::NormalizedEqual(vec![REASON_COFF_TIMESTAMP]));
    }

    #[test]
    fn objs_differing_in_real_bytes_differ() {
        let mut a = coff_obj(111);
        let mut b = coff_obj(111);
        a[2] = 1; // NumberOfSections — a genuine content difference
        b[2] = 2;
        assert_eq!(compare(&a, &b), Verdict::Differs);
    }

    #[test]
    fn identical_objs_need_no_normalization() {
        assert_eq!(compare(&coff_obj(5), &coff_obj(5)), Verdict::Identical);
    }

    #[test]
    fn non_coff_bytes_are_untouched() {
        let junk = b"not an object file at all".to_vec();
        let n = normalize(&junk);
        assert_eq!(n.bytes, junk);
        assert!(n.reasons.is_empty());
    }

    // --- PE image timestamp ----------------------------------------------

    /// A minimal PE image: "MZ", e_lfanew at 0x3c pointing past a short stub to
    /// "PE\0\0" + a 20-byte file header carrying `timestamp` at +4.
    fn pe_image(timestamp: u32) -> Vec<u8> {
        let e_lfanew: u32 = 0x40;
        let mut b = vec![0u8; e_lfanew as usize + 4 + 20];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine
        b[coff + 4..coff + 8].copy_from_slice(&timestamp.to_le_bytes());
        b
    }

    #[test]
    fn pe_timestamp_is_masked() {
        let img = pe_image(0x1234_5678);
        let n = normalize(&img);
        let coff = 0x40 + 4;
        assert_eq!(read_u32(&n.bytes, coff + 4), Some(0));
        assert!(n.reasons.contains(&REASON_PE_TIMESTAMP));
    }

    #[test]
    fn pe_images_differing_only_in_timestamp_are_normalized_equal() {
        assert_eq!(
            compare(&pe_image(1), &pe_image(2)),
            Verdict::NormalizedEqual(vec![REASON_PE_TIMESTAMP])
        );
    }

    // --- PE Rich header ---------------------------------------------------

    #[test]
    fn rich_header_is_masked() {
        // Build a DOS area containing an XOR-encoded DanS .. Rich+key span.
        let key: u32 = 0x9e3f_a1c2;
        let e_lfanew: u32 = 0x80;
        let mut b = vec![0u8; e_lfanew as usize + 4 + 20];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Rich header at offset 0x40: encoded DanS, two entry DWORDs, "Rich",
        // key. Entries vary run-to-run; masking must zero the whole span.
        let dans = 0x536e6144u32 ^ key;
        let span_start = 0x40usize;
        b[span_start..span_start + 4].copy_from_slice(&dans.to_le_bytes());
        b[span_start + 4..span_start + 8].copy_from_slice(&0xaaaa_bbbbu32.to_le_bytes());
        b[span_start + 8..span_start + 12].copy_from_slice(&0xcccc_ddddu32.to_le_bytes());
        let rich = span_start + 12;
        b[rich..rich + 4].copy_from_slice(b"Rich");
        b[rich + 4..rich + 8].copy_from_slice(&key.to_le_bytes());

        // PE header after the Rich header.
        let pe = e_lfanew as usize;
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        b[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());

        let n = normalize(&b);
        assert!(n.reasons.contains(&REASON_PE_RICH_HEADER));
        // The whole [DanS .. Rich+8) span is zeroed.
        assert!(
            b[span_start..rich + 8].iter().any(|&x| x != 0),
            "fixture should start non-zero"
        );
        assert!(
            n.bytes[span_start..rich + 8].iter().all(|&x| x == 0),
            "rich span must be fully masked"
        );
    }

    // --- relativize -------------------------------------------------------

    #[test]
    fn relativize_strips_workroot() {
        assert_eq!(
            relativize("c:\\work\\a\\main.obj", "c:\\work\\a"),
            "main.obj"
        );
        assert_eq!(
            relativize("c:\\work\\b\\sub\\x.obj", "c:\\work\\b\\"),
            "sub\\x.obj"
        );
    }

    #[test]
    fn relativize_leaves_outside_paths() {
        // A system header outside the workroot is machine-stable already.
        assert_eq!(
            relativize("c:\\program files\\inc\\stdio.h", "c:\\work\\a"),
            "c:\\program files\\inc\\stdio.h"
        );
    }

    #[test]
    fn relativize_does_not_swallow_sibling_dir() {
        // `c:\work\a` must NOT be treated as a prefix of `c:\work\ab\...`:
        // the match has to land on a separator boundary, else two unrelated
        // files would collide into one logical entry.
        assert_eq!(
            relativize("c:\\work\\ab\\x.obj", "c:\\work\\a"),
            "c:\\work\\ab\\x.obj"
        );
        // Exact-equal path (the root itself) is left as-is, not emptied.
        assert_eq!(relativize("c:\\work\\a", "c:\\work\\a"), "c:\\work\\a");
    }

    #[test]
    fn rich_less_pe_is_not_spuriously_masked() {
        // A PE with no Rich header (typical of lld-link output) must not have
        // real bytes zeroed by the Rich scan. Only the file-header timestamp
        // is touched.
        let img = pe_image(0xcafe_f00d);
        let n = normalize(&img);
        assert!(!n.reasons.contains(&REASON_PE_RICH_HEADER));
        // Everything except the masked 4-byte timestamp is preserved.
        let coff = 0x40 + 4;
        for (i, (&orig, &got)) in img.iter().zip(n.bytes.iter()).enumerate() {
            if (coff + 4..coff + 8).contains(&i) {
                continue; // the timestamp we intentionally zero
            }
            assert_eq!(orig, got, "byte {i} must be preserved");
        }
    }
}
