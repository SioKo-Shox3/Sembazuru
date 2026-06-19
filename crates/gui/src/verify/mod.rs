//! Authenticode verification + publisher pinning for downloaded updates (ADR 0009
//! §3). The gate a downloaded MSI must pass *before* it is ever executed.
//!
//! Two independent checks, both required:
//!
//!   1. **Authenticode** — `WinVerifyTrust` validates that the file carries a valid
//!      signature chaining to a trusted root and has not been tampered with.
//!   2. **Publisher pin** — the signer certificate's subject must match the pinned
//!      Sembazuru publisher. This is what stops a *validly signed but unrelated*
//!      installer (anyone's Authenticode cert) from being accepted: trust in the
//!      GitHub host is not relied upon, only the signature and the pinned publisher.
//!
//! Fail-closed: any error — no signature, broken chain, unreadable signer, or a
//! publisher mismatch — returns `Err`, and the caller must refuse to run the file.
//!
//! NOTE (M7 / release): [`EXPECTED_PUBLISHER`] is a **placeholder**. The mechanism
//! is real and exercised, but the pinned string must be replaced with the actual OV
//! certificate subject once the release signing cert is provisioned (ADR 0006 /
//! 0009 deferred items) — until then a real signed release would fail the pin, which
//! is the safe direction.

use std::path::Path;

/// The expected signer subject (certificate "simple display" name, i.e. the CN).
///
/// PLACEHOLDER — replace with the real OV certificate subject at release (M7). The
/// comparison is exact (case-insensitive, trimmed); see [`publisher_matches`].
pub const EXPECTED_PUBLISHER: &str = "Sembazuru (PLACEHOLDER — replace at release)";

/// Why an update file was rejected. All variants mean "do not run this file".
#[derive(Debug, Clone)]
pub enum VerifyError {
    /// `WinVerifyTrust` rejected the file (no signature, untrusted chain, tampered).
    /// Carries the raw status for diagnostics.
    Untrusted(i32),
    /// The signature was valid but the signer certificate could not be read.
    NoSigner(String),
    /// The signature was valid but the signer is not the pinned publisher.
    PublisherMismatch { found: String },
    /// Verification is not available on this platform (non-Windows).
    Unsupported,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Untrusted(code) => {
                write!(f, "the installer's signature is not trusted (0x{code:08X})")
            }
            VerifyError::NoSigner(m) => write!(f, "could not read the installer's signer: {m}"),
            VerifyError::PublisherMismatch { found } => {
                write!(
                    f,
                    "the installer is signed by an unexpected publisher ({found:?})"
                )
            }
            VerifyError::Unsupported => {
                write!(f, "signature verification is only available on Windows")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Whether an extracted signer subject matches the pinned publisher. Exact match,
/// case-insensitive and trimmed — pure, so the pin policy is unit-tested without a
/// real signed file. Deliberately NOT a substring/prefix match: a loose match would
/// let "Sembazuru Evil Co" satisfy a "Sembazuru" pin.
fn publisher_matches(found: &str, expected: &str) -> bool {
    found.trim().eq_ignore_ascii_case(expected.trim())
}

/// Verifies a downloaded MSI: valid Authenticode signature **and** the signer is the
/// pinned publisher ([`EXPECTED_PUBLISHER`]). Returns `Ok(())` only when both hold;
/// the caller must refuse to execute the file on any `Err`.
pub fn verify_msi(path: &Path) -> Result<(), VerifyError> {
    verify_msi_against(path, EXPECTED_PUBLISHER)
}

/// As [`verify_msi`], but with an explicit expected publisher — lets a test pin a
/// known value. The Authenticode check is identical; only the pinned string differs.
pub fn verify_msi_against(path: &Path, expected_publisher: &str) -> Result<(), VerifyError> {
    imp::authenticode_trusted(path)?;
    let subject = imp::signer_subject(path)?;
    if publisher_matches(&subject, expected_publisher) {
        Ok(())
    } else {
        Err(VerifyError::PublisherMismatch { found: subject })
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_CERT_INFO_PARAM, CertCloseStore,
        CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
        CryptMsgGetParam, CryptQueryObject, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };

    use super::VerifyError;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Runs `WinVerifyTrust` with the generic-verify action and no UI. `Ok(())` iff
    /// the file carries a valid signature chaining to a trusted root.
    pub fn authenticode_trusted(path: &Path) -> Result<(), VerifyError> {
        let file_path = wide(path);

        // SAFETY: zeroing C structs we then fully initialize per their contracts.
        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = file_path.as_ptr();

        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        // No revocation (CRL/OCSP) check: it needs network and we already pin the
        // publisher. A future hardening could opt into WTD_REVOKE_WHOLECHAIN.
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` is fully initialized; INVALID_HANDLE_VALUE as the hwnd with
        // WTD_UI_NONE suppresses any UI.
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };

        // Always release the state data, regardless of the verdict.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: same fully-initialized `data`, now with the close action.
        unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
        }

        if status == 0 {
            Ok(())
        } else {
            Err(VerifyError::Untrusted(status))
        }
    }

    /// Extracts the signer certificate's subject (simple display name / CN) from the
    /// file's embedded PKCS#7 signature. Only meaningful for a file that already
    /// passed [`authenticode_trusted`].
    pub fn signer_subject(path: &Path) -> Result<String, VerifyError> {
        let file_path = wide(path);
        let mut h_store: HCERTSTORE = std::ptr::null_mut();
        let mut h_msg: *mut core::ffi::c_void = std::ptr::null_mut();

        // SAFETY: out-params are valid; on success we own h_store and h_msg and free
        // them on every return path below.
        let ok = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                file_path.as_ptr().cast(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut h_store,
                &mut h_msg,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(VerifyError::NoSigner("no embedded signature".into()));
        }

        let result = signer_subject_from(h_store, h_msg);

        // SAFETY: handles came from a successful CryptQueryObject; close once each.
        unsafe {
            if !h_msg.is_null() {
                CryptMsgClose(h_msg);
            }
            if !h_store.is_null() {
                CertCloseStore(h_store, 0);
            }
        }
        result
    }

    fn signer_subject_from(
        h_store: HCERTSTORE,
        h_msg: *mut core::ffi::c_void,
    ) -> Result<String, VerifyError> {
        // 1. Ask the message for the signer's CERT_INFO (issuer + serial), sized first.
        let mut size: u32 = 0;
        // SAFETY: querying the required buffer size with a null output buffer.
        let ok = unsafe {
            CryptMsgGetParam(
                h_msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if ok == 0 || size == 0 {
            return Err(VerifyError::NoSigner("no signer info".into()));
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf is `size` bytes; CryptMsgGetParam writes a CERT_INFO into it.
        let ok = unsafe {
            CryptMsgGetParam(
                h_msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err(VerifyError::NoSigner("signer info read failed".into()));
        }
        let cert_info = buf.as_ptr() as *const CERT_INFO;

        // 2. Find the signer certificate in the file's store by issuer+serial.
        // SAFETY: cert_info points into `buf`, valid for this call; store handle live.
        let cert = unsafe {
            CertFindCertificateInStore(
                h_store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                cert_info.cast(),
                std::ptr::null(),
            )
        };
        if cert.is_null() {
            return Err(VerifyError::NoSigner("signer cert not found".into()));
        }

        let subject = cert_simple_name(cert);

        // SAFETY: `cert` is a context returned by CertFindCertificateInStore.
        unsafe { CertFreeCertificateContext(cert) };

        subject.ok_or_else(|| VerifyError::NoSigner("empty signer subject".into()))
    }

    /// The certificate's "simple display" subject name (the CN), as a Rust string.
    fn cert_simple_name(cert: *const CERT_CONTEXT) -> Option<String> {
        // Sized query first (returns the character count including the NUL).
        // SAFETY: `cert` is a valid context; a null buffer returns the needed length.
        let len = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            )
        };
        if len <= 1 {
            return None; // 1 == just the NUL terminator → empty name
        }
        let mut buf = vec![0u16; len as usize];
        // SAFETY: buf holds `len` u16s; CertGetNameStringW fills it incl. the NUL.
        let written = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                buf.as_mut_ptr(),
                len,
            )
        };
        if written <= 1 {
            return None;
        }
        // Trim the trailing NUL before decoding.
        let s = String::from_utf16_lossy(&buf[..(written as usize - 1)]);
        Some(s)
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use super::VerifyError;

    pub fn authenticode_trusted(_path: &Path) -> Result<(), VerifyError> {
        Err(VerifyError::Unsupported)
    }

    pub fn signer_subject(_path: &Path) -> Result<String, VerifyError> {
        Err(VerifyError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_pin_is_an_exact_case_insensitive_match() {
        assert!(publisher_matches(
            "Sembazuru Publisher",
            "sembazuru publisher"
        ));
        assert!(publisher_matches("  Sembazuru  ", "Sembazuru"));
        // A loose / substring match must NOT pass — this is the security property.
        assert!(!publisher_matches("Sembazuru Evil Co", "Sembazuru"));
        assert!(!publisher_matches("Sembazuru", "Sembazuru Publisher"));
        assert!(!publisher_matches("", "Sembazuru"));
    }

    #[cfg(windows)]
    #[test]
    fn an_unsigned_file_is_rejected_and_never_passes() {
        // A non-signed blob must fail Authenticode, so verify_msi returns Err and the
        // caller never runs it. This is the fail-closed direction we can test without
        // a real signing cert (the positive path is gated on the M7 OV cert).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sbz-verify-unsigned-{}.msi", std::process::id()));
        std::fs::write(&path, b"not a signed installer").unwrap();
        let result = verify_msi_against(&path, EXPECTED_PUBLISHER);
        let _ = std::fs::remove_file(&path);
        assert!(
            matches!(result, Err(VerifyError::Untrusted(_))),
            "an unsigned file must be rejected as untrusted, got {result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_file_is_rejected() {
        let result = verify_msi_against(
            Path::new("C:\\nope\\does-not-exist-xyz.msi"),
            EXPECTED_PUBLISHER,
        );
        assert!(
            result.is_err(),
            "a missing file cannot verify, got {result:?}"
        );
    }
}
