//! GitHub Releases self-update (ADR 0009): detect a newer release, then — only on
//! an explicit user action — download its signed MSI.
//!
//! This module does the two network steps; it never *applies* anything. Applying
//! is gated on two further steps that live elsewhere and must both succeed first:
//!
//!   1. signature verification — Authenticode + publisher pin ([`crate::verify`]);
//!   2. user approval — the GUI's "Install" button, which then elevates msiexec.
//!
//! Trust posture (ADR 0009 §3): TLS for transport, but the downloaded bytes are
//! NOT trusted on the basis of the host. They are verified by signature before
//! they are ever executed. The host being GitHub buys nothing on its own.
//!
//! There is deliberately **no background poller** — no scheduled task, Run key, or
//! resident polling loop (ADR 0009 §4 / ADR 0008 §3). A check happens only when the
//! user asks (tray "Check for updates…") or, at most, once per GUI launch.

use std::path::{Path, PathBuf};

use semver::Version;
use serde::Deserialize;

/// The latest-release endpoint for this project. Owner/repo match
/// `CARGO_PKG_REPOSITORY` (github.com/SioKo-Shox3/Sembazuru); pinned here as the
/// single outbound URL so it is auditable in one place (ADR 0009 / edr-allowlist).
const RELEASES_API: &str = "https://api.github.com/repos/SioKo-Shox3/Sembazuru/releases/latest";

/// GitHub requires a User-Agent on API requests; identify ourselves and our version.
const USER_AGENT: &str = concat!("sembazuru-gui/", env!("CARGO_PKG_VERSION"));

/// Why a self-update step did not complete. Carries a short, already-sanitized
/// message safe to show in the GUI (no secrets, no local paths beyond the asset
/// name).
#[derive(Debug, Clone)]
pub enum UpdateError {
    /// The request failed, was refused, or returned a non-success status.
    Network(String),
    /// The response could not be parsed, or the release tag was not valid semver.
    Parse(String),
    /// The newer release carries no `.msi` asset to install.
    NoMsiAsset,
    /// Writing the downloaded file failed.
    Io(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Network(m) => write!(f, "network error: {m}"),
            UpdateError::Parse(m) => write!(f, "could not read the release: {m}"),
            UpdateError::NoMsiAsset => write!(f, "the latest release has no MSI installer"),
            UpdateError::Io(m) => write!(f, "could not save the download: {m}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// A release newer than the running build, with the MSI asset to fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableUpdate {
    /// The new version (the release tag parsed as semver).
    pub version: Version,
    /// The raw release tag (e.g. "v0.0.2"), shown verbatim in the UI.
    pub tag: String,
    /// The release page, opened in the browser when the user clicks "Release notes".
    pub notes_url: String,
    /// The MSI asset's file name (shown, and sanitized for the temp file).
    pub asset_name: String,
    /// The asset download URL. Private: the only consumer is [`download_msi`].
    asset_url: String,
}

/// The result of a check: either already current, or a newer release is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateCheck {
    UpToDate { current: Version },
    Available(AvailableUpdate),
}

/// The subset of the GitHub release JSON we read.
#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// The version of the running build (`CARGO_PKG_VERSION`).
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is valid semver")
}

/// Parses a release tag as semver, tolerating a leading `v` (the common GitHub tag
/// convention). Returns `None` for a tag that is not semver.
fn parse_tag(tag: &str) -> Option<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok()
}

/// Sanitizes a server-supplied asset name into a safe bare `*.msi` file name under
/// our own temp dir. Drops any path components and any character outside a small
/// allowlist, then forces a `.msi` extension — a hostile asset name can neither
/// traverse out of the temp dir nor change the file type we hand to msiexec.
fn sanitize_msi_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let stem = stem.trim_matches('.');
    let stem = if stem.is_empty() {
        "sembazuru-update"
    } else {
        stem
    };
    if stem.to_ascii_lowercase().ends_with(".msi") {
        stem.to_string()
    } else {
        format!("{stem}.msi")
    }
}

/// Decides the check outcome from a parsed release and the running version. Pure
/// (no I/O), so the version comparison and asset selection are unit-tested without
/// the network. A newer release with no `.msi` asset is an error, not "up to date":
/// we surface it rather than silently treating an un-installable release as current.
fn evaluate(rel: GhRelease, current: &Version) -> Result<UpdateCheck, UpdateError> {
    let latest = parse_tag(&rel.tag_name).ok_or_else(|| {
        UpdateError::Parse(format!("release tag {:?} is not semver", rel.tag_name))
    })?;
    if latest <= *current {
        return Ok(UpdateCheck::UpToDate {
            current: current.clone(),
        });
    }
    let asset = rel
        .assets
        .into_iter()
        .find(|a| a.name.to_ascii_lowercase().ends_with(".msi"))
        .ok_or(UpdateError::NoMsiAsset)?;
    Ok(UpdateCheck::Available(AvailableUpdate {
        version: latest,
        tag: rel.tag_name,
        notes_url: rel.html_url,
        asset_name: asset.name,
        asset_url: asset.browser_download_url,
    }))
}

/// Builds the HTTPS client: a User-Agent (GitHub requires one) and `https_only` so
/// a redirect can never downgrade us to plaintext.
fn client() -> Result<reqwest::Client, UpdateError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(true)
        .build()
        .map_err(|e| UpdateError::Network(e.to_string()))
}

/// Asks GitHub for the latest release and compares it to the running version.
///
/// **User-initiated only** — the tray "Check for updates…" or a single throttled
/// check at GUI launch. There is no background poller (ADR 0009 §4).
pub async fn check_for_update() -> Result<UpdateCheck, UpdateError> {
    let rel: GhRelease = client()?
        .get(RELEASES_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .json()
        .await
        .map_err(|e| UpdateError::Parse(e.to_string()))?;
    evaluate(rel, &current_version())
}

/// Streams the update's MSI asset to `dir`, returning the saved path.
///
/// Called **only** after the user chooses to download. The saved bytes are NOT
/// trusted yet: the caller MUST pass them through [`crate::verify`] (Authenticode +
/// publisher pin) and obtain explicit user approval before executing the file.
pub async fn download_msi(update: &AvailableUpdate, dir: &Path) -> Result<PathBuf, UpdateError> {
    use tokio::io::AsyncWriteExt;

    let dest = dir.join(sanitize_msi_name(&update.asset_name));
    let mut resp = client()?
        .get(&update.asset_url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| UpdateError::Network(e.to_string()))?;
    let mut file = tokio::fs::File::create(&dest)
        .await
        .map_err(|e| UpdateError::Io(e.to_string()))?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| UpdateError::Network(e.to_string()))?
    {
        file.write_all(&chunk)
            .await
            .map_err(|e| UpdateError::Io(e.to_string()))?;
    }
    file.flush()
        .await
        .map_err(|e| UpdateError::Io(e.to_string()))?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(tag: &str, assets: &[&str]) -> GhRelease {
        GhRelease {
            tag_name: tag.to_string(),
            html_url: "https://example.test/releases/latest".to_string(),
            assets: assets
                .iter()
                .map(|n| GhAsset {
                    name: (*n).to_string(),
                    browser_download_url: format!("https://example.test/{n}"),
                })
                .collect(),
        }
    }

    #[test]
    fn parse_tag_tolerates_a_leading_v() {
        assert_eq!(parse_tag("v1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(parse_tag("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(parse_tag("not-a-version"), None);
    }

    #[test]
    fn a_newer_release_with_an_msi_is_available() {
        let current = Version::new(0, 0, 1);
        let out = evaluate(rel("v0.0.2", &["sembazuru-0.0.2-x64.msi"]), &current).unwrap();
        match out {
            UpdateCheck::Available(u) => {
                assert_eq!(u.version, Version::new(0, 0, 2));
                assert_eq!(u.tag, "v0.0.2");
                assert_eq!(u.asset_name, "sembazuru-0.0.2-x64.msi");
                assert!(u.asset_url.ends_with(".msi"));
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn same_or_older_release_is_up_to_date() {
        let current = Version::new(0, 0, 2);
        assert_eq!(
            evaluate(rel("v0.0.2", &["x.msi"]), &current).unwrap(),
            UpdateCheck::UpToDate {
                current: current.clone()
            }
        );
        assert_eq!(
            evaluate(rel("v0.0.1", &["x.msi"]), &current).unwrap(),
            UpdateCheck::UpToDate { current }
        );
    }

    #[test]
    fn a_newer_release_without_an_msi_is_an_error_not_up_to_date() {
        let current = Version::new(0, 0, 1);
        // Newer, but only a zip asset — must not be reported as "up to date".
        let err = evaluate(rel("v0.0.2", &["sembazuru-0.0.2.zip"]), &current).unwrap_err();
        assert!(matches!(err, UpdateError::NoMsiAsset), "got {err:?}");
    }

    #[test]
    fn a_non_semver_tag_is_a_parse_error() {
        let err = evaluate(rel("nightly", &["x.msi"]), &Version::new(0, 0, 1)).unwrap_err();
        assert!(matches!(err, UpdateError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn asset_names_are_sanitized_to_a_safe_local_msi() {
        // Path traversal is stripped to the bare name and forced to .msi.
        assert_eq!(
            sanitize_msi_name("..\\..\\windows\\system32\\evil.msi"),
            "evil.msi"
        );
        assert_eq!(sanitize_msi_name("a/b/c/sembazuru.msi"), "sembazuru.msi");
        // A non-.msi or empty name still yields a safe .msi file name.
        assert_eq!(sanitize_msi_name("payload.exe"), "payload.exe.msi");
        assert_eq!(sanitize_msi_name("...."), "sembazuru-update.msi");
        // Spaces and odd characters are dropped.
        assert_eq!(
            sanitize_msi_name("sembazuru 0.0.2 (x64).msi"),
            "sembazuru0.0.2x64.msi"
        );
    }

    #[test]
    fn current_version_is_the_crate_version() {
        // Sanity: the build's version parses and is what we compare against.
        assert_eq!(current_version().to_string(), env!("CARGO_PKG_VERSION"));
    }
}
