//! Compiler-environment allowlist (M7.1, `docs/deferred.md` M6.0/M6.1 security).
//!
//! The launcher captures its full environment and hands it to the daemon so a
//! local fallback and a remote run see the same environment. Forwarding the
//! *entire* environment is fine on a single machine (loopback intake), but the
//! moment an action reaches a real worker over the LAN it puts the developer's
//! secrets — cloud credentials, tokens, SSH agents — on the wire. The trust
//! model is LAN-trusted (ADR 0006), not "leak everything to every worker".
//!
//! So before the command leaves the launcher we keep only variables a Windows
//! C/C++ toolchain (MSVC `cl`, `clang-cl`, `link`) actually needs to reproduce
//! the build: search paths (PATH/INCLUDE/LIB/...), the VS/Windows-SDK locator
//! variables, and OS basics. Everything else is dropped. The worker already
//! `env_clear()`s and re-applies only what we send, so a dropped variable never
//! reaches the compiler. A build with an unusual environment dependency can
//! re-add names via `SEMBAZURU_ENV_PASSTHROUGH` (comma-separated).
//!
//! This is an allowlist, not a denylist: a new secret-bearing variable is
//! dropped by default rather than leaked until someone remembers to deny it.

use std::collections::HashMap;

/// Extra variable names to forward beyond the built-in toolchain set, as a
/// comma-separated list. An escape hatch for builds with environment
/// dependencies the allowlist does not cover; names are matched case-insensitively.
pub const ENV_PASSTHROUGH_VAR: &str = "SEMBAZURU_ENV_PASSTHROUGH";

/// Exact variable names (compared case-insensitively) a Windows C/C++ toolchain
/// needs: compiler/linker search paths, the VS + Windows SDK locator variables
/// `vcvars` exports, and OS basics tools assume exist.
const ALLOW_EXACT: &[&str] = &[
    // Toolchain search paths — the load-bearing ones.
    "PATH",
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "CL",
    "_CL_",
    "CC",
    "CXX",
    // Temp (intermediate files, response files).
    "TMP",
    "TEMP",
    // OS basics.
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_ARCHITEW6432",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    // Program-files roots used to locate toolchains.
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    // Visual Studio locator variables (from vcvars).
    "VSINSTALLDIR",
    "VCINSTALLDIR",
    "VCTOOLSINSTALLDIR",
    "VCTOOLSVERSION",
    "VCTOOLSREDISTDIR",
    "VCIDEINSTALLDIR",
    "VISUALSTUDIOVERSION",
    "DEVENVDIR",
    // Windows SDK / UCRT / .NET framework locator variables.
    "WINDOWSSDKDIR",
    "WINDOWSSDKVERSION",
    "WINDOWSSDKBINPATH",
    "WINDOWSSDKVERBINPATH",
    "WINDOWSLIBPATH",
    "UCRTVERSION",
    "UNIVERSALCRTSDKDIR",
    "EXTENSIONSDKDIR",
    "FRAMEWORKDIR",
    "FRAMEWORKDIR64",
    "FRAMEWORKVERSION",
    "FRAMEWORKVERSION64",
    "FRAMEWORK40VERSION",
    "NETFXSDKDIR",
];

/// Variable-name prefixes (compared case-insensitively) for toolchain families
/// whose exact names vary by version, so enumerating them is brittle.
const ALLOW_PREFIX: &[&str] = &[
    "VSCMD_",     // VSCMD_ARG_*, VSCMD_VER, …
    "__VSCMD",    // internal vcvars bookkeeping
    "WINDOWSSDK", // WindowsSdk* not covered exactly
    "VCTOOLS",    // VCTools* not covered exactly
    "FRAMEWORK",  // Framework* not covered exactly
];

/// Whether `name` is a compiler-relevant variable to forward. Matching is
/// case-insensitive (Windows environment names are).
pub fn is_compiler_env(name: &str, extra: &[String]) -> bool {
    let up = name.to_ascii_uppercase();
    if ALLOW_EXACT.contains(&up.as_str()) {
        return true;
    }
    if ALLOW_PREFIX.iter().any(|p| up.starts_with(p)) {
        return true;
    }
    extra.iter().any(|e| e.eq_ignore_ascii_case(name))
}

/// Parses [`ENV_PASSTHROUGH_VAR`] from `full` into the extra-name list. Empty
/// entries are ignored; whitespace is trimmed.
pub fn passthrough_names(full: &HashMap<String, String>) -> Vec<String> {
    full.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(ENV_PASSTHROUGH_VAR))
        .map(|(_, v)| {
            v.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Returns `full` reduced to the compiler-relevant variables (the built-in
/// allowlist plus any [`ENV_PASSTHROUGH_VAR`] names). This is what the launcher
/// sends to the daemon instead of the developer's whole environment.
pub fn filter_compiler_env(full: &HashMap<String, String>) -> HashMap<String, String> {
    let extra = passthrough_names(full);
    full.iter()
        .filter(|(k, _)| is_compiler_env(k, &extra))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn keeps_toolchain_vars_drops_secrets() {
        let full = env(&[
            ("PATH", "c:\\vs\\bin"),
            ("INCLUDE", "c:\\sdk\\include"),
            ("LIB", "c:\\sdk\\lib"),
            ("VSCMD_ARG_HOST_ARCH", "x64"),
            ("WindowsSdkVerBinPath", "c:\\sdk\\bin\\"),
            ("AWS_SECRET_ACCESS_KEY", "super-secret"),
            ("GITHUB_TOKEN", "ghp_xxx"),
            ("SSH_AUTH_SOCK", "\\\\.\\pipe\\ssh"),
            ("SEMBAZURU_DAEMON", "http://127.0.0.1:50071"),
        ]);
        let kept = filter_compiler_env(&full);
        assert!(kept.contains_key("PATH"));
        assert!(kept.contains_key("INCLUDE"));
        assert!(kept.contains_key("LIB"));
        assert!(kept.contains_key("VSCMD_ARG_HOST_ARCH"));
        assert!(kept.contains_key("WindowsSdkVerBinPath"));
        // Secrets and worker-internal vars are dropped.
        assert!(!kept.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!kept.contains_key("GITHUB_TOKEN"));
        assert!(!kept.contains_key("SSH_AUTH_SOCK"));
        assert!(!kept.contains_key("SEMBAZURU_DAEMON"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        // Windows reports "Path"/"SystemRoot" with mixed case; still forwarded.
        let full = env(&[("Path", "x"), ("SystemRoot", "c:\\windows")]);
        let kept = filter_compiler_env(&full);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn passthrough_adds_named_vars() {
        let full = env(&[
            ("MY_BUILD_FLAG", "1"),
            ("OTHER_SECRET", "no"),
            (ENV_PASSTHROUGH_VAR, "MY_BUILD_FLAG, missing_one"),
        ]);
        let kept = filter_compiler_env(&full);
        assert!(kept.contains_key("MY_BUILD_FLAG"), "passthrough name kept");
        assert!(
            !kept.contains_key("OTHER_SECRET"),
            "non-listed secret dropped"
        );
        // The passthrough variable itself is not toolchain-relevant; it is not
        // forwarded unless it names itself.
        assert!(!kept.contains_key(ENV_PASSTHROUGH_VAR));
    }
}
