//! Capability-scoped access to a trusted build/session root.
//!
//! This module is intentionally a thin wrapper around [`cap_std::fs::Dir`]. A
//! `RootDir` is opened once from a trusted root path with ambient authority, and
//! every later operation is relative to that already-open directory handle.
//!
//! The security reason for this wrapper is Windows path containment. Existing
//! checks in this codebase, such as `fileserver.rs`'s `normalize_requested` /
//! `path_in_scope` and `action_key.rs`'s `is_under_build_root`, reason about the
//! path string. Those lexical checks cannot see a symlink or junction planted as
//! an intermediate component under the root that the OS will later follow when a
//! caller performs `read`, `read_dir`, `rename`, or similar filesystem work.
//!
//! `cap_std::fs::Dir` delegates to the `cap-primitives` backend, which resolves
//! relative paths component by component and is reparse-aware on Windows. An open
//! that would escape the directory capability fails, so containment is structural
//! rather than a separate check each caller must remember to run. This module does
//! not reimplement component walking or reparse-point handling; that is the
//! reason to use `cap-std` here.

use std::io;
use std::path::Path;
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions, ReadDir};

/// A handle to a trusted root directory for contained filesystem operations.
#[derive(Clone)]
pub struct RootDir {
    dir: Arc<Dir>,
}

impl RootDir {
    /// Opens a trusted root directory using ambient filesystem authority.
    ///
    /// Call this only at setup time for a path that has already been chosen as a
    /// session or build root. All subsequent path operations should use the
    /// returned `RootDir` with relative paths.
    pub fn open_root(path: &Path) -> io::Result<Self> {
        Dir::open_ambient_dir(path, ambient_authority()).map(|dir| Self { dir: Arc::new(dir) })
    }

    /// Opens an existing file below this root for reading.
    pub fn open_read(&self, rel: &str) -> io::Result<File> {
        self.dir.open(rel)
    }

    /// Opens a file below this root with explicit options.
    pub fn open_with(&self, rel: &str, opts: &OpenOptions) -> io::Result<File> {
        self.dir.open_with(rel, opts)
    }

    /// Returns symlink metadata for a path below this root.
    pub fn symlink_metadata(&self, rel: &str) -> io::Result<Metadata> {
        self.dir.symlink_metadata(rel)
    }

    /// Returns followed metadata for a path below this root.
    pub fn metadata(&self, rel: &str) -> io::Result<Metadata> {
        self.dir.metadata(rel)
    }

    /// Reads a directory below this root.
    pub fn read_dir(&self, rel: &str) -> io::Result<ReadDir> {
        self.dir.read_dir(rel)
    }

    /// Opens a directory below this root as a new contained root.
    pub fn open_dir(&self, rel: &str) -> io::Result<RootDir> {
        self.dir
            .open_dir(rel)
            .map(|dir| RootDir { dir: Arc::new(dir) })
    }

    /// Creates a single directory below this root.
    pub fn create_dir(&self, rel: &str) -> io::Result<()> {
        self.dir.create_dir(rel)
    }

    /// Creates a directory and any missing parents below this root.
    pub fn create_dir_all(&self, rel: &str) -> io::Result<()> {
        self.dir.create_dir_all(rel)
    }

    /// Renames a path to another path within this same root directory handle.
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.dir.rename(from, &self.dir, to)
    }

    /// Removes a file below this root.
    pub fn remove_file(&self, rel: &str) -> io::Result<()> {
        self.dir.remove_file(rel)
    }
}

/// Opens a trusted root directory using ambient filesystem authority.
pub fn open_root(path: &Path) -> io::Result<RootDir> {
    RootDir::open_root(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct ScratchDir {
        path: PathBuf,
        reparse_dirs: Vec<PathBuf>,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("sbz-rootdir-{}-{tag}-{seq}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self {
                path,
                reparse_dirs: Vec::new(),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn register_reparse_dir(&mut self, path: PathBuf) {
            self.reparse_dirs.push(path);
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            for path in self.reparse_dirs.iter().rev() {
                let _ = fs::remove_dir(path);
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn open_root_then_read_a_file_inside_succeeds() {
        let root = ScratchDir::new("inside-read");
        fs::create_dir_all(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub").join("file.txt"), "inside").unwrap();

        let root_dir = RootDir::open_root(root.path()).unwrap();
        let mut file = root_dir.open_read("sub/file.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, "inside");
    }

    #[test]
    fn escape_via_dotdot_is_rejected() {
        let base = ScratchDir::new("dotdot");
        let root_path = base.path().join("root");
        let outside_path = base.path().join("outside");
        fs::create_dir_all(&root_path).unwrap();
        fs::create_dir_all(&outside_path).unwrap();
        fs::write(outside_path.join("secret.txt"), "outside").unwrap();

        let root_dir = RootDir::open_root(&root_path).unwrap();

        assert!(
            root_dir.open_read("../outside/secret.txt").is_err(),
            "dot-dot paths must not escape the root capability"
        );
    }

    #[cfg(windows)]
    #[test]
    fn escape_via_intermediate_junction_is_rejected() {
        let outside = ScratchDir::new("junction-outside");
        fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        let mut root = ScratchDir::new("junction-root");
        fs::create_dir_all(root.path().join("subdir_target")).unwrap();
        create_junction(&mut root, "escape_here", outside.path())
            .expect("mklink /J should create an unprivileged junction on Windows");

        let root_dir = RootDir::open_root(root.path()).unwrap();

        assert!(
            root_dir.open_read("escape_here/secret.txt").is_err(),
            "an intermediate junction that points outside the root must be rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn escape_via_directory_symlink_is_rejected() {
        let outside = ScratchDir::new("symlink-outside");
        fs::write(outside.path().join("secret.txt"), "outside").unwrap();
        let mut root = ScratchDir::new("symlink-root");
        if let Err(e) = create_directory_symlink(&mut root, "escape_here", outside.path()) {
            eprintln!("skipping directory symlink containment test: {e}");
            return;
        }

        let root_dir = RootDir::open_root(root.path()).unwrap();

        assert!(
            root_dir.open_read("escape_here/secret.txt").is_err(),
            "an intermediate directory symlink that points outside the root must be rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn intra_root_symlink_that_stays_inside_still_works() {
        let mut root = ScratchDir::new("intra-root-symlink");
        fs::create_dir_all(root.path().join("real_target")).unwrap();
        fs::write(root.path().join("real_target").join("file.txt"), "inside").unwrap();
        if let Err(e) = create_relative_directory_symlink(&mut root, "inside_link", "real_target") {
            eprintln!("skipping intra-root directory symlink test: {e}");
            return;
        }

        let root_dir = RootDir::open_root(root.path()).unwrap();
        let mut file = root_dir.open_read("inside_link/file.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, "inside");
    }

    #[test]
    fn same_dir_rename_publishes_atomically() {
        let root = ScratchDir::new("rename");
        fs::write(root.path().join("tmp_staged"), "published").unwrap();

        let root_dir = RootDir::open_root(root.path()).unwrap();
        root_dir.rename("tmp_staged", "final.txt").unwrap();

        assert_eq!(
            fs::read_to_string(root.path().join("final.txt")).unwrap(),
            "published"
        );
        assert!(!root.path().join("tmp_staged").exists());
    }

    #[test]
    fn create_dir_contained() {
        let root = ScratchDir::new("create-dir");
        let root_dir = RootDir::open_root(root.path()).unwrap();

        root_dir.create_dir("newsub").unwrap();

        assert!(root.path().join("newsub").is_dir());
    }

    #[test]
    fn open_with_metadata_read_dir_create_dir_all_and_remove_file_are_contained() {
        let root = ScratchDir::new("passthroughs");
        let root_dir = open_root(root.path()).unwrap();

        root_dir.create_dir_all("nested/sub").unwrap();

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        let mut file = root_dir.open_with("nested/sub/file.txt", &opts).unwrap();
        file.write_all(b"contained").unwrap();
        drop(file);

        assert!(root_dir.metadata("nested/sub/file.txt").unwrap().is_file());
        assert!(
            root_dir
                .symlink_metadata("nested/sub/file.txt")
                .unwrap()
                .is_file()
        );

        let entries = root_dir
            .read_dir("nested/sub")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec!["file.txt".to_string()]);

        root_dir.remove_file("nested/sub/file.txt").unwrap();
        assert!(
            !root
                .path()
                .join("nested")
                .join("sub")
                .join("file.txt")
                .exists()
        );
    }

    #[cfg(windows)]
    fn create_junction(
        root: &mut ScratchDir,
        link_name: &str,
        target: &Path,
    ) -> Result<(), String> {
        create_reparse_dir(root, link_name, target, "/J")
    }

    #[cfg(windows)]
    fn create_directory_symlink(
        root: &mut ScratchDir,
        link_name: &str,
        target: &Path,
    ) -> Result<(), String> {
        create_reparse_dir(root, link_name, target, "/D")
    }

    #[cfg(windows)]
    fn create_relative_directory_symlink(
        root: &mut ScratchDir,
        link_name: &str,
        target: &str,
    ) -> Result<(), String> {
        let output = std::process::Command::new("cmd")
            .current_dir(root.path())
            .args(["/C", "mklink", "/D", link_name, target])
            .output()
            .map_err(|e| format!("failed to spawn mklink /D: {e}"))?;
        if output.status.success() {
            root.register_reparse_dir(root.path().join(link_name));
            Ok(())
        } else {
            Err(format!(
                "mklink /D failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(windows)]
    fn create_reparse_dir(
        root: &mut ScratchDir,
        link_name: &str,
        target: &Path,
        kind: &str,
    ) -> Result<(), String> {
        let link = root.path().join(link_name);
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", kind])
            .arg(&link)
            .arg(target)
            .output()
            .map_err(|e| format!("failed to spawn mklink {kind}: {e}"))?;
        if output.status.success() {
            root.register_reparse_dir(link);
            Ok(())
        } else {
            Err(format!(
                "mklink {kind} failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}
