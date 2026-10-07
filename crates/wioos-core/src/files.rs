//! WIO Files: a sandboxed file manager backend.
//!
//! The service operates on a user home directory inside the WIOOS state dir.
//! It has no root access by design: absolute paths, `..` and other escapes are
//! rejected before touching the filesystem. Archive/extract, mounts, private
//! and encrypted storage are architecture entries reported as not implemented.

use std::{
    fmt::{Display, Formatter},
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// File manager errors (safe to show to users; never include absolute paths
/// outside the sandbox).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum FileError {
    InvalidPath { message: String },
    NotFound { message: String },
    AlreadyExists { message: String },
    TooLarge { message: String },
    Io { message: String },
}

impl Display for FileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::InvalidPath { message }
            | FileError::NotFound { message }
            | FileError::AlreadyExists { message }
            | FileError::TooLarge { message }
            | FileError::Io { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for FileError {}

impl From<std::io::Error> for FileError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            FileError::NotFound {
                message: "path not found".to_owned(),
            }
        } else {
            FileError::Io {
                message: error.to_string(),
            }
        }
    }
}

/// One directory entry (paths are relative to the sandbox root).
#[derive(Clone, Debug, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
}

/// Result of listing a directory.
#[derive(Clone, Debug, Serialize)]
pub struct ListResult {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<FileEntry>,
}

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_SEARCH_RESULTS: usize = 200;
/// Sandboxed file operations rooted at a user home directory.
#[derive(Clone, Debug)]
pub struct FileService {
    root: PathBuf,
    trash: PathBuf,
}

impl FileService {
    /// Create a service rooted at `root`; the trash lives inside the root so
    /// everything stays in one sandbox.
    pub fn new(root: PathBuf) -> Self {
        let trash = root.join(".trash");
        Self { root, trash }
    }

    /// The sandbox root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the sandbox directories if missing.
    pub fn ensure(&self) -> Result<(), FileError> {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(&self.trash)?;
        Ok(())
    }

    /// Resolve a relative path inside the sandbox.
    ///
    /// Absolute paths, `..`, prefixes and empty inputs are rejected; the
    /// returned path is always `root` joined with safe components only.
    fn resolve(&self, relative: &str) -> Result<PathBuf, FileError> {
        if relative.len() > 1024 {
            return Err(FileError::InvalidPath {
                message: "path too long".to_owned(),
            });
        }
        let input = Path::new(relative);
        if relative.is_empty() || relative == "." {
            return Ok(self.root.clone());
        }
        if input.is_absolute() {
            return Err(FileError::InvalidPath {
                message: "absolute paths are not allowed".to_owned(),
            });
        }
        let mut resolved = self.root.clone();
        for component in input.components() {
            match component {
                Component::Normal(name) => {
                    let name = name.to_string_lossy();
                    if name.len() > 255 || name.contains('\0') {
                        return Err(FileError::InvalidPath {
                            message: "invalid path component".to_owned(),
                        });
                    }
                    resolved.push(name.as_ref());
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(FileError::InvalidPath {
                        message: "'..' is not allowed".to_owned(),
                    });
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(FileError::InvalidPath {
                        message: "absolute paths are not allowed".to_owned(),
                    });
                }
            }
        }
        Ok(resolved)
    }

    fn relative_of(&self, absolute: &Path) -> String {
        absolute
            .strip_prefix(&self.root)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default()
    }

    fn entry(&self, absolute: &Path) -> Option<FileEntry> {
        let metadata = fs::symlink_metadata(absolute).ok()?;
        let is_dir = metadata.is_dir();
        let modified_unix = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        Some(FileEntry {
            name: absolute
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: self.relative_of(absolute),
            is_dir,
            size_bytes: if is_dir { 0 } else { metadata.len() },
            modified_unix,
        })
    }

    /// List a directory (directories first, then files, both alphabetical).
    pub fn list(&self, relative: &str) -> Result<ListResult, FileError> {
        self.ensure()?;
        let absolute = self.resolve(relative)?;
        if !absolute.is_dir() {
            return Err(FileError::NotFound {
                message: format!("directory '{relative}' not found"),
            });
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&absolute)? {
            let entry = entry?;
            if let Some(info) = self.entry(&entry.path()) {
                entries.push(info);
            }
        }
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        let normalized = if relative == "." || relative.is_empty() {
            String::new()
        } else {
            relative.trim_end_matches('/').to_owned()
        };
        let parent = if normalized.is_empty() {
            None
        } else {
            Path::new(&normalized)
                .parent()
                .map(|path| path.to_string_lossy().into_owned())
                .map(|value| if value.is_empty() { ".".to_owned() } else { value })
        };
        Ok(ListResult {
            path: normalized,
            parent,
            entries,
        })
    }

    /// Create a directory.
    pub fn mkdir(&self, relative: &str) -> Result<(), FileError> {
        self.ensure()?;
        let absolute = self.resolve(relative)?;
        if absolute.exists() {
            return Err(FileError::AlreadyExists {
                message: format!("'{relative}' already exists"),
            });
        }
        fs::create_dir_all(&absolute)?;
        Ok(())
    }

    /// Create or overwrite a UTF-8 text file (size capped at 1 MiB).
    pub fn write_file(&self, relative: &str, content: &str) -> Result<(), FileError> {
        self.ensure()?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(FileError::TooLarge {
                message: "content larger than 1 MiB".to_owned(),
            });
        }
        let absolute = self.resolve(relative)?;
        if absolute.is_dir() {
            return Err(FileError::AlreadyExists {
                message: format!("'{relative}' is a directory"),
            });
        }
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&absolute, content)?;
        Ok(())
    }

    /// Read a UTF-8 text file (size capped at 1 MiB).
    pub fn read_file(&self, relative: &str) -> Result<String, FileError> {
        self.ensure()?;
        let absolute = self.resolve(relative)?;
        let metadata = fs::metadata(&absolute)?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(FileError::TooLarge {
                message: "file larger than 1 MiB".to_owned(),
            });
        }
        Ok(fs::read_to_string(&absolute)?)
    }

    /// Rename or move an entry inside the sandbox.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), FileError> {
        self.ensure()?;
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        if !source.exists() {
            return Err(FileError::NotFound {
                message: format!("'{from}' not found"),
            });
        }
        if target.exists() {
            return Err(FileError::AlreadyExists {
                message: format!("'{to}' already exists"),
            });
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&source, &target)?;
        Ok(())
    }

    /// Move an entry into the trash (soft delete).
    pub fn delete(&self, relative: &str) -> Result<(), FileError> {
        self.ensure()?;
        let source = self.resolve(relative)?;
        if source == self.root {
            return Err(FileError::InvalidPath {
                message: "cannot delete the sandbox root".to_owned(),
            });
        }
        if source == self.trash {
            return Err(FileError::InvalidPath {
                message: "cannot delete the trash directory".to_owned(),
            });
        }
        if !source.exists() {
            return Err(FileError::NotFound {
                message: format!("'{relative}' not found"),
            });
        }
        let name = source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "entry".to_owned());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let mut target = self.trash.join(format!("{stamp}-{name}"));
        let mut counter = 1u32;
        while target.exists() {
            target = self.trash.join(format!("{stamp}-{counter}-{name}"));
            counter += 1;
        }
        fs::rename(&source, &target)?;
        Ok(())
    }

    /// Search file and directory names inside the sandbox (trash excluded).
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<FileEntry>, FileError> {
        self.ensure()?;
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.clamp(1, MAX_SEARCH_RESULTS);
        let mut results = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(directory) = stack.pop() {
            if results.len() >= limit {
                break;
            }
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if results.len() >= limit {
                    break;
                }
                let path = entry.path();
                if path == self.trash {
                    continue;
                }
                let Some(info) = self.entry(&path) else {
                    continue;
                };
                if info.name.to_lowercase().contains(&query) {
                    results.push(info.clone());
                }
                if info.is_dir {
                    stack.push(path);
                }
            }
        }
        Ok(results)
    }

    /// Current trash contents.
    pub fn trash_entries(&self) -> Result<Vec<FileEntry>, FileError> {
        self.ensure()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.trash)? {
            let entry = entry?;
            if let Some(info) = self.entry(&entry.path()) {
                entries.push(info);
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Permanently remove everything in the trash; returns items removed.
    pub fn purge_trash(&self) -> Result<usize, FileError> {
        self.ensure()?;
        let mut removed = 0;
        for entry in fs::read_dir(&self.trash)? {
            let path = entry?.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
            removed += 1;
        }
        Ok(removed)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn service(dir: &tempfile::TempDir) -> FileService {
        let service = FileService::new(dir.path().join("home"));
        service.ensure().expect("ensure sandbox");
        service
    }

    #[test]
    fn rejects_path_escapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        for escape in [
            "/etc/passwd",
            "../secret",
            "a/../../b",
            "..",
            "nested/../../outside",
        ] {
            assert!(
                service.list(escape).is_err(),
                "escape '{escape}' must be rejected"
            );
        }
        assert!(service.read_file("/etc/hostname").is_err());
        assert!(service.write_file("../outside.txt", "x").is_err());
        assert!(service.delete("..").is_err());
    }

    #[test]
    fn lists_folders_before_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service.mkdir("docs").expect("mkdir");
        service.write_file("notes.txt", "hello").expect("write");
        service.write_file("docs/readme.md", "# hi").expect("write");
        let listing = service.list(".").expect("list");
        assert_eq!(listing.entries.len(), 3); // .trash, docs, notes.txt
        let docs = listing
            .entries
            .iter()
            .find(|entry| entry.name == "docs")
            .expect("docs");
        assert!(docs.is_dir);
    }

    #[test]
    fn write_read_rename_delete_flow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service.write_file("a.txt", "one").expect("write");
        assert_eq!(service.read_file("a.txt").expect("read"), "one");
        service.rename("a.txt", "b.txt").expect("rename");
        assert!(service.read_file("a.txt").is_err());
        assert_eq!(service.read_file("b.txt").expect("read"), "one");

        service.delete("b.txt").expect("delete");
        assert!(service.read_file("b.txt").is_err());
        let trash = service.trash_entries().expect("trash");
        assert_eq!(trash.len(), 1);
        assert!(trash[0].name.ends_with("b.txt"));
        assert_eq!(service.purge_trash().expect("purge"), 1);
        assert!(service.trash_entries().expect("trash").is_empty());
    }

    #[test]
    fn search_finds_entries_and_respects_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service.write_file("Documents/report.txt", "x").expect("write");
        service.write_file("other.txt", "x").expect("write");
        let results = service.search("report", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "Documents/report.txt");
        assert!(service.search("   ", 10).expect("empty").is_empty());
        let limited = service.search("t", 1).expect("limited");
        assert!(limited.len() <= 1);
    }

    #[test]
    fn rejects_duplicate_and_missing_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service.mkdir("x").expect("mkdir");
        assert!(matches!(
            service.mkdir("x"),
            Err(FileError::AlreadyExists { .. })
        ));
        assert!(matches!(
            service.rename("missing", "y"),
            Err(FileError::NotFound { .. })
        ));
        assert!(matches!(
            service.list("missing"),
            Err(FileError::NotFound { .. })
        ));
        let too_big = "x".repeat(MAX_FILE_BYTES as usize + 1);
        assert!(matches!(
            service.write_file("big.txt", &too_big),
            Err(FileError::TooLarge { .. })
        ));
    }
}
