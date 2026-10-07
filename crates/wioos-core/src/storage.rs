//! Storage Manager: real filesystem usage plus a state-directory breakdown.
//!
//! Filesystem totals come from `statvfs`. Per-category attribution is only
//! reported for the WIOOS state directory; host-wide "system vs apps"
//! attribution has no backend and is reported as unavailable.

use std::path::Path;

use serde::Serialize;

use crate::status::{ComponentStatus};

/// Usage of one filesystem.
#[derive(Clone, Debug, Serialize)]
pub struct FilesystemUsage {
    pub path: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub used_percent: f64,
}

/// Sizes inside the WIOOS state directory (real directory walk).
#[derive(Clone, Debug, Serialize)]
pub struct StorageBreakdown {
    pub apps_bytes: u64,
    pub user_home_bytes: u64,
    pub settings_and_logs_bytes: u64,
    /// Host-wide attribution needs a full-disk indexer; not available.
    pub system: ComponentStatus,
}

/// Storage Manager report.
#[derive(Clone, Debug, Serialize)]
pub struct StorageReport {
    pub filesystem: Option<FilesystemUsage>,
    pub breakdown: StorageBreakdown,
    pub status: ComponentStatus,
}

fn statvfs_usage(path: &Path) -> Option<FilesystemUsage> {
    use std::ffi::CString;
    let raw = path.to_str()?;
    let c_path = CString::new(raw).ok()?;
    unsafe {
        let mut stats: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stats) != 0 {
            return None;
        }
        let fragment = stats.f_frsize.max(1) as u64;
        let total = stats.f_blocks as u64 * fragment;
        let available = stats.f_bavail as u64 * fragment;
        let used = total.saturating_sub(stats.f_bfree as u64 * fragment);
        let used_percent = if total == 0 {
            0.0
        } else {
            used as f64 / total as f64 * 100.0
        };
        Some(FilesystemUsage {
            path: raw.to_owned(),
            total_bytes: total,
            available_bytes: available,
            used_bytes: used,
            used_percent,
        })
    }
}

fn directory_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    let mut visited = 0u64;
    while let Some(directory) = stack.pop() {
        if visited > 1_000_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            let path = entry.path();
            match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => stack.push(path),
                Ok(metadata) if metadata.is_file() => total += metadata.len(),
                _ => {}
            }
        }
    }
    total
}

/// Build the Storage Manager report for a state directory.
pub fn report(state_dir: &Path) -> StorageReport {
    let filesystem = statvfs_usage(state_dir).or_else(|| statvfs_usage(Path::new("/")));
    let apps_bytes = directory_size(&state_dir.join("apps"));
    let user_home_bytes = directory_size(&state_dir.join("home"));
    let total_bytes = directory_size(state_dir);
    let breakdown = StorageBreakdown {
        apps_bytes,
        user_home_bytes,
        settings_and_logs_bytes: total_bytes.saturating_sub(apps_bytes + user_home_bytes),
        system: ComponentStatus::unavailable(
            "storage-system",
            "System storage attribution",
            "host-wide system/app/cache attribution requires a full-disk \
             indexer, which is not implemented"
                .to_owned(),
        ),
    };
    let status = if filesystem.is_some() {
        ComponentStatus::operational("storage-manager", "Storage Manager")
            .with_note("category sizes cover the WIOOS state directory only")
    } else {
        ComponentStatus::unavailable(
            "storage-manager",
            "Storage Manager",
            "statvfs is unavailable on this host",
        )
    };
    StorageReport {
        filesystem,
        breakdown,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_contains_real_or_unavailable_values_never_fabricated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = report(dir.path());
        if let Some(filesystem) = &report.filesystem {
            assert!(filesystem.total_bytes > 0);
            assert!((0.0..=100.0).contains(&filesystem.used_percent));
        } else {
            assert!(!report.status.is_operational());
        }
        assert!(!report.breakdown.system.is_operational());
        assert_eq!(report.breakdown.apps_bytes, 0);
        assert_eq!(report.breakdown.user_home_bytes, 0);
    }

    #[test]
    fn directory_size_walks_nested_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("a/b")).expect("mkdir");
        std::fs::write(dir.path().join("a/b/file.txt"), [0u8; 1024]).expect("write");
        std::fs::write(dir.path().join("top.txt"), [0u8; 128]).expect("write");
        assert_eq!(directory_size(dir.path()), 1152);
    }
}
