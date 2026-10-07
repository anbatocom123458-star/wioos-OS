//! Native `.wio` package build / read / verify / extract.
//!
//! A `.wio` file is a tar archive containing `wio.toml`, `checksums.json`
//! (sha256 of every payload file) and the payload under `files/`. Nothing is
//! ever executed during build, read or verification.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use wioos_core::security::IntegrityCheck;

use crate::manifest::{Architecture, WioManifest};

/// Manifest member name inside the archive.
pub const MANIFEST_MEMBER: &str = "wio.toml";
/// Checksums member name inside the archive.
pub const CHECKSUMS_MEMBER: &str = "checksums.json";
/// Payload prefix inside the archive.
pub const PAYLOAD_PREFIX: &str = "files/";

/// sha256 checksums for every payload file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Checksums {
    pub schema: u32,
    pub algorithm: String,
    /// Payload-relative path -> lowercase hex digest.
    pub files: BTreeMap<String, String>,
}

/// Result of `wio build`.
#[derive(Clone, Debug)]
pub struct BuiltPackage {
    pub path: PathBuf,
    pub manifest: WioManifest,
    pub package_sha256: String,
    pub size_bytes: u64,
    pub file_count: usize,
}

/// Everything read from a package without extracting it.
#[derive(Clone, Debug)]
pub struct PackageInfo {
    pub manifest: WioManifest,
    pub checksums: Option<Checksums>,
    pub payload_members: Vec<String>,
    pub size_bytes: u64,
}

/// Outcome of full package verification.
#[derive(Clone, Debug)]
pub struct PackageVerification {
    pub manifest_ok: bool,
    pub manifest_error: Option<String>,
    /// `None` when the archive could not be read at all.
    pub integrity: Option<IntegrityCheck>,
    pub entry_present: bool,
    pub architecture: Option<Architecture>,
    pub errors: Vec<String>,
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn sha256_reader<R: Read>(reader: R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut reader = reader;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
/// Collect payload files from a source directory, skipping build output and
/// VCS metadata. Returns `(relative_path, absolute_path)` sorted by path.
pub fn collect_source_files(src_dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut files = Vec::new();
    let mut stack = vec![(src_dir.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = stack.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == MANIFEST_MEMBER || name == "target" || name == "dist" || name == ".git" {
                continue;
            }
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = entry
                .metadata()
                .map_err(|error| format!("cannot stat {relative}: {error}"))?;
            if metadata.is_dir() {
                stack.push((path, relative));
            } else if metadata.is_file() {
                if relative.len() > 512 {
                    return Err(format!("payload path too long: {relative}"));
                }
                files.push((relative, path));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// Build a `.wio` package from an app source directory containing `wio.toml`.
pub fn build(src_dir: &Path, out_dir: &Path) -> Result<BuiltPackage, String> {
    let manifest_path = src_dir.join(MANIFEST_MEMBER);
    let manifest_raw = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let manifest = WioManifest::from_toml(&manifest_raw)?;
    manifest.validate()?;

    let files = collect_source_files(src_dir)?;
    if files.is_empty() {
        return Err("source directory has no payload files".to_owned());
    }
    if !files.iter().any(|(relative, _)| *relative == manifest.entry) {
        return Err(format!(
            "entry '{}' does not exist in the source payload",
            manifest.entry
        ));
    }

    let mut checksum_files = BTreeMap::new();
    for (relative, absolute) in &files {
        let bytes =
            fs::read(absolute).map_err(|error| format!("cannot read {relative}: {error}"))?;
        checksum_files.insert(relative.clone(), sha256_hex(&bytes));
    }
    let checksums = Checksums {
        schema: 1,
        algorithm: "sha256".to_owned(),
        files: checksum_files,
    };

    fs::create_dir_all(out_dir)
        .map_err(|error| format!("cannot create {}: {error}", out_dir.display()))?;
    let package_path = out_dir.join(format!("{}-{}.wio", manifest.name, manifest.version));
    let package_file =
        File::create(&package_path).map_err(|error| format!("cannot create package: {error}"))?;
    let mut builder = tar::Builder::new(package_file);

    let manifest_bytes = manifest.to_toml().into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, MANIFEST_MEMBER, manifest_bytes.as_slice())
        .map_err(|error| format!("cannot add manifest: {error}"))?;

    let checksum_bytes =
        serde_json::to_vec_pretty(&checksums).map_err(|error| error.to_string())?;
    let mut header = tar::Header::new_gnu();
    header.set_size(checksum_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, CHECKSUMS_MEMBER, checksum_bytes.as_slice())
        .map_err(|error| format!("cannot add checksums: {error}"))?;

    for (relative, absolute) in &files {
        let mut file = File::open(absolute).map_err(|error| format!("cannot open {relative}: {error}"))?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{PAYLOAD_PREFIX}{relative}"), &mut file)
            .map_err(|error| format!("cannot add {relative}: {error}"))?;
    }

    builder
        .finish()
        .map_err(|error| format!("cannot finalise package: {error}"))?;
    let package_file = builder
        .into_inner()
        .map_err(|error| format!("cannot flush package: {error}"))?;
    package_file
        .sync_all()
        .map_err(|error| format!("cannot sync package: {error}"))?;

    let size_bytes = fs::metadata(&package_path)
        .map_err(|error| error.to_string())?
        .len();
    let package_sha256 = {
        let bytes = fs::read(&package_path).map_err(|error| error.to_string())?;
        sha256_hex(&bytes)
    };
    Ok(BuiltPackage {
        path: package_path,
        manifest,
        package_sha256,
        size_bytes,
        file_count: files.len(),
    })
}
/// Read manifest, checksums and payload list without extracting.
pub fn read_package(path: &Path) -> Result<PackageInfo, String> {
    let file = File::open(path).map_err(|error| format!("cannot open package: {error}"))?;
    let size_bytes = file.metadata().map_err(|error| error.to_string())?.len();
    let mut archive = tar::Archive::new(file);
    let mut manifest = None;
    let mut checksums = None;
    let mut payload_members = Vec::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("invalid archive: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("invalid archive entry: {error}"))?;
        let member = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let member = member.to_string_lossy().into_owned();
        if member == MANIFEST_MEMBER {
            let mut raw = String::new();
            entry
                .read_to_string(&mut raw)
                .map_err(|error| error.to_string())?;
            manifest = Some(WioManifest::from_toml(&raw)?);
        } else if member == CHECKSUMS_MEMBER {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).map_err(|error| error.to_string())?;
            checksums = Some(
                serde_json::from_slice::<Checksums>(&raw)
                    .map_err(|error| format!("invalid checksums.json: {error}"))?,
            );
        } else if let Some(relative) = member.strip_prefix(PAYLOAD_PREFIX) {
            if !is_safe_relative(relative) {
                return Err(format!("unsafe payload path '{relative}'"));
            }
            payload_members.push(relative.to_owned());
        } else {
            return Err(format!("unexpected archive member '{member}'"));
        }
    }
    let manifest = manifest.ok_or_else(|| "package has no wio.toml".to_owned())?;
    payload_members.sort();
    Ok(PackageInfo {
        manifest,
        checksums,
        payload_members,
        size_bytes,
    })
}

fn is_safe_relative(relative: &str) -> bool {
    !relative.is_empty()
        && !relative.starts_with('/')
        && !relative.contains('\\')
        && relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
/// Verify manifest, payload checksums and entry presence.
pub fn verify_package(path: &Path) -> Result<PackageVerification, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read package: {error}"))?;
    let package_sha256 = sha256_hex(&bytes);

    let mut verification = PackageVerification {
        manifest_ok: false,
        manifest_error: None,
        integrity: None,
        entry_present: false,
        architecture: None,
        errors: Vec::new(),
    };

    let info = match read_package(path) {
        Ok(info) => info,
        Err(error) => {
            verification.manifest_error = Some(error.clone());
            verification.errors.push(error);
            return Ok(verification);
        }
    };
    verification.manifest_ok = true;
    verification.architecture = Some(info.manifest.architecture);
    verification.entry_present = info
        .payload_members
        .iter()
        .any(|member| *member == info.manifest.entry);

    let Some(checksums) = &info.checksums else {
        verification.integrity = Some(IntegrityCheck::Missing);
        verification.errors.push("package has no checksums.json".to_owned());
        return Ok(verification);
    };
    if checksums.algorithm != "sha256" || checksums.schema != 1 {
        verification.integrity = Some(IntegrityCheck::Missing);
        verification
            .errors
            .push("unsupported checksum metadata".to_owned());
        return Ok(verification);
    }

    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut archive = tar::Archive::new(file);
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let member = entry.path().map_err(|error| error.to_string())?.into_owned();
        let member = member.to_string_lossy().into_owned();
        let Some(relative) = member.strip_prefix(PAYLOAD_PREFIX) else {
            continue;
        };
        let digest = sha256_reader(&mut entry).map_err(|error| error.to_string())?;
        seen.insert(relative.to_owned(), digest);
    }
    for (relative, digest) in &seen {
        match checksums.files.get(relative) {
            Some(expected) if expected == digest => {}
            Some(expected) => {
                verification.integrity = Some(IntegrityCheck::Mismatch {
                    expected: expected.clone(),
                    actual: digest.clone(),
                });
                verification
                    .errors
                    .push(format!("checksum mismatch for '{relative}'"));
            }
            None => {
                verification.integrity = Some(IntegrityCheck::Mismatch {
                    expected: "entry covered by checksums.json".to_owned(),
                    actual: relative.clone(),
                });
                verification
                    .errors
                    .push(format!("payload file not covered by checksums: '{relative}'"));
            }
        }
    }
    for expected in checksums.files.keys() {
        if !seen.contains_key(expected) {
            verification.integrity = Some(IntegrityCheck::Mismatch {
                expected: expected.clone(),
                actual: "missing from archive".to_owned(),
            });
            verification
                .errors
                .push(format!("checksummed file missing from archive: '{expected}'"));
        }
    }
    if verification.integrity.is_none() {
        if seen.is_empty() {
            verification.integrity = Some(IntegrityCheck::Missing);
            verification.errors.push("package has no payload".to_owned());
        } else {
            verification.integrity = Some(IntegrityCheck::Valid {
                algorithm: "sha256".to_owned(),
                digest: package_sha256,
            });
        }
    }
    Ok(verification)
}
/// Summary of a successful extraction.
#[derive(Clone, Debug)]
pub struct ExtractSummary {
    pub payload_files: usize,
    pub payload_bytes: u64,
}

/// Extract a package into `dest`, verifying every payload file against
/// `checksums.json` while writing. Unsafe members abort the extraction.
pub fn extract_package(path: &Path, dest: &Path) -> Result<ExtractSummary, String> {
    let info = read_package(path)?;
    let checksums = info
        .checksums
        .clone()
        .ok_or_else(|| "package has no checksums.json".to_owned())?;
    fs::create_dir_all(dest).map_err(|error| format!("cannot create install dir: {error}"))?;

    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut archive = tar::Archive::new(file);
    let mut payload_files = 0usize;
    let mut payload_bytes = 0u64;
    let mut extracted: BTreeMap<String, ()> = BTreeMap::new();

    for entry in archive
        .entries()
        .map_err(|error| format!("invalid archive: {error}"))?
    {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err("package contains a non-regular member (links are not allowed)".to_owned());
        }
        let member = entry.path().map_err(|error| error.to_string())?.into_owned();
        let member = member.to_string_lossy().into_owned();

        if let Some(relative) = member.strip_prefix(PAYLOAD_PREFIX) {
            if !is_safe_relative(relative) {
                return Err(format!("unsafe payload path '{relative}'"));
            }
            let Some(expected) = checksums.files.get(relative) else {
                return Err(format!("payload file not covered by checksums: '{relative}'"));
            };
            let mut raw = Vec::new();
            entry
                .read_to_end(&mut raw)
                .map_err(|error| error.to_string())?;
            let digest = sha256_hex(&raw);
            if digest != *expected {
                return Err(format!("checksum mismatch for '{relative}'"));
            }
            let target = dest.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::write(&target, &raw).map_err(|error| error.to_string())?;
            payload_bytes += raw.len() as u64;
            payload_files += 1;
            extracted.insert(relative.to_owned(), ());
        } else if member == MANIFEST_MEMBER || member == CHECKSUMS_MEMBER {
            if entry_type.is_file() {
                let mut raw = Vec::new();
                entry.read_to_end(&mut raw).map_err(|error| error.to_string())?;
                fs::write(dest.join(&member), raw).map_err(|error| error.to_string())?;
            }
        } else {
            return Err(format!("unexpected archive member '{member}'"));
        }
    }

    for expected in checksums.files.keys() {
        if !extracted.contains_key(expected) {
            return Err(format!("checksummed file missing from archive: '{expected}'"));
        }
    }
    if payload_files == 0 {
        return Err("package has no payload".to_owned());
    }
    Ok(ExtractSummary {
        payload_files,
        payload_bytes,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source(dir: &Path) {
        fs::create_dir_all(dir.join("bin")).expect("mkdir");
        fs::create_dir_all(dir.join("assets")).expect("mkdir");
        fs::write(
            dir.join(MANIFEST_MEMBER),
            r##"
schema_version = 1
name = "calculator"
version = "1.0.0"
display_name = "Calculator"
description = "A small calculator."
architecture = "x86_64"
entry = "bin/calculator"
permissions = ["network"]
"##,
        )
        .expect("manifest");
        fs::write(dir.join("bin/calculator"), "#!/bin/sh\necho calc\n").expect("entry");
        fs::write(dir.join("assets/icon.txt"), "CALC").expect("asset");
    }

    fn write_tar(path: &Path, members: &[(&str, &[u8])]) {
        let file = File::create(path).expect("tar file");
        let mut builder = tar::Builder::new(file);
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, *data)
                .expect("append");
        }
        builder.finish().expect("finish");
    }

    #[test]
    fn builds_reads_and_verifies_a_real_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        let built = build(&src, &dir.path().join("dist")).expect("build");
        assert!(built.path.ends_with("calculator-1.0.0.wio"));
        assert_eq!(built.file_count, 2);
        assert_eq!(built.package_sha256.len(), 64);

        let info = read_package(&built.path).expect("read");
        assert_eq!(info.manifest.name, "calculator");
        assert_eq!(info.payload_members, vec!["assets/icon.txt", "bin/calculator"]);
        assert!(info.checksums.is_some());

        let verification = verify_package(&built.path).expect("verify");
        assert!(verification.manifest_ok, "{:?}", verification.errors);
        assert!(verification.entry_present);
        assert_eq!(verification.architecture, Some(Architecture::X86_64));
        assert!(
            matches!(verification.integrity, Some(IntegrityCheck::Valid { .. })),
            "{:?}",
            verification.integrity
        );
        assert!(verification.errors.is_empty());
    }

    #[test]
    fn detects_tampered_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        let built = build(&src, &dir.path().join("dist")).expect("build");

        // Craft a package whose payload no longer matches checksums.json.
        let checksums = serde_json::json!({
            "schema": 1,
            "algorithm": "sha256",
            "files": { "bin/calculator": sha256_hex(b"clean content") }
        });
        let evil = dir.path().join("evil.wio");
        write_tar(
            &evil,
            &[
                (MANIFEST_MEMBER, fs::read_to_string(src.join(MANIFEST_MEMBER)).unwrap().as_bytes()),
                (CHECKSUMS_MEMBER, serde_json::to_vec(&checksums).unwrap().as_slice()),
                (concat!("files/", "bin/calculator"), b"dirty content"),
            ],
        );
        let verification = verify_package(&evil).expect("verify runs");
        assert!(verification.manifest_ok);
        assert!(
            matches!(verification.integrity, Some(IntegrityCheck::Mismatch { .. })),
            "{:?}",
            verification.integrity
        );
        assert!(!verification.errors.is_empty());
        let _ = built;
    }

    #[test]
    fn blocks_packages_without_checksums() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        let manifest = fs::read_to_string(src.join(MANIFEST_MEMBER)).unwrap();
        let no_checksums = dir.path().join("no-checksums.wio");
        write_tar(
            &no_checksums,
            &[
                (MANIFEST_MEMBER, manifest.as_bytes()),
                ("files/bin/calculator", b"whatever"),
            ],
        );
        let verification = verify_package(&no_checksums).expect("verify");
        assert!(matches!(verification.integrity, Some(IntegrityCheck::Missing)));
        assert_eq!(verification.manifest_ok, true);
    }

    #[test]
    fn build_requires_existing_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        fs::remove_file(src.join("bin/calculator")).expect("remove entry");
        let error = build(&src, &dir.path().join("dist")).expect_err("must fail");
        assert!(error.contains("does not exist"));
    }

    #[test]
    fn extracts_payload_with_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        let built = build(&src, &dir.path().join("dist")).expect("build");
        let install_dir = dir.path().join("installed");
        let summary = extract_package(&built.path, &install_dir).expect("extract");
        assert_eq!(summary.payload_files, 2);
        assert!(summary.payload_bytes > 0);
        assert_eq!(
            fs::read_to_string(install_dir.join("bin/calculator")).expect("entry"),
            "#!/bin/sh\necho calc\n"
        );
        assert!(install_dir.join(MANIFEST_MEMBER).exists());
        assert!(install_dir.join(CHECKSUMS_MEMBER).exists());
    }

    #[test]
    fn rejects_unsafe_payload_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source(&src);
        let manifest = fs::read_to_string(src.join(MANIFEST_MEMBER)).unwrap();
        let unsafe_package = dir.path().join("unsafe.wio");
        write_tar(
            &unsafe_package,
            &[
                (MANIFEST_MEMBER, manifest.as_bytes()),
                ("files/../escape", b"evil"),
            ],
        );
        let error = read_package(&unsafe_package).expect_err("must reject");
        assert!(error.contains("unsafe payload path"));
    }
}
