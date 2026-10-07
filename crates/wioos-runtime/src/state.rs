use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    net::IpAddr,
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct VerificationStore {
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VerificationStatus {
    Pending,
    Verified,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VerifyOutcome {
    Verified,
    AlreadyVerified,
    NotPending,
}

impl VerificationStore {
    pub async fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let store = Self { path };
        tokio::task::spawn_blocking({
            let path = store.path.clone();
            move || with_locked_state(&path, |_| Ok(()))
        })
        .await
        .map_err(io::Error::other)??;
        Ok(store)
    }

    pub async fn record_request(&self, ip: IpAddr) -> io::Result<VerificationStatus> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            with_locked_state(&path, |state| {
                Ok(*state
                    .entry(ip.to_string())
                    .or_insert(VerificationStatus::Pending))
            })
        })
        .await
        .map_err(io::Error::other)?
    }

    pub async fn verify(&self, ip: IpAddr) -> io::Result<VerifyOutcome> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            with_locked_state(&path, |state| match state.get_mut(&ip.to_string()) {
                Some(status @ VerificationStatus::Pending) => {
                    *status = VerificationStatus::Verified;
                    Ok(VerifyOutcome::Verified)
                }
                Some(VerificationStatus::Verified) => Ok(VerifyOutcome::AlreadyVerified),
                None => Ok(VerifyOutcome::NotPending),
            })
        })
        .await
        .map_err(io::Error::other)?
    }
}

fn with_locked_state<T>(
    path: &Path,
    update: impl FnOnce(&mut BTreeMap<String, VerificationStatus>) -> io::Result<T>,
) -> io::Result<T> {
    let lock_file = File::create(path.with_extension("lock"))?;
    lock_file.lock_exclusive()?;
    let mut state = if path.exists() {
        serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)?
    } else {
        BTreeMap::new()
    };
    let result = update(&mut state)?;
    let temp_path = path.with_extension("tmp");
    fs::write(
        &temp_path,
        serde_json::to_vec_pretty(&state).map_err(io::Error::other)?,
    )?;
    fs::rename(temp_path, path)?;
    FileExt::unlock(&lock_file)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verification_is_persisted_and_duplicate_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("verification.json");
        let ip = "192.0.2.8".parse().expect("valid IP");
        let store = VerificationStore::open(path.clone())
            .await
            .expect("open store");
        assert_eq!(
            store.record_request(ip).await.unwrap(),
            VerificationStatus::Pending
        );
        assert_eq!(store.verify(ip).await.unwrap(), VerifyOutcome::Verified);
        assert_eq!(
            store.verify(ip).await.unwrap(),
            VerifyOutcome::AlreadyVerified
        );
        let reloaded = VerificationStore::open(path).await.expect("reload store");
        assert_eq!(
            reloaded.record_request(ip).await.unwrap(),
            VerificationStatus::Verified
        );
        assert_eq!(
            reloaded.verify("192.0.2.9".parse().unwrap()).await.unwrap(),
            VerifyOutcome::NotPending
        );
    }
}
