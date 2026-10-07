use std::{env, error::Error, path::PathBuf, str::FromStr};

use ipnet::IpNet;

pub struct Config {
    pub port: u16,
    pub state_path: PathBuf,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_owned())
            .parse::<u16>()?;
        let state_dir = env::var_os("WIOOS_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"));
        let state_path = state_dir.join("verification.json");
        let trusted_proxy_cidrs = env::var("WIOOS_TRUSTED_PROXY_CIDRS")
            .unwrap_or_default()
            .split(',')
            .filter(|entry| !entry.trim().is_empty())
            .map(|entry| IpNet::from_str(entry.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            port,
            state_path,
            trusted_proxy_cidrs,
        })
    }
}
