//! WIOOS Core: profiles, configuration, service contracts and platform
//! services shared by every WIOOS target (Desktop, Server, Render, Mobile,
//! Railway Runtime, Minimal).
//!
//! Honesty rules for this crate: every service either reads real data from the
//! host it runs on, or reports an explicit `unavailable` / `not_implemented` /
//! `planned` state through [`status::ComponentStatus`]. Nothing here simulates
//! hardware, malware scanning, or package installation.

pub mod config;
pub mod desktop;
pub mod display;
pub mod files;
pub mod fsutil;
pub mod monitor;
pub mod network;
pub mod permission;
pub mod profile;
pub mod security;
pub mod settings;
pub mod status;
pub mod storage;
pub mod time_service;
pub mod update;
