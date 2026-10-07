//! WIOOS application ecosystem: manifests, packages, store, registry,
//! languages and the installation security gate.
//!
//! Honesty rules: native `.wio` packages are real archives with real sha256
//! checksums; web apps are clearly labelled URL entries; language installation
//! and remote store fetches report `not_implemented` until a package
//! repository exists.

pub mod gate;
pub mod language;
pub mod manifest;
pub mod package;
pub mod registry;
pub mod report;
pub mod store;
pub mod webapp;
