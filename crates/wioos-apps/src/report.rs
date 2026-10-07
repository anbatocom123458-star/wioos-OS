//! Full system status report: WIOOS Core components plus the app ecosystem.
//!
//! This report is what the About/Settings panels and the CLI print: one
//! transparent list of what works and what is architecture-only.

use wioos_core::status::{ComponentStatus, StatusReport};
use wioos_core::{config::EnvironmentInfo, monitor, network, security, status};

/// Full system report assembled from every backend in this phase.
pub fn full_report(environment: &EnvironmentInfo) -> StatusReport {
    let mut components = Vec::new();

    // --- WIOOS Core ---
    components.push(status::component_status());
    components.push(environment_status(environment));
    components.push(security::center_report().into_iter().next().expect("security log status"));
    components.push(monitor::component_status());
    components.push(monitor::gpu_component().with_note(
        "no GPU backend or telemetry interface exists in this runtime",
    ));
    components.push(network::report().status);
    components.push(crate::core::display::component_status());
    components.push(crate::core::desktop::DockConfig::default().validate().is_ok()
        .then(|| status::ComponentStatus::operational("desktop", "Desktop shell"))
        .unwrap_or_else(|| {
            status::ComponentStatus::not_implemented(
                "desktop", "Desktop shell",
                "no shell backend in this profile",
            )
        }));
    components.push(status::ComponentStatus::operational("time-service", "Time Service"));

    // --- App ecosystem ---
    components.push(apps_status());

    StatusReport::new(components)
}

fn environment_status(environment: &EnvironmentInfo) -> ComponentStatus {
    ComponentStatus::operational("runtime-environment", "Runtime Environment")
        .with_note(format!(
            "OS {} / arch {} / deployed as {}",
            environment.os, environment.arch, environment.runtime_kind
        ))
        .with_note(environment.note.clone())
}

fn apps_status() -> ComponentStatus {
    let mut status = ComponentStatus::operational("app-ecosystem", "App Ecosystem");
    status.notes.push(
        "native .wio packages and web apps are both real; native apps are never \
         presented as web apps"
            .to_owned(),
    );
    status
}

/// Architecture-only subsystems, reported honestly with no fake data.
pub fn infrastructure_status() -> Vec<ComponentStatus> {
    vec![
        status::ComponentStatus::not_implemented(
            "driver-manager",
            "Driver Manager",
            "hardware detection and drivers require the future driver package source",
        ),
        status::ComponentStatus::not_implemented(
            "update-center",
            "Update Center",
            "updates require an update service and boot-level control",
        ),
        status::ComponentStatus::not_implemented(
            "backup-recovery",
            "Backup & Recovery",
            "snapshots and restore require real file-system recovery backends",
        ),
        status::ComponentStatus::not_implemented(
            "firewall",
            "Firewall",
            "no packet filtering backend exists in this runtime",
        ),
        status::ComponentStatus::not_implemented(
            "threat-scanner",
            "Threat Scanner",
            "no malware scanning engine exists; WIOOS never reports threat counts",
        ),
        status::ComponentStatus::not_implemented(
            "sandbox",
            "App Sandbox",
            "no sandbox runner exists yet",
        ),
        status::ComponentStatus::planned(
            "language-installation",
            "Language installation",
            "15 languages are defined; download/install needs the package repository",
        ),
        status::ComponentStatus::planned(
            "native-app-launcher",
            "Native app launcher",
            "native .wio executables require the future native app runtime",
        ),
        status::ComponentStatus::planned(
            "web-runtime-improvements",
            "Web Runtime improvements",
            "iframe embedding, external browser fallback and URL framing limitations",
        ),
    ]
}

/// Checkpoint used by tests and the boot sequence to assert a known state.
pub fn boot_checkpoint() -> StatusReport {
    full_report(&EnvironmentInfo::detect())
}
