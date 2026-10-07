mod config;
mod state;
mod verification;
mod web;

use std::{error::Error, net::SocketAddr};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::EnvFilter;

use crate::{config::Config, state::VerificationStore};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> AppResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = Config::from_env()?;
    let store = VerificationStore::open(config.state_path.clone()).await?;

    if let Some(command) = std::env::args().nth(1) {
        return run_command(&command, &store).await;
    }

    let address = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app = web::router(store.clone(), config.trusted_proxy_cidrs);
    tracing::info!(%address, "WIOOS runtime prototype listening");
    tokio::spawn(read_operator_commands(store));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn run_command(command: &str, store: &VerificationStore) -> AppResult<()> {
    if command != "verify" {
        eprintln!("Unknown command. Usage: wioos-runtime verify <IP>");
        std::process::exit(2);
    }
    let Some(raw_ip) = std::env::args().nth(2) else {
        eprintln!("Usage: wioos-runtime verify <IP>");
        std::process::exit(2);
    };
    if std::env::args().nth(3).is_some() {
        eprintln!("Usage: wioos-runtime verify <IP>");
        std::process::exit(2);
    }
    match verification::parse_verify_command(&format!("verify {raw_ip}")) {
        Ok(ip) => log_verification(ip, store).await?,
        Err(error) => {
            println!("WIOOS VERIFICATION REJECTED\nIP: {raw_ip}\nREASON: {error}");
            std::process::exit(2);
        }
    }
    Ok(())
}

async fn read_operator_commands(store: VerificationStore) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match verification::parse_verify_command(&line) {
                Ok(ip) => {
                    if let Err(error) = log_verification(ip, &store).await {
                        tracing::error!(%error, "Could not process operator command");
                    }
                }
                Err(error) => println!("WIOOS COMMAND REJECTED\nCOMMAND: {line}\nREASON: {error}"),
            },
            Ok(None) => break,
            Err(error) => {
                tracing::error!(%error, "Could not read operator input");
                break;
            }
        }
    }
}

async fn log_verification(ip: std::net::IpAddr, store: &VerificationStore) -> AppResult<()> {
    let outcome = store.verify(ip).await?;
    let (status, detail) = match outcome {
        state::VerifyOutcome::Verified => ("VERIFIED", "IP marked as verified"),
        state::VerifyOutcome::AlreadyVerified => ("REJECTED", "IP was already verified"),
        state::VerifyOutcome::NotPending => ("REJECTED", "IP is not pending verification"),
    };
    println!(
        "WIOOS VERIFICATION\nIP: {ip}\nTIME: {}\nSTATUS: {status}\nDETAIL: {detail}",
        verification::timestamp()
    );
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
