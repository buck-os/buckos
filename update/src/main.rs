//! `buckos-update` — atomic update agent CLI for ostree-based BuckOS.
//!
//! Thin front-end over [`buckos_update`]: parse args, build an [`UpdateConfig`],
//! and dispatch to the [`Ostree`] driver. See SPEC-006 §5.6 and SPEC-007.

use anyhow::Result;
use buckos_update::{CheckResult, Ostree, UpdateConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "buckos-update",
    version,
    about = "Atomic update agent for BuckOS (ostree)"
)]
struct Cli {
    /// Sysroot to operate on.
    #[arg(long, default_value = "/", global = true)]
    sysroot: PathBuf,
    /// Stateroot / OS name.
    #[arg(long, default_value = "buckos", global = true)]
    os: String,
    /// ostree remote name.
    #[arg(long, default_value = "buckos", global = true)]
    remote: String,
    /// Channel ref to track (default: the booted deployment's origin).
    #[arg(long, global = true)]
    branch: Option<String>,
    /// Path to the ostree binary (default: $BUCKOS_OSTREE or `ostree`).
    #[arg(long, global = true)]
    ostree: Option<String>,
    /// Operate even if the remote does not verify signatures (NOT recommended).
    #[arg(long, global = true)]
    insecure: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show current and pending deployments.
    Status,
    /// Check the channel for a newer commit (no deploy).
    Check,
    /// Pull the latest commit from the channel (verified).
    Pull,
    /// Deploy the latest commit.
    Deploy {
        /// Reboot into the new deployment after staging it.
        #[arg(long)]
        reboot: bool,
    },
    /// Roll back to the previous deployment.
    Rollback,
    /// Prune old, undeployed commits.
    Cleanup,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let mut cfg = UpdateConfig {
        sysroot: cli.sysroot,
        os: cli.os,
        remote: cli.remote,
        branch: cli.branch,
        allow_insecure: cli.insecure,
        ..UpdateConfig::default()
    };
    if let Some(bin) = cli.ostree {
        cfg.ostree_bin = bin;
    }
    let ostree = Ostree::new(cfg);

    match cli.command {
        Command::Status => ostree.status()?,
        Command::Check => match ostree.check()? {
            CheckResult::UpToDate { commit } => println!("up to date ({})", short(&commit)),
            CheckResult::UpdateAvailable { current, candidate } => {
                println!(
                    "update available: {} -> {}",
                    short(&current),
                    short(&candidate)
                )
            }
        },
        Command::Pull => ostree.pull()?,
        Command::Deploy { reboot } => ostree.deploy(reboot)?,
        Command::Rollback => ostree.rollback()?,
        Command::Cleanup => ostree.cleanup()?,
    }
    Ok(())
}

fn short(csum: &str) -> &str {
    &csum[..csum.len().min(12)]
}
