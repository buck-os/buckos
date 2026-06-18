//! BuckOS Installer - Graphical system installation tool
//!
//! This installer provides a beginner-friendly GUI for installing BuckOS
//! while maintaining the flexibility for manual installation similar to Gentoo.

mod app;
mod disk;
mod install;
mod kernel_config;
mod steps;
mod system;
mod tui;
mod types;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// BuckOS Installer - Install BuckOS to your system
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run in text-only mode (no GUI)
    #[arg(long)]
    text_mode: bool,

    /// Target root directory for installation
    #[arg(long, default_value = "/mnt/buckos")]
    target: String,

    /// Path to buckos-build repository (auto-detected if not specified)
    #[arg(long)]
    buckos_build_path: Option<String>,

    /// Skip system requirements check
    #[arg(long)]
    skip_checks: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Perform a dry run without making changes
    #[arg(long)]
    dry_run: bool,

    /// Install a signed ostree image from this channel URL instead of building
    /// from source (e.g. <https://repo.buckos.org/ostree>).
    #[arg(long)]
    ostree_channel: Option<String>,

    /// ostree channel ref to deploy when --ostree-channel is set.
    #[arg(long, default_value = "buckos/x86_64/stable")]
    ostree_ref: String,
}

/// Build the install source from CLI flags: a signed ostree channel when
/// `--ostree-channel` is given, otherwise the default source build.
fn ostree_install_source(args: &Args) -> Option<types::InstallSource> {
    args.ostree_channel
        .clone()
        .map(|channel_url| types::InstallSource::OstreeImage {
            channel_url,
            branch: args.ostree_ref.clone(),
        })
}

/// Locate a Wayland display socket inside the given runtime directory.
///
/// Prefers the conventional `wayland-0`/`wayland-1` names, then falls back to
/// scanning for any `wayland-*` socket (ignoring `.lock` files and compositor
/// helper sockets such as Alacritty's).
fn find_wayland_socket(runtime_dir: &std::path::Path) -> Option<String> {
    for name in ["wayland-0", "wayland-1"] {
        if runtime_dir.join(name).exists() {
            return Some(name.to_string());
        }
    }

    let entries = std::fs::read_dir(runtime_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("wayland-") && !name.ends_with(".lock") {
            return Some(name.into_owned());
        }
    }
    None
}

/// Repair the display environment when running under `sudo`.
///
/// `sudo` mangles the Wayland environment in session-dependent ways: it may drop
/// `WAYLAND_DISPLAY`, and it commonly resets `XDG_RUNTIME_DIR` to root's
/// directory (or drops it) while leaving `DISPLAY` pointing at an Xwayland
/// server we have no auth cookie for. Any of these makes winit's Wayland backend
/// fail to find the compositor socket and fall back to X11, which then dies with
/// "Failed to open connection to X server".
///
/// To make `sudo ./buckos-installer` work on a Wayland session (e.g. sway), we
/// rebuild the invoking user's Wayland environment from `SUDO_UID`: point
/// `XDG_RUNTIME_DIR` at `/run/user/<uid>`, locate the real compositor socket,
/// and drop `DISPLAY` so winit/eframe commit to the Wayland backend.
fn repair_display_environment() {
    use std::env;
    use std::path::PathBuf;

    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    // Without SUDO_UID we can't know the invoking user's runtime dir (e.g. a
    // real root login). Leave the environment untouched.
    let Some(uid) = env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    else {
        return;
    };

    // /run/user/<uid> is the canonical runtime dir for the invoking user; an
    // inherited XDG_RUNTIME_DIR under sudo often points at the wrong place.
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    if !runtime_dir.is_dir() {
        return;
    }

    // Trust an inherited WAYLAND_DISPLAY only if its socket actually exists in
    // the runtime dir; otherwise discover the real one.
    let socket = match env::var("WAYLAND_DISPLAY") {
        Ok(name) if runtime_dir.join(&name).exists() => Some(name),
        _ => find_wayland_socket(&runtime_dir),
    };

    let Some(socket) = socket else {
        return;
    };

    tracing::info!(
        "Reconstructing Wayland environment for uid {uid}: XDG_RUNTIME_DIR={}, WAYLAND_DISPLAY={}",
        runtime_dir.display(),
        socket
    );
    env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
    env::set_var("WAYLAND_DISPLAY", &socket);
    // The inherited DISPLAY points at an Xwayland server we can't authenticate
    // to; removing it forces winit/eframe onto the Wayland backend.
    env::remove_var("DISPLAY");
}

/// Check that we have the necessary environment variables to connect to a display server.
/// This is especially important when running with sudo.
fn check_display_environment() -> Result<()> {
    use std::env;

    // Check if we're running as root
    let is_root = unsafe { libc::geteuid() } == 0;

    if !is_root {
        // Not running as root, environment should be fine
        return Ok(());
    }

    // Attempt to reconstruct a stripped Wayland environment before checking.
    repair_display_environment();

    // Running as root - check for necessary environment variables
    let has_wayland = env::var("WAYLAND_DISPLAY").is_ok();
    let has_xdg_runtime = env::var("XDG_RUNTIME_DIR").is_ok();
    let has_display = env::var("DISPLAY").is_ok();

    // If we have neither Wayland nor X11 environment variables, we'll likely fail
    if !has_wayland && !has_display {
        eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
        eprintln!("║              ERROR: Display Server Connection Missing              ║");
        eprintln!("╚════════════════════════════════════════════════════════════════════╝\n");
        eprintln!("The installer is running as root but cannot connect to your display");
        eprintln!("server. This happens when environment variables are not preserved.\n");

        if !has_wayland {
            eprintln!("Missing: WAYLAND_DISPLAY environment variable");
        }
        if !has_xdg_runtime {
            eprintln!("Missing: XDG_RUNTIME_DIR environment variable");
        }
        if !has_display {
            eprintln!("Missing: DISPLAY environment variable");
        }

        eprintln!("\n📋 SOLUTIONS:\n");
        eprintln!("  1. Run with preserved environment variables:");
        eprintln!("     $ sudo -E ./target/release/buckos-installer\n");

        eprintln!("  2. For Wayland (recommended), explicitly preserve variables:");
        eprintln!("     $ sudo WAYLAND_DISPLAY=\"$WAYLAND_DISPLAY\" \\");
        eprintln!("            XDG_RUNTIME_DIR=\"$XDG_RUNTIME_DIR\" \\");
        eprintln!("            ./target/release/buckos-installer\n");

        eprintln!("  3. Use the text-mode installer (no GUI):");
        eprintln!("     $ sudo ./target/release/buckos-installer --text-mode\n");

        eprintln!("  4. Run without sudo and use polkit/pkexec for privilege escalation");
        eprintln!("     when needed (GUI will prompt for password):\n");
        eprintln!("     $ ./target/release/buckos-installer\n");

        return Err(anyhow::anyhow!(
            "Cannot connect to display server. Please use one of the solutions above."
        ));
    }

    // Warn if we're missing Wayland-specific variables even though WAYLAND_DISPLAY is set
    if has_wayland && !has_xdg_runtime {
        tracing::warn!(
            "WAYLAND_DISPLAY is set but XDG_RUNTIME_DIR is missing. This may cause issues."
        );
        eprintln!("\n⚠️  WARNING: XDG_RUNTIME_DIR is not set.");
        eprintln!("    The installer may have trouble connecting to Wayland.\n");
        eprintln!("    Consider running with:");
        eprintln!("    $ sudo -E ./target/release/buckos-installer\n");
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.debug {
        "buckos_installer=debug,info"
    } else {
        "buckos_installer=info,warn"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("BuckOS Installer starting...");

    // Check for proper environment when running with sudo (GUI mode only)
    if !args.text_mode {
        check_display_environment()?;
    }

    // Detect or validate buckos-build path
    let buckos_build_path = system::detect_buckos_build_path(args.buckos_build_path.as_deref())?;
    tracing::info!("Using buckos-build at: {}", buckos_build_path.display());

    // Check system requirements
    if !args.skip_checks {
        if let Err(e) = system::check_requirements() {
            tracing::error!("System requirements not met: {}", e);
            eprintln!("\nSystem requirements check failed:");
            eprintln!("  {}\n", e);
            eprintln!("You can skip this check with --skip-checks, but installation may fail.");
            eprintln!("For manual installation, please ensure the required tools are available.");
            std::process::exit(1);
        }
    }

    if args.text_mode {
        // Run text-based installer
        run_text_installer(&args, buckos_build_path)
    } else {
        // Run graphical installer
        run_gui_installer(&args, buckos_build_path)
    }
}

fn run_gui_installer(args: &Args, buckos_build_path: std::path::PathBuf) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 650.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("BuckOS Installer"),
        ..Default::default()
    };

    let target = args.target.clone();
    let dry_run = args.dry_run;
    let install_source = ostree_install_source(args);

    eframe::run_native(
        "BuckOS Installer",
        options,
        Box::new(move |cc| {
            // Setup custom fonts and styles
            setup_custom_styles(&cc.egui_ctx);
            Ok(Box::new(app::InstallerApp::new(
                cc,
                target,
                dry_run,
                buckos_build_path,
                install_source,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}

fn run_text_installer(args: &Args, buckos_build_path: std::path::PathBuf) -> Result<()> {
    tui::run_tui_installer(
        args.target.clone(),
        args.dry_run,
        buckos_build_path,
        ostree_install_source(args),
    )
}

fn setup_custom_styles(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Use slightly larger text for readability
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(22.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );

    // Improve spacing
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);

    ctx.set_style(style);
}
