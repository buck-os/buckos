//! buckos-update — atomic update agent for BuckOS (SPEC-006 §5.6, SPEC-007).
//!
//! A thin, synchronous wrapper over the `ostree` CLI that drives the
//! deploy/rollback lifecycle of an ostree-based BuckOS system: `status`,
//! `check`, `pull`, `deploy`, `rollback`, `cleanup`.
//!
//! Signature verification is enforced by the ostree *remote*
//! (`sign-verify=true`, set up by the installer / baked into the image per
//! SPEC-007). This agent additionally **fails closed**: it refuses to pull or
//! deploy from a remote that is not configured to verify signatures, unless
//! `--insecure` is given.
//!
//! libostree itself does the heavy lifting (verification, atomic deployment,
//! boot entries); this crate orchestrates it. End-to-end behaviour is exercised
//! by the QEMU update-cycle test (SPEC-006 P6); the pure parsing/policy helpers
//! are unit-tested below.

pub mod install;

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;

/// Runtime configuration for the update agent.
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// Sysroot to operate on (`/` on a running system).
    pub sysroot: PathBuf,
    /// Stateroot / OS name (`ostree admin --os`).
    pub os: String,
    /// ostree remote name to pull from.
    pub remote: String,
    /// Channel ref to track, e.g. `buckos/x86_64/stable`. When `None`, the
    /// agent tracks the refspec the booted deployment was created from.
    pub branch: Option<String>,
    /// `ostree` binary to invoke (overridable for tests via `BUCKOS_OSTREE`).
    pub ostree_bin: String,
    /// Allow operating against a remote that does not verify signatures.
    pub allow_insecure: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            sysroot: PathBuf::from("/"),
            os: "buckos".to_string(),
            remote: "buckos".to_string(),
            branch: None,
            ostree_bin: std::env::var("BUCKOS_OSTREE").unwrap_or_else(|_| "ostree".to_string()),
            allow_insecure: false,
        }
    }
}

/// Outcome of a `check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// The booted commit already matches the channel tip.
    UpToDate { commit: String },
    /// A newer commit is available on the channel.
    UpdateAvailable { current: String, candidate: String },
}

/// Driver around the `ostree` CLI.
pub struct Ostree {
    cfg: UpdateConfig,
}

impl Ostree {
    pub fn new(cfg: UpdateConfig) -> Self {
        Self { cfg }
    }

    fn repo_path(&self) -> PathBuf {
        self.cfg.sysroot.join("ostree/repo")
    }

    fn sysroot_arg(&self) -> String {
        format!("--sysroot={}", self.cfg.sysroot.display())
    }

    fn repo_arg(&self) -> String {
        format!("--repo={}", self.repo_path().display())
    }

    /// Run `ostree <args>`, capturing stdout; errors carry stderr.
    fn capture(&self, args: &[String]) -> Result<String> {
        let out = Command::new(&self.cfg.ostree_bin)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {}", self.cfg.ostree_bin))?;
        if !out.status.success() {
            bail!(
                "ostree {} failed ({}):\n{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run `ostree <args>` with inherited stdio (live progress); error on
    /// non-zero exit.
    fn inherit(&self, args: &[String]) -> Result<()> {
        let status = Command::new(&self.cfg.ostree_bin)
            .args(args)
            .status()
            .with_context(|| format!("failed to execute {}", self.cfg.ostree_bin))?;
        if !status.success() {
            bail!("ostree {} failed ({})", args.join(" "), status);
        }
        Ok(())
    }

    /// `ostree admin <sub> --sysroot=... <rest>` capturing stdout.
    fn admin_capture(&self, args: &[String]) -> Result<String> {
        self.capture(&self.admin_args(args))
    }

    /// `ostree admin <sub> --sysroot=... <rest>` with live stdio.
    fn admin_inherit(&self, args: &[String]) -> Result<()> {
        self.inherit(&self.admin_args(args))
    }

    /// Build `["admin", <sub>, "--sysroot=...", <rest>...]` from `[<sub>, <rest>...]`.
    fn admin_args(&self, args: &[String]) -> Vec<String> {
        let mut full = vec!["admin".to_string()];
        if let Some((sub, rest)) = args.split_first() {
            full.push(sub.clone());
            full.push(self.sysroot_arg());
            full.extend_from_slice(rest);
        } else {
            full.push(self.sysroot_arg());
        }
        full
    }

    /// Show current and pending deployments (`ostree admin status`).
    pub fn status(&self) -> Result<()> {
        self.admin_inherit(&["status".to_string()])
    }

    /// The refspec the agent tracks: explicit `--branch`, else the booted
    /// deployment's origin.
    fn refspec(&self) -> Result<String> {
        if let Some(b) = &self.cfg.branch {
            return Ok(format!("{}:{}", self.cfg.remote, b));
        }
        let status = self.admin_capture(&["status".to_string()])?;
        parse_booted_origin(&status)
            .context("could not determine the tracked refspec; pass --branch")
    }

    fn booted_checksum(&self) -> Result<String> {
        let status = self.admin_capture(&["status".to_string()])?;
        parse_booted_checksum(&status).context("could not determine the booted commit")
    }

    /// Refuse to proceed unless the remote cryptographically verifies commits
    /// (SPEC-007 fail-closed), unless `--insecure`.
    pub fn ensure_trusted(&self) -> Result<()> {
        if self.cfg.allow_insecure {
            tracing::warn!(
                "--insecure: skipping the signature-verification check on remote '{}'",
                self.cfg.remote
            );
            return Ok(());
        }
        if self.remote_verifies()? {
            return Ok(());
        }
        bail!(
            "remote '{}' is not configured to verify signatures (sign-verify); \
             refusing to pull/deploy unverified content (SPEC-007). \
             Re-run with --insecure to override (not recommended).",
            self.cfg.remote
        );
    }

    /// True if the remote is configured to verify commit signatures. Reads the
    /// repo config and `/etc/ostree/remotes.d/<remote>.conf`.
    fn remote_verifies(&self) -> Result<bool> {
        let header = format!("[remote \"{}\"]", self.cfg.remote);
        let candidates = [
            self.repo_path().join("config"),
            self.cfg
                .sysroot
                .join("etc/ostree/remotes.d")
                .join(format!("{}.conf", self.cfg.remote)),
        ];
        for path in candidates {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(section) = ini_section(&text, &header) {
                if section_verifies(&section) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check the channel for a newer commit without deploying. Fetches only the
    /// commit metadata (cheap, still signature-verified) and compares.
    pub fn check(&self) -> Result<CheckResult> {
        self.ensure_trusted()?;
        let refspec = self.refspec()?;
        let (remote, branch) = split_refspec(&refspec)?;
        self.capture(&[
            self.repo_arg(),
            "pull".to_string(),
            "--commit-metadata-only".to_string(),
            remote,
            branch,
        ])?;
        let candidate = self
            .capture(&[self.repo_arg(), "rev-parse".to_string(), refspec])?
            .trim()
            .to_string();
        let current = self.booted_checksum()?;
        if candidate == current {
            Ok(CheckResult::UpToDate { commit: current })
        } else {
            Ok(CheckResult::UpdateAvailable { current, candidate })
        }
    }

    /// Pull the latest commit on the tracked ref (verified by the remote).
    pub fn pull(&self) -> Result<()> {
        self.ensure_trusted()?;
        let (remote, branch) = split_refspec(&self.refspec()?)?;
        self.inherit(&[self.repo_arg(), "pull".to_string(), remote, branch])
    }

    /// Deploy the tracked ref's tip; optionally reboot into it.
    pub fn deploy(&self, reboot: bool) -> Result<()> {
        self.ensure_trusted()?;
        let refspec = self.refspec()?;
        self.admin_inherit(&[
            "deploy".to_string(),
            format!("--os={}", self.cfg.os),
            refspec,
        ])?;
        if reboot {
            tracing::info!("deployment staged; rebooting");
            let st = Command::new("systemctl")
                .arg("reboot")
                .status()
                .context("failed to invoke `systemctl reboot`")?;
            if !st.success() {
                bail!("`systemctl reboot` failed ({})", st);
            }
        }
        Ok(())
    }

    /// Roll back to the previous deployment (re-deploy the commit immediately
    /// after the booted one; it is already local and was verified when pulled).
    pub fn rollback(&self) -> Result<()> {
        let status = self.admin_capture(&["status".to_string()])?;
        let prior =
            parse_prior_checksum(&status).context("no previous deployment to roll back to")?;
        self.admin_inherit(&["deploy".to_string(), format!("--os={}", self.cfg.os), prior])
    }

    /// Prune old, undeployed commits (`ostree admin cleanup`).
    pub fn cleanup(&self) -> Result<()> {
        self.admin_inherit(&["cleanup".to_string()])
    }
}

// ── pure parsing / policy helpers (unit-tested) ──────────────────────────────

/// Extract the first 64-hex-character run from a line (an ostree commit
/// checksum, e.g. the `<csum>.0` deployment id in `ostree admin status`).
fn first_hex64(line: &str) -> Option<String> {
    for tok in line.split_whitespace() {
        let hex: String = tok.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() >= 64 {
            return Some(hex[..64].to_string());
        }
    }
    None
}

/// Checksums of every deployment, in listed order.
fn parse_deployment_checksums(status: &str) -> Vec<String> {
    status.lines().filter_map(first_hex64).collect()
}

/// Index (within the deployment list) of the booted deployment (marked `*`).
fn parse_booted_index(status: &str) -> Option<usize> {
    let mut idx = 0;
    for line in status.lines() {
        if first_hex64(line).is_some() {
            if line.contains('*') {
                return Some(idx);
            }
            idx += 1;
        }
    }
    None
}

/// Checksum of the booted deployment.
fn parse_booted_checksum(status: &str) -> Option<String> {
    status
        .lines()
        .find(|l| l.contains('*') && first_hex64(l).is_some())
        .and_then(first_hex64)
}

/// Checksum of the deployment the machine can roll back to (the one listed
/// immediately after the booted deployment).
fn parse_prior_checksum(status: &str) -> Option<String> {
    let checksums = parse_deployment_checksums(status);
    let booted = parse_booted_index(status)?;
    checksums.get(booted + 1).cloned()
}

/// The booted deployment's `origin refspec:` value.
fn parse_booted_origin(status: &str) -> Option<String> {
    let mut seen = false;
    for line in status.lines() {
        if line.contains('*') {
            seen = true;
        }
        if seen {
            if let Some(rest) = line.trim().strip_prefix("origin refspec:") {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

/// Return the lines under a `[group]` header (until the next `[`).
fn ini_section(text: &str, header: &str) -> Option<String> {
    let mut out = String::new();
    let mut in_section = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == header;
            continue;
        }
        if in_section {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// True if an ostree remote section enables signature verification.
fn section_verifies(section: &str) -> bool {
    for line in section.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("sign-verify") {
            let v = rest.trim_start().trim_start_matches('=').trim();
            if v.eq_ignore_ascii_case("true") {
                return true;
            }
        }
        if l.starts_with("verification-") {
            return true;
        }
    }
    false
}

/// Split a `<remote>:<ref>` refspec.
fn split_refspec(refspec: &str) -> Result<(String, String)> {
    match refspec.split_once(':') {
        Some((r, b)) if !r.is_empty() && !b.is_empty() => Ok((r.to_string(), b.to_string())),
        _ => bail!("malformed refspec '{}', expected '<remote>:<ref>'", refspec),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "\
State: idle
Deployments:
* buckos 1111111111111111111111111111111111111111111111111111111111111111.0
    Version: 2026.2
    origin refspec: buckos:buckos/x86_64/stable
  buckos 2222222222222222222222222222222222222222222222222222222222222222.0
    Version: 2026.1
    origin refspec: buckos:buckos/x86_64/stable
";

    #[test]
    fn finds_booted_checksum_and_origin() {
        assert_eq!(parse_booted_checksum(STATUS).unwrap(), "1".repeat(64));
        assert_eq!(
            parse_booted_origin(STATUS).unwrap(),
            "buckos:buckos/x86_64/stable"
        );
    }

    #[test]
    fn rollback_target_is_the_next_deployment() {
        assert_eq!(parse_booted_index(STATUS), Some(0));
        assert_eq!(parse_deployment_checksums(STATUS).len(), 2);
        assert_eq!(parse_prior_checksum(STATUS).unwrap(), "2".repeat(64));
    }

    #[test]
    fn no_prior_when_single_deployment() {
        let single = "Deployments:\n* buckos ".to_string() + &"a".repeat(64) + ".0\n";
        assert_eq!(parse_prior_checksum(&single), None);
    }

    #[test]
    fn refspec_split() {
        assert_eq!(
            split_refspec("buckos:buckos/x86_64/stable").unwrap(),
            ("buckos".to_string(), "buckos/x86_64/stable".to_string())
        );
        assert!(split_refspec("no-colon").is_err());
        assert!(split_refspec(":empty").is_err());
    }

    #[test]
    fn ini_section_and_verify_policy() {
        let cfg = "\
[core]
repo_version=1

[remote \"buckos\"]
url=https://example/ostree
sign-verify=true
";
        let section = ini_section(cfg, "[remote \"buckos\"]").unwrap();
        assert!(section_verifies(&section));

        let unverified = "[remote \"buckos\"]\nurl=https://example/ostree\n";
        let s = ini_section(unverified, "[remote \"buckos\"]").unwrap();
        assert!(!section_verifies(&s));
    }

    #[test]
    fn verify_policy_accepts_verification_file_and_rejects_lookalikes() {
        assert!(section_verifies(
            "verification-file=/etc/ostree/keys/buckos.ed25519.pub\n"
        ));
        assert!(!section_verifies("sign-verify-deltas=true\n"));
        assert!(!section_verifies("sign-verify=false\n"));
    }
}
