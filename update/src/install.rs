//! Install-time ostree operations (SPEC-006 §5.5, SPEC-007).
//!
//! Deploys a **signed** ostree image onto a freshly partitioned + mounted
//! target, so the BuckOS installer's "ostree image" mode can lay down a system
//! by pulling a release commit instead of building a rootfs from source.
//!
//! This lives in `buckos-update` (not the installer) so the agent and the
//! installer share one trust model: the remote is **always** created with
//! signature verification enabled, so the very first `pull` is verified.
//!
//! NOTE: the exact libostree remote-config key names for ed25519 verification
//! (`verification-ed25519-key`) are version-sensitive; validate against our
//! libostree 2024.10 in SPEC-007 S2. They are isolated as constants below.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Remote-config key that turns on signature verification.
const SIGN_VERIFY: &str = "sign-verify";
/// Remote-config key carrying an inline ed25519 public key (base64). Inline
/// (vs a file) keeps the key in `<repo>/config`, so it is valid both at install
/// time and after the system boots — no path that only exists under the target.
const ED25519_KEY: &str = "verification-ed25519-key";

/// Parameters for deploying a signed ostree image onto a target sysroot.
#[derive(Debug, Clone)]
pub struct ImageInstall {
    /// Mounted target sysroot (e.g. `/mnt`).
    pub target: PathBuf,
    /// Stateroot / OS name.
    pub os: String,
    /// ostree remote name.
    pub remote: String,
    /// Channel base URL (e.g. `https://repo.buckos.org/ostree`).
    pub url: String,
    /// Channel ref to deploy (e.g. `buckos/x86_64/stable`).
    pub branch: String,
    /// ed25519 public key (base64) the remote must verify against. `None`
    /// leaves verification on but unkeyed, which makes `pull` fail closed until
    /// a key is provided — intentional: we never silently pull unverified.
    pub pubkey: Option<String>,
    /// Kernel arguments for the deployment (e.g. `["rw"]`).
    pub kargs: Vec<String>,
    /// `ostree` binary to invoke (overridable for tests via `BUCKOS_OSTREE`).
    pub ostree_bin: String,
}

impl ImageInstall {
    fn repo(&self) -> PathBuf {
        self.target.join("ostree/repo")
    }

    fn refspec(&self) -> String {
        format!("{}:{}", self.remote, self.branch)
    }

    /// init-fs → add verified remote → pull (verified) → stateroot-init →
    /// deploy. `log` receives human-readable progress lines.
    pub fn run(&self, mut log: impl FnMut(&str)) -> Result<()> {
        log("Initializing ostree sysroot");
        self.run_ostree(&init_fs_args(&self.target))?;

        log(&format!("Adding signature-verified remote '{}'", self.remote));
        self.run_ostree(&remote_add_args(
            &self.repo(),
            &self.remote,
            &self.url,
            self.pubkey.as_deref(),
        ))?;

        log(&format!(
            "Pulling {} (signature-verified)",
            self.refspec()
        ));
        self.run_ostree(&pull_args(&self.repo(), &self.remote, &self.branch))?;

        log(&format!("Initializing stateroot '{}'", self.os));
        self.run_ostree(&stateroot_init_args(&self.target, &self.os))?;

        log("Deploying initial commit");
        self.run_ostree(&deploy_args(
            &self.target,
            &self.os,
            &self.refspec(),
            &self.kargs,
        ))?;
        Ok(())
    }

    fn run_ostree(&self, args: &[String]) -> Result<()> {
        let status = Command::new(&self.ostree_bin)
            .args(args)
            .status()
            .with_context(|| format!("failed to execute {}", self.ostree_bin))?;
        if !status.success() {
            bail!("ostree {} failed ({})", args.join(" "), status);
        }
        Ok(())
    }
}

// ── pure arg builders (unit-tested) ──────────────────────────────────────────

fn init_fs_args(target: &Path) -> Vec<String> {
    vec![
        "admin".to_string(),
        "init-fs".to_string(),
        "--modern".to_string(),
        target.display().to_string(),
    ]
}

fn stateroot_init_args(target: &Path, os: &str) -> Vec<String> {
    vec![
        "admin".to_string(),
        "stateroot-init".to_string(),
        format!("--sysroot={}", target.display()),
        os.to_string(),
    ]
}

/// Always sets `sign-verify=true` (the SPEC-007 invariant); adds the inline
/// ed25519 key when provided.
fn remote_add_args(repo: &Path, remote: &str, url: &str, pubkey: Option<&str>) -> Vec<String> {
    let mut v = vec![
        format!("--repo={}", repo.display()),
        "remote".to_string(),
        "add".to_string(),
        "--if-not-exists".to_string(),
        format!("--set={}=true", SIGN_VERIFY),
    ];
    if let Some(key) = pubkey {
        v.push(format!("--set={}={}", ED25519_KEY, key.trim()));
    }
    v.push(remote.to_string());
    v.push(url.to_string());
    v
}

fn pull_args(repo: &Path, remote: &str, branch: &str) -> Vec<String> {
    vec![
        format!("--repo={}", repo.display()),
        "pull".to_string(),
        remote.to_string(),
        branch.to_string(),
    ]
}

fn deploy_args(target: &Path, os: &str, refspec: &str, kargs: &[String]) -> Vec<String> {
    let mut v = vec![
        "admin".to_string(),
        "deploy".to_string(),
        format!("--sysroot={}", target.display()),
        format!("--os={}", os),
    ];
    for k in kargs {
        v.push(format!("--karg={}", k));
    }
    v.push(refspec.to_string());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_fs_is_modern() {
        let a = init_fs_args(Path::new("/mnt"));
        assert_eq!(a, ["admin", "init-fs", "--modern", "/mnt"]);
    }

    #[test]
    fn remote_add_always_verifies() {
        // The SPEC-007 invariant: a remote is never created without verification.
        let a = remote_add_args(Path::new("/mnt/ostree/repo"), "buckos", "https://x/ostree", None);
        assert!(a.iter().any(|s| s == "--set=sign-verify=true"));
        assert!(a.contains(&"buckos".to_string()));
        assert!(a.contains(&"https://x/ostree".to_string()));
        assert!(!a.iter().any(|s| s.starts_with("--set=verification-")));
    }

    #[test]
    fn remote_add_carries_inline_key() {
        let a = remote_add_args(
            Path::new("/mnt/ostree/repo"),
            "buckos",
            "https://x/ostree",
            Some("AAAA_base64_key"),
        );
        assert!(a.iter().any(|s| s == "--set=sign-verify=true"));
        assert!(a
            .iter()
            .any(|s| s == "--set=verification-ed25519-key=AAAA_base64_key"));
    }

    #[test]
    fn deploy_passes_all_kargs_and_refspec_last() {
        let a = deploy_args(
            Path::new("/mnt"),
            "buckos",
            "buckos:buckos/x86_64/stable",
            &["rw".to_string(), "quiet".to_string()],
        );
        assert!(a.contains(&"--os=buckos".to_string()));
        assert!(a.contains(&"--karg=rw".to_string()));
        assert!(a.contains(&"--karg=quiet".to_string()));
        assert_eq!(a.last().unwrap(), "buckos:buckos/x86_64/stable");
    }

    #[test]
    fn pull_targets_repo_remote_branch() {
        let a = pull_args(Path::new("/mnt/ostree/repo"), "buckos", "buckos/x86_64/stable");
        assert_eq!(
            a,
            [
                "--repo=/mnt/ostree/repo",
                "pull",
                "buckos",
                "buckos/x86_64/stable"
            ]
        );
    }
}
