use std::io;

use anyhow::Context as _;
use nix::unistd::{Uid, User, geteuid, getgid, getuid, setgroups, setresgid, setresuid, setuid};

/// Permanently drop privileges to the given user/group.
/// Order matters — and it must be verified after the fact.
pub fn maybe_drop_privileges(username: &str) -> Result<(), anyhow::Error> {
    if !geteuid().is_root() {
        // We're already unprivileged. The fact that we got here means
        // the operations above succeeded without root — no drop needed.
        log::info!("[*] euid={} — not root, skipping privilege drop", geteuid());
        return Ok(());
    }

    // Root path: full drop, same as before
    let user = User::from_name(username)
        .context("failed to check user exists")?
        .ok_or(anyhow::anyhow!("user '{}' not found", username))?;

    let uid = user.uid;
    let gid = user.gid;

    setgroups(&[])?;
    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;

    if getuid() != uid || getgid() != gid {
        anyhow::bail!("privilege drop verification failed");
    }

    if setuid(Uid::from_raw(0)).is_ok() {
        anyhow::bail!("re-escalation succeeded — aborting");
    }

    log::info!("[+] Dropped privileges to '{}'", username);
    Ok(())
}
/// Maps EACCES/EPERM specifically to a "must be root" message.
/// Other errors (ENOENT, EADDRINUSE, etc.) pass through unchanged.
pub trait MustBeRoot<T> {
    fn or_must_be_root(self, context: &str) -> Result<T, anyhow::Error>;
}

impl<T> MustBeRoot<T> for io::Result<T> {
    fn or_must_be_root(self, context: &str) -> Result<T, anyhow::Error> {
        self.map_err(|e| match e.kind() {
            // Both EACCES and EPERM map to PermissionDenied in Rust
            io::ErrorKind::PermissionDenied => anyhow::anyhow!("must be root: {}", context),
            // ENOENT, EADDRINUSE, etc. are not a privilege problem
            _ => anyhow::Error::from(e),
        })
    }
}
