use std::io;

use nix::unistd::{Gid, Group, Uid, User, setgid, setgroups, setresgid, setresuid, setuid};

/// Permanently drop privileges to the given user/group.
/// Order matters — and it must be verified after the fact.
fn drop_privileges(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Look up the target user/group by name
    let user =
        User::from_name(username)?.ok_or_else(|| format!("user '{}' not found", username))?;

    let uid = user.uid;
    let gid = user.gid;

    // 1. Clear ALL supplementary groups first (while still root)
    setgroups(&[]).map_err(|e| format!("setgroups failed: {}", e))?;

    // 2. Drop GID BEFORE UID — once you drop root UID you
    //    can no longer change the GID.
    //    setresgid sets real, effective, AND saved GID.
    setresgid(gid, gid, gid).map_err(|e| format!("setresgid failed: {}", e))?;

    // 3. Drop UID last.
    //    setresuid sets real, effective, AND saved UID,
    //    making it impossible to regain root.
    setresuid(uid, uid, uid).map_err(|e| format!("setresuid failed: {}", e))?;

    // 4. CRITICAL: verify the drop actually worked.
    //    Never skip this — some failure modes are silent.
    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    if current_uid != uid || current_gid != gid {
        return Err("privilege drop verification failed".into());
    }

    // 5. Attempt to re-escalate — this MUST fail.
    if setuid(Uid::from_raw(0)).is_ok() {
        return Err("was able to re-escalate to root — aborting".into());
    }

    Ok(())
}

/// Returns `true` if the error is an access/permission denial
/// that likely requires elevated privileges (sudo) to resolve.
///
/// Covers both `EACCES` (permission denied) and `EPERM` (operation not permitted)
/// via `io::ErrorKind::PermissionDenied` on Linux and FreeBSD.
fn is_permission_denied(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
}
