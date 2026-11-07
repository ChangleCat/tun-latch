//! Offline checks of the proposed launchd deployment preview.

use std::{error::Error, fs, process::Command};

use serde_json::{Value, json};
use tunlatch_platform::{
    launchd::{ResourceKind, deployment_preview},
    store::{RecordKind, SYSTEM_STORE_DIRECTORY},
};

#[test]
fn preview_has_fixed_private_resources_and_no_deployment_authority() {
    let preview = deployment_preview();
    assert_eq!(preview, deployment_preview());
    assert!(!preview.ready);
    assert!(
        preview
            .resources
            .iter()
            .all(|r| r.owner == "root" && r.group == "wheel")
    );
    let resource = |path: &str| preview.resources.iter().find(|r| r.path == path);
    for kind in [RecordKind::Policy, RecordKind::Recovery] {
        let path = format!("{SYSTEM_STORE_DIRECTORY}/{}", kind.file_name());
        assert!(resource(&path).is_some_and(|r| r.kind == ResourceKind::File && r.mode == 0o600));
    }
    for (path, kind, mode) in [
        (
            "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch",
            ResourceKind::Directory,
            0o755,
        ),
        (
            "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch/tunlatchd",
            ResourceKind::File,
            0o755,
        ),
        (
            "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch/tunlatch-admin",
            ResourceKind::File,
            0o755,
        ),
        (
            "/Library/LaunchDaemons/io.github.changlecat.tunlatch.plist",
            ResourceKind::File,
            0o644,
        ),
        (SYSTEM_STORE_DIRECTORY, ResourceKind::Directory, 0o700),
        (
            "/private/var/db/tunlatch/writer.lock",
            ResourceKind::File,
            0o600,
        ),
        (
            "/private/var/db/tunlatch-runtime",
            ResourceKind::Directory,
            0o755,
        ),
        (
            "/private/var/db/tunlatch-runtime/query.sock",
            ResourceKind::Socket,
            0o666,
        ),
        (
            "/private/var/db/tunlatch-runtime/control",
            ResourceKind::Directory,
            0o700,
        ),
        (
            "/private/var/db/tunlatch-runtime/control/control.sock",
            ResourceKind::Socket,
            0o600,
        ),
        ("/private/var/log/tunlatch", ResourceKind::Directory, 0o700),
        (
            "/private/var/log/tunlatch/daemon.stdout.log",
            ResourceKind::File,
            0o600,
        ),
        (
            "/private/var/log/tunlatch/daemon.stderr.log",
            ResourceKind::File,
            0o600,
        ),
    ] {
        assert!(
            resource(path).is_some_and(|r| r.kind == kind && r.mode == mode),
            "{path}"
        );
    }
    assert_eq!(preview.resources.len(), 15);
}

#[test]
fn plist_parses_to_the_closed_fixed_launchd_configuration() -> Result<(), Box<dyn Error>> {
    let preview = deployment_preview();
    let temp = tempfile::tempdir()?;
    let plist = temp.path().join("preview.plist");
    fs::write(&plist, preview.plist_xml)?;
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(plist)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        parsed,
        json!({
            "Label": "io.github.changlecat.tunlatch",
            "ProgramArguments": ["/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch/tunlatchd", "--system"],
            "UserName": "root", "GroupName": "wheel",
            "RunAtLoad": true, "KeepAlive": true,
            "WorkingDirectory": "/",
            "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            "Umask": 63,
            "StandardOutPath": "/private/var/log/tunlatch/daemon.stdout.log",
            "StandardErrorPath": "/private/var/log/tunlatch/daemon.stderr.log"
        })
    );
    Ok(())
}
