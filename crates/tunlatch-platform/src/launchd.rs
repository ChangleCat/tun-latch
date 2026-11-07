//! Inert preview of a proposed system deployment. Nothing here installs or starts a service.
//!
//! The current development daemon rejects the proposed `--system` entry. This fixture is
//! not a deployable package, a recovery implementation, or evidence of protection.

use serde::Serialize;

use crate::store::{LOCK_NAME, RecordKind, SYSTEM_STORE_DIRECTORY};

const LABEL: &str = "io.github.changlecat.tunlatch";
const PROGRAM_DIRECTORY: &str = "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch";
const DAEMON: &str = "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch/tunlatchd";
const ADMIN: &str = "/Library/PrivilegedHelperTools/io.github.changlecat.tunlatch/tunlatch-admin";
const PLIST: &str = "/Library/LaunchDaemons/io.github.changlecat.tunlatch.plist";
/// Fixed parent of the separate system query and administrator sockets.
pub const SYSTEM_RUNTIME_DIRECTORY: &str = "/private/var/db/tunlatch-runtime";
/// Query socket leaf within the system runtime directory.
pub const QUERY_SOCKET_NAME: &str = "query.sock";
/// Private administrator directory leaf within the system runtime directory.
pub const CONTROL_DIRECTORY_NAME: &str = "control";
/// Control socket leaf within the administrator directory.
pub const CONTROL_SOCKET_NAME: &str = "control.sock";
const LOG_DIRECTORY: &str = "/private/var/log/tunlatch";

/// Intended type of a fixed resource; no resource is created by this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A directory containing fixed resources.
    Directory,
    /// A program or data file.
    File,
    /// A Unix socket created by the future service.
    Socket,
}

/// Proposed ownership and permissions, subject to future installation and verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeploymentResource {
    /// Absolute fixed path.
    pub path: String,
    /// Expected filesystem type.
    pub kind: ResourceKind,
    /// Required owner name.
    pub owner: &'static str,
    /// Required group name.
    pub group: &'static str,
    /// Unix permission bits, serialized as an integer.
    pub mode: u32,
}

/// Static design preview; `ready` is always false and carries no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeploymentPreview {
    /// Whether this is ready for deployment. Always false.
    pub ready: bool,
    /// Expected paths and attributes, including records, locks and sockets created at runtime.
    /// This inventory does not instruct an installer to pre-create those objects.
    pub resources: Vec<DeploymentResource>,
    /// Proposed launchd property list, never written or loaded by this function.
    pub plist_xml: String,
}

fn resource(path: impl Into<String>, kind: ResourceKind, mode: u32) -> DeploymentResource {
    DeploymentResource {
        path: path.into(),
        kind,
        owner: "root",
        group: "wheel",
        mode,
    }
}

/// Produce deterministic deployment design data without accessing the filesystem or launchd.
#[must_use]
pub fn deployment_preview() -> DeploymentPreview {
    use ResourceKind::{Directory, File, Socket};

    let resources = vec![
        resource(PROGRAM_DIRECTORY, Directory, 0o755),
        resource(DAEMON, File, 0o755),
        resource(ADMIN, File, 0o755),
        resource(PLIST, File, 0o644),
        resource(SYSTEM_STORE_DIRECTORY, Directory, 0o700),
        resource(
            format!(
                "{SYSTEM_STORE_DIRECTORY}/{}",
                RecordKind::Policy.file_name()
            ),
            File,
            0o600,
        ),
        resource(
            format!(
                "{SYSTEM_STORE_DIRECTORY}/{}",
                RecordKind::Recovery.file_name()
            ),
            File,
            0o600,
        ),
        resource(format!("{SYSTEM_STORE_DIRECTORY}/{LOCK_NAME}"), File, 0o600),
        resource(SYSTEM_RUNTIME_DIRECTORY, Directory, 0o755),
        resource(
            format!("{SYSTEM_RUNTIME_DIRECTORY}/{QUERY_SOCKET_NAME}"),
            Socket,
            0o666,
        ),
        resource(
            format!("{SYSTEM_RUNTIME_DIRECTORY}/{CONTROL_DIRECTORY_NAME}"),
            Directory,
            0o700,
        ),
        resource(
            format!("{SYSTEM_RUNTIME_DIRECTORY}/{CONTROL_DIRECTORY_NAME}/{CONTROL_SOCKET_NAME}"),
            Socket,
            0o600,
        ),
        resource(LOG_DIRECTORY, Directory, 0o700),
        resource(format!("{LOG_DIRECTORY}/daemon.stdout.log"), File, 0o600),
        resource(format!("{LOG_DIRECTORY}/daemon.stderr.log"), File, 0o600),
    ];
    // Values are closed constants, not supplied text: no XML or shell interpolation surface.
    let plist_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
  <key>Label</key><string>{LABEL}</string>\n\
  <key>ProgramArguments</key><array><string>{DAEMON}</string><string>--system</string></array>\n\
  <key>UserName</key><string>root</string>\n\
  <key>GroupName</key><string>wheel</string>\n\
  <key>RunAtLoad</key><true/>\n\
  <key>KeepAlive</key><true/>\n\
  <key>WorkingDirectory</key><string>/</string>\n\
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>\n\
  <key>Umask</key><integer>63</integer>\n\
  <key>StandardOutPath</key><string>{LOG_DIRECTORY}/daemon.stdout.log</string>\n\
  <key>StandardErrorPath</key><string>{LOG_DIRECTORY}/daemon.stderr.log</string>\n\
</dict>\n</plist>\n"
    );
    DeploymentPreview {
        ready: false,
        resources,
        plist_xml,
    }
}
