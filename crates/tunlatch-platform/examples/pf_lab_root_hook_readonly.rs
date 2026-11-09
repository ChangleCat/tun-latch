//! Protected read-only qualification of the root filter ioctl layout.
#[allow(dead_code)]
#[path = "../tests/pf_lab/bootstrap.rs"]
mod bootstrap;
#[path = "../tests/pf_lab/native_files.rs"]
mod native_files;
#[allow(dead_code)]
#[path = "../src/pf/native_hook.rs"]
mod native_hook;
#[allow(dead_code)]
#[path = "../tests/pf_lab/sync_observe.rs"]
mod sync_observe;

use bootstrap::{Acl, Error, Result};
use native_files::{NativePathInspection, ObservedChain};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const BASE: &str = "/private/var/root/tunlatch-pf-root-hook-readonly";
const PROGRAM: &str = "pf-lab-root-hook-readonly";
const EXECUTABLE: &str =
    "/private/var/root/tunlatch-pf-root-hook-readonly/pf-lab-root-hook-readonly";
fn command(program: &str, args: &[&str], deadline: Instant) -> Result<Vec<u8>> {
    Ok(sync_observe::execute_program(program, args, deadline)?.0)
}
fn text_line(bytes: &[u8]) -> Result<&str> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::Refused("invalid system identifier"))?;
    let line = s
        .strip_suffix('\n')
        .ok_or(Error::Refused("invalid system identifier"))?;
    if line.is_empty() || !line.is_ascii() || line.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::Refused("invalid system identifier"));
    }
    Ok(line)
}
fn open_named(dir: &File, name: &str) -> Result<File> {
    Ok(openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?
    .into())
}
fn checked(file: &File, mode: u32, directory: bool) -> Result<Metadata> {
    let m = file.metadata()?;
    if m.uid() != 0
        || m.mode() & 0o7777 != mode
        || (if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        })
        || NativePathInspection.acl(file) != Acl::Empty
    {
        return Err(Error::Refused("protected object invalid"));
    }
    Ok(m)
}
fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.uid(),
        a.mode(),
        a.nlink(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.uid(),
        b.mode(),
        b.nlink(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
fn read_file(file: &File, max: usize, mode: u32) -> Result<Vec<u8>> {
    let before = checked(file, mode, false)?;
    if before.len() > max as u64 {
        return Err(Error::Refused("protected file too large"));
    }
    let mut data = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut data)?;
    if data.len() as u64 != before.len() || !unchanged(&before, &checked(file, mode, false)?) {
        return Err(Error::Refused("protected file changed"));
    }
    Ok(data)
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        let _ = write!(digest, "{byte:02x}");
    }
    digest
}
struct Protected {
    chain: ObservedChain,
    program: File,
}
impl Protected {
    fn open() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() || std::env::current_exe()? != Path::new(EXECUTABLE) {
            return Err(Error::Refused("requires fixed protected executable"));
        }
        let chain = ObservedChain::open(Path::new(BASE))?;
        checked(chain.directory()?, 0o700, true)?;
        let program = open_named(chain.directory()?, PROGRAM)?;
        checked(&program, 0o500, false)?;
        let this = Self { chain, program };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        self.chain.recheck()?;
        let old = checked(self.chain.directory()?, 0o700, true)?;
        let fresh = ObservedChain::open(Path::new(BASE))?;
        let new = checked(fresh.directory()?, 0o700, true)?;
        if (old.dev(), old.ino()) != (new.dev(), new.ino()) {
            return Err(Error::Refused("protected directory replaced"));
        }
        let held = checked(&self.program, 0o500, false)?;
        let named = open_named(fresh.directory()?, PROGRAM)?;
        if !unchanged(&held, &checked(&named, 0o500, false)?) {
            return Err(Error::Refused("protected executable replaced"));
        }
        Ok(())
    }
    fn verify(&self, boot: &str) -> Result<()> {
        self.recheck()?;
        let program = open_named(self.chain.directory()?, PROGRAM)?;
        if !unchanged(&self.program.metadata()?, &program.metadata()?) {
            return Err(Error::Refused("executable changed"));
        }
        let content = read_file(&program, 32 * 1024 * 1024, 0o500)?;
        if content.is_empty() {
            return Err(Error::Refused("empty executable"));
        }
        let digest = sha256_hex(&content);
        let manifest_file = open_named(self.chain.directory()?, "operator-manifest.json")?;
        let manifest: Manifest = serde_json::from_slice(&read_file(&manifest_file, 512, 0o600)?)
            .map_err(|_| Error::Refused("invalid operator manifest"))?;
        if manifest.mode != "pf-root-hook-abi-readonly"
            || manifest.boot != boot
            || manifest.sha256 != digest
        {
            return Err(Error::Refused("operator manifest mismatch"));
        }
        self.recheck()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    boot: String,
    mode: String,
    sha256: String,
}

fn parse_rules(bytes: &[u8]) -> Result<Vec<native_hook::ReadonlyRule>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::Refused("invalid root rule output"))?;
    if !text.is_ascii()
        || (!text.is_empty() && !text.ends_with('\n'))
        || text
            .bytes()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
    {
        return Err(Error::Refused("invalid root rule framing"));
    }
    let mut result = Vec::new();
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let class = words.next().ok_or(Error::Refused("empty root rule"))?;
        // pfctl shows the system scrub hook with filters. PF_PASS selects only the
        // filter ruleset; the full textual before/after check still covers this line.
        if line == "scrub-anchor \"com.apple/*\" all fragment reassemble" {
            continue;
        }
        let call = match class {
            "pass" | "block" => String::new(),
            "anchor" => words
                .next()
                .and_then(|s| s.strip_prefix('"'))
                .and_then(|s| s.strip_suffix('"'))
                .filter(|s| !s.is_empty())
                .ok_or(Error::Refused("unsupported root call"))?
                .to_owned(),
            _ => return Err(Error::Refused("unsupported root rule class")),
        };
        if result.len() >= 256 {
            return Err(Error::Refused("invalid or excessive root rule output"));
        }
        result.push(native_hook::ReadonlyRule {
            class: match class {
                "pass" => "pass",
                "block" => "block",
                _ => "anchor",
            },
            call,
        });
    }
    Ok(result)
}
fn check() -> Result<Value> {
    let protected = Protected::open()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let boot_data = command(
        "/usr/sbin/sysctl",
        &["-n", "kern.bootsessionuuid"],
        deadline,
    )?;
    let boot = text_line(&boot_data)?.to_ascii_lowercase();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(Error::Refused("invalid boot identity"));
    }
    protected.verify(&boot)?;
    let build_data = command("/usr/bin/sw_vers", &["-buildVersion"], deadline)?;
    let kernel_data = command("/usr/sbin/sysctl", &["-n", "kern.version"], deadline)?;
    let build = text_line(&build_data)?;
    let kernel = text_line(&kernel_data)?;
    native_hook::check_host(build, kernel)
        .map_err(|_| Error::Refused("unqualified PF ABI target"))?;
    let before = command("/sbin/pfctl", &["-s", "rules"], deadline)?;
    let expected = parse_rules(&before)?;
    protected.recheck()?;
    let device: File = open(
        Path::new("/dev/pf"),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let actual = native_hook::readonly_rules(&device, build, kernel)
        .map_err(|_| Error::Refused("native root filter read refused"))?;
    let after = command("/sbin/pfctl", &["-s", "rules"], deadline)?;
    if before != after || actual != expected {
        return Err(Error::Refused(
            "root filter observations disagree or changed",
        ));
    }
    protected.verify(&boot)?;
    if Instant::now() >= deadline {
        return Err(Error::Refused("observation deadline exceeded"));
    }
    Ok(
        json!({"result":"readback_matched","scope":"root_filter_read_layout",
              "rules":actual.len(),"build":"25G83",
              "root_rules_sha256":sha256_hex(&before)}),
    )
}
fn run() -> Result<Value> {
    let mut args = std::env::args_os().skip(1);
    let action = args.next();
    if args.next().is_some() {
        return Err(Error::Refused("unexpected arguments"));
    }
    match action.as_deref().and_then(|s| s.to_str()) {
        Some("layout") => {
            let (size, alignment, count, read) = native_hook::readonly_layout();
            Ok(
                json!({"size":size,"alignment":alignment,"count":format!("{count:#x}"),"read":format!("{read:#x}")}),
            )
        }
        Some("check") => check(),
        _ => Err(Error::Refused("expected layout or check")),
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            if writeln!(io::stdout().lock(), "{value}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            let reason = match error {
                Error::Refused(reason) => reason,
                Error::Io(_) | Error::System(_) => "protected read or system query failed",
            };
            let _ = writeln!(
                io::stdout().lock(),
                "{}",
                json!({"result":"refused","reason":reason})
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod qualification_tests {
    use super::*;

    #[test]
    fn rule_parser_preserves_order_and_rejects_unknown_or_unframed_output() -> Result<()> {
        let rules = parse_rules(b"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\nblock drop all\npass all\n")?;
        assert_eq!(
            rules
                .iter()
                .map(|r| (r.class, r.call.as_str()))
                .collect::<Vec<_>>(),
            vec![("anchor", "com.apple/*"), ("block", ""), ("pass", "")]
        );
        for bad in [
            b"anchor unquoted all\n".as_slice(),
            b"scrub-anchor \"x\" all\n",
            b"pass all",
            b"pass all\r\n",
            b"\n",
        ] {
            assert!(parse_rules(bad).is_err());
        }
        Ok(())
    }
}
