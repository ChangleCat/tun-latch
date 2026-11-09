//! Evaluate a saved pcap and explicitly supplied evidence offline. Opens no sockets or PF devices.
#[allow(dead_code)]
#[path = "../tests/pf_lab/driver.rs"]
mod driver;
#[allow(dead_code)]
#[path = "../tests/pf_lab/exact_filter.rs"]
mod exact_filter;
#[path = "../tests/pf_lab/offline_capture.rs"]
mod offline_capture;
#[allow(dead_code)]
#[path = "../tests/pf_lab/traffic.rs"]
mod traffic;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

fn read_bounded(path: &OsStr, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other("input is not a regular file"));
    }
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: pf_lab_capture_eval MANIFEST.json CAPTURE.pcap".into());
    }
    let manifest = serde_json::from_slice(&read_bounded(&args[0], 65536)?)?;
    let capture = read_bounded(&args[1], 1024 * 1024)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&offline_capture::evaluate(manifest, &capture)?)?
    );
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("offline evaluation unavailable: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    #[test]
    fn accepts_only_bounded_regular_files_and_non_utf8_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("regular");
        let non_utf8 = std::ffi::OsString::from_vec(vec![b'p', 0xff]);
        assert!(read_bounded(&non_utf8, 4).is_err());
        std::fs::write(&path, b"abcd")?;
        assert_eq!(read_bounded(path.as_os_str(), 4)?, b"abcd");
        assert!(read_bounded(path.as_os_str(), 3).is_err());
        let link = dir.path().join("link");
        symlink(&path, &link)?;
        assert!(read_bounded(link.as_os_str(), 10).is_err());
        assert!(read_bounded(dir.path().as_os_str(), 10).is_err());
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR)?;
        assert!(read_bounded(fifo.as_os_str(), 10).is_err());
        Ok(())
    }
}
