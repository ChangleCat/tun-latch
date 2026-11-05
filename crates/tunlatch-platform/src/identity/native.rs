//! Narrow, read-only libproc FFI. Never opens, copies or operates on a target FD.

use std::{io, mem, ptr};

use libproc::net_info::{KernCtlInfo, SocketFDInfo, SocketInfo};
use nix::{errno::Errno, libc};

use super::process::{ProcessIdentity, RawControl, RawFd};

pub(super) const MAX_FDS: usize = 1024;
const CAPACITY: usize = MAX_FDS + 1;

#[derive(Debug)]
pub(super) enum NativeError {
    Os(Option<i32>),
    ShortRead,
    Truncated,
    Invalid,
    UnsupportedLayout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SocketSample {
    so: u64,
    pcb: u64,
    kind: i32,
    family: i32,
    protocol: i32,
    control: Option<RawControl>,
}

fn check_layout() -> Result<(), NativeError> {
    if !cfg!(target_arch = "aarch64")
        || mem::size_of::<libc::proc_bsdinfo>() != 136
        || mem::size_of::<libc::proc_fdinfo>() != 8
        || mem::size_of::<SocketFDInfo>() != 792
        || mem::offset_of!(SocketFDInfo, psi) != 24
        || mem::offset_of!(SocketInfo, soi_kind) != 232
        || mem::offset_of!(SocketInfo, soi_proto) != 240
        || mem::offset_of!(SocketInfo, soi_so) != 136
        || mem::offset_of!(SocketInfo, soi_pcb) != 144
        || mem::offset_of!(KernCtlInfo, kcsi_name) != 24
        || mem::offset_of!(KernCtlInfo, kcsi_unit) != 20
    {
        return Err(NativeError::UnsupportedLayout);
    }
    Ok(())
}

fn os_failure() -> NativeError {
    let errno = io::Error::last_os_error()
        .raw_os_error()
        .filter(|number| *number != 0);
    NativeError::Os(errno)
}

pub(super) fn process(pid: i32) -> Result<ProcessIdentity, NativeError> {
    check_layout()?;
    // SAFETY: proc_bsdinfo consists entirely of integer and byte-array fields; zero is valid.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    Errno::clear();
    // SAFETY: `info` is writable and correctly aligned, with the precise size passed to libproc;
    // pid and the flavor are checked/fixed by this module. The call retains no pointer.
    let ret = unsafe { libc::proc_pidinfo(pid, 3, 0, ptr::from_mut(&mut info).cast(), 136) };
    if ret <= 0 {
        return Err(os_failure());
    }
    if ret != 136 {
        return Err(NativeError::ShortRead);
    }
    Ok(ProcessIdentity {
        pid: info.pbi_pid,
        uid: info.pbi_uid,
        birth_seconds: info.pbi_start_tvsec,
        birth_microseconds: u32::try_from(info.pbi_start_tvusec).unwrap_or(u32::MAX),
    })
}

pub(super) fn fds(pid: i32) -> Result<Vec<RawFd>, NativeError> {
    check_layout()?;
    let mut entries: [libc::proc_fdinfo; CAPACITY] = std::array::from_fn(|_| libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    });
    Errno::clear();
    // SAFETY: entries is an initialized aligned array of 1025 SDK entries; 8200 is exactly
    // its byte length. libproc writes only within this buffer and retains no pointer.
    let ret = unsafe { libc::proc_pidinfo(pid, 1, 0, entries.as_mut_ptr().cast(), 8200) };
    if ret <= 0 {
        return Err(os_failure());
    }
    let count = checked_fd_bytes(ret)?;
    let mut result = Vec::with_capacity(count / 8);
    for entry in entries.iter().take(count / 8) {
        if entry.proc_fd < 0 {
            return Err(NativeError::Invalid);
        }
        result.push(RawFd {
            fd: entry.proc_fd,
            kind: entry.proc_fdtype,
        });
    }
    result.sort_unstable_by_key(|entry| entry.fd);
    if result.windows(2).any(|pair| pair[0].fd == pair[1].fd) {
        return Err(NativeError::Invalid);
    }
    Ok(result)
}

fn checked_fd_bytes(ret: i32) -> Result<usize, NativeError> {
    let count = usize::try_from(ret).map_err(|_| NativeError::Invalid)?;
    if count % 8 != 0 {
        return Err(NativeError::ShortRead);
    }
    if count >= 8200 || count / 8 > MAX_FDS {
        return Err(NativeError::Truncated);
    }
    Ok(count)
}

pub(super) fn socket(pid: i32, fd: i32) -> Result<SocketSample, NativeError> {
    check_layout()?;
    // SAFETY: the checked SDK structure contains only integers, byte arrays and C unions;
    // all-zero values are valid. Initialize the entire union, rather than only one member.
    let mut info: SocketFDInfo = unsafe { mem::zeroed() };
    Errno::clear();
    // SAFETY: SocketFDInfo has the SDK checked layout, is aligned and initialized; the fixed
    // read-only flavor writes at most 792 bytes and cannot retain this pointer.
    let ret = unsafe { libc::proc_pidfdinfo(pid, fd, 3, ptr::from_mut(&mut info).cast(), 792) };
    if ret <= 0 {
        return Err(os_failure());
    }
    if ret != 792 {
        return Err(NativeError::ShortRead);
    }
    let control = if info.psi.soi_kind == 6 {
        // SAFETY: the kernel returned the complete socket structure and kind 6 identifies this
        // union member. KernCtlInfo consists entirely of integer/byte fields with valid bit patterns.
        let ctl = unsafe { info.psi.soi_proto.pri_kern_ctl };
        let name: Vec<u8> = ctl.kcsi_name.iter().map(|byte| *byte as u8).collect();
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(NativeError::Invalid)?;
        let name = std::str::from_utf8(&name[..end]).map_err(|_| NativeError::Invalid)?;
        if name.is_empty() {
            return Err(NativeError::Invalid);
        }
        Some(RawControl {
            fd,
            name: name.to_owned(),
            id: ctl.kcsi_id,
            unit: ctl.kcsi_unit,
            socket: info.psi.soi_so,
            pcb: info.psi.soi_pcb,
        })
    } else {
        None
    };
    Ok(SocketSample {
        so: info.psi.soi_so,
        pcb: info.psi.soi_pcb,
        kind: info.psi.soi_kind,
        family: info.psi.soi_family,
        protocol: info.psi.soi_protocol,
        control,
    })
}

impl SocketSample {
    pub(super) fn control(&self) -> Option<&RawControl> {
        self.control.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_misaligned_or_full_fd_buffer() {
        assert!(matches!(checked_fd_bytes(8192), Ok(8192)));
        assert!(matches!(
            checked_fd_bytes(8200),
            Err(NativeError::Truncated)
        ));
        assert!(matches!(checked_fd_bytes(9), Err(NativeError::ShortRead)));
        assert!(matches!(checked_fd_bytes(-1), Err(NativeError::Invalid)));
    }

    #[test]
    fn socket_layout_matches_checked_sdk() {
        if cfg!(target_arch = "aarch64") {
            assert!(check_layout().is_ok());
        } else {
            assert!(matches!(
                check_layout(),
                Err(NativeError::UnsupportedLayout)
            ));
        }
    }
}
