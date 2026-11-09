//! Experimental root filter hook ABI. Compiled only for offline tests until the protected
//! operator, runtime layout qualification, and independent recovery are connected.

use std::fs::{File, symlink_metadata};
use std::io;
use std::num::NonZeroU64;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use nix::libc;

// Darwin arm64 pfioc_rule from the pinned pfctl 0.7.0 bindings. The outer ruleset
// ticket and the inner per-rule ticket have different widths and purposes.
const SIZE: usize = 3104;
const GET_ACTION: usize = 0;
const SET_TICKET: usize = 4;
const INDEX: usize = 12;
const ANCHOR: usize = 16;
const CALL: usize = 1040;
const RULE: usize = 2064;
const RULE_TICKET: usize = RULE + 688;
const OWNER: usize = RULE + 696;
const RULE_INDEX: usize = RULE + 948;
const RULE_ACTION: usize = RULE + 1004;
const MAX_RULES: u32 = 256;
const PF_PASS: u8 = 0;
const PF_GET_NONE: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Operation {
    Count = 6,
    Read = 7,
    Insert = 27,
    Delete = 28,
}

impl Operation {
    const fn code(self) -> libc::c_ulong {
        // Darwin _IOWR('D', number, struct pfioc_rule).
        0xc000_0000
            | ((SIZE as libc::c_ulong) << 16)
            | ((b'D' as libc::c_ulong) << 8)
            | self as libc::c_ulong
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("PF hook refused: {0}")]
    Refused(&'static str),
    #[error("PF hook {operation:?} ioctl failed; result unconfirmed")]
    Ioctl {
        operation: Operation,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[repr(C, align(8))]
struct Frame([u8; SIZE]);

const _: () = {
    assert!(std::mem::size_of::<Frame>() == SIZE);
    assert!(std::mem::align_of::<Frame>() == 8);
};

impl Frame {
    fn u32(&self, at: usize) -> u32 {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(&self.0[at..at + 4]);
        u32::from_ne_bytes(bytes)
    }

    fn set_u32(&mut self, at: usize, value: u32) {
        self.0[at..at + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn rule_ticket(&self) -> Result<NonZeroU64> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.0[RULE_TICKET..RULE_TICKET + 8]);
        NonZeroU64::new(u64::from_ne_bytes(bytes)).ok_or(Error::Refused("missing per-rule ticket"))
    }

    fn field(&self, start: usize, length: usize) -> Result<&[u8]> {
        let field = &self.0[start..start + length];
        let end = field
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Error::Refused("unterminated PF rule field"))?;
        Ok(&field[..end])
    }

    fn is_root(&self) -> bool {
        self.0[ANCHOR..CALL].iter().all(|&byte| byte == 0)
    }
}

struct RootName(String);

impl RootName {
    fn new(session: &str) -> Result<Self> {
        if session.len() != 32
            || session.bytes().all(|b| b == b'0')
            || !session
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Refused("expected a nonzero lowercase hex session"));
        }
        Ok(Self(format!("tunlatch-lab-{session}")))
    }

    fn request(&self, operation: Operation) -> Request {
        let mut request = Request::new(operation);
        let name = self.0.as_bytes();
        request.frame.0[CALL..CALL + name.len()].copy_from_slice(name);
        request.frame.0[OWNER..OWNER + name.len()].copy_from_slice(name);
        request
    }

    fn check_owner(&self, frame: &Frame) -> Result<()> {
        if !frame.is_root()
            || frame.0[RULE_ACTION] != PF_PASS
            || frame.field(OWNER, 64)? != self.0.as_bytes()
        {
            return Err(Error::Refused("root filter class or owner changed"));
        }
        Ok(())
    }
}

struct Request {
    operation: Operation,
    frame: Frame,
}

impl Request {
    fn new(operation: Operation) -> Self {
        let mut frame = Frame([0; SIZE]);
        frame.0[RULE_ACTION] = PF_PASS;
        Self { operation, frame }
    }

    fn delete(name: &RootName, ticket: NonZeroU64) -> Self {
        let mut request = name.request(Operation::Delete);
        request.frame.0[RULE_TICKET..RULE_TICKET + 8].copy_from_slice(&ticket.get().to_ne_bytes());
        request
    }

    fn validate_read_only(&self) -> Result<()> {
        if matches!(self.operation, Operation::Insert | Operation::Delete) {
            // XNU can accept these requests on an O_RDONLY descriptor.
            return Err(Error::Refused("protected PF write entry is not connected"));
        }
        if self.frame.u32(GET_ACTION) != PF_GET_NONE
            || !self.frame.is_root()
            || self.frame.0[RULE_ACTION] != PF_PASS
        {
            return Err(Error::Refused(
                "only non-mutating root filter reads are allowed",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Hook {
    index: u32,
    ticket: NonZeroU64,
}

fn summary(frame: &Frame) -> Result<(u32, u32)> {
    let count = frame.u32(INDEX);
    if !frame.is_root() || frame.0[RULE_ACTION] != PF_PASS || count > MAX_RULES {
        return Err(Error::Refused("unexpected root rule summary"));
    }
    Ok((count, frame.u32(SET_TICKET)))
}

/// Collects only the exact hook's owned fields. The root ruleset ticket checks for change
/// during enumeration. A caller must also compare complete semantics with independent output.
fn observe(name: &RootName, mut run: impl FnMut(Request) -> Result<Frame>) -> Result<Option<Hook>> {
    let (count, ticket) = summary(&run(Request::new(Operation::Count))?)?;
    let mut hook = None;
    for index in 0..count {
        // A new frame for each call keeps opaque output from being sent back as input.
        let mut row = Request::new(Operation::Read);
        row.frame.set_u32(SET_TICKET, ticket);
        row.frame.set_u32(INDEX, index);
        let frame = run(row)?;
        if !frame.is_root()
            || frame.u32(INDEX) != index
            || frame.u32(RULE_INDEX) != index
            || frame.u32(SET_TICKET) != ticket
        {
            return Err(Error::Refused("root rules changed during enumeration"));
        }
        if frame.field(CALL, 1024)? == name.0.as_bytes() {
            name.check_owner(&frame)?;
            let found = Hook {
                index,
                ticket: frame.rule_ticket()?,
            };
            if hook.replace(found).is_some() {
                return Err(Error::Refused("duplicate root hook"));
            }
        }
    }
    if summary(&run(Request::new(Operation::Count))?)? != (count, ticket) {
        return Err(Error::Refused(
            "root rule summary changed during enumeration",
        ));
    }
    Ok(hook)
}

/// The caller journals intent first and independently observes the returned rule.
fn insert(name: &RootName, run: impl FnOnce(Request) -> Result<Frame>) -> Result<NonZeroU64> {
    let frame = run(name.request(Operation::Insert))?;
    name.check_owner(&frame)?;
    if frame.field(CALL, 1024)? != name.0.as_bytes() {
        return Err(Error::Refused("insertion reply call target changed"));
    }
    frame.rule_ticket()
}

/// The caller has already verified the original receipt and current exact root rule.
fn remove(
    name: &RootName,
    ticket: NonZeroU64,
    run: impl FnOnce(Request) -> Result<Frame>,
) -> Result<()> {
    run(Request::delete(name, ticket)).map(|_| ())
}

/// Static candidate layout gate. Identifiers must come from the current host. Matching
/// identifiers still require independent read-only ABI qualification before any live writes.
fn check_host(build: &str, kernel: &str) -> Result<()> {
    if !cfg!(all(
        target_os = "macos",
        target_arch = "aarch64",
        target_endian = "little"
    )) || build != "25G83"
        || kernel
            != "Darwin Kernel Version 25.6.0: Fri Jul 31 19:16:20 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_T8142"
    {
        return Err(Error::Refused("unqualified PF ABI target"));
    }
    Ok(())
}

/// The future isolated helper must provide a freshly qualified build, the held PF device
/// and the checked experiment's authority. The current workspace provides no live caller.
fn ioctl(device: &File, build: &str, kernel: &str, mut request: Request) -> Result<Frame> {
    request.validate_read_only()?;
    if !nix::unistd::geteuid().is_root() {
        return Err(Error::Refused("PF device requires an administrator"));
    }
    check_host(build, kernel)?;
    let held = device.metadata()?;
    if !held.file_type().is_char_device() || held.uid() != 0 {
        return Err(Error::Refused("expected a root character device"));
    }
    let named = symlink_metadata("/dev/pf")?;
    if !named.file_type().is_char_device()
        || (held.dev(), held.ino(), held.rdev()) != (named.dev(), named.ino(), named.rdev())
    {
        return Err(Error::Refused("unexpected PF device identity"));
    }
    // SAFETY: the held descriptor matches the fixed character device. The private operation
    // codes all use the same fixed _IOWR length. The mutable frame is fully initialized and
    // 8-byte aligned, remains live during the synchronous call, and is not reinterpreted as
    // pointer-bearing Rust values. Only initialized bytes are subsequently decoded.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::ioctl(
            device.as_raw_fd(),
            request.operation.code(),
            std::ptr::from_mut(&mut request.frame).cast::<libc::c_void>(),
        )
    };
    if ret < 0 {
        return Err(Error::Ioctl {
            operation: request.operation,
            source: io::Error::last_os_error(),
        });
    }
    if ret != 0 {
        return Err(Error::Refused("unexpected PF ioctl result"));
    }
    Ok(request.frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const BUILD: &str = "25G83";
    const KERNEL: &str = "Darwin Kernel Version 25.6.0: Fri Jul 31 19:16:20 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_T8142";
    const NATIVE_TICKET: u64 = 0x9134_5678_0000_0015;

    #[test]
    fn requests_match_the_audited_darwin_abi() {
        assert_eq!(Operation::Count.code(), 0xcc20_4406);
        assert_eq!(Operation::Read.code(), 0xcc20_4407);
        assert_eq!(Operation::Insert.code(), 0xcc20_441b);
        assert_eq!(Operation::Delete.code(), 0xcc20_441c);
        assert_eq!(std::mem::size_of::<Frame>(), 3104);
        assert_eq!(std::mem::align_of::<Frame>(), 8);
        assert_eq!(
            check_host(BUILD, KERNEL).is_ok(),
            cfg!(target_arch = "aarch64")
        );
        assert!(check_host("25G84", KERNEL).is_err());
        assert!(check_host(BUILD, "Darwin 25.6.0").is_err());
    }

    #[test]
    fn mutation_uses_only_the_fixed_root_name_and_per_rule_ticket() -> Result<()> {
        for malformed in [
            "",
            "00000000000000000000000000000000",
            "00112233445566778899AABBCCDDEEFF",
            "com.apple/*",
        ] {
            assert!(RootName::new(malformed).is_err());
        }
        let name = RootName::new(SESSION)?;
        let inserted = insert(&name, |request| {
            assert_eq!(request.operation, Operation::Insert);
            let mut frame = request.frame;
            assert!(frame.is_root());
            assert_eq!(frame.field(CALL, 1024)?, name.0.as_bytes());
            assert_eq!(frame.field(OWNER, 64)?, name.0.as_bytes());
            assert!(frame.rule_ticket().is_err());
            frame.0[RULE_TICKET..RULE_TICKET + 8].copy_from_slice(&NATIVE_TICKET.to_ne_bytes());
            Ok(frame)
        })?;
        assert_eq!(inserted.get(), NATIVE_TICKET);
        remove(&name, inserted, |request| {
            assert_eq!(request.operation, Operation::Delete);
            assert_eq!(request.frame.u32(SET_TICKET), 0);
            assert_eq!(request.frame.rule_ticket()?.get(), NATIVE_TICKET);
            assert!(request.frame.is_root());
            assert_eq!(request.frame.field(CALL, 1024)?, name.0.as_bytes());
            assert_eq!(request.frame.field(OWNER, 64)?, name.0.as_bytes());
            let mut fields = request.frame;
            fields.0[CALL..RULE].fill(0);
            fields.0[OWNER..OWNER + 64].fill(0);
            fields.0[RULE_TICKET..RULE_TICKET + 8].fill(0);
            assert!(fields.0.iter().all(|&byte| byte == 0));
            Ok(fields)
        })?;
        Ok(())
    }

    #[test]
    fn incomplete_insertion_receipt_stays_unconfirmed() -> Result<()> {
        let name = RootName::new(SESSION)?;
        assert!(insert(&name, |request| Ok(request.frame)).is_err());
        assert!(
            insert(&name, |request| {
                let mut frame = request.frame;
                frame.0[CALL] = b'x';
                frame.0[RULE_TICKET..RULE_TICKET + 8].copy_from_slice(&NATIVE_TICKET.to_ne_bytes());
                Ok(frame)
            })
            .is_err()
        );
        let mut calls = 0;
        let result = insert(&name, |_| {
            calls += 1;
            Err(Error::Ioctl {
                operation: Operation::Insert,
                source: io::Error::from_raw_os_error(libc::EIO),
            })
        });
        assert!(matches!(
            result,
            Err(Error::Ioctl {
                operation: Operation::Insert,
                ..
            })
        ));
        assert_eq!(calls, 1);
        Ok(())
    }

    fn fake_row(name: &RootName, request: Request, change: &str) -> Result<Frame> {
        let mut frame = request.frame;
        let index = frame.u32(INDEX);
        assert_eq!(frame.u32(SET_TICKET), 113);
        assert!(frame.is_root());
        assert!(frame.field(CALL, 1024)?.is_empty());
        assert_eq!(frame.0[0], 0);
        frame.set_u32(RULE_INDEX, index);
        if index == 1 || change == "duplicate" {
            frame.0[CALL..CALL + name.0.len()].copy_from_slice(name.0.as_bytes());
            frame.0[OWNER..OWNER + name.0.len()].copy_from_slice(name.0.as_bytes());
            frame.0[RULE_TICKET..RULE_TICKET + 8].copy_from_slice(&NATIVE_TICKET.to_ne_bytes());
        }
        if index == 1 {
            match change {
                "bad-index" => frame.set_u32(RULE_INDEX, 5),
                "bad-ticket" => frame.set_u32(SET_TICKET, 114),
                "bad-owner" => frame.0[OWNER] = b'x',
                "unterminated" => frame.0[CALL..RULE].fill(b'x'),
                "wrong-class" => frame.0[RULE_ACTION] = 1,
                "missing-rule-ticket" => frame.0[RULE_TICKET..RULE_TICKET + 8].fill(0),
                _ => {}
            }
        }
        Ok(frame)
    }

    #[test]
    fn enumeration_requires_one_matching_root_call_in_a_stable_ruleset() -> Result<()> {
        let name = RootName::new(SESSION)?;
        for change in [
            "none",
            "duplicate",
            "bad-index",
            "bad-ticket",
            "bad-owner",
            "unterminated",
            "wrong-class",
            "missing-rule-ticket",
            "late-ticket",
            "excess",
        ] {
            let mut sweeps = 0;
            let result = observe(&name, |request| match request.operation {
                Operation::Count => {
                    sweeps += 1;
                    let mut frame = request.frame;
                    frame.set_u32(INDEX, if change == "excess" { MAX_RULES + 1 } else { 2 });
                    frame.set_u32(
                        SET_TICKET,
                        if sweeps > 1 && change == "late-ticket" {
                            114
                        } else {
                            113
                        },
                    );
                    Ok(frame)
                }
                Operation::Read => fake_row(&name, request, change),
                _ => Err(Error::Refused("test saw a write request")),
            });
            if change == "none" {
                assert_eq!(
                    result?.map(|hook| (hook.index, hook.ticket.get())),
                    Some((1, NATIVE_TICKET))
                );
                assert_eq!(sweeps, 2);
            } else {
                assert!(result.is_err(), "{change}");
            }
        }
        Ok(())
    }

    #[test]
    fn transport_refuses_mutations_and_non_pf_descriptors() -> Result<()> {
        let file = tempfile::tempfile()?;
        let name = RootName::new(SESSION)?;
        assert!(matches!(
            ioctl(&file, BUILD, KERNEL, name.request(Operation::Insert)),
            Err(Error::Refused(_))
        ));
        let ticket =
            NonZeroU64::new(NATIVE_TICKET).ok_or(Error::Refused("fixture ticket missing"))?;
        assert!(matches!(
            ioctl(&file, BUILD, KERNEL, Request::delete(&name, ticket)),
            Err(Error::Refused(_))
        ));
        // Without administrator permissions this stops even before looking up the device.
        // Under root the regular file still fails the fixed character-device check.
        assert!(matches!(
            ioctl(&file, BUILD, KERNEL, Request::new(Operation::Count)),
            Err(Error::Refused(_))
        ));
        let mut read = Request::new(Operation::Read);
        assert!(read.validate_read_only().is_ok());
        read.frame.set_u32(GET_ACTION, 1);
        assert!(read.validate_read_only().is_err());
        Ok(())
    }
}
