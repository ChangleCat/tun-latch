//! Read-only routing socket notifications. A notification is only an invalidation hint.

use std::io::IoSliceMut;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, recvmsg, socket};

const STARTING: u8 = 0;
const RUNNING: u8 = 1;
const FAILED: u8 = 2;
const STOPPED: u8 = 3;

/// Observable state of the native notification subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionState {
    /// The worker has started but native registration has not completed.
    Starting,
    /// Native registration succeeded; this is not a guarantee of event completeness.
    Running,
    /// Cancellation was requested and native teardown is still in progress.
    Stopping,
    /// Registration, sequencing, or the worker failed; continuity is unknown.
    Failed,
    /// The subscription was stopped; continuity is unknown.
    Stopped,
}

/// A bounded, coalesced view of the native subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventStatus {
    /// Subscription lifecycle state.
    pub state: SubscriptionState,
    /// Monotonic notification counter; changed values require a fresh scan.
    pub revision: u64,
    /// The worker has exited and its thread handle has been joined.
    pub reaped: bool,
}

struct Shared {
    state: AtomicU8,
    revision: AtomicU64,
    stop: AtomicBool,
}

/// Cloneable, non-owning control for a supervised notification worker.
#[derive(Clone)]
pub struct NetworkEventControl {
    shared: Arc<Shared>,
}

impl NetworkEventControl {
    /// Request non-blocking cancellation of the owned worker.
    pub fn request_stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
    }

    /// Read subscription state and revision; this does not reap the worker.
    pub fn status(&self) -> (SubscriptionState, u64) {
        let state = match self.shared.state.load(Ordering::Acquire) {
            STARTING | RUNNING if self.shared.stop.load(Ordering::Acquire) => {
                SubscriptionState::Stopping
            }
            STARTING => SubscriptionState::Starting,
            RUNNING => SubscriptionState::Running,
            STOPPED => SubscriptionState::Stopped,
            _ => SubscriptionState::Failed,
        };
        (state, self.shared.revision.load(Ordering::Acquire))
    }
}

/// Owns one native subscription worker. No event payloads or unbounded queues are retained.
///
/// Callers must periodically perform full scans even when no notification arrives. A subscription
/// cannot prove coverage of all interface changes, sleep/wake, or server interruptions. Stop is
/// requested without blocking; poll until the worker exits before discarding its handle.
pub struct NetworkEventMonitor {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl NetworkEventMonitor {
    /// Return a control handle without transferring ownership of the worker.
    pub fn control(&self) -> NetworkEventControl {
        NetworkEventControl {
            shared: Arc::clone(&self.shared),
        }
    }
    /// Start registration on one dedicated owner thread; inspect `poll` for its result.
    pub fn start() -> Result<Self, std::io::Error> {
        let shared = Arc::new(Shared {
            state: AtomicU8::new(STARTING),
            revision: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("tunlatch-network-events".into())
            .spawn(move || {
                let guard = WorkerGuard(Arc::clone(&worker_shared));
                let Ok(fd) = socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
                else {
                    return;
                };
                if fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).is_err() {
                    return;
                }
                if worker_shared.stop.load(Ordering::Acquire) {
                    return;
                }
                worker_shared.state.store(RUNNING, Ordering::Release);
                while !worker_shared.stop.load(Ordering::Acquire) {
                    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
                    let ready = match poll(&mut fds, 250u16) {
                        Ok(value) => value,
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => {
                            worker_shared.state.store(FAILED, Ordering::Release);
                            break;
                        }
                    };
                    if ready == 0 {
                        continue;
                    }
                    let flags = fds[0].revents().unwrap_or(PollFlags::POLLERR);
                    if flags
                        .intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                        || !flags.contains(PollFlags::POLLIN)
                    {
                        worker_shared.state.store(FAILED, Ordering::Release);
                        break;
                    }
                    // Bound both memory and time spent draining a busy routing socket.
                    let mut buffer = [0u8; 65536];
                    let mut drained = false;
                    for _ in 0..64 {
                        let mut slices = [IoSliceMut::new(&mut buffer)];
                        let msg = match recvmsg::<()>(
                            fd.as_raw_fd(),
                            &mut slices,
                            None,
                            MsgFlags::MSG_DONTWAIT,
                        ) {
                            Ok(msg) => msg,
                            Err(nix::errno::Errno::EAGAIN) => {
                                drained = true;
                                break;
                            }
                            Err(nix::errno::Errno::EINTR) => continue,
                            Err(_) => break,
                        };
                        let len = msg.bytes;
                        let truncated = msg.flags.contains(MsgFlags::MSG_TRUNC);
                        if truncated || !valid_messages(&buffer[..len]) {
                            break;
                        }
                        if worker_shared
                            .revision
                            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                            .is_err()
                        {
                            break;
                        }
                    }
                    if !drained {
                        worker_shared.state.store(FAILED, Ordering::Release);
                        break;
                    }
                }
                drop(fd);
                drop(guard);
            })?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    /// Read lifecycle and revision, and reap a worker that has already exited.
    pub fn poll(&mut self) -> EventStatus {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            self.shared.state.store(FAILED, Ordering::Release);
        }
        let (state, revision) = self.control().status();
        EventStatus {
            state,
            revision,
            reaped: self.worker.is_none(),
        }
    }

    /// Request cancellation without waiting for native teardown.
    pub fn request_stop(&self) {
        self.control().request_stop();
    }
}

impl Drop for NetworkEventMonitor {
    fn drop(&mut self) {
        self.request_stop();
    }
}

// XNU net/route.h and net/if.h: u16 native-endian length, u8 version, u8 type.
// Validate each known fixed header before treating it as an invalidation hint.
fn minimum_header(message_type: u8) -> Option<usize> {
    use nix::libc;
    use std::mem::size_of;

    match i32::from(message_type) {
        libc::RTM_ADD
        | libc::RTM_DELETE
        | libc::RTM_CHANGE
        | libc::RTM_GET
        | libc::RTM_LOSING
        | libc::RTM_REDIRECT
        | libc::RTM_MISS
        | libc::RTM_LOCK
        | libc::RTM_OLDADD
        | libc::RTM_OLDDEL
        | libc::RTM_RESOLVE => Some(size_of::<libc::rt_msghdr>()),
        libc::RTM_NEWADDR | libc::RTM_DELADDR => Some(size_of::<libc::ifa_msghdr>()),
        libc::RTM_IFINFO => Some(size_of::<libc::if_msghdr>()),
        libc::RTM_NEWMADDR | libc::RTM_DELMADDR => Some(size_of::<libc::ifma_msghdr>()),
        libc::RTM_IFINFO2 => Some(size_of::<libc::if_msghdr2>()),
        libc::RTM_NEWMADDR2 => Some(size_of::<libc::ifma_msghdr2>()),
        libc::RTM_GET2 => Some(size_of::<libc::rt_msghdr2>()),
        _ => None,
    }
}

fn valid_messages(mut bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return false;
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let Some(minimum) = minimum_header(bytes[3]) else {
            return false;
        };
        if length < minimum || length > bytes.len() || i32::from(bytes[2]) != nix::libc::RTM_VERSION
        {
            return false;
        }
        bytes = &bytes[length..];
    }
    true
}

struct WorkerGuard(Arc<Shared>);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let current = self.0.state.load(Ordering::Acquire);
        let next = if current == FAILED || !self.0.stop.load(Ordering::Acquire) {
            FAILED
        } else {
            STOPPED
        };
        self.0.state.store(next, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Invalidation, NetworkObserver, ScanError};
    use std::time::Duration;

    #[test]
    fn rejects_incomplete_and_unknown_routing_messages() {
        use nix::libc;
        use std::mem::size_of;

        let headers = [
            (libc::RTM_ADD, size_of::<libc::rt_msghdr>()),
            (libc::RTM_NEWADDR, size_of::<libc::ifa_msghdr>()),
            (libc::RTM_IFINFO, size_of::<libc::if_msghdr>()),
            (libc::RTM_NEWMADDR, size_of::<libc::ifma_msghdr>()),
            (libc::RTM_IFINFO2, size_of::<libc::if_msghdr2>()),
            (libc::RTM_NEWMADDR2, size_of::<libc::ifma_msghdr2>()),
            (libc::RTM_GET2, size_of::<libc::rt_msghdr2>()),
        ];
        let mut combined = Vec::new();
        for (kind, size) in headers {
            let mut message = vec![0; size];
            message[..2].copy_from_slice(&u16::try_from(size).unwrap_or_default().to_ne_bytes());
            message[2] = u8::try_from(libc::RTM_VERSION).unwrap_or_default();
            message[3] = u8::try_from(kind).unwrap_or_default();
            assert!(valid_messages(&message));
            assert!(!valid_messages(&message[..size - 1]));
            let short_length = u16::try_from(size - 1).unwrap_or_default();
            message[..2].copy_from_slice(&short_length.to_ne_bytes());
            assert!(!valid_messages(&message));
            message[..2].copy_from_slice(&u16::try_from(size).unwrap_or_default().to_ne_bytes());
            combined.extend_from_slice(&message);
        }
        assert!(valid_messages(&combined));
        combined.push(1);
        assert!(!valid_messages(&combined));
        assert!(!valid_messages(&[]));
        assert!(!valid_messages(&[4, 0, 5]));
        assert!(!valid_messages(&[3, 0, 5, 14]));
        assert!(!valid_messages(&[4, 0, 5, 14]));
        let mut invalid = vec![0; size_of::<libc::if_msghdr>()];
        let invalid_length = u16::try_from(invalid.len()).unwrap_or_default();
        invalid[..2].copy_from_slice(&invalid_length.to_ne_bytes());
        invalid[2] = 4;
        invalid[3] = u8::try_from(libc::RTM_IFINFO).unwrap_or_default();
        assert!(!valid_messages(&invalid));
        invalid[2] = 5;
        invalid[3] = 0x11;
        assert!(!valid_messages(&invalid));
    }

    // Cross-checked against the installed macOS SDK headers on arm64.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn libc_header_sizes_match_the_checked_sdk() {
        use nix::libc;
        use std::mem::size_of;

        assert_eq!(size_of::<libc::rt_msghdr>(), 92);
        assert_eq!(size_of::<libc::rt_msghdr2>(), 92);
        assert_eq!(size_of::<libc::if_msghdr>(), 112);
        assert_eq!(size_of::<libc::if_msghdr2>(), 160);
        assert_eq!(size_of::<libc::ifa_msghdr>(), 20);
        assert_eq!(size_of::<libc::ifma_msghdr>(), 16);
        assert_eq!(size_of::<libc::ifma_msghdr2>(), 20);
    }

    fn fake_monitor() -> (NetworkEventMonitor, Arc<Shared>) {
        let shared = Arc::new(Shared {
            state: AtomicU8::new(RUNNING),
            revision: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        (
            NetworkEventMonitor {
                shared: Arc::clone(&shared),
                worker: None,
            },
            shared,
        )
    }

    #[test]
    fn notifications_during_scan_discard_the_result() {
        let (mut monitor, shared) = fake_monitor();
        let mut observer = NetworkObserver::new(Duration::from_secs(10));
        let result = observer.refresh_with_monitor(&mut monitor, || {
            shared.revision.fetch_add(2, Ordering::AcqRel);
            Ok(Vec::new())
        });
        assert!(matches!(result, Err(ScanError::Interrupted)));
        assert_eq!(observer.invalidation(), Some(Invalidation::Interrupted));
        assert!(observer.current().is_none());
        assert!(
            observer
                .refresh_with_monitor(&mut monitor, || Ok(Vec::new()))
                .is_ok()
        );
    }

    #[test]
    fn failed_subscription_invalidates_a_previous_snapshot() {
        let (mut monitor, shared) = fake_monitor();
        let mut observer = NetworkObserver::new(Duration::from_secs(10));
        assert!(
            observer
                .refresh_with_monitor(&mut monitor, || Ok(Vec::new()))
                .is_ok()
        );
        shared.state.store(FAILED, Ordering::Release);
        assert!(matches!(
            observer.refresh_with_monitor(&mut monitor, || Ok(Vec::new())),
            Err(ScanError::Interrupted)
        ));
        assert!(observer.current().is_none());
    }

    #[test]
    fn stop_request_immediately_makes_subscription_unavailable() {
        let (mut monitor, _) = fake_monitor();
        monitor.request_stop();
        assert_eq!(monitor.poll().state, SubscriptionState::Stopping);
        monitor.request_stop();
    }
}
