//! Shared bounded transport for the offline driver and separately gated operator example.
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{MsgFlags, recv};
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct ProbeFailure {
    pub(super) stage: &'static str,
    pub(super) source: io::Error,
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.source)
    }
}

impl std::error::Error for ProbeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn at<T>(stage: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|source| io::Error::new(source.kind(), ProbeFailure { stage, source }))
}

pub(super) fn peer_matches(actual: SocketAddr, expected: SocketAddr) -> bool {
    match (actual, expected) {
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            a.ip() == b.ip() && a.port() == b.port() && a.scope_id() == b.scope_id()
        }
        (a, b) => a == b,
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline"))
}
fn read_before(stream: &impl AsFd, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
    let fd = stream.as_fd();
    loop {
        remaining(deadline)?;
        // Darwin rejects socket option changes after both halves close. Keep reading
        // without changing SO_RCVTIMEO, including when the final bytes and FIN arrive together.
        match recv(fd.as_raw_fd(), buffer, MsgFlags::MSG_DONTWAIT) {
            Ok(count) => return Ok(count),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => {}
            Err(error) => return Err(error.into()),
        }
        let millis = remaining(deadline)?.as_millis().saturating_add(1);
        let timeout = PollTimeout::try_from(millis).unwrap_or(PollTimeout::MAX);
        let mut waiting = [PollFd::new(fd, PollFlags::POLLIN)];
        match poll(&mut waiting, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_exact(stream: &TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let count = read_before(stream, &mut buffer[offset..], deadline)?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short probe"));
        }
        offset += count;
    }
    Ok(())
}
fn write_all(stream: &mut TcpStream, buffer: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = stream.write(&buffer[offset..])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short probe write",
            ));
        }
        offset += count;
    }
    Ok(())
}
pub(super) fn end_of_stream(stream: &impl AsFd, deadline: Instant) -> io::Result<()> {
    if read_before(stream, &mut [0; 1], deadline)? != 0 {
        return Err(io::Error::other("extra probe bytes"));
    }
    Ok(())
}
pub(super) fn exchange(
    sender: bool,
    tcp: bool,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    budget: Duration,
    ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > 512 {
        return at(
            "input",
            Err(io::Error::other("bounded probe payload required")),
        );
    }
    let deadline = Instant::now() + budget;
    let domain = if source.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let (kind, proto) = if tcp {
        (socket2::Type::STREAM, socket2::Protocol::TCP)
    } else {
        (socket2::Type::DGRAM, socket2::Protocol::UDP)
    };
    let socket = at("socket", socket2::Socket::new(domain, kind, Some(proto)))?;
    if source.is_ipv6() {
        at("ipv6_only", socket.set_only_v6(true))?;
    }
    at(
        "bind",
        socket.bind(&if sender { source } else { destination }.into()),
    )?;
    let mut buffer = [0; 513];
    if tcp {
        let mut stream: TcpStream = if sender {
            let wait = at("connect_budget", remaining(deadline))?;
            at(
                "connect_attempted",
                socket.connect_timeout(&destination.into(), wait),
            )?;
            socket.into()
        } else {
            at("listen", socket.listen(1))?;
            at("listen_mode", socket.set_nonblocking(true))?;
            at("ready_output", ready())?;
            let (accepted, peer) = loop {
                match socket.accept() {
                    Ok(pair) => break pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::park_timeout(
                            at("accept", remaining(deadline))?.min(Duration::from_millis(1)),
                        );
                    }
                    Err(error) => return at("accept", Err(error)),
                }
            };
            if !peer
                .as_socket()
                .is_some_and(|actual| peer_matches(actual, source))
            {
                return at("peer", Err(io::Error::other("foreign probe peer")));
            }
            at("stream_mode", accepted.set_nonblocking(false))?;
            accepted.into()
        };
        if sender {
            at("write", write_all(&mut stream, payload, deadline))?;
            at("shutdown_write", stream.shutdown(Shutdown::Write))?;
        }
        at(
            "read",
            read_exact(&stream, &mut buffer[..payload.len()], deadline),
        )?;
        at("read_eof", end_of_stream(&stream, deadline))?;
        if &buffer[..payload.len()] != payload {
            return at("nonce", Err(io::Error::other("probe nonce mismatch")));
        }
        if !sender {
            at("write", write_all(&mut stream, payload, deadline))?;
            at("shutdown_write", stream.shutdown(Shutdown::Write))?;
        }
        at("deadline", remaining(deadline))?;
        Ok(buffer[..payload.len()].to_vec())
    } else {
        let socket: UdpSocket = socket.into();
        if sender {
            at(
                "send",
                send_datagram(&socket, payload, destination, deadline),
            )?;
        } else {
            at("ready_output", ready())?;
        }
        let (size, peer) = at(
            "receive",
            remaining(deadline).and_then(|wait| {
                socket.set_read_timeout(Some(wait))?;
                socket.recv_from(&mut buffer)
            }),
        )?;
        if !peer_matches(peer, if sender { destination } else { source }) {
            return at("peer", Err(io::Error::other("foreign UDP probe")));
        }
        if &buffer[..size] != payload {
            return at("nonce", Err(io::Error::other("mismatched UDP probe")));
        }
        if !sender {
            at("send", send_datagram(&socket, payload, peer, deadline))?;
        }
        at("deadline", remaining(deadline))?;
        Ok(buffer[..size].to_vec())
    }
}

fn send_datagram(
    socket: &UdpSocket,
    payload: &[u8],
    destination: SocketAddr,
    deadline: Instant,
) -> io::Result<()> {
    socket.set_write_timeout(Some(remaining(deadline)?))?;
    if socket.send_to(payload, destination)? != payload.len() {
        return Err(io::Error::other("short datagram"));
    }
    Ok(())
}
