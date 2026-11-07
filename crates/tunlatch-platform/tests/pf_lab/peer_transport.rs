//! Shared bounded transport for the offline driver and separately gated operator example.
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline"))
}
fn read_exact(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let count = stream.read(&mut buffer[offset..])?;
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
fn end_of_stream(stream: &mut TcpStream, deadline: Instant) -> io::Result<()> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    if stream.read(&mut [0; 1])? != 0 {
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
        return Err(io::Error::other("bounded probe payload required"));
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
    let socket = socket2::Socket::new(domain, kind, Some(proto))?;
    if source.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&if sender { source } else { destination }.into())?;
    let mut buffer = [0; 513];
    if tcp {
        let mut stream: TcpStream = if sender {
            socket.connect_timeout(&destination.into(), remaining(deadline)?)?;
            socket.into()
        } else {
            socket.listen(1)?;
            socket.set_nonblocking(true)?;
            ready()?;
            let (accepted, peer) = loop {
                match socket.accept() {
                    Ok(pair) => break pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::park_timeout(
                            remaining(deadline)?.min(Duration::from_millis(1)),
                        );
                    }
                    Err(e) => return Err(e),
                }
            };
            if peer.as_socket() != Some(source) {
                return Err(io::Error::other("foreign probe peer"));
            }
            accepted.set_nonblocking(false)?;
            accepted.into()
        };
        if sender {
            write_all(&mut stream, payload, deadline)?;
            stream.shutdown(Shutdown::Write)?;
        }
        read_exact(&mut stream, &mut buffer[..payload.len()], deadline)?;
        end_of_stream(&mut stream, deadline)?;
        if &buffer[..payload.len()] != payload {
            return Err(io::Error::other("probe nonce mismatch"));
        }
        if !sender {
            write_all(&mut stream, payload, deadline)?;
            stream.shutdown(Shutdown::Write)?;
        }
        remaining(deadline)?;
        Ok(buffer[..payload.len()].to_vec())
    } else {
        let socket: UdpSocket = socket.into();
        if sender {
            socket.set_write_timeout(Some(remaining(deadline)?))?;
            if socket.send_to(payload, destination)? != payload.len() {
                return Err(io::Error::other("short datagram"));
            }
        } else {
            ready()?;
        }
        socket.set_read_timeout(Some(remaining(deadline)?))?;
        let (size, peer) = socket.recv_from(&mut buffer)?;
        if peer != if sender { destination } else { source } || &buffer[..size] != payload {
            return Err(io::Error::other("foreign or mismatched UDP probe"));
        }
        if !sender {
            socket.set_write_timeout(Some(remaining(deadline)?))?;
            if socket.send_to(payload, peer)? != payload.len() {
                return Err(io::Error::other("short datagram"));
            }
        }
        remaining(deadline)?;
        Ok(buffer[..size].to_vec())
    }
}
