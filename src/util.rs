//! Various utilities.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};

use get_if_addrs::{get_if_addrs, Interface};
use tokio;

/// To support the bare-bones nature of this proof-of-concept code, return the first non-loopback
/// IPv4 address of this host.
pub fn get_local_address() -> Ipv4Addr {
    fn log_candidate(iface: &Interface, message: &str) {
        info!("interface candidate {} {:?} {}", iface.name, iface.ip(), message);
    }

    info!("Scanning for a suitable local network interface...");
    for iface in get_if_addrs().unwrap() {
        if iface.is_loopback() {
            log_candidate(&iface, "rejected due to being a loopback interface.");
            continue;
        }
        if iface.name.starts_with("docker") || iface.name.starts_with("veth") {
            log_candidate(&iface, "rejected due to being a docker interface.");
            continue;
        }
        let ip = iface.ip();
        if let IpAddr::V4(ip) = ip {
            log_candidate(&iface, "accepted.");
            return ip;
        } else {
            log_candidate(&iface, "rejected due to not being an IPv4 address.");
        }
    }
    panic!("No non-loopback IPv4 interface was found.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_address() {
        let ip = get_local_address();
        println!("Local IPv4 address: {}", ip);
    }
}

use std::fmt;
use std::io;

use bytes::Bytes;
use futures::{Async, AsyncSink, Poll, Sink, StartSend};
use tokio::io::AsyncWrite;

/// Wrap an `AsyncWrite` in a `Sink`, so it can be used as the target of a `Stream.forward()`.
#[allow(dead_code)]
pub struct AsyncWriteSink<T> {
    writer: T,
}

impl<T> AsyncWriteSink<T>
where
    T: AsyncWrite,
{
    #[allow(dead_code)]
    pub fn new(writer: T) -> AsyncWriteSink<T> {
        AsyncWriteSink { writer }
    }
}

impl<T> Sink for AsyncWriteSink<T>
where
    T: AsyncWrite,
{
    type SinkItem = Bytes;
    type SinkError = io::Error;

    fn start_send(&mut self, payload: Bytes) -> StartSend<Self::SinkItem, Self::SinkError> {
        match self.writer.poll_write(&payload) {
            Ok(Async::Ready(nbytes)) => {
                if nbytes != payload.len() {
                    // With datagrams, it's an error if we can't write the entire buffer.
                    Err(io::Error::new(io::ErrorKind::Other, "buffer overrun"))
                } else {
                    Ok(AsyncSink::Ready)
                }
            }
            Ok(Async::NotReady) => Ok(AsyncSink::NotReady(payload)),
            Err(e) => Err(e),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.writer.poll_flush()
    }
}

/// Wrap a `Sink` and arrange for it to be flushed after every write.  Because we are dealing with
/// datagrams, it's important we don't try to buffer bytes as if they were part of a continuous
/// stream.
#[allow(dead_code)]
pub struct FlushingSink<S> {
    sink: S,
    needs_flush: bool,
}
impl<S> FlushingSink<S>
where
    S: Sink,
{
    #[allow(dead_code)]
    pub fn new(sink: S) -> FlushingSink<S> {
        FlushingSink {
            sink,
            needs_flush: false,
        }
    }
}

impl<S> Sink for FlushingSink<S>
where
    S: Sink,
{
    type SinkItem = S::SinkItem;
    type SinkError = S::SinkError;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        if self.needs_flush {
            match self.sink.poll_complete() {
                Ok(Async::Ready(_)) => self.needs_flush = false,
                Ok(Async::NotReady) => return Ok(AsyncSink::NotReady(item)),
                Err(e) => return Err(e),
            }
        }

        match self.sink.start_send(item) {
            Ok(AsyncSink::Ready) => self.needs_flush = true,
            Ok(AsyncSink::NotReady(t)) => return Ok(AsyncSink::NotReady(t)),
            Err(e) => return Err(e),
        };

        match self.sink.poll_complete() {
            Ok(Async::Ready(_)) => self.needs_flush = false,
            Ok(Async::NotReady) => {} // Can't flush now; try again next time
            Err(e) => return Err(e),
        };
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.sink.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.sink.close()
    }
}

/// Generate a hexdump of the provided byte slice.
pub fn hexdump(f: &mut fmt::Formatter, prefix: &str, buffer: &[u8]) -> Result<(), fmt::Error> {
    const COLUMNS: usize = 16;
    let mut offset: usize = 0;
    if buffer.len() == 0 {
        // For a zero-length buffer, at least print an offset instead of
        // nothing.
        write!(f, "{}{:04x}: ", prefix, 0)?;
    }
    while offset < buffer.len() {
        write!(f, "{}{:04x}: ", prefix, offset)?;

        // Determine row byte range
        let next_offset = offset + COLUMNS;
        let (row_size, padding) = if next_offset <= buffer.len() {
            (COLUMNS, 0)
        } else {
            (buffer.len() - offset, next_offset - buffer.len())
        };
        let row = &buffer[offset..offset + row_size];

        // Print hex representation
        for b in row {
            write!(f, "{:02x} ", b)?;
        }
        for _ in 0..padding {
            write!(f, "   ")?;
        }

        // Print ASCII representation
        for b in row {
            write!(
                f,
                "{}",
                match *b {
                    c @ 0x20...0x7E => c as char,
                    _ => '.',
                }
            )?;
        }

        offset += COLUMNS;
        if offset < buffer.len() {
            writeln!(f, "")?;
        }
    }
    Ok(())
}

/// A byte slice wrapped in Hex is printable as a hex dump.
#[allow(dead_code)]
pub struct Hex<'a>(pub &'a [u8]);
impl<'a> fmt::Display for Hex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hexdump(f, "", self.0)
    }
}

/// Wrap the provided byte slice in a Hex to allow it to be printable as a hex dump.
pub fn hex(bytes: &[u8]) -> Hex {
    Hex(bytes)
}

/// A Write/AsyncWrite impl that will hexdump all incoming data
#[allow(dead_code)]
pub struct HexWriter {}
impl HexWriter {
    #[allow(dead_code)]
    pub fn new() -> HexWriter {
        HexWriter {}
    }
}

impl Write for HexWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("{}", Hex(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for HexWriter {
    fn shutdown(&mut self) -> Result<Async<()>, tokio::io::Error> {
        Ok(Async::Ready(()))
    }
}
