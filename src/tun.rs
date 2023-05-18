use crate::params::Params;
use crate::result::Result;
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{self, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

/// Represents a TUN or TAP device. Use [`TunBuilder`](struct.TunBuilder.html) to create a new instance of [`Tun`](struct.Tun.html).
pub struct Tun {
    tun: crate::platform::tun::TunImpl,
}

#[cfg(target_os = "linux")]
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

// FIXME: implement for wintun
#[cfg(target_os = "linux")]
impl AsyncRead for Tun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        Pin::new(&mut self.tun).poll_read(cx, buf)
    }
}

// FIXME: implement for wintun
#[cfg(target_os = "linux")]
impl AsyncWrite for Tun {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        Pin::new(&mut self.tun).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> task::Poll<io::Result<()>> {
        Pin::new(&mut self.tun).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> task::Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Tun {
    /// Creates a new instance of Tun/Tap device.
    pub(crate) fn new(params: Params) -> Result<Self> {
        crate::platform::tun::TunImpl::new(params).map(|tun| Self { tun })
    }

    /// Creates a new instance of Tun/Tap device.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_mq(params: Params, queues: usize) -> Result<Vec<Self>> {
        let tuns = crate::platform::tun::TunImpl::new_mq(params, queues)?;
        Ok(tuns.into_iter().map(|tun| Self { tun }).collect())
    }

    /// Receives a packet from the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf).await
    }

    /// Sends a packet to the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf).await
    }

    /// Try to receive a packet from the Tun/Tap interface
    ///
    /// When there is no pending data, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.try_recv(buf)
    }

    /// Try to send a packet to the Tun/Tap interface
    ///
    /// When the socket buffer is full, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.try_send(buf)
    }

    /// Returns the name of Tun/Tap device.
    pub fn name(&self) -> &str {
        self.tun.name()
    }

    /// Returns the value of MTU.
    #[cfg(target_os = "linux")]
    pub fn mtu(&self) -> Result<i32> {
        self.tun.mtu()
    }

    /// Returns the IPv4 address of MTU.
    #[cfg(target_os = "linux")]
    pub fn address(&self) -> Result<Ipv4Addr> {
        self.tun.address()
    }

    /// Returns the IPv4 destination address of MTU.
    #[cfg(target_os = "linux")]
    pub fn destination(&self) -> Result<Ipv4Addr> {
        self.tun.destination()
    }

    /// Returns the IPv4 broadcast address of MTU.
    #[cfg(target_os = "linux")]
    pub fn broadcast(&self) -> Result<Ipv4Addr> {
        self.tun.broadcast()
    }

    /// Returns the IPv4 netmask address of MTU.
    #[cfg(target_os = "linux")]
    pub fn netmask(&self) -> Result<Ipv4Addr> {
        self.tun.netmask()
    }

    /// Returns the flags of MTU.
    #[cfg(target_os = "linux")]
    pub fn flags(&self) -> Result<i16> {
        self.tun.flags()
    }
}
