use std::{io, sync::Arc};

use widestring::{U16CString, u16cstr, U16CStr};

use crate::{params::Params, result::Result};

use super::wintun::{WintunAdapter, WintunDll};

pub struct TunImpl {
    adapter: Arc<WintunAdapter>,
    // FIXME
    name: String,
}

impl TunImpl {
    /// Creates a new instance of a Wintun device.
    pub fn new(params: Params) -> Result<Self> {
        // TODO: could be specified in params
        const TUNNEL_TYPE: &U16CStr = u16cstr!("TestTunnelType");

        let adapter = WintunAdapter::create(
            WintunDll::instance(&std::env::current_dir().unwrap())
                .expect("FIXME: failed to load wintun.dll"),
            &U16CString::from_str(&params.name).expect("FIXME: contains nul"),
            TUNNEL_TYPE,
            // TODO: optionally specify GUID
            None,
        )
        .expect("fixme: failed to create interface");

        Ok(Self {
            adapter: Arc::new(adapter),
            name: params.name,
        })
    }

    /// Receives a packet from the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: try_recv but wait for event if nothing is instantly avail
        Ok(0)
    }

    /// Sends a packet to the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // TODO
        // TODO: this busyloops if the write buffer is full,
        // but that should be a rare occurence
        Ok(0)
    }

    /// Try to receive a packet from the Tun/Tap interface
    ///
    /// When there is no pending data, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: same as recv but just fail if there is nothing to read yet

        Ok(0)
    }

    /// Try to send a packet to the Tun/Tap interface
    ///
    /// When the socket buffer is full, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        // TODO: send but just fail if the buf is full

        Ok(0)
    }

    pub fn name(&self) -> &str {
        // TODO
        //self.adapter.name().to_string()
        &self.name
    }

    // TODO: name
    // TODO: MTU
    // TODO: IP address
    // TODO: netmask
}
