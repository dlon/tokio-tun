use std::{io, sync::Arc};

use widestring::{U16CString, u16cstr, U16CStr};
use windows_sys::Win32::{Foundation::{ERROR_NO_MORE_ITEMS, WAIT_FAILED, WAIT_OBJECT_0, WAIT_ABANDONED_0, ERROR_BUFFER_OVERFLOW}, System::{Threading::WaitForSingleObject, WindowsProgramming::INFINITE}};

use crate::{params::Params, result::Result};

use super::wintun::{WintunAdapter, WintunDll, WintunSession};

pub struct TunImpl {
    session: WintunSession,
    name: String,
}

unsafe impl Send for TunImpl {}
unsafe impl Sync for TunImpl {}

impl TunImpl {
    /// Creates a new instance of a Wintun device.
    pub fn new(params: Params) -> Result<Self> {
        // TODO: could be specified in params
        const TUNNEL_TYPE: &U16CStr = u16cstr!("TestTunnelType");

        let dll = WintunDll::instance(&std::env::current_dir().unwrap())
            .expect("FIXME: failed to load wintun.dll");
    
        dll.activate_logging();

        let adapter = WintunAdapter::create(
            dll,
            &U16CString::from_str(&params.name).expect("FIXME: contains nul"),
            TUNNEL_TYPE,
            // TODO: optionally specify GUID
            None,
        )
        .expect("fixme: failed to create interface");

        let adapter = Arc::new(adapter);

        let session = WintunSession::new(
            adapter.clone(),
            // TODO: configurable capacity
            0x400000,
        )
        .expect("fixme: failed to create wintun session");

        Ok(Self {
            session,
            name: params.name,
        })
    }

    /// Receives a packet from the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.session.try_recv(buf) {
                Ok(read) => return Ok(read),
                Err(error) => {
                    if error.raw_os_error() != Some(ERROR_NO_MORE_ITEMS as i32) {
                        return Err(error);
                    }

                    let event = self.session.read_wait_event() as isize;

                    // TODO: stop on shutdown? should be automagically handled
                    // TODO: should we be using something other than a threadpool?

                    let wait_result = tokio::task::spawn_blocking(move || {
                        unsafe {
                            WaitForSingleObject(event, INFINITE)
                        }
                    })
                    .await
                    .unwrap();

                    match wait_result {
                        WAIT_OBJECT_0 => (),
                        WAIT_ABANDONED_0 => return Err(io::Error::new(io::ErrorKind::Other, "read event was abandoned")),
                        WAIT_FAILED => return Err(io::Error::last_os_error()),
                        _ => unreachable!("unexpected wait result"),
                    }
                }
            }
        }
    }

    /// Try to receive a packet from the Tun/Tap interface
    ///
    /// When there is no pending data, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.session.try_recv(buf)
    }

    /// Sends a packet to the Tun/Tap interface
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.session.try_send(buf) {
                Ok(sent) => return Ok(sent),
                Err(error) => {
                    if error.raw_os_error() != Some(ERROR_BUFFER_OVERFLOW as i32) {
                        return Err(error);
                    }

                    // busy loop while the send buffer is full
                    // TODO: find a nicer way than busy looping, perhaps
                }
            }
        }

    }

    /// Try to send a packet to the Tun/Tap interface
    ///
    /// When the socket buffer is full, `Err(io::ErrorKind::WouldBlock)` is returned.
    ///
    /// This method takes &self, so it is possible to call this method concurrently with other methods on this struct.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.session.try_send(buf)
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
