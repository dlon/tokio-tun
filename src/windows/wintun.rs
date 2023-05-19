use std::{
    ffi::CStr,
    fmt, io, mem,
    os::windows::io::RawHandle,
    path::Path,
    ptr,
    sync::{Arc, Mutex},
};
use lazy_static::lazy_static;
use widestring::{U16CStr, U16CString};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{HINSTANCE, NO_ERROR},
        NetworkManagement::{IpHelper::ConvertInterfaceLuidToGuid, Ndis::NET_LUID_LH},
        System::{
            LibraryLoader::{
                FreeLibrary, GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
            },
        },
    },
};

lazy_static! {
    /// Shared `WintunDll` instance
    static ref WINTUN_DLL: Mutex<Option<Arc<WintunDll>>> = Mutex::new(None);
}

type WintunCreateAdapterFn = unsafe extern "stdcall" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const GUID,
) -> RawHandle;
type WintunCloseAdapterFn = unsafe extern "stdcall" fn(adapter: RawHandle);
type WintunGetAdapterLuidFn =
    unsafe extern "stdcall" fn(adapter: RawHandle, luid: *mut NET_LUID_LH);

type SessionHandle = RawHandle;

type WintunStartSessionFn = unsafe extern "stdcall" fn(RawHandle, u32) -> SessionHandle;
type WintunEndSessionFn = unsafe extern "stdcall" fn(SessionHandle);
type WintunGetReadWaitEventFn = unsafe extern "stdcall" fn(SessionHandle) -> RawHandle;
type WintunReceivePacketFn = unsafe extern "stdcall" fn(SessionHandle, *mut u32) -> *mut u8;
type WintunReleaseReceivePacketFn = unsafe extern "stdcall" fn(SessionHandle, *const u8);
type WintunAllocateSendPacketFn = unsafe extern "stdcall" fn(SessionHandle, u32) -> *mut u8;
type WintunSendPacket = unsafe extern "stdcall" fn(SessionHandle, *const u8);

type WintunLoggerCbFn = extern "stdcall" fn(WintunLoggerLevel, u64, *const u16);
type WintunSetLoggerFn = unsafe extern "stdcall" fn(Option<WintunLoggerCbFn>);

#[repr(C)]
#[allow(dead_code)]
enum WintunLoggerLevel {
    Info,
    Warn,
    Err,
}

pub struct WintunDll {
    handle: HINSTANCE,
    func_create: WintunCreateAdapterFn,
    func_close: WintunCloseAdapterFn,

    func_get_adapter_luid: WintunGetAdapterLuidFn,

    func_start_session: WintunStartSessionFn,
    func_end_session: WintunEndSessionFn,
    func_get_read_wait_event: WintunGetReadWaitEventFn,
    func_receive_packet: WintunReceivePacketFn,
    func_release_receive_packet: WintunReleaseReceivePacketFn,
    func_allocate_send_packet: WintunAllocateSendPacketFn,
    func_send_packet: WintunSendPacket,

    func_set_logger: WintunSetLoggerFn,
}

unsafe impl Send for WintunDll {}
unsafe impl Sync for WintunDll {}

/// Represents a Wintun adapter.
pub struct WintunAdapter {
    dll_handle: Arc<WintunDll>,
    handle: RawHandle,
    name: U16CString,
}

impl fmt::Debug for WintunAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunAdapter")
            .field("handle", &self.handle)
            .finish()
    }
}

unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

impl WintunAdapter {
    pub fn create(
        dll_handle: Arc<WintunDll>,
        name: &U16CStr,
        tunnel_type: &U16CStr,
        requested_guid: Option<GUID>,
    ) -> io::Result<Self> {
        let handle = dll_handle.create_adapter(name, tunnel_type, requested_guid)?;
        let adapter = Self {
            dll_handle,
            handle,
            name: name.to_owned(),
        };
        Ok(adapter)
    }

    pub fn name(&self) -> &U16CStr {
        &self.name
    }

    pub fn luid(&self) -> NET_LUID_LH {
        unsafe { self.dll_handle.get_adapter_luid(self.handle) }
    }

    pub fn guid(&self) -> io::Result<GUID> {
        let mut guid = mem::MaybeUninit::zeroed();
        let result = unsafe { ConvertInterfaceLuidToGuid(&self.luid(), guid.as_mut_ptr()) };
        if result != NO_ERROR as i32 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(unsafe { guid.assume_init() })
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        unsafe { self.dll_handle.close_adapter(self.handle) };
    }
}

impl WintunDll {
    pub fn instance(resource_dir: &Path) -> io::Result<Arc<Self>> {
        let mut dll = (*WINTUN_DLL).lock().expect("Wintun mutex poisoned");
        match &*dll {
            Some(dll) => Ok(dll.clone()),
            None => {
                let new_dll = Arc::new(Self::new(resource_dir)?);
                *dll = Some(new_dll.clone());
                Ok(new_dll)
            }
        }
    }

    fn new(resource_dir: &Path) -> io::Result<Self> {
        let wintun_dll = U16CString::from_os_str_truncate(resource_dir.join("wintun.dll"));

        let handle =
            unsafe { LoadLibraryExW(wintun_dll.as_ptr(), 0, LOAD_WITH_ALTERED_SEARCH_PATH) };
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }
        Self::new_inner(handle, Self::get_proc_address)
    }

    fn new_inner(
        handle: HINSTANCE,
        get_proc_fn: unsafe fn(
            HINSTANCE,
            &CStr,
        ) -> io::Result<unsafe extern "system" fn() -> isize>,
    ) -> io::Result<Self> {
        Ok(WintunDll {
            handle,
            func_create: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunCreateAdapter\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_close: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunCloseAdapter\0").unwrap(),
                )?) as *const _ as *const _)
            },

            func_start_session: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunStartSession\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_end_session: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunEndSession\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_get_read_wait_event: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunGetReadWaitEvent\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_receive_packet: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunReceivePacket\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_release_receive_packet: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunReleaseReceivePacket\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_allocate_send_packet: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunAllocateSendPacket\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_send_packet: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunSendPacket\0").unwrap(),
                )?) as *const _ as *const _)
            },

            func_set_logger: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunSetLogger\0").unwrap(),
                )?) as *const _ as *const _)
            },
            func_get_adapter_luid: unsafe {
                *((&get_proc_fn(
                    handle,
                    CStr::from_bytes_with_nul(b"WintunGetAdapterLUID\0").unwrap(),
                )?) as *const _ as *const _)
            },
        })
    }

    unsafe fn get_proc_address(
        handle: HINSTANCE,
        name: &CStr,
    ) -> io::Result<unsafe extern "system" fn() -> isize> {
        let handle = GetProcAddress(handle, name.as_ptr() as *const u8);
        handle.ok_or(io::Error::last_os_error())
    }

    pub fn create_adapter(
        &self,
        name: &U16CStr,
        tunnel_type: &U16CStr,
        requested_guid: Option<GUID>,
    ) -> io::Result<RawHandle> {
        let guid_ptr = match requested_guid.as_ref() {
            Some(guid) => guid as *const _,
            None => ptr::null_mut(),
        };
        let handle = unsafe { (self.func_create)(name.as_ptr(), tunnel_type.as_ptr(), guid_ptr) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }

    pub unsafe fn close_adapter(&self, adapter: RawHandle) {
        (self.func_close)(adapter);
    }

    pub unsafe fn get_adapter_luid(&self, adapter: RawHandle) -> NET_LUID_LH {
        let mut luid = mem::MaybeUninit::<NET_LUID_LH>::zeroed();
        (self.func_get_adapter_luid)(adapter, luid.as_mut_ptr());
        luid.assume_init()
    }

    unsafe fn start_session(&self, adapter: RawHandle, capacity: u32) -> io::Result<SessionHandle> {
        let session = (self.func_start_session)(adapter, capacity);
        if session.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(session)
    }

    unsafe fn end_session(&self, session: SessionHandle) {
        (self.func_end_session)(session)
    }

    unsafe fn read_wait_event(&self, session: SessionHandle) -> RawHandle {
        (self.func_get_read_wait_event)(session)
    }

    unsafe fn receive_packet(&self, session: SessionHandle) -> io::Result<(*mut u8, u32)> {
        let mut bytes_read = 0u32;
        let read_bytes = (self.func_receive_packet)(session, &mut bytes_read);
        if read_bytes.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok((read_bytes, bytes_read))
    }

    unsafe fn release_receive_packet(&self, session: SessionHandle, packet: *mut u8) {
        (self.func_release_receive_packet)(session, packet);
    }

    unsafe fn allocate_send_packet(&self, session: SessionHandle, packet_size: u32) -> io::Result<*mut u8> {
        let packet = (self.func_allocate_send_packet)(session, packet_size);
        if packet.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(packet)
    }

    unsafe fn send_packet(&self, session: SessionHandle, packet: *mut u8) {
        (self.func_send_packet)(session, packet);
    }

    pub fn activate_logging(self: &Arc<Self>) -> WintunLoggerHandle {
        WintunLoggerHandle::from_handle(self.clone())
    }

    fn set_logger(&self, logger: Option<WintunLoggerCbFn>) {
        unsafe { (self.func_set_logger)(logger) };
    }
}

impl Drop for WintunDll {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.handle) };
    }
}

pub struct WintunSession {
    adapter: Arc<WintunAdapter>,
    handle: SessionHandle,
}

impl WintunSession {
    pub fn new(
        adapter: Arc<WintunAdapter>,
        capacity: u32,
    ) -> io::Result<Self> {
        Ok(Self {
            handle: unsafe {
                adapter.dll_handle.start_session(
                    adapter.handle,
                    capacity,
                )?
            },
            adapter,
        })
    }

    pub fn read_wait_event(&self) -> RawHandle {
        unsafe { self.adapter.dll_handle.read_wait_event(self.handle) }
    }

    /// Receive a packet, if there's anything to receive
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (pkt, size) = unsafe { self.adapter.dll_handle.receive_packet(self.handle) }?;

        let size = usize::try_from(size).unwrap();
        unsafe { pkt.copy_to_nonoverlapping(buf.as_mut_ptr(), size) };

        unsafe { self.adapter.dll_handle.release_receive_packet(self.handle, pkt) };

        Ok(size)
    }

    /// Send a packet, unless the buffer is full
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        // TODO: refuse buf.len() > WINTUN_MAX_IP_PACKET_SIZE
        // TODO: handle size limits more nicely

        let size = u32::try_from(buf.len()).unwrap();

        let pkt = unsafe { self.adapter.dll_handle.allocate_send_packet(self.handle, size) }?;

        unsafe { pkt.copy_from_nonoverlapping(buf.as_ptr(), buf.len()) };

        unsafe { self.adapter.dll_handle.send_packet(self.handle, pkt) };

        Ok(buf.len())
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        unsafe { self.adapter.dll_handle.end_session(self.handle) }
    }
}

pub struct WintunLoggerHandle {
    dll_handle: Arc<WintunDll>,
}

impl WintunLoggerHandle {
    fn from_handle(dll_handle: Arc<WintunDll>) -> Self {
        dll_handle.set_logger(Some(Self::callback));
        Self { dll_handle }
    }

    extern "stdcall" fn callback(level: WintunLoggerLevel, _timestamp: u64, message: *const u16) {
        if message.is_null() {
            return;
        }
        let message = unsafe { U16CStr::from_ptr_str(message) };

        use WintunLoggerLevel::*;

        match level {
            Info => println!("[Wintun][info] {}", message.to_string_lossy()),
            Warn => println!("[Wintun][warn] {}", message.to_string_lossy()),
            Err => println!("[Wintun][err] {}", message.to_string_lossy()),
        }
    }
}

impl fmt::Debug for WintunLoggerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunLogger").finish()
    }
}

impl Drop for WintunLoggerHandle {
    fn drop(&mut self) {
        self.dll_handle.set_logger(None);
    }
}
