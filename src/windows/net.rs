use std::{mem, io, net::{IpAddr, SocketAddr}};
use socket2::SockAddr;
use windows_sys::Win32::{Foundation::NO_ERROR, NetworkManagement::{Ndis::NET_LUID_LH, IpHelper::{InitializeUnicastIpAddressEntry, CreateUnicastIpAddressEntry}}, Networking::WinSock::{IpDadStatePreferred, SOCKADDR_INET}};

/// Adds a unicast IP address for the given interface.
pub fn add_ip_address_for_interface(luid: NET_LUID_LH, address: IpAddr) -> io::Result<()> {
    let mut row = unsafe { mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };

    row.InterfaceLuid = luid;
    row.Address = inet_sockaddr_from_socketaddr(SocketAddr::new(address, 0));
    row.DadState = IpDadStatePreferred;
    row.OnLinkPrefixLength = 255;

    let status = unsafe { CreateUnicastIpAddressEntry(&row) };
    if status != NO_ERROR as i32 {
        return Err(io::Error::from_raw_os_error(
            status,
        ));
    }
    Ok(())
}

/// Converts a `SocketAddr` to `SOCKADDR_INET`
pub fn inet_sockaddr_from_socketaddr(addr: SocketAddr) -> SOCKADDR_INET {
    let mut sockaddr: SOCKADDR_INET = unsafe { mem::zeroed() };
    match addr {
        // SAFETY: `*const sockaddr` may be treated as `*const sockaddr_in` since we know it's a v4
        // address.
        SocketAddr::V4(_) => unsafe {
            sockaddr.Ipv4 = *(SockAddr::from(addr).as_ptr() as *const _)
        },
        // SAFETY: `*const sockaddr` may be treated as `*const sockaddr_in6` since we know it's a v6
        // address.
        SocketAddr::V6(_) => unsafe {
            sockaddr.Ipv6 = *(SockAddr::from(addr).as_ptr() as *const _)
        },
    }
    sockaddr
}
