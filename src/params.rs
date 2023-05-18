use std::net::Ipv4Addr;

/// Represents parameters for creating a new TUN or TAP device.
pub struct Params {
    #[cfg(target_os = "windows")]
    pub name: String,
    #[cfg(target_os = "linux")]
    pub name: Option<String>,
    #[cfg(target_os = "linux")]
    pub flags: i16,
    #[cfg(target_os = "linux")]
    pub persist: bool,
    pub up: bool,
    // TODO
    #[cfg(target_os = "linux")]
    pub mtu: Option<i32>,
    #[cfg(target_os = "linux")]
    pub owner: Option<i32>,
    #[cfg(target_os = "linux")]
    pub group: Option<i32>,
    pub address: Option<Ipv4Addr>,
    #[cfg(target_os = "linux")]
    pub destination: Option<Ipv4Addr>,
    #[cfg(target_os = "linux")]
    pub broadcast: Option<Ipv4Addr>,
    // TODO
    #[cfg(target_os = "linux")]
    pub netmask: Option<Ipv4Addr>,
}
