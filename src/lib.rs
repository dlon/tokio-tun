#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod platform;

#[cfg(target_os = "windows")]
#[path = "windows/mod.rs"]
mod platform;

mod params;
mod builder;
mod tun;

pub mod result;

pub use self::builder::TunBuilder;
pub use self::tun::Tun;
