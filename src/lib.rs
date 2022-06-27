#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{err, set, DeviceInterface, RouteSocket, WgMcastEventIterator, WgSocket};

pub mod get;

#[cfg(feature = "xplatform")]
pub mod xplatform;
