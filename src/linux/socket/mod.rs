mod route_socket;
pub use route_socket::RouteSocket;

mod wg_socket;
pub use wg_socket::{WgMcastEventIterator, WgSocket};

pub(crate) mod parse;

pub(crate) type NlWgMsgType = u16;
pub(crate) type NlMcastMsgType = u32;

pub(crate) mod link_message;
pub(crate) use link_message::{link_message, WireGuardDeviceLinkOperation};

pub(crate) mod list_device_names_utils;
