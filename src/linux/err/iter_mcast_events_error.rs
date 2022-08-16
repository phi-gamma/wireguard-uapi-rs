use crate::get::MonitorEventBuilderError;
use crate::linux::err::ParseAttributeError;
use crate::linux::err::ParseDeviceError;
use neli::err::{DeError, NlError};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IterMcastEventsError {
    #[error(transparent)]
    NlError(NlError),

    #[error(transparent)]
    NlDeError(DeError),

    #[error("This is not a multicast socket")]
    McastDisabledError,

    #[error(transparent)]
    ParseAttributeError(ParseAttributeError),

    #[error("Unexpected WireGuard Netlink command {}", cmd)]
    UnexpectedCommandError { cmd: u8 },

    #[error(transparent)]
    IOError(io::Error),

    #[error(transparent)]
    ParseDeviceError(ParseDeviceError),

    #[error(transparent)]
    MonitorEventBuilderError(#[from] MonitorEventBuilderError),
}

impl From<NlError> for IterMcastEventsError {
    fn from(error: NlError) -> Self {
        Self::NlError(error)
    }
}

impl From<std::io::Error> for IterMcastEventsError {
    fn from(error: io::Error) -> Self {
        Self::IOError(error)
    }
}

impl From<DeError> for IterMcastEventsError {
    fn from(error: DeError) -> Self {
        Self::NlDeError(error)
    }
}

impl From<ParseDeviceError> for IterMcastEventsError {
    fn from(error: ParseDeviceError) -> Self {
        Self::ParseDeviceError(error)
    }
}

impl From<ParseAttributeError> for IterMcastEventsError {
    fn from(error: ParseAttributeError) -> Self {
        Self::ParseAttributeError(error)
    }
}
