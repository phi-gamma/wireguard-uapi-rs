use crate::linux::attr::WgDeviceAttribute;
use neli::err::SerError;
use neli::genl::Nlattr;
use neli::types::Buffer;
use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceInterface<'a> {
    Index(u32),
    Name(Cow<'a, str>),
}

impl<'a> DeviceInterface<'a> {
    pub fn from_index(index: u32) -> Self {
        DeviceInterface::Index(index)
    }

    pub fn from_name<T: Into<Cow<'a, str>>>(name: T) -> Self {
        DeviceInterface::Name(name.into())
    }
}

impl<'a> TryFrom<&DeviceInterface<'a>> for Nlattr<WgDeviceAttribute, Buffer> {
    type Error = SerError;

    fn try_from(interface: &DeviceInterface) -> Result<Self, Self::Error> {
        let attr = match interface {
            &DeviceInterface::Index(ifindex) => {
                Nlattr::new(false, false, WgDeviceAttribute::Ifindex, ifindex)?
            }
            DeviceInterface::Name(ifname) => {
                Nlattr::new(false, false, WgDeviceAttribute::Ifname, ifname.as_ref())?
            }
        };
        Ok(attr)
    }
}
