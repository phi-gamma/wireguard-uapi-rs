use crate::linux::attr::WgDeviceAttribute;
use neli::{
    err::NlError,
    genl::{AttrTypeBuilder, Nlattr, NlattrBuilder},
    types::Buffer,
};
use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq)]
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
    type Error = NlError;

    fn try_from(interface: &DeviceInterface) -> Result<Self, Self::Error> {
        let attr = match interface {
            &DeviceInterface::Index(ifindex) => NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(WgDeviceAttribute::Ifindex)
                        .build()?,
                )
                .nla_payload(ifindex)
                .build()?,
            DeviceInterface::Name(ifname) => NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(WgDeviceAttribute::Ifname)
                        .build()?,
                )
                .nla_payload(ifname.as_ref())
                .build()?,
        };
        Ok(attr)
    }
}
