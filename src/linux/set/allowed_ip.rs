use crate::linux::attr::NLA_F_NESTED;
use crate::linux::attr::{NlaNested, WgAllowedIpAttribute};
use neli::err::NlError;
use neli::genl::{AttrTypeBuilder, Nlattr, NlattrBuilder};
use neli::types::Buffer;
use std::convert::TryFrom;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AllowedIp<'a> {
    pub ipaddr: &'a IpAddr,
    pub cidr_mask: Option<u8>,
}

impl<'a> AllowedIp<'a> {
    pub fn from_ipaddr(ipaddr: &'a IpAddr) -> Self {
        Self {
            ipaddr,
            cidr_mask: None,
        }
    }
}

impl<'a> TryFrom<&AllowedIp<'a>> for Nlattr<NlaNested, Buffer> {
    type Error = NlError;

    fn try_from(allowed_ip: &AllowedIp) -> Result<Self, Self::Error> {
        let family = match allowed_ip.ipaddr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        };
        let ipaddr = match allowed_ip.ipaddr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        let cidr_mask = allowed_ip.cidr_mask.unwrap_or(match allowed_ip.ipaddr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });

        let nested = NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_type(NlaNested::Unspec | NLA_F_NESTED)
                    .build()?,
            )
            .nla_payload(Vec::<u8>::new())
            .build()?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(WgAllowedIpAttribute::Family)
                            .build()?,
                    )
                    .nla_payload(&family.to_ne_bytes()[..])
                    .build()?,
            )?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(WgAllowedIpAttribute::IpAddr)
                            .build()?,
                    )
                    .nla_payload(ipaddr)
                    .build()?,
            )?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(WgAllowedIpAttribute::CidrMask)
                            .build()?,
                    )
                    .nla_payload(&cidr_mask.to_ne_bytes()[..])
                    .build()?,
            )?;

        Ok(nested)
    }
}
