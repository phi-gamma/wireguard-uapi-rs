use super::parse::parse_nla_nul_string;
use crate::err::ListDevicesError;
use neli::{
    consts::{
        nl::{NlTypeWrapper, NlmF, NlmFFlags},
        rtnl::{Arphrd, Iff, IffFlags, Ifla, Rtm},
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifinfomsg, Rtattr},
    types::RtBuffer,
    Nl,
};
use std::convert::TryFrom;

pub fn get_list_device_names_msg() -> Nlmsghdr<Rtm, Ifinfomsg> {
    let infomsg = {
        let ifi_family =
            neli::consts::rtnl::RtAddrFamily::UnrecognizedVariant(libc::AF_UNSPEC as u8);
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = IffFlags::empty();
        let rtattrs = RtBuffer::new();
        let ifi_change = IffFlags::new(&[Iff::Up]);

        Ifinfomsg::new(
            ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change, rtattrs,
        )
    };

    let len = None;
    let nl_type = Rtm::Getlink;
    let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Dump]);
    let seq = None;
    let pid = None;
    let payload = infomsg;
    Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
}

pub struct PotentialWireGuardDeviceName {
    pub ifname: Option<String>,
    pub is_wireguard: bool,
}

impl TryFrom<Nlmsghdr<NlTypeWrapper, Ifinfomsg>> for PotentialWireGuardDeviceName {
    type Error = ListDevicesError;

    fn try_from(response: Nlmsghdr<NlTypeWrapper, Ifinfomsg>) -> Result<Self, Self::Error> {
        let mut is_wireguard = false;
        let mut ifname: Option<String> = None;

        for attr in response.get_payload()?.rtattrs.iter() {
            match attr.rta_type {
                Ifla::UnrecognizedVariant(libc::IFLA_LINKINFO) => {
                    let buf = attr.rta_payload.as_ref();
                    let linkinfo =
                        Rtattr::<u16, Vec<u8>>::deserialize(buf).map_err(NlError::new)?;

                    if linkinfo.rta_type == libc::IFLA_INFO_KIND {
                        let info_kind = parse_nla_nul_string(&linkinfo.rta_payload)?;
                        if info_kind == crate::linux::consts::WG_GENL_NAME {
                            is_wireguard = true;
                        }
                    }
                }
                Ifla::Ifname => {
                    ifname = Some(parse_nla_nul_string(attr.rta_payload.as_ref())?);
                }
                _ => {}
            };
        }

        Ok(PotentialWireGuardDeviceName {
            ifname,
            is_wireguard,
        })
    }
}
