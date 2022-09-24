use crate::err::ListDevicesError;
use neli::{
    consts::{
        nl::{NlmF, Nlmsg},
        rtnl::{Arphrd, Iff, Ifla, IflaInfo, Rtm},
    },
    err::BuilderError,
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    rtnl::{Ifinfomsg, IfinfomsgBuilder},
    types::RtBuffer,
};
use std::convert::TryFrom;

pub fn get_list_device_names_msg() -> Result<Nlmsghdr<Rtm, Ifinfomsg>, BuilderError> {
    let infomsg = {
        IfinfomsgBuilder::default()
            .ifi_family(neli::consts::rtnl::RtAddrFamily::Unspecified)
            // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
            // embedded C library does.
            .ifi_type(Arphrd::Netrom)
            .ifi_index(0)
            .ifi_flags(Iff::empty())
            .rtattrs(RtBuffer::new())
            .ifi_change(Iff::UP)
            .build()
            .map_err(BuilderError::from)?
    };

    NlmsghdrBuilder::default()
        .nl_type(Rtm::Getlink)
        .nl_flags(NlmF::REQUEST | NlmF::ACK | NlmF::DUMP)
        .nl_payload(NlPayload::Payload(infomsg))
        .build()
        .map_err(BuilderError::from)
}

pub struct PotentialWireGuardDeviceName {
    pub ifname: Option<String>,
    pub is_wireguard: bool,
}

impl TryFrom<Nlmsghdr<Nlmsg, Ifinfomsg>> for PotentialWireGuardDeviceName {
    type Error = ListDevicesError;

    fn try_from(response: Nlmsghdr<Nlmsg, Ifinfomsg>) -> Result<Self, Self::Error> {
        let payload = response.get_payload().ok_or(ListDevicesError::Unknown)?;
        let mut handle = payload.rtattrs().get_attr_handle();

        Ok(PotentialWireGuardDeviceName {
            ifname: handle
                .get_attr_payload_as_with_len::<String>(Ifla::Ifname)
                .ok(),
            is_wireguard: handle
                .get_nested_attributes(Ifla::Linkinfo)
                .map_or(false, |linkinfo| {
                    linkinfo
                        .get_attr_payload_as_with_len::<String>(IflaInfo::Kind)
                        .map_or(false, |info_kind| {
                            info_kind == crate::linux::consts::WG_GENL_NAME
                        })
                }),
        })
    }
}
