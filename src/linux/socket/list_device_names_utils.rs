use crate::err::ListDevicesError;
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags, Nlmsg},
        rtnl::{Arphrd, Iff, IffFlags, Ifla, IflaInfo, Rtm},
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::Ifinfomsg,
    types::RtBuffer,
};
use std::convert::TryFrom;

pub fn get_list_device_names_msg() -> Nlmsghdr<Rtm, Ifinfomsg> {
    let infomsg = {
        let ifi_family = neli::consts::rtnl::RtAddrFamily::Unspecified;
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

impl TryFrom<Nlmsghdr<Nlmsg, Ifinfomsg>> for PotentialWireGuardDeviceName {
    type Error = ListDevicesError;

    fn try_from(response: Nlmsghdr<Nlmsg, Ifinfomsg>) -> Result<Self, Self::Error> {
        let mut is_wireguard = false;
        let payload = response
            .nl_payload
            .get_payload()
            .ok_or(ListDevicesError::Unknown)?;
        let mut handle = payload.rtattrs.get_attr_handle();
        let ifname = handle
            .get_attr_payload_as_with_len::<String>(Ifla::Ifname)
            .ok();
        if let Ok(linkinfo) = handle.get_nested_attributes(Ifla::Linkinfo) {
            let linktype = linkinfo.get_attr_payload_as_with_len::<String>(IflaInfo::Kind)?;
            is_wireguard = linktype == crate::linux::consts::WG_GENL_NAME;
        }

        Ok(PotentialWireGuardDeviceName {
            ifname,
            is_wireguard,
        })
    }
}
