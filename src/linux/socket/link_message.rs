use crate::linux::consts::WG_GENL_NAME;
use neli::consts::{
    nl::NlmF,
    rtnl::{Arphrd, Ifla, IflaInfo, Rtm},
};
use neli::err::SerError;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::rtnl::Ifinfomsg;
use neli::rtnl::Rtattr;
use neli::types::RtBuffer;

pub enum WireGuardDeviceLinkOperation {
    Add,
    Delete,
}

pub fn link_message(
    ifname: &str,
    link_operation: WireGuardDeviceLinkOperation,
) -> Result<Nlmsghdr<Rtm, Ifinfomsg>, SerError> {
    let rtattrs = {
        let mut attrs = RtBuffer::new();
        attrs.push(Rtattr::new(None, Ifla::Ifname, ifname.as_bytes())?);

        let mut genl_name = RtBuffer::new();
        genl_name.push(Rtattr::new(None, IflaInfo::Kind, WG_GENL_NAME.as_bytes())?);

        let link = Rtattr::new(None, Ifla::Linkinfo, genl_name)?;

        attrs.push(link);
        attrs
    };

    let infomsg = {
        let ifi_family = neli::consts::rtnl::RtAddrFamily::Unspecified;
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = neli::consts::rtnl::IffFlags::empty();
        let ifi_change = neli::consts::rtnl::IffFlags::empty();
        Ifinfomsg::new(
            ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change, rtattrs,
        )
    };

    let nlmsg = {
        let len = None;
        let nl_type = match link_operation {
            WireGuardDeviceLinkOperation::Add => Rtm::Newlink,
            WireGuardDeviceLinkOperation::Delete => Rtm::Dellink,
        };
        let flags = match link_operation {
            WireGuardDeviceLinkOperation::Add => neli::consts::nl::NlmFFlags::new(&[
                NlmF::Request,
                NlmF::Ack,
                NlmF::Create,
                NlmF::Excl,
            ]),
            WireGuardDeviceLinkOperation::Delete => {
                neli::consts::nl::NlmFFlags::new(&[NlmF::Request, NlmF::Ack])
            }
        };
        let seq = None;
        let pid = None;
        let payload = NlPayload::Payload(infomsg);
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };

    Ok(nlmsg)
}
