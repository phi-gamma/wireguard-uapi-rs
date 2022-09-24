use crate::linux::consts::WG_GENL_NAME;
use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Arphrd, Iff, Ifla, IflaInfo, RtAddrFamily, Rtm},
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    rtnl::{Ifinfomsg, IfinfomsgBuilder, RtattrBuilder},
    types::RtBuffer,
};

pub enum WireGuardDeviceLinkOperation {
    Add,
    Delete,
}

pub fn link_message(
    ifname: &str,
    link_operation: WireGuardDeviceLinkOperation,
) -> Result<Nlmsghdr<Rtm, Ifinfomsg>, NlError> {
    let rtattrs = {
        let mut attrs = RtBuffer::new();
        attrs.push(
            RtattrBuilder::default()
                .rta_type(Ifla::Ifname)
                .rta_payload(ifname.as_bytes())
                .build()?,
        );

        let mut genl_name = RtBuffer::new();
        genl_name.push(
            RtattrBuilder::default()
                .rta_type(IflaInfo::Kind)
                .rta_payload(WG_GENL_NAME.as_bytes())
                .build()?,
        );

        let link = RtattrBuilder::default()
            .rta_type(Ifla::Linkinfo)
            .rta_payload(genl_name)
            .build()?;

        attrs.push(link);
        attrs
    };
    let infomsg = {
        IfinfomsgBuilder::default()
            .ifi_family(RtAddrFamily::Unspecified)
            // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
            // embedded C library does.
            .ifi_type(Arphrd::Netrom)
            .ifi_index(0)
            .ifi_flags(Iff::empty())
            .ifi_change(Iff::UP)
            .rtattrs(rtattrs)
            .build()?
    };

    let nlmsg = {
        let nl_type = match link_operation {
            WireGuardDeviceLinkOperation::Add => Rtm::Newlink,
            WireGuardDeviceLinkOperation::Delete => Rtm::Dellink,
        };
        let flags = match link_operation {
            WireGuardDeviceLinkOperation::Add => {
                NlmF::REQUEST | NlmF::ACK | NlmF::CREATE | NlmF::EXCL
            }
            WireGuardDeviceLinkOperation::Delete => NlmF::REQUEST | NlmF::ACK,
        };
        let payload = NlPayload::Payload(infomsg);
        NlmsghdrBuilder::default()
            .nl_type(nl_type)
            .nl_flags(flags)
            .nl_payload(payload)
            .build()?
    };

    Ok(nlmsg)
}
