use crate::linux::consts::WG_GENL_NAME;
use libc::{IFLA_INFO_KIND, IFLA_LINKINFO};
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Arphrd, Iff, IffFlags, Ifla, Rtm},
    },
    err::NlError,
    genl::Nlattr,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifinfomsg, Rtattr},
    types::{Buffer, RtBuffer},
    Nl,
};

const RTATTR_HEADER_LEN: libc::c_ushort = 4;

pub enum WireGuardDeviceLinkOperation {
    Add,
    Delete,
}

fn create_rtattr(rta_type: Ifla, rta_payload: Buffer) -> Rtattr<Ifla, Buffer> {
    let mut rtattr = Rtattr {
        rta_len: 0,
        rta_type,
        rta_payload,
    };
    // neli doesn't provide a nice way to automatically set this for rtattr (it does for nlattr),
    // so we'll do some small math ourselves.
    rtattr.rta_len = rtattr.rta_payload.size() as libc::c_ushort + RTATTR_HEADER_LEN;
    rtattr
}

pub fn link_message(
    ifname: &str,
    link_operation: WireGuardDeviceLinkOperation,
) -> Result<Nlmsghdr<Rtm, Ifinfomsg>, NlError> {
    let ifname = create_rtattr(Ifla::Ifname, Buffer::from(ifname.as_bytes()));

    let link = {
        let rta_type = Ifla::UnrecognizedVariant(IFLA_LINKINFO);
        let rtattr = Nlattr::new(
            None,
            false,
            false,
            IFLA_INFO_KIND,
            WG_GENL_NAME.as_bytes().to_vec(),
        )?;
        create_rtattr(rta_type, rtattr.nla_payload)
    };

    let infomsg = {
        let ifi_family =
            neli::consts::rtnl::RtAddrFamily::UnrecognizedVariant(libc::AF_UNSPEC as u8);
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = IffFlags::empty();
        let mut rtattrs = RtBuffer::new();
        let ifi_change = IffFlags::new(&[Iff::Up]);

        rtattrs.push(ifname);
        rtattrs.push(link);

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
            WireGuardDeviceLinkOperation::Add => {
                NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Create, NlmF::Excl])
            }
            WireGuardDeviceLinkOperation::Delete => NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        };
        let seq = None;
        let pid = None;
        let payload = NlPayload::Payload(infomsg);
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };

    Ok(nlmsg)
}
