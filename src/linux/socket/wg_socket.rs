use crate::get;
use crate::linux::attr::WgDeviceAttribute;
use crate::linux::cmd::WgCmd;
use crate::linux::consts::NLA_NETWORK_ORDER;
use crate::linux::consts::{WG_GENL_NAME, WG_GENL_VERSION, WG_MULTICAST_GROUP_PEERS};
use crate::linux::err::{ConnectError, GetDeviceError, IterMcastEventsError, SetDeviceError};
use crate::linux::set;
use crate::linux::set::create_set_device_messages;
use crate::linux::socket::parse::*;
use crate::linux::socket::{NlMcastMsgType, NlWgMsgType};
use crate::linux::DeviceInterface;
use libc::IFNAMSIZ;
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags, Nlmsg},
        socket::NlFamily,
    },
    err::NlError,
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::GenlBuffer,
};
use std::convert::TryFrom;

pub struct WgSocket {
    sock: NlSocketHandle,
    family_id: NlWgMsgType,
    mcast_id: Option<NlMcastMsgType>,
}

impl WgSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let family_id = {
            NlSocketHandle::new(NlFamily::Generic)?
                .resolve_genl_family(WG_GENL_NAME)
                .map_err(ConnectError::ResolveFamilyError)?
        };

        // Autoselect a PID
        let pid = None;
        let groups = &[];
        let wgsock = NlSocketHandle::connect(NlFamily::Generic, pid, groups)?;

        Ok(Self {
            sock: wgsock,
            family_id,
            mcast_id: None,
        })
    }

    pub fn connect_mcast() -> Result<Self, ConnectError> {
        let family_id = {
            NlSocketHandle::new(NlFamily::Generic)?
                .resolve_genl_family(WG_GENL_NAME)
                .map_err(ConnectError::ResolveFamilyError)?
        };

        let mcast_id = {
            Some(
                NlSocketHandle::new(NlFamily::Generic)?
                    .resolve_nl_mcast_group(WG_GENL_NAME, WG_MULTICAST_GROUP_PEERS)
                    .map_err(ConnectError::ResolveMcastGroupError)?,
            )
        };

        // Autoselect a PID
        let pid = None;
        let groups = &[];
        let wgsock = NlSocketHandle::connect(NlFamily::Generic, pid, groups)?;

        Ok(Self {
            sock: wgsock,
            family_id,
            mcast_id,
        })
    }

    pub fn iter_mcast_events(self) -> Result<WgMcastEventIterator, IterMcastEventsError> {
        let Self {
            sock,
            family_id,
            mcast_id,
        } = self;

        let mcast_id = if let Some(id) = mcast_id {
            id
        } else {
            return Err(IterMcastEventsError::McastDisabledError);
        };

        sock.add_mcast_membership(&[mcast_id])?;

        Ok(WgMcastEventIterator::new(sock, family_id, mcast_id))
    }

    pub fn get_device(
        &mut self,
        interface: DeviceInterface,
    ) -> Result<get::Device, GetDeviceError> {
        let attr = match interface {
            DeviceInterface::Name(name) => {
                Some(name.len())
                    .filter(|&len| 0 < len && len < IFNAMSIZ)
                    .ok_or(GetDeviceError::InvalidInterfaceName)?;
                Nlattr::new(
                    false,
                    NLA_NETWORK_ORDER,
                    WgDeviceAttribute::Ifname,
                    name.as_ref(),
                )?
            }
            DeviceInterface::Index(index) => {
                Nlattr::new(false, NLA_NETWORK_ORDER, WgDeviceAttribute::Ifindex, index)?
            }
        };
        let genlhdr = {
            let cmd = WgCmd::GetDevice;
            let version = WG_GENL_VERSION;
            let mut attrs = GenlBuffer::new();

            attrs.push(attr);
            Genlmsghdr::new(cmd, version, attrs)
        };
        let nlhdr = {
            let size = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(genlhdr);
            Nlmsghdr::new(size, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr)?;

        let mut iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>(false);

        let mut device = None;
        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                Nlmsg::Error => return Err(GetDeviceError::AccessError),
                Nlmsg::Done => break,
                _ => (),
            };

            let handle = response.get_payload()?.get_attr_handle();
            device = Some(match device {
                Some(device) => extend_device(device, handle)?,
                None => get::Device::try_from(handle)?,
            });
        }

        device.ok_or(GetDeviceError::AccessError)
    }

    /// This assumes that the device interface has already been created. Otherwise an error will
    /// be returned. You can create a new device interface with
    /// [`RouteSocket::add_device`](./struct.RouteSocket.html#add_device.v).
    ///
    /// The peers in this device won't be reachable at their allowed IPs until they're added to the
    /// newly created device interface through a Netlink Route message. This library doesn't have
    /// built-in way to do that right now. Here's how it would be done with the `ip` command:
    ///
    ///
    /// ```sh
    ///  sudo ip -4 route add 127.3.1.1/32 dev wgtest0
    /// ```
    pub fn set_device(&mut self, device: set::Device) -> Result<(), SetDeviceError> {
        for nl_message in create_set_device_messages(device, self.family_id)? {
            self.sock.send(nl_message)?;
            self.sock.recv()?;
        }

        Ok(())
    }
}

/**
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    hdr = genlmsg_put(skb, 0, 0,
              &genl_family, 0, WG_CMD_CHANGED_PEER);

    nla_put_u32(skb, WGDEVICE_A_IFINDEX, peer->device->dev->ifindex);
    nla_put_string(skb, WGDEVICE_A_IFNAME, peer->device->dev->name);

    peer_nest = nla_nest_start(skb, WGDEVICE_A_PEERS);
    peer_array_nest = nla_nest_start(skb, 0);
    down_read(&peer->handshake.lock);
    nla_put(skb, WGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN,
        peer->handshake.remote_static);
    up_read(&peer->handshake.lock);

    read_lock_bh(&peer->endpoint_lock);
    if (peer->endpoint.addr.sa_family == AF_INET)
        fail = nla_put(skb, WGPEER_A_ENDPOINT,
                   sizeof(peer->endpoint.addr4),
                   &peer->endpoint.addr4);
    else if (peer->endpoint.addr.sa_family == AF_INET6)
        fail = nla_put(skb, WGPEER_A_ENDPOINT,
                   sizeof(peer->endpoint.addr6),
                   &peer->endpoint.addr6);
*/

pub struct WgMcastEventIterator {
    sock: NlSocketHandle,
    family_id: NlWgMsgType,
    mcast_id: NlMcastMsgType,
}

impl WgMcastEventIterator {
    fn new(sock: NlSocketHandle, family_id: NlWgMsgType, mcast_id: NlMcastMsgType) -> Self {
        Self {
            sock,
            family_id,
            mcast_id,
        }
    }
}

impl Iterator for WgMcastEventIterator {
    type Item = Result<get::MonitorEvent, IterMcastEventsError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>(false);

        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                Nlmsg::UnrecognizedConst(n) if n == self.family_id => (),
                Nlmsg::Noop => continue,
                other => {
                    return Some(Err(NlError::msg(format!(
                        "unexpected netlink response type: {:?}, family={}, mcast={}",
                        other, self.family_id, self.mcast_id
                    ))
                    .into()));
                }
            };

            let payload = response.get_payload().ok()?;

            let handle = match payload.cmd {
                WgCmd::ChangedPeer | WgCmd::I2nHandshake => payload.get_attr_handle(),
                cmd => {
                    let cmd = u8::from(cmd);
                    return Some(Err(IterMcastEventsError::UnexpectedCommandError { cmd }));
                }
            };

            return Some(parse_monitor_event(handle));
        }

        None
    }
}
