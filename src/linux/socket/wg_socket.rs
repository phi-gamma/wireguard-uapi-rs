use crate::get;
use crate::linux::attr::WgDeviceAttribute;
use crate::linux::cmd::WgCmd;
use crate::linux::consts::{WG_GENL_NAME, WG_GENL_VERSION};
use crate::linux::err::{ConnectError, GetDeviceError, SetDeviceError};
use crate::linux::set;
use crate::linux::set::create_set_device_messages;
use crate::linux::socket::parse::*;
use crate::linux::socket::NlWgMsgType;
use crate::linux::DeviceInterface;
use libc::IFNAMSIZ;
use neli::{
    consts::{
        genl::{CtrlAttr, CtrlCmd},
        nl::{NlmF, Nlmsg},
        socket::NlFamily,
    },
    err::{BuilderError, NlError},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    iter::IterationBehavior,
    nl::{NlPayload, NlmsghdrBuilder},
    socket::NlSocketHandle,
    types::GenlBuffer,
    utils::Groups,
};
use std::convert::TryFrom;

pub struct WgSocket {
    sock: NlSocketHandle,
    family_id: NlWgMsgType,
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
        let wgsock = NlSocketHandle::connect(NlFamily::Generic, pid, Groups::empty())?;

        Ok(Self {
            sock: wgsock,
            family_id,
        })
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
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(WgDeviceAttribute::Ifname)
                            .build()
                            .map_err(BuilderError::from)?,
                    )
                    .nla_payload(name.as_ref())
                    .build()
                    .map_err(BuilderError::from)?
            }
            DeviceInterface::Index(index) => NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(WgDeviceAttribute::Ifindex)
                        .build()
                        .map_err(BuilderError::from)?,
                )
                .nla_payload(index)
                .build()
                .map_err(BuilderError::from)?,
        };

        let genlhdr = {
            let mut attrs = GenlBuffer::new();
            attrs.push(attr);

            GenlmsghdrBuilder::default()
                .cmd(WgCmd::GetDevice)
                .version(WG_GENL_VERSION)
                .attrs(attrs)
                .build()
                .map_err(BuilderError::from)?
        };
        let nlhdr = NlmsghdrBuilder::default()
            .nl_type(self.family_id)
            .nl_flags(NlmF::REQUEST | NlmF::ACK | NlmF::DUMP)
            .nl_payload(NlPayload::Payload(genlhdr))
            .build()
            .map_err(BuilderError::from)?;

        self.sock.send(nlhdr)?;

        let mut iter = self
            .sock
            .recv::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>(IterationBehavior::EndMultiOnDone);

        let mut device = None;
        while let Some(Ok(response)) = iter.next() {
            match response.nl_type() {
                Nlmsg::Error => return Err(GetDeviceError::AccessError),
                Nlmsg::Done => break,
                _ => (),
            };

            let handle = response
                .get_payload()
                .ok_or_else(|| NlError::msg("No payload found"))?
                .get_attr_handle();
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
            self.sock
                .recv::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>(IterationBehavior::EndMultiOnDone);
        }

        Ok(())
    }
}
