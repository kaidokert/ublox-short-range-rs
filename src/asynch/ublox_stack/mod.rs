#[cfg(feature = "socket-tcp")]
pub mod tcp;
// #[cfg(feature = "socket-udp")]
// pub mod udp;

pub mod dns;

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::Poll;

use crate::command::data_mode::responses::ConnectPeerResponse;
use crate::command::data_mode::urc::PeerDisconnected;
use crate::command::data_mode::{ClosePeerConnection, ConnectPeer};
use crate::command::edm::types::{DataEvent, Protocol, DATA_PACKAGE_SIZE};
use crate::command::edm::urc::EdmEvent;
use crate::command::edm::EdmDataCommand;
use crate::command::ping::urc::{PingErrorResponse, PingResponse};
use crate::command::Urc;
use crate::peer_builder::PeerUrlBuilder;

use self::dns::DnsSocket;

use super::state::{self, LinkState};

use atat::asynch::AtatClient;
use embassy_futures::select::{select3, Either3};
use embassy_sync::waitqueue::WakerRegistration;
use embassy_time::{Duration, Instant, Timer};
use embedded_nal_async::SocketAddr;
use futures::pin_mut;
use no_std_net::IpAddr;
use ublox_sockets::{AnySocket, ChannelId, PeerHandle, Socket, SocketSet, SocketStorage};

#[cfg(feature = "socket-tcp")]
use ublox_sockets::TcpState;

pub struct StackResources<const SOCK: usize> {
    sockets: [SocketStorage<'static>; SOCK],
}

impl<const SOCK: usize> StackResources<SOCK> {
    pub fn new() -> Self {
        Self {
            sockets: [SocketStorage::EMPTY; SOCK],
        }
    }
}

pub struct UbloxStack<AT: AtatClient + 'static> {
    pub(crate) socket: RefCell<SocketStack>,
    inner: RefCell<Inner<AT>>,
}

struct Inner<AT: AtatClient + 'static> {
    device: state::Device<'static, AT>,
    link_up: bool,
    dns_result: Option<Result<IpAddr, ()>>,
    dns_waker: WakerRegistration,
}

pub(crate) struct SocketStack {
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) waker: WakerRegistration,
    dropped_sockets: heapless::Vec<PeerHandle, 3>,
}

impl<AT: AtatClient> UbloxStack<AT> {
    pub fn new<const SOCK: usize>(
        device: state::Device<'static, AT>,
        resources: &'static mut StackResources<SOCK>,
    ) -> Self {
        let sockets = SocketSet::new(&mut resources.sockets[..]);

        let socket = SocketStack {
            sockets,
            waker: WakerRegistration::new(),
            dropped_sockets: heapless::Vec::new(),
        };

        let inner = Inner {
            device,
            link_up: false,
            dns_result: None,
            dns_waker: WakerRegistration::new(),
        };

        Self {
            socket: RefCell::new(socket),
            inner: RefCell::new(inner),
        }
    }

    pub async fn run(&self) -> ! {
        loop {
            let s = &mut *self.socket.borrow_mut();
            let i = &mut *self.inner.borrow_mut();
            i.poll(s).await;
        }
    }

    /// Make a query for a given name and return the corresponding IP addresses.
    // #[cfg(feature = "dns")]
    pub async fn dns_query(
        &self,
        name: &str,
        addr_type: embedded_nal_async::AddrType,
    ) -> Result<IpAddr, dns::Error> {
        DnsSocket::new(self).query(name, addr_type).await
    }
}

impl<AT: AtatClient> Inner<AT> {
    async fn poll(&mut self, s: &mut SocketStack) {
        let poll_at = Timer::at(Instant::now() + Duration::from_millis(10));
        pin_mut!(poll_at);

        match select3(
            self.device.urc_subscription.next_message_pure(),
            poll_at,
            poll_fn(|cx| Poll::Ready(self.device.link_state(cx))),
        )
        .await
        {
            Either3::First(event) => {
                self.socket_rx(event, s).await;
            }
            Either3::Second(_) => {
                self.socket_tx(s).await;
            }
            Either3::Third(new_state) => {
                // Update link up
                let old_link_up = self.link_up;
                self.link_up = new_state == LinkState::Up;

                // Print when changed
                if old_link_up != self.link_up {
                    defmt::info!("link_up = {:?}", self.link_up);
                }
            }
        }
    }

    async fn socket_rx(&mut self, event: EdmEvent, s: &mut SocketStack) {
        match event {
            EdmEvent::IPv4ConnectEvent(ev) => {
                let endpoint = SocketAddr::new(ev.remote_ip.into(), ev.remote_port);
                Self::connect_event(ev.channel_id, ev.protocol, endpoint, s);
            }
            EdmEvent::IPv6ConnectEvent(ev) => {
                let endpoint = SocketAddr::new(ev.remote_ip.into(), ev.remote_port);
                Self::connect_event(ev.channel_id, ev.protocol, endpoint, s);
            }
            EdmEvent::DisconnectEvent(channel_id) => {
                for (_handle, socket) in s.sockets.iter_mut() {
                    match socket {
                        #[cfg(feature = "socket-udp")]
                        Socket::Udp(udp) if udp.edm_channel == Some(channel_id) => {
                            udp.edm_channel = None;
                            break;
                        }
                        #[cfg(feature = "socket-tcp")]
                        Socket::Tcp(tcp) if tcp.edm_channel == Some(channel_id) => {
                            tcp.edm_channel = None;
                            break;
                        }
                        _ => {}
                    }
                }
            }
            EdmEvent::DataEvent(DataEvent { channel_id, data }) => {
                for (_handle, socket) in s.sockets.iter_mut() {
                    match socket {
                        #[cfg(feature = "socket-udp")]
                        Socket::Udp(udp)
                            if udp.edm_channel == Some(channel_id) && udp.may_recv() =>
                        {
                            let n = udp.rx_enqueue_slice(&data);
                            if n < data.len() {
                                defmt::error!(
                                    "[{}] UDP RX data overflow! Discarding {} bytes",
                                    udp.peer_handle,
                                    data.len() - n
                                );
                            }
                            break;
                        }
                        #[cfg(feature = "socket-tcp")]
                        Socket::Tcp(tcp)
                            if tcp.edm_channel == Some(channel_id) && tcp.may_recv() =>
                        {
                            let n = tcp.rx_enqueue_slice(&data);
                            if n < data.len() {
                                defmt::error!(
                                    "[{}] TCP RX data overflow! Discarding {} bytes",
                                    tcp.peer_handle,
                                    data.len() - n
                                );
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            EdmEvent::ATEvent(Urc::PeerDisconnected(PeerDisconnected { handle })) => {
                for (_handle, socket) in s.sockets.iter_mut() {
                    match socket {
                        #[cfg(feature = "socket-udp")]
                        Socket::Udp(udp) if udp.peer_handle == Some(handle) => {
                            udp.peer_handle = None;
                            udp.set_state(UdpState::TimeWait);
                            break;
                        }
                        #[cfg(feature = "socket-tcp")]
                        Socket::Tcp(tcp) if tcp.peer_handle == Some(handle) => {
                            tcp.peer_handle = None;
                            tcp.set_state(TcpState::TimeWait);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            EdmEvent::ATEvent(Urc::PingResponse(PingResponse { ip, .. })) => {
                // TODO: Check that the result corresponds to the requested hostname?
                self.dns_result = Some(Ok(ip));
                self.dns_waker.wake();
            }
            EdmEvent::ATEvent(Urc::PingErrorResponse(PingErrorResponse { error: _ })) => {
                self.dns_result = Some(Err(()));
                self.dns_waker.wake();
            }
            _ => {}
        }
    }

    async fn socket_tx(&mut self, s: &mut SocketStack) {
        // Handle delayed close-by-drop here
        while let Some(dropped_peer_handle) = s.dropped_sockets.pop() {
            defmt::warn!("Handling dropped socket {}", dropped_peer_handle);
            self.device
                .at
                .send_edm(ClosePeerConnection {
                    peer_handle: dropped_peer_handle,
                })
                .await
                .ok();
        }

        for (_handle, socket) in s.sockets.iter_mut() {
            match socket {
                #[cfg(feature = "socket-udp")]
                Socket::Udp(udp) => todo!(),
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(tcp) => {
                    tcp.poll();

                    match tcp.state() {
                        TcpState::Closed => {
                            if let Some(addr) = tcp.remote_endpoint() {
                                let url = PeerUrlBuilder::new()
                                    .address(&addr)
                                    .set_local_port(tcp.local_port)
                                    .tcp::<128>()
                                    .unwrap();

                                if let Ok(ConnectPeerResponse { peer_handle }) =
                                    self.device.at.send_edm(ConnectPeer { url: &url }).await
                                {
                                    tcp.peer_handle = Some(peer_handle);
                                    tcp.set_state(TcpState::SynSent);
                                }
                            }
                        }
                        // We transmit data in all states where we may have data in the buffer,
                        // or the transmit half of the connection is still open.
                        TcpState::Established | TcpState::CloseWait | TcpState::LastAck => {
                            if let Some(edm_channel) = tcp.edm_channel {
                                defmt::error!("Sending data on {}", edm_channel);
                                tcp.async_tx_dequeue(|payload| async {
                                    let len = core::cmp::max(payload.len(), DATA_PACKAGE_SIZE);
                                    let res = self
                                        .device
                                        .at
                                        .send(EdmDataCommand {
                                            channel: edm_channel,
                                            data: &payload[..len],
                                        })
                                        .await;

                                    (len, res)
                                })
                                .await
                                .ok();
                            }
                        }
                        TcpState::FinWait1 => {
                            self.device
                                .at
                                .send_edm(ClosePeerConnection {
                                    peer_handle: tcp.peer_handle.unwrap(),
                                })
                                .await
                                .ok();
                        }
                        TcpState::Listen => todo!(),
                        TcpState::SynReceived => todo!(),
                        _ => {}
                    };
                }
                _ => {}
            };
        }
    }

    fn connect_event(
        channel_id: ChannelId,
        protocol: Protocol,
        endpoint: SocketAddr,
        s: &mut SocketStack,
    ) {
        for (_handle, socket) in s.sockets.iter_mut() {
            match protocol {
                #[cfg(feature = "socket-tcp")]
                Protocol::TCP => match ublox_sockets::tcp::Socket::downcast_mut(socket) {
                    Some(tcp) if tcp.remote_endpoint == Some(endpoint) => {
                        tcp.edm_channel = Some(channel_id);
                        tcp.set_state(TcpState::Established);
                        break;
                    }
                    _ => {}
                },
                #[cfg(feature = "socket-udp")]
                Protocol::UDP => match ublox_sockets::udp::Socket::downcast_mut(socket) {
                    Some(udp) if udp.remote_endpoint == Some(endpoint) => {
                        udp.edm_channel = Some(channel_id);
                        udp.set_state(ublox_sockets::UdpState::Established);
                        break;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
