use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc::{Permit, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use lru_time_cache::LruCache;
use smoltcp::socket::Socket;
use crate::messages::{ConnectionId, IpPacket, NetworkCommand, TransportCommand, TransportEvent, TunnelInfo};
use anyhow::Result;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr};

struct ConnectionState {
    closed: bool,
    packets: VecDeque<Vec<u8>>,
    read_tx: Option<oneshot::Sender<Vec<u8>>>
}

impl ConnectionState {
    fn receive_packet(&mut self, data: Vec<u8>) {
        if self.closed {
            return
        } else if let Some(tx) = self.read_tx.take() {
            tx.send(data).ok();
        } else {
            self.packets.push_back(data);
        }
    }
    fn read_packet(&mut self, tx: oneshot::Sender<Vec<u8>>) {
        assert!(self.read_tx.is_none());
        if self.closed {
            tx.send(Vec::new()).ok();
        } else if let Some(data) = self.packets.pop_front() {
            tx.send(data).ok();
        } else {
            self.read_tx = Some(tx);
        }
    }
}


pub struct UdpHandler {
    next_connection_id: ConnectionId,
    id_lookup: LruCache::<(SocketAddr, SocketAddr), ConnectionId>
    connections: LruCache::<ConnectionId, ConnectionState>,
    net_tx: Sender<NetworkCommand>,
}

impl UdpHandler {
    pub fn new(net_tx: Sender<NetworkCommand>) -> Self {
        let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
            Duration::from_secs(60 * 10),
        );

        let mut id_lookup = LruCache::<(SocketAddr, SocketAddr), ConnectionId>::with_expiry_duration(
            Duration::from_secs(60 * 10),
        );

        Self {
            connections,
            id_lookup,
            net_tx,
            next_connection_id: 1
        }
    }

    pub fn receive_packet(
        &mut self,
        mut packet: IpPacket,
        tunnel_info: TunnelInfo,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        self.id_lookup.entry((packet.src_ip()))
        todo!();
    }

    pub fn receive_packet_udp(
        &mut self,
        mut packet: IpPacket,
        tunnel_info: TunnelInfo,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        todo!("FIXME REMOVE");
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let mut udp_packet = match UdpPacket::new_checked(packet.payload_mut()) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Received invalid UDP packet: {}", e);
                return Ok(());
            }
        };

        let src_addr = SocketAddr::new(src_ip, udp_packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, udp_packet.dst_port());

        let event = TransportEvent::DatagramReceived {
            data: udp_packet.payload_mut().to_vec(),
            src_addr,
            dst_addr,
            tunnel_info,
        };

        permit.send(event);
        Ok(())
    }

    pub fn send_datagram(&mut self, data: Vec<u8>, src_addr: SocketAddr, dst_addr: SocketAddr) {
        todo!("FIXME REMOVE");

        let permit = match self.net_tx.try_reserve() {
            Ok(p) => p,
            Err(_) => {
                log::debug!("Channel full, discarding UDP packet.");
                return;
            }
        };

        // We now know that there's space for us to send,
        // let's painstakingly reassemble the IP packet...

        let udp_repr = UdpRepr {
            src_port: src_addr.port(),
            dst_port: dst_addr.port(),
        };

        let ip_repr: IpRepr = match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::from(*src_addr.ip()),
                dst_addr: Ipv4Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::from(*src_addr.ip()),
                dst_addr: Ipv6Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            _ => {
                log::error!("Failed to assemble UDP datagram: mismatched IP address versions");
                return;
            }
        };

        let buf = vec![0u8; ip_repr.buffer_len()];

        let mut ip_packet = match ip_repr {
            IpRepr::Ipv4(repr) => {
                let mut packet = Ipv4Packet::new_unchecked(buf);
                repr.emit(&mut packet, &ChecksumCapabilities::default());
                IpPacket::from(packet)
            }
            IpRepr::Ipv6(repr) => {
                let mut packet = Ipv6Packet::new_unchecked(buf);
                repr.emit(&mut packet);
                IpPacket::from(packet)
            }
        };

        udp_repr.emit(
            &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            data.len(),
            |buf| buf.copy_from_slice(data.as_slice()),
            &ChecksumCapabilities::default(),
        );

        permit.send(NetworkCommand::SendPacket(ip_packet));
    }


}