//! Security boundary shared by restricted-default DNS and TCP egress.
//!
//! This crate deliberately has no socket, DNS, HTTP, libkrun, or control-plane
//! dependencies. A future packet data plane must call this same policy for DNS
//! answers and for the numeric destination of every outbound connection.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket, UnixStream as TokioUnixStream},
    sync::{Semaphore, mpsc},
    time::{interval, timeout},
};

use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    time::{Duration as SmolDuration, Instant},
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr},
};

/// The Phase 1 guest MTU is 1500. One Ethernet header and one VLAN tag are the
/// largest frame accepted from the libkrun unix-stream backend.
pub const MAX_ETHERNET_FRAME_BYTES: usize = 1_518;
pub const MIN_ETHERNET_FRAME_BYTES: usize = 14;
pub const GUEST_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const MAX_DNS_MESSAGE_BYTES: usize = 1_232;
pub const MAX_DNS_ANSWERS: usize = 16;
pub const MAX_DNS_NAME_BYTES: usize = 253;
pub const MAX_DNS_TTL_SECONDS: u32 = 300;
pub const MAX_DHCP_MESSAGE_BYTES: usize = 576;
pub const DHCP_LEASE_SECONDS: u32 = 3_600;
pub const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpRequestKind {
    Discover,
    Request,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpRequest {
    pub transaction_id: u32,
    pub kind: DhcpRequestKind,
    pub rapid_commit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpError {
    Oversized,
    Truncated,
    InvalidIdentity,
    InvalidOption,
    UnsupportedMessage,
    AddressMismatch,
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized => formatter.write_str("DHCP message exceeds the bounded size"),
            Self::Truncated => formatter.write_str("truncated DHCP message"),
            Self::InvalidIdentity => formatter.write_str("invalid DHCP client identity"),
            Self::InvalidOption => formatter.write_str("invalid DHCP option"),
            Self::UnsupportedMessage => formatter.write_str("unsupported DHCP message"),
            Self::AddressMismatch => formatter.write_str("DHCP address does not match fixed lease"),
        }
    }
}

impl std::error::Error for DhcpError {}

/// Parses the fixed single-guest DHCP subset. Unknown options, option overload,
/// relays, duplicate identity-bearing options, and lease/address changes are
/// rejected rather than reflected into a response.
pub fn inspect_dhcp_request(
    message: &[u8],
    expected_guest_mac: [u8; 6],
) -> Result<DhcpRequest, DhcpError> {
    if message.len() > MAX_DHCP_MESSAGE_BYTES {
        return Err(DhcpError::Oversized);
    }
    if message.len() < 241 {
        return Err(DhcpError::Truncated);
    }
    if message[0] != 1
        || message[1] != 1
        || message[2] != 6
        || message[3] != 0
        || message[24..28] != [0; 4]
        || message[28..34] != expected_guest_mac
        || message[236..240] != [0x63, 0x82, 0x53, 0x63]
    {
        return Err(DhcpError::InvalidIdentity);
    }
    let client_ip = Ipv4Addr::new(message[12], message[13], message[14], message[15]);
    if !matches!(client_ip, Ipv4Addr::UNSPECIFIED | GUEST_IPV4) {
        return Err(DhcpError::AddressMismatch);
    }
    let mut kind = None;
    let mut requested_ip = None;
    let mut server_identifier = None;
    let mut client_identifier_seen = false;
    let mut rapid_commit = false;
    let mut cursor = 240;
    let mut ended = false;
    while cursor < message.len() {
        let option = message[cursor];
        cursor += 1;
        match option {
            0 => continue,
            255 => {
                ended = true;
                break;
            }
            _ => {}
        }
        let length = usize::from(*message.get(cursor).ok_or(DhcpError::Truncated)?);
        cursor += 1;
        let data = message
            .get(cursor..cursor + length)
            .ok_or(DhcpError::Truncated)?;
        cursor += length;
        match (option, data) {
            (53, [1]) if kind.is_none() => kind = Some(DhcpRequestKind::Discover),
            (53, [3]) if kind.is_none() => kind = Some(DhcpRequestKind::Request),
            (50, [a, b, c, d]) if requested_ip.is_none() => {
                requested_ip = Some(Ipv4Addr::new(*a, *b, *c, *d));
            }
            (54, [a, b, c, d]) if server_identifier.is_none() => {
                server_identifier = Some(Ipv4Addr::new(*a, *b, *c, *d));
            }
            (61, [1, a, b, c, d, e, f]) if !client_identifier_seen => {
                if [*a, *b, *c, *d, *e, *f] != expected_guest_mac {
                    return Err(DhcpError::InvalidIdentity);
                }
                client_identifier_seen = true;
            }
            // Parameter request list, maximum message size, host name and
            // vendor class do not affect the fixed response and stay bounded.
            (80, []) if !rapid_commit => rapid_commit = true,
            (55 | 57 | 12 | 60, _) if length <= 64 => {}
            _ => return Err(DhcpError::InvalidOption),
        }
    }
    if !ended || message[cursor..].iter().any(|byte| *byte != 0) {
        return Err(DhcpError::InvalidOption);
    }
    let kind = kind.ok_or(DhcpError::UnsupportedMessage)?;
    if requested_ip.is_some_and(|address| address != GUEST_IPV4)
        || server_identifier.is_some_and(|address| address != GATEWAY_IPV4)
        || (kind == DhcpRequestKind::Request
            && client_ip == Ipv4Addr::UNSPECIFIED
            && requested_ip != Some(GUEST_IPV4))
    {
        return Err(DhcpError::AddressMismatch);
    }
    Ok(DhcpRequest {
        transaction_id: u32::from_be_bytes([message[4], message[5], message[6], message[7]]),
        kind,
        rapid_commit,
    })
}

/// Emits a fixed OFFER/ACK for the single guest. The response contains only
/// subnet, router, virtual DNS, server identity and bounded lease timers.
pub fn build_dhcp_response(request: DhcpRequest, guest_mac: [u8; 6]) -> Vec<u8> {
    let mut message = vec![0; 240];
    message[0] = 2;
    message[1] = 1;
    message[2] = 6;
    message[4..8].copy_from_slice(&request.transaction_id.to_be_bytes());
    message[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    message[16..20].copy_from_slice(&GUEST_IPV4.octets());
    message[20..24].copy_from_slice(&GATEWAY_IPV4.octets());
    message[28..34].copy_from_slice(&guest_mac);
    message[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    push_dhcp_option(
        &mut message,
        53,
        &[match request.kind {
            DhcpRequestKind::Discover if request.rapid_commit => 5,
            DhcpRequestKind::Discover => 2,
            DhcpRequestKind::Request => 5,
        }],
    );
    if request.rapid_commit {
        push_dhcp_option(&mut message, 80, &[]);
    }
    push_dhcp_option(&mut message, 54, &GATEWAY_IPV4.octets());
    push_dhcp_option(&mut message, 1, &[255, 255, 255, 0]);
    push_dhcp_option(&mut message, 3, &GATEWAY_IPV4.octets());
    push_dhcp_option(&mut message, 6, &GATEWAY_IPV4.octets());
    push_dhcp_option(&mut message, 26, &1500_u16.to_be_bytes());
    push_dhcp_option(&mut message, 51, &DHCP_LEASE_SECONDS.to_be_bytes());
    push_dhcp_option(&mut message, 58, &(DHCP_LEASE_SECONDS / 2).to_be_bytes());
    push_dhcp_option(
        &mut message,
        59,
        &(DHCP_LEASE_SECONDS * 7 / 8).to_be_bytes(),
    );
    message.push(255);
    message
}

fn push_dhcp_option(message: &mut Vec<u8>, kind: u8, data: &[u8]) {
    debug_assert!(data.len() <= u8::MAX as usize);
    message.push(kind);
    message.push(data.len() as u8);
    message.extend_from_slice(data);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyLimits {
    pub max_connections: usize,
    pub bytes_per_connection: usize,
    pub max_connection_bytes: u64,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_connections: 32,
            bytes_per_connection: 128 * 1024,
            max_connection_bytes: 512 * 1024 * 1024,
        }
    }
}

impl ProxyLimits {
    pub fn validate(self) -> Result<Self, AdmissionError> {
        if self.max_connections == 0
            || self.max_connections > 256
            || self.bytes_per_connection < 16 * 1024
            || self.bytes_per_connection > 1024 * 1024
            || self
                .max_connections
                .checked_mul(self.bytes_per_connection)
                .is_none_or(|bytes| bytes > 64 * 1024 * 1024)
            || self.max_connection_bytes < self.bytes_per_connection as u64
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidLimits,
    Capacity,
    ByteLimit,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid proxy admission limits"),
            Self::Capacity => formatter.write_str("proxy connection capacity exhausted"),
            Self::ByteLimit => formatter.write_str("proxy connection byte limit exhausted"),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Debug)]
struct AdmissionState {
    limits: ProxyLimits,
    active: usize,
    generation: u64,
}

#[derive(Clone, Debug)]
pub struct ConnectionAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

impl ConnectionAdmission {
    pub fn new(limits: ProxyLimits) -> Result<Self, AdmissionError> {
        Ok(Self {
            state: Arc::new(Mutex::new(AdmissionState {
                limits: limits.validate()?,
                active: 0,
                generation: 0,
            })),
        })
    }

    pub fn reserve(&self) -> Result<ConnectionPermit, AdmissionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.active == state.limits.max_connections {
            return Err(AdmissionError::Capacity);
        }
        state.generation = state.generation.wrapping_add(1);
        state.active += 1;
        Ok(ConnectionPermit {
            state: Arc::clone(&self.state),
            generation: state.generation,
            transferred_bytes: 0,
            released: false,
        })
    }

    pub fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .active
    }
}

pub struct ConnectionPermit {
    state: Arc<Mutex<AdmissionState>>,
    generation: u64,
    transferred_bytes: u64,
    released: bool,
}

impl std::fmt::Debug for ConnectionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionPermit")
            .field("generation", &self.generation)
            .field("transferred_bytes", &self.transferred_bytes)
            .finish_non_exhaustive()
    }
}

impl ConnectionPermit {
    pub fn account_bytes(&mut self, bytes: usize) -> Result<(), AdmissionError> {
        let limit = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .limits
            .max_connection_bytes;
        let next = self
            .transferred_bytes
            .checked_add(bytes as u64)
            .ok_or(AdmissionError::ByteLimit)?;
        if next > limit {
            return Err(AdmissionError::ByteLimit);
        }
        self.transferred_bytes = next;
        Ok(())
    }

    pub fn transferred_bytes(&self) -> u64 {
        self.transferred_bytes
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.active = state.active.saturating_sub(1);
        self.released = true;
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpProxyEvent {
    Dial {
        id: ConnectionId,
        target: std::net::SocketAddrV4,
    },
    Closed {
        id: ConnectionId,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum TcpProxyError {
    InvalidMac,
    Device(DeviceQueueError),
    Packet(PacketDenyReason),
    Admission(AdmissionError),
    StackConfiguration,
    UnknownConnection,
    ConnectionClosed,
}

impl std::fmt::Display for TcpProxyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMac => formatter.write_str("invalid proxy MAC identity"),
            Self::Device(error) => write!(formatter, "bounded device: {error}"),
            Self::Packet(reason) => write!(formatter, "guest packet denied: {reason:?}"),
            Self::Admission(error) => write!(formatter, "connection admission: {error}"),
            Self::StackConfiguration => formatter.write_str("invalid TCP stack configuration"),
            Self::UnknownConnection => formatter.write_str("unknown TCP proxy connection"),
            Self::ConnectionClosed => formatter.write_str("TCP proxy connection is closed"),
        }
    }
}

impl std::error::Error for TcpProxyError {}

impl From<DeviceQueueError> for TcpProxyError {
    fn from(value: DeviceQueueError) -> Self {
        Self::Device(value)
    }
}

struct TcpConnection {
    id: ConnectionId,
    handle: SocketHandle,
    target: std::net::SocketAddrV4,
    permit: ConnectionPermit,
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpConnection")
            .field("id", &self.id)
            .field(
                "address_class",
                &classify_address(IpAddr::V4(*self.target.ip())),
            )
            .field("port", &self.target.port())
            .field("permit", &self.permit)
            .finish_non_exhaustive()
    }
}

/// Synchronous transparent TCP endpoint. It terminates guest TCP in smoltcp and
/// emits numeric dial events for the host adapter. It never opens a host socket,
/// performs DNS, spawns a task, or creates a channel.
pub struct TcpProxyCore {
    guest_mac: [u8; 6],
    device: BoundedEthernetDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    listeners: [(u16, SocketHandle); 2],
    connections: Vec<TcpConnection>,
    admission: ConnectionAdmission,
    limits: ProxyLimits,
    next_connection: u64,
}

impl std::fmt::Debug for TcpProxyCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpProxyCore")
            .field("active_connections", &self.connections.len())
            .field("device", &self.device)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl TcpProxyCore {
    pub fn new(
        guest_mac: [u8; 6],
        gateway_mac: [u8; 6],
        device_limits: DeviceLimits,
        proxy_limits: ProxyLimits,
    ) -> Result<Self, TcpProxyError> {
        if !valid_unicast_mac(guest_mac)
            || !valid_unicast_mac(gateway_mac)
            || guest_mac == gateway_mac
        {
            return Err(TcpProxyError::InvalidMac);
        }
        let limits = proxy_limits.validate().map_err(TcpProxyError::Admission)?;
        let admission = ConnectionAdmission::new(limits).map_err(TcpProxyError::Admission)?;
        let mut device = BoundedEthernetDevice::new(device_limits)?;
        let mut config =
            InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(gateway_mac)));
        config.random_seed = u64::from_be_bytes([
            guest_mac[0],
            guest_mac[1],
            guest_mac[2],
            guest_mac[3],
            guest_mac[4],
            guest_mac[5],
            gateway_mac[4],
            gateway_mac[5],
        ]);
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        let mut address_configured = false;
        interface.update_ip_addrs(|addresses| {
            addresses.clear();
            address_configured = addresses
                .push(IpCidr::new(IpAddress::from(GATEWAY_IPV4), 24))
                .is_ok();
        });
        if !address_configured
            || interface
                .routes_mut()
                .add_default_ipv4_route(GATEWAY_IPV4)
                .is_err()
        {
            return Err(TcpProxyError::StackConfiguration);
        }
        interface.set_any_ip(true);
        let mut sockets = SocketSet::new(Vec::with_capacity(limits.max_connections + 2));
        let http = add_tcp_listener(&mut sockets, 80, limits.bytes_per_connection)?;
        let https = add_tcp_listener(&mut sockets, 443, limits.bytes_per_connection)?;
        Ok(Self {
            guest_mac,
            device,
            interface,
            sockets,
            listeners: [(80, http), (443, https)],
            connections: Vec::with_capacity(limits.max_connections),
            admission,
            limits,
            next_connection: 0,
        })
    }

    pub fn enqueue_guest_frame(&mut self, frame: Vec<u8>) -> Result<(), TcpProxyError> {
        match inspect_guest_ethernet(&frame, self.guest_mac) {
            PacketDecision::AllowArp | PacketDecision::AllowTcp { .. } => {
                self.device.enqueue_guest_frame(frame)?;
                Ok(())
            }
            PacketDecision::Deny(reason) => Err(TcpProxyError::Packet(reason)),
            PacketDecision::AllowDhcp | PacketDecision::AllowDns => {
                Err(TcpProxyError::Packet(PacketDenyReason::UnsupportedProtocol))
            }
        }
    }

    pub fn poll(&mut self, now_millis: i64) -> Result<Vec<TcpProxyEvent>, TcpProxyError> {
        let now = Instant::from_millis(now_millis);
        // Device ingress is bounded, so Interface::poll cannot do unbounded work.
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let mut events = Vec::new();
        for listener_index in 0..self.listeners.len() {
            let (port, handle) = self.listeners[listener_index];
            if self.sockets.get::<TcpSocket<'_>>(handle).state() == TcpState::Listen {
                continue;
            }
            let endpoints = {
                let socket = self.sockets.get::<TcpSocket<'_>>(handle);
                (socket.local_endpoint(), socket.remote_endpoint())
            };
            let Some((local, remote)) = endpoints.0.zip(endpoints.1) else {
                reset_tcp_listener(&mut self.sockets, handle, port)?;
                continue;
            };
            let IpAddress::Ipv4(target_ip) = local.addr;
            let IpAddress::Ipv4(source_ip) = remote.addr;
            if source_ip != GUEST_IPV4
                || local.port != port
                || evaluate_tcp_connect(IpAddr::V4(target_ip), port) != EgressDecision::Allow
            {
                reset_tcp_listener(&mut self.sockets, handle, port)?;
                continue;
            }
            let permit = match self.admission.reserve() {
                Ok(permit) => permit,
                Err(AdmissionError::Capacity) => {
                    reset_tcp_listener(&mut self.sockets, handle, port)?;
                    continue;
                }
                Err(error) => return Err(TcpProxyError::Admission(error)),
            };
            self.next_connection = self.next_connection.wrapping_add(1);
            let id = ConnectionId(self.next_connection);
            let target = std::net::SocketAddrV4::new(target_ip, port);
            self.connections.push(TcpConnection {
                id,
                handle,
                target,
                permit,
            });
            self.listeners[listener_index].1 =
                add_tcp_listener(&mut self.sockets, port, self.limits.bytes_per_connection)?;
            events.push(TcpProxyEvent::Dial { id, target });
        }

        let mut closed = Vec::new();
        for (index, connection) in self.connections.iter().enumerate() {
            if self.sockets.get::<TcpSocket<'_>>(connection.handle).state() == TcpState::Closed {
                closed.push(index);
            }
        }
        for index in closed.into_iter().rev() {
            let connection = self.connections.swap_remove(index);
            self.sockets.remove(connection.handle);
            events.push(TcpProxyEvent::Closed { id: connection.id });
        }
        Ok(events)
    }

    pub fn dequeue_guest_bound_frame(&mut self) -> Option<Vec<u8>> {
        self.device.dequeue_guest_bound_frame()
    }

    pub fn take_guest_payload(
        &mut self,
        id: ConnectionId,
        output: &mut [u8],
    ) -> Result<usize, TcpProxyError> {
        let connection = self
            .connections
            .iter_mut()
            .find(|connection| connection.id == id)
            .ok_or(TcpProxyError::UnknownConnection)?;
        let socket = self.sockets.get_mut::<TcpSocket<'_>>(connection.handle);
        if !socket.can_recv() {
            return Ok(0);
        }
        let read = socket
            .recv_slice(output)
            .map_err(|_| TcpProxyError::ConnectionClosed)?;
        if let Err(error) = connection.permit.account_bytes(read) {
            socket.abort();
            return Err(TcpProxyError::Admission(error));
        }
        Ok(read)
    }

    pub fn send_host_payload(
        &mut self,
        id: ConnectionId,
        input: &[u8],
    ) -> Result<usize, TcpProxyError> {
        let connection = self
            .connections
            .iter_mut()
            .find(|connection| connection.id == id)
            .ok_or(TcpProxyError::UnknownConnection)?;
        let socket = self.sockets.get_mut::<TcpSocket<'_>>(connection.handle);
        if !socket.can_send() {
            return Ok(0);
        }
        let written = socket
            .send_slice(input)
            .map_err(|_| TcpProxyError::ConnectionClosed)?;
        if let Err(error) = connection.permit.account_bytes(written) {
            socket.abort();
            return Err(TcpProxyError::Admission(error));
        }
        Ok(written)
    }

    pub fn host_eof(&mut self, id: ConnectionId) -> Result<(), TcpProxyError> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.id == id)
            .ok_or(TcpProxyError::UnknownConnection)?;
        self.sockets
            .get_mut::<TcpSocket<'_>>(connection.handle)
            .close();
        Ok(())
    }

    /// True after guest FIN and after all guest-to-host bytes have been
    /// consumed, so the host adapter may half-close its numeric TCP socket.
    pub fn guest_write_closed(&self, id: ConnectionId) -> Result<bool, TcpProxyError> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.id == id)
            .ok_or(TcpProxyError::UnknownConnection)?;
        Ok(!self
            .sockets
            .get::<TcpSocket<'_>>(connection.handle)
            .may_recv())
    }

    pub fn abort(&mut self, id: ConnectionId) -> Result<(), TcpProxyError> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.id == id)
            .ok_or(TcpProxyError::UnknownConnection)?;
        self.sockets
            .get_mut::<TcpSocket<'_>>(connection.handle)
            .abort();
        Ok(())
    }

    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }
}

fn valid_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0
}

fn add_tcp_listener(
    sockets: &mut SocketSet<'static>,
    port: u16,
    buffer_bytes: usize,
) -> Result<SocketHandle, TcpProxyError> {
    let per_direction = buffer_bytes / 2;
    if per_direction < 8 * 1024 {
        return Err(TcpProxyError::StackConfiguration);
    }
    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0; per_direction]),
        TcpSocketBuffer::new(vec![0; per_direction]),
    );
    socket.set_timeout(Some(SmolDuration::from_secs(120)));
    socket
        .listen(port)
        .map_err(|_| TcpProxyError::StackConfiguration)?;
    Ok(sockets.add(socket))
}

fn reset_tcp_listener(
    sockets: &mut SocketSet<'static>,
    handle: SocketHandle,
    port: u16,
) -> Result<(), TcpProxyError> {
    let socket = sockets.get_mut::<TcpSocket<'_>>(handle);
    socket.abort();
    socket
        .listen(port)
        .map_err(|_| TcpProxyError::StackConfiguration)
}

#[derive(Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub question_type: DnsQuestionType,
    canonical_name: Vec<u8>,
}

impl std::fmt::Debug for DnsQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsQuery")
            .field("id", &self.id)
            .field("question_type", &self.question_type)
            .field("canonical_name", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsQuestionType {
    A,
    Aaaa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub address: Ipv4Addr,
    pub ttl_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    Oversized,
    Truncated,
    InvalidHeader,
    InvalidName,
    CompressionLoop,
    UnsupportedQuestion,
    TooManyAnswers,
    MismatchedTransaction,
    RejectedAddress(AddressClass),
    Ipv6Unsupported,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized => formatter.write_str("DNS message exceeds the bounded size"),
            Self::Truncated => formatter.write_str("truncated DNS message"),
            Self::InvalidHeader => formatter.write_str("invalid DNS header"),
            Self::InvalidName => formatter.write_str("invalid DNS name"),
            Self::CompressionLoop => formatter.write_str("DNS compression pointer loop"),
            Self::UnsupportedQuestion => formatter.write_str("unsupported DNS question"),
            Self::TooManyAnswers => formatter.write_str("too many DNS answers"),
            Self::MismatchedTransaction => formatter.write_str("mismatched DNS transaction"),
            Self::RejectedAddress(class) => {
                write!(formatter, "rejected DNS address class {class:?}")
            }
            Self::Ipv6Unsupported => formatter.write_str("IPv6 DNS answer is unsupported"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Validates a guest DNS query without retaining or logging its name. Only one
/// IN A/AAAA question is accepted; the data plane answers AAAA with NODATA until
/// IPv6 egress exists.
pub fn inspect_dns_query(message: &[u8]) -> Result<DnsQuery, DnsError> {
    validate_dns_size(message)?;
    if message.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let flags = dns_u16(message, 2)?;
    if flags & 0x8000 != 0
        || flags & 0x7800 != 0
        || dns_u16(message, 4)? != 1
        || dns_u16(message, 6)? != 0
        || dns_u16(message, 8)? != 0
        || dns_u16(message, 10)? > 1
    {
        return Err(DnsError::InvalidHeader);
    }
    let (canonical_name, cursor) = parse_dns_name(message, 12, false)?;
    if cursor + 4 > message.len() {
        return Err(DnsError::Truncated);
    }
    let question_type = match dns_u16(message, cursor)? {
        1 => DnsQuestionType::A,
        28 => DnsQuestionType::Aaaa,
        _ => return Err(DnsError::UnsupportedQuestion),
    };
    if dns_u16(message, cursor + 2)? != 1 {
        return Err(DnsError::UnsupportedQuestion);
    }
    Ok(DnsQuery {
        id: dns_u16(message, 0)?,
        question_type,
        canonical_name,
    })
}

/// Builds a bounded, transaction-bound NODATA response for a supported query.
/// Phase 1 has no IPv6 packet path, so AAAA must receive an immediate empty
/// answer instead of being dropped: libc resolvers commonly wait for both A
/// and AAAA before returning an IPv4 result.
pub fn build_dns_nodata_response(message: &[u8]) -> Result<Vec<u8>, DnsError> {
    let query = inspect_dns_query(message)?;
    let (_, name_end) = parse_dns_name(message, 12, false)?;
    let question_end = name_end.checked_add(4).ok_or(DnsError::Truncated)?;
    if question_end > message.len() {
        return Err(DnsError::Truncated);
    }
    let mut response = message[..question_end].to_vec();
    let request_flags = dns_u16(message, 2)?;
    // QR + copied RD + RA. RCODE remains NOERROR and all record counts are 0.
    let response_flags = 0x8000 | (request_flags & 0x0100) | 0x0080;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[4..6].copy_from_slice(&1_u16.to_be_bytes());
    response[6..12].fill(0);
    debug_assert_eq!(dns_u16(&response, 0), Ok(query.id));
    Ok(response)
}

/// Validates an upstream response and returns only public IPv4 answers. A
/// private/special answer rejects the whole response so it cannot enter a
/// connection cache alongside a public answer.
pub fn inspect_dns_response(
    message: &[u8],
    expected: &DnsQuery,
) -> Result<Vec<DnsAnswer>, DnsError> {
    validate_dns_size(message)?;
    if message.len() < 12 {
        return Err(DnsError::Truncated);
    }
    if dns_u16(message, 0)? != expected.id {
        return Err(DnsError::MismatchedTransaction);
    }
    let flags = dns_u16(message, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 || flags & 0x000f != 0 {
        return Err(DnsError::InvalidHeader);
    }
    if dns_u16(message, 4)? != 1 {
        return Err(DnsError::InvalidHeader);
    }
    let answer_count = usize::from(dns_u16(message, 6)?);
    let authority_count = usize::from(dns_u16(message, 8)?);
    let additional_count = usize::from(dns_u16(message, 10)?);
    let total_records = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsError::TooManyAnswers)?;
    if total_records > MAX_DNS_ANSWERS {
        return Err(DnsError::TooManyAnswers);
    }
    let (response_name, mut cursor) = parse_dns_name(message, 12, true)?;
    if cursor + 4 > message.len() {
        return Err(DnsError::Truncated);
    }
    let response_question = match dns_u16(message, cursor)? {
        1 => DnsQuestionType::A,
        28 => DnsQuestionType::Aaaa,
        _ => return Err(DnsError::UnsupportedQuestion),
    };
    if response_name != expected.canonical_name
        || response_question != expected.question_type
        || dns_u16(message, cursor + 2)? != 1
    {
        return Err(DnsError::MismatchedTransaction);
    }
    cursor += 4;
    let mut answers = Vec::with_capacity(answer_count.min(MAX_DNS_ANSWERS));
    for record_index in 0..total_records {
        let (_, next) = parse_dns_name(message, cursor, true)?;
        cursor = next;
        if cursor + 10 > message.len() {
            return Err(DnsError::Truncated);
        }
        let answer_type = dns_u16(message, cursor)?;
        let class = dns_u16(message, cursor + 2)?;
        let ttl = dns_u32(message, cursor + 4)?;
        let data_len = usize::from(dns_u16(message, cursor + 8)?);
        cursor += 10;
        let data = message
            .get(cursor..cursor + data_len)
            .ok_or(DnsError::Truncated)?;
        cursor += data_len;
        if class != 1 {
            continue;
        }
        match (answer_type, data) {
            (1, [a, b, c, d]) if expected.question_type == DnsQuestionType::A => {
                let address = Ipv4Addr::new(*a, *b, *c, *d);
                let class = classify_address(IpAddr::V4(address));
                if class != AddressClass::PublicUnicast {
                    return Err(DnsError::RejectedAddress(class));
                }
                if record_index < answer_count {
                    answers.push(DnsAnswer {
                        address,
                        ttl_seconds: ttl.min(MAX_DNS_TTL_SECONDS),
                    });
                }
            }
            (1, [a, b, c, d]) => {
                let class = classify_address(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
                if class != AddressClass::PublicUnicast {
                    return Err(DnsError::RejectedAddress(class));
                }
            }
            // CNAME records are bounded and already have their owner name
            // checked. Validate the compressed RDATA name before skipping it.
            (5, _) => {
                let rdata_start = cursor - data_len;
                let (_, consumed) = parse_dns_name(message, rdata_start, true)?;
                if consumed != cursor {
                    return Err(DnsError::InvalidName);
                }
            }
            (28, data) if data.len() == 16 => return Err(DnsError::Ipv6Unsupported),
            _ => {}
        }
    }
    if cursor != message.len() {
        return Err(DnsError::InvalidHeader);
    }
    Ok(answers)
}

/// Revalidates a response and clamps every resource-record TTL in-place before
/// it is returned to the guest. This prevents an upstream from extending the
/// lifetime of an otherwise valid public answer beyond the policy bound.
pub fn validate_and_clamp_dns_response(
    message: &mut [u8],
    expected: &DnsQuery,
) -> Result<Vec<DnsAnswer>, DnsError> {
    let answers = inspect_dns_response(message, expected)?;
    let total_records = usize::from(dns_u16(message, 6)?)
        + usize::from(dns_u16(message, 8)?)
        + usize::from(dns_u16(message, 10)?);
    let (_, mut cursor) = parse_dns_name(message, 12, true)?;
    cursor += 4;
    for _ in 0..total_records {
        let (_, next) = parse_dns_name(message, cursor, true)?;
        cursor = next;
        if cursor + 10 > message.len() {
            return Err(DnsError::Truncated);
        }
        let ttl = dns_u32(message, cursor + 4)?.min(MAX_DNS_TTL_SECONDS);
        message[cursor + 4..cursor + 8].copy_from_slice(&ttl.to_be_bytes());
        let data_len = usize::from(dns_u16(message, cursor + 8)?);
        cursor = cursor
            .checked_add(10 + data_len)
            .ok_or(DnsError::Truncated)?;
        if cursor > message.len() {
            return Err(DnsError::Truncated);
        }
    }
    Ok(answers)
}

fn validate_dns_size(message: &[u8]) -> Result<(), DnsError> {
    if message.len() > MAX_DNS_MESSAGE_BYTES {
        Err(DnsError::Oversized)
    } else {
        Ok(())
    }
}

fn dns_u16(message: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = message.get(offset..offset + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn dns_u32(message: &[u8], offset: usize) -> Result<u32, DnsError> {
    let bytes = message.get(offset..offset + 4).ok_or(DnsError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Returns a lowercase canonical wire name and the cursor after the name in its
/// original location. Callers retain it only for transaction binding; Debug
/// output never includes it.
fn parse_dns_name(
    message: &[u8],
    start: usize,
    allow_compression: bool,
) -> Result<(Vec<u8>, usize), DnsError> {
    let mut cursor = start;
    let mut original_end = None;
    let mut canonical = Vec::new();
    let mut jumps = 0_usize;
    let max_jumps = message.len().min(32);
    loop {
        let length = *message.get(cursor).ok_or(DnsError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            if !allow_compression {
                return Err(DnsError::InvalidName);
            }
            let next = *message.get(cursor + 1).ok_or(DnsError::Truncated)?;
            let pointer = usize::from(u16::from(length & 0x3f) << 8 | u16::from(next));
            if pointer >= message.len() || pointer >= cursor || jumps >= max_jumps {
                return Err(DnsError::CompressionLoop);
            }
            original_end.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidName);
        }
        cursor += 1;
        if length == 0 {
            canonical.push(0);
            return Ok((canonical, original_end.unwrap_or(cursor)));
        }
        let label_len = usize::from(length);
        if label_len > 63 || cursor + label_len > message.len() {
            return Err(DnsError::InvalidName);
        }
        let decoded_len = canonical
            .len()
            .checked_add(label_len + 1)
            .ok_or(DnsError::InvalidName)?;
        if decoded_len > MAX_DNS_NAME_BYTES + 1 {
            return Err(DnsError::InvalidName);
        }
        canonical.push(length);
        canonical.extend(
            message[cursor..cursor + label_len]
                .iter()
                .map(u8::to_ascii_lowercase),
        );
        cursor += label_len;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLimits {
    pub max_ingress_frames: usize,
    pub max_egress_frames: usize,
    pub max_buffered_bytes: usize,
}

impl Default for DeviceLimits {
    fn default() -> Self {
        Self {
            max_ingress_frames: 64,
            max_egress_frames: 64,
            max_buffered_bytes: 128 * 1024,
        }
    }
}

impl DeviceLimits {
    pub fn validate(self) -> Result<Self, DeviceQueueError> {
        if self.max_ingress_frames == 0
            || self.max_egress_frames == 0
            || self.max_buffered_bytes < MAX_ETHERNET_FRAME_BYTES * 2
            || self.max_buffered_bytes > 16 * 1024 * 1024
        {
            return Err(DeviceQueueError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceQueueError {
    InvalidLimits,
    InvalidFrameLength(usize),
    IngressFull,
}

impl std::fmt::Display for DeviceQueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid bounded device limits"),
            Self::InvalidFrameLength(length) => write!(formatter, "invalid frame length {length}"),
            Self::IngressFull => formatter.write_str("bounded device ingress is full"),
        }
    }
}

impl std::error::Error for DeviceQueueError {}

/// Caller-driven, single-threaded smoltcp device. Both directions have fixed
/// frame and aggregate byte limits; no channel, task, or implicit worker is
/// created. Egress saturation applies backpressure by returning no TxToken.
pub struct BoundedEthernetDevice {
    limits: DeviceLimits,
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    ingress_bytes: usize,
    egress_bytes: usize,
}

impl std::fmt::Debug for BoundedEthernetDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundedEthernetDevice")
            .field("limits", &self.limits)
            .field("ingress_frames", &self.ingress.len())
            .field("egress_frames", &self.egress.len())
            .field("ingress_bytes", &self.ingress_bytes)
            .field("egress_bytes", &self.egress_bytes)
            .finish()
    }
}

impl BoundedEthernetDevice {
    pub fn new(limits: DeviceLimits) -> Result<Self, DeviceQueueError> {
        Ok(Self {
            limits: limits.validate()?,
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            ingress_bytes: 0,
            egress_bytes: 0,
        })
    }

    pub fn enqueue_guest_frame(&mut self, frame: Vec<u8>) -> Result<(), DeviceQueueError> {
        validate_frame_length(frame.len())?;
        if self.ingress.len() == self.limits.max_ingress_frames
            || self.total_buffered_bytes() + frame.len() > self.limits.max_buffered_bytes
        {
            return Err(DeviceQueueError::IngressFull);
        }
        self.ingress_bytes += frame.len();
        self.ingress.push_back(frame);
        Ok(())
    }

    pub fn dequeue_guest_bound_frame(&mut self) -> Option<Vec<u8>> {
        let frame = self.egress.pop_front()?;
        self.egress_bytes -= frame.len();
        Some(frame)
    }

    pub fn total_buffered_bytes(&self) -> usize {
        self.ingress_bytes + self.egress_bytes
    }

    pub fn ingress_frames(&self) -> usize {
        self.ingress.len()
    }

    pub fn egress_frames(&self) -> usize {
        self.egress.len()
    }

    fn can_transmit(&self) -> bool {
        self.egress.len() < self.limits.max_egress_frames
            && self.total_buffered_bytes() + MAX_ETHERNET_FRAME_BYTES
                <= self.limits.max_buffered_bytes
    }
}

pub struct BoundedRxToken {
    frame: Vec<u8>,
}

impl RxToken for BoundedRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

pub struct BoundedTxToken<'a> {
    egress: &'a mut VecDeque<Vec<u8>>,
    egress_bytes: &'a mut usize,
    limits: DeviceLimits,
    ingress_bytes: usize,
}

impl TxToken for BoundedTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp receives fixed capacities from this device. If it violates
        // those capabilities, refuse to queue the frame but still call the
        // closure with an empty buffer so this infallible trait stays bounded.
        if validate_frame_length(len).is_err()
            || self.egress.len() == self.limits.max_egress_frames
            || self.ingress_bytes + *self.egress_bytes + len > self.limits.max_buffered_bytes
        {
            return f(&mut []);
        }
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        *self.egress_bytes += len;
        self.egress.push_back(frame);
        result
    }
}

impl Device for BoundedEthernetDevice {
    type RxToken<'a> = BoundedRxToken;
    type TxToken<'a> = BoundedTxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.can_transmit() {
            return None;
        }
        let frame = self.ingress.pop_front()?;
        self.ingress_bytes -= frame.len();
        Some((
            BoundedRxToken { frame },
            BoundedTxToken {
                egress: &mut self.egress,
                egress_bytes: &mut self.egress_bytes,
                limits: self.limits,
                ingress_bytes: self.ingress_bytes,
            },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        if !self.can_transmit() {
            return None;
        }
        Some(BoundedTxToken {
            egress: &mut self.egress,
            egress_bytes: &mut self.egress_bytes,
            limits: self.limits,
            ingress_bytes: self.ingress_bytes,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = MAX_ETHERNET_FRAME_BYTES;
        capabilities.max_burst_size = Some(1);
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

fn validate_frame_length(length: usize) -> Result<(), DeviceQueueError> {
    if !(MIN_ETHERNET_FRAME_BYTES..=MAX_ETHERNET_FRAME_BYTES).contains(&length) {
        Err(DeviceQueueError::InvalidFrameLength(length))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    PublicUnicast,
    Metadata,
    Unspecified,
    Loopback,
    Private,
    Shared,
    LinkLocal,
    Documentation,
    Benchmark,
    Multicast,
    Reserved,
    UniqueLocal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    Address(AddressClass),
    Port,
    Ipv6EgressUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny(DenyReason),
}

/// A payload-free event safe for structured audit logs. Hostnames, DNS labels,
/// HTTP data, and guest payload bytes are intentionally not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressEvent {
    pub address_class: AddressClass,
    pub port: u16,
    pub decision: EgressDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDecision {
    AllowArp,
    AllowDhcp,
    AllowDns,
    AllowTcp { destination: Ipv4Addr, port: u16 },
    Deny(PacketDenyReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDenyReason {
    Malformed,
    SourceMac,
    SourceAddress,
    UnsupportedEtherType,
    Ipv4Fragment,
    UnsupportedProtocol,
    Egress(DenyReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestDatagramKind {
    Dhcp,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestDatagram<'a> {
    pub kind: GuestDatagramKind,
    pub source_mac: [u8; 6],
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

pub fn admitted_guest_datagram(
    frame: &[u8],
    expected_guest_mac: [u8; 6],
) -> Result<GuestDatagram<'_>, PacketDenyReason> {
    let decision = inspect_guest_ethernet(frame, expected_guest_mac);
    let kind = match decision {
        PacketDecision::AllowDhcp => GuestDatagramKind::Dhcp,
        PacketDecision::AllowDns => GuestDatagramKind::Dns,
        PacketDecision::Deny(reason) => return Err(reason),
        _ => return Err(PacketDenyReason::UnsupportedProtocol),
    };
    let ip = &frame[14..];
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let udp = &ip[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let source_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let destination_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum != 0 && udp_checksum(source_ip, destination_ip, &udp[..udp_len]) != 0 {
        return Err(PacketDenyReason::Malformed);
    }
    Ok(GuestDatagram {
        kind,
        source_mac: expected_guest_mac,
        source_ip,
        destination_ip,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..udp_len],
    })
}

pub fn build_udp_ethernet_response(
    datagram: GuestDatagram<'_>,
    gateway_mac: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>, PacketDenyReason> {
    let (source_ip, destination_ip, source_port, destination_port, destination_mac): (
        Ipv4Addr,
        Ipv4Addr,
        u16,
        u16,
        [u8; 6],
    ) = match datagram.kind {
        GuestDatagramKind::Dhcp => (GATEWAY_IPV4, Ipv4Addr::BROADCAST, 67, 68, [0xff; 6]),
        GuestDatagramKind::Dns => (
            GATEWAY_IPV4,
            GUEST_IPV4,
            53,
            datagram.source_port,
            datagram.source_mac,
        ),
    };
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(PacketDenyReason::Malformed)?;
    let ip_len = 20_usize
        .checked_add(udp_len)
        .ok_or(PacketDenyReason::Malformed)?;
    let frame_len = 14_usize
        .checked_add(ip_len)
        .ok_or(PacketDenyReason::Malformed)?;
    if frame_len > MAX_ETHERNET_FRAME_BYTES || udp_len > usize::from(u16::MAX) {
        return Err(PacketDenyReason::Malformed);
    }
    let mut frame = vec![0; frame_len];
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&gateway_mac);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&destination_ip.octets());
    let ip_checksum = ipv4_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let udp = &mut ip[20..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = udp_checksum(source_ip, destination_ip, udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
    Ok(frame)
}

/// Fail-closed L2 admission before a frame is handed to DHCP, DNS, or TCP
/// state. The guest has one fixed MAC and IPv4 identity; VLAN, IPv6, IP
/// fragments, raw protocols, arbitrary UDP, and resolver bypass are rejected.
pub fn inspect_guest_ethernet(frame: &[u8], expected_guest_mac: [u8; 6]) -> PacketDecision {
    if !(MIN_ETHERNET_FRAME_BYTES..=MAX_ETHERNET_FRAME_BYTES).contains(&frame.len()) {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    if frame[6..12] != expected_guest_mac {
        return PacketDecision::Deny(PacketDenyReason::SourceMac);
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => inspect_arp(&frame[14..], expected_guest_mac),
        0x0800 => inspect_ipv4(&frame[14..]),
        _ => PacketDecision::Deny(PacketDenyReason::UnsupportedEtherType),
    }
}

fn inspect_arp(packet: &[u8], expected_guest_mac: [u8; 6]) -> PacketDecision {
    if packet.len() < 28
        || packet[0..2] != [0, 1]
        || packet[2..4] != [0x08, 0]
        || packet[4] != 6
        || packet[5] != 4
        || packet[6..8] != [0, 1]
        || packet[8..14] != expected_guest_mac
        || packet[14..18] != GUEST_IPV4.octets()
        || packet[24..28] != GATEWAY_IPV4.octets()
    {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    PacketDecision::AllowArp
}

fn inspect_ipv4(packet: &[u8]) -> PacketDecision {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20
        || header_len > packet.len()
        || total_len < header_len
        || total_len > packet.len()
        || ipv4_checksum(&packet[..header_len]) != 0
    {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return PacketDecision::Deny(PacketDenyReason::Ipv4Fragment);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let transport = &packet[header_len..total_len];
    match packet[9] {
        6 => {
            if source != GUEST_IPV4 || transport.len() < 20 {
                return PacketDecision::Deny(PacketDenyReason::SourceAddress);
            }
            let port = u16::from_be_bytes([transport[2], transport[3]]);
            match evaluate_tcp_connect(IpAddr::V4(destination), port) {
                EgressDecision::Allow => PacketDecision::AllowTcp { destination, port },
                EgressDecision::Deny(reason) => {
                    PacketDecision::Deny(PacketDenyReason::Egress(reason))
                }
            }
        }
        17 => inspect_udp(source, destination, transport),
        _ => PacketDecision::Deny(PacketDenyReason::UnsupportedProtocol),
    }
}

fn inspect_udp(source: Ipv4Addr, destination: Ipv4Addr, packet: &[u8]) -> PacketDecision {
    if packet.len() < 8 {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
    let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if length < 8 || length > packet.len() {
        return PacketDecision::Deny(PacketDenyReason::Malformed);
    }
    if source_port == 68
        && destination_port == 67
        && matches!(source, GUEST_IPV4 | Ipv4Addr::UNSPECIFIED)
        && matches!(destination, GATEWAY_IPV4 | Ipv4Addr::BROADCAST)
    {
        return PacketDecision::AllowDhcp;
    }
    if source == GUEST_IPV4 && destination == GATEWAY_IPV4 && destination_port == 53 {
        return PacketDecision::AllowDns;
    }
    if source != GUEST_IPV4 {
        PacketDecision::Deny(PacketDenyReason::SourceAddress)
    } else {
        PacketDecision::Deny(PacketDenyReason::UnsupportedProtocol)
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for bytes in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, packet: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for bytes in source.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    }
    for bytes in destination.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    }
    sum += 17;
    sum += packet.len() as u32;
    for bytes in packet.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    }
    if let Some(last) = packet.chunks_exact(2).remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

/// Classifies an address without performing DNS or another implicit lookup.
/// IPv4-mapped IPv6 is reduced to the embedded IPv4 address so it cannot bypass
/// IPv4 private/special-use checks.
pub fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_v4(address),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => classify_v4(mapped),
            None => classify_v6(address),
        },
    }
}

/// Applies the exact policy used when admitting a DNS answer. IPv6 answers are
/// classified but rejected until the packet data plane implements IPv6.
pub fn evaluate_dns_answer(address: IpAddr) -> EgressDecision {
    evaluate_address(address)
}

/// Applies the Phase 1 restricted-default policy to the actual numeric TCP
/// destination. Callers must not substitute a hostname or a cached verdict.
pub fn evaluate_tcp_connect(address: IpAddr, port: u16) -> EgressDecision {
    let address_decision = evaluate_address(address);
    if address_decision != EgressDecision::Allow {
        return address_decision;
    }
    if !matches!(port, 80 | 443) {
        return EgressDecision::Deny(DenyReason::Port);
    }
    EgressDecision::Allow
}

const PROXY_TICK: Duration = Duration::from_millis(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DNS_IN_FLIGHT: usize = 16;
const IO_CHUNK_BYTES: usize = 16 * 1024;
const MAX_GUEST_OUTPUT_FRAMES: usize = 64;
const MAX_GUEST_OUTPUT_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub enum RestrictedProxyError {
    Configuration(&'static str),
    Io(io::Error),
    Framing(FrameError),
    Tcp(TcpProxyError),
    GuestOutputCapacity,
}

impl std::fmt::Display for RestrictedProxyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "restricted proxy I/O: {error}"),
            Self::Framing(error) => write!(formatter, "restricted proxy framing: {error}"),
            Self::Tcp(error) => write!(formatter, "restricted proxy TCP: {error}"),
            Self::GuestOutputCapacity => {
                formatter.write_str("restricted proxy guest output capacity exhausted")
            }
        }
    }
}

impl std::error::Error for RestrictedProxyError {}

impl From<io::Error> for RestrictedProxyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FrameError> for RestrictedProxyError {
    fn from(value: FrameError) -> Self {
        Self::Framing(value)
    }
}

impl From<TcpProxyError> for RestrictedProxyError {
    fn from(value: TcpProxyError) -> Self {
        Self::Tcp(value)
    }
}

struct HostConnection {
    stream: TcpStream,
    to_host: VecDeque<u8>,
    to_guest: VecDeque<u8>,
    host_eof: bool,
    guest_shutdown: bool,
}

struct DnsResult {
    request_frame: Vec<u8>,
    response: Vec<u8>,
}

/// Runs one fail-closed restricted-default data plane over libkrun's framed
/// Unix stream. All host connects are numeric, every destination is classified
/// again by `TcpProxyCore`, and all queues and concurrent work are bounded.
/// EOF or any framing/capacity fault tears down this VM's network endpoint.
pub async fn run_restricted_proxy(
    stream: UnixStream,
    resolvers: Vec<Ipv4Addr>,
    dns_over_https_name: Option<String>,
    proxy_limits: ProxyLimits,
) -> Result<(), RestrictedProxyError> {
    validate_resolvers(&resolvers)?;
    validate_dns_over_https_name(dns_over_https_name.as_deref())?;
    stream.set_nonblocking(true)?;
    let stream = TokioUnixStream::from_std(stream)?;
    let mut decoder = UnixStreamFrameDecoder::default();
    let mut tcp = TcpProxyCore::new(
        GUEST_MAC,
        GATEWAY_MAC,
        DeviceLimits::default(),
        proxy_limits,
    )?;
    let mut host_connections = BTreeMap::<ConnectionId, HostConnection>::new();
    let mut output = VecDeque::<Vec<u8>>::new();
    let mut output_bytes = 0_usize;
    let mut output_offset = 0_usize;
    let (dial_tx, mut dial_rx) = mpsc::channel(proxy_limits.max_connections);
    let dial_admission = Arc::new(Semaphore::new(proxy_limits.max_connections));
    let (dns_tx, mut dns_rx) = mpsc::channel(MAX_DNS_IN_FLIGHT);
    let dns_admission = Arc::new(Semaphore::new(MAX_DNS_IN_FLIGHT));
    let mut resolver_index = 0_usize;
    let mut tick = interval(PROXY_TICK);
    let started = std::time::Instant::now();
    let mut read_buffer = [0_u8; 8 * 1024];

    loop {
        tokio::select! {
            readable = stream.readable() => {
                readable?;
                match stream.try_read(&mut read_buffer) {
                    Ok(0) => {
                        decoder.finish()?;
                        return Ok(());
                    }
                    Ok(read) => {
                        for frame in decoder.push(&read_buffer[..read])? {
                            match inspect_guest_ethernet(&frame, GUEST_MAC) {
                                PacketDecision::AllowDhcp => {
                                    let datagram = admitted_guest_datagram(&frame, GUEST_MAC)
                                        .map_err(|_| RestrictedProxyError::Configuration("admitted DHCP frame failed decoding"))?;
                                    let request = match inspect_dhcp_request(datagram.payload, GUEST_MAC) {
                                        Ok(request) => request,
                                        Err(_) => continue,
                                    };
                                    let payload = build_dhcp_response(request, GUEST_MAC);
                                    let response = build_udp_ethernet_response(datagram, GATEWAY_MAC, &payload)
                                        .map_err(|_| RestrictedProxyError::Configuration("DHCP response exceeded frame bounds"))?;
                                    queue_guest_frame(&mut output, &mut output_bytes, response)?;
                                }
                                PacketDecision::AllowDns => {
                                    let datagram = admitted_guest_datagram(&frame, GUEST_MAC)
                                        .map_err(|_| RestrictedProxyError::Configuration("admitted DNS frame failed decoding"))?;
                                    let query = match inspect_dns_query(datagram.payload) {
                                        Ok(query) => query,
                                        Err(_) => continue,
                                    };
                                    if query.question_type == DnsQuestionType::Aaaa {
                                        if let Ok(payload) = build_dns_nodata_response(datagram.payload)
                                            && let Ok(response) = build_udp_ethernet_response(
                                                datagram,
                                                GATEWAY_MAC,
                                                &payload,
                                            )
                                        {
                                            queue_guest_frame(
                                                &mut output,
                                                &mut output_bytes,
                                                response,
                                            )?;
                                        }
                                        continue;
                                    }
                                    let Ok(permit) = Arc::clone(&dns_admission).try_acquire_owned() else {
                                        continue;
                                    };
                                    let resolver = resolvers[resolver_index % resolvers.len()];
                                    resolver_index = resolver_index.wrapping_add(1);
                                    let dns_over_https_name = dns_over_https_name.clone();
                                    let request_frame = frame.clone();
                                    let request = datagram.payload.to_vec();
                                    let sender = dns_tx.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Ok(response) = forward_dns(
                                            resolver,
                                            dns_over_https_name.as_deref(),
                                            request,
                                            query,
                                        ).await {
                                            let _ = sender.try_send(DnsResult { request_frame, response });
                                        }
                                    });
                                }
                                PacketDecision::AllowArp | PacketDecision::AllowTcp { .. } => {
                                    // Malformed guest traffic is dropped; only framing and host-side
                                    // invariant failures terminate the network endpoint.
                                    let _ = tcp.enqueue_guest_frame(frame);
                                }
                                PacketDecision::Deny(_) => {}
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Some((id, result)) = dial_rx.recv() => {
                match result {
                    Ok(stream) => {
                        host_connections.insert(id, HostConnection {
                            stream,
                            to_host: VecDeque::new(),
                            to_guest: VecDeque::new(),
                            host_eof: false,
                            guest_shutdown: false,
                        });
                    }
                    Err(()) => { let _ = tcp.abort(id); }
                }
            }
            Some(result) = dns_rx.recv() => {
                if let Ok(datagram) = admitted_guest_datagram(&result.request_frame, GUEST_MAC)
                    && let Ok(response) = build_udp_ethernet_response(datagram, GATEWAY_MAC, &result.response)
                {
                    queue_guest_frame(&mut output, &mut output_bytes, response)?;
                }
            }
            _ = tick.tick() => {
                let now = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
                for event in tcp.poll(now)? {
                    match event {
                        TcpProxyEvent::Dial { id, target } => {
                            let Ok(permit) = Arc::clone(&dial_admission).try_acquire_owned() else {
                                let _ = tcp.abort(id);
                                continue;
                            };
                            let sender = dial_tx.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let result = timeout(
                                    CONNECT_TIMEOUT,
                                    TcpStream::connect(SocketAddr::V4(target)),
                                )
                                .await
                                .ok()
                                .and_then(Result::ok)
                                .ok_or(());
                                let _ = sender.try_send((id, result));
                            });
                        }
                        TcpProxyEvent::Closed { id } => { host_connections.remove(&id); }
                    }
                }
                pump_host_connections(&mut tcp, &mut host_connections).await;
                while let Some(frame) = tcp.dequeue_guest_bound_frame() {
                    queue_guest_frame(&mut output, &mut output_bytes, frame)?;
                }
                flush_guest_output(&stream, &mut output, &mut output_bytes, &mut output_offset)?;
            }
        }
    }
}

/// Worker-thread entry point. The runtime is current-thread only, so all
/// packet, DNS and host-socket state remains in one bounded ownership domain.
pub fn run_restricted_proxy_blocking(
    stream: UnixStream,
    resolvers: Vec<Ipv4Addr>,
    dns_over_https_name: Option<String>,
    proxy_limits: ProxyLimits,
) -> Result<(), RestrictedProxyError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(RestrictedProxyError::Io)?
        .block_on(run_restricted_proxy(
            stream,
            resolvers,
            dns_over_https_name,
            proxy_limits,
        ))
}

/// Starts the proxy and waits until its single-thread Tokio runtime exists.
/// The returned handle owns no additional guest descriptor: dropping or
/// crashing the thread closes only the proxy peer and therefore fails closed.
pub fn spawn_restricted_proxy(
    stream: UnixStream,
    resolvers: Vec<Ipv4Addr>,
    dns_over_https_name: Option<String>,
    proxy_limits: ProxyLimits,
) -> Result<std::thread::JoinHandle<()>, RestrictedProxyError> {
    validate_resolvers(&resolvers)?;
    validate_dns_over_https_name(dns_over_https_name.as_deref())?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("boxd-net-restricted".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            let _ = runtime.block_on(run_restricted_proxy(
                stream,
                resolvers,
                dns_over_https_name,
                proxy_limits,
            ));
        })?;
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(_)) => {
            let _ = handle.join();
            Err(RestrictedProxyError::Configuration(
                "restricted proxy runtime initialization failed",
            ))
        }
        Err(_) => Err(RestrictedProxyError::Configuration(
            "restricted proxy readiness timed out",
        )),
    }
}

fn validate_resolvers(resolvers: &[Ipv4Addr]) -> Result<(), RestrictedProxyError> {
    if resolvers.is_empty()
        || resolvers.len() > 3
        || resolvers
            .iter()
            .any(|address| classify_address(IpAddr::V4(*address)) != AddressClass::PublicUnicast)
        || resolvers
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != resolvers.len()
    {
        Err(RestrictedProxyError::Configuration(
            "restricted proxy requires one to three unique public IPv4 resolvers",
        ))
    } else {
        Ok(())
    }
}

fn validate_dns_over_https_name(value: Option<&str>) -> Result<(), RestrictedProxyError> {
    if value.is_none_or(|name| {
        name.len() <= 253
            && name.contains('.')
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    }) {
        Ok(())
    } else {
        Err(RestrictedProxyError::Configuration(
            "DNS-over-HTTPS authority must be a canonical ASCII hostname",
        ))
    }
}

async fn forward_dns(
    resolver: Ipv4Addr,
    dns_over_https_name: Option<&str>,
    request: Vec<u8>,
    query: DnsQuery,
) -> Result<Vec<u8>, ()> {
    if let Some(name) = dns_over_https_name {
        return forward_dns_over_https(resolver, name, request, query).await;
    }
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|_| ())?;
    socket
        .connect(SocketAddrV4::new(resolver, 53))
        .await
        .map_err(|_| ())?;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
    let read = timeout(DNS_TIMEOUT, async {
        socket.send(&request).await?;
        socket.recv(&mut response).await
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    response.truncate(read);
    validate_and_clamp_dns_response(&mut response, &query).map_err(|_| ())?;
    Ok(response)
}

async fn forward_dns_over_https(
    resolver: Ipv4Addr,
    name: &str,
    request: Vec<u8>,
    query: DnsQuery,
) -> Result<Vec<u8>, ()> {
    let address = SocketAddr::V4(SocketAddrV4::new(resolver, 443));
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(DNS_TIMEOUT)
        .resolve(name, address)
        .build()
        .map_err(|_| ())?;
    let mut upstream = client
        .post(format!("https://{name}/dns-query"))
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .body(request)
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let mut response = Vec::with_capacity(MAX_DNS_MESSAGE_BYTES);
    while let Some(chunk) = upstream.chunk().await.map_err(|_| ())? {
        if response.len().saturating_add(chunk.len()) > MAX_DNS_MESSAGE_BYTES {
            return Err(());
        }
        response.extend_from_slice(&chunk);
    }
    validate_and_clamp_dns_response(&mut response, &query).map_err(|_| ())?;
    Ok(response)
}

async fn pump_host_connections(
    tcp: &mut TcpProxyCore,
    connections: &mut BTreeMap<ConnectionId, HostConnection>,
) {
    let ids: Vec<_> = connections.keys().copied().collect();
    let mut remove = Vec::new();
    for id in ids {
        let Some(connection) = connections.get_mut(&id) else {
            continue;
        };
        let mut buffer = [0_u8; IO_CHUNK_BYTES];
        if connection.to_host.len() < IO_CHUNK_BYTES {
            match tcp.take_guest_payload(id, &mut buffer) {
                Ok(read) => connection.to_host.extend(&buffer[..read]),
                Err(TcpProxyError::UnknownConnection) => {
                    remove.push(id);
                    continue;
                }
                Err(_) => {
                    let _ = tcp.abort(id);
                    continue;
                }
            }
        }
        if !connection.to_host.is_empty() {
            let (first, _) = connection.to_host.as_slices();
            match connection.stream.try_write(first) {
                Ok(written) => {
                    connection.to_host.drain(..written);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    let _ = tcp.abort(id);
                    continue;
                }
            }
        }
        if connection.to_guest.is_empty() && !connection.host_eof {
            match connection.stream.try_read(&mut buffer) {
                Ok(0) => {
                    connection.host_eof = true;
                    let _ = tcp.host_eof(id);
                }
                Ok(read) => connection.to_guest.extend(&buffer[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    connection.host_eof = true;
                    let _ = tcp.host_eof(id);
                }
            }
        }
        if !connection.to_guest.is_empty() {
            let (first, _) = connection.to_guest.as_slices();
            match tcp.send_host_payload(id, first) {
                Ok(written) => {
                    connection.to_guest.drain(..written);
                }
                Err(_) => {
                    let _ = tcp.abort(id);
                    continue;
                }
            }
        }
        if !connection.guest_shutdown
            && connection.to_host.is_empty()
            && tcp.guest_write_closed(id).unwrap_or(false)
        {
            let _ = connection.stream.shutdown().await;
            connection.guest_shutdown = true;
        }
    }
    for id in remove {
        connections.remove(&id);
    }
}

fn queue_guest_frame(
    output: &mut VecDeque<Vec<u8>>,
    output_bytes: &mut usize,
    frame: Vec<u8>,
) -> Result<(), RestrictedProxyError> {
    let encoded_len = 4 + frame.len();
    if output.len() == MAX_GUEST_OUTPUT_FRAMES
        || output_bytes.saturating_add(encoded_len) > MAX_GUEST_OUTPUT_BYTES
    {
        return Err(RestrictedProxyError::GuestOutputCapacity);
    }
    let mut encoded = Vec::with_capacity(encoded_len);
    encoded.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&frame);
    *output_bytes += encoded.len();
    output.push_back(encoded);
    Ok(())
}

fn flush_guest_output(
    stream: &TokioUnixStream,
    output: &mut VecDeque<Vec<u8>>,
    output_bytes: &mut usize,
    offset: &mut usize,
) -> Result<(), RestrictedProxyError> {
    while let Some(frame) = output.front() {
        match stream.try_write(&frame[*offset..]) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "network peer closed").into());
            }
            Ok(written) => {
                *offset += written;
                if *offset == frame.len() {
                    *output_bytes -= frame.len();
                    output.pop_front();
                    *offset = 0;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn event_for_tcp_connect(address: IpAddr, port: u16) -> EgressEvent {
    EgressEvent {
        address_class: classify_address(address),
        port,
        decision: evaluate_tcp_connect(address, port),
    }
}

fn evaluate_address(address: IpAddr) -> EgressDecision {
    let class = classify_address(address);
    if class != AddressClass::PublicUnicast {
        return EgressDecision::Deny(DenyReason::Address(class));
    }
    if address.is_ipv6() && address.to_canonical().is_ipv6() {
        return EgressDecision::Deny(DenyReason::Ipv6EgressUnsupported);
    }
    EgressDecision::Allow
}

fn classify_v4(address: Ipv4Addr) -> AddressClass {
    let octets = address.octets();
    if matches!(
        octets,
        [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200]
    ) {
        return AddressClass::Metadata;
    }
    if address.is_unspecified() || in_v4(octets, [0, 0, 0, 0], 8) {
        AddressClass::Unspecified
    } else if address.is_loopback() {
        AddressClass::Loopback
    } else if address.is_private() {
        AddressClass::Private
    } else if in_v4(octets, [100, 64, 0, 0], 10) {
        AddressClass::Shared
    } else if address.is_link_local() {
        AddressClass::LinkLocal
    } else if in_v4(octets, [192, 0, 2, 0], 24)
        || in_v4(octets, [198, 51, 100, 0], 24)
        || in_v4(octets, [203, 0, 113, 0], 24)
    {
        AddressClass::Documentation
    } else if in_v4(octets, [198, 18, 0, 0], 15) {
        AddressClass::Benchmark
    } else if address.is_multicast() {
        AddressClass::Multicast
    } else if in_v4(octets, [192, 0, 0, 0], 24)
        || in_v4(octets, [192, 88, 99, 0], 24)
        || octets[0] >= 240
    {
        AddressClass::Reserved
    } else {
        AddressClass::PublicUnicast
    }
}

fn classify_v6(address: Ipv6Addr) -> AddressClass {
    let segments = address.segments();
    if address == "fd00:ec2::254".parse::<Ipv6Addr>().expect("constant IPv6")
        || address
            == "fe80::a9fe:a9fe"
                .parse::<Ipv6Addr>()
                .expect("constant IPv6")
    {
        return AddressClass::Metadata;
    }
    if address.is_unspecified() {
        AddressClass::Unspecified
    } else if address.is_loopback() {
        AddressClass::Loopback
    } else if segments[0] & 0xfe00 == 0xfc00 {
        AddressClass::UniqueLocal
    } else if segments[0] & 0xffc0 == 0xfe80 {
        AddressClass::LinkLocal
    } else if segments[0] & 0xff00 == 0xff00 {
        AddressClass::Multicast
    } else if in_v6(address, "2001:db8::".parse().expect("constant IPv6"), 32) {
        AddressClass::Documentation
    } else if in_v6(address, "2001:2::".parse().expect("constant IPv6"), 48) {
        AddressClass::Benchmark
    } else if in_v6(address, "100::".parse().expect("constant IPv6"), 64)
        || in_v6(address, "2001::".parse().expect("constant IPv6"), 23)
        || in_v6(address, "2002::".parse().expect("constant IPv6"), 16)
        || segments[0] & 0xe000 != 0x2000
    {
        AddressClass::Reserved
    } else {
        AddressClass::PublicUnicast
    }
}

fn in_v4(address: [u8; 4], network: [u8; 4], prefix: u8) -> bool {
    let address = u32::from_be_bytes(address);
    let network = u32::from_be_bytes(network);
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    address & mask == network & mask
}

fn in_v6(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let address = u128::from_be_bytes(address.octets());
    let network = u128::from_be_bytes(network.octets());
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    address & mask == network & mask
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidLength(usize),
    Truncated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(length) => {
                write!(formatter, "invalid ethernet frame length {length}")
            }
            Self::Truncated => formatter.write_str("truncated unix-stream ethernet frame"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Incremental decoder for libkrun's `u32 big-endian length || Ethernet II`
/// stream. It never buffers more than one bounded frame, even if a caller feeds
/// an arbitrarily large input slice.
#[derive(Debug, Default)]
pub struct UnixStreamFrameDecoder {
    header: [u8; 4],
    header_len: usize,
    payload: Vec<u8>,
    expected_payload: Option<usize>,
}

impl UnixStreamFrameDecoder {
    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut frames = Vec::new();
        while !input.is_empty() {
            if self.expected_payload.is_none() {
                let take = (4 - self.header_len).min(input.len());
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&input[..take]);
                self.header_len += take;
                input = &input[take..];
                if self.header_len == 4 {
                    let length = u32::from_be_bytes(self.header) as usize;
                    if !(MIN_ETHERNET_FRAME_BYTES..=MAX_ETHERNET_FRAME_BYTES).contains(&length) {
                        self.reset();
                        return Err(FrameError::InvalidLength(length));
                    }
                    self.payload = Vec::with_capacity(length);
                    self.expected_payload = Some(length);
                }
            }
            if let Some(expected) = self.expected_payload {
                let take = (expected - self.payload.len()).min(input.len());
                self.payload.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.payload.len() == expected {
                    frames.push(std::mem::take(&mut self.payload));
                    self.header_len = 0;
                    self.expected_payload = None;
                }
            }
        }
        Ok(frames)
    }

    pub fn finish(self) -> Result<(), FrameError> {
        if self.header_len == 0 && self.expected_payload.is_none() {
            Ok(())
        } else {
            Err(FrameError::Truncated)
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.header_len + self.payload.len()
    }

    fn reset(&mut self) {
        self.header_len = 0;
        self.payload.clear();
        self.expected_payload = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address")
    }

    #[test]
    fn rejects_every_ipv4_special_use_class_and_metadata() {
        let cases = [
            ("0.0.0.0", AddressClass::Unspecified),
            ("10.1.2.3", AddressClass::Private),
            ("100.64.0.1", AddressClass::Shared),
            ("100.100.100.200", AddressClass::Metadata),
            ("127.0.0.1", AddressClass::Loopback),
            ("169.254.169.254", AddressClass::Metadata),
            ("169.254.170.2", AddressClass::Metadata),
            ("172.31.255.255", AddressClass::Private),
            ("192.0.0.1", AddressClass::Reserved),
            ("192.0.2.1", AddressClass::Documentation),
            ("192.168.1.1", AddressClass::Private),
            ("198.18.0.1", AddressClass::Benchmark),
            ("198.51.100.1", AddressClass::Documentation),
            ("203.0.113.1", AddressClass::Documentation),
            ("224.0.0.1", AddressClass::Multicast),
            ("255.255.255.255", AddressClass::Reserved),
        ];
        for (address, class) in cases {
            let address = ip(address);
            assert_eq!(classify_address(address), class, "{address}");
            assert_eq!(
                evaluate_tcp_connect(address, 443),
                EgressDecision::Deny(DenyReason::Address(class)),
                "{address}"
            );
        }
    }

    #[test]
    fn mapped_ipv4_cannot_bypass_classification() {
        assert_eq!(
            classify_address(ip("::ffff:127.0.0.1")),
            AddressClass::Loopback
        );
        assert_eq!(
            classify_address(ip("::ffff:169.254.169.254")),
            AddressClass::Metadata
        );
        assert_eq!(
            evaluate_dns_answer(ip("::ffff:10.0.0.1")),
            EgressDecision::Deny(DenyReason::Address(AddressClass::Private))
        );
        assert_eq!(
            evaluate_tcp_connect(ip("::ffff:1.1.1.1"), 443),
            EgressDecision::Allow
        );
    }

    #[test]
    fn classifies_ipv6_but_rejects_ipv6_egress() {
        let cases = [
            ("::", AddressClass::Unspecified),
            ("::1", AddressClass::Loopback),
            ("fd00:ec2::254", AddressClass::Metadata),
            ("fc00::1", AddressClass::UniqueLocal),
            ("fe80::1", AddressClass::LinkLocal),
            ("2001:db8::1", AddressClass::Documentation),
            ("2001:2::1", AddressClass::Benchmark),
            ("ff02::1", AddressClass::Multicast),
            ("2001:4860:4860::8888", AddressClass::PublicUnicast),
        ];
        for (address, class) in cases {
            assert_eq!(classify_address(ip(address)), class, "{address}");
        }
        assert_eq!(
            evaluate_dns_answer(ip("2001:4860:4860::8888")),
            EgressDecision::Deny(DenyReason::Ipv6EgressUnsupported)
        );
    }

    #[test]
    fn only_public_ipv4_http_and_https_are_allowed() {
        assert_eq!(evaluate_dns_answer(ip("1.1.1.1")), EgressDecision::Allow);
        assert_eq!(
            evaluate_tcp_connect(ip("1.1.1.1"), 80),
            EgressDecision::Allow
        );
        assert_eq!(
            evaluate_tcp_connect(ip("8.8.8.8"), 443),
            EgressDecision::Allow
        );
        assert_eq!(
            evaluate_tcp_connect(ip("1.1.1.1"), 53),
            EgressDecision::Deny(DenyReason::Port)
        );
    }

    #[test]
    fn audit_event_cannot_contain_hostname_or_payload() {
        let event = event_for_tcp_connect(ip("169.254.169.254"), 80);
        assert_eq!(event.address_class, AddressClass::Metadata);
        assert_eq!(
            event.decision,
            EgressDecision::Deny(DenyReason::Address(AddressClass::Metadata))
        );
        let debug = format!("{event:?}");
        assert!(!debug.contains("169.254"));
    }

    fn encoded_frame(payload: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(4 + payload.len());
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(payload);
        encoded
    }

    fn ethernet_ipv4(
        source_mac: [u8; 6],
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + transport.len();
        let mut frame = vec![0; 14 + total_len];
        frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&source_mac);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&source.octets());
        ip[16..20].copy_from_slice(&destination.octets());
        let checksum = ipv4_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip[20..].copy_from_slice(transport);
        frame
    }

    fn tcp(destination_port: u16) -> Vec<u8> {
        let mut segment = vec![0; 20];
        segment[..2].copy_from_slice(&40_000_u16.to_be_bytes());
        segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
        segment[12] = 5 << 4;
        segment
    }

    fn udp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut datagram = vec![0; 8];
        datagram[..2].copy_from_slice(&source_port.to_be_bytes());
        datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
        datagram[4..6].copy_from_slice(&8_u16.to_be_bytes());
        datagram
    }

    #[test]
    fn l2_gate_allows_only_fixed_guest_public_http_and_https() {
        let mac = [2, 0, 0, 0, 0, 2];
        for port in [80, 443] {
            let frame = ethernet_ipv4(mac, GUEST_IPV4, Ipv4Addr::new(1, 1, 1, 1), 6, &tcp(port));
            assert_eq!(
                inspect_guest_ethernet(&frame, mac),
                PacketDecision::AllowTcp {
                    destination: Ipv4Addr::new(1, 1, 1, 1),
                    port
                }
            );
        }
        let wrong_mac = ethernet_ipv4(
            [2, 0, 0, 0, 0, 3],
            GUEST_IPV4,
            Ipv4Addr::new(1, 1, 1, 1),
            6,
            &tcp(443),
        );
        assert_eq!(
            inspect_guest_ethernet(&wrong_mac, mac),
            PacketDecision::Deny(PacketDenyReason::SourceMac)
        );
        let spoofed = ethernet_ipv4(
            mac,
            Ipv4Addr::new(192, 0, 2, 99),
            Ipv4Addr::new(1, 1, 1, 1),
            6,
            &tcp(443),
        );
        assert_eq!(
            inspect_guest_ethernet(&spoofed, mac),
            PacketDecision::Deny(PacketDenyReason::SourceAddress)
        );
    }

    #[test]
    fn l2_gate_rejects_special_targets_ports_fragments_and_ipv6() {
        let mac = [2, 0, 0, 0, 0, 2];
        let metadata = ethernet_ipv4(
            mac,
            GUEST_IPV4,
            Ipv4Addr::new(169, 254, 169, 254),
            6,
            &tcp(80),
        );
        assert_eq!(
            inspect_guest_ethernet(&metadata, mac),
            PacketDecision::Deny(PacketDenyReason::Egress(DenyReason::Address(
                AddressClass::Metadata
            )))
        );
        let ssh = ethernet_ipv4(mac, GUEST_IPV4, Ipv4Addr::new(1, 1, 1, 1), 6, &tcp(22));
        assert_eq!(
            inspect_guest_ethernet(&ssh, mac),
            PacketDecision::Deny(PacketDenyReason::Egress(DenyReason::Port))
        );
        let mut fragment = ethernet_ipv4(mac, GUEST_IPV4, Ipv4Addr::new(1, 1, 1, 1), 6, &tcp(443));
        fragment[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
        fragment[24..26].fill(0);
        let checksum = ipv4_checksum(&fragment[14..34]);
        fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            inspect_guest_ethernet(&fragment, mac),
            PacketDecision::Deny(PacketDenyReason::Ipv4Fragment)
        );
        let mut ipv6 = vec![0; MIN_ETHERNET_FRAME_BYTES];
        ipv6[6..12].copy_from_slice(&mac);
        ipv6[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        assert_eq!(
            inspect_guest_ethernet(&ipv6, mac),
            PacketDecision::Deny(PacketDenyReason::UnsupportedEtherType)
        );
    }

    #[test]
    fn l2_gate_allows_only_virtual_dns_and_dhcp_udp() {
        let mac = [2, 0, 0, 0, 0, 2];
        let dns = ethernet_ipv4(mac, GUEST_IPV4, GATEWAY_IPV4, 17, &udp(40_000, 53));
        assert_eq!(inspect_guest_ethernet(&dns, mac), PacketDecision::AllowDns);
        let external_dns = ethernet_ipv4(
            mac,
            GUEST_IPV4,
            Ipv4Addr::new(8, 8, 8, 8),
            17,
            &udp(40_000, 53),
        );
        assert_eq!(
            inspect_guest_ethernet(&external_dns, mac),
            PacketDecision::Deny(PacketDenyReason::UnsupportedProtocol)
        );
        let dhcp = ethernet_ipv4(
            mac,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            17,
            &udp(68, 67),
        );
        assert_eq!(
            inspect_guest_ethernet(&dhcp, mac),
            PacketDecision::AllowDhcp
        );
    }

    #[test]
    fn admitted_dns_datagram_roundtrips_a_checksum_valid_response_frame() {
        let guest_mac = [2, 0, 0, 0, 0, 2];
        let gateway_mac = [2, 0, 0, 0, 0, 1];
        let query = dns_query(77, 1);
        let mut datagram = udp(40_000, 53);
        datagram[4..6].copy_from_slice(&((8 + query.len()) as u16).to_be_bytes());
        datagram.extend_from_slice(&query);
        let mut frame = ethernet_ipv4(guest_mac, GUEST_IPV4, GATEWAY_IPV4, 17, &datagram);
        frame[..6].copy_from_slice(&gateway_mac);
        let admitted = admitted_guest_datagram(&frame, guest_mac).expect("admitted DNS");
        assert_eq!(admitted.kind, GuestDatagramKind::Dns);
        assert_eq!(admitted.payload, query);
        let response_payload = dns_a_response(77, &[(Ipv4Addr::new(1, 1, 1, 1), 60)]);
        let response = build_udp_ethernet_response(admitted, gateway_mac, &response_payload)
            .expect("response");
        assert_eq!(&response[..6], &guest_mac);
        assert_eq!(ipv4_checksum(&response[14..34]), 0);
        let ip = &response[14..];
        assert_eq!(
            udp_checksum(GATEWAY_IPV4, GUEST_IPV4, &ip[20..]),
            0,
            "UDP response checksum"
        );
        assert_eq!(&ip[28..], response_payload);
    }

    #[test]
    fn admitted_datagram_rejects_bad_udp_checksum_and_oversized_response() {
        let guest_mac = [2, 0, 0, 0, 0, 2];
        let gateway_mac = [2, 0, 0, 0, 0, 1];
        let mut datagram = udp(40_000, 53);
        datagram[6..8].copy_from_slice(&1_u16.to_be_bytes());
        let mut frame = ethernet_ipv4(guest_mac, GUEST_IPV4, GATEWAY_IPV4, 17, &datagram);
        frame[..6].copy_from_slice(&gateway_mac);
        assert_eq!(
            admitted_guest_datagram(&frame, guest_mac),
            Err(PacketDenyReason::Malformed)
        );
        datagram[6..8].fill(0);
        let mut valid = ethernet_ipv4(guest_mac, GUEST_IPV4, GATEWAY_IPV4, 17, &datagram);
        valid[..6].copy_from_slice(&gateway_mac);
        let admitted = admitted_guest_datagram(&valid, guest_mac).expect("valid DNS");
        assert_eq!(
            build_udp_ethernet_response(admitted, gateway_mac, &vec![0; MAX_ETHERNET_FRAME_BYTES]),
            Err(PacketDenyReason::Malformed)
        );
    }

    #[test]
    fn decoder_accepts_fragmented_and_coalesced_frames() {
        let first = vec![0x11; MIN_ETHERNET_FRAME_BYTES];
        let second = vec![0x22; MAX_ETHERNET_FRAME_BYTES];
        let mut encoded = encoded_frame(&first);
        encoded.extend_from_slice(&encoded_frame(&second));
        let mut decoder = UnixStreamFrameDecoder::default();
        let mut frames = Vec::new();
        for chunk in encoded.chunks(3) {
            frames.extend(decoder.push(chunk).expect("valid stream"));
            assert!(decoder.buffered_bytes() <= MAX_ETHERNET_FRAME_BYTES + 4);
        }
        decoder.finish().expect("complete stream");
        assert_eq!(frames, vec![first, second]);
    }

    #[test]
    fn decoder_rejects_invalid_lengths_and_truncation() {
        for length in [
            0,
            MIN_ETHERNET_FRAME_BYTES - 1,
            MAX_ETHERNET_FRAME_BYTES + 1,
            u16::MAX as usize,
        ] {
            let mut decoder = UnixStreamFrameDecoder::default();
            assert_eq!(
                decoder.push(&(length as u32).to_be_bytes()),
                Err(FrameError::InvalidLength(length))
            );
            assert_eq!(decoder.buffered_bytes(), 0);
        }
        let mut decoder = UnixStreamFrameDecoder::default();
        let encoded = encoded_frame(&[0; MIN_ETHERNET_FRAME_BYTES]);
        decoder
            .push(&encoded[..encoded.len() - 1])
            .expect("partial input");
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
    }

    #[test]
    fn bounded_device_applies_frame_byte_and_direction_limits() {
        let limits = DeviceLimits {
            max_ingress_frames: 2,
            max_egress_frames: 1,
            max_buffered_bytes: MAX_ETHERNET_FRAME_BYTES * 3,
        };
        let mut device = BoundedEthernetDevice::new(limits).expect("valid limits");
        let frame = vec![0xaa; MAX_ETHERNET_FRAME_BYTES];
        device
            .enqueue_guest_frame(frame.clone())
            .expect("first ingress");
        device.enqueue_guest_frame(frame).expect("second ingress");
        assert_eq!(
            device.enqueue_guest_frame(vec![0; MIN_ETHERNET_FRAME_BYTES]),
            Err(DeviceQueueError::IngressFull)
        );
        let (rx, tx) = device.receive(Instant::ZERO).expect("device receive");
        assert_eq!(rx.consume(|bytes| bytes.len()), MAX_ETHERNET_FRAME_BYTES);
        assert_eq!(
            tx.consume(MIN_ETHERNET_FRAME_BYTES, |bytes| {
                bytes.fill(0xbb);
                bytes.len()
            }),
            MIN_ETHERNET_FRAME_BYTES
        );
        assert!(device.transmit(Instant::ZERO).is_none());
        assert_eq!(device.egress_frames(), 1);
        assert_eq!(
            device.dequeue_guest_bound_frame(),
            Some(vec![0xbb; MIN_ETHERNET_FRAME_BYTES])
        );
        assert_eq!(device.egress_frames(), 0);
        assert!(device.total_buffered_bytes() <= limits.max_buffered_bytes);
    }

    #[test]
    fn bounded_device_rejects_invalid_configuration_and_frames() {
        assert!(matches!(
            BoundedEthernetDevice::new(DeviceLimits {
                max_ingress_frames: 0,
                ..DeviceLimits::default()
            }),
            Err(DeviceQueueError::InvalidLimits)
        ));
        let mut device = BoundedEthernetDevice::new(DeviceLimits::default()).expect("valid");
        assert_eq!(
            device.enqueue_guest_frame(vec![0; MIN_ETHERNET_FRAME_BYTES - 1]),
            Err(DeviceQueueError::InvalidFrameLength(
                MIN_ETHERNET_FRAME_BYTES - 1
            ))
        );
        assert_eq!(device.total_buffered_bytes(), 0);
    }

    #[test]
    fn smoltcp_feature_graph_excludes_platform_and_bypass_features() {
        let metadata = include_str!("../third-party/smoltcp-0.12.0.provenance.json");
        for forbidden in [
            "phy-raw_socket",
            "phy-tuntap_interface",
            "proto-ipv6",
            "socket-raw",
            "socket-icmp",
            "multicast",
        ] {
            assert!(metadata.contains(forbidden));
        }
        assert_eq!(smoltcp::phy::Medium::default(), Medium::Ethernet);
    }

    fn dns_name(labels: &[&str]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in labels {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn dns_query(id: u16, question_type: u16) -> Vec<u8> {
        let mut message = vec![0; 12];
        message[..2].copy_from_slice(&id.to_be_bytes());
        message[2..4].copy_from_slice(&0x0100_u16.to_be_bytes());
        message[4..6].copy_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&dns_name(&["example", "com"]));
        message.extend_from_slice(&question_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message
    }

    fn dns_a_response(id: u16, addresses: &[(Ipv4Addr, u32)]) -> Vec<u8> {
        let mut message = vec![0; 12];
        message[..2].copy_from_slice(&id.to_be_bytes());
        message[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        message[4..6].copy_from_slice(&1_u16.to_be_bytes());
        message[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
        message.extend_from_slice(&dns_name(&["example", "com"]));
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        for (address, ttl) in addresses {
            message.extend_from_slice(&[0xc0, 0x0c]);
            message.extend_from_slice(&1_u16.to_be_bytes());
            message.extend_from_slice(&1_u16.to_be_bytes());
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&4_u16.to_be_bytes());
            message.extend_from_slice(&address.octets());
        }
        message
    }

    #[test]
    fn dns_parser_accepts_one_a_query_and_caps_public_answer_ttl() {
        let query = inspect_dns_query(&dns_query(7, 1)).expect("valid query");
        assert_eq!(
            query,
            DnsQuery {
                id: 7,
                question_type: DnsQuestionType::A,
                canonical_name: dns_name(&["example", "com"])
            }
        );
        let response = dns_a_response(7, &[(Ipv4Addr::new(1, 1, 1, 1), 86_400)]);
        assert_eq!(
            inspect_dns_response(&response, &query),
            Ok(vec![DnsAnswer {
                address: Ipv4Addr::new(1, 1, 1, 1),
                ttl_seconds: MAX_DNS_TTL_SECONDS
            }])
        );
    }

    #[test]
    fn aaaa_query_gets_immediate_transaction_bound_nodata() {
        let request = dns_query(0x1234, 28);
        let response = build_dns_nodata_response(&request).expect("AAAA NODATA");
        assert_eq!(&response[..2], &0x1234_u16.to_be_bytes());
        assert_eq!(dns_u16(&response, 2), Ok(0x8180));
        assert_eq!(dns_u16(&response, 4), Ok(1));
        assert_eq!(dns_u16(&response, 6), Ok(0));
        assert_eq!(dns_u16(&response, 8), Ok(0));
        assert_eq!(dns_u16(&response, 10), Ok(0));
        let expected = inspect_dns_query(&request).expect("query");
        assert_eq!(inspect_dns_response(&response, &expected), Ok(Vec::new()));
    }

    #[test]
    fn dns_response_rejects_rebinding_if_any_answer_is_special() {
        let query = inspect_dns_query(&dns_query(9, 1)).expect("query");
        let response = dns_a_response(
            9,
            &[
                (Ipv4Addr::new(1, 1, 1, 1), 60),
                (Ipv4Addr::new(169, 254, 169, 254), 60),
            ],
        );
        assert_eq!(
            inspect_dns_response(&response, &query),
            Err(DnsError::RejectedAddress(AddressClass::Metadata))
        );
    }

    #[test]
    fn dns_response_rejects_special_additional_records_and_trailing_bytes() {
        let query = inspect_dns_query(&dns_query(10, 1)).expect("query");
        let mut response = dns_a_response(10, &[(Ipv4Addr::new(1, 1, 1, 1), 60)]);
        response[10..12].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            inspect_dns_response(&response, &query),
            Err(DnsError::RejectedAddress(AddressClass::Private))
        );
        let mut trailing = dns_a_response(10, &[(Ipv4Addr::new(1, 1, 1, 1), 60)]);
        trailing.push(0);
        assert_eq!(
            inspect_dns_response(&trailing, &query),
            Err(DnsError::InvalidHeader)
        );
    }

    #[test]
    fn dns_parser_rejects_pointer_loops_truncation_and_oversize() {
        let query = inspect_dns_query(&dns_query(1, 1)).expect("query");
        let mut looped = vec![0; 18];
        looped[..2].copy_from_slice(&1_u16.to_be_bytes());
        looped[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        looped[4..6].copy_from_slice(&1_u16.to_be_bytes());
        looped[12..14].copy_from_slice(&[0xc0, 0x0c]);
        assert_eq!(
            inspect_dns_response(&looped, &query),
            Err(DnsError::CompressionLoop)
        );
        assert_eq!(inspect_dns_query(&[0; 11]), Err(DnsError::Truncated));
        assert_eq!(
            inspect_dns_query(&vec![0; MAX_DNS_MESSAGE_BYTES + 1]),
            Err(DnsError::Oversized)
        );
        let mut many = dns_a_response(1, &[]);
        many[6..8].copy_from_slice(&((MAX_DNS_ANSWERS + 1) as u16).to_be_bytes());
        assert_eq!(
            inspect_dns_response(&many, &query),
            Err(DnsError::TooManyAnswers)
        );
    }

    #[test]
    fn dns_transaction_binds_case_insensitive_question_without_logging_name() {
        let query = inspect_dns_query(&dns_query(12, 1)).expect("query");
        assert!(!format!("{query:?}").contains("example"));
        let mut response = dns_a_response(12, &[(Ipv4Addr::new(1, 1, 1, 1), 60)]);
        response[13..20].copy_from_slice(b"EXAMPLE");
        assert!(inspect_dns_response(&response, &query).is_ok());
        response[13..20].copy_from_slice(b"ATTACKR");
        assert_eq!(
            inspect_dns_response(&response, &query),
            Err(DnsError::MismatchedTransaction)
        );
    }

    #[test]
    fn connection_admission_is_bounded_and_raii_releases() {
        let admission = ConnectionAdmission::new(ProxyLimits {
            max_connections: 2,
            bytes_per_connection: 16 * 1024,
            max_connection_bytes: 32 * 1024,
        })
        .expect("valid limits");
        let mut first = admission.reserve().expect("first");
        let second = admission.reserve().expect("second");
        assert_eq!(admission.reserve().unwrap_err(), AdmissionError::Capacity);
        first.account_bytes(16 * 1024).expect("within limit");
        first.account_bytes(16 * 1024).expect("exact limit");
        assert_eq!(first.transferred_bytes(), 32 * 1024);
        assert_eq!(first.account_bytes(1), Err(AdmissionError::ByteLimit));
        drop(second);
        assert_eq!(admission.active(), 1);
        let replacement = admission.reserve().expect("released slot");
        replacement.release();
        drop(first);
        assert_eq!(admission.active(), 0);
    }

    #[test]
    fn connection_admission_rejects_unbounded_configuration() {
        assert!(matches!(
            ConnectionAdmission::new(ProxyLimits {
                max_connections: 257,
                ..ProxyLimits::default()
            }),
            Err(AdmissionError::InvalidLimits)
        ));
        assert!(matches!(
            ConnectionAdmission::new(ProxyLimits {
                max_connections: 256,
                bytes_per_connection: 1024 * 1024,
                ..ProxyLimits::default()
            }),
            Err(AdmissionError::InvalidLimits)
        ));
    }

    fn dhcp_request(
        kind: u8,
        requested_ip: Option<Ipv4Addr>,
        guest_mac: [u8; 6],
        rapid_commit: bool,
    ) -> Vec<u8> {
        let mut message = vec![0; 240];
        message[0] = 1;
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
        message[28..34].copy_from_slice(&guest_mac);
        message[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        push_dhcp_option(&mut message, 53, &[kind]);
        if rapid_commit {
            push_dhcp_option(&mut message, 80, &[]);
        }
        push_dhcp_option(
            &mut message,
            61,
            &[
                1,
                guest_mac[0],
                guest_mac[1],
                guest_mac[2],
                guest_mac[3],
                guest_mac[4],
                guest_mac[5],
            ],
        );
        if let Some(address) = requested_ip {
            push_dhcp_option(&mut message, 50, &address.octets());
            push_dhcp_option(&mut message, 54, &GATEWAY_IPV4.octets());
        }
        message.push(255);
        message
    }

    #[test]
    fn fixed_dhcp_discover_and_request_emit_offer_and_ack() {
        let mac = [2, 0, 0, 0, 0, 2];
        let discover =
            inspect_dhcp_request(&dhcp_request(1, None, mac, false), mac).expect("discover");
        assert_eq!(discover.kind, DhcpRequestKind::Discover);
        assert!(!discover.rapid_commit);
        let offer = build_dhcp_response(discover, mac);
        assert!(offer.len() <= MAX_DHCP_MESSAGE_BYTES);
        assert_eq!(&offer[16..20], &GUEST_IPV4.octets());
        assert!(offer.windows(3).any(|bytes| bytes == [53, 1, 2]));

        let request = inspect_dhcp_request(&dhcp_request(3, Some(GUEST_IPV4), mac, false), mac)
            .expect("request");
        assert_eq!(request.kind, DhcpRequestKind::Request);
        let ack = build_dhcp_response(request, mac);
        assert!(ack.windows(3).any(|bytes| bytes == [53, 1, 5]));
        assert!(ack.windows(6).any(|bytes| bytes == [6, 4, 192, 0, 2, 1]));

        let rapid =
            inspect_dhcp_request(&dhcp_request(1, None, mac, true), mac).expect("rapid discover");
        assert!(rapid.rapid_commit);
        let rapid_ack = build_dhcp_response(rapid, mac);
        assert!(rapid_ack.windows(3).any(|bytes| bytes == [53, 1, 5]));
        assert!(rapid_ack.windows(2).any(|bytes| bytes == [80, 0]));
    }

    #[test]
    fn fixed_dhcp_rejects_identity_address_unknown_option_and_trailing_data() {
        let mac = [2, 0, 0, 0, 0, 2];
        let other = [2, 0, 0, 0, 0, 3];
        assert_eq!(
            inspect_dhcp_request(&dhcp_request(1, None, other, false), mac),
            Err(DhcpError::InvalidIdentity)
        );
        assert_eq!(
            inspect_dhcp_request(
                &dhcp_request(3, Some(Ipv4Addr::new(192, 0, 2, 9)), mac, false),
                mac
            ),
            Err(DhcpError::AddressMismatch)
        );
        let mut unknown = dhcp_request(1, None, mac, false);
        unknown.pop();
        push_dhcp_option(&mut unknown, 82, &[1]);
        unknown.push(255);
        assert_eq!(
            inspect_dhcp_request(&unknown, mac),
            Err(DhcpError::InvalidOption)
        );
        let mut trailing = dhcp_request(1, None, mac, false);
        trailing.push(1);
        assert_eq!(
            inspect_dhcp_request(&trailing, mac),
            Err(DhcpError::InvalidOption)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restricted_proxy_unixstream_serves_fixed_dhcp_and_closes_on_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (worker, guest) = UnixStream::pair().expect("network pair");
        guest.set_nonblocking(true).expect("nonblocking guest");
        let mut guest = TokioUnixStream::from_std(guest).expect("tokio guest");
        let proxy = tokio::spawn(run_restricted_proxy(
            worker,
            vec![Ipv4Addr::new(1, 1, 1, 1)],
            None,
            ProxyLimits::default(),
        ));

        let payload = dhcp_request(1, None, GUEST_MAC, true);
        let mut udp = udp(68, 67);
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&payload);
        let request = ethernet_ipv4(
            GUEST_MAC,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            17,
            &udp,
        );
        guest
            .write_all(&encoded_frame(&request))
            .await
            .expect("write request");
        let mut header = [0_u8; 4];
        timeout(Duration::from_secs(1), guest.read_exact(&mut header))
            .await
            .expect("DHCP timeout")
            .expect("DHCP header");
        let length = u32::from_be_bytes(header) as usize;
        assert!((MIN_ETHERNET_FRAME_BYTES..=MAX_ETHERNET_FRAME_BYTES).contains(&length));
        let mut response = vec![0_u8; length];
        guest.read_exact(&mut response).await.expect("DHCP frame");
        assert_eq!(&response[..6], &[0xff; 6]);
        assert!(response.windows(3).any(|bytes| bytes == [53, 1, 5]));
        assert!(response.windows(2).any(|bytes| bytes == [80, 0]));
        assert!(
            response
                .windows(6)
                .any(|bytes| bytes == [6, 4, 192, 0, 2, 1])
        );
        drop(guest);
        timeout(Duration::from_secs(1), proxy)
            .await
            .expect("proxy close timeout")
            .expect("proxy task")
            .expect("clean EOF");
    }

    struct GuestTcpHarness {
        device: BoundedEthernetDevice,
        interface: Interface,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
    }

    impl GuestTcpHarness {
        fn new(guest_mac: [u8; 6], target: Ipv4Addr, port: u16) -> Self {
            Self::with_source_port(guest_mac, target, port, 40_000)
        }

        fn with_source_port(
            guest_mac: [u8; 6],
            target: Ipv4Addr,
            port: u16,
            source_port: u16,
        ) -> Self {
            let mut device = BoundedEthernetDevice::new(DeviceLimits::default()).expect("device");
            let mut config =
                InterfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(guest_mac)));
            config.random_seed = 41;
            let mut interface = Interface::new(config, &mut device, Instant::ZERO);
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(IpAddress::from(GUEST_IPV4), 24))
                    .expect("guest address");
            });
            interface
                .routes_mut()
                .add_default_ipv4_route(GATEWAY_IPV4)
                .expect("guest route");
            let mut sockets = SocketSet::new(Vec::new());
            let socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0; 16 * 1024]),
                TcpSocketBuffer::new(vec![0; 16 * 1024]),
            );
            let handle = sockets.add(socket);
            sockets
                .get_mut::<TcpSocket<'_>>(handle)
                .connect(
                    interface.context(),
                    (IpAddress::from(target), port),
                    source_port,
                )
                .expect("guest connect");
            Self {
                device,
                interface,
                sockets,
                handle,
            }
        }

        fn poll(&mut self, now: i64) {
            self.interface.poll(
                Instant::from_millis(now),
                &mut self.device,
                &mut self.sockets,
            );
        }

        fn transfer_to_proxy(&mut self, proxy: &mut TcpProxyCore) {
            while let Some(frame) = self.device.dequeue_guest_bound_frame() {
                proxy
                    .enqueue_guest_frame(frame)
                    .expect("guest frame admitted");
            }
        }

        fn receive_from_proxy(&mut self, proxy: &mut TcpProxyCore) {
            while let Some(frame) = proxy.dequeue_guest_bound_frame() {
                self.device.enqueue_guest_frame(frame).expect("proxy frame");
            }
        }
    }

    #[test]
    fn transparent_tcp_core_emits_numeric_dial_and_roundtrips_payload() {
        let guest_mac = [2, 0, 0, 0, 0, 2];
        let gateway_mac = [2, 0, 0, 0, 0, 1];
        let target = Ipv4Addr::new(1, 1, 1, 1);
        let mut proxy = TcpProxyCore::new(
            guest_mac,
            gateway_mac,
            DeviceLimits::default(),
            ProxyLimits::default(),
        )
        .expect("proxy");
        let mut guest = GuestTcpHarness::new(guest_mac, target, 443);
        let mut dial = None;
        for tick in 0..100 {
            guest.poll(tick);
            guest.transfer_to_proxy(&mut proxy);
            for event in proxy.poll(tick).expect("proxy poll") {
                if let TcpProxyEvent::Dial { id, target } = event {
                    assert_eq!(
                        target,
                        std::net::SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)
                    );
                    dial = Some(id);
                }
            }
            guest.receive_from_proxy(&mut proxy);
            if guest.sockets.get::<TcpSocket<'_>>(guest.handle).state() == TcpState::Established {
                break;
            }
        }
        let id = dial.expect("numeric dial event");
        assert_eq!(proxy.active_connections(), 1);
        assert_eq!(
            guest.sockets.get::<TcpSocket<'_>>(guest.handle).state(),
            TcpState::Established
        );

        guest
            .sockets
            .get_mut::<TcpSocket<'_>>(guest.handle)
            .send_slice(b"guest-to-host")
            .expect("guest send");
        let mut received = [0; 32];
        let mut guest_bytes = 0;
        for tick in 100..200 {
            guest.poll(tick);
            guest.transfer_to_proxy(&mut proxy);
            proxy.poll(tick).expect("proxy poll");
            guest_bytes = proxy
                .take_guest_payload(id, &mut received)
                .expect("host read");
            guest.receive_from_proxy(&mut proxy);
            if guest_bytes != 0 {
                break;
            }
        }
        assert_eq!(&received[..guest_bytes], b"guest-to-host");

        assert_eq!(proxy.send_host_payload(id, b"host-to-guest"), Ok(13));
        let mut host_bytes = [0; 32];
        let mut read = 0;
        for tick in 200..300 {
            proxy.poll(tick).expect("proxy poll");
            guest.receive_from_proxy(&mut proxy);
            guest.poll(tick);
            if guest.sockets.get::<TcpSocket<'_>>(guest.handle).can_recv() {
                read = guest
                    .sockets
                    .get_mut::<TcpSocket<'_>>(guest.handle)
                    .recv_slice(&mut host_bytes)
                    .expect("guest read");
            }
            guest.transfer_to_proxy(&mut proxy);
            if read != 0 {
                break;
            }
        }
        assert_eq!(&host_bytes[..read], b"host-to-guest");
    }

    #[test]
    fn transparent_tcp_capacity_rejects_second_flow_and_abort_releases_slot() {
        let guest_mac = [2, 0, 0, 0, 0, 2];
        let gateway_mac = [2, 0, 0, 0, 0, 1];
        let mut proxy = TcpProxyCore::new(
            guest_mac,
            gateway_mac,
            DeviceLimits::default(),
            ProxyLimits {
                max_connections: 1,
                ..ProxyLimits::default()
            },
        )
        .expect("proxy");
        let mut first =
            GuestTcpHarness::with_source_port(guest_mac, Ipv4Addr::new(1, 1, 1, 1), 443, 40_000);
        let mut first_id = None;
        for tick in 0..100 {
            first.poll(tick);
            first.transfer_to_proxy(&mut proxy);
            for event in proxy.poll(tick).expect("poll") {
                if let TcpProxyEvent::Dial { id, .. } = event {
                    first_id = Some(id);
                }
            }
            first.receive_from_proxy(&mut proxy);
        }
        let first_id = first_id.expect("first dial");
        assert_eq!(proxy.active_connections(), 1);

        let mut second =
            GuestTcpHarness::with_source_port(guest_mac, Ipv4Addr::new(8, 8, 8, 8), 80, 40_001);
        let mut second_dials = 0;
        for tick in 100..200 {
            second.poll(tick);
            second.transfer_to_proxy(&mut proxy);
            second_dials += proxy
                .poll(tick)
                .expect("poll")
                .into_iter()
                .filter(|event| matches!(event, TcpProxyEvent::Dial { .. }))
                .count();
            second.receive_from_proxy(&mut proxy);
        }
        assert_eq!(second_dials, 0);
        assert_eq!(proxy.active_connections(), 1);

        proxy.abort(first_id).expect("abort");
        let events = proxy.poll(201).expect("collect close");
        assert!(events.contains(&TcpProxyEvent::Closed { id: first_id }));
        assert_eq!(proxy.active_connections(), 0);
    }
}
