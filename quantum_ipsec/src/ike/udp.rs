//! Single-peer, blocking UDP transport for the fixed childless handshake.
//! Optional single CHILD_SA; no NAT-T, peer migration or listener pool. The supplied socket is
//! consumed; success returns it with the authenticated session to its owner.
use super::{auth::AuthRole, child::ChildPolicy, PskPolicy, PskSession, SessionState};
use crate::QuantumIpsecError;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use thiserror::Error;

const MAX_DATAGRAM: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct UdpOptions {
    /// Absolute handshake deadline; responder then serves cached replies for
    /// one further timeout interval so a lost final AUTH response can recover.
    pub timeout: Duration,
    pub initial_retry: Duration,
    pub max_retry: Duration,
    /// Entire invocation, including discarded datagrams and responder grace.
    pub max_datagrams: u32,
}
impl Default for UdpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            initial_retry: Duration::from_millis(250),
            max_retry: Duration::from_secs(2),
            max_datagrams: 256,
        }
    }
}
impl UdpOptions {
    fn validate(&self) -> Result<(), UdpError> {
        if self.timeout.is_zero()
            || self.timeout > Duration::from_secs(60)
            || self.initial_retry < Duration::from_millis(10)
            || self.initial_retry > self.max_retry
            || self.max_retry > self.timeout
            || self.max_datagrams == 0
            || self.max_datagrams > 4096
        {
            return Err(UdpError::Configuration);
        }
        Ok(())
    }
}
#[derive(Debug, Error)]
pub enum UdpError {
    #[error("invalid UDP handshake options or peer address (NAT-T is unsupported)")]
    Configuration,
    #[error("IKE UDP negotiation timed out before completing the requested exchanges")]
    Timeout,
    #[error("IKE UDP datagram budget exhausted")]
    DatagramLimit,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] QuantumIpsecError),
}
#[derive(Debug, Default)]
pub struct UdpStats {
    pub received: u32,
    pub discarded: u32,
    pub sent: u32,
    pub timed_retries: u32,
}
#[derive(Debug)]
pub struct AuthenticatedUdp {
    pub session: PskSession,
    pub socket: UdpSocket,
    pub stats: UdpStats,
}

/// Exact endpoint filtering is an admission restriction, never authentication.
/// The session still verifies identities, AUTH and SPI/message-ID correlation.
/// Runs for at most twice `timeout` plus bounded OS scheduling/I/O delay.
/// The returned socket is blocking with timeouts configured by this function.
pub fn handshake(
    socket: UdpSocket,
    peer: SocketAddr,
    role: AuthRole,
    policy: PskPolicy,
    options: UdpOptions,
) -> Result<AuthenticatedUdp, UdpError> {
    run(socket, peer, role, policy, options, None)
}
/// Negotiate and install one policy-authorized ESP pair after mutual IKE AUTH.
/// Uses the same deadline/budget as the handshake, including final reply grace.
pub fn handshake_with_child(
    socket: UdpSocket,
    peer: SocketAddr,
    role: AuthRole,
    policy: PskPolicy,
    child: ChildPolicy,
    options: UdpOptions,
) -> Result<AuthenticatedUdp, UdpError> {
    run(socket, peer, role, policy, options, Some(child))
}
fn run(
    socket: UdpSocket,
    peer: SocketAddr,
    role: AuthRole,
    policy: PskPolicy,
    options: UdpOptions,
    child: Option<ChildPolicy>,
) -> Result<AuthenticatedUdp, UdpError> {
    let needs_child = child.is_some();
    let mut child_started = false;
    options.validate()?;
    let local = socket.local_addr()?;
    if peer.port() == 0
        || peer.port() == 4500
        || local.port() == 4500
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || peer.is_ipv4() != local.is_ipv4()
        || peer == local
        || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(UdpError::Configuration);
    }
    socket.set_nonblocking(false)?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut session = PskSession::new(role, policy, options.timeout * 2 + Duration::from_secs(1))?;
    if let Some(child) = child {
        session.configure_child(child)?;
    }
    let deadline = Instant::now() + options.timeout;
    let mut grace_deadline = None;
    let mut retry_interval = options.initial_retry;
    let mut retry_at = Instant::now() + retry_interval;
    let mut stats = UdpStats::default();
    if role == AuthRole::Initiator {
        send(&socket, peer, &session.start()?, &mut stats)?;
    }
    // Extra byte detects oversize input even when the OS truncates the datagram.
    let mut buffer = [0; MAX_DATAGRAM + 1];
    loop {
        let now = Instant::now();
        let stop = grace_deadline.unwrap_or(deadline);
        if now >= stop {
            if session.state() == SessionState::Authenticated
                && (!needs_child || session.child_established())
            {
                return Ok(AuthenticatedUdp {
                    session,
                    socket,
                    stats,
                });
            }
            return Err(UdpError::Timeout);
        }
        // Check this on every iteration, including under continuous bad traffic.
        if role == AuthRole::Initiator && now >= retry_at {
            if let Some(wire) = session.retransmit()? {
                send(&socket, peer, &wire, &mut stats)?;
                stats.timed_retries += 1;
            }
            retry_interval = (retry_interval * 2).min(options.max_retry);
            retry_at = Instant::now() + retry_interval;
        }
        let wake = if role == AuthRole::Initiator {
            stop.min(retry_at)
        } else {
            stop
        };
        socket.set_read_timeout(Some(
            wake.saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))?;
        let (len, source) = match socket.recv_from(&mut buffer) {
            Ok(packet) => packet,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        };
        // A packet received after the deadline must not extend the handshake.
        if Instant::now() >= stop {
            continue;
        }
        if stats.received >= options.max_datagrams {
            return Err(UdpError::DatagramLimit);
        }
        stats.received += 1;
        if source != peer || len > MAX_DATAGRAM {
            stats.discarded += 1;
            continue;
        }
        let before = session.state();
        let response = match session.receive(&buffer[..len]) {
            Ok(response) => response,
            Err(_) => {
                stats.discarded += 1;
                continue;
            }
        };
        if let Some(wire) = response {
            send(&socket, peer, &wire, &mut stats)?;
        }
        let after = session.state();
        if after == SessionState::Authenticated
            && needs_child
            && role == AuthRole::Initiator
            && !child_started
        {
            send(&socket, peer, &session.start_child()?, &mut stats)?;
            child_started = true;
            retry_interval = options.initial_retry;
            retry_at = Instant::now() + retry_interval;
        }
        if after == SessionState::Authenticated && (!needs_child || session.child_established()) {
            if role == AuthRole::Initiator {
                return Ok(AuthenticatedUdp {
                    session,
                    socket,
                    stats,
                });
            }
            // Duplicates never extend grace. Only the initiator retransmits on
            // a timer; the responder sends cached replies in response to input.
            if grace_deadline.is_none() {
                grace_deadline = Some(Instant::now() + options.timeout);
            }
        } else if before != after {
            retry_interval = options.initial_retry;
            retry_at = Instant::now() + retry_interval;
        }
    }
}
fn send(
    socket: &UdpSocket,
    peer: SocketAddr,
    wire: &[u8],
    stats: &mut UdpStats,
) -> Result<(), UdpError> {
    if socket.send_to(wire, peer)? != wire.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete UDP send").into());
    }
    stats.sent += 1;
    Ok(())
}
