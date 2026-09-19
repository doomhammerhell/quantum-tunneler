use crate::utils::{self, CliError};
use clap::{Args, ValueEnum};
use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ike::{
        auth::AuthRole,
        child::ChildPolicy,
        udp::{handshake, handshake_with_child, UdpOptions},
        PskPolicy,
    },
};
use serde::Serialize;
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Role {
    Initiator,
    Responder,
}
#[derive(Debug, Clone, Args)]
pub struct HandshakeArgs {
    #[arg(long, value_enum)]
    pub role: Role,
    /// Local IP:port; port 0 selects an ephemeral port. NAT-T/4500 unsupported.
    #[arg(long)]
    pub bind: SocketAddr,
    /// Exact permitted remote IP:port. No DNS, roaming or NAT traversal.
    #[arg(long)]
    pub peer: SocketAddr,
    #[arg(long)]
    pub local_id: String,
    #[arg(long)]
    pub peer_id: String,
    /// Negotiate one ESP CHILD_SA for this exact local inner IPv4 host.
    #[arg(long, requires = "peer_inner_ip")]
    pub local_inner_ip: Option<Ipv4Addr>,
    #[arg(long, requires = "local_inner_ip")]
    pub peer_inner_ip: Option<Ipv4Addr>,
    /// Read a 32-byte PSK encoded as 64 hex digits, optional newline, then EOF.
    #[arg(long, required = true)]
    pub psk_stdin: bool,
    /// Handshake deadline; responder also waits this long for final retries.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=60))]
    pub timeout_secs: u64,
}

fn read_psk(mut reader: impl Read) -> Result<SecretBytes<32>, CliError> {
    // Fixed storage avoids reallocating and leaving copies of the encoded PSK.
    let mut encoded = Zeroizing::new([0u8; 67]);
    let mut length = 0;
    while length < encoded.len() {
        match reader.read(&mut encoded[length..]) {
            Ok(0) => break,
            Ok(n) => length += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let input = &encoded[..length];
    let line = input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input);
    if line.len() != 64 {
        return Err(CliError::Other(
            "PSK stdin must contain exactly 64 hex digits and EOF".into(),
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    for (index, pair) in line.chunks_exact(2).enumerate() {
        let high =
            digit(pair[0]).ok_or_else(|| CliError::Other("invalid PSK hex encoding".into()))?;
        let low =
            digit(pair[1]).ok_or_else(|| CliError::Other("invalid PSK hex encoding".into()))?;
        bytes[index] = high * 16 + low;
    }
    Ok(SecretBytes::new(*bytes))
}
#[derive(Debug, Serialize)]
struct Report {
    result: &'static str,
    peer: SocketAddr,
    peer_id: String,
    initiator_spi: String,
    responder_spi: String,
    sent: u32,
    received: u32,
    discarded: u32,
    timed_retries: u32,
    child_sa_established: bool,
    child_inbound_spi: Option<u32>,
    child_outbound_spi: Option<u32>,
    tunnel_established: bool,
    session_retained: bool,
}
pub fn run(args: HandshakeArgs, global: &crate::Cli) -> Result<(), CliError> {
    let psk = read_psk(io::stdin().lock())?;
    let policy = PskPolicy::new(args.local_id.as_bytes(), args.peer_id.as_bytes(), psk)?;
    let socket = UdpSocket::bind(args.bind)?;
    // Public endpoint only: useful for port-zero callers and process supervisors.
    if !global.quiet {
        eprintln!("IKE UDP bound: {}", socket.local_addr()?);
    }
    let timeout = Duration::from_secs(args.timeout_secs);
    let options = UdpOptions {
        timeout,
        max_retry: Duration::from_secs(2).min(timeout),
        ..UdpOptions::default()
    };
    let role = match args.role {
        Role::Initiator => AuthRole::Initiator,
        Role::Responder => AuthRole::Responder,
    };
    let mut result = match (args.local_inner_ip, args.peer_inner_ip) {
        (Some(local), Some(peer)) => handshake_with_child(
            socket,
            args.peer,
            role,
            policy,
            ChildPolicy::new(local, peer)?,
            options,
        ),
        (None, None) => handshake(socket, args.peer, role, policy, options),
        _ => return Err(CliError::Other("both inner IPv4 hosts are required".into())),
    }
    .map_err(|e| CliError::Other(e.to_string()))?;
    let child_sa_established = result.session.child_established();
    let child_spis = result
        .session
        .child_metadata()
        .map(|m| (m[0].spi, m[1].spi));
    let (spii, spir) = result
        .session
        .authenticated_spis()
        .ok_or_else(|| CliError::Other("IKE session expired".into()))?;
    // This command is a handshake probe, not a persistent daemon or VPN.
    result.session.close();
    utils::print_output(
        &Report {
            result: if child_sa_established {
                "authenticated-child-sa"
            } else {
                "authenticated-childless-handshake"
            },
            peer: args.peer,
            peer_id: args.peer_id,
            initiator_spi: format!("{spii:016x}"),
            responder_spi: format!("{spir:016x}"),
            sent: result.stats.sent,
            received: result.stats.received,
            discarded: result.stats.discarded,
            timed_retries: result.stats.timed_retries,
            child_sa_established,
            child_inbound_spi: child_spis.map(|s| s.0),
            child_outbound_spi: child_spis.map(|s| s.1),
            tunnel_established: false,
            session_retained: false,
        },
        &global.output_format,
        global.verbose,
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_psk_input() {
        let hex = "a5".repeat(32);
        for suffix in ["", "\n", "\r\n"] {
            assert_eq!(
                read_psk(format!("{hex}{suffix}").as_bytes())
                    .unwrap()
                    .expose(),
                &[0xa5; 32]
            );
        }
        for text in [
            "a5".repeat(31),
            "a5".repeat(33),
            "gg".repeat(32),
            format!("{hex}\nextra"),
        ] {
            assert!(read_psk(text.as_bytes()).is_err());
        }
    }
}
