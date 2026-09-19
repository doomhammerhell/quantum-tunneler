use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ike::{
        auth::AuthRole,
        udp::{handshake, UdpError, UdpOptions},
        PskPolicy, SessionState,
    },
};
use std::{
    net::UdpSocket,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
fn socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}
fn policy(local: &[u8], peer: &[u8], key: u8) -> PskPolicy {
    PskPolicy::new(local, peer, SecretBytes::new([key; 32])).unwrap()
}
fn options() -> UdpOptions {
    UdpOptions {
        timeout: Duration::from_millis(400),
        initial_retry: Duration::from_millis(20),
        max_retry: Duration::from_millis(80),
        max_datagrams: 256,
    }
}
#[test]
fn loss_recovers_with_exact_requests_and_final_cached_response() {
    let i = socket();
    let r = socket();
    let relay = socket();
    let ia = i.local_addr().unwrap();
    let ra = r.local_addr().unwrap();
    let pa = relay.local_addr().unwrap();
    relay
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let proxy = thread::spawn(move || {
        let mut buf = [0; 4096];
        let mut request_dropped = false;
        let mut auth_dropped = false;
        let mut originals = std::collections::HashMap::new();
        let mut repeats = 0;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
            let Ok((n, src)) = relay.recv_from(&mut buf) else {
                continue;
            };
            let wire = &buf[..n];
            let id = (src == ia, wire[18]);
            if let Some(original) = originals.get(&id) {
                assert_eq!(original, wire);
                repeats += 1;
            } else {
                originals.insert(id, wire.to_vec());
            }
            if src == ia && !request_dropped {
                request_dropped = true;
                continue;
            }
            if src == ra && wire[18] == 35 && !auth_dropped {
                auth_dropped = true;
                continue;
            }
            relay
                .send_to(wire, if src == ia { ra } else { ia })
                .unwrap();
        }
        assert!(request_dropped && auth_dropped);
        assert!(repeats >= 2);
    });
    let responder = thread::spawn(move || {
        handshake(r, pa, AuthRole::Responder, policy(b"r", b"i", 7), options())
    });
    let initiator = handshake(i, pa, AuthRole::Initiator, policy(b"i", b"r", 7), options());
    let responded = responder.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    proxy.join().unwrap();
    let initiator = initiator.unwrap();
    let responded = responded.unwrap();
    assert_eq!(initiator.session.state(), SessionState::Authenticated);
    assert_eq!(
        initiator.session.authenticated_spis(),
        responded.session.authenticated_spis()
    );
    assert!(initiator.stats.timed_retries >= 2);
    assert_eq!(responded.stats.timed_retries, 0);
}
#[test]
fn foreign_source_cannot_claim_session() {
    let i = socket();
    let r = socket();
    let rogue = socket();
    let ia = i.local_addr().unwrap();
    let ra = r.local_addr().unwrap();
    let mut attacker = quantum_ipsec::ike::PskSession::new(
        AuthRole::Initiator,
        policy(b"i", b"r", 7),
        Duration::from_secs(2),
    )
    .unwrap();
    rogue.send_to(&attacker.start().unwrap(), ra).unwrap();
    let responder = thread::spawn(move || {
        handshake(r, ia, AuthRole::Responder, policy(b"r", b"i", 7), options()).unwrap()
    });
    let result = handshake(i, ra, AuthRole::Initiator, policy(b"i", b"r", 7), options()).unwrap();
    let responded = responder.join().unwrap();
    assert!(responded.stats.discarded >= 1);
    assert_eq!(
        result.session.authenticated_spis(),
        responded.session.authenticated_spis()
    );
}
#[test]
fn wrong_credentials_and_absent_peer_timeout() {
    let i = socket();
    let r = socket();
    let ia = i.local_addr().unwrap();
    let ra = r.local_addr().unwrap();
    let responder = thread::spawn(move || {
        handshake(r, ia, AuthRole::Responder, policy(b"r", b"i", 8), options())
    });
    assert!(matches!(
        handshake(i, ra, AuthRole::Initiator, policy(b"i", b"r", 7), options()),
        Err(UdpError::Timeout)
    ));
    assert!(matches!(responder.join().unwrap(), Err(UdpError::Timeout)));
    let sink = socket();
    assert!(matches!(
        handshake(
            socket(),
            sink.local_addr().unwrap(),
            AuthRole::Initiator,
            policy(b"i", b"r", 7),
            options()
        ),
        Err(UdpError::Timeout)
    ));
}
#[test]
fn input_budget_and_deadline_bound_invalid_traffic() {
    let peer = socket();
    let receiver = socket();
    let destination = receiver.local_addr().unwrap();
    let mut limits = options();
    limits.max_datagrams = 2;
    peer.send_to(&[0; 5000], destination).unwrap();
    peer.send_to(&[0; 28], destination).unwrap();
    peer.send_to(&[0; 28], destination).unwrap();
    assert!(matches!(
        handshake(
            receiver,
            peer.local_addr().unwrap(),
            AuthRole::Responder,
            policy(b"r", b"i", 7),
            limits
        ),
        Err(UdpError::DatagramLimit)
    ));
    let receiver = socket();
    let destination = receiver.local_addr().unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let flood = thread::spawn(move || {
        for _ in 0..600 {
            let _ = peer.send_to(&[0; 28], destination);
            thread::sleep(Duration::from_millis(1));
        }
    });
    let mut limits = options();
    limits.max_datagrams = 4096;
    let start = Instant::now();
    assert!(matches!(
        handshake(
            receiver,
            peer_addr,
            AuthRole::Responder,
            policy(b"r", b"i", 7),
            limits
        ),
        Err(UdpError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    flood.join().unwrap();
}
#[test]
fn nat_t_and_invalid_limits_are_explicitly_rejected() {
    assert!(matches!(
        handshake(
            socket(),
            "127.0.0.1:4500".parse().unwrap(),
            AuthRole::Initiator,
            policy(b"i", b"r", 7),
            options()
        ),
        Err(UdpError::Configuration)
    ));
    let mut limits = options();
    limits.initial_retry = Duration::ZERO;
    assert!(matches!(
        handshake(
            socket(),
            "127.0.0.1:500".parse().unwrap(),
            AuthRole::Initiator,
            policy(b"i", b"r", 7),
            limits
        ),
        Err(UdpError::Configuration)
    ));
}
