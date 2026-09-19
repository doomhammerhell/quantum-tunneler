use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ike::{
        auth::AuthRole,
        child::ChildPolicy,
        udp::{handshake_with_child, UdpOptions},
        PskPolicy, PskSession,
    },
    keying::provenance::KeyDerivationId,
    QuantumIpsecError as Error,
};
use std::{
    net::{Ipv4Addr, UdpSocket},
    thread,
    time::Duration,
};
fn policy(local: &str, peer: &str) -> ChildPolicy {
    ChildPolicy::new(local.parse().unwrap(), peer.parse().unwrap()).unwrap()
}
fn psk(local: &[u8], peer: &[u8]) -> PskPolicy {
    PskPolicy::new(local, peer, SecretBytes::new([7; 32])).unwrap()
}
fn pair() -> (PskSession, PskSession) {
    let mut i = PskSession::new(
        AuthRole::Initiator,
        psk(b"i", b"r"),
        Duration::from_secs(60),
    )
    .unwrap();
    let mut r = PskSession::new(
        AuthRole::Responder,
        psk(b"r", b"i"),
        Duration::from_secs(60),
    )
    .unwrap();
    i.configure_child(policy("10.0.0.1", "10.0.0.2")).unwrap();
    r.configure_child(policy("10.0.0.2", "10.0.0.1")).unwrap();
    (i, r)
}
fn authenticate(i: &mut PskSession, r: &mut PskSession) -> Vec<u8> {
    let req = i.start().unwrap();
    let rsp = r.receive(&req).unwrap().unwrap();
    let auth = i.receive(&rsp).unwrap().unwrap();
    let done = r.receive(&auth).unwrap().unwrap();
    i.receive(&done).unwrap();
    auth
}
fn packet(source: &str, destination: &str) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 24, 0, 0, 0x40, 0, 64, 17, 0, 0];
    p.extend_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
    p.extend_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
    p.extend_from_slice(b"test");
    let checksum = quantum_ipsec::utils::calculate_checksum(&p[..20]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p
}
#[test]
fn negotiated_keys_protect_both_directions_without_reinstall() {
    let (mut i, mut r) = pair();
    let auth = authenticate(&mut i, &mut r);
    let req = i.start_child().unwrap();
    assert_ne!(&auth[32..40], &req[32..40]);
    assert_eq!(&req[20..24], &2u32.to_be_bytes());
    assert_eq!(req[18], 36);
    let rsp = r.receive(&req).unwrap().unwrap();
    i.receive(&rsp).unwrap();
    assert!(i.child_established() && r.child_established());
    let im = i.child_metadata().unwrap();
    let rm = r.child_metadata().unwrap();
    assert_eq!(im[0].spi, rm[1].spi);
    assert_eq!(im[1].spi, rm[0].spi);
    assert_eq!(im[0].provenance, rm[1].provenance);
    assert_eq!(
        im[0].provenance.derivation,
        KeyDerivationId::IkeV2PrfHmacSha256
    );
    let pi = packet("10.0.0.1", "10.0.0.2");
    let pr = packet("10.0.0.2", "10.0.0.1");
    let wire = i.encrypt_ipv4(&pi).unwrap();
    assert_eq!(r.decrypt_ipv4(&wire).unwrap(), pi);
    assert_eq!(r.receive(&req).unwrap(), Some(rsp.clone()));
    assert!(i.receive(&rsp).unwrap().is_none());
    assert_eq!(r.decrypt_ipv4(&wire), Err(Error::Replay));
    assert_eq!(i.child_metadata().unwrap()[1].packets, 1);
    assert_eq!(r.child_metadata().unwrap()[0].packets, 1);
    assert_eq!(i.decrypt_ipv4(&r.encrypt_ipv4(&pr).unwrap()).unwrap(), pr);
    assert!(i.start_child().is_err());
    assert!(r.start_child().is_err());
    r.close();
    assert!(!r.child_established());
    assert!(r.child_metadata().is_none());
    assert!(r.decrypt_ipv4(&wire).is_err());
}
#[test]
fn unauthenticated_child_and_policy_changes_fail() {
    let (mut i, mut r) = pair();
    assert!(i.start_child().is_err());
    assert!(i.encrypt_ipv4(&packet("10.0.0.1", "10.0.0.2")).is_err());
    authenticate(&mut i, &mut r);
    assert!(r.configure_child(policy("10.0.0.3", "10.0.0.4")).is_err());
    let req = i.start_child().unwrap();
    let mut fresh = PskSession::new(
        AuthRole::Responder,
        psk(b"r", b"i"),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(fresh.receive(&req).is_err());
    assert!(!fresh.child_established());
}
#[test]
fn tampered_child_response_does_not_install_or_advance() {
    let (mut i, mut r) = pair();
    authenticate(&mut i, &mut r);
    let req = i.start_child().unwrap();
    for index in 0..req.len() {
        let mut bad = req.clone();
        bad[index] ^= 1;
        assert!(r.receive(&bad).is_err(), "byte {index}");
        assert!(!r.child_established());
    }
    let rsp = r.receive(&req).unwrap().unwrap();
    for index in 0..rsp.len() {
        let mut bad = rsp.clone();
        bad[index] ^= 1;
        assert!(i.receive(&bad).is_err(), "byte {index}");
        assert!(!i.child_established());
        assert_eq!(i.retransmit().unwrap(), Some(req.clone()));
    }
    i.receive(&rsp).unwrap();
    let mut wire = i.encrypt_ipv4(&packet("10.0.0.1", "10.0.0.2")).unwrap();
    wire[20] ^= 1;
    assert_eq!(r.decrypt_ipv4(&wire), Err(Error::Authentication));
    assert_eq!(r.child_metadata().unwrap()[0].packets, 0);
}
#[test]
fn mismatched_selectors_rejected_and_outbound_policy_preserves_counter() {
    let (mut i, _) = pair();
    let mut r = PskSession::new(
        AuthRole::Responder,
        psk(b"r", b"i"),
        Duration::from_secs(60),
    )
    .unwrap();
    r.configure_child(policy("10.0.0.2", "10.0.0.9")).unwrap();
    authenticate(&mut i, &mut r);
    assert!(r.receive(&i.start_child().unwrap()).is_err());
    assert!(!r.child_established());
    let (mut i, mut r) = pair();
    authenticate(&mut i, &mut r);
    let req = i.start_child().unwrap();
    let rsp = r.receive(&req).unwrap().unwrap();
    i.receive(&rsp).unwrap();
    assert!(i.encrypt_ipv4(&packet("10.0.0.1", "10.0.0.9")).is_err());
    assert_eq!(i.child_metadata().unwrap()[1].packets, 0);
    let wire = i.encrypt_ipv4(&packet("10.0.0.1", "10.0.0.2")).unwrap();
    assert_eq!(&wire[4..8], &1u32.to_be_bytes());
}
#[test]
fn udp_negotiates_child_and_returns_usable_esp_pair() {
    let i = UdpSocket::bind("127.0.0.1:0").unwrap();
    let r = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ia = i.local_addr().unwrap();
    let ra = r.local_addr().unwrap();
    let opts = UdpOptions {
        timeout: Duration::from_millis(500),
        max_retry: Duration::from_millis(250),
        ..UdpOptions::default()
    };
    let responder = thread::spawn(move || {
        handshake_with_child(
            r,
            ia,
            AuthRole::Responder,
            psk(b"r", b"i"),
            policy("10.0.0.2", "10.0.0.1"),
            opts,
        )
        .unwrap()
    });
    let mut initiator = handshake_with_child(
        i,
        ra,
        AuthRole::Initiator,
        psk(b"i", b"r"),
        policy("10.0.0.1", "10.0.0.2"),
        opts,
    )
    .unwrap();
    let mut responder = responder.join().unwrap();
    let packet = packet("10.0.0.1", "10.0.0.2");
    assert_eq!(
        responder
            .session
            .decrypt_ipv4(&initiator.session.encrypt_ipv4(&packet).unwrap())
            .unwrap(),
        packet
    );
}
