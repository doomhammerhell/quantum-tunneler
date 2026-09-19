use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ike::{auth::AuthRole, IkeProcessor, PskPolicy, PskSession, SessionState},
};
use std::time::Duration;
fn session(role: AuthRole, local: &[u8], peer: &[u8], key: u8) -> PskSession {
    PskSession::new(
        role,
        PskPolicy::new(local, peer, SecretBytes::new([key; 32])).unwrap(),
        Duration::from_secs(60),
    )
    .unwrap()
}
fn pair() -> (PskSession, PskSession) {
    (
        session(AuthRole::Initiator, b"client", b"server", 7),
        session(AuthRole::Responder, b"server", b"client", 7),
    )
}
fn exchange(i: &mut PskSession, r: &mut PskSession) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let req = i.start().unwrap();
    let rsp = r.receive(&req).unwrap().unwrap();
    let auth = i.receive(&rsp).unwrap().unwrap();
    (req, rsp, auth)
}
#[test]
fn mutual_authentication_and_exact_retransmissions() {
    let (mut i, mut r) = pair();
    assert!(i.authenticated_peer().is_none());
    assert!(r.start().is_err());
    let (req, rsp, auth) = exchange(&mut i, &mut r);
    assert_eq!(i.state(), SessionState::AuthSent);
    assert_eq!(r.state(), SessionState::AwaitingAuth);
    assert_eq!(r.receive(&req).unwrap(), Some(rsp.clone()));
    assert_eq!(i.receive(&rsp).unwrap(), Some(auth.clone()));
    assert_eq!(i.retransmit().unwrap(), Some(auth.clone()));
    assert!(i.start().is_err());
    let done = r.receive(&auth).unwrap().unwrap();
    assert_eq!(r.state(), SessionState::Authenticated);
    assert_eq!(r.authenticated_peer(), Some(b"client".as_slice()));
    assert_eq!(r.receive(&auth).unwrap(), Some(done.clone()));
    assert!(i.receive(&done).unwrap().is_none());
    assert!(i.receive(&done).unwrap().is_none());
    assert_eq!(i.state(), SessionState::Authenticated);
    assert_eq!(i.authenticated_peer(), Some(b"server".as_slice()));
    assert_eq!(i.authenticated_spis(), r.authenticated_spis());
    assert!(i.receive(&auth).is_err()); // Reflection.
    assert_eq!(i.state(), SessionState::Authenticated);
}
#[test]
fn tampering_never_advances_state_or_poison_cache() {
    let (mut i, mut r) = pair();
    let (_, rsp, auth) = exchange(&mut i, &mut r);
    for index in 0..auth.len() {
        let mut bad = auth.clone();
        bad[index] ^= 1;
        assert!(r.receive(&bad).is_err(), "byte {index}");
        assert_eq!(r.state(), SessionState::AwaitingAuth);
        assert!(r.authenticated_peer().is_none());
        assert_eq!(r.retransmit().unwrap(), Some(rsp.clone()));
    }
    for len in 0..auth.len() {
        assert!(r.receive(&auth[..len]).is_err());
    }
    let done = r.receive(&auth).unwrap().unwrap();
    for index in 0..done.len() {
        let mut bad = done.clone();
        bad[index] ^= 1;
        assert!(i.receive(&bad).is_err());
        assert_eq!(i.state(), SessionState::AuthSent);
    }
    i.receive(&done).unwrap();
}
#[test]
fn wrong_psk_and_unauthorized_identities_rejected() {
    for (client_key, client_id, expected_server) in [
        (8, b"client".as_slice(), b"server".as_slice()),
        (7, b"intruder", b"server"),
        (7, b"client", b"different"),
    ] {
        let mut i = session(AuthRole::Initiator, client_id, expected_server, client_key);
        let mut r = session(AuthRole::Responder, b"server", b"client", 7);
        let (_, _, auth) = exchange(&mut i, &mut r);
        match r.receive(&auth) {
            Err(_) => {
                assert_ne!(r.state(), SessionState::Authenticated);
            }
            Ok(Some(done)) => {
                assert!(i.receive(&done).is_err());
                assert_ne!(i.state(), SessionState::Authenticated);
            }
            _ => panic!("unexpected result"),
        }
    }
}
#[test]
fn init_profile_and_low_order_public_keys_rejected() {
    let (mut i, mut r) = pair();
    let req = i.start().unwrap();
    // SA transform ID, key length, DH group and nonce length.
    for index in [47, 51, 67, 73] {
        let mut bad = req.clone();
        bad[index] ^= 1;
        assert!(r.receive(&bad).is_err(), "index {index}");
        assert_eq!(r.state(), SessionState::Initial);
    }
    let mut bad = req.clone();
    bad[76..108].fill(0);
    assert!(r.receive(&bad).is_err());
    let rsp = r.receive(&req).unwrap().unwrap();
    let mut missing = rsp[..rsp.len() - 8].to_vec();
    missing[108] = 0; // Nonce payload is now last.
    let len = missing.len() as u32;
    missing[24..28].copy_from_slice(&len.to_be_bytes());
    assert!(i.receive(&missing).is_err());
    assert_eq!(i.state(), SessionState::InitSent);
    let mut wrong_spi = rsp.clone();
    wrong_spi[0] ^= 1;
    assert!(i.receive(&wrong_spi).is_err());
    i.receive(&rsp).unwrap();
}
#[test]
fn cross_session_auth_and_reordered_messages_rejected() {
    let (mut i, mut r) = pair();
    let (mut i2, mut r2) = pair();
    let (_, _, auth) = exchange(&mut i, &mut r);
    let (_, _, other) = exchange(&mut i2, &mut r2);
    assert!(r.receive(&other).is_err());
    let mut fresh = session(AuthRole::Responder, b"server", b"client", 7);
    assert!(fresh.receive(&auth).is_err());
    let done = r.receive(&auth).unwrap().unwrap();
    assert!(i2.receive(&done).is_err());
}
#[test]
fn close_is_terminal_and_processor_requires_configuration() {
    let (mut i, mut r) = pair();
    let (req, _, auth) = exchange(&mut i, &mut r);
    r.close();
    assert_eq!(r.state(), SessionState::Closed);
    assert!(r.receive(&req).is_err());
    assert!(r.receive(&auth).is_err());
    assert!(r.retransmit().is_err());
    assert!(r.authenticated_peer().is_none());
    assert!(r.authenticated_spis().is_none());
    assert!(IkeProcessor::new().start().is_err());
    let mut configured = IkeProcessor::with_psk(
        AuthRole::Initiator,
        PskPolicy::new(b"a", b"b", SecretBytes::new([1; 32])).unwrap(),
        Duration::from_secs(30),
    )
    .unwrap();
    configured.start().unwrap();
    assert_eq!(configured.state(), SessionState::InitSent);
    assert!(PskPolicy::new(b"a", b"a", SecretBytes::new([1; 32])).is_err());
}
