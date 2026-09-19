use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ike::{
        auth::{AuthRole, PskAuth},
        schedule::IkeKeys,
        IkeProcessor, SessionState,
    },
    QuantumIpsecError as Error,
};

fn keys() -> IkeKeys {
    IkeKeys {
        sk_d: SecretBytes::new([0; 32]),
        sk_ei: SecretBytes::new([0; 36]),
        sk_er: SecretBytes::new([0; 36]),
        sk_pi: SecretBytes::new([3; 32]),
        sk_pr: SecretBytes::new([4; 32]),
    }
}
fn wire(role: AuthRole) -> Vec<u8> {
    let mut w = Vec::from(1u64.to_be_bytes());
    w.extend_from_slice(
        &(if role == AuthRole::Initiator {
            0u64
        } else {
            2u64
        })
        .to_be_bytes(),
    );
    w.extend_from_slice(&[
        250,
        32,
        34,
        if role == AuthRole::Initiator { 8 } else { 32 },
    ]);
    w.extend_from_slice(&[0; 4]);
    w.extend_from_slice(&35u32.to_be_bytes());
    // Unknown noncritical payload with nonzero reserved header bits.
    w.extend_from_slice(&[0, 1, 0, 7, b'a', b'b', b'c']);
    w
}
const ID: &[u8] = b"\x02\x01\x02\x03peer";

#[test]
fn independent_hmac_vectors_both_roles() {
    // Python stdlib hmac/sha256: H(H(07*48, label), wire || 09*16 || H(SK_p, ID)).
    let keys = keys();
    let psk = SecretBytes::new([7; 48]);
    for (role, expected) in [
        (
            AuthRole::Initiator,
            "8ed53331952b89cc9ac93022f309f2bfc4e84fa58f4fe17ec02d1b40b2d2209c",
        ),
        (
            AuthRole::Responder,
            "2ade9d4b08915bf99940fa97407cda5db3603d153c0caf9e3a609a637e278c08",
        ),
    ] {
        let w = wire(role);
        let auth = PskAuth::new(role, &w, &[9; 16], ID, &keys).unwrap();
        let tag = auth.compute(&psk).unwrap();
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        auth.verify(&psk, &tag).unwrap();
        for len in 0..32 {
            assert_eq!(auth.verify(&psk, &tag[..len]), Err(Error::Authentication));
        }
        assert_eq!(auth.verify(&psk, &[0; 33]), Err(Error::Authentication));
        for i in 0..32 {
            let mut changed = tag;
            changed[i] ^= 1;
            assert_eq!(auth.verify(&psk, &changed), Err(Error::Authentication));
        }
    }
}

#[test]
fn binds_exact_wire_nonce_identity_and_keys() {
    let k = keys();
    let psk = SecretBytes::new([7; 48]);
    for role in [AuthRole::Initiator, AuthRole::Responder] {
        let w = wire(role);
        let auth = PskAuth::new(role, &w, &[9; 16], ID, &k).unwrap();
        let tag = auth.compute(&psk).unwrap();
        assert_eq!(
            auth.verify(&SecretBytes::new([8; 48]), &tag),
            Err(Error::Authentication)
        );
        for index in [6, 19, 29, 34] {
            let mut changed = w.clone();
            changed[index] ^= 1;
            assert_eq!(
                PskAuth::new(role, &changed, &[9; 16], ID, &k)
                    .unwrap()
                    .verify(&psk, &tag),
                Err(Error::Authentication)
            );
        }
        assert_eq!(
            PskAuth::new(role, &w, &[8; 16], ID, &k)
                .unwrap()
                .verify(&psk, &tag),
            Err(Error::Authentication)
        );
        for index in 0..ID.len() {
            let mut id = ID.to_vec();
            id[index] ^= 1;
            assert_eq!(
                PskAuth::new(role, &w, &[9; 16], &id, &k)
                    .unwrap()
                    .verify(&psk, &tag),
                Err(Error::Authentication)
            );
        }
        let mut changed = keys();
        changed.sk_pi = SecretBytes::new([5; 32]);
        changed.sk_pr = SecretBytes::new([6; 32]);
        assert_eq!(
            PskAuth::new(role, &w, &[9; 16], ID, &changed)
                .unwrap()
                .verify(&psk, &tag),
            Err(Error::Authentication)
        );
    }
}

#[test]
fn rejects_invalid_context_and_empty_psk() {
    let k = keys();
    let w = wire(AuthRole::Initiator);
    assert!(PskAuth::new(AuthRole::Responder, &w, &[9; 16], ID, &k).is_err());
    for nonce in [vec![9; 15], vec![9; 257]] {
        assert!(PskAuth::new(AuthRole::Initiator, &w, &nonce, ID, &k).is_err());
    }
    for id in [vec![2; 4], vec![2; 4097]] {
        assert!(PskAuth::new(AuthRole::Initiator, &w, &[9; 16], &id, &k).is_err());
    }
    let mut marked = vec![0; 4];
    marked.extend_from_slice(&w);
    assert!(PskAuth::new(AuthRole::Initiator, &marked, &[9; 16], ID, &k).is_err());
    let mut response = wire(AuthRole::Responder);
    response[8..16].fill(0);
    assert!(PskAuth::new(AuthRole::Responder, &response, &[9; 16], ID, &k).is_err());
    let mut other = w.clone();
    other[18] = 35;
    other[15] = 2;
    assert!(PskAuth::new(AuthRole::Initiator, &other, &[9; 16], ID, &k).is_err());
    assert_eq!(
        PskAuth::new(AuthRole::Initiator, &w, &[9; 16], ID, &k)
            .unwrap()
            .compute(&SecretBytes::new([])),
        Err(Error::Crypto)
    );
}

#[test]
fn auth_arithmetic_does_not_enable_negotiation() {
    let mut processor = IkeProcessor::new();
    assert_eq!(
        processor.process(&wire(AuthRole::Initiator)),
        Err(Error::Unsupported("authenticated IKEv2 negotiation"))
    );
    assert_eq!(processor.state(), SessionState::Failed);
}
