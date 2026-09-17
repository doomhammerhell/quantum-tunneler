use proptest::prelude::*;
use quantum_ipsec::{
    crypto::{secret::SecretBytes, symmetric},
    ipsec::{
        esp::{self, decrypt_packet, encrypt_packet},
        sa::{Direction, SaLifetime, SecurityAssociation, SecurityAssociationDatabase},
    },
    keying::schedule::{derive_traffic_keys, KeyContext},
    QuantumIpsecError as Error,
};
use static_assertions::assert_not_impl_any;
use std::time::Duration;
assert_not_impl_any!(SecretBytes<32>: Clone, serde::Serialize, serde::de::DeserializeOwned);
assert_not_impl_any!(SecurityAssociation: Clone, serde::Serialize, serde::de::DeserializeOwned);
fn context(generation: u64) -> KeyContext {
    KeyContext {
        initiator_spi: 256,
        responder_spi: 257,
        session_id: [1; 32],
        transcript_hash: [2; 32],
        generation,
    }
}
fn sa(c: &KeyContext, direction: Direction, limits: SaLifetime) -> SecurityAssociation {
    let (keys, p) = derive_traffic_keys(SecretBytes::new([7; 32]), c).unwrap();
    SecurityAssociation::new(
        c.responder_spi,
        direction,
        keys.initiator_to_responder,
        limits,
        p,
    )
    .unwrap()
}
fn pair() -> (SecurityAssociation, SecurityAssociation) {
    (
        sa(&context(1), Direction::Outbound, SaLifetime::default()),
        sa(&context(1), Direction::Inbound, SaLifetime::default()),
    )
}
#[test]
fn aes256_gcm_known_answer() {
    // NIST GCM all-zero AES-256 vector, 128-bit plaintext/tag.
    let mut data = [0; 16];
    let tag = symmetric::seal(&[0; 32], &[0; 12], &[], &mut data).unwrap();
    assert_eq!(
        quantum_ipsec::utils::bytes_to_hex(&data),
        "cea7403d4d606b6e074ec5d3baf39d18"
    );
    assert_eq!(
        quantum_ipsec::utils::bytes_to_hex(&tag),
        "d0d1c8a799996bf0265b98b5d48ab919"
    );
    symmetric::open(&[0; 32], &[0; 12], &[], &mut data, &tag).unwrap();
    assert_eq!(data, [0; 16]);
}
#[test]
fn packet_round_trip_lengths_and_headers() {
    for n in [0, 1, 2, 3, 4, 64, 512, 1400, 9000, esp::MAX_PLAINTEXT] {
        let (mut tx, mut rx) = pair();
        let body = vec![42; n];
        let wire = encrypt_packet(&mut tx, &body, 41).unwrap();
        assert_eq!(&wire[..8], &[0, 0, 1, 1, 0, 0, 0, 1]);
        assert_eq!(wire.len() % 4, 0);
        let p = decrypt_packet(&mut rx, &wire).unwrap();
        assert_eq!(p.payload, body);
        assert_eq!(p.next_header, 41);
    }
}
#[test]
fn tamper_each_byte_rejected_without_advancing_window() {
    let (mut tx, mut rx) = pair();
    let wire = encrypt_packet(&mut tx, b"sensitive message", 4).unwrap();
    for i in 0..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 0x80;
        assert!(decrypt_packet(&mut rx, &bad).is_err(), "byte {i}");
    }
    assert_eq!(rx.metadata().packets, 0);
    assert!(decrypt_packet(&mut rx, &wire).is_ok());
    assert_eq!(decrypt_packet(&mut rx, &wire), Err(Error::Replay));
}
#[test]
fn reordering_and_window_boundary() {
    let (mut tx, mut rx) = pair();
    let packets: Vec<_> = (0..70)
        .map(|_| encrypt_packet(&mut tx, b"x", 4).unwrap())
        .collect();
    decrypt_packet(&mut rx, &packets[69]).unwrap();
    decrypt_packet(&mut rx, &packets[6]).unwrap(); // 70 - 7 == 63
    assert_eq!(decrypt_packet(&mut rx, &packets[5]), Err(Error::Replay));
    decrypt_packet(&mut rx, &packets[68]).unwrap();
    assert_eq!(decrypt_packet(&mut rx, &packets[68]), Err(Error::Replay));
}
#[test]
fn forged_high_sequence_does_not_poison_window() {
    let (mut tx, mut rx) = pair();
    let wire = encrypt_packet(&mut tx, b"x", 4).unwrap();
    let mut bad = wire.clone();
    bad[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(decrypt_packet(&mut rx, &bad), Err(Error::Authentication));
    assert!(decrypt_packet(&mut rx, &wire).is_ok());
}
#[test]
fn nonce_unique_and_limits_enforced() {
    let (mut tx, _) = pair();
    let p = encrypt_packet(&mut tx, b"x", 4).unwrap();
    let q = encrypt_packet(&mut tx, b"x", 4).unwrap();
    assert_ne!(&p[8..16], &q[8..16]);
    let limit = SaLifetime {
        max_packets: 1,
        rekey_after_packets: 1,
        ..SaLifetime::default()
    };
    let mut tx = sa(&context(1), Direction::Outbound, limit);
    encrypt_packet(&mut tx, b"x", 4).unwrap();
    assert!(tx.needs_rekey());
    assert_eq!(encrypt_packet(&mut tx, b"x", 4), Err(Error::SaExpired));
    let limit = SaLifetime {
        max_bytes: 3,
        ..SaLifetime::default()
    };
    let mut tx = sa(&context(1), Direction::Outbound, limit);
    assert_eq!(encrypt_packet(&mut tx, b"x", 4), Err(Error::SaExpired));
    assert_eq!(tx.metadata().packets, 0);
}
#[test]
fn retired_expired_and_wrong_direction_rejected() {
    let (mut tx, mut rx) = pair();
    let wire = encrypt_packet(&mut tx, b"x", 4).unwrap();
    assert_eq!(decrypt_packet(&mut tx, &wire), Err(Error::UnknownSa));
    assert_eq!(encrypt_packet(&mut rx, b"x", 4), Err(Error::UnknownSa));
    rx.retire();
    assert_eq!(decrypt_packet(&mut rx, &wire), Err(Error::SaExpired));
    let mut tx = sa(
        &context(1),
        Direction::Outbound,
        SaLifetime {
            max_age: Duration::from_nanos(1),
            ..SaLifetime::default()
        },
    );
    std::thread::sleep(Duration::from_millis(1));
    assert_eq!(encrypt_packet(&mut tx, b"x", 4), Err(Error::SaExpired));
}
#[test]
fn transcript_generation_spi_session_and_direction_separate_keys() {
    let base = context(1);
    let mut changes = vec![
        context(2),
        KeyContext {
            responder_spi: 258,
            ..base
        },
        KeyContext {
            session_id: [3; 32],
            ..base
        },
        KeyContext {
            transcript_hash: [4; 32],
            ..base
        },
    ];
    let baseline = encrypt_packet(
        &mut sa(&base, Direction::Outbound, SaLifetime::default()),
        b"message",
        4,
    )
    .unwrap();
    for c in changes.drain(..) {
        let wire = encrypt_packet(
            &mut sa(&c, Direction::Outbound, SaLifetime::default()),
            b"message",
            4,
        )
        .unwrap();
        assert_ne!(&wire[16..], &baseline[16..]);
    }
    let (keys, p) = derive_traffic_keys(SecretBytes::new([7; 32]), &base).unwrap();
    let mut reverse = SecurityAssociation::new(
        base.initiator_spi,
        Direction::Outbound,
        keys.responder_to_initiator,
        SaLifetime::default(),
        p,
    )
    .unwrap();
    let wire = encrypt_packet(&mut reverse, b"message", 4).unwrap();
    assert_ne!(&wire[16..], &baseline[16..]);
}
#[test]
fn rekey_replaces_generation_and_old_outbound_stops() {
    let mut db = SecurityAssociationDatabase::new(4);
    db.add_sa(sa(&context(1), Direction::Outbound, SaLifetime::default()))
        .unwrap();
    let new = KeyContext {
        responder_spi: 258,
        generation: 2,
        ..context(1)
    };
    db.replace_generation(257, sa(&new, Direction::Outbound, SaLifetime::default()))
        .unwrap();
    assert_eq!(
        encrypt_packet(db.get_sa_mut(257).unwrap(), b"x", 4),
        Err(Error::SaExpired)
    );
    assert!(encrypt_packet(db.get_sa_mut(258).unwrap(), b"x", 4).is_ok());
    db.remove_sa(257);
    assert_eq!(
        db.add_sa(sa(&context(1), Direction::Outbound, SaLifetime::default())),
        Err(Error::Duplicate)
    );
}
#[test]
fn failed_rekey_leaves_old_sa_usable() {
    let mut db = SecurityAssociationDatabase::new(1);
    db.add_sa(sa(&context(1), Direction::Outbound, SaLifetime::default()))
        .unwrap();
    let new = KeyContext {
        responder_spi: 258,
        generation: 2,
        ..context(1)
    };
    assert_eq!(
        db.replace_generation(257, sa(&new, Direction::Outbound, SaLifetime::default())),
        Err(Error::Capacity)
    );
    assert!(encrypt_packet(db.get_sa_mut(257).unwrap(), b"x", 4).is_ok());
}
#[test]
fn metadata_and_debug_do_not_expose_keys() {
    let (tx, _) = pair();
    let output = format!("{tx:?}");
    assert!(!output.contains("traffic_key"));
    assert!(!output.contains("[7, 7"));
    assert_eq!(
        format!("{:?}", SecretBytes::new([77; 32])),
        "SecretBytes([REDACTED])"
    );
}
#[test]
fn invalid_context_and_false_provenance_rejected() {
    assert!(derive_traffic_keys(
        SecretBytes::new([1; 32]),
        &KeyContext {
            generation: 0,
            ..context(1)
        }
    )
    .is_err());
    let (keys, mut p) = derive_traffic_keys(SecretBytes::new([1; 32]), &context(1)).unwrap();
    p.generation = 7;
    assert!(SecurityAssociation::new(
        257,
        Direction::Outbound,
        keys.initiator_to_responder,
        SaLifetime::default(),
        p
    )
    .is_err());
}
#[test]
fn malformed_hex_unicode_and_short_esp() {
    for s in ["💥", "a💥a", "é", "zz", "a"] {
        assert!(quantum_ipsec::utils::hex_to_bytes(s).is_err());
    }
    for n in 0..36 {
        assert!(esp::EspPacket::parse(&vec![0; n]).is_err());
    }
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test] fn arbitrary_round_trip(body in prop::collection::vec(any::<u8>(),0..4096), nh in any::<u8>()) {
        let (mut tx,mut rx)=pair(); let wire=encrypt_packet(&mut tx,&body,nh).unwrap();
        let result=decrypt_packet(&mut rx,&wire).unwrap(); prop_assert_eq!(result.payload,body); prop_assert_eq!(result.next_header,nh);
    }
    #[test] fn arbitrary_esp_no_panic(data in prop::collection::vec(any::<u8>(),0..4096)) { let _=esp::EspPacket::parse(&data); }
}

#[test]
fn independent_python_esp_fixture() {
    let (mut tx, mut rx) = pair();
    let fixture =
        quantum_ipsec::utils::hex_to_bytes(include_str!("fixtures/esp.hex").trim()).unwrap();
    let wire = encrypt_packet(&mut tx, b"independent ESP fixture", 4).unwrap();
    assert_eq!(wire, fixture);
    assert_eq!(
        decrypt_packet(&mut rx, &fixture).unwrap().payload,
        b"independent ESP fixture"
    );
}
#[test]
fn authenticated_invalid_padding_does_not_commit_replay() {
    let (_, mut rx) = pair();
    let bad = quantum_ipsec::utils::hex_to_bytes(include_str!("fixtures/bad_padding.hex").trim())
        .unwrap();
    assert!(matches!(
        decrypt_packet(&mut rx, &bad),
        Err(Error::PacketError(_))
    ));
    assert_eq!(rx.metadata().packets, 0);
    let good = quantum_ipsec::utils::hex_to_bytes(include_str!("fixtures/esp.hex").trim()).unwrap();
    assert!(decrypt_packet(&mut rx, &good).is_ok());
}
#[test]
fn inbound_rekey_drain_and_retirement_preserve_replay() {
    let (mut tx, rx) = pair();
    let first = encrypt_packet(&mut tx, b"old1", 4).unwrap();
    let second = encrypt_packet(&mut tx, b"old2", 4).unwrap();
    let mut db = SecurityAssociationDatabase::new(4);
    db.add_sa(rx).unwrap();
    decrypt_packet(db.get_sa_mut(257).unwrap(), &first).unwrap();
    let new = KeyContext {
        responder_spi: 258,
        generation: 2,
        ..context(1)
    };
    db.replace_generation(257, sa(&new, Direction::Inbound, SaLifetime::default()))
        .unwrap();
    assert_eq!(
        decrypt_packet(db.get_sa_mut(257).unwrap(), &first),
        Err(Error::Replay)
    );
    decrypt_packet(db.get_sa_mut(257).unwrap(), &second).unwrap();
    db.get_sa_mut(257).unwrap().retire();
    assert_eq!(db.cleanup_expired(), 1);
    assert!(db.get_sa(257).is_none());
    assert!(db.get_sa(258).is_some());
}
#[test]
fn metadata_counters_distinguish_auth_failure_and_replay() {
    let (mut tx, rx) = pair();
    let wire = encrypt_packet(&mut tx, b"x", 4).unwrap();
    let mut runtime = quantum_ipsec::IpSecProcessor::new(2);
    runtime.install_sa(rx).unwrap();
    let mut bad = wire.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(runtime.decrypt(&bad).is_err());
    runtime.decrypt(&wire).unwrap();
    assert!(runtime.decrypt(&wire).is_err());
    assert_eq!(runtime.get_stats().auth_failures, 1);
    assert_eq!(runtime.get_stats().replay_rejections, 1);
    assert_eq!(runtime.get_stats().esp_packets, 1);
}

#[test]
fn rekey_cannot_reactivate_a_retired_zeroized_inbound_sa() {
    let (_, mut rx) = pair();
    rx.retire();
    let mut db = SecurityAssociationDatabase::new(4);
    assert_eq!(db.add_sa(rx), Err(Error::SaExpired));
    let (_, rx) = pair();
    db.add_sa(rx).unwrap();
    db.get_sa_mut(257).unwrap().retire();
    let new = KeyContext {
        responder_spi: 258,
        generation: 2,
        ..context(1)
    };
    assert_eq!(
        db.replace_generation(257, sa(&new, Direction::Inbound, SaLifetime::default())),
        Err(Error::SaExpired)
    );
    assert_eq!(
        db.get_sa(257).unwrap().metadata().state,
        quantum_ipsec::ipsec::sa::SaState::Retired
    );
    assert!(db.get_sa(258).is_none());
    assert_eq!(db.active_count(), 0);
}
