use quantum_ipsec::{crypto::secret::SecretBytes, ike::schedule::*, utils::bytes_to_hex};
#[test]
fn ike_schedule_independent_hmac_fixture() {
    // Fixed oracle generated with Python stdlib hmac/hashlib, not this library.
    let keys = initial_keys(&SecretBytes::new([1; 32]), &[2; 32], &[3; 32], 1, 2).unwrap();
    let mut all = Vec::new();
    all.extend_from_slice(keys.sk_d.expose());
    all.extend_from_slice(keys.sk_ei.expose());
    all.extend_from_slice(keys.sk_er.expose());
    all.extend_from_slice(keys.sk_pi.expose());
    all.extend_from_slice(keys.sk_pr.expose());
    assert_eq!(bytes_to_hex(&all),"945734f4c988b602911c45c34e8e7e8b824d6491deb4597bc94c21c40980419a90783b7c4a9a32696eafc3c2fecccca0d86e5dd3d14962a05999ec46cfc560124694376298b434133332a27034f711a7d6ee538f363f7e4b9219308d6ad91fb3661279e921e28e0e3ac9d4252aaa5bf3b5f7a474ba69e7ef6557e45321504405d67b5b02e3f090379e3620afab73f4ee90d8025d81a62075786208be454145d12006e964af268fe6");
    let child = child_keymat(&keys.sk_d, None, &[2; 32], &[3; 32]).unwrap();
    assert_eq!(bytes_to_hex(&child),"ebcabd1fc0c458ece761f09b44b5b6164c3e51e72a49ba04699abc03bcefb82627de4dabcbcd2c8caa433c34177faf35cb65ddec4a71974714692f94dbfb94c52ae253c81082fcac");
    let next = additional_exchange(
        &keys.sk_d,
        &SecretBytes::new([4; 32]),
        &[2; 32],
        &[3; 32],
        1,
        2,
    )
    .unwrap();
    assert_eq!(
        bytes_to_hex(next.sk_d.expose()),
        "b3a974761c4572d348aba45b5eceb4f9f4989d6e5b39bcf4189aee1e3064e2b5"
    );
}
#[test]
fn prf_plus_bounds_and_inputs() {
    assert!(prf_plus(&[1; 32], &[], 8161).is_err());
    assert!(prf_plus(&[], &[], 1).is_err());
    assert!(initial_keys(&SecretBytes::new([1; 32]), &[1; 15], &[2; 32], 1, 2).is_err());
    assert!(initial_keys(&SecretBytes::new([1; 32]), &[1; 32], &[2; 32], 0, 2).is_err());
    let a = initial_keys(&SecretBytes::new([1; 32]), &[2; 32], &[3; 32], 1, 2).unwrap();
    let b = initial_keys(&SecretBytes::new([1; 32]), &[2; 32], &[3; 32], 1, 3).unwrap();
    assert_ne!(a.sk_d.expose(), b.sk_d.expose());
    assert_ne!(a.sk_ei.expose(), a.sk_er.expose());
    assert_ne!(
        child_keymat(&a.sk_d, None, &[2; 32], &[3; 32]).unwrap(),
        child_keymat(
            &a.sk_d,
            Some(&SecretBytes::new([4; 32])),
            &[2; 32],
            &[3; 32]
        )
        .unwrap()
    );
}
#[test]
fn hkdf_rfc5869_case_1() {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        &[0x0b; 22],
    );
    let mut out = [0; 42];
    hk.expand(
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        &mut out,
    )
    .unwrap();
    assert_eq!(
        bytes_to_hex(&out),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}
