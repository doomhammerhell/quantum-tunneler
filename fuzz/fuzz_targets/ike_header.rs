#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]| {
    let _=quantum_ipsec::ike::parser::parse_header(data);
    let a=quantum_ipsec::ike::parser::parse_message(data);
    let b=quantum_ipsec::ike::parser::parse_message(data);
    assert_eq!(a,b);
    if let Ok(message)=a { let wire=message.serialize().unwrap(); assert!(quantum_ipsec::ike::parser::parse_message(&wire).is_ok()); }
});
