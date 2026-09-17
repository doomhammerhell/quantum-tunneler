#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| if let Some((&kind, body)) = data.split_first() {
    let _ = quantum_ipsec::ike::parser::parse_payloads(kind, body);
});
