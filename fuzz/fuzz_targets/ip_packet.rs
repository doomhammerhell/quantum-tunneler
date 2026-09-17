#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]| { let _=quantum_ipsec::ipsec::utils::parse_ip_header(data); });
