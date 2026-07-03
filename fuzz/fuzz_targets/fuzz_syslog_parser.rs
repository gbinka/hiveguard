#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_ingest::syslog_parser::{parse_syslog, extract_ip_from_message};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        if let Some(msg) = parse_syslog(line) {
            // Exercise IP extraction on the parsed message body
            let _ = extract_ip_from_message(&msg.message);
        }
    }
});
