#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_ingest::nginx_parser::{NginxPattern, parse_nginx_line, nginx_event_to_normalized};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let pattern = NginxPattern::new();
        if let Some(event) = parse_nginx_line(line, &pattern) {
            let _normalized = nginx_event_to_normalized(event);
        }
    }
});
