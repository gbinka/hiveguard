#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_ingest::ssh_parser::{SshPatterns, parse_ssh_line, ssh_event_to_normalized};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let patterns = SshPatterns::new();
        if let Some(event) = parse_ssh_line(line, &patterns) {
            let _normalized = ssh_event_to_normalized(event);
        }
    }
});
