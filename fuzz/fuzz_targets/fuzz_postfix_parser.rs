#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_ingest::postfix_parser::{PostfixPatterns, parse_postfix_line, postfix_event_to_normalized};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let patterns = PostfixPatterns::new();
        if let Some(event) = parse_postfix_line(line, &patterns) {
            let _normalized = postfix_event_to_normalized(event);
        }
    }
});
