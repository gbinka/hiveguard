#![no_main]
use libfuzzer_sys::fuzz_target;
use regex::Regex;
use hiveguard_ingest::custom_parser::parse_custom_line;

/// Fuzz the custom parser with a fixed realistic pattern.
/// The goal is to exercise regex matching + IP parsing on arbitrary input.
static PATTERN: &str = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(?P<user>\S+)\s+(?P<status>\d+)";

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        // Use a pre-compiled pattern (realistic usage)
        let re = Regex::new(PATTERN).unwrap();
        let _result = parse_custom_line(line, &re, "fuzz_detector");
    }
});
