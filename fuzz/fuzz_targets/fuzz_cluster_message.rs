#![no_main]
use libfuzzer_sys::fuzz_target;
use hiveguard_net::messages::ClusterMessage;

/// Fuzz postcard deserialization of ClusterMessage.
/// Tests that arbitrary byte sequences cannot cause panics
/// when deserialized as cluster protocol messages.
fuzz_target!(|data: &[u8]| {
    // Must not panic — invalid data should return Err
    let _result = postcard::from_bytes::<ClusterMessage>(data);
});
