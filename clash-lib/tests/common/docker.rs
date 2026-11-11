//! Reuse the protocol unit tests' Docker harness in integration test binaries.
#![allow(dead_code)]

use std::sync::atomic::AtomicU16;

// Each integration test binary is a separate process, so it needs its own
// allocator, just like the library test binary.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(30001);

#[path = "../../src/proxy/utils/test_utils/docker_utils/consts.rs"]
pub mod consts;
#[path = "../../src/proxy/utils/test_utils/docker_utils/docker_runner.rs"]
pub mod docker_runner;
