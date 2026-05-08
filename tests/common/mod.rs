//! Shared test helpers — lives in `tests/common/mod.rs` so it is
//! reachable from every integration-test binary without becoming an
//! integration-test target itself (cargo treats `tests/common/mod.rs`
//! as a module, not as a separate test crate, by virtue of the
//! `mod.rs` filename inside a sub-directory of `tests/`).
//!
//! Cargo runs every `tests/*.rs` file as its own binary, and inside
//! each binary the individual `#[test]` fns are dispatched on a
//! parallel thread pool. libitb keeps several settings as
//! process-global atomics — `set_bit_soup`, `set_lock_soup`,
//! `set_nonce_bits`, `set_barrier_fill`, `set_max_workers`. A test
//! that mutates one of those races against any sibling test that
//! reads or writes the same setting concurrently.
//!
//! The discipline: any test that calls a process-wide `set_*` (i.e.
//! `itb::set_lock_soup`, `itb::set_bit_soup`, `itb::set_nonce_bits`,
//! `itb::set_barrier_fill`, `itb::set_max_workers`) must hold
//! [`serial_lock`] for its entire duration. Tests that only mutate
//! per-`Encryptor` knobs via `Encryptor::set_*` do not touch global
//! state and need not lock.

use std::sync::{Mutex, MutexGuard};

static GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the process-wide test-state lock. The returned guard
/// must be held for the duration of any test body that mutates
/// libitb's process-global settings (BitSoup, LockSoup, NonceBits,
/// BarrierFill, MaxWorkers).
///
/// Mutex poisoning from a panicked sibling test is recovered
/// transparently — a panic during one test must not block the rest
/// of the suite from running.
pub fn serial_lock() -> MutexGuard<'static, ()> {
    match GLOBAL_STATE_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}
