//! Process-global configuration roundtrip tests.
//!
//! Mirror of the Python `TestConfig` class in
//! `bindings/python/tests/test_roundtrip.py`. These tests mutate
//! libitb's process-wide atomics (`bit_soup`, `lock_soup`,
//! `max_workers`, `nonce_bits`, `barrier_fill`); they live in their
//! own integration-test binary so cargo isolates them in a separate
//! process. Inside this binary every `#[test]` holds
//! `common::serial_lock()`, so config mutations cannot race even
//! when cargo runs the `#[test]` fns on its parallel thread pool.

#[path = "common/mod.rs"]
mod common;

#[test]
fn bit_soup_roundtrip() {
    let _g = common::serial_lock();
    let orig = itb::get_bit_soup();
    itb::set_bit_soup(1).unwrap();
    assert_eq!(itb::get_bit_soup(), 1);
    itb::set_bit_soup(0).unwrap();
    assert_eq!(itb::get_bit_soup(), 0);
    itb::set_bit_soup(orig).unwrap();
}

#[test]
fn lock_soup_roundtrip() {
    let _g = common::serial_lock();
    let orig = itb::get_lock_soup();
    itb::set_lock_soup(1).unwrap();
    assert_eq!(itb::get_lock_soup(), 1);
    itb::set_lock_soup(orig).unwrap();
}

#[test]
fn max_workers_roundtrip() {
    let _g = common::serial_lock();
    let orig = itb::get_max_workers();
    itb::set_max_workers(4).unwrap();
    assert_eq!(itb::get_max_workers(), 4);
    itb::set_max_workers(orig).unwrap();
}

#[test]
fn nonce_bits_validation() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    for valid in [128, 256, 512] {
        itb::set_nonce_bits(valid).unwrap();
        assert_eq!(itb::get_nonce_bits(), valid);
    }
    for bad in [0, 1, 192, 1024] {
        let err = itb::set_nonce_bits(bad).unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_INPUT,
            "set_nonce_bits({bad}) must reject with STATUS_BAD_INPUT"
        );
    }
    itb::set_nonce_bits(orig).unwrap();
}

#[test]
fn barrier_fill_validation() {
    let _g = common::serial_lock();
    let orig = itb::get_barrier_fill();
    for valid in [1, 2, 4, 8, 16, 32] {
        itb::set_barrier_fill(valid).unwrap();
        assert_eq!(itb::get_barrier_fill(), valid);
    }
    for bad in [0, 3, 5, 7, 64] {
        let err = itb::set_barrier_fill(bad).unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_INPUT,
            "set_barrier_fill({bad}) must reject with STATUS_BAD_INPUT"
        );
    }
    itb::set_barrier_fill(orig).unwrap();
}
