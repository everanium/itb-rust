//! Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
//! heap-profile writer, the pool-counter snapshot and its slot layout,
//! the hash-registry enumeration and the auto DRBG tier report.

use itb3::{ItbStatus, drbg_auto_tier, hash_names, pool_stats, pool_stats_len, set_gomaxprocs, write_heap_profile};

#[test]
fn gomaxprocs_query_set_restore() {
    let orig = set_gomaxprocs(0).unwrap();
    assert!(orig > 0);
    assert_eq!(set_gomaxprocs(-3).unwrap(), orig);
    assert_eq!(set_gomaxprocs(orig + 1).unwrap(), orig);
    assert_eq!(set_gomaxprocs(0).unwrap(), orig + 1);
    assert_eq!(set_gomaxprocs(orig).unwrap(), orig + 1);
}

#[test]
fn heap_profile_written_and_empty_path_rejected() {
    let dir = std::env::temp_dir().join(format!("itb-loop-test-heap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("heap.prof");
    write_heap_profile(&path).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
    std::fs::remove_dir_all(&dir).unwrap();
    // SAFETY (env): single-threaded test body; the variable governs
    // only the fallback under test.
    unsafe { std::env::remove_var("ITB_MEMPROFILE") };
    let err = write_heap_profile("").unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn pool_stats_layout() {
    let len = pool_stats_len().unwrap();
    assert!(len >= 9);
    let v = pool_stats().unwrap();
    assert_eq!(v.len(), len);
    let tiers = v[0];
    assert!(tiers > 0);
    assert_eq!((1 + 5 * tiers + 8) as usize, len);
}

#[test]
fn hash_names_canonical() {
    let names = hash_names().unwrap();
    assert_eq!(names.first().map(String::as_str), Some("aesitb128"));
    assert!(names.iter().any(|n| n == "areion512"));
}

#[test]
fn drbg_auto_tier_is_a_fill_cipher() {
    let tier = drbg_auto_tier().unwrap();
    assert!(tier == "aes-256-ctr" || tier == "chacha20", "drbg auto tier: {tier}");
}
