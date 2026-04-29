//! Thread-safe, concurrent one-way replacement store.
//!
//! # Concurrency Model
//!
//! The store uses [`dashmap::DashMap`] — a concurrent hash map with shard-level
//! locking (default 64 shards). This gives us:
//!
//! - **Lock-free reads** for lookups of already-mapped values.
//! - **Shard-level write locks** that are held only while inserting a new entry.
//!   With 64 shards and 8–16 threads, the probability of two threads contending
//!   on the same shard is very low.
//! - **Atomic get-or-insert** via the `entry()` API, which prevents TOCTOU races
//!   and guarantees first-writer-wins semantics.
//!
//! The forward map is keyed by `(Category, original)` → `sanitized`.
//! Replacements are **one-way only** — there is no reverse map, no mapping
//! file, and no restore capability.
//!
//! # Memory Characteristics
//!
//! At 10M unique values with average key length 20 bytes and average value
//! length 30 bytes:
//! - Forward map: 10M × (20 + 30 + ~120 DashMap overhead) ≈ 1.7 GB
//! - **Total: ~1.7 GB** — acceptable for server workloads.
//!
//! An optional `capacity_limit` can be set to prevent unbounded growth.

use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::generator::ReplacementGenerator;
use compact_str::CompactString;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Composite key for the forward map
// ---------------------------------------------------------------------------

/// Composite key: `(Category, original_value)`.
///
/// Uses `String` for `original` (rather than `CompactString`) so that
/// the Drop impl can zeroize sensitive plaintext via the `Zeroize`
/// trait without unsafe code (F-09 fix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ForwardKey {
    category: Category,
    original: String,
}

// ---------------------------------------------------------------------------
// MappingStore
// ---------------------------------------------------------------------------

/// Thread-safe concurrent one-way replacement store.
///
/// Caches forward mappings for per-run consistency (same input always
/// produces the same output within a run). There is no reverse map,
/// no journal, and no persistence — replacements are one-way only.
///
/// See the [module-level documentation](self) for concurrency and memory details.
pub struct MappingStore {
    /// `(category, original) → sanitized`
    forward: DashMap<ForwardKey, CompactString>,
    /// Replacement generator (HMAC deterministic or CSPRNG random).
    generator: Arc<dyn ReplacementGenerator>,
    /// Current number of mappings (atomic for lock-free reads).
    len: AtomicUsize,
    /// Optional upper bound on the number of mappings.
    capacity_limit: Option<usize>,
}

impl MappingStore {
    // ---------------- Construction ----------------

    /// Create a new, empty mapping store.
    ///
    /// # Arguments
    ///
    /// - `generator` — replacement strategy (HMAC or random).
    /// - `capacity_limit` — optional max number of unique mappings.
    #[must_use]
    pub fn new(generator: Arc<dyn ReplacementGenerator>, capacity_limit: Option<usize>) -> Self {
        Self {
            forward: DashMap::with_capacity(1024),
            generator,
            len: AtomicUsize::new(0),
            capacity_limit,
        }
    }

    // ---------------- Core API ----------------

    /// Get or create the sanitized replacement for `(category, original)`.
    ///
    /// This is the primary API for one-way sanitization.
    ///
    /// **Thread-safety:** Uses `DashMap::entry()` which holds a shard-level
    /// lock only for the duration of the insert closure. The generator is
    /// called inside the lock, but generation is fast (one HMAC or one RNG
    /// call). Capacity enforcement uses `compare_exchange` to prevent
    /// TOCTOU over-insertion (C-1 fix).
    ///
    /// **Per-run consistency:** Once a value is mapped, all subsequent
    /// lookups return the same sanitized value (first-writer-wins).
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::CapacityExceeded`] if the store has
    /// reached its configured capacity limit.
    pub fn get_or_insert(&self, category: &Category, original: &str) -> Result<CompactString> {
        // Fast path: already mapped (lock-free read).
        let key = ForwardKey {
            category: category.clone(),
            original: original.to_owned(),
        };
        if let Some(existing) = self.forward.get(&key) {
            return Ok(existing.value().clone());
        }

        // Slow path: need to insert.
        // Atomically reserve a capacity slot *before* generating the
        // value.  This eliminates the TOCTOU race (C-1) where multiple
        // threads pass the capacity check and all insert.
        if let Some(limit) = self.capacity_limit {
            loop {
                let current = self.len.load(Ordering::Acquire);
                if current >= limit {
                    // One more chance: key may have been inserted by
                    // another thread while we were checking.
                    if let Some(existing) = self.forward.get(&key) {
                        return Ok(existing.value().clone());
                    }
                    return Err(SanitizeError::CapacityExceeded { current, limit });
                }
                // Try to reserve a slot atomically.
                if self
                    .len
                    .compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break;
                }
                // CAS failed → another thread incremented; retry.
            }

            // Slot reserved — generate and insert.
            // Use entry() for first-writer-wins semantics.
            let mut was_inserted = false;
            let result = self
                .forward
                .entry(key)
                .or_insert_with(|| {
                    was_inserted = true;
                    let val = self.generator.generate(category, original);
                    CompactString::new(val)
                })
                .value()
                .clone();

            if !was_inserted {
                // Another thread inserted first — release our reserved slot.
                self.len.fetch_sub(1, Ordering::Release);
            }

            Ok(result)
        } else {
            // No capacity limit — generate inside the entry lock to
            // avoid wasted work (C-2 fix: only the first writer generates).
            let mut was_inserted = false;
            let result = self
                .forward
                .entry(key)
                .or_insert_with(|| {
                    was_inserted = true;
                    let val = self.generator.generate(category, original);
                    CompactString::new(val)
                })
                .value()
                .clone();

            if was_inserted {
                self.len.fetch_add(1, Ordering::Release);
            }

            Ok(result)
        }
    }

    /// Look up an existing forward mapping without creating one.
    #[must_use]
    pub fn forward_lookup(&self, category: &Category, original: &str) -> Option<CompactString> {
        let key = ForwardKey {
            category: category.clone(),
            original: original.to_owned(),
        };
        self.forward.get(&key).map(|r| r.value().clone())
    }

    // ---------------- Metrics ----------------

    /// Number of unique mappings in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all mappings, zeroizing the original plaintexts.
    ///
    /// This is useful for resetting the store between runs without
    /// dropping and recreating it.
    pub fn clear(&mut self) {
        let old_map = std::mem::take(&mut self.forward);
        for (mut key, _value) in old_map {
            key.original.zeroize();
        }
        self.len.store(0, Ordering::Release);
    }

    // ---------------- Snapshot / diff (for format-preserving pass) ----------------

    /// Snapshot the set of `(category, original)` keys currently in the store.
    ///
    /// Call this before structured processing; diff against `iter()` afterwards
    /// to find which mappings were added by the processor.
    pub fn snapshot_keys(&self) -> std::collections::HashSet<(Category, String)> {
        self.forward
            .iter()
            .map(|e| (e.key().category.clone(), e.key().original.clone()))
            .collect()
    }

    // ---------------- Iteration (for external use) ----------------

    /// Iterate over all mappings. Yields `(category, original, sanitized)`.
    ///
    /// Note: iteration over `DashMap` is not snapshot-consistent if concurrent
    /// inserts are happening. Call this after all workers have finished.
    pub fn iter(&self) -> impl Iterator<Item = (Category, CompactString, CompactString)> + '_ {
        self.forward.iter().map(|entry| {
            (
                entry.key().category.clone(),
                CompactString::new(&entry.key().original),
                entry.value().clone(),
            )
        })
    }
}

/// F-09 fix: zeroize original keys stored in the forward map on drop.
/// This prevents sensitive plaintext values from lingering on the heap
/// after the store is no longer needed. Uses safe Zeroize on Strings.
impl Drop for MappingStore {
    fn drop(&mut self) {
        // DashMap::retain() visits each entry. We use it to overwrite
        // the original plaintext before the entry is dropped.
        // retain() gives us (&K, &mut V); the key is behind a shared
        // reference.  We extract the original, create a zeroizing copy,
        // then clear the map. This ensures the String backing buffer
        // is zeroed before being freed.
        //
        // Approach: swap the map contents with an empty map, consuming
        // ownership of all entries via IntoIter.
        let old_map = std::mem::take(&mut self.forward);
        for (mut key, _value) in old_map {
            key.original.zeroize();
        }
    }
}

/// Compile-time assertion that a type is `Send + Sync`.
macro_rules! static_assertions_send_sync {
    ($t:ty) => {
        const _: fn() = || {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}
            assert_send::<$t>();
            assert_sync::<$t>();
        };
    };
}

// DashMap is Send + Sync, AtomicUsize is Send + Sync,
// Arc<dyn ReplacementGenerator> is Send + Sync.
// This is satisfied automatically, but let's assert it:
static_assertions_send_sync!(MappingStore);

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{HmacGenerator, RandomGenerator};
    use std::sync::Arc;

    fn hmac_store(limit: Option<usize>) -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, limit)
    }

    fn random_store() -> MappingStore {
        let gen = Arc::new(RandomGenerator::new());
        MappingStore::new(gen, None)
    }

    // --- Basic operations ---

    #[test]
    fn insert_and_lookup() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert!(!s1.is_empty());
        assert!(s1.contains("@corp.com"), "domain must be preserved");
        assert_eq!(s1.len(), "alice@corp.com".len(), "length must be preserved");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn same_input_same_output() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(s1, s2, "repeated insert must return cached value");
        assert_eq!(store.len(), 1, "no duplicate entry");
    }

    #[test]
    fn different_inputs_different_outputs() {
        let store = hmac_store(None);
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "bob@corp.com")
            .unwrap();
        assert_ne!(s1, s2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn different_categories_different_outputs() {
        let store = hmac_store(None);
        let s1 = store.get_or_insert(&Category::Email, "test").unwrap();
        let s2 = store.get_or_insert(&Category::Name, "test").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn forward_lookup_works() {
        let store = hmac_store(None);
        let sanitized = store.get_or_insert(&Category::IpV4, "192.168.1.1").unwrap();
        let found = store.forward_lookup(&Category::IpV4, "192.168.1.1");
        assert_eq!(found, Some(sanitized));
    }

    #[test]
    fn forward_lookup_missing() {
        let store = hmac_store(None);
        assert!(store.forward_lookup(&Category::Email, "nope").is_none());
    }

    // --- Capacity limit ---

    #[test]
    fn capacity_limit_enforced() {
        let store = hmac_store(Some(2));
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::Email, "b@b.com").unwrap();
        let result = store.get_or_insert(&Category::Email, "c@c.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            SanitizeError::CapacityExceeded {
                current: 2,
                limit: 2,
            } => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn capacity_limit_allows_duplicate() {
        let store = hmac_store(Some(1));
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        // Re-inserting same value should succeed (fast path).
        let s2 = store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        assert!(!s2.is_empty());
    }

    // --- Random generator within store ---

    #[test]
    fn random_store_caches() {
        let store = random_store();
        let s1 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        let s2 = store
            .get_or_insert(&Category::Email, "alice@corp.com")
            .unwrap();
        assert_eq!(s1, s2, "random store must still cache the first result");
    }

    // --- Iteration ---

    #[test]
    fn iter_yields_all_mappings() {
        let store = hmac_store(None);
        store.get_or_insert(&Category::Email, "a@a.com").unwrap();
        store.get_or_insert(&Category::IpV4, "1.2.3.4").unwrap();
        let collected: Vec<_> = store.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    // --- Concurrent inserts (basic smoke test) ---

    #[test]
    fn concurrent_inserts_no_panic() {
        use std::sync::Arc;
        use std::thread;

        let gen = Arc::new(HmacGenerator::new([99u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        let mut handles = vec![];
        for t in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..1000 {
                    let val = format!("thread{}-val{}", t, i);
                    store.get_or_insert(&Category::Email, &val).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(store.len(), 8000);
    }

    #[test]
    fn concurrent_inserts_same_key_idempotent() {
        use std::sync::Arc;
        use std::thread;

        let gen = Arc::new(HmacGenerator::new([7u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));

        let mut handles = vec![];
        for _ in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let mut results = Vec::new();
                for i in 0..100 {
                    let val = format!("shared-{}", i);
                    let r = store.get_or_insert(&Category::Email, &val).unwrap();
                    results.push((val, r));
                }
                results
            }));
        }

        let mut all_results: Vec<Vec<(String, CompactString)>> = vec![];
        for h in handles {
            all_results.push(h.join().unwrap());
        }

        // All threads must agree on every mapping.
        assert_eq!(store.len(), 100);
        for i in 0..100 {
            let val = format!("shared-{}", i);
            let expected = store.forward_lookup(&Category::Email, &val).unwrap();
            for thread_results in &all_results {
                let (_, got) = &thread_results[i];
                assert_eq!(
                    got, &expected,
                    "all threads must see the same mapping for {}",
                    val
                );
            }
        }
    }
}
