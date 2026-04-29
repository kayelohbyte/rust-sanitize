//! Implementing a custom replacement strategy.
//!
//! Run with: `cargo run --example custom_strategy`

use sanitize_engine::category::Category;
use sanitize_engine::store::MappingStore;
use sanitize_engine::strategy::{EntropyMode, Strategy, StrategyGenerator};
use std::sync::Arc;

/// A simple strategy that replaces every character with `X`.
struct Redact;

impl Strategy for Redact {
    fn name(&self) -> &'static str {
        "redact"
    }

    fn replace(&self, original: &str, _entropy: &[u8; 32]) -> String {
        "X".repeat(original.len())
    }
}

fn main() {
    // Wrap the custom strategy in a StrategyGenerator.
    let strategy = Redact;
    let mode = EntropyMode::Deterministic { key: [42u8; 32] };
    let generator = Arc::new(StrategyGenerator::new(Box::new(strategy), mode));

    // Use it with MappingStore as usual.
    let store = MappingStore::new(generator, None);

    let pairs = [
        (Category::Email, "alice@corp.com"),
        (Category::IpV4, "10.0.0.1"),
        (Category::Name, "Secret Agent"),
    ];

    for (category, original) in &pairs {
        let sanitized = store
            .get_or_insert(category, original)
            .expect("replacement should succeed");
        println!("{original:<20} → {sanitized}");
    }
}
