//! Fuzz target: JSON structured processor.
//!
//! Feeds arbitrary bytes through `JsonProcessor::process` to ensure
//! it never panics on malformed or adversarial JSON input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sanitize_engine::category::Category;
use sanitize_engine::generator::HmacGenerator;
use sanitize_engine::processor::json_proc::JsonProcessor;
use sanitize_engine::processor::{FieldRule, FileTypeProfile, Processor};
use sanitize_engine::store::MappingStore;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    // Limit input size to avoid timeouts on huge blobs.
    if data.len() > 256 * 1024 {
        return;
    }

    let gen = Arc::new(HmacGenerator::new([0xABu8; 32]));
    let store = MappingStore::new(gen, Some(5000));

    let profile = FileTypeProfile::new(
        "json",
        vec![
            FieldRule::new("*.password").with_category(Category::Custom("password".into())),
            FieldRule::new("*.email").with_category(Category::Email),
            FieldRule::new("*.token").with_category(Category::Custom("api_key".into())),
        ],
    )
    .with_extension("json");

    let processor = JsonProcessor;
    if processor.can_handle(data, &profile) {
        let _ = processor.process(data, &profile, &store);
    }
});
