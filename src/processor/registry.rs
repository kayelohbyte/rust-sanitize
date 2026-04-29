//! Processor registry — discovers and dispatches structured processors.
//!
//! The [`ProcessorRegistry`] holds a set of registered [`Processor`]
//! implementations and provides methods to:
//!
//! 1. Look up a processor by name.
//! 2. Auto-detect a processor for given content + profile.
//! 3. Process content using a matching processor, falling back to `None`
//!    if no processor matches (caller can then use the streaming scanner).

use super::{FileTypeProfile, Processor};
use crate::error::Result;
use crate::store::MappingStore;
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of structured processors.
///
/// Thread-safe (processors are `Arc<dyn Processor>`) and can be shared
/// across threads via `Arc<ProcessorRegistry>`.
pub struct ProcessorRegistry {
    /// Processors indexed by name.
    processors: HashMap<String, Arc<dyn Processor>>,
}

impl ProcessorRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            processors: HashMap::new(),
        }
    }

    /// Create a registry pre-populated with all built-in processors.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        reg.register(Arc::new(super::key_value::KeyValueProcessor));
        reg.register(Arc::new(super::json_proc::JsonProcessor));
        reg.register(Arc::new(super::yaml_proc::YamlProcessor));
        reg.register(Arc::new(super::xml_proc::XmlProcessor));
        reg.register(Arc::new(super::csv_proc::CsvProcessor));
        reg.register(Arc::new(super::toml_proc::TomlProcessor));
        reg.register(Arc::new(super::env_proc::EnvProcessor));
        reg.register(Arc::new(super::ini_proc::IniProcessor));
        reg.register(Arc::new(super::log_line::LogLineProcessor::new()));
        reg
    }

    /// Register a processor. Overwrites any existing processor with the
    /// same name.
    pub fn register(&mut self, processor: Arc<dyn Processor>) {
        self.processors
            .insert(processor.name().to_string(), processor);
    }

    /// Look up a processor by its name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Processor>> {
        self.processors.get(name)
    }

    /// List all registered processor names.
    pub fn names(&self) -> Vec<&str> {
        self.processors.keys().map(|s| s.as_str()).collect()
    }

    /// Number of registered processors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.processors.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.processors.is_empty()
    }

    /// Find a processor that can handle the given content + profile.
    ///
    /// 1. If the profile names a specific processor, look it up directly.
    /// 2. Otherwise, iterate all processors and return the first whose
    ///    `can_handle` returns `true`.
    ///
    /// Returns `None` if no processor matches (caller should fall back
    /// to the streaming scanner).
    pub fn find_processor(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
    ) -> Option<&Arc<dyn Processor>> {
        // Direct lookup by profile's processor name.
        if let Some(proc) = self.processors.get(&profile.processor) {
            if proc.can_handle(content, profile) {
                return Some(proc);
            }
        }

        // Auto-detect: first matching processor.
        self.processors
            .values()
            .find(|proc| proc.can_handle(content, profile))
    }

    /// Process content using the matching processor.
    ///
    /// Returns `Ok(Some(output))` if a processor matched and succeeded,
    /// `Ok(None)` if no processor matches (caller should fall back),
    /// or `Err(...)` if processing failed.
    ///
    /// # Errors
    ///
    /// Returns the underlying processor's error if processing fails.
    pub fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<u8>>> {
        match self.find_processor(content, profile) {
            Some(proc) => {
                let output = proc.process(content, profile, store)?;
                Ok(Some(output))
            }
            None => Ok(None),
        }
    }
}

impl Default for ProcessorRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}
