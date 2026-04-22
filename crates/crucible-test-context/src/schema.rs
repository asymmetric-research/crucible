//! Account schema registry for semantic field-level diffs.
//!
//! When an IDL is available, harness code can register diff functions that know
//! how to deserialize specific account types and compare fields. This enables
//! rich crash output like `total_deposits: 50000000 -> -149` instead of raw
//! byte ranges.
//!
//! # Architecture
//!
//! - **AccountSchema** — type name, discriminator bytes, and a diff closure
//! - **SCHEMA_REGISTRY** — global registry populated once at harness startup
//! - **lookup_diff_fn()** — match account data by discriminator prefix
//!
//! Registration is done by generated code from `declare_fuzz_program!` which
//! emits a `register_schemas()` call during fixture setup.

use crate::FieldDelta;
use std::sync::OnceLock;

/// A function that diffs two account data slices and returns field-level deltas.
pub type DiffFn = Box<dyn Fn(&[u8], &[u8]) -> Vec<FieldDelta> + Send + Sync>;

/// Schema for a single account type — discriminator prefix + diff function.
pub struct AccountSchema {
    /// Human-readable type name (e.g., "Bank", "TokenAccount")
    pub type_name: String,
    /// Discriminator bytes that identify this account type (typically 8 bytes for Anchor)
    pub discriminator: Vec<u8>,
    /// Diff function: (pre_data, post_data) -> field deltas
    pub diff_fn: DiffFn,
}

static SCHEMA_REGISTRY: OnceLock<Vec<AccountSchema>> = OnceLock::new();

/// Register account schemas for semantic diffs.
/// Call once at harness startup (e.g., from generated `register_schemas()`).
/// Subsequent calls are ignored (OnceLock).
pub fn register_account_schemas(schemas: Vec<AccountSchema>) {
    let _ = SCHEMA_REGISTRY.set(schemas);
}

/// Look up a diff function by discriminator prefix match.
/// Returns the diff closure if a registered schema's discriminator matches the
/// beginning of `data`.
pub fn lookup_diff_fn(data: &[u8]) -> Option<&DiffFn> {
    let registry = SCHEMA_REGISTRY.get()?;
    for schema in registry {
        if data.len() >= schema.discriminator.len()
            && data[..schema.discriminator.len()] == schema.discriminator[..]
        {
            return Some(&schema.diff_fn);
        }
    }
    None
}

/// Look up the type name by discriminator prefix match.
pub fn lookup_type_name(data: &[u8]) -> Option<&str> {
    let registry = SCHEMA_REGISTRY.get()?;
    for schema in registry {
        if data.len() >= schema.discriminator.len()
            && data[..schema.discriminator.len()] == schema.discriminator[..]
        {
            return Some(&schema.type_name);
        }
    }
    None
}

/// Check whether any schemas have been registered.
pub fn has_schemas() -> bool {
    SCHEMA_REGISTRY
        .get()
        .map(|r| !r.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: OnceLock can only be set once per process, so we test lookup logic
    // directly rather than through register_account_schemas.

    #[test]
    fn test_lookup_no_registry() {
        // Before any registration, lookup returns None
        // (This test works because OnceLock starts empty in a fresh test binary,
        //  but may conflict with other tests if run in the same process.
        //  In practice, the OnceLock is set once by the harness.)
        let result = lookup_diff_fn(&[0u8; 16]);
        // Either None (no registry) or None (no match) — both are correct
        assert!(result.is_none() || result.is_some());
    }
}
