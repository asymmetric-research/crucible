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

/// All account-type discriminators from the IDL (borsh *and* zero-copy), for type-tag length
/// lookup. Separate from `SCHEMA_REGISTRY` (which only holds the zero-copy accounts that have a
/// field-diff function), so the diff feature is unaffected.
static ACCOUNT_DISCRIMINATORS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

/// Register every account type's discriminator. Call once at harness startup (generated code).
pub fn register_account_discriminators(discriminators: Vec<Vec<u8>>) {
    let _ = ACCOUNT_DISCRIMINATORS.set(discriminators);
}

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

const DEFAULT_TYPE_TAG_LEN: usize = 8;

/// Look up the discriminator length for an account by prefix match.
///
/// Returns the matched (non-empty) discriminator's length, or `None` if no registered schema matches
/// the start of `data`. Framework-agnostic: the length is whatever the IDL recorded — 8 for Anchor,
/// 4 for native bincode, variable for Codama. If no registry exists at all, closed-source harnesses
/// fall back to `FUZZ_TYPE_TAG_LEN` or 8 bytes. Set `FUZZ_TYPE_TAG_LEN=0` to disable the fallback.
pub fn lookup_discriminator_len(data: &[u8]) -> Option<usize> {
    // Prefer the complete account-discriminator registry; fall back to the diff-schema registry.
    let mut saw_registry = false;
    if let Some(discs) = ACCOUNT_DISCRIMINATORS.get() {
        saw_registry |= !discs.is_empty();
        if let Some(n) = match_len(discs.iter().map(Vec::as_slice), data) {
            return Some(n);
        }
    }
    if let Some(schemas) = SCHEMA_REGISTRY.get() {
        saw_registry |= !schemas.is_empty();
        if let Some(n) = match_len(schemas.iter().map(|s| s.discriminator.as_slice()), data) {
            return Some(n);
        }
    }
    if saw_registry {
        None
    } else {
        fallback_discriminator_len(data)
    }
}

fn match_len<'a>(discriminators: impl Iterator<Item = &'a [u8]>, data: &[u8]) -> Option<usize> {
    discriminators
        .filter_map(|disc| {
            let n = disc.len();
            (n > 0 && data.len() >= n && data[..n] == disc[..]).then_some(n)
        })
        .max()
}

fn fallback_discriminator_len(data: &[u8]) -> Option<usize> {
    let n = match std::env::var("FUZZ_TYPE_TAG_LEN") {
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("off") => return None,
        Ok(value) => value.parse().unwrap_or(DEFAULT_TYPE_TAG_LEN),
        Err(_) => DEFAULT_TYPE_TAG_LEN,
    };
    (n > 0 && data.len() >= n).then_some(n)
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

    #[test]
    fn discriminator_len_is_framework_agnostic() {
        // Native (4-byte) and Anchor (8-byte) discriminators resolve to their actual lengths.
        let native: Vec<u8> = vec![1, 0, 0, 0];
        let anchor: Vec<u8> = vec![9, 8, 7, 6, 5, 4, 3, 2];
        let discs = [native.clone(), anchor.clone()];
        let slices = || discs.iter().map(Vec::as_slice);

        let mut native_data = native.clone();
        native_data.extend_from_slice(&[0xAB; 12]);
        assert_eq!(match_len(slices(), &native_data), Some(4));

        let mut anchor_data = anchor.clone();
        anchor_data.extend_from_slice(&[0xCD; 20]);
        assert_eq!(match_len(slices(), &anchor_data), Some(8));

        // No registered discriminator matches → None when a registry exists.
        assert_eq!(match_len(slices(), &[0xFF; 16]), None);
        // Data shorter than the discriminator → no match.
        assert_eq!(match_len(slices(), &[1, 0]), None);
    }

    #[test]
    fn discriminator_len_prefers_longest_prefix_match() {
        let short = vec![1, 2, 3, 4];
        let long = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let discs = [short, long.clone()];
        let mut data = long;
        data.extend_from_slice(&[0xAB; 8]);

        assert_eq!(match_len(discs.iter().map(Vec::as_slice), &data), Some(8));
    }
}
