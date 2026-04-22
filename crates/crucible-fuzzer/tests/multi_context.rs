//! Multi-context generalization verification tests.
//!
//! These tests verify that the multi-context codegen in crucible-fuzz-macro
//! correctly generalizes over N `TestContext` fields instead of using
//! hardcoded `self_b` references from the old feature/diff branch.
//!
//! Since `#[anchor_fuzz]` generates a `main()` function (incompatible with
//! `#[test]` harness), we verify correctness at the source/codegen level:
//! - Helpers iterate over the full `contexts` slice (normal mode)
//! - Helpers skip(1) for additional contexts (stateful mode)
//! - Generated variable names use index suffixes (`__pristine_svm_0`, etc.)
//! - Default `contexts = [ctx]` produces equivalent code to old single-context

use std::fs;
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .to_path_buf()
}

fn read_macro_src(filename: &str) -> String {
    let path = project_root()
        .join("crates/crucible-fuzz-macro/src")
        .join(filename);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e))
}

// =============================================================================
// Normal-mode helpers: iterate over ALL contexts
// =============================================================================

#[test]
fn test_normal_helpers_iterate_all_contexts() {
    // The 6 normal-mode helpers must iterate over the full `contexts` slice
    // (not skip any). This ensures single-context harnesses still work.
    let src = read_macro_src("codegen.rs");

    // contexts_take_snapshot: iterates all contexts
    let take_snap = extract_fn_body(&src, "fn contexts_take_snapshot(");
    assert!(
        take_snap.contains(".iter()") && !take_snap.contains(".skip("),
        "contexts_take_snapshot should iterate ALL contexts (no skip)",
    );

    // contexts_swap_out: iterates all with enumerate
    let swap_out = extract_fn_body(&src, "fn contexts_swap_out(");
    assert!(
        swap_out.contains(".enumerate()") && !swap_out.contains(".skip("),
        "contexts_swap_out should enumerate ALL contexts",
    );

    // contexts_reset_check: iterates all with enumerate
    let reset = extract_fn_body(&src, "fn contexts_reset_check(");
    assert!(
        reset.contains(".enumerate()") && !reset.contains(".skip("),
        "contexts_reset_check should enumerate ALL contexts",
    );

    // contexts_swap_in: iterates all with enumerate
    let swap_in = extract_fn_body(&src, "fn contexts_swap_in(");
    assert!(
        swap_in.contains(".enumerate()") && !swap_in.contains(".skip("),
        "contexts_swap_in should enumerate ALL contexts",
    );

    // contexts_restore_and_clear: iterates all
    let restore = extract_fn_body(&src, "fn contexts_restore_and_clear(");
    assert!(
        restore.contains(".iter()") && !restore.contains(".skip("),
        "contexts_restore_and_clear should iterate ALL contexts",
    );

    // contexts_swap_back: iterates all with enumerate
    let swap_back = extract_fn_body(&src, "fn contexts_swap_back(");
    assert!(
        swap_back.contains(".enumerate()") && !swap_back.contains(".skip("),
        "contexts_swap_back should enumerate ALL contexts",
    );
}

// =============================================================================
// Stateful-mode helpers: skip(1) for additional contexts
// =============================================================================

#[test]
fn test_stateful_helpers_skip_primary() {
    // The 5 stateful helpers handle contexts[1..] (additional contexts).
    // The primary context (index 0) is handled by existing stateful logic.
    let src = read_macro_src("codegen.rs");

    let helpers = [
        "fn stateful_extra_take_snapshot(",
        "fn stateful_extra_swap_out(",
        "fn stateful_extra_swap_in(",
        "fn stateful_extra_restore_and_swap_back(",
        "fn stateful_extra_swap_back(",
    ];

    for h in &helpers {
        let body = extract_fn_body(&src, h);
        assert!(
            body.contains(".skip(1)"),
            "{} must use .skip(1) to skip primary context",
            h,
        );
    }
}

#[test]
fn test_stateful_helpers_use_extra_svm_prefix() {
    // Stateful helpers generate `__extra_svm_{i}` variables (not `__pristine_svm`
    // or `__saved_svm`), distinguishing them from normal-mode RefCell variables.
    let src = read_macro_src("codegen.rs");

    let helpers_with_vars = [
        "fn stateful_extra_swap_out(",
        "fn stateful_extra_swap_in(",
        "fn stateful_extra_restore_and_swap_back(",
        "fn stateful_extra_swap_back(",
    ];

    for h in &helpers_with_vars {
        let body = extract_fn_body(&src, h);
        assert!(
            body.contains("__extra_svm_"),
            "{} should generate __extra_svm_{{i}} variables",
            h,
        );
    }
}

// =============================================================================
// Variable naming: indexed suffixes for multi-context support
// =============================================================================

#[test]
fn test_normal_helpers_use_indexed_variables() {
    // Normal-mode helpers create `__pristine_svm_{i}` and `__saved_svm_{i}`
    // using the enumerate index. This supports any number of contexts.
    let src = read_macro_src("codegen.rs");

    // contexts_swap_out creates both pristine and saved
    let swap_out = extract_fn_body(&src, "fn contexts_swap_out(");
    assert!(
        swap_out.contains("__pristine_svm_") && swap_out.contains("__saved_svm_"),
        "contexts_swap_out should create __pristine_svm_{{i}} and __saved_svm_{{i}}",
    );

    // contexts_reset_check references both
    let reset = extract_fn_body(&src, "fn contexts_reset_check(");
    assert!(
        reset.contains("__pristine_svm_") && reset.contains("__saved_svm_"),
        "contexts_reset_check should reference __pristine_svm_{{i}} and __saved_svm_{{i}}",
    );
}

// =============================================================================
// Default single-context: contexts = [ctx]
// =============================================================================

#[test]
fn test_default_contexts_is_ctx() {
    // When no `contexts = [...]` is specified, the default should be `[ctx]`.
    let src = read_macro_src("lib.rs");

    // The Default impl should produce vec![ctx]
    assert!(
        src.contains("format_ident!(\"ctx\")"),
        "FuzzArgs::default() should default to [ctx]",
    );

    // The Parse impl should fall back to [ctx] when contexts is None
    assert!(
        src.contains("unwrap_or_else"),
        "FuzzArgs::parse should fall back to default [ctx] when contexts not specified",
    );
}

#[test]
fn test_fuzz_args_parses_contexts_attribute() {
    // The parser should handle `contexts = [ident, ident, ...]` syntax.
    let src = read_macro_src("lib.rs");

    assert!(
        src.contains("\"contexts\"") || src.contains("ident == \"contexts\""),
        "FuzzArgs parser should recognize 'contexts' keyword",
    );
    assert!(
        src.contains("bracketed!"),
        "FuzzArgs parser should use syn::bracketed! for [ctx, ctx_b] syntax",
    );
    assert!(
        src.contains("parse_terminated"),
        "FuzzArgs parser should use parse_terminated for comma-separated idents",
    );
}

// =============================================================================
// Integration: helpers called with correct fixture params in stateful mode
// =============================================================================

#[test]
fn test_stateful_singlecore_uses_seed_fixture() {
    // In stateful singlecore, the seed phase uses `__seed_fixture` as the
    // fixture param for extra context swap operations.
    let src = read_macro_src("stateful.rs");

    assert!(
        src.contains("__seed_fixture"),
        "stateful singlecore should use __seed_fixture for seed phase",
    );
    // Both swap_in and swap_back for seed should be present
    assert!(
        src.contains("extra_swap_in_seed") && src.contains("extra_swap_back_seed"),
        "stateful singlecore should have seed-specific extra swap helpers",
    );
}

#[test]
fn test_stateful_multicore_uses_iter_fixture() {
    // In stateful multicore, the iteration fixture is `__iter_fixture`.
    let src = read_macro_src("stateful.rs");

    assert!(
        src.contains("__iter_fixture"),
        "stateful multicore should use __iter_fixture for iteration phase",
    );
    assert!(
        src.contains("extra_swap_in_iter") && src.contains("extra_restore_swap_back_iter"),
        "stateful multicore should have iter-specific extra swap helpers",
    );
}

// =============================================================================
// No-tracing switch: must handle all contexts
// =============================================================================

#[test]
fn test_no_tracing_switch_handles_all_contexts() {
    // contexts_no_tracing_switch must re-snapshot and re-swap ALL contexts
    // when switching from tracing to no-tracing mode.
    let src = read_macro_src("codegen.rs");

    let body = extract_fn_body(&src, "fn contexts_no_tracing_switch(");
    assert!(
        body.contains("take_snapshot") && body.contains("__pristine_svm_"),
        "no_tracing_switch should re-snapshot and update pristine SVMs for all contexts",
    );
    // Should NOT skip any contexts
    assert!(
        !body.contains(".skip("),
        "no_tracing_switch should handle ALL contexts (no skip)",
    );
}

// =============================================================================
// Helper: extract approximate function body from source
// =============================================================================

/// Extract the body of a function by finding its signature and counting braces.
/// Returns a rough substring from the function start to its closing brace.
fn extract_fn_body(src: &str, fn_sig: &str) -> String {
    let start = src
        .find(fn_sig)
        .unwrap_or_else(|| panic!("function not found: {}", fn_sig));

    let rest = &src[start..];

    // Find the opening brace
    let open = match rest.find('{') {
        Some(pos) => pos,
        None => return rest[..std::cmp::min(500, rest.len())].to_string(),
    };

    // Count braces to find the matching close
    let mut depth = 0;
    let mut end = open;
    for (i, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    rest[..end].to_string()
}
