// crucible-fuzzer/src/lib.rs

pub use crucible_fuzz_macro::crucible_fuzz;
pub use crucible_invariant_macro::fuzz_fixture;
pub use crucible_invariant_macro::invariant_test;
pub use crucible_test_context::AccountBuilderBase;
pub use crucible_test_context::AccountMutationConfig;
pub use crucible_test_context::TestContext;

// Re-export fuzz assertion macros
pub use crucible_test_context::fuzz_assert;
pub use crucible_test_context::fuzz_assert_eq;
pub use crucible_test_context::fuzz_assert_ge;
pub use crucible_test_context::fuzz_assert_gt;
pub use crucible_test_context::fuzz_assert_le;
pub use crucible_test_context::fuzz_assert_lt;
pub use crucible_test_context::fuzz_assert_ne;

// Re-export anchor-lang and anchor-spl so consumers don't need to depend on them directly
pub use anchor_lang;
pub use anchor_spl;

// Re-export fuzz runtime types for structured mutation
// These are used by generated code from #[fuzz_fixture] and #[crucible_fuzz(structured)]
pub use crucible_fuzz_runtime::ActionGenerator;
pub use crucible_fuzz_runtime::CrossoverMutator;
pub use crucible_fuzz_runtime::FuzzAction;
pub use crucible_fuzz_runtime::FuzzInput;
pub use crucible_fuzz_runtime::FuzzRand;
pub use crucible_fuzz_runtime::ParamMutator;
pub use crucible_fuzz_runtime::SequenceMutator;
pub use crucible_fuzz_runtime::StdRand;
pub use crucible_fuzz_runtime::{
    gen_i128, gen_i64, gen_range_u64, gen_range_usize, gen_u128, gen_u64, gen_usize, mutate_bool,
    mutate_i64, mutate_u64, mutate_usize, rand_below,
};
// Re-export serde_json for generated from_name_and_params code
pub use crucible_fuzz_runtime::cmin;
pub use crucible_fuzz_runtime::SuccessPatternMetadata;
pub use crucible_fuzz_runtime::SuccessTrimStage;
pub use serde_json;

// Re-export mimalloc for use as default global allocator in generated harnesses.
// mimalloc dramatically improves multi-threaded performance by eliminating
// allocator contention that the default system allocator suffers from.
pub use mimalloc::MiMalloc;

// Re-export libc for signal handling in generated harness code.
pub extern crate libc;
