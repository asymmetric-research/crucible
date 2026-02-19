// crucible-fuzzer/src/lib.rs

pub use crucible_fuzz_macro::anchor_fuzz;
pub use crucible_invariant_macro::fuzz_fixture;
pub use crucible_invariant_macro::invariant_test;
pub use crucible_test_context::TestContext;
pub use crucible_test_context::AccountBuilderBase;

// Re-export fuzz assertion macros
pub use crucible_test_context::fuzz_assert;
pub use crucible_test_context::fuzz_assert_eq;
pub use crucible_test_context::fuzz_assert_ne;
pub use crucible_test_context::fuzz_assert_le;
pub use crucible_test_context::fuzz_assert_lt;
pub use crucible_test_context::fuzz_assert_ge;
pub use crucible_test_context::fuzz_assert_gt;

// Re-export anchor-lang and anchor-spl so consumers don't need to depend on them directly
pub use anchor_lang;
pub use anchor_spl;

// Re-export fuzz runtime types for structured mutation
// These are used by generated code from #[fuzz_fixture] and #[anchor_fuzz(structured)]
pub use crucible_fuzz_runtime::FuzzAction;
pub use crucible_fuzz_runtime::FuzzInput;
pub use crucible_fuzz_runtime::ActionGenerator;
pub use crucible_fuzz_runtime::SequenceMutator;
pub use crucible_fuzz_runtime::ParamMutator;
pub use crucible_fuzz_runtime::CrossoverMutator;
pub use crucible_fuzz_runtime::{
    gen_range_u64, gen_range_usize, mutate_u64, mutate_usize, mutate_bool, mutate_i64,
    rand_below,
};
pub use crucible_fuzz_runtime::FuzzRand;
pub use crucible_fuzz_runtime::SuccessTrimStage;
pub use crucible_fuzz_runtime::SuccessPatternMetadata;

