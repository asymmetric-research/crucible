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

