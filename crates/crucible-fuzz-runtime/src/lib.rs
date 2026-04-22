pub mod action;
pub mod cmin;
pub mod coverage_utils;
pub mod generator;
pub mod input;
pub mod mutators;

#[cfg(test)]
pub(crate) mod test_helpers;

pub use action::FuzzAction;
pub use generator::ActionGenerator;
pub use input::{FuzzInput, ParseInfo};
pub use mutators::{
    gen_i128, gen_i64, gen_range_u128, gen_range_u64, gen_range_usize, gen_u128, gen_u64,
    gen_usize, mutate_bool, mutate_i128, mutate_i64, mutate_u128, mutate_u64, mutate_usize,
    rand_below, CrossoverMutator, ParamMutator, SequenceMutator, SuccessPatternMetadata,
    SuccessTrimStage,
};

// Re-export Rand trait so generated code can reference it
pub use libafl_bolts::rands::Rand as FuzzRand;

// Re-export serde_json so generated code can reference crucible_fuzzer::serde_json
pub use serde_json;

// Re-export concrete RNG type for use in generated code (e.g., success-seeking retries)
pub use libafl_bolts::rands::StdRand;
