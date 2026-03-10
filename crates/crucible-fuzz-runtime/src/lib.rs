pub mod action;
pub mod input;
pub mod generator;
pub mod mutators;

#[cfg(test)]
pub(crate) mod test_helpers;

pub use action::FuzzAction;
pub use input::{FuzzInput, ParseInfo};
pub use generator::ActionGenerator;
pub use mutators::{
    gen_range_u64, gen_range_u128, gen_range_usize, mutate_u64, mutate_u128, mutate_i128, mutate_usize, mutate_bool, mutate_i64,
    rand_below, SequenceMutator, ParamMutator, CrossoverMutator,
    SuccessTrimStage, SuccessPatternMetadata,
};

// Re-export Rand trait so generated code can reference it
pub use libafl_bolts::rands::Rand as FuzzRand;

// Re-export concrete RNG type for use in generated code (e.g., success-seeking retries)
pub use libafl_bolts::rands::StdRand;
