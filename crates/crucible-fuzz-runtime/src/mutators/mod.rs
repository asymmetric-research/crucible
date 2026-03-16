pub mod primitives;
pub mod sequence;
pub mod params;
pub mod crossover;
pub mod trim;

#[cfg(test)]
mod bench_tests;

pub use primitives::{gen_range_u64, gen_range_u128, gen_range_usize, mutate_u64, mutate_u128, mutate_i128, mutate_usize, mutate_bool, mutate_i64, rand_below};
pub use sequence::SequenceMutator;
pub use params::ParamMutator;
pub use crossover::CrossoverMutator;
pub use trim::{SuccessTrimStage, SuccessPatternMetadata};
