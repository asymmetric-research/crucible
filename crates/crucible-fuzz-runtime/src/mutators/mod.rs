pub mod crossover;
pub mod params;
pub mod primitives;
pub mod sequence;
pub mod trim;

#[cfg(test)]
mod bench_tests;

pub use crossover::CrossoverMutator;
pub use params::ParamMutator;
pub use primitives::{
    gen_i128, gen_i64, gen_range_u128, gen_range_u64, gen_range_usize, gen_u128, gen_u64,
    gen_usize, mutate_bool, mutate_i128, mutate_i64, mutate_u128, mutate_u64, mutate_usize,
    rand_below,
};
pub use sequence::SequenceMutator;
pub use trim::{SuccessPatternMetadata, SuccessTrimStage};
