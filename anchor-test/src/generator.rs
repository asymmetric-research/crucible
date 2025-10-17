//for generating data

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub trait InputGenerator<T> {
    fn generate(&mut self) -> T;
    //fn mutate(&mut self, input: &T) -> T;
}

pub struct RangeGenerator<T> {
    rng: StdRng,
    min: T,
    max: T,
}

impl<T> RangeGenerator<T> {
    pub fn new(seed: u64, min: T, max: T) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            min,
            max,
        }
    }
}

//generate functionality for each type
macro_rules! impl_range_generator {
    ($($t:ty),*) => {
        $(
            impl InputGenerator<$t> for RangeGenerator<$t> {
                fn generate(&mut self) -> $t {
                    self.rng.gen_range(self.min..self.max)
                }
            }
        )*
    };
}

impl_range_generator!(u8, u16, u32, u64);

pub struct FullRangeGenerator<T> {
    rng: StdRng,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> FullRangeGenerator<T> {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            _phantom: std::marker::PhantomData,
        }
    }
}


macro_rules! impl_full_range_generator {
    ($($t:ty),*) => {
        $(
            impl InputGenerator<$t> for FullRangeGenerator<$t> {
                fn generate(&mut self) -> $t {
                    self.rng.gen()
                }
            }
        )*
    };
}

impl_full_range_generator!(u8, u16, u32, u64);
