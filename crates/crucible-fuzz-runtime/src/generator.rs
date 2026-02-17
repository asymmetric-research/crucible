use std::marker::PhantomData;
use libafl::generators::Generator;
use libafl::inputs::BytesInput;
use libafl::state::HasRand;
use crate::action::FuzzAction;
use crate::input::FuzzInput;

/// Generates random action sequences, serialized as `BytesInput`.
pub struct ActionGenerator<A: FuzzAction> {
    pub min_actions: usize,
    pub max_actions: usize,
    _phantom: PhantomData<A>,
}

impl<A: FuzzAction> ActionGenerator<A> {
    pub fn new(min_actions: usize, max_actions: usize) -> Self {
        Self {
            min_actions,
            max_actions,
            _phantom: PhantomData,
        }
    }
}

impl<A: FuzzAction, S: HasRand> Generator<BytesInput, S> for ActionGenerator<A> {
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, libafl::Error> {
        let rng = state.rand_mut();
        let count = if self.max_actions > self.min_actions {
            self.min_actions + crate::mutators::primitives::rand_below(rng, self.max_actions - self.min_actions + 1)
        } else {
            self.min_actions
        };
        let actions: Vec<A> = (0..count).map(|_| A::random(rng)).collect();
        let fuzz_input = FuzzInput::new(actions);
        Ok(BytesInput::new(fuzz_input.to_bytes()))
    }
}
