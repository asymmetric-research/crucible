use libafl::corpus::CorpusId;
use libafl::inputs::BytesInput;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl::Error;
use libafl_bolts::Named;
use std::marker::PhantomData;

use crate::action::FuzzAction;
use crate::input::FuzzInput;

/// Parameter mutator: picks a random action and mutates its fields.
///
/// Deserializes to FuzzInput, picks a random action, calls `action.mutate(rng)`,
/// then reserializes.
pub struct ParamMutator<A: FuzzAction> {
    _phantom: PhantomData<A>,
}

impl<A: FuzzAction> ParamMutator<A> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<A: FuzzAction> Named for ParamMutator<A> {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("ParamMutator");
        &NAME
    }
}

impl<A, S> Mutator<BytesInput, S> for ParamMutator<A>
where
    A: FuzzAction,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let mut fuzz_input = FuzzInput::<A>::from_bytes(input.as_ref());
        if fuzz_input.actions.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let rng = state.rand_mut();
        let idx = crate::mutators::primitives::rand_below(rng, fuzz_input.actions.len());
        fuzz_input.actions[idx].mutate(rng);
        *input = BytesInput::new(fuzz_input.to_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
