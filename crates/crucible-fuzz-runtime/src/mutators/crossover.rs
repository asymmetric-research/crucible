use std::marker::PhantomData;
use libafl::corpus::{Corpus, CorpusId};
use libafl::inputs::BytesInput;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::{HasCorpus, HasRand};
use libafl::Error;
use libafl_bolts::Named;

use crate::action::FuzzAction;
use crate::input::FuzzInput;

/// Crossover mutator: splices a subsequence from a random corpus entry.
///
/// Deserializes both donor and current to FuzzInput, picks a random subsequence
/// from the donor, inserts it into the current at a random position,
/// truncates to max_actions, and reserializes.
pub struct CrossoverMutator<A: FuzzAction> {
    pub max_actions: usize,
    _phantom: PhantomData<A>,
}

impl<A: FuzzAction> CrossoverMutator<A> {
    pub fn new(max_actions: usize) -> Self {
        Self {
            max_actions,
            _phantom: PhantomData,
        }
    }
}

impl<A: FuzzAction> Named for CrossoverMutator<A> {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("CrossoverMutator");
        &NAME
    }
}

impl<A, S> Mutator<BytesInput, S> for CrossoverMutator<A>
where
    A: FuzzAction,
    S: HasRand + HasCorpus<BytesInput>,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let corpus_count = state.corpus().count();
        if corpus_count == 0 {
            return Ok(MutationResult::Skipped);
        }

        // Pick a random corpus entry
        let corpus_idx = CorpusId::from(crate::mutators::primitives::rand_below(state.rand_mut(), corpus_count));

        let donor_bytes = {
            let mut tc = state.corpus().get(corpus_idx)?.borrow_mut();
            let donor_input = tc.load_input(state.corpus())?;
            donor_input.as_ref().to_vec()
        };

        let donor_fuzz = FuzzInput::<A>::from_bytes(&donor_bytes);
        if donor_fuzz.actions.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let mut fuzz_input = FuzzInput::<A>::from_bytes(input.as_ref());
        let rng = state.rand_mut();

        let donor_len = donor_fuzz.actions.len();
        let splice_start = crate::mutators::primitives::rand_below(rng, donor_len);
        let splice_len = 1 + crate::mutators::primitives::rand_below(rng, (donor_len - splice_start).min(4));
        let splice_end = (splice_start + splice_len).min(donor_len);

        let insert_at = if fuzz_input.actions.is_empty() {
            0
        } else {
            crate::mutators::primitives::rand_below(rng, fuzz_input.actions.len() + 1)
        };

        let actual_splice = splice_end - splice_start;
        fuzz_input.actions.reserve(actual_splice);
        for (i, action) in donor_fuzz.actions[splice_start..splice_end].iter().cloned().enumerate() {
            fuzz_input.actions.insert(insert_at + i, action);
        }

        fuzz_input.actions.truncate(self.max_actions);

        *input = BytesInput::new(fuzz_input.to_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
