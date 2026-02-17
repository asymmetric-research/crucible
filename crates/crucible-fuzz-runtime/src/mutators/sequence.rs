use std::marker::PhantomData;
use libafl::inputs::BytesInput;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl::Error;
use libafl_bolts::Named;
use libafl::corpus::CorpusId;

use crate::action::FuzzAction;
use crate::input::FuzzInput;

/// Structural mutator for action sequences.
///
/// Wraps BytesInput: decodes to FuzzInput<A>, applies sequence-level mutations,
/// then re-encodes. Performs mutations that preserve action integrity:
/// - Swap two actions
/// - Delete a random action
/// - Duplicate an existing action
/// - Insert a new random action
/// - Shuffle a subsequence
/// - Truncate to random length
/// - Repeat an action
pub struct SequenceMutator<A: FuzzAction> {
    pub max_actions: usize,
    _phantom: PhantomData<A>,
}

impl<A: FuzzAction> SequenceMutator<A> {
    pub fn new(max_actions: usize) -> Self {
        Self {
            max_actions,
            _phantom: PhantomData,
        }
    }
}

impl<A: FuzzAction> Named for SequenceMutator<A> {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> = std::borrow::Cow::Borrowed("SequenceMutator");
        &NAME
    }
}

impl<A, S> Mutator<BytesInput, S> for SequenceMutator<A>
where
    A: FuzzAction,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let mut fuzz_input = FuzzInput::<A>::from_bytes(input.as_ref());
        let len = fuzz_input.actions.len();

        if len == 0 {
            fuzz_input.actions.push(A::random(state.rand_mut()));
            *input = BytesInput::new(fuzz_input.to_bytes());
            return Ok(MutationResult::Mutated);
        }

        let rng = state.rand_mut();

        // Action-count-aware mutation selection:
        // Growth mutations (2=duplicate, 3=insert, 6=repeat) outnumber shrink (1=delete) 3:1,
        // causing action counts to rapidly saturate at max_actions. Each action = 1 SVM tx,
        // so 8-action inputs cost ~4x more than 2-action inputs.
        // When at/above capacity, restrict to non-growth mutations to keep average action count lower.
        let mutation_type = if len >= self.max_actions {
            // At/above capacity: only pick from non-growth types
            // 0=swap, 1=delete, 4=shuffle, 5=truncate
            [0, 1, 4, 5][crate::mutators::primitives::rand_below(rng, 4)]
        } else {
            crate::mutators::primitives::rand_below(rng, 7)
        };

        match mutation_type {
            0 => {
                // Swap two random actions
                if len < 2 {
                    return Ok(MutationResult::Skipped);
                }
                let i = crate::mutators::primitives::rand_below(rng, len);
                let j = crate::mutators::primitives::rand_below(rng, len);
                if i == j {
                    return Ok(MutationResult::Skipped);
                }
                fuzz_input.actions.swap(i, j);
            }
            1 => {
                // Delete a random action (keep at least 1)
                if len <= 1 {
                    return Ok(MutationResult::Skipped);
                }
                let idx = crate::mutators::primitives::rand_below(rng, len);
                fuzz_input.actions.remove(idx);
            }
            2 => {
                // Duplicate an existing action
                if len >= self.max_actions {
                    return Ok(MutationResult::Skipped);
                }
                let src = crate::mutators::primitives::rand_below(rng, len);
                let cloned = fuzz_input.actions[src].clone();
                let insert_at = crate::mutators::primitives::rand_below(rng, len + 1);
                fuzz_input.actions.insert(insert_at, cloned);
            }
            3 => {
                // Insert a new random action
                if len >= self.max_actions {
                    return Ok(MutationResult::Skipped);
                }
                let action = A::random(rng);
                let insert_at = crate::mutators::primitives::rand_below(rng, len + 1);
                fuzz_input.actions.insert(insert_at, action);
            }
            4 => {
                // Shuffle a random subsequence
                if len < 3 {
                    return Ok(MutationResult::Skipped);
                }
                let start = crate::mutators::primitives::rand_below(rng, len - 1);
                let end = (start + 2 + crate::mutators::primitives::rand_below(rng, (len - start - 1).min(4))).min(len);

                // Fisher-Yates shuffle on the subsequence
                for i in (1..(end - start)).rev() {
                    let j = crate::mutators::primitives::rand_below(rng, i + 1);
                    fuzz_input.actions.swap(start + i, start + j);
                }
            }
            5 => {
                // Truncate to random shorter length
                if len <= 1 {
                    return Ok(MutationResult::Skipped);
                }
                let new_len = 1 + crate::mutators::primitives::rand_below(rng, len - 1);
                fuzz_input.actions.truncate(new_len);
            }
            6 => {
                // Repeat: copy an action to the position after it
                if len >= self.max_actions {
                    return Ok(MutationResult::Skipped);
                }
                let src = crate::mutators::primitives::rand_below(rng, len);
                let cloned = fuzz_input.actions[src].clone();
                let insert_at = (src + 1).min(len);
                fuzz_input.actions.insert(insert_at, cloned);
            }
            _ => unreachable!(),
        }

        // Enforce max_actions cap
        fuzz_input.actions.truncate(self.max_actions);

        *input = BytesInput::new(fuzz_input.to_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
