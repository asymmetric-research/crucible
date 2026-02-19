use std::marker::PhantomData;
use libafl::corpus::{Corpus, HasCurrentCorpusId};
use libafl::inputs::BytesInput;
use libafl::state::HasCorpus;
use libafl::stages::{Stage, Restartable};
use libafl::HasMetadata;
use libafl::Error;

use crate::action::FuzzAction;
use crate::input::FuzzInput;

/// Metadata attached to corpus entries recording which actions succeeded.
///
/// Set by `SuccessPatternFeedback::append_metadata` after each harness iteration.
/// Read by `SuccessTrimStage` to strip failed actions from corpus entries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuccessPatternMetadata {
    pub pattern: Vec<bool>,
}

libafl_bolts::impl_serdeany!(SuccessPatternMetadata);

/// Non-executing stage that trims failed actions from the current corpus entry in-place.
///
/// Reads `SuccessPatternMetadata` from the current corpus entry (set by
/// `SuccessPatternFeedback`), then removes actions where `pattern[i] == false`.
/// The corpus entry is rewritten directly — no execution happens. This ensures
/// subsequent mutators (seq/param/cross) start from a clean base of only
/// successful actions.
///
/// Skips trimming if:
/// - No metadata is attached (initial seed inputs)
/// - All actions succeeded (nothing to trim)
/// - All actions failed (would produce empty input)
pub struct SuccessTrimStage<A: FuzzAction> {
    _phantom: PhantomData<A>,
}

impl<A: FuzzAction> SuccessTrimStage<A> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<A, E, EM, S, Z> Stage<E, EM, S, Z> for SuccessTrimStage<A>
where
    A: FuzzAction,
    S: HasCorpus<BytesInput> + HasCurrentCorpusId,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        let current_id = match state.corpus().current() {
            Some(id) => *id,
            None => return Ok(()),
        };

        // Read success pattern metadata
        let pattern: Vec<bool> = {
            let tc = state.corpus().get(current_id)?;
            let tc_ref = tc.borrow();
            match tc_ref.metadata::<SuccessPatternMetadata>() {
                Ok(m) => m.pattern.clone(),
                Err(_) => return Ok(()),
            }
        };

        // Load and decode the input
        let input_bytes = {
            let tc = state.corpus().get(current_id)?;
            let tc_ref = tc.borrow();
            match tc_ref.input() {
                Some(input) => input.clone(),
                None => return Ok(()),
            }
        };

        let fuzz_input = FuzzInput::<A>::from_bytes(input_bytes.as_ref());
        if fuzz_input.actions.is_empty() {
            return Ok(());
        }

        let actions_len = fuzz_input.actions.len();
        let pattern_len = pattern.len();
        let effective_len = actions_len.min(pattern_len);
        let success_count = pattern[..effective_len].iter().filter(|&&s| s).count();

        // Skip if nothing to trim or everything failed
        if success_count == 0 || success_count == effective_len {
            return Ok(());
        }

        // Keep only successful actions
        let trimmed: Vec<A> = fuzz_input
            .actions
            .into_iter()
            .enumerate()
            .filter(|(i, _)| {
                if *i >= pattern_len {
                    return true;
                }
                pattern[*i]
            })
            .map(|(_, a)| a)
            .collect();

        if trimmed.is_empty() {
            return Ok(());
        }

        // Rewrite the corpus entry in-place
        let new_input = FuzzInput::new(trimmed);
        let new_bytes = BytesInput::new(new_input.to_bytes());
        {
            let tc = state.corpus().get(current_id)?;
            let mut tc_ref = tc.borrow_mut();
            *tc_ref.input_mut() = Some(new_bytes);
            // Remove stale success pattern since action indices shifted
            let _ = tc_ref.metadata_map_mut().remove::<SuccessPatternMetadata>();
        }

        Ok(())
    }
}

impl<A, S> Restartable<S> for SuccessTrimStage<A>
where
    A: FuzzAction,
{
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
