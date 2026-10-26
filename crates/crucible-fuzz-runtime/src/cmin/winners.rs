//! Per-edge best-input tracking for streaming corpus minimization.

use std::ffi::{OsStr, OsString};

use rustc_hash::FxHashMap;

/// An input that is the best (smallest, then lowest file name) for at least one edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Winner {
    pub name: OsString,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
struct Owner {
    size: u64,
    slot: u32,
}

#[derive(Debug)]
struct Slot {
    name: OsString,
    size: u64,
    refs: u32,
}

/// Maps each edge seen so far to its best input. Memory is bounded by distinct edges, and the
/// winners match size-then-name-sorted streaming whatever order inputs arrive in.
#[derive(Debug, Default)]
pub struct WinnerTable {
    best: FxHashMap<u64, Owner>,
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
}

impl WinnerTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offers an input's edges; it takes every edge it is better for than the current owner.
    pub fn offer(&mut self, name: &OsStr, size: u64, edges: impl IntoIterator<Item = u64>) {
        let mut id: Option<u32> = None;
        for edge in edges {
            if let Some(&owner) = self.best.get(&edge) {
                if owner.size < size {
                    continue;
                }
                if owner.size == size && self.slot(owner.slot).name.as_os_str() <= name {
                    continue;
                }
            }
            let new_id = if let Some(i) = id {
                i
            } else {
                let i = self.alloc(name, size);
                id = Some(i);
                i
            };
            let taken = Owner { size, slot: new_id };
            if let Some(prev) = self.best.insert(edge, taken) {
                self.release(prev.slot);
            }
            self.slot_mut(new_id).refs += 1;
        }
    }

    pub fn edge_count(&self) -> usize {
        self.best.len()
    }

    pub fn live_winners(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub fn edges(&self) -> impl Iterator<Item = u64> + '_ {
        self.best.keys().copied()
    }

    /// Current winners in `(size, name)` order, so that `greedy_set_cover`'s
    /// earlier-index tie-breaking prefers smaller inputs.
    pub fn winners(&self) -> Vec<Winner> {
        let mut winners: Vec<Winner> = self
            .slots
            .iter()
            .flatten()
            .map(|s| Winner {
                name: s.name.clone(),
                size: s.size,
            })
            .collect();
        winners.sort_by(|a, b| (a.size, &a.name).cmp(&(b.size, &b.name)));
        winners
    }

    fn alloc(&mut self, name: &OsStr, size: u64) -> u32 {
        let slot = Some(Slot {
            name: name.to_owned(),
            size,
            refs: 0,
        });
        match self.free.pop() {
            Some(id) => {
                self.slots[id as usize] = slot;
                id
            }
            None => {
                let id =
                    u32::try_from(self.slots.len()).expect("live winners never exceed u32::MAX");
                self.slots.push(slot);
                id
            }
        }
    }

    fn release(&mut self, id: u32) {
        let slot = self.slot_mut(id);
        slot.refs -= 1;
        if slot.refs == 0 {
            self.slots[id as usize] = None;
            self.free.push(id);
        }
    }

    fn slot(&self, id: u32) -> &Slot {
        self.slots[id as usize]
            .as_ref()
            .expect("edge owner slot is live")
    }

    fn slot_mut(&mut self, id: u32) -> &mut Slot {
        self.slots[id as usize]
            .as_mut()
            .expect("edge owner slot is live")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    type Input = (String, u64, Vec<u64>);

    fn input(name: &str, size: u64, edges: &[u64]) -> Input {
        (name.to_string(), size, edges.to_vec())
    }

    fn offer_all(table: &mut WinnerTable, inputs: &[Input]) {
        for (name, size, edges) in inputs {
            table.offer(OsStr::new(name), *size, edges.iter().copied());
        }
    }

    fn winner_names(table: &WinnerTable) -> Vec<String> {
        table
            .winners()
            .into_iter()
            .map(|w| w.name.into_string().unwrap())
            .collect()
    }

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state >> 33
    }

    // Sizes come from a small range so that size ties, and therefore name tie-breaking, are common.
    fn random_corpus(seed: u64, n: usize, edge_space: u64) -> Vec<Input> {
        let mut s = seed;
        (0..n)
            .map(|i| {
                let size = lcg(&mut s) % 64;
                let k = 1 + lcg(&mut s) % 8;
                let edges = (0..k).map(|_| lcg(&mut s) % edge_space).collect();
                (format!("in{i:05}"), size, edges)
            })
            .collect()
    }

    fn shuffle<T>(v: &mut [T], seed: u64) {
        let mut s = seed;
        for i in (1..v.len()).rev() {
            let j = (lcg(&mut s) % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }

    /// libFuzzer-style merge: walk inputs by (size, name), keep each one that adds a new edge.
    fn sorted_streaming_reference(corpus: &[Input]) -> BTreeSet<String> {
        let mut sorted: Vec<&Input> = corpus.iter().collect();
        sorted.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
        let mut seen = HashSet::new();
        let mut kept = BTreeSet::new();
        for (name, _, edges) in sorted {
            let mut adds = false;
            for e in edges {
                adds |= seen.insert(*e);
            }
            if adds {
                kept.insert(name.clone());
            }
        }
        kept
    }

    #[test]
    fn equal_size_tie_breaks_by_name() {
        for inputs in [
            vec![input("b", 10, &[1]), input("a", 10, &[1])],
            vec![input("a", 10, &[1]), input("b", 10, &[1])],
        ] {
            let mut t = WinnerTable::new();
            offer_all(&mut t, &inputs);
            assert_eq!(winner_names(&t), vec!["a"]);
        }
    }

    #[test]
    fn fully_displaced_input_is_freed() {
        let mut t = WinnerTable::new();
        offer_all(
            &mut t,
            &[
                input("big", 100, &[1, 2, 3]),
                input("s1", 1, &[1, 2]),
                input("s2", 2, &[3]),
            ],
        );
        assert_eq!(winner_names(&t), vec!["s1", "s2"]);
        assert_eq!(t.live_winners(), 2);
    }

    #[test]
    fn partially_displaced_input_stays_live() {
        let mut t = WinnerTable::new();
        offer_all(
            &mut t,
            &[input("big", 100, &[1, 2, 3]), input("s", 1, &[1])],
        );
        assert_eq!(winner_names(&t), vec!["s", "big"]);
        let mut edges: Vec<u64> = t.edges().collect();
        edges.sort_unstable();
        assert_eq!(edges, vec![1, 2, 3]);
    }

    #[test]
    fn winners_are_independent_of_arrival_order() {
        let corpus = random_corpus(11, 2_000, 400);
        let mut t = WinnerTable::new();
        offer_all(&mut t, &corpus);
        let expected = t.winners();
        for seed in 1..=5 {
            let mut shuffled = corpus.clone();
            shuffle(&mut shuffled, seed);
            let mut u = WinnerTable::new();
            offer_all(&mut u, &shuffled);
            assert_eq!(u.winners(), expected, "shuffle seed {seed}");
        }
    }

    #[test]
    fn winners_match_size_sorted_streaming() {
        for seed in 1..=10 {
            let corpus = random_corpus(seed, 1_000, 250);
            let mut t = WinnerTable::new();
            offer_all(&mut t, &corpus);
            let got: BTreeSet<String> = winner_names(&t).into_iter().collect();
            assert_eq!(
                got,
                sorted_streaming_reference(&corpus),
                "corpus seed {seed}"
            );
        }
    }

    #[test]
    fn winners_are_sorted_by_size_then_name() {
        let mut t = WinnerTable::new();
        offer_all(
            &mut t,
            &[
                input("z", 1, &[1]),
                input("b", 7, &[2]),
                input("a", 7, &[3]),
                input("m", 3, &[4]),
            ],
        );
        assert_eq!(winner_names(&t), vec!["z", "m", "a", "b"]);
    }
}
