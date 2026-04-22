use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::Arc;

// =========================================================================
// Multi-iteration + dirty tracker
// =========================================================================

#[test]
fn test_multi_iteration_dirty_overlap() {
    // Run 3 iterations against the same snapshot with overlapping dirty sets.
    // After each restore, ALL accounts should be back to snapshot values.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    let acct_a = make_account(100, &[1]);
    let acct_b = make_account(200, &[2]);
    let acct_c = make_account(300, &[3]);
    svm.set_account(pk_a, acct_a.clone()).unwrap();
    svm.set_account(pk_b, acct_b.clone()).unwrap();
    svm.set_account(pk_c, acct_c.clone()).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    let mut dirty = DirtyTracker::new();

    // --- Iteration 1: dirties {A, B} ---
    dirty.clear();
    svm.set_account(pk_a, make_account(999, &[0xAA])).unwrap();
    svm.set_account(pk_b, make_account(888, &[0xBB])).unwrap();
    dirty.mark_account_dirty(&pk_a);
    dirty.mark_account_dirty(&pk_b);
    snap.restore(&mut svm, &dirty);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

    // --- Iteration 2: dirties {B, C} ---
    dirty.clear();
    svm.set_account(pk_b, make_account(777, &[0xBB])).unwrap();
    svm.set_account(pk_c, make_account(666, &[0xCC])).unwrap();
    dirty.mark_account_dirty(&pk_b);
    dirty.mark_account_dirty(&pk_c);
    snap.restore(&mut svm, &dirty);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

    // --- Iteration 3: dirties {A, C} ---
    dirty.clear();
    svm.set_account(pk_a, make_account(555, &[0xAA])).unwrap();
    svm.set_account(pk_c, make_account(444, &[0xCC])).unwrap();
    dirty.mark_account_dirty(&pk_a);
    dirty.mark_account_dirty(&pk_c);
    snap.restore(&mut svm, &dirty);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
}

#[test]
fn test_delta_chain_restore_full_at_each_level() {
    // Build A→B→C chain. Call restore_full from each delta and verify
    // each produces the exact state at that level — not a mix.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();
    let pk_z = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(10, &[1])).unwrap();
    svm.set_account(pk_y, make_account(20, &[2])).unwrap();
    svm.set_account(pk_z, make_account(30, &[3])).unwrap();

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action A: modify X → 100, add Z → 300
    svm.set_account(pk_x, make_account(100, &[0xA1])).unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk_x);
    let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

    // Action B: modify Y → 200 (parent = delta_a)
    svm.set_account(pk_y, make_account(200, &[0xB2])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_y);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

    // Action C: modify Z → 300 (parent = delta_b)
    svm.set_account(pk_z, make_account(300, &[0xC3])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_z);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);

    // Scramble SVM
    svm.set_account(pk_x, make_account(1, &[0])).unwrap();
    svm.set_account(pk_y, make_account(1, &[0])).unwrap();
    svm.set_account(pk_z, make_account(1, &[0])).unwrap();

    // Restore from delta_a: only X=100
    delta_a.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    // Y and Z not in delta_a, so SVM still has scrambled values for them
    // (restore_full only writes what's in the delta)

    // Scramble again
    svm.set_account(pk_x, make_account(1, &[0])).unwrap();
    svm.set_account(pk_y, make_account(1, &[0])).unwrap();
    svm.set_account(pk_z, make_account(1, &[0])).unwrap();

    // Restore from delta_b: X=100 (inherited from A), Y=200
    delta_b.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 200);

    // Scramble again
    svm.set_account(pk_x, make_account(1, &[0])).unwrap();
    svm.set_account(pk_y, make_account(1, &[0])).unwrap();
    svm.set_account(pk_z, make_account(1, &[0])).unwrap();

    // Restore from delta_c: X=100 (inherited), Y=200 (inherited), Z=300
    delta_c.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_z).unwrap().lamports, 300);
}

// =========================================================================
// Gap 1: restore_selective → restore_selective_from transition
//
// The real fuzzer uses restore_selective on iteration 1 (no prev_delta),
// then switches to restore_selective_from on iteration 2+. This test
// exercises the exact handoff with real divergent_keys accumulation.
// =========================================================================

#[test]
fn test_restore_selective_to_from_transition() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    // Initial state
    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();
    svm.set_account(pk_c, make_account(300, &[3])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State variables matching the real loop
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // --- Build two pool states ---
    // State 0 (initial): empty delta
    let _delta_0 = SvmSnapshot::empty(initial.clock().clone());

    // State 1: pk_a=500 (from action on state 0)
    let mut delta_1_accounts = FastHashMap::default();
    delta_1_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
    let delta_1 = SvmSnapshot {
        accounts: delta_1_accounts,
        sysvars: make_test_sysvars(10),
    };

    // State 2: pk_a=500 (inherited), pk_b=600 (from action on state 1)
    let mut delta_2_accounts = FastHashMap::default();
    delta_2_accounts.insert(pk_a, delta_1.accounts()[&pk_a].clone()); // same Arc
    delta_2_accounts.insert(pk_b, Arc::new(make_account(600, &[6])));
    let delta_2 = SvmSnapshot {
        accounts: delta_2_accounts,
        sysvars: make_test_sysvars(20),
    };

    // === ITERATION 1: Pick state 1, use restore_selective ===
    // (prev_delta_arc is None)
    assert!(prev_delta_arc.is_none());
    initial.restore_selective(&mut svm, &divergent_keys, &delta_1);

    // Real loop: divergent_keys = delta.keys()
    divergent_keys.clear();
    divergent_keys.extend(delta_1.accounts().keys().copied());

    // Verify SVM state after restore
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // initial
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // initial

    // Simulate action execution: dirtied pk_a and pk_c
    svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
    svm.set_account(pk_c, make_account(350, &[0xCC])).unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_a);
    dirty.mark_account_dirty(&pk_c);

    // Real loop end: update tracking variables
    let action_succeeded = true;
    prev_exec_dirty.clear();
    if action_succeeded {
        prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
        divergent_keys.extend(prev_exec_dirty.iter().copied());
    }
    prev_delta_arc = Some(delta_1.clone());

    // divergent_keys should now be {pk_a, pk_c} (delta_1 keys ∪ dirty accounts)
    assert!(divergent_keys.contains(&pk_a));
    assert!(divergent_keys.contains(&pk_c));
    assert!(!divergent_keys.contains(&pk_b)); // not in delta_1, not dirtied

    // === ITERATION 2: Pick state 2, use restore_selective_from ===
    assert!(prev_delta_arc.is_some());
    let prev = prev_delta_arc.as_ref().unwrap();
    initial.restore_selective_from(&mut svm, &divergent_keys, prev, &delta_2, &prev_exec_dirty);

    // Real loop: divergent_keys = delta.keys()
    divergent_keys.clear();
    divergent_keys.extend(delta_2.accounts().keys().copied());

    // Verify SVM state:
    // pk_a: in delta_2 (500). Same Arc as delta_1. But pk_a IS in prev_exec_dirty
    //        → forced write → SVM gets 500 (correct, overwriting the 550 from execution)
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
    // pk_b: in delta_2 (600). NOT in prev_delta (delta_1). → unconditional write
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600);
    // pk_c: in divergent_keys, NOT in delta_2 → restored to initial (300)
    //        (was 350 after execution, needs to be reset)
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    // Clock should be from delta_2
    assert_eq!(svm.get_sysvar::<Clock>().slot, 20);
}

// =========================================================================
// Gap 2: divergent_keys = delta.keys() ∪ prev_exec_dirty
//
// Tests the exact union computation. Specifically: an account that's in
// prev_exec_dirty but NOT in any delta still gets restored to initial.
// =========================================================================

#[test]
fn test_divergent_keys_union_exec_dirty_outside_delta() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_cpi = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    // pk_cpi does NOT exist initially (CPI-created during iteration)
    let tracked: HashSet<Pubkey> = [pk_a].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Delta has pk_a=500 only
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // === Iteration 1: restore_selective ===
    initial.restore_selective(&mut svm, &divergent_keys, &delta);
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());

    // Simulate execution: pk_a modified + CPI creates pk_cpi
    svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
    svm.set_account(pk_cpi, make_account(999, &[9, 9])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_a);
    prev_exec_dirty.insert(pk_cpi);
    divergent_keys.extend(prev_exec_dirty.iter().copied());

    // divergent_keys = {pk_a} (from delta) ∪ {pk_a, pk_cpi} (from exec dirty) = {pk_a, pk_cpi}
    assert!(divergent_keys.contains(&pk_a));
    assert!(divergent_keys.contains(&pk_cpi));

    // === Iteration 2: pick a state with empty delta (initial state) ===
    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    let prev_delta = delta.clone();

    initial.restore_selective_from(
        &mut svm,
        &divergent_keys,
        &prev_delta,
        &empty_delta,
        &prev_exec_dirty,
    );

    // pk_a: in divergent, NOT in empty_delta → restored to initial (100)
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    // pk_cpi: in divergent, NOT in empty_delta, NOT in initial → zeroed (deleted)
    assert!(svm.get_account(&pk_cpi).is_none());
}

#[test]
fn test_divergent_keys_prev_exec_dirty_account_in_initial() {
    // Account in prev_exec_dirty that IS in initial snapshot and is NOT in
    // either delta. After restore, it should be back to initial value.
    let mut svm = LiteSVM::new();
    let pk_target = Pubkey::new_unique();
    let pk_delta = Pubkey::new_unique();

    svm.set_account(pk_target, make_account(100, &[1])).unwrap();
    svm.set_account(pk_delta, make_account(200, &[2])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_target, pk_delta].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // prev_delta only has pk_delta=500
    let mut prev_accounts = FastHashMap::default();
    prev_accounts.insert(pk_delta, Arc::new(make_account(500, &[5])));
    let prev_delta = SvmSnapshot {
        accounts: prev_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // next_delta also only has pk_delta=500 (same state picked again)
    let next_delta = prev_delta.clone();

    // divergent_keys = {pk_delta} (from prev delta) ∪ {pk_target} (from prev exec dirty)
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    divergent_keys.insert(pk_delta);
    divergent_keys.insert(pk_target);

    // pk_target was exec-dirty (modified by previous action)
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_target);

    // SVM must be consistent with prev_delta state (simulating previous restore wrote it).
    // pk_delta was set to 500 by the previous restore_selective call.
    svm.set_account(pk_delta, make_account(500, &[5])).unwrap();
    // pk_target was modified by execution AFTER prev restore (SVM has garbage 999)
    svm.set_account(pk_target, make_account(999, &[9])).unwrap();

    initial.restore_selective_from(
        &mut svm,
        &divergent_keys,
        &prev_delta,
        &next_delta,
        &prev_exec_dirty,
    );

    // pk_target: in divergent, NOT in next_delta → restored to initial (100)
    assert_eq!(svm.get_account(&pk_target).unwrap().lamports, 100);
    // pk_delta: in both deltas, same Arc, NOT in prev_exec_dirty → skipped.
    // SVM already has the correct value (500) from the previous restore.
    assert_eq!(svm.get_account(&pk_delta).unwrap().lamports, 500);
}

// =========================================================================
// Gap 3: Same state picked consecutively
//
// When the pool returns the same state twice in a row, prev_delta == next_delta
// (identical object). All Arcs are ptr_eq. Only prev_exec_dirty accounts
// get written. This is the hot path.
// =========================================================================

#[test]
fn test_same_state_picked_consecutively() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();
    svm.set_account(pk_c, make_account(300, &[3])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Build a state delta: pk_a=500, pk_b=600
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
    delta_accounts.insert(pk_b, Arc::new(make_account(600, &[6])));
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: make_test_sysvars(50),
    };

    // === Iteration 1: restore_selective (no prev) ===
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent_keys, &delta);
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);

    // Simulate execution: dirtied pk_a and pk_c
    svm.set_account(pk_a, make_account(555, &[0xAA])).unwrap();
    svm.set_account(pk_c, make_account(333, &[0xCC])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_a);
    prev_exec_dirty.insert(pk_c);
    divergent_keys.extend(prev_exec_dirty.iter().copied());

    // === Iteration 2: SAME state picked again ===
    // prev_delta and next_delta are the same object → all Arcs are ptr_eq
    let count =
        initial.restore_selective_from(&mut svm, &divergent_keys, &delta, &delta, &prev_exec_dirty);

    // pk_a: same Arc, BUT in prev_exec_dirty → forced write (1 call)
    // pk_b: same Arc, NOT in prev_exec_dirty → skipped (0 calls)
    // pk_c: in divergent, NOT in delta → restored to initial (1 call)
    assert_eq!(count, 2); // pk_a + pk_c

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500); // delta value restored
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 600); // untouched, still correct
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // back to initial
}

// =========================================================================
// Gap 4: Tombstone in delta overlaid via restore_selective
//
// When a delta contains a tombstone (lamports=0) and the SVM has a live
// account at that key (from CPI in a prior iteration), restore_selective
// step 2 should zero it.
// =========================================================================

#[test]
fn test_restore_selective_tombstone_overlay() {
    let mut svm = LiteSVM::new();
    let pk_live = Pubkey::new_unique();
    let pk_tombstoned = Pubkey::new_unique();

    svm.set_account(pk_live, make_account(100, &[1])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_live].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Delta has a tombstone for pk_tombstoned (account was deleted in this state)
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(
        pk_tombstoned,
        Arc::new(Account {
            lamports: 0,
            ..Default::default()
        }),
    );
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // SVM has a live account at pk_tombstoned (CPI-created in prior iteration)
    svm.set_account(pk_tombstoned, make_account(999, &[9, 9]))
        .unwrap();
    assert!(svm.get_account(&pk_tombstoned).is_some());

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);

    // Tombstone written by step 2 → LiteSVM treats zero-lamport as deleted
    assert!(svm.get_account(&pk_tombstoned).is_none());
}

#[test]
fn test_restore_selective_from_tombstone_overlay() {
    // Same as above but via restore_selective_from path.
    // Tombstone is in next_delta, SVM has live account.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    svm.set_account(pk, make_account(100, &[1])).unwrap();
    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // prev_delta: pk=500 (live)
    let mut prev_accounts = FastHashMap::default();
    prev_accounts.insert(pk, Arc::new(make_account(500, &[5])));
    let prev_delta = SvmSnapshot {
        accounts: prev_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // next_delta: pk=tombstone (deleted in this state)
    let mut next_accounts = FastHashMap::default();
    next_accounts.insert(
        pk,
        Arc::new(Account {
            lamports: 0,
            ..Default::default()
        }),
    );
    let next_delta = SvmSnapshot {
        accounts: next_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // SVM has pk=500 (from prev_delta restore)
    svm.set_account(pk, make_account(500, &[5])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);
    let prev_exec_dirty = FastHashSet::default();

    initial.restore_selective_from(
        &mut svm,
        &divergent,
        &prev_delta,
        &next_delta,
        &prev_exec_dirty,
    );

    // pk: in next_delta (tombstone), different Arc from prev_delta → written
    assert!(svm.get_account(&pk).is_none());
}

// =========================================================================
// Gap 5: Failed action leaves prev_exec_dirty empty
//
// If the action fails, prev_exec_dirty stays cleared. On next iteration,
// restore_selective_from skips more Arcs. But the DirtyTracker still
// recorded writable accounts from the instructions. The real code only
// populates prev_exec_dirty on success.
// =========================================================================

#[test]
fn test_failed_action_empty_prev_exec_dirty() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State delta: pk_a=500
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(500, &[5])));
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: make_test_sysvars(10),
    };

    // === Iteration 1: restore + execute (action SUCCEEDS) ===
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent_keys, &delta);
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());

    // Action modifies pk_a and pk_b
    svm.set_account(pk_a, make_account(550, &[0xAA])).unwrap();
    svm.set_account(pk_b, make_account(250, &[0xBB])).unwrap();

    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    // Action succeeded → populate prev_exec_dirty
    prev_exec_dirty.insert(pk_a);
    prev_exec_dirty.insert(pk_b);
    divergent_keys.extend(prev_exec_dirty.iter().copied());
    let prev_delta = delta.clone();

    // === Iteration 2: same state picked, action FAILS ===
    initial.restore_selective_from(
        &mut svm,
        &divergent_keys,
        &prev_delta,
        &delta,
        &prev_exec_dirty,
    );
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());

    // Verify state is correct after restore
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // back to initial

    // Simulate FAILED action: SVM was modified but action_succeeded = false
    svm.set_account(pk_a, make_account(777, &[0xFF])).unwrap();
    svm.set_account(pk_b, make_account(888, &[0xEE])).unwrap();

    // Failed action: prev_exec_dirty stays EMPTY (real loop clears it)
    prev_exec_dirty.clear();
    // divergent_keys NOT extended (action failed)
    let prev_delta_2 = delta.clone();

    // === Iteration 3: same state picked again ===
    // prev_exec_dirty is EMPTY. pk_a has same Arc in both deltas → SKIPPED.
    // But SVM has pk_a=777 (garbage from failed execution)!
    let count = initial.restore_selective_from(
        &mut svm,
        &divergent_keys,
        &prev_delta_2,
        &delta,
        &prev_exec_dirty,
    );

    // pk_a: same Arc, NOT in prev_exec_dirty → SKIPPED. SVM still has 777 (STALE!)
    // pk_b: NOT in divergent_keys (only delta keys = {pk_a}). NOT in delta. Never touched.
    //        SVM has 888 (STALE from failed execution!)
    //
    // This documents a KNOWN LIMITATION: failed actions can leave SVM in a dirty
    // state that is not detected by the Arc skip optimization. The real fuzzer
    // accepts this trade-off because:
    //   1. Failed actions typically don't modify SVM state (tx reverts)
    //   2. The DirtyTracker records intended writes, not actual writes
    //   3. The performance gain of skipping is worth occasional stale reads
    assert_eq!(count, 0); // everything skipped
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 777); // stale!
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 888); // stale!
}

// =========================================================================
// Gap 6: Deeper chains (5 levels) with mixed modifications
//
// Real chains go 5-20 levels deep. Tests accumulation bugs:
// - Divergent keys growing correctly
// - Arc pointers shared across multiple levels
// - Accounts modified at some levels but not others
// - State restored correctly after jumping between deep chain nodes
// =========================================================================

#[test]
fn test_deep_chain_five_levels() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();
    let pk_e = Pubkey::new_unique();
    let pks = [pk_a, pk_b, pk_c, pk_d, pk_e];

    // Initial state: each account has lamports = 10 * (index+1)
    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[i as u8]))
            .unwrap();
    }
    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Level 1: modify A → 100
    svm.set_account(pk_a, make_account(100, &[0x01])).unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_a);
    let delta_1 = SvmSnapshot::take_delta(&svm, &delta_root, &dirty);
    assert_eq!(delta_1.account_count(), 1);

    // Level 2: modify B → 200 (parent=delta_1)
    svm.set_account(pk_b, make_account(200, &[0x02])).unwrap();
    dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_b);
    let delta_2 = SvmSnapshot::take_delta(&svm, &delta_1, &dirty);
    assert_eq!(delta_2.account_count(), 2);
    // A inherited from delta_1 via Arc
    assert!(Arc::ptr_eq(
        &delta_2.accounts()[&pk_a],
        &delta_1.accounts()[&pk_a]
    ));

    // Level 3: modify C → 300 (parent=delta_2)
    svm.set_account(pk_c, make_account(300, &[0x03])).unwrap();
    dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_c);
    let delta_3 = SvmSnapshot::take_delta(&svm, &delta_2, &dirty);
    assert_eq!(delta_3.account_count(), 3);
    // A and B inherited via Arc from delta_2
    assert!(Arc::ptr_eq(
        &delta_3.accounts()[&pk_a],
        &delta_1.accounts()[&pk_a]
    ));
    assert!(Arc::ptr_eq(
        &delta_3.accounts()[&pk_b],
        &delta_2.accounts()[&pk_b]
    ));

    // Level 4: modify A AGAIN → 400 (parent=delta_3)
    svm.set_account(pk_a, make_account(400, &[0x04])).unwrap();
    dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_a);
    let delta_4 = SvmSnapshot::take_delta(&svm, &delta_3, &dirty);
    assert_eq!(delta_4.account_count(), 3);
    // A is a NEW Arc (overwritten), B and C inherited
    assert!(!Arc::ptr_eq(
        &delta_4.accounts()[&pk_a],
        &delta_3.accounts()[&pk_a]
    ));
    assert!(Arc::ptr_eq(
        &delta_4.accounts()[&pk_b],
        &delta_2.accounts()[&pk_b]
    ));
    assert!(Arc::ptr_eq(
        &delta_4.accounts()[&pk_c],
        &delta_3.accounts()[&pk_c]
    ));

    // Level 5: modify D and E → 500, 600 (parent=delta_4)
    svm.set_account(pk_d, make_account(500, &[0x05])).unwrap();
    svm.set_account(pk_e, make_account(600, &[0x06])).unwrap();
    dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_d);
    dirty.mark_account_dirty(&pk_e);
    let delta_5 = SvmSnapshot::take_delta(&svm, &delta_4, &dirty);
    assert_eq!(delta_5.account_count(), 5); // all accounts now in delta

    // --- Now test restore_full at each level ---

    // Scramble SVM
    for pk in &pks {
        svm.set_account(*pk, make_account(1, &[0])).unwrap();
    }

    // restore_full from delta_2: A=100, B=200
    delta_2.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);

    // restore_full from delta_5: A=400, B=200, C=300, D=500, E=600
    delta_5.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 400); // overwritten at level 4
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_e).unwrap().lamports, 600);

    // --- Test restore_selective jumping from deep to shallow ---
    // SVM is at delta_5 state. Jump to delta_2 (A=100, B=200 only).
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    for pk in delta_5.accounts().keys() {
        divergent.insert(*pk);
    }

    initial.restore_selective(&mut svm, &divergent, &delta_2);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    // C, D, E: in divergent but NOT in delta_2 → restored to initial
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30); // initial
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 40); // initial
    assert_eq!(svm.get_account(&pk_e).unwrap().lamports, 50); // initial
}

#[test]
fn test_deep_chain_selective_from_between_levels() {
    // Jump between delta_3 and delta_5 using restore_selective_from.
    // Tests Arc sharing across 3+ levels.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    svm.set_account(pk_c, make_account(30, &[3])).unwrap();
    svm.set_account(pk_d, make_account(40, &[4])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c, pk_d].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Build chain: root → 1(A=100) → 2(B=200) → 3(C=300) → 4(A=400) → 5(D=500)
    svm.set_account(pk_a, make_account(100, &[0x11])).unwrap();
    let mut d = DirtyTracker::new();
    d.mark_account_dirty(&pk_a);
    let delta_1 = SvmSnapshot::take_delta(&svm, &delta_root, &d);

    svm.set_account(pk_b, make_account(200, &[0x22])).unwrap();
    d = DirtyTracker::new();
    d.mark_account_dirty(&pk_b);
    let delta_2 = SvmSnapshot::take_delta(&svm, &delta_1, &d);

    svm.set_account(pk_c, make_account(300, &[0x33])).unwrap();
    d = DirtyTracker::new();
    d.mark_account_dirty(&pk_c);
    let delta_3 = SvmSnapshot::take_delta(&svm, &delta_2, &d);

    svm.set_account(pk_a, make_account(400, &[0x44])).unwrap();
    d = DirtyTracker::new();
    d.mark_account_dirty(&pk_a);
    let delta_4 = SvmSnapshot::take_delta(&svm, &delta_3, &d);

    svm.set_account(pk_d, make_account(500, &[0x55])).unwrap();
    d = DirtyTracker::new();
    d.mark_account_dirty(&pk_d);
    let delta_5 = SvmSnapshot::take_delta(&svm, &delta_4, &d);

    // Reset SVM to initial state before starting the simulated loop.
    // Chain building left the SVM at the level-5 state. In the real fuzzer,
    // the SVM starts at initial before the first iteration.
    initial.restore_full(&mut svm);

    // === Simulated loop: iteration 1 picks delta_3 ===
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent_keys, &delta_3);
    divergent_keys.clear();
    divergent_keys.extend(delta_3.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 40); // initial

    // Simulate execution: dirtied pk_a
    svm.set_account(pk_a, make_account(150, &[0xAA])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_a);
    divergent_keys.extend(prev_exec_dirty.iter().copied());

    // === Iteration 2: jump to delta_5 ===
    let count = initial.restore_selective_from(
        &mut svm,
        &divergent_keys,
        &delta_3,
        &delta_5,
        &prev_exec_dirty,
    );

    // Analyze what happens:
    // delta_3 has: {A=100, B=200, C=300}
    // delta_5 has: {A=400, B=200, C=300, D=500}
    //
    // Step 1 (divergent not in delta_5): nothing (all divergent keys are in delta_5)
    // Step 2 (delta_5 accounts):
    //   A: prev_exec_dirty contains A → forced write (400). Count +1.
    //   B: Arc::ptr_eq(delta_3[B], delta_5[B])? Both inherited from delta_2 → YES. Skip.
    //   C: Arc::ptr_eq(delta_3[C], delta_5[C])? delta_3 created C, delta_5 inherited → YES. Skip.
    //   D: NOT in delta_3 → unconditional write (500). Count +1.
    assert_eq!(count, 2);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 400); // forced write
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200); // skipped (correct)
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300); // skipped (correct)
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 500); // new in delta_5
}

// =========================================================================
// Full mini-fuzzing-loop integration test
//
// Runs 4 iterations mimicking the exact real loop:
//   Iter 1: restore_selective (no prev), execute, succeed
//   Iter 2: restore_selective_from (same state), execute, succeed
//   Iter 3: restore_selective_from (different state), execute, FAIL
//   Iter 4: restore_selective_from (jump to shallow state), execute, succeed
// Verifies all 6 gaps in a single realistic scenario.
// =========================================================================

#[test]
fn test_full_mini_fuzzing_loop() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    svm.set_account(pk_c, make_account(30, &[3])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Pool states (pre-built):
    // State 0 (initial): empty delta
    let state_0 = SvmSnapshot::empty(initial.clock().clone());
    // State 1: A=100 (from action on state 0)
    let mut s1_accounts = FastHashMap::default();
    s1_accounts.insert(pk_a, Arc::new(make_account(100, &[0x11])));
    let state_1 = SvmSnapshot {
        accounts: s1_accounts,
        sysvars: make_test_sysvars(10),
    };
    // State 2: A=100 (inherited from state 1), B=200
    let mut s2_accounts = FastHashMap::default();
    s2_accounts.insert(pk_a, state_1.accounts()[&pk_a].clone()); // same Arc
    s2_accounts.insert(pk_b, Arc::new(make_account(200, &[0x22])));
    let state_2 = SvmSnapshot {
        accounts: s2_accounts,
        sysvars: make_test_sysvars(20),
    };

    // Loop state
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // ====== ITERATION 1: pick state_1, restore_selective ======
    {
        let delta = &state_1;
        assert!(prev_delta_arc.is_none());
        initial.restore_selective(&mut svm, &divergent_keys, delta);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

        // Execute: modify A, success
        svm.set_account(pk_a, make_account(150, &[0xAA])).unwrap();
        let action_succeeded = true;
        prev_exec_dirty.clear();
        if action_succeeded {
            prev_exec_dirty.insert(pk_a);
            divergent_keys.extend(prev_exec_dirty.iter().copied());
        }
        prev_delta_arc = Some(delta.clone());
    }

    // ====== ITERATION 2: pick state_1 AGAIN (same state), restore_selective_from ======
    {
        let delta = &state_1;
        let prev = prev_delta_arc.as_ref().unwrap();
        let count = initial.restore_selective_from(
            &mut svm,
            &divergent_keys,
            prev,
            delta,
            &prev_exec_dirty,
        );
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // A: same Arc, BUT in prev_exec_dirty → forced write
        assert_eq!(count, 1); // only A written
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

        // Execute: modify B and C, success
        svm.set_account(pk_b, make_account(25, &[0xBB])).unwrap();
        svm.set_account(pk_c, make_account(35, &[0xCC])).unwrap();
        let action_succeeded = true;
        prev_exec_dirty.clear();
        if action_succeeded {
            prev_exec_dirty.insert(pk_b);
            prev_exec_dirty.insert(pk_c);
            divergent_keys.extend(prev_exec_dirty.iter().copied());
        }
        prev_delta_arc = Some(delta.clone());
    }

    // ====== ITERATION 3: pick state_2 (different state), action FAILS ======
    {
        let delta = &state_2;
        let prev = prev_delta_arc.as_ref().unwrap();
        initial.restore_selective_from(&mut svm, &divergent_keys, prev, delta, &prev_exec_dirty);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // A: same Arc between state_1 and state_2 → skip? No! B and C are in prev_exec_dirty,
        //    but A is NOT → skip is correct. A should still be 100.
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
        // B: in delta_2 (200), different from state_1 (no B) → unconditional write
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
        // C: in divergent (from prev exec dirty), NOT in delta_2 → restored to initial
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);

        // Execute: modify A, but action FAILS
        svm.set_account(pk_a, make_account(999, &[0xFF])).unwrap();
        let action_succeeded = false;
        prev_exec_dirty.clear();
        if action_succeeded {
            // NOT executed — prev_exec_dirty stays empty
            unreachable!();
        }
        // divergent_keys NOT extended (action failed)
        prev_delta_arc = Some(delta.clone());
    }

    // ====== ITERATION 4: jump to state_0 (shallow), restore_selective_from ======
    {
        let delta = &state_0;
        let prev = prev_delta_arc.as_ref().unwrap();
        initial.restore_selective_from(&mut svm, &divergent_keys, prev, delta, &prev_exec_dirty);
        divergent_keys.clear();
        divergent_keys.extend(delta.accounts().keys().copied());

        // state_0 is empty delta → all divergent keys restored to initial
        // divergent_keys was {A, B} from state_2. state_0 is empty.
        // Step 1: A and B both not in empty delta → restored to initial
        // Step 2: empty delta → nothing
        // BUT: A was modified to 999 in failed iteration 3, and prev_exec_dirty is EMPTY.
        // Since state_2[A] and state_0 don't share Arcs (state_0 is empty),
        // A is in divergent → restored to initial via step 1. Good.
        assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10); // initial
        assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20); // initial
        assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30); // initial (untouched)
    }
}

// =========================================================================
// Stateful mode correctness tests
//
// These tests verify the 5 core invariants of stateful fuzzing:
// 1. Setup generates the correct initial state
// 2. Picking a state from the pool restores all accounts to that state
// 3. Dirty tracking catches created, deleted, and modified accounts
// 4. Tree branching (A→B→C, B→D) — all nodes are reachable
// 5. No residual carryover between iterations
// =========================================================================

// ---- Test 1: Setup generates the correct initial state ----

#[test]
fn test_stateful_setup_captures_initial_state() {
    // After setup, the initial snapshot must capture every account
    // that was created during setup, with exact lamports/data/owner.
    let mut svm = LiteSVM::new();

    // Simulate setup: create program accounts, user accounts, vaults
    let user = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let reserve = Pubkey::new_unique();

    svm.set_account(user, make_account(5_000_000, &[0; 165]))
        .unwrap();
    svm.set_account(vault, make_account(1_000, &[0; 64]))
        .unwrap();
    svm.set_account(mint, make_account(1_461_600, &[0; 82]))
        .unwrap();
    svm.set_account(reserve, make_account(2_000_000, &[0xAB; 256]))
        .unwrap();

    let tracked: HashSet<Pubkey> = [user, vault, mint, reserve].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Verify all 4 accounts captured with exact values
    assert_eq!(initial.account_count(), 4);
    assert_eq!(initial.accounts()[&user].lamports, 5_000_000);
    assert_eq!(initial.accounts()[&user].data.len(), 165);
    assert_eq!(initial.accounts()[&vault].lamports, 1_000);
    assert_eq!(initial.accounts()[&vault].data.len(), 64);
    assert_eq!(initial.accounts()[&mint].lamports, 1_461_600);
    assert_eq!(initial.accounts()[&mint].data.len(), 82);
    assert_eq!(initial.accounts()[&reserve].lamports, 2_000_000);
    assert_eq!(initial.accounts()[&reserve].data.len(), 256);
}

#[test]
fn test_stateful_setup_empty_delta_represents_initial() {
    // The initial pool state has an empty delta, meaning "all accounts
    // match the initial snapshot." Restoring an empty delta should
    // produce the exact initial state.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    svm.set_account(pk_a, make_account(100, &[1, 2, 3]))
        .unwrap();
    svm.set_account(pk_b, make_account(200, &[4, 5])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Scramble SVM
    svm.set_account(pk_a, make_account(999, &[0xFF])).unwrap();
    svm.set_account(pk_b, make_account(0, &[])).unwrap();

    // Restore empty delta (represents initial state)
    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_a);
    divergent.insert(pk_b);

    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_a).unwrap().data, vec![1, 2, 3]);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_b).unwrap().data, vec![4, 5]);
}

// ---- Test 2: Picking a state restores all accounts correctly ----

#[test]
fn test_stateful_pick_restores_delta_accounts() {
    // When we pick a state with delta {A=100, B=200}, the SVM must
    // have exactly A=100, B=200, and all other accounts at initial values.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique(); // untouched by delta

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    svm.set_account(pk_c, make_account(30, &[3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Build a delta: A=100, B=200 (C not in delta = same as initial)
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_a, Arc::new(make_account(100, &[0xAA])));
    delta_accts.insert(pk_b, Arc::new(make_account(200, &[0xBB])));
    let delta = SvmSnapshot {
        accounts: delta_accts,
        sysvars: initial.sysvars.clone(),
    };

    // Scramble everything first
    svm.set_account(pk_a, make_account(0, &[])).unwrap();
    svm.set_account(pk_b, make_account(0, &[])).unwrap();
    svm.set_account(pk_c, make_account(0, &[])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_a);
    divergent.insert(pk_b);
    divergent.insert(pk_c);

    initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_a).unwrap().data, vec![0xAA]);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_b).unwrap().data, vec![0xBB]);
    // C: not in delta → restored to initial
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 30);
    assert_eq!(svm.get_account(&pk_c).unwrap().data, vec![3]);
}

#[test]
fn test_stateful_pick_restores_delta_with_tombstone() {
    // A delta can contain a tombstone (lamports=0) for an account that
    // was deleted in that state. Restoring must delete it in the SVM.
    let mut svm = LiteSVM::new();
    let pk_alive = Pubkey::new_unique();
    let pk_deleted = Pubkey::new_unique();

    svm.set_account(pk_alive, make_account(100, &[1])).unwrap();
    svm.set_account(pk_deleted, make_account(200, &[2]))
        .unwrap();

    let tracked: HashSet<Pubkey> = [pk_alive, pk_deleted].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Delta: pk_deleted has tombstone (lamports=0 = deleted)
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_alive, Arc::new(make_account(150, &[0xAA])));
    delta_accts.insert(
        pk_deleted,
        Arc::new(Account {
            lamports: 0,
            ..Default::default()
        }),
    );
    let delta = SvmSnapshot {
        accounts: delta_accts,
        sysvars: initial.sysvars.clone(),
    };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_alive);
    divergent.insert(pk_deleted);

    initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(svm.get_account(&pk_alive).unwrap().lamports, 150);
    // Tombstone: LiteSVM treats lamports=0 as nonexistent
    assert!(svm.get_account(&pk_deleted).is_none());
}

// ---- Test 3: Dirty tracking catches created, deleted, and modified accounts ----

#[test]
fn test_stateful_dirty_tracking_created_account() {
    // An action that creates a new account must be tracked so that
    // restore can clean it up (zero it out).
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    svm.set_account(pk_initial, make_account(100, &[1]))
        .unwrap();

    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Action creates a brand-new account
    let pk_created = Pubkey::new_unique();
    svm.set_account(pk_created, make_account(500, &[9, 9, 9]))
        .unwrap();
    assert!(svm.get_account(&pk_created).is_some());

    // Dirty tracker records it
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_created);

    // take_delta: created account NOT in initial → should still be in delta
    let parent_delta = SvmSnapshot::empty(initial.clock().clone());
    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);
    assert!(delta.accounts().contains_key(&pk_created));
    assert_eq!(delta.accounts()[&pk_created].lamports, 500);

    // Now restore to initial (empty delta) — created account must be cleaned up
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.extend(delta.accounts().keys().copied());

    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    // Created account must be gone
    assert!(svm.get_account(&pk_created).is_none());
    // Original account untouched
    assert_eq!(svm.get_account(&pk_initial).unwrap().lamports, 100);
}

#[test]
fn test_stateful_dirty_tracking_deleted_account() {
    // An action that deletes an existing account (sets lamports=0)
    // must be tracked so restore can bring it back.
    let mut svm = LiteSVM::new();
    let pk_will_delete = Pubkey::new_unique();
    let pk_survives = Pubkey::new_unique();
    svm.set_account(pk_will_delete, make_account(100, &[1, 2]))
        .unwrap();
    svm.set_account(pk_survives, make_account(200, &[3, 4]))
        .unwrap();

    let tracked: HashSet<Pubkey> = [pk_will_delete, pk_survives].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Action deletes pk_will_delete
    svm.set_account(
        pk_will_delete,
        Account {
            lamports: 0,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(svm.get_account(&pk_will_delete).is_none()); // LiteSVM: 0 lamports = gone

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_will_delete);

    // take_delta records the tombstone
    let parent_delta = SvmSnapshot::empty(initial.clock().clone());
    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);
    assert!(delta.accounts().contains_key(&pk_will_delete));
    assert_eq!(delta.accounts()[&pk_will_delete].lamports, 0); // tombstone

    // Restore to initial — deleted account must come back
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.extend(delta.accounts().keys().copied());
    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    let restored = svm.get_account(&pk_will_delete).unwrap();
    assert_eq!(restored.lamports, 100);
    assert_eq!(restored.data, vec![1, 2]);
}

#[test]
fn test_stateful_dirty_tracking_modified_account() {
    // Basic: action modifies existing account data/lamports.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[0; 32])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Action modifies lamports and data
    svm.set_account(pk, make_account(999, &[0xFF; 32])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    let parent_delta = SvmSnapshot::empty(initial.clock().clone());
    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);
    assert_eq!(delta.accounts()[&pk].lamports, 999);

    // Restore to initial
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);
    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk).unwrap().data, vec![0; 32]);
}

#[test]
fn test_stateful_dirty_tracking_create_and_delete_same_iteration() {
    // Edge case: action creates an account then another action in the same
    // iteration deletes it. The delta should have a tombstone, and restoring
    // to initial should leave no trace.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Create then delete
    let pk_ephemeral = Pubkey::new_unique();
    svm.set_account(pk_ephemeral, make_account(500, &[9]))
        .unwrap();
    svm.set_account(
        pk_ephemeral,
        Account {
            lamports: 0,
            ..Default::default()
        },
    )
    .unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_ephemeral);

    let parent_delta = SvmSnapshot::empty(initial.clock().clone());
    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // Delta has tombstone for ephemeral
    assert_eq!(delta.accounts()[&pk_ephemeral].lamports, 0);

    // Restoring to initial: ephemeral not in initial → gets zeroed (already zero)
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_ephemeral);
    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    assert!(svm.get_account(&pk_ephemeral).is_none());
}

// ---- Test 4: Tree branching — A→B→C and B→D, all nodes reachable ----

#[test]
fn test_stateful_tree_branching_all_nodes_reachable() {
    // State tree:
    //   A (initial, empty delta)
    //   └── B (A modifies pk_x=100, creates pk_new)
    //       ├── C (B modifies pk_x=200, pk_y=300)
    //       └── D (B deletes pk_new, modifies pk_y=400)
    //
    // We must be able to restore to A, B, C, D from any other state.

    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();
    svm.set_account(pk_y, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State A: empty delta (initial state)
    let delta_a = SvmSnapshot::empty(initial.clock().clone());

    // Build state B: modify pk_x=100, create pk_new=500
    let pk_new = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(100, &[0xAA])).unwrap();
    svm.set_account(pk_new, make_account(500, &[0xBB])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_x);
    dirty_b.mark_account_dirty(&pk_new);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

    // Build state C (from B): modify pk_x=200, pk_y=300
    svm.set_account(pk_x, make_account(200, &[0xCC])).unwrap();
    svm.set_account(pk_y, make_account(300, &[0xDD])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_x);
    dirty_c.mark_account_dirty(&pk_y);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);

    // Build state D (from B, NOT from C): delete pk_new, modify pk_y=400
    // Reset SVM to B's state first
    initial.restore_full(&mut svm);
    for (pk, acct) in delta_b.accounts() {
        let _ = svm.set_account(*pk, (**acct).clone());
    }
    svm.set_account(
        pk_new,
        Account {
            lamports: 0,
            ..Default::default()
        },
    )
    .unwrap();
    svm.set_account(pk_y, make_account(400, &[0xEE])).unwrap();
    let mut dirty_d = DirtyTracker::new();
    dirty_d.mark_account_dirty(&pk_new);
    dirty_d.mark_account_dirty(&pk_y);
    let delta_d = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_d);

    // Reset SVM completely
    initial.restore_full(&mut svm);

    // Verify delta contents
    // B: {pk_x=100, pk_new=500}
    assert_eq!(delta_b.accounts()[&pk_x].lamports, 100);
    assert_eq!(delta_b.accounts()[&pk_new].lamports, 500);
    assert!(!delta_b.accounts().contains_key(&pk_y)); // unchanged from initial

    // C: {pk_x=200, pk_new=500(inherited), pk_y=300}
    assert_eq!(delta_c.accounts()[&pk_x].lamports, 200);
    assert_eq!(delta_c.accounts()[&pk_new].lamports, 500); // inherited from B
    assert_eq!(delta_c.accounts()[&pk_y].lamports, 300);

    // D: {pk_x=100(inherited from B), pk_new=0(tombstone), pk_y=400}
    assert_eq!(delta_d.accounts()[&pk_x].lamports, 100); // inherited from B
    assert_eq!(delta_d.accounts()[&pk_new].lamports, 0); // tombstone!
    assert_eq!(delta_d.accounts()[&pk_y].lamports, 400);

    // --- Now test restoring to each state from scratch ---
    let all_keys: Vec<Pubkey> = vec![pk_x, pk_y, pk_new];
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to A
    divergent.clear();
    for &pk in &all_keys {
        divergent.insert(pk);
    }
    initial.restore_selective(&mut svm, &divergent, &delta_a);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 10);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 20);
    assert!(svm.get_account(&pk_new).is_none()); // never existed in initial

    // Restore to B
    divergent.clear();
    for &pk in &all_keys {
        divergent.insert(pk);
    }
    initial.restore_selective(&mut svm, &divergent, &delta_b);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 20); // initial (not in delta_b)
    assert_eq!(svm.get_account(&pk_new).unwrap().lamports, 500);

    // Restore to C
    divergent.clear();
    for &pk in &all_keys {
        divergent.insert(pk);
    }
    initial.restore_selective(&mut svm, &divergent, &delta_c);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 300);
    assert_eq!(svm.get_account(&pk_new).unwrap().lamports, 500); // inherited from B

    // Restore to D
    divergent.clear();
    for &pk in &all_keys {
        divergent.insert(pk);
    }
    initial.restore_selective(&mut svm, &divergent, &delta_d);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100); // inherited from B
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 400);
    assert!(svm.get_account(&pk_new).is_none()); // tombstone = deleted
}

#[test]
fn test_stateful_tree_arc_sharing_between_siblings() {
    // States C and D both branch from B. They share B's Arc<Account> for pk_x.
    // Jumping from C to D via restore_selective_from should skip pk_x (same Arc).
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();
    svm.set_account(pk_y, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let delta_root = SvmSnapshot::empty(initial.clock().clone());

    // B: modify pk_x=100
    svm.set_account(pk_x, make_account(100, &[0xAA])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_x);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_b);

    // C: modify pk_y=300 (inherits pk_x from B)
    svm.set_account(pk_y, make_account(300, &[0xCC])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_y);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);

    // D: modify pk_y=400 (also inherits pk_x from B)
    // Reset to B first
    svm.set_account(pk_y, make_account(400, &[0xDD])).unwrap();
    let mut dirty_d = DirtyTracker::new();
    dirty_d.mark_account_dirty(&pk_y);
    let delta_d = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_d);

    // Both C and D have pk_x inherited from B → same Arc
    assert!(Arc::ptr_eq(
        &delta_c.accounts()[&pk_x],
        &delta_d.accounts()[&pk_x],
    ));

    // Restore to C, then jump to D via restore_selective_from
    initial.restore_full(&mut svm);
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta_c);
    divergent.extend(delta_c.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 300);

    // Simulate execution on C: dirty pk_y
    svm.set_account(pk_y, make_account(350, &[0x99])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_y);
    divergent.extend(prev_exec_dirty.iter().copied());

    // Jump C → D
    let count =
        initial.restore_selective_from(&mut svm, &divergent, &delta_c, &delta_d, &prev_exec_dirty);

    // pk_x: same Arc, not exec-dirtied → SKIPPED
    // pk_y: exec-dirtied → forced write (even though both C and D have pk_y in delta)
    assert_eq!(count, 1); // only pk_y
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100); // unchanged
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 400); // from delta_d
}

// ---- Test 5: No residual carryover between iterations ----

#[test]
fn test_stateful_no_carryover_created_account() {
    // Iteration 1 at state D creates pk_new. Iteration 2 at state B
    // must NOT see pk_new (it doesn't exist in B's lineage).
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let _delta_a = SvmSnapshot::empty(initial.clock().clone());

    // State B: pk_x=100
    let mut b_accounts = FastHashMap::default();
    b_accounts.insert(pk_x, Arc::new(make_account(100, &[0xBB])));
    let delta_b = SvmSnapshot {
        accounts: b_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // State D: pk_x=100 (same arc from B)
    let mut d_accounts = FastHashMap::default();
    d_accounts.insert(pk_x, delta_b.accounts()[&pk_x].clone());
    let delta_d = SvmSnapshot {
        accounts: d_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // --- Iteration 1: pick D, execute, create pk_new ---
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    simulate_restore(
        &initial,
        &mut svm,
        &divergent,
        &delta_d,
        None,
        &prev_exec_dirty,
    );
    divergent.clear();
    divergent.extend(delta_d.accounts().keys().copied());

    // Action creates pk_new
    let pk_new = Pubkey::new_unique();
    svm.set_account(pk_new, make_account(999, &[0xFF; 64]))
        .unwrap();

    // Track dirty accounts (the fix: always track regardless of success)
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_x); // writable in tx
    prev_exec_dirty.insert(pk_new); // created
    divergent.extend(prev_exec_dirty.iter().copied());
    let prev_delta = Some(delta_d.clone());

    // --- Iteration 2: pick B ---
    simulate_restore(
        &initial,
        &mut svm,
        &divergent,
        &delta_b,
        prev_delta.as_ref(),
        &prev_exec_dirty,
    );

    // pk_new must NOT exist — it was created by iteration 1, not in B's lineage
    assert!(
        svm.get_account(&pk_new).is_none(),
        "CARRYOVER BUG: pk_new from iteration 1 leaked into iteration 2"
    );
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
}

#[test]
fn test_stateful_no_carryover_deleted_account() {
    // Iteration 1 at state C deletes pk_y. Iteration 2 at state B
    // must see pk_y at B's value (not deleted).
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();
    svm.set_account(pk_y, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State B: pk_x=100, pk_y=200
    let mut b_accounts = FastHashMap::default();
    b_accounts.insert(pk_x, Arc::new(make_account(100, &[0xAA])));
    b_accounts.insert(pk_y, Arc::new(make_account(200, &[0xBB])));
    let delta_b = SvmSnapshot {
        accounts: b_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // State C: inherits from B but pk_y=tombstone (deleted)
    let mut c_accounts = FastHashMap::default();
    c_accounts.insert(pk_x, delta_b.accounts()[&pk_x].clone());
    c_accounts.insert(
        pk_y,
        Arc::new(Account {
            lamports: 0,
            ..Default::default()
        }),
    );
    let delta_c = SvmSnapshot {
        accounts: c_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // --- Iteration 1: pick C ---
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    simulate_restore(
        &initial,
        &mut svm,
        &divergent,
        &delta_c,
        None,
        &prev_exec_dirty,
    );
    divergent.extend(delta_c.accounts().keys().copied());

    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
    assert!(svm.get_account(&pk_y).is_none()); // deleted in C

    // Action on C: succeeds, dirtied pk_x
    svm.set_account(pk_x, make_account(150, &[0xCC])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_x);
    divergent.extend(prev_exec_dirty.iter().copied());
    let prev_delta = delta_c.clone();

    // --- Iteration 2: pick B ---
    initial.restore_selective_from(
        &mut svm,
        &divergent,
        &prev_delta,
        &delta_b,
        &prev_exec_dirty,
    );

    // pk_y must be restored to B's value (200), NOT still deleted
    assert_eq!(
        svm.get_account(&pk_y).unwrap().lamports,
        200,
        "CARRYOVER BUG: pk_y deletion from C leaked into B's restoration"
    );
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);
}

#[test]
fn test_stateful_no_carryover_modified_account() {
    // Iteration 1 modifies pk_x during execution. Iteration 2 picks
    // a different state — pk_x must be at the new state's value,
    // not the execution-modified value.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Two states with different pk_x values
    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_x, Arc::new(make_account(100, &[0xAA])));
    let delta_1 = SvmSnapshot {
        accounts: s1_accts,
        sysvars: initial.sysvars.clone(),
    };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk_x, Arc::new(make_account(200, &[0xBB])));
    let delta_2 = SvmSnapshot {
        accounts: s2_accts,
        sysvars: initial.sysvars.clone(),
    };

    // --- Iteration 1: pick state 1, execute ---
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 100);

    // Execution modifies pk_x to garbage value
    svm.set_account(pk_x, make_account(77777, &[0xFF; 100]))
        .unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_x);
    divergent.extend(prev_exec_dirty.iter().copied());

    // --- Iteration 2: pick state 2 ---
    initial.restore_selective_from(&mut svm, &divergent, &delta_1, &delta_2, &prev_exec_dirty);

    // pk_x must be 200 (state 2's value), not 77777 (execution garbage)
    assert_eq!(
        svm.get_account(&pk_x).unwrap().lamports,
        200,
        "CARRYOVER BUG: execution-modified pk_x leaked into next iteration"
    );
    assert_eq!(svm.get_account(&pk_x).unwrap().data, vec![0xBB]);
}

#[test]
fn test_stateful_no_carryover_failed_action_with_side_effects() {
    // Critical test: an action partially succeeds (creates pk_new via tx1),
    // then fails (tx2 panics). The action is marked as failed.
    // With the divergent_keys fix, pk_new must still be tracked so the
    // next iteration can clean it up.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    svm.set_account(pk_x, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_x].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_x, Arc::new(make_account(100, &[0xAA])));
    let delta_1 = SvmSnapshot {
        accounts: s1_accts,
        sysvars: initial.sysvars.clone(),
    };

    let delta_initial = SvmSnapshot::empty(initial.clock().clone());

    // --- Iteration 1: pick state 1, action partially succeeds then fails ---
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());

    // Action: tx1 creates pk_new (succeeds)
    let pk_new = Pubkey::new_unique();
    svm.set_account(pk_new, make_account(999, &[0xBB; 32]))
        .unwrap();
    // tx2 modifies pk_x (but tx fails, SVM rolls back pk_x)
    // However, pk_new from tx1 is still in the SVM!

    let _action_succeeded = false; // action overall failed

    // THE FIX: always track dirty accounts regardless of action success
    // (dirty_tracker records all writable accounts from all txs)
    prev_exec_dirty.clear();
    // In real code: dirty_tracker.dirty_accounts() includes both pk_x and pk_new
    prev_exec_dirty.insert(pk_x);
    prev_exec_dirty.insert(pk_new);
    divergent.extend(prev_exec_dirty.iter().copied());

    // On failure: don't set prev_delta_arc (forces simple restore next iteration)
    let prev_delta: Option<&SvmSnapshot> = None; // cleared on failure

    // --- Iteration 2: pick initial state ---
    simulate_restore(
        &initial,
        &mut svm,
        &divergent,
        &delta_initial,
        prev_delta,
        &prev_exec_dirty,
    );

    // pk_new MUST be cleaned up — it was created by the failed action
    assert!(
        svm.get_account(&pk_new).is_none(),
        "CARRYOVER BUG: pk_new from failed action leaked into next iteration"
    );
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 10); // initial
}

#[test]
fn test_stateful_no_carryover_rapid_state_switching() {
    // Stress test: rapidly switch between 4 states across 10 iterations.
    // After each restore, verify ALL accounts match the target state exactly.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(1, &[0x01])).unwrap();
    svm.set_account(pk_b, make_account(2, &[0x02])).unwrap();
    svm.set_account(pk_c, make_account(3, &[0x03])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // 4 states with distinct values for all 3 accounts
    let states: Vec<SvmSnapshot> = vec![
        SvmSnapshot::empty(initial.clock().clone()), // state 0: initial
        SvmSnapshot {
            // state 1: A=10, B=20
            accounts: {
                let mut m = FastHashMap::default();
                m.insert(pk_a, Arc::new(make_account(10, &[0x10])));
                m.insert(pk_b, Arc::new(make_account(20, &[0x20])));
                m
            },
            sysvars: initial.sysvars.clone(),
        },
        SvmSnapshot {
            // state 2: B=30, C=40
            accounts: {
                let mut m = FastHashMap::default();
                m.insert(pk_b, Arc::new(make_account(30, &[0x30])));
                m.insert(pk_c, Arc::new(make_account(40, &[0x40])));
                m
            },
            sysvars: initial.sysvars.clone(),
        },
        SvmSnapshot {
            // state 3: A=50, C=60
            accounts: {
                let mut m = FastHashMap::default();
                m.insert(pk_a, Arc::new(make_account(50, &[0x50])));
                m.insert(pk_c, Arc::new(make_account(60, &[0x60])));
                m
            },
            sysvars: initial.sysvars.clone(),
        },
    ];

    // Expected values for each state (lamports for A, B, C)
    let expected: Vec<(u64, u64, u64)> = vec![
        (1, 2, 3),   // state 0: all initial
        (10, 20, 3), // state 1: A=10, B=20, C=initial
        (1, 30, 40), // state 2: A=initial, B=30, C=40
        (50, 2, 60), // state 3: A=50, B=initial, C=60
    ];

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Sequence: 1, 3, 0, 2, 1, 3, 2, 0, 3, 1
    let sequence = [1, 3, 0, 2, 1, 3, 2, 0, 3, 1];

    for (iter, &state_idx) in sequence.iter().enumerate() {
        let delta = &states[state_idx];
        let (ea, eb, ec) = expected[state_idx];

        simulate_restore(
            &initial,
            &mut svm,
            &divergent,
            delta,
            prev_delta.as_ref(),
            &prev_exec_dirty,
        );
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        let got_a = svm.get_account(&pk_a).map_or(0, |a| a.lamports);
        let got_b = svm.get_account(&pk_b).map_or(0, |a| a.lamports);
        let got_c = svm.get_account(&pk_c).map_or(0, |a| a.lamports);

        assert_eq!(
            got_a, ea,
            "iter {} state {}: pk_a expected {} got {}",
            iter, state_idx, ea, got_a
        );
        assert_eq!(
            got_b, eb,
            "iter {} state {}: pk_b expected {} got {}",
            iter, state_idx, eb, got_b
        );
        assert_eq!(
            got_c, ec,
            "iter {} state {}: pk_c expected {} got {}",
            iter, state_idx, ec, got_c
        );

        // Simulate execution dirtying a random account
        let dirty_pk = [pk_a, pk_b, pk_c][iter % 3];
        svm.set_account(dirty_pk, make_account(99999, &[0xDE, 0xAD]))
            .unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(dirty_pk);
        divergent.extend(prev_exec_dirty.iter().copied());
        prev_delta = Some(delta.clone());
    }
}
