use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::Arc;

// =========================================================================
// Exhaustive edge case tests
// =========================================================================

// ---- Category 1: Account Lifecycle Edge Cases ----

#[test]
fn test_edge_account_recreated_after_deletion() {
    // State A tombstones pk. State B has pk alive with different data.
    // Restore A → B must bring pk back. Then B → A must delete it again.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1, 2, 3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State A: pk is tombstoned (deleted)
    let mut a_accts = FastHashMap::default();
    a_accts.insert(pk, Arc::new(Account { lamports: 0, ..Default::default() }));
    let delta_a = SvmSnapshot { accounts: a_accts, sysvars: initial.sysvars.clone() };

    // State B: pk is alive with different data
    let mut b_accts = FastHashMap::default();
    b_accts.insert(pk, Arc::new(make_account(500, &[0xDE, 0xAD])));
    let delta_b = SvmSnapshot { accounts: b_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to A (tombstone)
    simulate_restore(&initial, &mut svm, &divergent, &delta_a, None, &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta_a.accounts().keys().copied());
    assert!(svm.get_account(&pk).is_none(), "pk should be deleted in state A");

    // Jump A → B (resurrect)
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &delta_a, &delta_b, &prev_exec_dirty,
    );
    assert!(count > 0, "should have written pk");
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk).unwrap().data, vec![0xDE, 0xAD]);

    // Jump B → A (delete again)
    divergent.clear();
    divergent.extend(delta_b.accounts().keys().copied());
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &delta_b, &delta_a, &prev_exec_dirty,
    );
    assert!(count > 0);
    assert!(svm.get_account(&pk).is_none(), "pk should be deleted again in state A");
}

#[test]
fn test_edge_account_data_length_change() {
    // State 1 has pk with 32-byte data. State 2 has pk with 256-byte data.
    // Verify restore correctly handles growing/shrinking account data.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(10, &[0; 8])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(make_account(100, &[0xAA; 32])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk, Arc::new(make_account(200, &[0xBB; 256])));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to state 1 (32 bytes)
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().data.len(), 32);

    // Jump to state 2 (grow to 256 bytes)
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &delta_2, &prev_exec_dirty,
    );
    divergent.clear();
    divergent.extend(delta_2.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().data.len(), 256);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 200);
    assert!(svm.get_account(&pk).unwrap().data.iter().all(|&b| b == 0xBB));

    // Jump back to state 1 (shrink to 32 bytes)
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_2, &delta_1, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk).unwrap().data.len(), 32);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);
    assert!(svm.get_account(&pk).unwrap().data.iter().all(|&b| b == 0xAA));

    // Jump to initial (8 bytes)
    divergent.clear();
    divergent.extend(delta_1.accounts().keys().copied());
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &empty, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk).unwrap().data.len(), 8);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 10);
}

#[test]
fn test_edge_account_owner_change() {
    // State 1 has pk owned by program_1. State 2 has pk owned by program_2.
    // Verify restore_selective correctly swaps the owner, not just data/lamports.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let owner_initial = Pubkey::new_unique();
    svm.set_account(pk, Account {
        lamports: 100, data: vec![1], owner: owner_initial,
        executable: false, rent_epoch: 0,
    }).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let owner_1 = Pubkey::new_unique();
    let owner_2 = Pubkey::new_unique();

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(Account {
        lamports: 100, data: vec![1], owner: owner_1,
        executable: false, rent_epoch: 0,
    }));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk, Arc::new(Account {
        lamports: 100, data: vec![1], owner: owner_2,
        executable: false, rent_epoch: 0,
    }));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to state 1
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().owner, owner_1);

    // Jump to state 2 — owner must change
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &delta_2, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk).unwrap().owner, owner_2);

    // Jump to initial — owner must revert
    divergent.clear();
    divergent.extend(delta_2.accounts().keys().copied());
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty);
    assert_eq!(svm.get_account(&pk).unwrap().owner, owner_initial);
}

#[test]
fn test_edge_tombstone_roundtrip() {
    // Rapid tombstone/live cycles:
    // A(live) → B(tombstone) → C(live different data) → D(tombstone)
    // Verify restore to each state yields correct result.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let tombstone = Account { lamports: 0, ..Default::default() };

    let mut a_accts = FastHashMap::default();
    a_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta_a = SvmSnapshot { accounts: a_accts, sysvars: initial.sysvars.clone() };

    let mut b_accts = FastHashMap::default();
    b_accts.insert(pk, Arc::new(tombstone.clone()));
    let delta_b = SvmSnapshot { accounts: b_accts, sysvars: initial.sysvars.clone() };

    let mut c_accts = FastHashMap::default();
    c_accts.insert(pk, Arc::new(make_account(300, &[0xCC; 16])));
    let delta_c = SvmSnapshot { accounts: c_accts, sysvars: initial.sysvars.clone() };

    let mut d_accts = FastHashMap::default();
    d_accts.insert(pk, Arc::new(tombstone.clone()));
    let delta_d = SvmSnapshot { accounts: d_accts, sysvars: initial.sysvars.clone() };

    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // A → B (live → tombstone)
    initial.restore_selective(&mut svm, &divergent, &delta_a);
    divergent.extend(delta_a.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 200);

    initial.restore_selective_from(&mut svm, &divergent, &delta_a, &delta_b, &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta_b.accounts().keys().copied());
    assert!(svm.get_account(&pk).is_none());

    // B → C (tombstone → live)
    initial.restore_selective_from(&mut svm, &divergent, &delta_b, &delta_c, &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta_c.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 300);
    assert_eq!(svm.get_account(&pk).unwrap().data.len(), 16);

    // C → D (live → tombstone)
    initial.restore_selective_from(&mut svm, &divergent, &delta_c, &delta_d, &prev_exec_dirty);
    assert!(svm.get_account(&pk).is_none());
}

#[test]
fn test_edge_cpi_account_persisted_in_delta() {
    // CPI-created account (not in initial) exists in a delta.
    // Switching to a state without it must zero the account.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Delta with CPI-created account (not in initial)
    let pk_cpi = Pubkey::new_unique();
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_cpi, Arc::new(make_account(500, &[0xCC; 64])));
    let delta_with_cpi = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let empty_delta = SvmSnapshot::empty(initial.clock().clone());
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to state with CPI account
    initial.restore_selective(&mut svm, &divergent, &delta_with_cpi);
    divergent.extend(delta_with_cpi.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk_cpi).unwrap().lamports, 500);

    // Switch to empty state — CPI account must be zeroed
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_with_cpi, &empty_delta, &prev_exec_dirty,
    );
    assert!(svm.get_account(&pk_cpi).is_none(),
        "CPI account should be zeroed when switching to state without it");
    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 100);
}

#[test]
fn test_edge_execution_modifies_to_initial_value() {
    // State delta has pk=200. Execution modifies pk back to initial value (10).
    // Dirty tracker records pk. Next iteration must still restore correctly.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(10, &[1, 2]);
    svm.set_account(pk, initial_acct.clone()).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk, Arc::new(make_account(300, &[0xBB])));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Iteration 1: pick state 1 (pk=200)
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());

    // Execution modifies pk BACK to initial value (10)
    svm.set_account(pk, initial_acct.clone()).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk);
    divergent.extend(prev_exec_dirty.iter().copied());

    // Iteration 2: pick state 2 (pk=300) — must work despite pk currently matching initial
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &delta_2, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 300,
        "pk must be 300 even though execution set it to initial value");
}

// ---- Category 2: restore_selective_from Pointer Optimization ----

#[test]
fn test_edge_from_tombstone_to_live() {
    // prev_delta has pk as tombstone. next_delta has pk as live account.
    // Different Arcs → unconditional write. Verify account resurrects.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut prev_accts = FastHashMap::default();
    prev_accts.insert(pk, Arc::new(Account { lamports: 0, ..Default::default() }));
    let prev_delta = SvmSnapshot { accounts: prev_accts, sysvars: initial.sysvars.clone() };

    let mut next_accts = FastHashMap::default();
    next_accts.insert(pk, Arc::new(make_account(500, &[0xFF; 32])));
    let next_delta = SvmSnapshot { accounts: next_accts, sysvars: initial.sysvars.clone() };

    // Set SVM to tombstone state
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &prev_delta);
    divergent.extend(prev_delta.accounts().keys().copied());
    assert!(svm.get_account(&pk).is_none());

    // Jump to live state
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );
    assert_eq!(count, 1);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk).unwrap().data, vec![0xFF; 32]);
}

#[test]
fn test_edge_from_live_to_tombstone() {
    // prev_delta has pk as live. next_delta has pk as tombstone.
    // Verify account deleted after restore.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut prev_accts = FastHashMap::default();
    prev_accts.insert(pk, Arc::new(make_account(500, &[0xAA])));
    let prev_delta = SvmSnapshot { accounts: prev_accts, sysvars: initial.sysvars.clone() };

    let mut next_accts = FastHashMap::default();
    next_accts.insert(pk, Arc::new(Account { lamports: 0, ..Default::default() }));
    let next_delta = SvmSnapshot { accounts: next_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &prev_delta);
    divergent.extend(prev_delta.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);

    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );
    assert!(svm.get_account(&pk).is_none(), "pk should be deleted (tombstone)");
}

#[test]
fn test_edge_same_state_consecutive() {
    // Same delta picked twice in a row. All Arcs are ptr_eq.
    // No exec-dirty. All writes should be skipped (count=0 for step 2).
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let shared_arc_a = Arc::new(make_account(100, &[0xAA]));
    let shared_arc_b = Arc::new(make_account(200, &[0xBB]));
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_a, shared_arc_a);
    delta_accts.insert(pk_b, shared_arc_b);
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // First pick
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.extend(delta.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);

    // Second pick of same delta — all Arcs are ptr_eq, no exec-dirty
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &delta, &delta, &prev_exec_dirty,
    );
    // All delta accounts should be skipped (same Arc, not dirty)
    assert_eq!(count, 0, "no writes needed when same state with no exec-dirty");
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200);
}

#[test]
fn test_edge_exec_dirty_forces_write_despite_same_arc() {
    // prev_delta and next_delta share same Arc for pk. But pk is in
    // prev_exec_dirty. Must force write. Verify count includes pk.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let shared_arc = Arc::new(make_account(100, &[0xAA]));
    let mut accts = FastHashMap::default();
    accts.insert(pk, shared_arc.clone());
    let delta = SvmSnapshot { accounts: accts, sysvars: initial.sysvars.clone() };

    // Both prev and next use same delta (same Arc for pk)
    assert!(Arc::ptr_eq(&delta.accounts()[&pk], &delta.accounts()[&pk]));

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.extend(delta.accounts().keys().copied());

    // Execution corrupts pk
    svm.set_account(pk, make_account(99999, &[0xDE, 0xAD])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk);
    divergent.extend(prev_exec_dirty.iter().copied());

    // Same delta again, but pk is exec-dirty → must force write
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &delta, &delta, &prev_exec_dirty,
    );
    assert_eq!(count, 1, "pk must be written despite same Arc because exec-dirty");
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk).unwrap().data, vec![0xAA]);
}

#[test]
fn test_edge_from_mixed_scenario() {
    // 5 accounts with different behaviors:
    // (a) shared Arc not dirty → skip
    // (b) shared Arc + dirty → write
    // (c) different Arcs → write
    // (d) in next only → write
    // (e) in prev only + in divergent → restore to initial
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();
    let pk_e = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(1, &[1])).unwrap();
    svm.set_account(pk_b, make_account(2, &[2])).unwrap();
    svm.set_account(pk_c, make_account(3, &[3])).unwrap();
    svm.set_account(pk_d, make_account(4, &[4])).unwrap();
    svm.set_account(pk_e, make_account(5, &[5])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c, pk_d, pk_e].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let shared_arc_a = Arc::new(make_account(10, &[0xAA]));
    let shared_arc_b = Arc::new(make_account(20, &[0xBB]));

    // prev_delta: has a (shared), b (shared), c (val=30), e (val=50)
    let mut prev_accts = FastHashMap::default();
    prev_accts.insert(pk_a, shared_arc_a.clone());
    prev_accts.insert(pk_b, shared_arc_b.clone());
    prev_accts.insert(pk_c, Arc::new(make_account(30, &[0xC1])));
    prev_accts.insert(pk_e, Arc::new(make_account(50, &[0xEE])));
    let prev_delta = SvmSnapshot { accounts: prev_accts, sysvars: initial.sysvars.clone() };

    // next_delta: has a (shared), b (shared), c (val=31 different Arc), d (val=40)
    let mut next_accts = FastHashMap::default();
    next_accts.insert(pk_a, shared_arc_a.clone()); // same Arc as prev
    next_accts.insert(pk_b, shared_arc_b.clone()); // same Arc but will be dirty
    next_accts.insert(pk_c, Arc::new(make_account(31, &[0xC2]))); // different Arc
    next_accts.insert(pk_d, Arc::new(make_account(40, &[0xDD]))); // only in next
    let next_delta = SvmSnapshot { accounts: next_accts, sysvars: initial.sysvars.clone() };

    // Setup SVM to prev_delta state
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &prev_delta);
    divergent.extend(prev_delta.accounts().keys().copied());

    // Simulate execution dirtying pk_b
    svm.set_account(pk_b, make_account(999, &[0xFF])).unwrap();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    prev_exec_dirty.insert(pk_b);
    divergent.extend(prev_exec_dirty.iter().copied());

    let count = initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    // Verify results:
    // (a) shared Arc, not dirty → skipped → still 10
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10);
    // (b) shared Arc + dirty → forced write → 20
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
    // (c) different Arc → write → 31
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 31);
    // (d) in next only → write → 40
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 40);
    // (e) in prev only + in divergent → restore to initial → 5
    assert_eq!(svm.get_account(&pk_e).unwrap().lamports, 5);

    // Count: b(dirty) + c(diff Arc) + d(next only) + e(divergent→initial) = 4
    // a is skipped
    assert_eq!(count, 4);
}

// ---- Category 3: Deep Delta Chains ----

#[test]
fn test_edge_deep_chain_5_levels() {
    // Chain: root → L1 → L2 → L3 → L4 → L5
    // Each level adds/modifies one account.
    // Verify restore_selective to any level yields correct accounts.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..6).map(|_| Pubkey::new_unique()).collect();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(1, &[0])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let root = SvmSnapshot::empty(initial.clock().clone());

    // Build chain: each level i adds pk[i] = (i+1)*100
    let mut levels: Vec<SvmSnapshot> = Vec::new();
    let mut parent = &root;
    for i in 0..6 {
        svm.set_account(pks[i], make_account((i as u64 + 1) * 100, &[i as u8])).unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pks[i]);
        let delta = SvmSnapshot::take_delta(&svm, parent, &dirty);
        levels.push(delta);
        parent = &levels[i];
    }

    // Verify Arc sharing: L5 inherits pk[0] from L1 (same Arc pointer chain)
    assert!(Arc::ptr_eq(
        &levels[0].accounts()[&pks[0]],
        &levels[5].accounts()[&pks[0]],
    ), "L5 should share Arc with L1 for pk[0]");

    // L5 should have all 6 accounts
    assert_eq!(levels[5].account_count(), 6);

    // Restore to each level and verify
    for level_idx in 0..6 {
        let delta = &levels[level_idx];
        let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
        for &pk in &pks { divergent.insert(pk); }

        initial.restore_selective(&mut svm, &divergent, delta);

        // Accounts up to level_idx should exist
        for i in 0..=level_idx {
            let got = svm.get_account(&pks[i]).map_or(0, |a| a.lamports);
            assert_eq!(got, (i as u64 + 1) * 100,
                "L{}: pk[{}] expected {} got {}", level_idx, i, (i+1)*100, got);
        }
        // Accounts beyond level_idx should not exist (not in initial either)
        for i in (level_idx + 1)..6 {
            assert!(svm.get_account(&pks[i]).is_none(),
                "L{}: pk[{}] should not exist", level_idx, i);
        }
    }
}

#[test]
fn test_edge_deep_chain_leaf_to_root() {
    // From L5, jump to root (empty delta).
    // All CPI/modified accounts must revert to initial.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(1, &[0])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let root = SvmSnapshot::empty(initial.clock().clone());

    // Build 5-level chain
    let mut parent = &root;
    let mut levels: Vec<SvmSnapshot> = Vec::new();
    for i in 0..5 {
        svm.set_account(pks[i], make_account((i as u64 + 1) * 100, &[i as u8])).unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pks[i]);
        let delta = SvmSnapshot::take_delta(&svm, parent, &dirty);
        levels.push(delta);
        parent = &levels[i];
    }

    let l5 = &levels[4];

    // Restore to L5
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, l5);
    divergent.extend(l5.accounts().keys().copied());

    // Verify all 5 exist
    for i in 0..5 {
        assert!(svm.get_account(&pks[i]).is_some(), "pk[{}] should exist in L5", i);
    }

    // Jump L5 → root using restore_selective_from
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective_from(
        &mut svm, &divergent, l5, &root, &prev_exec_dirty,
    );

    // All CPI accounts gone (not in initial, not in root delta)
    for i in 0..5 {
        assert!(svm.get_account(&pks[i]).is_none(),
            "pk[{}] should be zeroed after jumping to root", i);
    }
    // Base account restored
    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 1);
}

#[test]
fn test_edge_deep_chain_sibling_jump() {
    // L3 has two children: L4a and L4b. They share all L3 ancestor Arcs.
    // Jump from L4a → L4b should only write accounts that differ.
    let mut svm = LiteSVM::new();
    let pk_shared = Pubkey::new_unique(); // modified at L1, inherited by both
    let pk_diverge = Pubkey::new_unique(); // modified differently by L4a and L4b
    svm.set_account(pk_shared, make_account(10, &[1])).unwrap();
    svm.set_account(pk_diverge, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_shared, pk_diverge].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let root = SvmSnapshot::empty(initial.clock().clone());

    // L1-L3: modify pk_shared
    svm.set_account(pk_shared, make_account(100, &[0xAA])).unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_shared);
    let l3 = SvmSnapshot::take_delta(&svm, &root, &dirty);

    // L4a: modify pk_diverge=300 (inherits pk_shared from L3)
    svm.set_account(pk_diverge, make_account(300, &[0xBB])).unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk_diverge);
    let l4a = SvmSnapshot::take_delta(&svm, &l3, &dirty_a);

    // L4b: modify pk_diverge=400 (also inherits pk_shared from L3)
    svm.set_account(pk_diverge, make_account(400, &[0xCC])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_diverge);
    let l4b = SvmSnapshot::take_delta(&svm, &l3, &dirty_b);

    // Verify Arc sharing for pk_shared
    assert!(Arc::ptr_eq(
        &l4a.accounts()[&pk_shared],
        &l4b.accounts()[&pk_shared],
    ), "siblings should share ancestor Arc for pk_shared");

    // Restore to L4a
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &l4a);
    divergent.extend(l4a.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk_shared).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_diverge).unwrap().lamports, 300);

    // Jump L4a → L4b: pk_shared should be skipped (same Arc)
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &l4a, &l4b, &prev_exec_dirty,
    );
    assert_eq!(count, 1, "only pk_diverge should be written (pk_shared same Arc)");
    assert_eq!(svm.get_account(&pk_shared).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk_diverge).unwrap().lamports, 400);
}

// ---- Category 4: take_delta Edge Cases ----

#[test]
fn test_edge_take_delta_cpi_not_in_parent() {
    // CPI-created account not in parent delta and not in initial.
    // Dirty tracker has it. SVM has it. New delta must include it.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let _initial = SvmSnapshot::take(&svm, &tracked);
    let parent_delta = SvmSnapshot::empty(_initial.clock().clone());

    // CPI creates a brand new account
    let pk_cpi = Pubkey::new_unique();
    svm.set_account(pk_cpi, make_account(777, &[0xCC; 48])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_cpi);

    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    assert!(delta.accounts().contains_key(&pk_cpi));
    assert_eq!(delta.accounts()[&pk_cpi].lamports, 777);
    assert_eq!(delta.accounts()[&pk_cpi].data, vec![0xCC; 48]);
    // Base account should not be in delta (not dirty)
    assert!(!delta.accounts().contains_key(&pk_base));
}

#[test]
fn test_edge_take_delta_dirty_but_unchanged() {
    // Dirty tracker marks pk. SVM still has same value as parent delta.
    // take_delta always reads fresh from SVM — creates new Arc even if
    // value is identical. This is by design.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[0xAA])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let _initial = SvmSnapshot::take(&svm, &tracked);

    // Parent delta has pk=100
    let mut parent_accts = FastHashMap::default();
    let parent_arc = Arc::new(make_account(100, &[0xAA]));
    parent_accts.insert(pk, parent_arc.clone());
    let parent_delta = SvmSnapshot { accounts: parent_accts, sysvars: _initial.sysvars.clone() };

    // SVM still has pk=100, but dirty tracker marks it
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    let child_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // Value is identical
    assert_eq!(child_delta.accounts()[&pk].lamports, 100);
    assert_eq!(child_delta.accounts()[&pk].data, vec![0xAA]);

    // But Arc is different (fresh read from SVM)
    assert!(!Arc::ptr_eq(
        &parent_delta.accounts()[&pk],
        &child_delta.accounts()[&pk],
    ), "take_delta should create new Arc even if value unchanged");
}

#[test]
fn test_edge_take_delta_mixed_inherit_and_dirty() {
    // Parent has 5 accounts. 2 are dirty (one modified, one deleted).
    // 3 are inherited. Verify: 2 dirty get new Arcs, 3 inherited are ptr_eq.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[i as u8])).unwrap();
    }

    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let _initial = SvmSnapshot::take(&svm, &tracked);

    // Parent delta: all 5 accounts
    let mut parent_accts = FastHashMap::default();
    for (i, pk) in pks.iter().enumerate() {
        parent_accts.insert(*pk, Arc::new(make_account((i as u64 + 1) * 100, &[i as u8 + 10])));
    }
    let parent_delta = SvmSnapshot { accounts: parent_accts, sysvars: _initial.sysvars.clone() };

    // Set SVM to parent values, then modify 2 accounts
    for (pk, acct) in parent_delta.accounts() {
        svm.set_account(*pk, (**acct).clone()).unwrap();
    }
    // Modify pk[0]
    svm.set_account(pks[0], make_account(999, &[0xFF])).unwrap();
    // Delete pk[1]
    svm.set_account(pks[1], Account { lamports: 0, ..Default::default() }).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pks[0]);
    dirty.mark_account_dirty(&pks[1]);

    let child_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // pk[0]: dirty, modified → new Arc
    assert_eq!(child_delta.accounts()[&pks[0]].lamports, 999);
    assert!(!Arc::ptr_eq(
        &parent_delta.accounts()[&pks[0]],
        &child_delta.accounts()[&pks[0]],
    ));

    // pk[1]: dirty, deleted → tombstone, new Arc
    assert_eq!(child_delta.accounts()[&pks[1]].lamports, 0);
    assert!(!Arc::ptr_eq(
        &parent_delta.accounts()[&pks[1]],
        &child_delta.accounts()[&pks[1]],
    ));

    // pk[2..4]: inherited → same Arc as parent
    for i in 2..5 {
        assert!(Arc::ptr_eq(
            &parent_delta.accounts()[&pks[i]],
            &child_delta.accounts()[&pks[i]],
        ), "pk[{}] should be ptr_eq with parent (inherited)", i);
    }
}

// ---- Category 5: take_full vs take_delta Asymmetry ----

#[test]
fn test_edge_take_full_vs_take_delta_tombstone_behavior() {
    // Same scenario for both: account deleted.
    // take_delta produces tombstone (lamports=0 entry).
    // take_full removes the key entirely.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);
    let parent_delta = SvmSnapshot::empty(base.clock().clone());

    // Delete account
    svm.set_account(pk, Account { lamports: 0, ..Default::default() }).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    // take_delta: should have tombstone entry
    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);
    assert!(delta.accounts().contains_key(&pk), "take_delta should have tombstone entry");
    assert_eq!(delta.accounts()[&pk].lamports, 0);

    // take_full: should NOT have the key (deleted accounts removed)
    let full = SvmSnapshot::take_full(&svm, &base, &dirty);
    assert!(!full.accounts().contains_key(&pk),
        "take_full should remove deleted account, not keep tombstone");
}

#[test]
fn test_edge_take_full_preserves_untracked() {
    // Base has {A, B, C}. Dirty has only {B}. B is modified in SVM.
    // take_full should have {A(base arc), B(new), C(base arc)}.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    svm.set_account(pk_c, make_account(30, &[3])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    // Modify only B in SVM
    svm.set_account(pk_b, make_account(200, &[0xBB])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_b);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);

    // A and C: inherited from base (same Arc)
    assert!(Arc::ptr_eq(
        &base.accounts()[&pk_a],
        &full.accounts()[&pk_a],
    ), "A should be inherited Arc");
    assert!(Arc::ptr_eq(
        &base.accounts()[&pk_c],
        &full.accounts()[&pk_c],
    ), "C should be inherited Arc");

    // B: new Arc with updated value
    assert_eq!(full.accounts()[&pk_b].lamports, 200);
    assert!(!Arc::ptr_eq(
        &base.accounts()[&pk_b],
        &full.accounts()[&pk_b],
    ), "B should be new Arc");
}

// ---- Category 6: Multi-Iteration Stress Scenarios ----

#[test]
fn test_edge_delete_restore_delete_cycle() {
    // 3 iterations: (1) pick state with tombstone for pk,
    // (2) pick state where pk is alive,
    // (3) pick tombstone state again. pk must oscillate correctly.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut dead_accts = FastHashMap::default();
    dead_accts.insert(pk, Arc::new(Account { lamports: 0, ..Default::default() }));
    let state_dead = SvmSnapshot { accounts: dead_accts, sysvars: initial.sysvars.clone() };

    let mut alive_accts = FastHashMap::default();
    alive_accts.insert(pk, Arc::new(make_account(500, &[0xFF])));
    let state_alive = SvmSnapshot { accounts: alive_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Iteration 1: pick dead
    simulate_restore(&initial, &mut svm, &divergent, &state_dead,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    divergent.extend(state_dead.accounts().keys().copied());
    assert!(svm.get_account(&pk).is_none(), "iter 1: pk should be dead");
    prev_exec_dirty.clear();
    prev_delta = Some(state_dead.clone());

    // Iteration 2: pick alive
    simulate_restore(&initial, &mut svm, &divergent, &state_alive,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    divergent.extend(state_alive.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500, "iter 2: pk should be alive");
    prev_exec_dirty.clear();
    prev_delta = Some(state_alive.clone());

    // Iteration 3: pick dead again
    simulate_restore(&initial, &mut svm, &divergent, &state_dead,
        prev_delta.as_ref(), &prev_exec_dirty);
    assert!(svm.get_account(&pk).is_none(), "iter 3: pk should be dead again");
}

#[test]
fn test_edge_cpi_account_lifecycle_across_iterations() {
    // Iter 1: CPI creates pk_cpi1. Iter 2: pick different state, pk_cpi1 cleaned.
    // Iter 3: CPI creates pk_cpi2 at different address.
    // Iter 4: pick initial, both must be gone.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_base, Arc::new(make_account(200, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let empty_delta = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Iter 1: pick state 1, CPI creates pk_cpi1
    simulate_restore(&initial, &mut svm, &divergent, &delta_1,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta_1.accounts().keys().copied());

    let pk_cpi1 = Pubkey::new_unique();
    svm.set_account(pk_cpi1, make_account(777, &[0xCC])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_base);
    prev_exec_dirty.insert(pk_cpi1);
    divergent.extend(prev_exec_dirty.iter().copied());
    prev_delta = Some(delta_1.clone());

    // Iter 2: pick empty (initial state) — pk_cpi1 must be cleaned
    simulate_restore(&initial, &mut svm, &divergent, &empty_delta,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    assert!(svm.get_account(&pk_cpi1).is_none(), "pk_cpi1 should be cleaned up");
    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 100);
    prev_exec_dirty.clear();
    prev_delta = Some(empty_delta.clone());

    // Iter 3: pick state 1, CPI creates pk_cpi2
    simulate_restore(&initial, &mut svm, &divergent, &delta_1,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta_1.accounts().keys().copied());

    let pk_cpi2 = Pubkey::new_unique();
    svm.set_account(pk_cpi2, make_account(888, &[0xDD])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_base);
    prev_exec_dirty.insert(pk_cpi2);
    divergent.extend(prev_exec_dirty.iter().copied());
    prev_delta = Some(delta_1.clone());

    // Iter 4: pick initial — both CPI accounts must be gone
    simulate_restore(&initial, &mut svm, &divergent, &empty_delta,
        prev_delta.as_ref(), &prev_exec_dirty);
    assert!(svm.get_account(&pk_cpi1).is_none(), "pk_cpi1 should still be gone");
    assert!(svm.get_account(&pk_cpi2).is_none(), "pk_cpi2 should be cleaned up");
    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 100);
}

#[test]
fn test_edge_many_accounts_stress() {
    // 50 accounts. 10 states with random subsets modified.
    // 20 iterations switching between states. Verify ALL 50 correct after each.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..50).map(|_| Pubkey::new_unique()).collect();
    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account(i as u64 + 1, &[i as u8])).unwrap();
    }

    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Build 10 states: state i modifies accounts [i*5..(i+1)*5] with value (i+1)*1000+j
    let mut states: Vec<SvmSnapshot> = Vec::new();
    for i in 0..10 {
        let mut accts = FastHashMap::default();
        for j in 0..5 {
            let idx = i * 5 + j;
            accts.insert(pks[idx], Arc::new(make_account(
                (i as u64 + 1) * 1000 + j as u64,
                &[(i * 5 + j) as u8 + 100],
            )));
        }
        states.push(SvmSnapshot { accounts: accts, sysvars: initial.sysvars.clone() });
    }

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // 20-iteration sequence cycling through states
    let sequence = [0, 5, 3, 8, 1, 9, 2, 7, 4, 6, 0, 3, 9, 1, 5, 8, 2, 6, 7, 4];

    for (iter, &state_idx) in sequence.iter().enumerate() {
        let delta = &states[state_idx];
        simulate_restore(&initial, &mut svm, &divergent, delta,
            prev_delta.as_ref(), &prev_exec_dirty);
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        // Verify ALL 50 accounts
        for (k, pk) in pks.iter().enumerate() {
            let expected_lamports = if k >= state_idx * 5 && k < (state_idx + 1) * 5 {
                // In this state's modified range
                (state_idx as u64 + 1) * 1000 + (k - state_idx * 5) as u64
            } else {
                // Initial value
                k as u64 + 1
            };
            let got = svm.get_account(pk).map_or(0, |a| a.lamports);
            assert_eq!(got, expected_lamports,
                "iter {} state {}: pk[{}] expected {} got {}",
                iter, state_idx, k, expected_lamports, got);
        }

        // Simulate execution dirtying one account
        let dirty_idx = iter % 50;
        svm.set_account(pks[dirty_idx], make_account(99999, &[0xDE])).unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(pks[dirty_idx]);
        divergent.extend(prev_exec_dirty.iter().copied());
        prev_delta = Some(delta.clone());
    }
}

#[test]
fn test_edge_failed_action_no_prev_delta_arc() {
    // Iteration 1 fails (prev_delta=None). Iteration 2 must use
    // restore_selective (not restore_selective_from). Verify correct restore.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(make_account(100, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk, Arc::new(make_account(200, &[0xBB])));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Iteration 1: pick state 1, action fails
    simulate_restore(&initial, &mut svm, &divergent, &delta_1, None, &prev_exec_dirty);
    divergent.extend(delta_1.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);

    // Execution corrupts pk
    svm.set_account(pk, make_account(55555, &[0xFF; 100])).unwrap();
    prev_exec_dirty.insert(pk);
    divergent.extend(prev_exec_dirty.iter().copied());

    // Action fails → prev_delta stays None
    let prev_delta: Option<SvmSnapshot> = None;

    // Iteration 2: pick state 2 — must use restore_selective (not from)
    simulate_restore(&initial, &mut svm, &divergent, &delta_2,
        prev_delta.as_ref(), &prev_exec_dirty);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 200,
        "must restore correctly even without prev_delta");
}

#[test]
fn test_edge_alternating_success_failure() {
    // 6 iterations alternating success/failure.
    // Success sets prev_delta, failure clears it.
    // Verify correct restore path chosen each time.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let make_state = |val: u64| -> SvmSnapshot {
        let mut accts = FastHashMap::default();
        accts.insert(pk, Arc::new(make_account(val, &[val as u8])));
        SvmSnapshot { accounts: accts, sysvars: initial.sysvars.clone() }
    };

    let states: Vec<SvmSnapshot> = (1..=6).map(|i| make_state(i * 100)).collect();
    let successes = [true, false, true, false, true, false];

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    for (iter, (&success, delta)) in successes.iter().zip(states.iter()).enumerate() {
        simulate_restore(&initial, &mut svm, &divergent, delta,
            prev_delta.as_ref(), &prev_exec_dirty);
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        let expected = (iter as u64 + 1) * 100;
        assert_eq!(svm.get_account(&pk).unwrap().lamports, expected,
            "iter {}: expected {}", iter, expected);

        // Simulate execution
        svm.set_account(pk, make_account(99999, &[0xEE])).unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(pk);
        divergent.extend(prev_exec_dirty.iter().copied());

        if success {
            prev_delta = Some(delta.clone());
        } else {
            prev_delta = None; // failure clears prev_delta
        }
    }
}

// ---- Category 7: DirtyTracker Edge Cases ----
// (These tests are duplicated in dirty_tracker.rs as well, keeping them here as edge case context)

#[test]
fn test_edge_dirty_tracker_clear_is_complete() {
    // Record 10 accounts across 3 transactions. Clear. Verify all empty.
    // Record 2 new accounts. Verify only new ones present.
    let mut tracker = DirtyTracker::new();

    let fee_payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    // 3 transactions with multiple accounts each
    for _tx in 0..3 {
        let mut accounts = Vec::new();
        for _ in 0..3 {
            accounts.push(AccountMeta::new(Pubkey::new_unique(), false));
        }
        let ix = Instruction::new_with_bytes(program, &[], accounts);
        tracker.record_tx(&[ix], &fee_payer);
    }
    tracker.mark_clock_dirty();

    assert!(tracker.dirty_count() > 0);
    assert!(!tracker.dirty_accounts().is_empty());
    assert!(!tracker.read_accounts().is_empty());
    assert!(tracker.is_clock_dirty());

    // Clear
    tracker.clear();
    assert_eq!(tracker.dirty_count(), 0);
    assert!(tracker.dirty_accounts().is_empty());
    assert!(tracker.read_accounts().is_empty());
    assert!(!tracker.is_clock_dirty());

    // Record 2 new accounts
    let pk_new_1 = Pubkey::new_unique();
    let pk_new_2 = Pubkey::new_unique();
    tracker.mark_account_dirty(&pk_new_1);
    tracker.mark_account_dirty(&pk_new_2);

    assert_eq!(tracker.dirty_count(), 2);
    assert!(tracker.dirty_accounts().contains(&pk_new_1));
    assert!(tracker.dirty_accounts().contains(&pk_new_2));
}

#[test]
fn test_edge_dirty_tracker_duplicate_writable() {
    // Same pubkey appears as writable in 3 different instructions
    // across 2 transactions. dirty_count() should be deduplicated.
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();
    let pk_shared = Pubkey::new_unique();

    // Tx 1: 2 instructions both writing pk_shared
    let ix1 = Instruction::new_with_bytes(program, &[], vec![
        AccountMeta::new(pk_shared, false),
        AccountMeta::new(Pubkey::new_unique(), false),
    ]);
    let ix2 = Instruction::new_with_bytes(program, &[], vec![
        AccountMeta::new(pk_shared, false),
    ]);
    tracker.record_tx(&[ix1, ix2], &fee_payer);

    // Tx 2: pk_shared again
    let ix3 = Instruction::new_with_bytes(program, &[], vec![
        AccountMeta::new(pk_shared, false),
    ]);
    tracker.record_tx(&[ix3], &fee_payer);

    // pk_shared should appear only once
    let count = tracker.dirty_accounts().iter()
        .filter(|&&pk| pk == pk_shared)
        .count();
    assert_eq!(count, 1, "pk_shared should be deduplicated in dirty set");

    // But total dirty count includes fee_payer + pk_shared + the unique one
    assert!(tracker.dirty_count() >= 2, "should have at least fee_payer and pk_shared");
}

#[test]
fn test_edge_dirty_tracker_clone_is_fresh() {
    // Clone a dirty tracker with 5 recorded accounts.
    // Clone should be empty (by design — Clone impl returns fresh).
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    for _ in 0..5 {
        let ix = Instruction::new_with_bytes(program, &[], vec![
            AccountMeta::new(Pubkey::new_unique(), false),
        ]);
        tracker.record_tx(&[ix], &fee_payer);
    }
    tracker.mark_clock_dirty();

    assert!(tracker.dirty_count() > 0);
    assert!(tracker.is_clock_dirty());

    let cloned = tracker.clone();
    assert_eq!(cloned.dirty_count(), 0, "cloned tracker should be empty");
    assert!(cloned.dirty_accounts().is_empty());
    assert!(cloned.read_accounts().is_empty());
    assert!(!cloned.is_clock_dirty(), "cloned tracker should not have clock dirty");
}
