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
// Fingerprinting helpers
// =========================================================================

#[test]
fn test_value_bucket() {
    assert_eq!(value_bucket(0), 0);
    assert_eq!(value_bucket(1), 1);
    assert_eq!(value_bucket(2), 2);    // 2..=9 => bucket 2
    assert_eq!(value_bucket(5), 2);
    assert_eq!(value_bucket(9), 2);
    assert_eq!(value_bucket(10), 3);   // 10..=99 => bucket 3
    assert_eq!(value_bucket(99), 3);
    assert_eq!(value_bucket(100), 4);  // 100..=999 => bucket 4
    assert_eq!(value_bucket(999), 4);
    assert_eq!(value_bucket(1_000), 5);
    assert_eq!(value_bucket(9_999), 5);
    assert_eq!(value_bucket(10_000), 6);
    assert_eq!(value_bucket(99_999), 6);
    assert_eq!(value_bucket(100_000), 7);
    assert_eq!(value_bucket(999_999), 7);
    assert_eq!(value_bucket(1_000_000), 8);
    assert_eq!(value_bucket(9_999_999), 8);
    assert_eq!(value_bucket(10_000_000), 9);
    assert_eq!(value_bucket(100_000_000), 10);
    assert_eq!(value_bucket(1_000_000_000), 11);
    assert_eq!(value_bucket(10_000_000_000), 12);
    assert_eq!(value_bucket(100_000_000_000), 13);
    assert_eq!(value_bucket(1_000_000_000_000), 14);
    assert_eq!(value_bucket(9_999_999_999_999), 14);
    assert_eq!(value_bucket(10_000_000_000_000), 15);
    assert_eq!(value_bucket(u64::MAX), 15);
}

#[test]
fn test_slot_bucket() {
    use super::super::svm_snapshot::slot_bucket;
    // Individual slots 0-9
    assert_eq!(slot_bucket(0), 0);
    assert_eq!(slot_bucket(1), 1);
    assert_eq!(slot_bucket(5), 5);
    assert_eq!(slot_bucket(9), 9);
    // Per-10 range: 10-99 → buckets 10-18
    assert_eq!(slot_bucket(10), 10);
    assert_eq!(slot_bucket(50), 14);
    assert_eq!(slot_bucket(99), 18);
    // Per-100 range: 100-999 → buckets 19-27
    assert_eq!(slot_bucket(100), 19);
    assert_eq!(slot_bucket(500), 23);
    assert_eq!(slot_bucket(999), 27);
    // Per-1K range: 1000-9999 → buckets 28-36
    assert_eq!(slot_bucket(1000), 28);
    assert_eq!(slot_bucket(1600), 28);
    assert_eq!(slot_bucket(2000), 29);
    assert_eq!(slot_bucket(5000), 32);
    // Per-10K range: 10000-99999 → buckets 37-45
    assert_eq!(slot_bucket(10000), 37);
    assert_eq!(slot_bucket(50000), 41);
    // Per-100K range: 100000-999999 → buckets 46-54
    assert_eq!(slot_bucket(100000), 46);
    assert_eq!(slot_bucket(500000), 50);
    // Per-1M range: 1000000-9999999 → buckets 55-63
    assert_eq!(slot_bucket(1_000_000), 55);
    assert_eq!(slot_bucket(9_999_999), 63);
    // Overflow
    assert_eq!(slot_bucket(10_000_000), 64);
    assert_eq!(slot_bucket(u64::MAX), 64);
}

#[test]
fn test_state_class_from_fingerprint() {
    // Top 16 bits of 0xABCD_0000_0000_0000 should be 0xABCD
    assert_eq!(state_class_from_fingerprint(0xABCD_0000_0000_0000), 0xABCD);
    assert_eq!(state_class_from_fingerprint(0), 0);
    assert_eq!(state_class_from_fingerprint(u64::MAX), 0xFFFF);
    // Lower bits shouldn't affect state class
    assert_eq!(
        state_class_from_fingerprint(0xDEAD_1234_5678_9ABC),
        0xDEAD
    );
}

// =========================================================================
// SvmSnapshot — unit tests (no SVM needed)
// =========================================================================

#[test]
fn test_svm_snapshot_empty() {
    let clock = Clock {
        slot: 42,
        epoch_start_timestamp: 1000,
        epoch: 5,
        leader_schedule_epoch: 6,
        unix_timestamp: 2000,
    };
    let snap = SvmSnapshot::empty(clock.clone());
    assert_eq!(snap.account_count(), 0);
    assert_eq!(snap.clock().slot, 42);
    assert_eq!(snap.clock().unix_timestamp, 2000);
}

#[test]
fn test_svm_snapshot_accounts_and_clock() {
    let clock = Clock {
        slot: 100,
        epoch_start_timestamp: 0,
        epoch: 1,
        leader_schedule_epoch: 2,
        unix_timestamp: 5000,
    };
    let mut accounts = FastHashMap::default();
    let pk = Pubkey::new_unique();
    accounts.insert(pk, Arc::new(Account {
        lamports: 999,
        data: vec![1, 2, 3],
        owner: Pubkey::new_unique(),
        executable: false,
        rent_epoch: 0,
    }));
    let sysvars = clock_to_sysvars(&clock);
    let snap = SvmSnapshot { accounts, sysvars };
    assert_eq!(snap.account_count(), 1);
    assert!(snap.accounts().contains_key(&pk));
    assert_eq!(snap.accounts()[&pk].lamports, 999);
    assert_eq!(snap.clock().slot, 100);
}

// =========================================================================
// SvmSnapshot — LiteSVM integration tests
// =========================================================================

#[test]
fn test_svm_snapshot_take_and_restore_round_trip() {
    let mut svm = LiteSVM::new();
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let acct1 = make_account(1000, &[1, 2, 3]);
    let acct2 = make_account(2000, &[4, 5, 6, 7]);
    svm.set_account(pk1, acct1.clone()).unwrap();
    svm.set_account(pk2, acct2.clone()).unwrap();

    // Snapshot both accounts
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    assert_eq!(snap.account_count(), 2);

    // Mutate accounts in the SVM
    svm.set_account(pk1, make_account(9999, &[0xFF])).unwrap();
    svm.set_account(pk2, make_account(0, &[])).unwrap();
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 9999);

    // Restore via dirty tracker that marks both as dirty
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);
    let restored = snap.restore(&mut svm, &dirty);
    assert_eq!(restored, 2);

    // Verify original state is back
    let got1 = svm.get_account(&pk1).unwrap();
    assert_eq!(got1.lamports, acct1.lamports);
    assert_eq!(got1.data, acct1.data);
    let got2 = svm.get_account(&pk2).unwrap();
    assert_eq!(got2.lamports, acct2.lamports);
    assert_eq!(got2.data, acct2.data);
}

#[test]
fn test_svm_snapshot_restore_removes_created_accounts() {
    let mut svm = LiteSVM::new();
    let pk_original = Pubkey::new_unique();
    svm.set_account(pk_original, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_original].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Create a new account that wasn't in the snapshot
    let pk_new = Pubkey::new_unique();
    svm.set_account(pk_new, make_account(500, &[9, 9])).unwrap();
    assert!(svm.get_account(&pk_new).is_some());

    // Restore — pk_new gets zeroed (lamports=0), which LiteSVM treats as deleted
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_new);
    snap.restore(&mut svm, &dirty);

    // LiteSVM returns None for zero-lamport accounts (they don't "exist")
    assert!(svm.get_account(&pk_new).is_none());
}

// =========================================================================
// Executable (program) account protection — prevents programs_cache desync
// =========================================================================

/// Helper: create an executable (program) account that LiteSVM will accept.
/// Uses the native_loader as owner so LiteSVM stores it without ELF validation.
fn make_executable_account(lamports: u64, data: &[u8]) -> Account {
    Account {
        lamports,
        data: data.to_vec(),
        owner: solana_pubkey::pubkey!("NativeLoader1111111111111111111111111111111"),
        executable: true,
        rent_epoch: 0,
    }
}

#[test]
fn test_restore_skips_zeroing_executable_accounts() {
    // Executable accounts created during an iteration must NOT be zeroed on
    // restore — zeroing removes them from accounts_db but not programs_cache,
    // causing a desync panic in litesvm.
    let mut svm = LiteSVM::new();
    let pk_original = Pubkey::new_unique();
    svm.set_account(pk_original, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_original].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Simulate a program being deployed during an iteration
    let pk_program = Pubkey::new_unique();
    svm.set_account(pk_program, make_executable_account(5000, &[0xEF; 32])).unwrap();
    assert!(svm.get_account(&pk_program).is_some());

    // Restore — pk_program should be SKIPPED (not zeroed)
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_program);
    snap.restore(&mut svm, &dirty);

    // Executable account must still exist
    let prog = svm.get_account(&pk_program);
    assert!(prog.is_some(), "executable account should NOT be zeroed by restore");
    assert_eq!(prog.unwrap().lamports, 5000);
}

#[test]
fn test_restore_zeroes_non_executable_but_skips_executable() {
    // When both executable and non-executable accounts are created during an
    // iteration, restore should zero only the non-executable ones.
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    let pk_data = Pubkey::new_unique();
    let pk_program = Pubkey::new_unique();
    svm.set_account(pk_data, make_account(500, &[9, 9])).unwrap();
    svm.set_account(pk_program, make_executable_account(5000, &[0xEF; 32])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_data);
    dirty.mark_account_dirty(&pk_program);
    snap.restore(&mut svm, &dirty);

    // Non-executable gets zeroed (deleted)
    assert!(svm.get_account(&pk_data).is_none(),
        "non-executable created account should be zeroed");
    // Executable survives
    assert!(svm.get_account(&pk_program).is_some(),
        "executable account should NOT be zeroed");
}

#[test]
fn test_restore_selective_skips_zeroing_executable_accounts() {
    // restore_selective: executable accounts in divergent_keys but not in
    // initial snapshot must not be zeroed.
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Simulate: previous iteration deployed a program
    let pk_program = Pubkey::new_unique();
    svm.set_account(pk_program, make_executable_account(5000, &[0xEF; 32])).unwrap();
    // And created a data account
    let pk_data = Pubkey::new_unique();
    svm.set_account(pk_data, make_account(300, &[7, 8])).unwrap();

    // Both are in divergent_keys (dirtied by previous iteration)
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_program);
    divergent.insert(pk_data);

    // Restore to empty delta (= initial state, neither account in delta)
    let empty_delta = SvmSnapshot::empty(initial.clock());
    initial.restore_selective(&mut svm, &divergent, &empty_delta);

    // Data account gets zeroed
    assert!(svm.get_account(&pk_data).is_none(),
        "non-executable divergent account should be zeroed");
    // Program account survives
    assert!(svm.get_account(&pk_program).is_some(),
        "executable divergent account should NOT be zeroed by restore_selective");
}

#[test]
fn test_restore_selective_from_skips_zeroing_executable_accounts() {
    // restore_selective_from: same protection applies when restoring with
    // delta-to-delta comparison.
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Simulate: previous iteration deployed a program and created a data account
    let pk_program = Pubkey::new_unique();
    svm.set_account(pk_program, make_executable_account(5000, &[0xEF; 32])).unwrap();
    let pk_data = Pubkey::new_unique();
    svm.set_account(pk_data, make_account(300, &[7, 8])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_program);
    divergent.insert(pk_data);

    let prev_delta = SvmSnapshot::empty(initial.clock());
    let next_delta = SvmSnapshot::empty(initial.clock());
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    // Data account gets zeroed
    assert!(svm.get_account(&pk_data).is_none(),
        "non-executable divergent account should be zeroed");
    // Program account survives
    assert!(svm.get_account(&pk_program).is_some(),
        "executable divergent account should NOT be zeroed by restore_selective_from");
}

#[test]
fn test_svm_snapshot_restore_clock() {
    let mut svm = LiteSVM::new();
    let original_clock = svm.get_sysvar::<Clock>();

    let tracked: HashSet<Pubkey> = HashSet::new();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Advance the clock
    let new_clock = Clock {
        slot: original_clock.slot + 100,
        epoch: original_clock.epoch + 1,
        unix_timestamp: original_clock.unix_timestamp + 60,
        ..original_clock
    };
    svm.set_sysvar(&new_clock);
    assert_eq!(svm.get_sysvar::<Clock>().slot, new_clock.slot);

    // Restore with clock_dirty flag
    let mut dirty = DirtyTracker::new();
    dirty.mark_clock_dirty(100);
    snap.restore(&mut svm, &dirty);

    let restored_clock = svm.get_sysvar::<Clock>();
    assert_eq!(restored_clock.slot, original_clock.slot);
}

#[test]
fn test_svm_snapshot_restore_always_restores_sysvars() {
    let mut svm = LiteSVM::new();
    let original_clock = svm.get_sysvar::<Clock>();

    let tracked: HashSet<Pubkey> = HashSet::new();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Advance the clock
    let new_clock = Clock {
        slot: original_clock.slot + 100,
        ..original_clock
    };
    svm.set_sysvar(&new_clock);

    // Restore — all sysvars are always restored now
    let dirty = DirtyTracker::new();
    snap.restore(&mut svm, &dirty);

    let after = svm.get_sysvar::<Clock>();
    assert_eq!(after.slot, original_clock.slot); // restored to original
}

#[test]
fn test_svm_snapshot_take_all() {
    let mut svm = LiteSVM::new();
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    svm.set_account(pk1, make_account(100, &[1])).unwrap();
    svm.set_account(pk2, make_account(200, &[2])).unwrap();

    let snap = SvmSnapshot::take_all(&svm);
    // Should capture at least our 2 accounts (plus any sysvar/builtin accounts)
    assert!(snap.account_count() >= 2);
    assert!(snap.accounts().contains_key(&pk1));
    assert!(snap.accounts().contains_key(&pk2));
    assert_eq!(snap.accounts()[&pk1].lamports, 100);
}

#[test]
fn test_svm_snapshot_restore_full_round_trip() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(777, &[0xAB, 0xCD])).unwrap();

    // take_all captures everything
    let snap = SvmSnapshot::take_all(&svm);

    // Mutate to different (non-zero) value — LiteSVM deletes zero-lamport accounts
    svm.set_account(pk, make_account(1, &[0xFF])).unwrap();
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 1);

    // restore_full writes everything back
    let count = snap.restore_full(&mut svm);
    assert!(count >= 1);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 777);
    assert_eq!(svm.get_account(&pk).unwrap().data, vec![0xAB, 0xCD]);
}

#[test]
fn test_svm_snapshot_take_delta() {
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    let pk_changed = Pubkey::new_unique();
    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
    svm.set_account(pk_changed, make_account(200, &[2])).unwrap();

    // Parent delta is empty (initial state)
    let parent_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Simulate an action that modifies pk_changed
    svm.set_account(pk_changed, make_account(999, &[9, 9, 9])).unwrap();

    // Track which accounts were dirty
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_changed);

    let delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // Delta should contain only the changed account
    assert_eq!(delta.account_count(), 1);
    assert!(delta.accounts().contains_key(&pk_changed));
    assert!(!delta.accounts().contains_key(&pk_initial));
    assert_eq!(delta.accounts()[&pk_changed].lamports, 999);
}

#[test]
fn test_svm_snapshot_take_delta_inherits_parent() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();

    let empty_delta = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action 1: modifies pk_a
    svm.set_account(pk_a, make_account(111, &[0xAA])).unwrap();
    let mut dirty1 = DirtyTracker::new();
    dirty1.mark_account_dirty(&pk_a);
    let delta1 = SvmSnapshot::take_delta(&svm, &empty_delta, &dirty1);
    assert_eq!(delta1.account_count(), 1); // only pk_a

    // Action 2: modifies pk_b, parent is delta1
    svm.set_account(pk_b, make_account(222, &[0xBB])).unwrap();
    let mut dirty2 = DirtyTracker::new();
    dirty2.mark_account_dirty(&pk_b);
    let delta2 = SvmSnapshot::take_delta(&svm, &delta1, &dirty2);

    // Delta2 should inherit pk_a from delta1 AND have pk_b
    assert_eq!(delta2.account_count(), 2);
    assert_eq!(delta2.accounts()[&pk_a].lamports, 111);
    assert_eq!(delta2.accounts()[&pk_b].lamports, 222);
}

#[test]
fn test_svm_snapshot_restore_selective() {
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

    // Build a delta where pk_a=111, pk_b=222 (pk_c unchanged from initial)
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(111, &[0xAA])));
    delta_accounts.insert(pk_b, Arc::new(make_account(222, &[0xBB])));
    let delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // Scramble SVM state (simulates previous iteration left garbage)
    svm.set_account(pk_a, make_account(0, &[])).unwrap();
    svm.set_account(pk_b, make_account(0, &[])).unwrap();
    svm.set_account(pk_c, make_account(0, &[])).unwrap();

    // divergent_keys = all 3 accounts (they all differ from initial)
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_a);
    divergent.insert(pk_b);
    divergent.insert(pk_c);

    let count = initial.restore_selective(&mut svm, &divergent, &delta);
    // pk_c restored to initial (1 call), pk_a and pk_b from delta (2 calls) = 3
    assert_eq!(count, 3);

    // pk_a and pk_b should be delta values
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 111);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 222);
    // pk_c should be initial value
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
}

#[test]
fn test_svm_snapshot_restore_selective_from_skips_shared_arcs() {
    let mut svm = LiteSVM::new();
    let pk_shared = Pubkey::new_unique();
    let pk_changed = Pubkey::new_unique();

    svm.set_account(pk_shared, make_account(100, &[1])).unwrap();
    svm.set_account(pk_changed, make_account(200, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_shared, pk_changed].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Build prev_delta and next_delta that SHARE an Arc for pk_shared
    let shared_arc = Arc::new(make_account(555, &[5, 5, 5]));
    let mut prev_accounts = FastHashMap::default();
    prev_accounts.insert(pk_shared, shared_arc.clone());
    prev_accounts.insert(pk_changed, Arc::new(make_account(888, &[8])));
    let prev_delta = SvmSnapshot {
        accounts: prev_accounts,
        sysvars: initial.sysvars.clone(),
    };

    let mut next_accounts = FastHashMap::default();
    next_accounts.insert(pk_shared, shared_arc.clone()); // same Arc!
    next_accounts.insert(pk_changed, Arc::new(make_account(999, &[9])));
    let next_delta = SvmSnapshot {
        accounts: next_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // Set SVM to prev_delta values (simulate previous iteration)
    svm.set_account(pk_shared, make_account(555, &[5, 5, 5])).unwrap();
    svm.set_account(pk_changed, make_account(888, &[8])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_shared);
    divergent.insert(pk_changed);

    // No accounts were dirtied by execution (clean transition)
    let prev_exec_dirty = FastHashSet::default();

    let count = initial.restore_selective_from(
        &mut svm,
        &divergent,
        &prev_delta,
        &next_delta,
        &prev_exec_dirty,
    );

    // pk_shared shares Arc AND wasn't exec-dirtied → skipped (0 calls)
    // pk_changed has different Arc → set_account (1 call)
    assert_eq!(count, 1);

    // pk_shared should still have prev value (unchanged — that's the point)
    assert_eq!(svm.get_account(&pk_shared).unwrap().lamports, 555);
    // pk_changed should have next value
    assert_eq!(svm.get_account(&pk_changed).unwrap().lamports, 999);
}

#[test]
fn test_svm_snapshot_restore_selective_from_respects_exec_dirty() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Both deltas share the same Arc for pk
    let shared_arc = Arc::new(make_account(500, &[5]));
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk, shared_arc.clone());
    let prev_delta = SvmSnapshot {
        accounts: delta_accounts.clone(),
        sysvars: initial.sysvars.clone(),
    };
    let next_delta = SvmSnapshot {
        accounts: delta_accounts,
        sysvars: initial.sysvars.clone(),
    };

    // Simulate execution dirtied pk (SVM now has garbage, not the delta value)
    svm.set_account(pk, make_account(0, &[0xFF, 0xFF])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);

    // Mark pk as exec-dirtied
    let mut prev_exec_dirty = FastHashSet::default();
    prev_exec_dirty.insert(pk);

    let count = initial.restore_selective_from(
        &mut svm,
        &divergent,
        &prev_delta,
        &next_delta,
        &prev_exec_dirty,
    );

    // Even though Arc pointers are the same, exec_dirty forces a write
    assert_eq!(count, 1);
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 500);
}

// =========================================================================
// DirtyTracker + SvmSnapshot integration — the fuzz iteration loop
// =========================================================================

#[test]
fn test_dirty_tracker_snapshot_iteration_cycle() {
    // Simulates the core fuzz loop:
    // 1. Setup initial state & snapshot
    // 2. Execute actions (mutate accounts)
    // 3. Dirty tracker records what changed
    // 4. Restore snapshot
    // 5. Verify initial state is back
    let mut svm = LiteSVM::new();
    let pk_user = Pubkey::new_unique();
    let pk_vault = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();

    // Both accounts must have non-zero lamports — LiteSVM deletes zero-lamport accounts
    svm.set_account(pk_user, make_account(1_000_000, &[0; 32])).unwrap();
    svm.set_account(pk_vault, make_account(1, &[0; 64])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_user, pk_vault].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // --- Iteration 1: simulate deposit ---
    let mut dirty = DirtyTracker::new();
    let ix = anchor_lang::solana_program::instruction::Instruction {
        program_id,
        accounts: vec![
            anchor_lang::solana_program::instruction::AccountMeta::new(pk_user, true),
            anchor_lang::solana_program::instruction::AccountMeta::new(pk_vault, false),
        ],
        data: vec![0x01], // deposit instruction
    };
    let fee_payer = Pubkey::new_unique();
    dirty.record_tx(&[ix], &fee_payer);

    // Simulate the state change (normally done by SVM execution)
    svm.set_account(pk_user, make_account(500_000, &[0; 32])).unwrap();
    svm.set_account(pk_vault, make_account(500_001, &[0; 64])).unwrap();

    // Verify dirty tracker caught the right accounts
    assert!(dirty.dirty_accounts().contains(&pk_user));
    assert!(dirty.dirty_accounts().contains(&pk_vault));

    // Restore
    snap.restore(&mut svm, &dirty);
    assert_eq!(svm.get_account(&pk_user).unwrap().lamports, 1_000_000);
    assert_eq!(svm.get_account(&pk_vault).unwrap().lamports, 1);

    // --- Iteration 2: different action, same snapshot ---
    dirty.clear();
    let ix2 = anchor_lang::solana_program::instruction::Instruction {
        program_id,
        accounts: vec![anchor_lang::solana_program::instruction::AccountMeta::new(pk_vault, false)],
        data: vec![0x02],
    };
    dirty.record_tx(&[ix2], &fee_payer);
    svm.set_account(pk_vault, make_account(999_999, &[0xFF; 64])).unwrap();

    snap.restore(&mut svm, &dirty);
    assert_eq!(svm.get_account(&pk_vault).unwrap().lamports, 1);
    assert_eq!(svm.get_account(&pk_vault).unwrap().data, vec![0; 64]);
    // pk_user was NOT dirty in iteration 2, should be unchanged from initial
    assert_eq!(svm.get_account(&pk_user).unwrap().lamports, 1_000_000);
}

#[test]
fn test_take_full_captures_dirty_and_base() {
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(100, &[1])).unwrap();
    svm.set_account(pk_b, make_account(200, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    // Modify pk_a only
    svm.set_account(pk_a, make_account(999, &[9, 9])).unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_a);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);

    // Full snapshot should have BOTH accounts
    assert_eq!(full.account_count(), 2);
    // pk_a should have the new value
    assert_eq!(full.accounts()[&pk_a].lamports, 999);
    // pk_b should have the original value (from base)
    assert_eq!(full.accounts()[&pk_b].lamports, 200);
}

// =========================================================================
// Fingerprint tests
// =========================================================================

#[test]
fn test_fingerprint_empty_dirty_set() {
    let svm = LiteSVM::new();
    let dirty = DirtyTracker::new();
    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };
    assert_eq!(compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial), 0);
}

#[test]
fn test_fingerprint_changes_with_data() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    // Create initial snapshot before modifications (empty accounts = 0 initial lamports)
    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    // Use data that crosses log2_bucket boundaries:
    // [0,0,0,0,0,0,0,0] → u64 LE = 0 → bucket 0
    svm.set_account(pk, make_account(1000, &[0, 0, 0, 0, 0, 0, 0, 0])).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    let fp1 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);
    assert_ne!(fp1, 0); // non-zero because pubkey + lamports also contribute

    // [1,0,0,0,0,0,0,0] → u64 LE = 1 → bucket 1 (different from bucket 0)
    svm.set_account(pk, make_account(1000, &[1, 0, 0, 0, 0, 0, 0, 0])).unwrap();
    let fp2 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);

    assert_ne!(fp1, fp2, "data crossing bucket boundaries should produce different fingerprints");

    // Also test lamports bucket boundary:
    // lamports=1 (diff from 0 = 1 → bucket 1) vs lamports=u64::MAX (diff from 0 = MAX → overflow bucket)
    svm.set_account(pk, make_account(1, &[0; 8])).unwrap();
    let fp3 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);
    svm.set_account(pk, make_account(u64::MAX, &[0; 8])).unwrap();
    let fp4 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);
    assert_ne!(fp3, fp4, "lamports crossing bucket boundary should change fingerprint");
}

#[test]
fn test_fingerprint_deterministic() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(500, &[0xAB; 16])).unwrap();

    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    let fp1 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);
    let fp2 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial);
    assert_eq!(fp1, fp2, "same state should produce same fingerprint");
}

#[test]
fn test_slot_diff_bucket() {
    use super::super::svm_snapshot::slot_diff_bucket;
    // Individual 0-9
    assert_eq!(slot_diff_bucket(0), 0);
    assert_eq!(slot_diff_bucket(5), 5);
    assert_eq!(slot_diff_bucket(9), 9);
    // Per-10: 10-99
    assert_eq!(slot_diff_bucket(10), 10);
    assert_eq!(slot_diff_bucket(50), 14);
    assert_eq!(slot_diff_bucket(99), 18);
    // Per-100: 100-999
    assert_eq!(slot_diff_bucket(100), 19);
    assert_eq!(slot_diff_bucket(999), 27);
    // Per-1K: 1000-9999
    assert_eq!(slot_diff_bucket(1000), 28);
    assert_eq!(slot_diff_bucket(2000), 29);
    assert_eq!(slot_diff_bucket(3000), 30);
    assert_eq!(slot_diff_bucket(9999), 36);
    // Per-10K: 10000-99999
    assert_eq!(slot_diff_bucket(10000), 37);
    assert_eq!(slot_diff_bucket(54520), 41);
    assert_eq!(slot_diff_bucket(99999), 45);
    // Per-100K: 100000-999999
    assert_eq!(slot_diff_bucket(100000), 46);
    assert_eq!(slot_diff_bucket(999999), 54);
    // Overflow (≥1M)
    assert_eq!(slot_diff_bucket(1_000_000), 55);
    assert_eq!(slot_diff_bucket(u64::MAX), 55);
}

// =========================================================================
// Multi-step state chains (A→B→C)
// =========================================================================

#[test]
fn test_delta_chain_three_levels_same_account() {
    // Account X modified at every level: 100→200→300→400.
    // take_delta at each step. restore_full from each delta yields correct value.
    // restore_selective from delta_C back to delta_A correctly reverts X.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();

    // Initial state: X=100
    svm.set_account(pk_x, make_account(100, &[0x01])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_x].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action A: X → 200
    svm.set_account(pk_x, make_account(200, &[0x02])).unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk_x);
    let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);
    assert_eq!(delta_a.accounts()[&pk_x].lamports, 200);

    // Action B: X → 300 (parent = delta_a)
    svm.set_account(pk_x, make_account(300, &[0x03])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_x);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);
    assert_eq!(delta_b.accounts()[&pk_x].lamports, 300);

    // Action C: X → 400 (parent = delta_b)
    svm.set_account(pk_x, make_account(400, &[0x04])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_x);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);
    assert_eq!(delta_c.accounts()[&pk_x].lamports, 400);

    // restore_full from delta_a → X=200
    delta_a.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200);

    // restore_full from delta_b → X=300
    delta_b.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 300);

    // restore_full from delta_c → X=400
    delta_c.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 400);

    // restore_selective from delta_C state back to delta_A:
    // SVM currently has delta_C values. divergent = {pk_x} (delta_C's key).
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_x);
    initial.restore_selective(&mut svm, &divergent, &delta_a);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200);
}

#[test]
fn test_delta_chain_middle_deletes_account() {
    // Action A creates X. Action B deletes X (tombstone in delta_B).
    // Action C adds Y. Verify delta_B has tombstone, restore_full zeroes X.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    // Initial: X=100
    svm.set_account(pk_x, make_account(100, &[1])).unwrap();
    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action A: X → 200
    svm.set_account(pk_x, make_account(200, &[2])).unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk_x);
    let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

    // Action B: delete X (simulate by setting lamports=0, which makes get_account return None)
    svm.set_account(pk_x, Account { lamports: 0, ..Default::default() }).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_x);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

    // Delta B should have X as tombstone (lamports=0)
    assert!(delta_b.accounts().contains_key(&pk_x));
    assert_eq!(delta_b.accounts()[&pk_x].lamports, 0);

    // Action C: add Y=500 (parent = delta_b)
    svm.set_account(pk_y, make_account(500, &[5])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_y);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_b, &dirty_c);
    assert!(delta_c.accounts().contains_key(&pk_y));
    assert_eq!(delta_c.accounts()[&pk_y].lamports, 500);
    // X tombstone inherited from delta_b
    assert_eq!(delta_c.accounts()[&pk_x].lamports, 0);

    // Restore to a state where X existed first
    svm.set_account(pk_x, make_account(999, &[9])).unwrap();
    // restore_full from delta_b should zero X
    delta_b.restore_full(&mut svm);
    // LiteSVM treats zero-lamport as deleted
    assert!(svm.get_account(&pk_x).is_none());
}

#[test]
fn test_delta_chain_sibling_branches() {
    // delta_A is parent. delta_B (from A) modifies X. delta_C (also from A) modifies Y.
    // Both inherit unchanged accounts from A via Arc clone.
    // restore_selective_from(prev=delta_B, next=delta_C) should skip shared Arcs.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    // Initial
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();
    svm.set_account(pk_x, make_account(200, &[2])).unwrap();
    svm.set_account(pk_y, make_account(300, &[3])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_base, pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action A: modify base → 111
    svm.set_account(pk_base, make_account(111, &[0xAA])).unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk_base);
    let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

    // Sibling B (from delta_a): modify X → 222
    svm.set_account(pk_x, make_account(222, &[0xBB])).unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk_x);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

    // Reset X for sibling C
    svm.set_account(pk_x, make_account(200, &[2])).unwrap();

    // Sibling C (from delta_a): modify Y → 333
    svm.set_account(pk_y, make_account(333, &[0xCC])).unwrap();
    let mut dirty_c = DirtyTracker::new();
    dirty_c.mark_account_dirty(&pk_y);
    let delta_c = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_c);

    // Both siblings share the same Arc for pk_base (inherited from delta_a)
    assert!(Arc::ptr_eq(
        &delta_b.accounts()[&pk_base],
        &delta_c.accounts()[&pk_base],
    ));

    // delta_b has X=222, delta_c has Y=333
    assert_eq!(delta_b.accounts()[&pk_x].lamports, 222);
    assert!(!delta_b.accounts().contains_key(&pk_y));
    assert_eq!(delta_c.accounts()[&pk_y].lamports, 333);
    assert!(!delta_c.accounts().contains_key(&pk_x));

    // Set SVM to delta_b state
    delta_b.restore_full(&mut svm);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 222);

    // restore_selective_from: prev=delta_B, next=delta_C
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    for pk in delta_b.accounts().keys() {
        divergent.insert(*pk);
    }
    let prev_exec_dirty = FastHashSet::default();

    let count = initial.restore_selective_from(
        &mut svm, &divergent, &delta_b, &delta_c, &prev_exec_dirty,
    );

    // pk_base shares Arc → skipped. X is in divergent but not in delta_c → restored to initial.
    // Y is in delta_c but not in delta_b → unconditional write.
    // So count should be 2 (X restored to initial + Y from delta_c)
    assert_eq!(count, 2);

    // Verify final state
    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 111); // shared, unchanged
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 200); // restored to initial
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 333); // from delta_c
}

// =========================================================================
// restore_selective / restore_selective_from edge cases
// =========================================================================

#[test]
fn test_restore_selective_divergent_not_in_initial_or_delta() {
    // divergent_keys contains an account that exists in neither initial nor delta.
    // This is a CPI-created account from a prior iteration. Should be zeroed.
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    let pk_cpi = Pubkey::new_unique();

    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // CPI-created account in SVM (not in initial snapshot)
    svm.set_account(pk_cpi, make_account(999, &[9, 9])).unwrap();

    // Delta doesn't include pk_cpi either
    let delta = SvmSnapshot::empty(initial.clock().clone());

    // divergent includes pk_cpi (from previous iteration's dirty tracker)
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_cpi);

    initial.restore_selective(&mut svm, &divergent, &delta);

    // pk_cpi should be zeroed (deleted) — not in initial, not in delta
    assert!(svm.get_account(&pk_cpi).is_none());
}

#[test]
fn test_restore_selective_from_next_has_new_accounts() {
    // prev_delta has {X}, next_delta has {X, Y}. Y is brand new.
    // Step 2 finds Y not in prev_delta → unconditional write.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(100, &[1])).unwrap();
    svm.set_account(pk_y, make_account(200, &[2])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // prev_delta: only X=500
    let mut prev_accounts = FastHashMap::default();
    prev_accounts.insert(pk_x, Arc::new(make_account(500, &[5])));
    let prev_delta = SvmSnapshot { accounts: prev_accounts, sysvars: initial.sysvars.clone() };

    // next_delta: X=500 (same Arc) + Y=700 (new)
    let shared_x = prev_delta.accounts()[&pk_x].clone();
    let mut next_accounts = FastHashMap::default();
    next_accounts.insert(pk_x, shared_x);
    next_accounts.insert(pk_y, Arc::new(make_account(700, &[7])));
    let next_delta = SvmSnapshot { accounts: next_accounts, sysvars: initial.sysvars.clone() };

    // SVM starts at prev_delta state
    svm.set_account(pk_x, make_account(500, &[5])).unwrap();

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_x);
    let prev_exec_dirty = FastHashSet::default();

    let count = initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    // X: shared Arc, not exec-dirty → skipped
    // Y: in next_delta, not in prev_delta → written (1 call)
    assert_eq!(count, 1);
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 500);
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 700);
}

#[test]
fn test_restore_selective_from_prev_accounts_not_in_divergent() {
    // prev_delta has {X, Y}, next_delta has {X}. Y is in prev_delta but NOT in
    // divergent_keys. After restore, Y retains prev_delta's value (stale) — documents
    // the contract that callers MUST include all prev_delta keys in divergent_keys.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(100, &[1])).unwrap();
    svm.set_account(pk_y, make_account(200, &[2])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_x, pk_y].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut prev_accounts = FastHashMap::default();
    prev_accounts.insert(pk_x, Arc::new(make_account(500, &[5])));
    prev_accounts.insert(pk_y, Arc::new(make_account(600, &[6])));
    let prev_delta = SvmSnapshot { accounts: prev_accounts, sysvars: initial.sysvars.clone() };

    let mut next_accounts = FastHashMap::default();
    next_accounts.insert(pk_x, Arc::new(make_account(700, &[7])));
    // next_delta does NOT have Y
    let next_delta = SvmSnapshot { accounts: next_accounts, sysvars: initial.sysvars.clone() };

    // SVM at prev_delta state
    svm.set_account(pk_x, make_account(500, &[5])).unwrap();
    svm.set_account(pk_y, make_account(600, &[6])).unwrap();

    // BUG: divergent only includes pk_x, not pk_y (caller error)
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk_x);
    // NOT: divergent.insert(pk_y);
    let prev_exec_dirty = FastHashSet::default();

    initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    // X: in divergent AND in next_delta → skipped in step 1, written with next_delta value in step 2
    assert_eq!(svm.get_account(&pk_x).unwrap().lamports, 700);
    // Y: NOT in divergent → never touched in step 1. NOT in next_delta → never touched in step 2.
    // Still has prev_delta stale value (600).
    // This documents the contract: callers MUST include prev_delta keys in divergent.
    assert_eq!(svm.get_account(&pk_y).unwrap().lamports, 600);
}

#[test]
fn test_restore_selective_empty_divergent_with_delta() {
    // First-iteration case: divergent_keys is empty, delta has 3 accounts.
    // Step 1 is a no-op. Step 2 writes all 3 delta accounts.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    svm.set_account(pk_c, make_account(30, &[3])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Delta with different values for all 3
    let mut delta_accounts = FastHashMap::default();
    delta_accounts.insert(pk_a, Arc::new(make_account(111, &[0xAA])));
    delta_accounts.insert(pk_b, Arc::new(make_account(222, &[0xBB])));
    delta_accounts.insert(pk_c, Arc::new(make_account(333, &[0xCC])));
    let delta = SvmSnapshot { accounts: delta_accounts, sysvars: initial.sysvars.clone() };

    // Empty divergent (first iteration, SVM has initial state)
    let divergent: FastHashSet<Pubkey> = FastHashSet::default();

    let count = initial.restore_selective(&mut svm, &divergent, &delta);

    // Step 1: 0 (empty divergent). Step 2: 3 (all delta accounts).
    assert_eq!(count, 3);
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 111);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 222);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 333);
}

// =========================================================================
// take_delta edge cases
// =========================================================================

#[test]
fn test_take_delta_empty_dirty_tracker() {
    // Parent delta has {X=100, Y=200}. Dirty tracker is empty.
    // Result should be an exact clone with Arc pointers being ptr_eq.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(100, &[1])).unwrap();
    svm.set_account(pk_y, make_account(200, &[2])).unwrap();

    let mut parent_accounts = FastHashMap::default();
    parent_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
    parent_accounts.insert(pk_y, Arc::new(make_account(200, &[2])));
    let parent_delta = SvmSnapshot {
        accounts: parent_accounts,
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let dirty = DirtyTracker::new(); // empty
    let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // Same number of accounts
    assert_eq!(new_delta.account_count(), 2);
    assert_eq!(new_delta.accounts()[&pk_x].lamports, 100);
    assert_eq!(new_delta.accounts()[&pk_y].lamports, 200);

    // Arc pointers should be identical (no new allocations)
    assert!(Arc::ptr_eq(
        &new_delta.accounts()[&pk_x],
        &parent_delta.accounts()[&pk_x],
    ));
    assert!(Arc::ptr_eq(
        &new_delta.accounts()[&pk_y],
        &parent_delta.accounts()[&pk_y],
    ));
}

#[test]
fn test_take_delta_overwrites_parent_value() {
    // Parent delta has X=200. Action modifies X to 300. Dirty tracker has X.
    // New delta should have X=300 with a NEW Arc (not ptr_eq with parent).
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(300, &[3])).unwrap();

    let mut parent_accounts = FastHashMap::default();
    parent_accounts.insert(pk_x, Arc::new(make_account(200, &[2])));
    let parent_delta = SvmSnapshot {
        accounts: parent_accounts,
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_x);

    let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    assert_eq!(new_delta.accounts()[&pk_x].lamports, 300);
    // Must be a NEW Arc (different allocation from parent)
    assert!(!Arc::ptr_eq(
        &new_delta.accounts()[&pk_x],
        &parent_delta.accounts()[&pk_x],
    ));
}

#[test]
fn test_take_delta_deletes_account_from_parent() {
    // Parent delta has X=200. Action deletes X from SVM.
    // Dirty tracker has X, SVM returns None. New delta should have X as tombstone.
    let svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();

    // SVM has X deleted (zero lamports → None)
    // Don't set pk_x in SVM at all (get_account returns None)

    let mut parent_accounts = FastHashMap::default();
    parent_accounts.insert(pk_x, Arc::new(make_account(200, &[2])));
    let parent_delta = SvmSnapshot {
        accounts: parent_accounts,
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_x);

    let new_delta = SvmSnapshot::take_delta(&svm, &parent_delta, &dirty);

    // X should be present as tombstone (lamports=0)
    assert!(new_delta.accounts().contains_key(&pk_x));
    assert_eq!(new_delta.accounts()[&pk_x].lamports, 0);
}

// =========================================================================
// take_full edge cases
// =========================================================================

#[test]
fn test_take_full_deleted_account_removes_key() {
    // Base has {X=100, Y=200}. Dirty tracker marks X. SVM's X is deleted.
    // take_full should REMOVE X from the map (not insert tombstone).
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    svm.set_account(pk_y, make_account(200, &[2])).unwrap();
    // X is NOT in SVM (deleted)

    let mut base_accounts = FastHashMap::default();
    base_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
    base_accounts.insert(pk_y, Arc::new(make_account(200, &[2])));
    let base = SvmSnapshot {
        accounts: base_accounts,
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_x);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);

    // X should be REMOVED (not tombstoned) — asymmetry with take_delta
    assert!(!full.accounts().contains_key(&pk_x));
    // Y should remain from base
    assert_eq!(full.accounts()[&pk_y].lamports, 200);
    assert_eq!(full.account_count(), 1);
}

#[test]
fn test_take_full_adds_new_cpi_account() {
    // Base has {X=100}. Dirty tracker marks Y (CPI-created). SVM has Y=500.
    // take_full should produce {X=100, Y=500}.
    let mut svm = LiteSVM::new();
    let pk_x = Pubkey::new_unique();
    let pk_y = Pubkey::new_unique();

    svm.set_account(pk_x, make_account(100, &[1])).unwrap();
    svm.set_account(pk_y, make_account(500, &[5])).unwrap();

    let mut base_accounts = FastHashMap::default();
    base_accounts.insert(pk_x, Arc::new(make_account(100, &[1])));
    let base = SvmSnapshot {
        accounts: base_accounts,
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    };

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_y);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);

    assert_eq!(full.account_count(), 2);
    assert_eq!(full.accounts()[&pk_x].lamports, 100);
    assert_eq!(full.accounts()[&pk_y].lamports, 500);
}

// =========================================================================
// DirtyTracker edge cases (SVM-related)
// =========================================================================

#[test]
fn test_dirty_tracker_same_key_writable_and_program() {
    // Same Pubkey appears as writable AccountMeta in one instruction AND as
    // program_id in another. Should be in both writable and read_only sets.
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let dual_key = Pubkey::new_unique();
    let other_program = Pubkey::new_unique();

    // Instruction 1: dual_key is writable account
    let ix1 = anchor_lang::solana_program::instruction::Instruction {
        program_id: other_program,
        accounts: vec![anchor_lang::solana_program::instruction::AccountMeta::new(dual_key, false)],
        data: vec![],
    };
    // Instruction 2: dual_key is the program_id
    let ix2 = anchor_lang::solana_program::instruction::Instruction {
        program_id: dual_key,
        accounts: vec![],
        data: vec![],
    };

    tracker.record_tx(&[ix1, ix2], &fee_payer);

    // dual_key should be in BOTH sets
    assert!(tracker.dirty_accounts().contains(&dual_key), "should be in writable set");
    assert!(tracker.read_accounts().contains(&dual_key), "should be in read_only set");
    // dirty_accounts() (writable) is what restore uses
    assert!(tracker.dirty_accounts().contains(&dual_key));
}

#[test]
fn test_restore_with_fee_payer_not_in_snapshot() {
    // Fee payer is recorded as dirty (always writable) but didn't exist at
    // snapshot time. restore hits the "created during iteration" path and zeroes it.
    let mut svm = LiteSVM::new();
    let pk_initial = Pubkey::new_unique();
    let pk_fee_payer = Pubkey::new_unique();

    svm.set_account(pk_initial, make_account(100, &[1])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_initial].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Fee payer created during iteration
    svm.set_account(pk_fee_payer, make_account(1_000_000, &[0xFF; 32])).unwrap();

    let program_id = Pubkey::new_unique();
    let mut dirty = DirtyTracker::new();
    let ix = anchor_lang::solana_program::instruction::Instruction {
        program_id,
        accounts: vec![],
        data: vec![],
    };
    dirty.record_tx(&[ix], &pk_fee_payer);

    // Fee payer should be in dirty set
    assert!(dirty.dirty_accounts().contains(&pk_fee_payer));

    snap.restore(&mut svm, &dirty);

    // Fee payer should be zeroed (deleted) since it wasn't in the snapshot
    assert!(svm.get_account(&pk_fee_payer).is_none());
}

// =========================================================================
// Clock handling
// =========================================================================

#[test]
fn test_restore_selective_from_different_clocks() {
    // prev_delta.clock.slot=100, next_delta.clock.slot=200.
    // After restore_selective_from, SVM clock should be 200.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let prev_delta = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(100),
    };
    let next_delta = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(200),
    };

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty = FastHashSet::default();

    initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    let clock = svm.get_sysvar::<Clock>();
    assert_eq!(clock.slot, 200);
    assert_eq!(clock.unix_timestamp, 200); // make_test_clock sets unix_timestamp = slot
}

#[test]
fn test_restore_selective_always_sets_clock() {
    // Even if clock was NOT dirty in the current iteration, restore_selective
    // unconditionally writes the delta's clock. This differs from restore()
    // which checks is_clock_dirty().
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Set SVM clock to something different
    svm.set_sysvar(&make_test_clock(999));
    assert_eq!(svm.get_sysvar::<Clock>().slot, 999);

    // Delta has clock at slot 42
    let delta = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(42),
    };

    let divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // restore_selective always sets clock, even with empty divergent
    initial.restore_selective(&mut svm, &divergent, &delta);

    assert_eq!(svm.get_sysvar::<Clock>().slot, 42);
}

// =========================================================================
// Fingerprint novelty — verifies the pool admission approach
// =========================================================================

#[test]
fn test_fingerprint_changes_with_different_states() {
    // Verify that compute_state_fingerprint_from_snapshot produces different
    // fingerprints for meaningfully different states (different magnitudes).
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_clock = make_test_clock(100);
    svm.set_sysvar(&initial_clock);

    // State A: 100 lamports
    svm.set_account(pk, make_account(100, &[0u8; 16])).unwrap();

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);

    let initial = SvmSnapshot::take(&svm, &{
        let mut s = HashSet::new();
        s.insert(pk);
        s
    });

    let fp_a = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial);

    // State B: 10000 lamports (different magnitude)
    svm.set_account(pk, make_account(10000, &[0u8; 16])).unwrap();
    let fp_b = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial);

    assert_ne!(fp_a, fp_b, "different lamport magnitudes should produce different fingerprints");

    // State C: same as A (150 lamports, same magnitude)
    svm.set_account(pk, make_account(150, &[0u8; 16])).unwrap();
    let fp_c = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial);

    // fp_a and fp_c might collide (same bucket) — that's expected by design.
    // Just verify fp_b is different from fp_c.
    assert_ne!(fp_b, fp_c, "different magnitudes should differ");
}

// =========================================================================
// check_field_novelty — per-field diff-based novelty detection
// =========================================================================

#[test]
fn test_field_novelty_first_change_is_novel() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 32];
    svm.set_account(pk, make_account(1000, &initial_data)).unwrap();

    // Take initial snapshot
    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Modify one field (bytes 8-15)
    let mut new_data = initial_data.clone();
    new_data[8..16].copy_from_slice(&500u64.to_le_bytes());
    svm.set_account(pk, make_account(1000, &new_data)).unwrap();

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);

    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];
    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };

    // Should detect novelty: changed field at offset 8 + lamports check
    assert!(novel >= 1, "first field change should be novel, got {}", novel);
}

#[test]
fn test_field_novelty_same_bucket_not_novel() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 32];
    svm.set_account(pk, make_account(1000, &initial_data)).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // First: set field to 100
    let mut data1 = initial_data.clone();
    data1[8..16].copy_from_slice(&100u64.to_le_bytes());
    svm.set_account(pk, make_account(1000, &data1)).unwrap();
    let novel1 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel1 >= 1);

    // Second: set field to 150 (same bucket as 100 — both bucket 5)
    let mut data2 = initial_data.clone();
    data2[8..16].copy_from_slice(&150u64.to_le_bytes());
    svm.set_account(pk, make_account(1000, &data2)).unwrap();
    let novel2 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    // Same magnitude bucket → should NOT be novel (lamports also unchanged)
    assert_eq!(novel2, 0, "same bucket should not be novel");
}

#[test]
fn test_field_novelty_different_bucket_is_novel() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 32];
    svm.set_account(pk, make_account(1000, &initial_data)).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // First: set field to 100 (bucket 5: 100-999)
    let mut data1 = initial_data.clone();
    data1[8..16].copy_from_slice(&100u64.to_le_bytes());
    svm.set_account(pk, make_account(1000, &data1)).unwrap();
    let novel1 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel1 >= 1);

    // Second: set field to 5000 (bucket 6: 1000-9999) — different bucket
    let mut data2 = initial_data.clone();
    data2[8..16].copy_from_slice(&5000u64.to_le_bytes());
    svm.set_account(pk, make_account(1000, &data2)).unwrap();
    let novel2 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    // Different magnitude → at least the field should be novel
    assert!(novel2 >= 1, "different bucket should be novel, got {}", novel2);
}

#[test]
fn test_field_novelty_lamports_change() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(1000, &[0u8; 16])).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // Change lamports to different magnitude (1000 → 1_000_000)
    svm.set_account(pk, make_account(1_000_000, &[0u8; 16])).unwrap();
    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    // Lamports changed bucket → novel
    assert!(novel >= 1, "lamports change should be novel, got {}", novel);
}

#[test]
fn test_field_novelty_multiple_regions() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 64];
    svm.set_account(pk, make_account(1000, &initial_data)).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // Change two separate regions (two fields)
    let mut new_data = initial_data.clone();
    new_data[0..8].copy_from_slice(&42u64.to_le_bytes()); // field at offset 0
    new_data[32..40].copy_from_slice(&999u64.to_le_bytes()); // field at offset 32
    svm.set_account(pk, make_account(1000, &new_data)).unwrap();

    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    // 2 changed regions + lamports (same bucket) = at least 2 novel field bits
    assert!(novel >= 2, "two changed regions should produce at least 2 novel bits, got {}", novel);
}

#[test]
fn test_field_novelty_no_change_not_novel() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(1000, &[1, 2, 3, 4, 5, 6, 7, 8])).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // First check with same data (no actual changes) → novel due to first-time lamports bit
    let novel1 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };

    // Second check with same data → not novel (all bits already set)
    let novel2 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert_eq!(novel2, 0, "unchanged state should not be novel on second check");
}

#[test]
fn test_field_novelty_new_account() {
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    // pk not in initial snapshot
    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(0),
    };

    // Create account after initial
    svm.set_account(pk, make_account(5000, &[10, 20, 30, 40])).unwrap();

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    // New account: lamports + all bytes differ from empty initial → novel
    assert!(novel >= 1, "new account should be novel, got {}", novel);
}

#[test]
fn test_fingerprint_new_accounts_different_data() {
    // Regression test for Bug 1: two new accounts (not in initial) with same
    // lamports/length but different data must produce different fingerprints.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    // Empty initial — pk not present
    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(0),
    };

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);

    // State A: account with data [10, 20, 30, 40, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    let mut data_a = vec![0u8; 16];
    data_a[0..4].copy_from_slice(&[10, 20, 30, 40]);
    data_a[8..16].copy_from_slice(&1u64.to_le_bytes());
    svm.set_account(pk, make_account(5000, &data_a)).unwrap();
    let fp_a = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial);

    // State B: same lamports/length, different data
    let mut data_b = vec![0u8; 16];
    data_b[0..4].copy_from_slice(&[10, 20, 30, 40]);
    data_b[8..16].copy_from_slice(&999_999u64.to_le_bytes());
    svm.set_account(pk, make_account(5000, &data_b)).unwrap();
    let fp_b = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial);

    assert_ne!(fp_a, fp_b,
        "new accounts with same lamports/length but different data should have different fingerprints");
}

#[test]
fn test_field_novelty_new_accounts_different_data() {
    // Regression test for Bug 1 in check_field_novelty: two new accounts with
    // different non-zero data should produce different novelty contributions.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: make_test_sysvars(0),
    };

    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&pk);

    // State A
    let mut data_a = vec![0u8; 16];
    data_a[8..16].copy_from_slice(&1u64.to_le_bytes());
    svm.set_account(pk, make_account(5000, &data_a)).unwrap();
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];
    let novel_a = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel_a >= 2, "new account should have novel lamports + data fields, got {}", novel_a);

    // State B: different data magnitude in same field
    let mut data_b = vec![0u8; 16];
    data_b[8..16].copy_from_slice(&999_999u64.to_le_bytes());
    svm.set_account(pk, make_account(5000, &data_b)).unwrap();
    let novel_b = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel_b >= 1, "new account with different data magnitude should be novel, got {}", novel_b);
}

// =========================================================================
// Clock novelty — clock-only actions produce novelty bits
// =========================================================================

#[test]
fn test_field_novelty_clock_change_is_novel() {
    // Clock-only actions (e.g. advance_slots) must produce novelty even with
    // no dirty accounts, so they get saved to the state pool.
    let mut svm = LiteSVM::new();
    let initial_clock = make_test_clock(100);
    svm.set_sysvar(&initial_clock);

    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&initial_clock),
    };

    // Advance clock by 1000 slots (no account changes)
    let mut new_clock = make_test_clock(1100);
    new_clock.epoch = 0;
    svm.set_sysvar(&new_clock);

    let tracker = DirtyTracker::new(); // empty — no dirty accounts
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];
    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };

    assert!(novel >= 1, "clock-only change should produce novelty, got {}", novel);
}

#[test]
fn test_field_novelty_clock_epoch_change_is_novel() {
    // Different epochs should produce different novelty bits.
    let mut svm = LiteSVM::new();
    let initial_clock = make_test_clock(100);
    svm.set_sysvar(&initial_clock);

    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&initial_clock),
    };

    let tracker = DirtyTracker::new();
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];

    // Epoch 1
    let mut clock1 = make_test_clock(500);
    clock1.epoch = 1;
    svm.set_sysvar(&clock1);
    let novel1 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel1 >= 1, "epoch change should be novel, got {}", novel1);

    // Epoch 2 (different epoch bucket)
    let mut clock2 = make_test_clock(900);
    clock2.epoch = 2;
    svm.set_sysvar(&clock2);
    let novel2 = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };
    assert!(novel2 >= 1, "different epoch should be novel, got {}", novel2);
}

#[test]
fn test_field_novelty_same_clock_not_novel() {
    // If clock hasn't changed from initial, no clock novelty should be produced.
    let mut svm = LiteSVM::new();
    let initial_clock = make_test_clock(100);
    svm.set_sysvar(&initial_clock);

    let initial = SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&initial_clock),
    };

    let tracker = DirtyTracker::new();
    let mut bitmap = vec![0u8; FIELD_NOVELTY_BITMAP_SIZE];
    let novel = unsafe { check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len()) };

    assert_eq!(novel, 0, "unchanged clock should produce zero novelty, got {}", novel);
}
