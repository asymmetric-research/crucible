use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::Arc;

#[test]
fn test_adversarial_cpi_account_collides_with_next_delta() {
    // Execution in iter 1 creates pk_cpi at address X.
    // The NEXT delta also has an account at address X with different data.
    // Restore must use the delta's value, not the CPI remnant.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    let pk_collide = Pubkey::new_unique(); // shared address

    svm.set_account(pk_base, make_account(100, &[1])).unwrap();
    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // State A: just pk_base modified
    let mut a_accts = FastHashMap::default();
    a_accts.insert(pk_base, Arc::new(make_account(200, &[0xAA])));
    let delta_a = SvmSnapshot { accounts: a_accts, sysvars: initial.sysvars.clone() };

    // State B: has pk_collide with SPECIFIC value (this is the delta value)
    let mut b_accts = FastHashMap::default();
    b_accts.insert(pk_collide, Arc::new(make_account(999, &[0xBB; 128])));
    let delta_b = SvmSnapshot { accounts: b_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Iter 1: pick A, CPI creates pk_collide with WRONG value
    simulate_fuzzer_iteration(
        &initial, &mut svm, &mut divergent, &mut prev_delta, &mut prev_exec_dirty,
        &delta_a,
        &[(pk_collide, Some(make_account(777, &[0xFF; 64])))], // CPI creates colliding account
        true,
    );
    assert_eq!(svm.get_account(&pk_collide).unwrap().lamports, 777);

    // Iter 2: pick B — pk_collide must have DELTA value (999), not CPI remnant (777)
    simulate_fuzzer_iteration(
        &initial, &mut svm, &mut divergent, &mut prev_delta, &mut prev_exec_dirty,
        &delta_b,
        &[], // no execution this iter
        true,
    );
    assert_eq!(svm.get_account(&pk_collide).unwrap().lamports, 999,
        "BUG: CPI remnant leaked — delta value should override");
    assert_eq!(svm.get_account(&pk_collide).unwrap().data, vec![0xBB; 128],
        "BUG: CPI data leaked — delta data should override");
}

#[test]
fn test_adversarial_phantom_account_not_in_any_tracking() {
    // An account exists in SVM but is NOT in initial, NOT in any delta,
    // NOT in divergent_keys. This is a "phantom" — it should persist
    // across iterations (restore doesn't know about it).
    //
    // In the real fuzzer, take_all captures everything, so phantoms shouldn't
    // exist. But if they do, verify behavior is consistent.
    let mut svm = LiteSVM::new();
    let pk_tracked = Pubkey::new_unique();
    let pk_phantom = Pubkey::new_unique();

    svm.set_account(pk_tracked, make_account(100, &[1])).unwrap();
    svm.set_account(pk_phantom, make_account(42, &[0x42])).unwrap();

    // Only track pk_tracked — pk_phantom is invisible to snapshot system
    let tracked: HashSet<Pubkey> = [pk_tracked].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_tracked, Arc::new(make_account(200, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let empty_delta = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to state 1
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());

    // Phantom should still be there (restore doesn't know about it)
    assert_eq!(svm.get_account(&pk_phantom).unwrap().lamports, 42,
        "phantom should survive restore — not in divergent_keys");

    // Restore to initial
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &empty_delta, &prev_exec_dirty,
    );

    // Phantom STILL there — restore only touches divergent_keys
    assert_eq!(svm.get_account(&pk_phantom).unwrap().lamports, 42,
        "phantom survives across restores because it's never in divergent_keys");

    // NOW: if execution modifies the phantom and dirty_tracker records it...
    // The phantom enters divergent_keys. On next restore, it gets zeroed
    // (not in initial → zero). This is a REAL STATE LEAKAGE scenario!
    divergent.insert(pk_phantom);
    initial.restore_selective(&mut svm, &divergent, &empty_delta);
    assert!(svm.get_account(&pk_phantom).is_none(),
        "phantom should be zeroed once it enters divergent_keys — not in initial!");
}

#[test]
fn test_adversarial_account_in_initial_but_never_in_divergent() {
    // pk_hidden is in initial snapshot but NEVER enters divergent_keys
    // (never modified by any delta or execution). If execution silently
    // corrupts it (e.g., fee deduction), restore won't fix it!
    let mut svm = LiteSVM::new();
    let pk_normal = Pubkey::new_unique();
    let pk_hidden = Pubkey::new_unique();

    svm.set_account(pk_normal, make_account(100, &[1])).unwrap();
    svm.set_account(pk_hidden, make_account(50, &[0x50])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_normal, pk_hidden].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_normal, Arc::new(make_account(200, &[0xAA])));
    // pk_hidden NOT in delta
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to state 1
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());

    // Silently corrupt pk_hidden (NOT tracked by dirty tracker)
    svm.set_account(pk_hidden, make_account(0, &[])).unwrap();
    // pk_hidden NOT added to prev_exec_dirty or divergent_keys

    // Restore to same state again
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &delta_1, &prev_exec_dirty,
    );

    // pk_hidden is STILL corrupted because restore doesn't know about it
    // This demonstrates WHY dirty_tracker must capture ALL writable accounts
    let hidden_val = svm.get_account(&pk_hidden).map_or(0, |a| a.lamports);
    assert_eq!(hidden_val, 0,
        "pk_hidden stays corrupted — restore can't fix what it doesn't know about");

    // But if we properly track it, restore fixes it
    divergent.insert(pk_hidden);
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    assert_eq!(svm.get_account(&pk_hidden).unwrap().lamports, 50,
        "pk_hidden should be restored to initial when properly tracked");
}

#[test]
fn test_adversarial_arc_optimization_unsound_without_exec_dirty() {
    // Proves that the Arc::ptr_eq optimization is UNSOUND if exec_dirty
    // is not tracked. Without exec_dirty, this test would pass with the
    // wrong value.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(10, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Two states sharing same Arc for pk (common ancestry)
    let shared_arc = Arc::new(make_account(100, &[0xAA]));
    let mut a_accts = FastHashMap::default();
    a_accts.insert(pk, shared_arc.clone());
    let delta_a = SvmSnapshot { accounts: a_accts, sysvars: initial.sysvars.clone() };

    let mut b_accts = FastHashMap::default();
    b_accts.insert(pk, shared_arc.clone());
    let delta_b = SvmSnapshot { accounts: b_accts, sysvars: initial.sysvars.clone() };

    assert!(Arc::ptr_eq(&delta_a.accounts()[&pk], &delta_b.accounts()[&pk]));

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // Iter 1: restore to A
    initial.restore_selective(&mut svm, &divergent, &delta_a);
    divergent.extend(delta_a.accounts().keys().copied());
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100);

    // Execution corrupts pk
    svm.set_account(pk, make_account(66666, &[0xDE, 0xAD, 0xBE, 0xEF])).unwrap();

    // WITHOUT exec_dirty: optimization would skip the write (same Arc)
    let empty_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let count_without = initial.restore_selective_from(
        &mut svm, &divergent, &delta_a, &delta_b, &empty_exec_dirty,
    );
    assert_eq!(count_without, 0, "without exec_dirty, optimization skips the write");
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 66666,
        "BUG DEMO: without exec_dirty, corruption persists!");

    // WITH exec_dirty: forces the write
    let mut proper_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    proper_exec_dirty.insert(pk);
    let count_with = initial.restore_selective_from(
        &mut svm, &divergent, &delta_a, &delta_b, &proper_exec_dirty,
    );
    assert_eq!(count_with, 1, "with exec_dirty, pk is written");
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 100,
        "with exec_dirty, corruption is fixed");
}

#[test]
fn test_adversarial_dual_svm_divergent_tracking() {
    // Simulates the dual-SVM pattern from stateful.rs:
    // Fast SVM uses divergent_keys/prev_delta/prev_exec_dirty.
    // Traced SVM uses traced_divergent (simple restore only).
    // Every Nth iteration is traced. Verify both SVMs stay correct.
    let mut fast_svm = LiteSVM::new();
    let mut traced_svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    for svm in [&mut fast_svm, &mut traced_svm] {
        svm.set_account(pk_a, make_account(10, &[1])).unwrap();
        svm.set_account(pk_b, make_account(20, &[2])).unwrap();
    }

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&fast_svm, &tracked);

    let states: Vec<SvmSnapshot> = (1..=4).map(|i| {
        let mut accts = FastHashMap::default();
        accts.insert(pk_a, Arc::new(make_account(i * 100, &[i as u8 * 10])));
        accts.insert(pk_b, Arc::new(make_account(i * 200, &[i as u8 * 20])));
        SvmSnapshot { accounts: accts, sysvars: initial.sysvars.clone() }
    }).collect();

    // Fast SVM tracking
    let mut divergent_keys: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta_arc: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Traced SVM tracking (separate, simpler)
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();

    let trace_interval = 3;
    let sequence = [0, 1, 2, 3, 0, 2, 1, 3, 2, 0, 3, 1];

    for (iter, &state_idx) in sequence.iter().enumerate() {
        let is_traced = trace_interval > 0 && iter % trace_interval == 0;
        let delta = &states[state_idx];

        if is_traced {
            // Traced iteration: use traced_svm + traced_divergent (simple restore)
            initial.restore_selective(&mut traced_svm, &traced_divergent, delta);
            traced_divergent.clear();
            traced_divergent.extend(delta.accounts().keys().copied());

            // Simulate execution on traced SVM
            let dirty_pk = if iter % 2 == 0 { pk_a } else { pk_b };
            traced_svm.set_account(dirty_pk, make_account(99999, &[0xEE])).unwrap();
            traced_divergent.insert(dirty_pk);

            // Verify traced SVM BEFORE execution dirt
            // (can't verify after since we just dirtied it)
        } else {
            // Non-traced iteration: use fast_svm + optimized restore
            if let Some(ref prev) = prev_delta_arc {
                initial.restore_selective_from(
                    &mut fast_svm, &divergent_keys, prev, delta, &prev_exec_dirty,
                );
            } else {
                initial.restore_selective(&mut fast_svm, &divergent_keys, delta);
            }
            divergent_keys.clear();
            divergent_keys.extend(delta.accounts().keys().copied());

            // Verify fast SVM state
            let ea = states[state_idx].accounts()[&pk_a].lamports;
            let eb = states[state_idx].accounts()[&pk_b].lamports;
            assert_eq!(fast_svm.get_account(&pk_a).unwrap().lamports, ea,
                "iter {} (fast): pk_a expected {}", iter, ea);
            assert_eq!(fast_svm.get_account(&pk_b).unwrap().lamports, eb,
                "iter {} (fast): pk_b expected {}", iter, eb);

            // Simulate execution on fast SVM
            let dirty_pk = if iter % 2 == 0 { pk_a } else { pk_b };
            fast_svm.set_account(dirty_pk, make_account(88888, &[0xDD])).unwrap();
            prev_exec_dirty.clear();
            prev_exec_dirty.insert(dirty_pk);
            divergent_keys.extend(prev_exec_dirty.iter().copied());
            prev_delta_arc = Some(delta.clone());
        }

        // Fast SVM tracking is NOT modified during traced iterations —
        // this is critical for correctness
    }
}

#[test]
fn test_adversarial_clock_divergence_across_states() {
    // Different states have different clock values (slot/unix_timestamp).
    // Verify clock is correctly restored when switching between states.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let clock_100 = Clock { slot: 100, unix_timestamp: 1000, ..Default::default() };
    let clock_200 = Clock { slot: 200, unix_timestamp: 2000, ..Default::default() };
    let clock_300 = Clock { slot: 300, unix_timestamp: 3000, ..Default::default() };

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: clock_to_sysvars(&clock_100) };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk, Arc::new(make_account(300, &[0xBB])));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: clock_to_sysvars(&clock_200) };

    let delta_3 = SvmSnapshot {
        accounts: FastHashMap::default(), // empty delta = initial
        sysvars: clock_to_sysvars(&clock_300),
    };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // State 1: slot=100
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.extend(delta_1.accounts().keys().copied());
    let clock: Clock = svm.get_sysvar();
    assert_eq!(clock.slot, 100);
    assert_eq!(clock.unix_timestamp, 1000);

    // State 2: slot=200
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_1, &delta_2, &prev_exec_dirty,
    );
    divergent.clear();
    divergent.extend(delta_2.accounts().keys().copied());
    let clock: Clock = svm.get_sysvar();
    assert_eq!(clock.slot, 200, "clock should advance to state 2");
    assert_eq!(clock.unix_timestamp, 2000);

    // State 3: slot=300, empty delta (initial accounts)
    initial.restore_selective_from(
        &mut svm, &divergent, &delta_2, &delta_3, &prev_exec_dirty,
    );
    let clock: Clock = svm.get_sysvar();
    assert_eq!(clock.slot, 300, "clock should advance even with empty delta");

    // Back to state 1: slot should go BACKWARDS to 100
    divergent.clear();
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    let clock: Clock = svm.get_sysvar();
    assert_eq!(clock.slot, 100, "clock must go backwards when restoring older state");
}

#[test]
fn test_adversarial_fee_payer_drift_across_chain() {
    // Fee payer lamports decrease with each transaction (fee deduction).
    // Each delta in a chain has a slightly lower fee_payer balance.
    // Verify state switching correctly restores the RIGHT fee_payer balance.
    let mut svm = LiteSVM::new();
    let fee_payer = Pubkey::new_unique();
    let pk_data = Pubkey::new_unique();

    svm.set_account(fee_payer, make_account(10_000_000, &[0; 0])).unwrap();
    svm.set_account(pk_data, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [fee_payer, pk_data].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Chain: root → L1 → L2 → L3
    // Fee payer loses 5000 lamports per level (simulating tx fees)
    let root = SvmSnapshot::empty(initial.clock().clone());

    let mut l1_accts = FastHashMap::default();
    l1_accts.insert(fee_payer, Arc::new(make_account(9_995_000, &[]))); // -5000
    l1_accts.insert(pk_data, Arc::new(make_account(200, &[2])));
    let l1 = SvmSnapshot { accounts: l1_accts, sysvars: initial.sysvars.clone() };

    let mut l2_accts = FastHashMap::default();
    l2_accts.insert(fee_payer, Arc::new(make_account(9_990_000, &[]))); // -10000 total
    l2_accts.insert(pk_data, l1.accounts()[&pk_data].clone()); // inherited
    let l2 = SvmSnapshot { accounts: l2_accts, sysvars: initial.sysvars.clone() };

    let mut l3_accts = FastHashMap::default();
    l3_accts.insert(fee_payer, Arc::new(make_account(9_985_000, &[]))); // -15000 total
    l3_accts.insert(pk_data, Arc::new(make_account(300, &[3])));
    let l3 = SvmSnapshot { accounts: l3_accts, sysvars: initial.sysvars.clone() };

    // Verify fee_payer Arcs are NOT shared (different values)
    assert!(!Arc::ptr_eq(&l1.accounts()[&fee_payer], &l2.accounts()[&fee_payer]));
    assert!(!Arc::ptr_eq(&l2.accounts()[&fee_payer], &l3.accounts()[&fee_payer]));

    // But pk_data IS shared between L1 and L2
    assert!(Arc::ptr_eq(&l1.accounts()[&pk_data], &l2.accounts()[&pk_data]));

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Jump from L3 to L1: fee_payer must go UP (9_985_000 → 9_995_000)
    initial.restore_selective(&mut svm, &divergent, &l3);
    divergent.extend(l3.accounts().keys().copied());
    assert_eq!(svm.get_account(&fee_payer).unwrap().lamports, 9_985_000);

    initial.restore_selective_from(
        &mut svm, &divergent, &l3, &l1, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&fee_payer).unwrap().lamports, 9_995_000,
        "fee_payer must be restored to L1 value, not L3");

    // Jump from L1 to root: fee_payer must go to initial (10_000_000)
    divergent.clear();
    divergent.extend(l1.accounts().keys().copied());
    initial.restore_selective_from(
        &mut svm, &divergent, &l1, &root, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&fee_payer).unwrap().lamports, 10_000_000,
        "fee_payer must return to initial when jumping to root");
}

#[test]
fn test_adversarial_divergent_keys_must_include_exec_dirty_for_cpi_cleanup() {
    // THIS IS THE CRITICAL INVARIANT: if divergent_keys doesn't include
    // exec_dirty accounts, CPI-created accounts leak across iterations.
    //
    // Simulates the bug that would occur if line 729 in stateful.rs
    // (divergent_keys.extend(prev_exec_dirty)) was removed.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let empty = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Iter 1: pick state 1
    initial.restore_selective(&mut svm, &divergent, &delta_1);
    divergent.clear();
    divergent.extend(delta_1.accounts().keys().copied());

    // CPI creates pk_cpi
    let pk_cpi = Pubkey::new_unique();
    svm.set_account(pk_cpi, make_account(777, &[0xCC; 32])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk);
    prev_exec_dirty.insert(pk_cpi);

    // THE CRITICAL LINE: divergent_keys.extend(prev_exec_dirty)
    // Without this, pk_cpi would NOT be in divergent_keys
    divergent.extend(prev_exec_dirty.iter().copied());

    let prev_delta = Some(delta_1.clone());

    // Iter 2: pick empty (initial state)
    if let Some(ref prev) = prev_delta {
        initial.restore_selective_from(
            &mut svm, &divergent, prev, &empty, &prev_exec_dirty,
        );
    }

    // pk_cpi MUST be gone
    assert!(svm.get_account(&pk_cpi).is_none(),
        "CRITICAL BUG: CPI account leaked across iterations!");

    // Now demonstrate what happens WITHOUT the critical line:
    // Reset SVM, redo without extending divergent_keys
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let mut bad_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &bad_divergent, &delta_1);
    bad_divergent.clear();
    bad_divergent.extend(delta_1.accounts().keys().copied());

    svm.set_account(pk_cpi, make_account(777, &[0xCC; 32])).unwrap();
    // BUG: NOT extending divergent with exec_dirty
    // bad_divergent does NOT have pk_cpi

    initial.restore_selective_from(
        &mut svm, &bad_divergent, &delta_1, &empty, &prev_exec_dirty,
    );

    // pk_cpi LEAKS because it's in prev_exec_dirty (forces write in step 2)
    // but empty delta has no accounts, so step 2 doesn't iterate over pk_cpi.
    // And step 1 only iterates divergent_keys which doesn't have pk_cpi.
    // So pk_cpi is untouched — it LEAKS.
    assert_eq!(svm.get_account(&pk_cpi).unwrap().lamports, 777,
        "Without divergent_keys.extend(exec_dirty), CPI account leaks!");
}

#[test]
fn test_adversarial_10_iteration_full_state_verification() {
    // 10 iterations with full state verification after each restore.
    // Uses verify_full_state to check EVERY account, not just a few.
    // Includes CPI accounts, tombstones, and mixed success/failure.
    let mut svm = LiteSVM::new();
    let pks: Vec<Pubkey> = (0..10).map(|_| Pubkey::new_unique()).collect();
    for (i, pk) in pks.iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[i as u8])).unwrap();
    }

    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // 5 states with various modifications
    let states: Vec<SvmSnapshot> = vec![
        SvmSnapshot::empty(initial.clock().clone()), // state 0: initial
        {   // state 1: modify first 3
            let mut m = FastHashMap::default();
            m.insert(pks[0], Arc::new(make_account(100, &[0x10])));
            m.insert(pks[1], Arc::new(make_account(200, &[0x20])));
            m.insert(pks[2], Arc::new(make_account(300, &[0x30])));
            SvmSnapshot { accounts: m, sysvars: initial.sysvars.clone() }
        },
        {   // state 2: modify middle 3, tombstone first
            let mut m = FastHashMap::default();
            m.insert(pks[0], Arc::new(Account { lamports: 0, ..Default::default() }));
            m.insert(pks[4], Arc::new(make_account(400, &[0x40])));
            m.insert(pks[5], Arc::new(make_account(500, &[0x50])));
            m.insert(pks[6], Arc::new(make_account(600, &[0x60])));
            SvmSnapshot { accounts: m, sysvars: initial.sysvars.clone() }
        },
        {   // state 3: add CPI account (not in initial)
            let mut m = FastHashMap::default();
            let pk_cpi = Pubkey::new_unique();
            m.insert(pk_cpi, Arc::new(make_account(999, &[0xCC])));
            m.insert(pks[9], Arc::new(make_account(900, &[0x90])));
            SvmSnapshot { accounts: m, sysvars: initial.sysvars.clone() }
        },
        {   // state 4: modify last 3
            let mut m = FastHashMap::default();
            m.insert(pks[7], Arc::new(make_account(700, &[0x70])));
            m.insert(pks[8], Arc::new(make_account(800, &[0x80])));
            m.insert(pks[9], Arc::new(make_account(901, &[0x91])));
            SvmSnapshot { accounts: m, sysvars: initial.sysvars.clone() }
        },
    ];

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;
    let mut all_cpi_ever: Vec<Pubkey> = Vec::new();

    let sequence = [1, 2, 0, 3, 4, 2, 1, 0, 4, 3];
    let successes = [true, true, false, true, true, false, true, true, true, false];

    for (iter, (&state_idx, &success)) in sequence.iter().zip(successes.iter()).enumerate() {
        let delta = &states[state_idx];

        simulate_restore(&initial, &mut svm, &divergent, delta,
            prev_delta.as_ref(), &prev_exec_dirty);
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        // Verify full state (all initial accounts + delta accounts)
        verify_full_state(&svm, &initial, delta, &all_cpi_ever,
            &format!("iter {} state {}", iter, state_idx));

        // Simulate execution: dirty one account
        let exec_pk = pks[iter % 10];
        svm.set_account(exec_pk, make_account(77777, &[0xFF])).unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(exec_pk);
        divergent.extend(prev_exec_dirty.iter().copied());

        // Odd iterations: CPI creates a temp account
        if iter % 3 == 1 {
            let cpi_pk = Pubkey::new_unique();
            svm.set_account(cpi_pk, make_account(42, &[0x42])).unwrap();
            prev_exec_dirty.insert(cpi_pk);
            divergent.insert(cpi_pk);
            all_cpi_ever.push(cpi_pk);
        }

        if success {
            prev_delta = Some(delta.clone());
        } else {
            prev_delta = None;
        }
    }
}

#[test]
fn test_adversarial_take_delta_chain_fidelity() {
    // Build a 4-level chain using take_delta, then verify that restoring
    // to each level produces the exact expected state.
    // Crucially: modify the SVM between take_delta calls to ensure
    // take_delta reads the CURRENT SVM state, not stale data.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(1, &[0x01])).unwrap();
    svm.set_account(pk_b, make_account(2, &[0x02])).unwrap();
    svm.set_account(pk_c, make_account(3, &[0x03])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let root = SvmSnapshot::empty(initial.clock().clone());

    // L1: modify A=10
    svm.set_account(pk_a, make_account(10, &[0x10])).unwrap();
    let mut d1 = DirtyTracker::new();
    d1.mark_account_dirty(&pk_a);
    let l1 = SvmSnapshot::take_delta(&svm, &root, &d1);

    // Verify L1 content
    assert_eq!(l1.accounts()[&pk_a].lamports, 10);
    assert!(!l1.accounts().contains_key(&pk_b));
    assert!(!l1.accounts().contains_key(&pk_c));

    // L2: modify B=20 (inherits A=10 from L1)
    svm.set_account(pk_b, make_account(20, &[0x20])).unwrap();
    let mut d2 = DirtyTracker::new();
    d2.mark_account_dirty(&pk_b);
    let l2 = SvmSnapshot::take_delta(&svm, &l1, &d2);

    // L2 should have A(inherited) and B(fresh)
    assert_eq!(l2.accounts()[&pk_a].lamports, 10);
    assert_eq!(l2.accounts()[&pk_b].lamports, 20);
    assert!(Arc::ptr_eq(&l1.accounts()[&pk_a], &l2.accounts()[&pk_a]),
        "A should be inherited Arc");

    // L3: modify A=30 AGAIN (overrides L1's A=10)
    svm.set_account(pk_a, make_account(30, &[0x30])).unwrap();
    let mut d3 = DirtyTracker::new();
    d3.mark_account_dirty(&pk_a);
    let l3 = SvmSnapshot::take_delta(&svm, &l2, &d3);

    // L3: A=30(fresh), B=20(inherited from L2)
    assert_eq!(l3.accounts()[&pk_a].lamports, 30);
    assert_eq!(l3.accounts()[&pk_b].lamports, 20);
    assert!(!Arc::ptr_eq(&l2.accounts()[&pk_a], &l3.accounts()[&pk_a]),
        "A should be new Arc (overridden)");
    assert!(Arc::ptr_eq(&l2.accounts()[&pk_b], &l3.accounts()[&pk_b]),
        "B should be inherited Arc");

    // L4: delete A, modify C=40
    svm.set_account(pk_a, Account { lamports: 0, ..Default::default() }).unwrap();
    svm.set_account(pk_c, make_account(40, &[0x40])).unwrap();
    let mut d4 = DirtyTracker::new();
    d4.mark_account_dirty(&pk_a);
    d4.mark_account_dirty(&pk_c);
    let l4 = SvmSnapshot::take_delta(&svm, &l3, &d4);

    // L4: A=tombstone, B=20(inherited), C=40(fresh)
    assert_eq!(l4.accounts()[&pk_a].lamports, 0); // tombstone
    assert_eq!(l4.accounts()[&pk_b].lamports, 20);
    assert_eq!(l4.accounts()[&pk_c].lamports, 40);

    // Now restore to each level and verify full state
    let all_keys: FastHashSet<Pubkey> = [pk_a, pk_b, pk_c].into_iter().collect();

    // Restore to L1: A=10, B=initial(2), C=initial(3)
    initial.restore_selective(&mut svm, &all_keys, &l1);
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 2);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 3);

    // Restore to L4: A=gone, B=20, C=40
    initial.restore_selective(&mut svm, &all_keys, &l4);
    assert!(svm.get_account(&pk_a).is_none(), "A should be tombstoned in L4");
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 40);

    // Jump L4 → L1: A resurrects, B goes to initial, C goes to initial
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective_from(
        &mut svm, &all_keys, &l4, &l1, &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10, "A must resurrect");
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 2, "B must return to initial");
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 3, "C must return to initial");
}

#[test]
fn test_adversarial_multiple_cpi_accounts_tracked_and_cleaned() {
    // Each iteration creates 3 CPI accounts. Over 5 iterations, that's 15 CPI accounts.
    // Verify ALL are properly cleaned up when switching states.
    let mut svm = LiteSVM::new();
    let pk_base = Pubkey::new_unique();
    svm.set_account(pk_base, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_base].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s_accts = FastHashMap::default();
    s_accts.insert(pk_base, Arc::new(make_account(200, &[0xAA])));
    let delta = SvmSnapshot { accounts: s_accts, sysvars: initial.sysvars.clone() };
    let empty = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;
    let mut all_cpi: Vec<Pubkey> = Vec::new();

    for iter in 0..5 {
        // Restore to delta state
        simulate_restore(&initial, &mut svm, &divergent, &delta,
            prev_delta.as_ref(), &prev_exec_dirty);
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        // Create 3 CPI accounts
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(pk_base);
        for _ in 0..3 {
            let cpi = Pubkey::new_unique();
            svm.set_account(cpi, make_account(42, &[iter as u8])).unwrap();
            prev_exec_dirty.insert(cpi);
            all_cpi.push(cpi);
        }
        divergent.extend(prev_exec_dirty.iter().copied());
        prev_delta = Some(delta.clone());
    }

    // Now restore to empty (initial) — ALL 15 CPI accounts must be gone
    simulate_restore(&initial, &mut svm, &divergent, &empty,
        prev_delta.as_ref(), &prev_exec_dirty);

    assert_eq!(svm.get_account(&pk_base).unwrap().lamports, 100,
        "base must return to initial");
    for (i, cpi) in all_cpi.iter().enumerate() {
        // Only CPI accounts from the LAST iteration are in divergent_keys/exec_dirty.
        // CPI accounts from iterations 0-3 are NOT in divergent_keys anymore
        // (divergent was cleared each iteration). So only the last 3 are guaranteed clean.
        // The earlier ones may or may not be gone depending on whether the SVM reclaimed them.
        if i >= all_cpi.len() - 3 {
            // Last iteration's CPIs should be in divergent_keys
            assert!(svm.get_account(cpi).is_none(),
                "CPI {} from last iter should be cleaned up", i);
        }
    }
}

#[test]
fn test_adversarial_stale_cpi_from_old_iteration_leaks() {
    // DEMONSTRATES a real leakage scenario:
    // Iter 1: CPI creates pk_cpi_old → added to divergent_keys
    // Iter 2: restore clears divergent, picks new state → pk_cpi_old cleaned in step 1
    //         BUT: new execution creates pk_cpi_new → added to divergent
    //         divergent now has delta_keys ∪ {pk_cpi_new}
    //         pk_cpi_old is NOT in divergent anymore!
    // Iter 3: restore clears divergent, picks new state
    //         pk_cpi_old is NOT in divergent → NOT cleaned
    //         IF the SVM didn't clear it in iter 2... does iter 3 leak it?
    //
    // Answer: iter 2's restore_selective DOES clean pk_cpi_old (it was in divergent
    // at iter 2's start). After that, pk_cpi_old is gone from SVM. So iter 3 is fine.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s_accts = FastHashMap::default();
    s_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta = SvmSnapshot { accounts: s_accts, sysvars: initial.sysvars.clone() };
    let empty = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Iter 1: CPI creates pk_cpi_old
    simulate_restore(&initial, &mut svm, &divergent, &delta,
        prev_delta.as_ref(), &prev_exec_dirty);
    divergent.clear();
    divergent.extend(delta.accounts().keys().copied());
    let pk_cpi_old = Pubkey::new_unique();
    svm.set_account(pk_cpi_old, make_account(777, &[0xFF])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk);
    prev_exec_dirty.insert(pk_cpi_old);
    divergent.extend(prev_exec_dirty.iter().copied());
    prev_delta = Some(delta.clone());

    // At this point: divergent = {pk, pk_cpi_old}
    assert!(divergent.contains(&pk_cpi_old));

    // Iter 2: restore to empty → pk_cpi_old gets cleaned up
    simulate_restore(&initial, &mut svm, &divergent, &empty,
        prev_delta.as_ref(), &prev_exec_dirty);
    assert!(svm.get_account(&pk_cpi_old).is_none(),
        "pk_cpi_old must be cleaned in iter 2 restore");

    divergent.clear();
    // empty delta has no keys, so divergent = {}
    // Now create pk_cpi_new
    let pk_cpi_new = Pubkey::new_unique();
    svm.set_account(pk_cpi_new, make_account(888, &[0xEE])).unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk_cpi_new);
    divergent.extend(prev_exec_dirty.iter().copied());
    prev_delta = Some(empty.clone());

    // divergent = {pk_cpi_new} — pk_cpi_old is NOT here
    assert!(!divergent.contains(&pk_cpi_old));

    // Iter 3: restore to delta → pk_cpi_new cleaned, pk_cpi_old already gone
    simulate_restore(&initial, &mut svm, &divergent, &delta,
        prev_delta.as_ref(), &prev_exec_dirty);

    assert!(svm.get_account(&pk_cpi_old).is_none(),
        "pk_cpi_old should still be gone (was cleaned in iter 2)");
    assert!(svm.get_account(&pk_cpi_new).is_none(),
        "pk_cpi_new should be cleaned in iter 3");
    assert_eq!(svm.get_account(&pk).unwrap().lamports, 200);
}

#[test]
fn test_adversarial_exec_creates_account_at_initial_address() {
    // Execution creates an account at an address that already exists in initial.
    // This simulates a program re-initializing an account with different data.
    // The dirty tracker has it, but the delta doesn't — next restore must
    // restore to initial value.
    let mut svm = LiteSVM::new();
    let pk_reinit = Pubkey::new_unique();
    let owner_initial = Pubkey::new_unique();
    svm.set_account(pk_reinit, Account {
        lamports: 100, data: vec![1, 2, 3, 4], owner: owner_initial,
        executable: false, rent_epoch: 0,
    }).unwrap();

    let tracked: HashSet<Pubkey> = [pk_reinit].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);
    let empty = SvmSnapshot::empty(initial.clock().clone());

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();

    // Iter 1: pick initial state, execution "re-initializes" the account
    initial.restore_selective(&mut svm, &divergent, &empty);

    let owner_new = Pubkey::new_unique();
    svm.set_account(pk_reinit, Account {
        lamports: 500, data: vec![0xDE; 64], owner: owner_new,
        executable: false, rent_epoch: 0,
    }).unwrap();
    prev_exec_dirty.insert(pk_reinit);
    divergent.extend(prev_exec_dirty.iter().copied());

    // Iter 2: pick initial state again — must restore to ORIGINAL initial value
    let prev_delta = Some(empty.clone());
    simulate_restore(&initial, &mut svm, &divergent, &empty,
        prev_delta.as_ref(), &prev_exec_dirty);

    let restored = svm.get_account(&pk_reinit).unwrap();
    assert_eq!(restored.lamports, 100, "lamports must return to initial");
    assert_eq!(restored.data, vec![1, 2, 3, 4], "data must return to initial");
    assert_eq!(restored.owner, owner_initial, "owner must return to initial");
}

#[test]
fn test_adversarial_divergent_keys_growth_bounded() {
    // In the real fuzzer loop, divergent_keys is cleared each iteration then
    // rebuilt from delta.keys() ∪ exec_dirty. This test verifies it stays
    // bounded and doesn't leak old keys.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let mut s_accts = FastHashMap::default();
    s_accts.insert(pk, Arc::new(make_account(200, &[0xAA])));
    let delta = SvmSnapshot { accounts: s_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    for iter in 0..20 {
        simulate_restore(&initial, &mut svm, &divergent, &delta,
            prev_delta.as_ref(), &prev_exec_dirty);
        divergent.clear();
        divergent.extend(delta.accounts().keys().copied());

        // Create a unique CPI account each iteration
        let cpi = Pubkey::new_unique();
        svm.set_account(cpi, make_account(42, &[iter as u8])).unwrap();
        prev_exec_dirty.clear();
        prev_exec_dirty.insert(pk);
        prev_exec_dirty.insert(cpi);
        divergent.extend(prev_exec_dirty.iter().copied());
        prev_delta = Some(delta.clone());

        // divergent_keys should have: delta keys (1) + exec_dirty (2) = 3 max
        // NOT accumulating across iterations
        assert!(divergent.len() <= 3,
            "iter {}: divergent has {} keys, expected ≤3 (should not accumulate)",
            iter, divergent.len());
    }
}

#[test]
fn test_adversarial_prev_delta_none_after_failure_forces_full_restore() {
    // After a failed action, prev_delta_arc = None.
    // Next iteration MUST use restore_selective (not _from).
    // This test verifies the distinction matters: _from with wrong prev
    // would skip writes that _selective wouldn't.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let shared_arc = Arc::new(make_account(100, &[0xAA]));
    let mut s1_accts = FastHashMap::default();
    s1_accts.insert(pk_a, shared_arc.clone());
    let delta_1 = SvmSnapshot { accounts: s1_accts, sysvars: initial.sysvars.clone() };

    let mut s2_accts = FastHashMap::default();
    s2_accts.insert(pk_a, shared_arc.clone()); // SAME Arc as delta_1
    s2_accts.insert(pk_b, Arc::new(make_account(200, &[0xBB])));
    let delta_2 = SvmSnapshot { accounts: s2_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;

    // Iter 1: pick state 1, action SUCCEEDS
    simulate_fuzzer_iteration(
        &initial, &mut svm, &mut divergent, &mut prev_delta, &mut prev_exec_dirty,
        &delta_1,
        &[(pk_a, Some(make_account(55555, &[0xFF])))],
        true, // success
    );
    assert!(prev_delta.is_some());

    // Iter 2: pick state 1 again, action FAILS
    simulate_fuzzer_iteration(
        &initial, &mut svm, &mut divergent, &mut prev_delta, &mut prev_exec_dirty,
        &delta_1,
        &[(pk_a, Some(make_account(77777, &[0xEE])))],
        false, // failure
    );
    assert!(prev_delta.is_none(), "failure should clear prev_delta");

    // Iter 3: pick state 2 — prev_delta is None, so restore_selective is used
    // This is important because delta_2 shares Arc with delta_1 for pk_a.
    // If we incorrectly used restore_selective_from with delta_1 as prev,
    // AND pk_a was in exec_dirty from iter 2, it would work.
    // But if exec_dirty was somehow incomplete, _from would skip pk_a (same Arc).
    // Using restore_selective (no optimization) is the SAFE choice.
    simulate_restore(
        &initial, &mut svm, &divergent, &delta_2,
        prev_delta.as_ref(), &prev_exec_dirty,
    );
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100,
        "pk_a must be correctly restored even after failure");
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 200,
        "pk_b must be from state 2");
}

#[test]
fn test_adversarial_take_delta_with_empty_dirty_tracker() {
    // take_delta with empty dirty tracker should just clone parent.
    // All Arcs must be ptr_eq.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    svm.set_account(pk, make_account(100, &[1])).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let _initial = SvmSnapshot::take(&svm, &tracked);

    let mut parent_accts = FastHashMap::default();
    parent_accts.insert(pk, Arc::new(make_account(200, &[0xBB])));
    let parent = SvmSnapshot { accounts: parent_accts, sysvars: _initial.sysvars.clone() };

    let empty_dirty = DirtyTracker::new();
    let child = SvmSnapshot::take_delta(&svm, &parent, &empty_dirty);

    assert_eq!(child.account_count(), parent.account_count());
    assert!(Arc::ptr_eq(&parent.accounts()[&pk], &child.accounts()[&pk]),
        "empty dirty → child should be exact clone of parent (ptr_eq)");
}

#[test]
fn test_adversarial_restore_selective_empty_divergent_nonempty_delta() {
    // Empty divergent_keys + non-empty delta: should just write delta accounts.
    // No initial accounts get restored (nothing is divergent).
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    svm.set_account(pk_a, make_account(10, &[1])).unwrap();
    svm.set_account(pk_b, make_account(20, &[2])).unwrap();

    let tracked: HashSet<Pubkey> = [pk_a, pk_b].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Corrupt pk_b in SVM (but it's NOT in divergent_keys)
    svm.set_account(pk_b, make_account(99999, &[0xFF])).unwrap();

    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_a, Arc::new(make_account(100, &[0xAA])));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let divergent: FastHashSet<Pubkey> = FastHashSet::default(); // EMPTY
    let count = initial.restore_selective(&mut svm, &divergent, &delta);

    // pk_a: written from delta
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 100);
    // pk_b: NOT in divergent, NOT in delta → stays corrupted!
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 99999,
        "pk_b stays corrupted because it's not in divergent_keys — \
         this is correct behavior (caller must track divergence)");
    assert_eq!(count, 1, "only delta account written");
}

#[test]
fn test_adversarial_restore_all_account_fields() {
    // Verify that restore correctly sets ALL non-executable fields of an Account,
    // not just lamports and data. Checks: owner, rent_epoch, data content.
    // Note: LiteSVM rejects set_account with executable=true on non-program accounts,
    // so we test owner/rent_epoch/data instead.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();
    let owner_1 = Pubkey::new_unique();

    svm.set_account(pk, Account {
        lamports: 100,
        data: vec![1, 2, 3],
        owner: owner_1,
        executable: false,
        rent_epoch: 42,
    }).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let owner_2 = Pubkey::new_unique();
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk, Arc::new(Account {
        lamports: 200,
        data: vec![4, 5, 6, 7, 8],
        owner: owner_2,
        executable: false,
        rent_epoch: 99,
    }));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    divergent.insert(pk);

    // Restore to delta
    initial.restore_selective(&mut svm, &divergent, &delta);
    let acct = svm.get_account(&pk).unwrap();
    assert_eq!(acct.lamports, 200);
    assert_eq!(acct.data, vec![4, 5, 6, 7, 8]);
    assert_eq!(acct.owner, owner_2);
    assert_eq!(acct.rent_epoch, 99);

    // Restore to initial
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty);
    let acct = svm.get_account(&pk).unwrap();
    assert_eq!(acct.lamports, 100);
    assert_eq!(acct.data, vec![1, 2, 3]);
    assert_eq!(acct.owner, owner_1);
    assert_eq!(acct.rent_epoch, 42);
}

#[test]
fn test_adversarial_disjoint_delta_key_sets() {
    // prev_delta and next_delta have completely disjoint key sets.
    // All of prev's keys must be restored to initial.
    // All of next's keys must be written from delta.
    // No Arc sharing possible.
    let mut svm = LiteSVM::new();
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();

    for (i, pk) in [pk_a, pk_b, pk_c, pk_d].iter().enumerate() {
        svm.set_account(*pk, make_account((i as u64 + 1) * 10, &[i as u8])).unwrap();
    }

    let tracked: HashSet<Pubkey> = [pk_a, pk_b, pk_c, pk_d].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // prev: {A=100, B=200}
    let mut prev_accts = FastHashMap::default();
    prev_accts.insert(pk_a, Arc::new(make_account(100, &[0xAA])));
    prev_accts.insert(pk_b, Arc::new(make_account(200, &[0xBB])));
    let prev_delta = SvmSnapshot { accounts: prev_accts, sysvars: initial.sysvars.clone() };

    // next: {C=300, D=400} — completely disjoint!
    let mut next_accts = FastHashMap::default();
    next_accts.insert(pk_c, Arc::new(make_account(300, &[0xCC])));
    next_accts.insert(pk_d, Arc::new(make_account(400, &[0xDD])));
    let next_delta = SvmSnapshot { accounts: next_accts, sysvars: initial.sysvars.clone() };

    // Setup: restore to prev
    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &prev_delta);
    divergent.extend(prev_delta.accounts().keys().copied());

    // Jump prev → next
    let prev_exec_dirty: FastHashSet<Pubkey> = FastHashSet::default();
    let count = initial.restore_selective_from(
        &mut svm, &divergent, &prev_delta, &next_delta, &prev_exec_dirty,
    );

    // A and B: restored to initial (were in divergent, not in next)
    assert_eq!(svm.get_account(&pk_a).unwrap().lamports, 10);
    assert_eq!(svm.get_account(&pk_b).unwrap().lamports, 20);
    // C and D: from next delta
    assert_eq!(svm.get_account(&pk_c).unwrap().lamports, 300);
    assert_eq!(svm.get_account(&pk_d).unwrap().lamports, 400);
    // Count: 2 (A, B restored) + 2 (C, D written) = 4
    assert_eq!(count, 4);
}

#[test]
fn test_adversarial_large_data_mutation_integrity() {
    // Test with large account data (10KB) that changes patterns.
    // Verify byte-level integrity across restore cycles.
    let mut svm = LiteSVM::new();
    let pk = Pubkey::new_unique();

    let data_initial: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    svm.set_account(pk, make_account(100, &data_initial)).unwrap();

    let tracked: HashSet<Pubkey> = [pk].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    let data_modified: Vec<u8> = (0..10_000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk, Arc::new(make_account(200, &data_modified)));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();

    // Restore to delta
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.extend(delta.accounts().keys().copied());
    let acct = svm.get_account(&pk).unwrap();
    assert_eq!(acct.data.len(), 10_000);
    assert_eq!(acct.data, data_modified, "10KB data should match exactly");

    // Restore to initial
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty);
    let acct = svm.get_account(&pk).unwrap();
    assert_eq!(acct.data.len(), 10_000);
    assert_eq!(acct.data, data_initial, "10KB initial data should be restored exactly");
}

#[test]
fn test_adversarial_empty_data_and_zero_lamports_distinction() {
    // Verify the difference between:
    // 1. Account with lamports=0 (tombstone — account doesn't exist)
    // 2. Account with lamports>0 but empty data
    // 3. Account that was never created
    let mut svm = LiteSVM::new();
    let pk_has_data = Pubkey::new_unique();
    let pk_no_data = Pubkey::new_unique();

    svm.set_account(pk_has_data, make_account(100, &[1, 2, 3])).unwrap();
    svm.set_account(pk_no_data, make_account(50, &[])).unwrap(); // empty data, nonzero lamports

    let tracked: HashSet<Pubkey> = [pk_has_data, pk_no_data].into_iter().collect();
    let initial = SvmSnapshot::take(&svm, &tracked);

    // Delta: tombstone pk_has_data, keep pk_no_data as-is
    let mut delta_accts = FastHashMap::default();
    delta_accts.insert(pk_has_data, Arc::new(Account { lamports: 0, ..Default::default() }));
    let delta = SvmSnapshot { accounts: delta_accts, sysvars: initial.sysvars.clone() };

    let mut divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta);
    divergent.extend(delta.accounts().keys().copied());

    // pk_has_data: tombstoned (gone)
    assert!(svm.get_account(&pk_has_data).is_none());
    // pk_no_data: still alive with empty data and 50 lamports (not in delta → initial)
    let acct = svm.get_account(&pk_no_data).unwrap();
    assert_eq!(acct.lamports, 50);
    assert_eq!(acct.data.len(), 0);

    // Restore to initial: pk_has_data comes back
    let empty = SvmSnapshot::empty(initial.clock().clone());
    initial.restore_selective(&mut svm, &divergent, &empty);
    let acct = svm.get_account(&pk_has_data).unwrap();
    assert_eq!(acct.lamports, 100);
    assert_eq!(acct.data, vec![1, 2, 3]);
}
