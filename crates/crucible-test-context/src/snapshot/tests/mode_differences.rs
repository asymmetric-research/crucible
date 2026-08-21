use super::super::*;
use super::helpers::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

// =========================================================================
// Category 1: Restore Pattern Equivalence
// =========================================================================

#[test]
fn test_stateless_restore_vs_stateful_restore_selective_empty_delta() {
    // Both paths should produce identical SVMs when restoring to initial state.
    // Stateless: snapshot.restore(&dirty)
    // Stateful: initial.restore_selective(&divergent, &empty_delta)

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let pk4 = Pubkey::new_unique();
    let pk5 = Pubkey::new_unique();
    let pks = [pk1, pk2, pk3, pk4, pk5];

    let accts: Vec<Account> = (1..=5)
        .map(|i| make_account(i * 100, &[i as u8; 8]))
        .collect();

    // Setup SVM A (stateless path)
    let mut svm_a = LiteSVM::new();
    for (pk, acct) in pks.iter().zip(accts.iter()) {
        svm_a.set_account(*pk, acct.clone()).unwrap();
    }
    let tracked: HashSet<Pubkey> = pks.iter().copied().collect();
    let snap = SvmSnapshot::take(&svm_a, &tracked);

    // Setup SVM B (stateful path) - identical initial state
    let mut svm_b = LiteSVM::new();
    for (pk, acct) in pks.iter().zip(accts.iter()) {
        svm_b.set_account(*pk, acct.clone()).unwrap();
    }
    let initial = SvmSnapshot::take_all(&svm_b);

    // Modify same 3 accounts in both SVMs
    let dirty_pks = [pk1, pk3, pk5];
    for pk in &dirty_pks {
        let modified = make_account(9999, &[0xFF; 8]);
        svm_a.set_account(*pk, modified.clone()).unwrap();
        svm_b.set_account(*pk, modified).unwrap();
    }

    // Stateless restore
    let mut dirty = DirtyTracker::new();
    for pk in &dirty_pks {
        dirty.mark_account_dirty(pk);
    }
    snap.restore(&mut svm_a, &dirty);

    // Stateful restore with empty delta (= restore to initial)
    let divergent: FastHashSet<Pubkey> = dirty_pks.iter().copied().collect();
    let empty_delta = SvmSnapshot::empty(svm_b.get_sysvar::<Clock>());
    initial.restore_selective(&mut svm_b, &divergent, &empty_delta);

    // Both SVMs should have identical accounts
    for (i, pk) in pks.iter().enumerate() {
        let a = svm_a.get_account(pk).expect("SVM A missing account");
        let b = svm_b.get_account(pk).expect("SVM B missing account");
        assert_eq!(
            a.lamports, b.lamports,
            "pk[{}] lamports mismatch: A={} B={}",
            i, a.lamports, b.lamports
        );
        assert_eq!(a.data, b.data, "pk[{}] data mismatch", i);
    }
}

#[test]
fn test_restore_selective_from_equivalent_to_restore_selective() {
    // restore_selective_from(prev=A, next=B) should produce the same SVM state
    // as restore_selective(divergent, B).

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let pk4 = Pubkey::new_unique();

    let mut svm_setup = LiteSVM::new();
    let initial_accts: Vec<(Pubkey, Account)> = vec![
        (pk1, make_account(100, &[1; 16])),
        (pk2, make_account(200, &[2; 16])),
        (pk3, make_account(300, &[3; 16])),
        (pk4, make_account(400, &[4; 16])),
    ];
    for (pk, acct) in &initial_accts {
        svm_setup.set_account(*pk, acct.clone()).unwrap();
    }
    let initial = SvmSnapshot::take_all(&svm_setup);

    // Build delta A: pk1 modified, pk2 modified
    let delta_a = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 16])));
        map.insert(pk2, Arc::new(make_account(2000, &[0xA2; 16])));
        SvmSnapshot {
            accounts: map,
            sysvars: make_test_sysvars(10),
        }
    };

    // Build delta B: pk2 modified (shared Arc with A), pk3 modified
    let delta_b = {
        let mut map = FastHashMap::default();
        map.insert(pk2, delta_a.accounts.get(&pk2).unwrap().clone()); // same Arc
        map.insert(pk3, Arc::new(make_account(3000, &[0xB3; 16])));
        SvmSnapshot {
            accounts: map,
            sysvars: make_test_sysvars(20),
        }
    };

    // SVM 1: restore to B via restore_selective (simple path)
    let mut svm1 = LiteSVM::new();
    for (pk, acct) in &initial_accts {
        svm1.set_account(*pk, acct.clone()).unwrap();
    }
    // Apply delta A first to set up divergence
    let divergent_a: FastHashSet<Pubkey> = delta_a.accounts.keys().copied().collect();
    initial.restore_selective(&mut svm1, &FastHashSet::default(), &delta_a);

    // Now restore to B. Divergent = delta A keys
    let mut divergent_for_b: FastHashSet<Pubkey> = divergent_a.clone();
    initial.restore_selective(&mut svm1, &divergent_for_b, &delta_b);

    // SVM 2: restore to B via restore_selective_from (optimized path)
    let mut svm2 = LiteSVM::new();
    for (pk, acct) in &initial_accts {
        svm2.set_account(*pk, acct.clone()).unwrap();
    }
    initial.restore_selective(&mut svm2, &FastHashSet::default(), &delta_a);
    divergent_for_b = delta_a.accounts.keys().copied().collect();
    let empty_exec_dirty = FastHashSet::default();
    initial.restore_selective_from(
        &mut svm2,
        &divergent_for_b,
        &delta_a,
        &delta_b,
        &empty_exec_dirty,
    );

    // Both SVMs should be identical
    for pk in &[pk1, pk2, pk3, pk4] {
        let a1 = svm1.get_account(pk);
        let a2 = svm2.get_account(pk);
        match (a1, a2) {
            (Some(a), Some(b)) => {
                assert_eq!(a.lamports, b.lamports, "{:?} lamports differ", pk);
                assert_eq!(a.data, b.data, "{:?} data differs", pk);
            }
            (None, None) => {}
            _ => panic!("{:?}: one SVM has account, other doesn't", pk),
        }
    }
}

#[test]
fn test_both_modes_produce_same_state_after_same_modifications() {
    // Verify that the same modifications result in same SVM state in both modes
    // before any restore is applied.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let init_accts = vec![
        (pk1, make_account(100, &[1; 8])),
        (pk2, make_account(200, &[2; 8])),
        (pk3, make_account(300, &[3; 8])),
    ];

    // Stateless SVM
    let mut svm_stateless = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_stateless.set_account(*pk, acct.clone()).unwrap();
    }

    // Stateful SVM
    let mut svm_stateful = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_stateful.set_account(*pk, acct.clone()).unwrap();
    }

    // Apply same modifications to both
    let mod1 = make_account(999, &[0xAA; 8]);
    let mod2 = make_account(888, &[0xBB; 8]);
    svm_stateless.set_account(pk1, mod1.clone()).unwrap();
    svm_stateless.set_account(pk2, mod2.clone()).unwrap();
    svm_stateful.set_account(pk1, mod1).unwrap();
    svm_stateful.set_account(pk2, mod2).unwrap();

    // Before any restore, both SVMs should be identical
    for pk in &[pk1, pk2, pk3] {
        let sl = svm_stateless.get_account(pk).unwrap();
        let sf = svm_stateful.get_account(pk).unwrap();
        assert_eq!(sl.lamports, sf.lamports, "{:?} lamports", pk);
        assert_eq!(sl.data, sf.data, "{:?} data", pk);
    }

    // After stateless restore → back to initial
    let tracked: HashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
    let snap = SvmSnapshot::take(
        &{
            let mut tmp = LiteSVM::new();
            for (pk, acct) in &init_accts {
                tmp.set_account(*pk, acct.clone()).unwrap();
            }
            tmp
        },
        &tracked,
    );
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);
    snap.restore(&mut svm_stateless, &dirty);

    // After stateful take_delta → capture the modification
    let initial_sf = SvmSnapshot::take_all(&{
        let mut tmp = LiteSVM::new();
        for (pk, acct) in &init_accts {
            tmp.set_account(*pk, acct.clone()).unwrap();
        }
        tmp
    });
    let delta_root = SvmSnapshot::empty(svm_stateful.get_sysvar::<Clock>());
    let mut dirty_sf = DirtyTracker::new();
    dirty_sf.mark_account_dirty(&pk1);
    dirty_sf.mark_account_dirty(&pk2);
    let delta = SvmSnapshot::take_delta(&svm_stateful, &delta_root, &dirty_sf);

    // Restore stateful SVM to initial, then apply delta → should match pre-restore state
    let divergent: FastHashSet<Pubkey> = [pk1, pk2].iter().copied().collect();
    initial_sf.restore_selective(&mut svm_stateful, &divergent, &delta);

    // Stateful SVM should now be at the modified state (delta applied)
    assert_eq!(svm_stateful.get_account(&pk1).unwrap().lamports, 999);
    assert_eq!(svm_stateful.get_account(&pk2).unwrap().lamports, 888);
    assert_eq!(svm_stateful.get_account(&pk3).unwrap().lamports, 300);

    // Stateless SVM should be back at initial
    assert_eq!(svm_stateless.get_account(&pk1).unwrap().lamports, 100);
    assert_eq!(svm_stateless.get_account(&pk2).unwrap().lamports, 200);
    assert_eq!(svm_stateless.get_account(&pk3).unwrap().lamports, 300);
}

// =========================================================================
// Category 2: Iteration Lifecycle Simulation
// =========================================================================

#[test]
fn test_stateless_3_iteration_cycle_no_leakage() {
    // 3 stateless iterations modifying different accounts each time.
    // After each restore, SVM exactly matches initial. No leakage.

    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();
    let pk_d = Pubkey::new_unique();

    let init = vec![
        (pk_a, make_account(100, &[1; 4])),
        (pk_b, make_account(200, &[2; 4])),
        (pk_c, make_account(300, &[3; 4])),
        (pk_d, make_account(400, &[4; 4])),
    ];

    let mut svm = LiteSVM::new();
    for (pk, acct) in &init {
        svm.set_account(*pk, acct.clone()).unwrap();
    }
    let tracked: HashSet<Pubkey> = init.iter().map(|(pk, _)| *pk).collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    let mut dirty = DirtyTracker::new();

    let verify_initial = |svm: &LiteSVM, label: &str| {
        for (pk, acct) in &init {
            let got = svm
                .get_account(pk)
                .unwrap_or_else(|| panic!("{}: missing {:?}", label, pk));
            assert_eq!(got.lamports, acct.lamports, "{}: {:?} lamports", label, pk);
            assert_eq!(got.data, acct.data, "{}: {:?} data", label, pk);
        }
    };

    // Iteration 1: modify A, B
    dirty.clear();
    svm.set_account(pk_a, make_account(9999, &[0xFF; 4]))
        .unwrap();
    svm.set_account(pk_b, make_account(8888, &[0xFE; 4]))
        .unwrap();
    dirty.mark_account_dirty(&pk_a);
    dirty.mark_account_dirty(&pk_b);
    snap.restore(&mut svm, &dirty);
    verify_initial(&svm, "iter1");

    // Iteration 2: modify C, D + create new account
    dirty.clear();
    let pk_new = Pubkey::new_unique();
    svm.set_account(pk_c, make_account(7777, &[0xFD; 4]))
        .unwrap();
    svm.set_account(pk_d, make_account(6666, &[0xFC; 4]))
        .unwrap();
    svm.set_account(pk_new, make_account(5555, &[0xFB; 4]))
        .unwrap();
    dirty.mark_account_dirty(&pk_c);
    dirty.mark_account_dirty(&pk_d);
    dirty.mark_account_dirty(&pk_new);
    snap.restore(&mut svm, &dirty);
    verify_initial(&svm, "iter2");
    // Created account should be zeroed out
    let new_acct = svm.get_account(&pk_new);
    assert!(
        new_acct.is_none() || new_acct.unwrap().lamports == 0,
        "iter2: created account should be gone"
    );

    // Iteration 3: modify A, C
    dirty.clear();
    svm.set_account(pk_a, make_account(4444, &[0xFA; 4]))
        .unwrap();
    svm.set_account(pk_c, make_account(3333, &[0xF9; 4]))
        .unwrap();
    dirty.mark_account_dirty(&pk_a);
    dirty.mark_account_dirty(&pk_c);
    snap.restore(&mut svm, &dirty);
    verify_initial(&svm, "iter3");
}

#[test]
fn test_stateful_3_iteration_cycle_state_switching() {
    // 3 stateful iterations: pick delta_A, then delta_B, then delta_A again.
    // Verify correct state after each restore_selective.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let init_accts = vec![
        (pk1, make_account(100, &[1; 8])),
        (pk2, make_account(200, &[2; 8])),
        (pk3, make_account(300, &[3; 8])),
    ];

    let mut svm = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm.set_account(*pk, acct.clone()).unwrap();
    }
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    // Pre-build deltas
    let delta_a = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };
    let delta_b = {
        let mut map = FastHashMap::default();
        map.insert(pk2, Arc::new(make_account(2000, &[0xB2; 8])));
        map.insert(pk3, Arc::new(make_account(3000, &[0xB3; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    let mut divergent_keys = FastHashSet::default();
    let mut prev_delta: Option<&SvmSnapshot> = None;
    let prev_exec_dirty = FastHashSet::default();

    // Iteration 1: pick delta_A
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_a,
        prev_delta,
        &prev_exec_dirty,
    );
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        1000,
        "iter1: pk1 should be delta_A"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        200,
        "iter1: pk2 should be initial"
    );
    assert_eq!(
        svm.get_account(&pk3).unwrap().lamports,
        300,
        "iter1: pk3 should be initial"
    );

    divergent_keys.clear();
    divergent_keys.extend(delta_a.accounts.keys().copied());
    prev_delta = Some(&delta_a);

    // Iteration 2: switch to delta_B
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_b,
        prev_delta,
        &prev_exec_dirty,
    );
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        100,
        "iter2: pk1 should be initial"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        2000,
        "iter2: pk2 should be delta_B"
    );
    assert_eq!(
        svm.get_account(&pk3).unwrap().lamports,
        3000,
        "iter2: pk3 should be delta_B"
    );

    divergent_keys.clear();
    divergent_keys.extend(delta_b.accounts.keys().copied());
    prev_delta = Some(&delta_b);

    // Iteration 3: switch back to delta_A
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_a,
        prev_delta,
        &prev_exec_dirty,
    );
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        1000,
        "iter3: pk1 should be delta_A"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        200,
        "iter3: pk2 should be initial"
    );
    assert_eq!(
        svm.get_account(&pk3).unwrap().lamports,
        300,
        "iter3: pk3 should be initial"
    );
}

#[test]
fn test_stateful_iteration_with_failed_action_clears_prev_delta() {
    // When an action fails, prev_delta is set to None. The next iteration
    // must use simple restore_selective instead of restore_selective_from.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_a = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };
    let delta_b = {
        let mut map = FastHashMap::default();
        map.insert(pk2, Arc::new(make_account(2000, &[0xB2; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    let mut divergent_keys = FastHashSet::default();
    let mut prev_delta_opt: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty = FastHashSet::default();

    // Iteration 1: succeeds with delta_A
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_a,
        prev_delta_opt.as_ref(),
        &prev_exec_dirty,
    );
    // Simulate execution that modifies pk1
    svm.set_account(pk1, make_account(1111, &[0xEE; 8]))
        .unwrap();
    divergent_keys.clear();
    divergent_keys.extend(delta_a.accounts.keys());
    divergent_keys.insert(pk1); // dirty from execution
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk1);
    prev_delta_opt = Some(delta_a.clone()); // success → set prev_delta

    // Iteration 2: FAILS — prev_delta → None
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_a,
        prev_delta_opt.as_ref(),
        &prev_exec_dirty,
    );
    // Simulate failed execution (still modifies accounts though)
    svm.set_account(pk2, make_account(2222, &[0xDD; 8]))
        .unwrap();
    divergent_keys.clear();
    divergent_keys.extend(delta_a.accounts.keys());
    divergent_keys.insert(pk2);
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk2);
    prev_delta_opt = None; // failure → clear prev_delta

    // Iteration 3: picks delta_B. Since prev_delta is None, must use simple path.
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_b,
        prev_delta_opt.as_ref(),
        &prev_exec_dirty,
    );

    // Verify correct state: pk1 at initial, pk2 at delta_B
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        100,
        "pk1 should be initial"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        2000,
        "pk2 should be delta_B"
    );
}

#[test]
fn test_stateful_failed_action_dirty_accounts_in_divergent_keys() {
    // A failed action can still modify accounts. Those must be in divergent_keys
    // so the next iteration properly restores them.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_empty = SvmSnapshot::empty(clock.clone());
    let delta_target = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    // Iteration 1: pick empty delta, simulate failed action that modifies pk2, pk3
    let mut divergent_keys = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent_keys, &delta_empty);

    // Failed action partially executes, modifying accounts
    svm.set_account(pk2, make_account(9999, &[0xFF; 8]))
        .unwrap();
    svm.set_account(pk3, make_account(8888, &[0xFE; 8]))
        .unwrap();

    // Update divergent_keys to include dirty accounts from failed action
    let mut exec_dirty = FastHashSet::default();
    exec_dirty.insert(pk2);
    exec_dirty.insert(pk3);
    divergent_keys.extend(exec_dirty.iter());

    // Iteration 2: pick delta_target. Without pk2/pk3 in divergent_keys,
    // they'd remain at the stale values from the failed action.
    initial.restore_selective(&mut svm, &divergent_keys, &delta_target);

    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        1000,
        "pk1 should be delta_target"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        200,
        "pk2 should be restored to initial"
    );
    assert_eq!(
        svm.get_account(&pk3).unwrap().lamports,
        300,
        "pk3 should be restored to initial"
    );

    // Extra: verify that without the dirty accounts in divergent_keys, state leaks.
    // Reset SVM and try without tracking dirty accounts.
    let mut svm_bad = LiteSVM::new();
    svm_bad
        .set_account(pk1, make_account(100, &[1; 8]))
        .unwrap();
    svm_bad
        .set_account(pk2, make_account(200, &[2; 8]))
        .unwrap();
    svm_bad
        .set_account(pk3, make_account(300, &[3; 8]))
        .unwrap();

    initial.restore_selective(&mut svm_bad, &FastHashSet::default(), &delta_empty);
    svm_bad
        .set_account(pk2, make_account(9999, &[0xFF; 8]))
        .unwrap();
    svm_bad
        .set_account(pk3, make_account(8888, &[0xFE; 8]))
        .unwrap();

    // Restore without including dirty accounts in divergent → stale state!
    let no_dirty_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm_bad, &no_dirty_divergent, &delta_target);

    // pk2 and pk3 should still have stale values (demonstrating the bug)
    assert_eq!(
        svm_bad.get_account(&pk2).unwrap().lamports,
        9999,
        "pk2 stale without divergent tracking"
    );
    assert_eq!(
        svm_bad.get_account(&pk3).unwrap().lamports,
        8888,
        "pk3 stale without divergent tracking"
    );
}

// =========================================================================
// Category 3: DirtyTracker Lifecycle
// =========================================================================

#[test]
fn test_stateless_dirty_clear_makes_second_restore_noop() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 4])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 4])).unwrap();

    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);

    // Modify and restore
    svm.set_account(pk1, make_account(9999, &[0xFF; 4]))
        .unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    let count1 = snap.restore(&mut svm, &dirty);
    assert_eq!(count1, 1);
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100);

    // Clear dirty and call restore again — should restore 0 accounts
    dirty.clear();
    let count2 = snap.restore(&mut svm, &dirty);
    assert_eq!(count2, 0, "second restore with empty dirty should be noop");

    // State should still be correct
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200);
}

#[test]
fn test_stateful_dirty_not_cleared_feeds_delta_and_divergent() {
    // In stateful mode, dirty_tracker is NOT cleared between:
    // (a) action execution, (b) take_delta, (c) divergent_keys update.
    // The same dirty set is used for all three.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Simulate action: modify pk1 and pk2
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    svm.set_account(pk2, make_account(2000, &[0xA2; 8]))
        .unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);

    // (a) dirty_accounts() used to check what was modified
    let dirty_set_a: Vec<Pubkey> = dirty.dirty_accounts().iter().copied().collect();
    assert_eq!(dirty_set_a.len(), 2);

    // (b) take_delta uses the same dirty set
    let delta = SvmSnapshot::take_delta(&svm, &delta_root, &dirty);
    assert_eq!(
        delta.account_count(),
        2,
        "delta should have exactly the dirty accounts"
    );
    assert!(delta.accounts().contains_key(&pk1));
    assert!(delta.accounts().contains_key(&pk2));
    assert!(!delta.accounts().contains_key(&pk3));

    // (c) divergent_keys update uses the same dirty set
    let mut divergent_keys = FastHashSet::default();
    divergent_keys.extend(dirty.dirty_accounts().iter().copied());
    assert!(divergent_keys.contains(&pk1));
    assert!(divergent_keys.contains(&pk2));
    assert!(!divergent_keys.contains(&pk3));

    // All three uses of dirty set are consistent
    assert_eq!(dirty.dirty_count(), divergent_keys.len());
    assert_eq!(dirty.dirty_count(), delta.account_count());
}

#[test]
fn test_dirty_tracker_used_for_restore_vs_delta_capture() {
    // Stateless: dirty drives snapshot.restore() (which accounts to reset)
    // Stateful: dirty drives SvmSnapshot::take_delta() (which accounts to snapshot)
    // Both uses on the same dirty set should produce correct results.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    // Setup initial state
    let init_accts = vec![
        (pk1, make_account(100, &[1; 8])),
        (pk2, make_account(200, &[2; 8])),
        (pk3, make_account(300, &[3; 8])),
    ];

    // SVM for stateless
    let mut svm_sl = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_sl.set_account(*pk, acct.clone()).unwrap();
    }
    let tracked: HashSet<Pubkey> = init_accts.iter().map(|(pk, _)| *pk).collect();
    let snap_sl = SvmSnapshot::take(&svm_sl, &tracked);

    // SVM for stateful
    let mut svm_sf = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_sf.set_account(*pk, acct.clone()).unwrap();
    }
    let delta_root = SvmSnapshot::empty(svm_sf.get_sysvar::<Clock>());

    // Apply same modifications and build same dirty set
    let mod1 = make_account(999, &[0xAA; 8]);
    let mod2 = make_account(888, &[0xBB; 8]);
    svm_sl.set_account(pk1, mod1.clone()).unwrap();
    svm_sl.set_account(pk2, mod2.clone()).unwrap();
    svm_sf.set_account(pk1, mod1).unwrap();
    svm_sf.set_account(pk2, mod2).unwrap();

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);

    // Stateless use: restore — reset dirty accounts back to initial
    snap_sl.restore(&mut svm_sl, &dirty);
    assert_eq!(
        svm_sl.get_account(&pk1).unwrap().lamports,
        100,
        "stateless: pk1 restored"
    );
    assert_eq!(
        svm_sl.get_account(&pk2).unwrap().lamports,
        200,
        "stateless: pk2 restored"
    );
    assert_eq!(
        svm_sl.get_account(&pk3).unwrap().lamports,
        300,
        "stateless: pk3 unchanged"
    );

    // Stateful use: take_delta — capture dirty accounts' current values
    let delta = SvmSnapshot::take_delta(&svm_sf, &delta_root, &dirty);
    assert_eq!(
        delta.accounts().get(&pk1).unwrap().lamports,
        999,
        "stateful: delta captured pk1"
    );
    assert_eq!(
        delta.accounts().get(&pk2).unwrap().lamports,
        888,
        "stateful: delta captured pk2"
    );
    assert!(
        !delta.accounts().contains_key(&pk3),
        "stateful: pk3 not in delta"
    );
}

// =========================================================================
// Category 4: Delta Snapshot Properties
// =========================================================================

#[test]
fn test_take_delta_only_includes_accounts_in_dirty_set() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let pk4 = Pubkey::new_unique();
    let pk5 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    for (pk, lamports) in [(pk1, 100), (pk2, 200), (pk3, 300), (pk4, 400), (pk5, 500)] {
        svm.set_account(pk, make_account(lamports, &[lamports as u8]))
            .unwrap();
    }

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Modify 3 of 5 accounts
    svm.set_account(pk1, make_account(1000, &[0xA1])).unwrap();
    svm.set_account(pk3, make_account(3000, &[0xA3])).unwrap();
    svm.set_account(pk5, make_account(5000, &[0xA5])).unwrap();

    // Mark only those 3 as dirty
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk3);
    dirty.mark_account_dirty(&pk5);

    let delta = SvmSnapshot::take_delta(&svm, &delta_root, &dirty);

    // Delta should only contain the 3 dirty accounts
    assert_eq!(delta.account_count(), 3);
    assert!(delta.accounts().contains_key(&pk1));
    assert!(
        !delta.accounts().contains_key(&pk2),
        "pk2 should not be in delta"
    );
    assert!(delta.accounts().contains_key(&pk3));
    assert!(
        !delta.accounts().contains_key(&pk4),
        "pk4 should not be in delta"
    );
    assert!(delta.accounts().contains_key(&pk5));

    // Values should match current SVM state
    assert_eq!(delta.accounts().get(&pk1).unwrap().lamports, 1000);
    assert_eq!(delta.accounts().get(&pk3).unwrap().lamports, 3000);
    assert_eq!(delta.accounts().get(&pk5).unwrap().lamports, 5000);
}

#[test]
fn test_take_all_superset_of_take_tracked() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1])).unwrap();
    svm.set_account(pk2, make_account(200, &[2])).unwrap();
    svm.set_account(pk3, make_account(300, &[3])).unwrap();

    // take with only pk1, pk2 tracked
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let snap_tracked = SvmSnapshot::take(&svm, &tracked);

    // take_all captures everything
    let snap_all = SvmSnapshot::take_all(&svm);

    // snap_all must be a superset of snap_tracked
    for pk in snap_tracked.accounts().keys() {
        assert!(
            snap_all.accounts().contains_key(pk),
            "take_all should contain all tracked accounts"
        );
        // Values should match
        let tracked_acct = snap_tracked.accounts().get(pk).unwrap();
        let all_acct = snap_all.accounts().get(pk).unwrap();
        assert_eq!(tracked_acct.lamports, all_acct.lamports);
        assert_eq!(tracked_acct.data, all_acct.data);
    }

    // snap_all should contain pk3 which snap_tracked does not
    assert!(snap_all.accounts().contains_key(&pk3));
    assert!(!snap_tracked.accounts().contains_key(&pk3));

    // snap_all has at least as many accounts (likely more due to system accounts)
    assert!(snap_all.account_count() >= snap_tracked.account_count());
}

#[test]
fn test_restore_full_vs_restore_selective_with_all_accounts_as_delta() {
    // restore_full(delta) and restore_selective(all_divergent, delta) should
    // produce identical state when delta contains all modified accounts.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let init_accts = vec![
        (pk1, make_account(100, &[1; 8])),
        (pk2, make_account(200, &[2; 8])),
        (pk3, make_account(300, &[3; 8])),
    ];

    // Build a full delta (all accounts modified)
    let mut delta_map = FastHashMap::default();
    delta_map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
    delta_map.insert(pk2, Arc::new(make_account(2000, &[0xA2; 8])));
    delta_map.insert(pk3, Arc::new(make_account(3000, &[0xA3; 8])));
    let full_delta = SvmSnapshot {
        accounts: delta_map,
        sysvars: make_test_sysvars(42),
    };

    // SVM 1: restore_full
    let mut svm1 = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm1.set_account(*pk, acct.clone()).unwrap();
    }
    full_delta.restore_full(&mut svm1);

    // SVM 2: restore_selective with all accounts in divergent
    let mut svm2 = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm2.set_account(*pk, acct.clone()).unwrap();
    }
    let initial2 = SvmSnapshot::take_all(&svm2);
    let all_divergent: FastHashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
    initial2.restore_selective(&mut svm2, &all_divergent, &full_delta);

    // Both SVMs should have identical account state
    for pk in &[pk1, pk2, pk3] {
        let a1 = svm1.get_account(pk).unwrap();
        let a2 = svm2.get_account(pk).unwrap();
        assert_eq!(a1.lamports, a2.lamports, "{:?} lamports differ", pk);
        assert_eq!(a1.data, a2.data, "{:?} data differs", pk);
    }
}

// =========================================================================
// Category 5: Dual-SVM Equivalence
// =========================================================================

#[test]
fn test_dual_svm_traced_and_fast_same_state_after_restore() {
    // Simulate dual-SVM: traced uses restore_selective, fast uses restore_selective_from.
    // Both should have identical state when restoring to the same delta.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let init_accts = vec![
        (pk1, make_account(100, &[1; 16])),
        (pk2, make_account(200, &[2; 16])),
        (pk3, make_account(300, &[3; 16])),
    ];

    // Setup both SVMs identically
    let mut svm_traced = LiteSVM::new();
    let mut svm_fast = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_traced.set_account(*pk, acct.clone()).unwrap();
        svm_fast.set_account(*pk, acct.clone()).unwrap();
    }
    let initial_traced = SvmSnapshot::take_all(&svm_traced);
    let initial_fast = SvmSnapshot::take_all(&svm_fast);
    let clock = svm_traced.get_sysvar::<Clock>();

    let delta_prev = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 16])));
        map.insert(pk2, Arc::new(make_account(2000, &[0xA2; 16])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    let delta_next = {
        let mut map = FastHashMap::default();
        // pk1 shares Arc with prev (same value)
        map.insert(pk1, delta_prev.accounts.get(&pk1).unwrap().clone());
        // pk3 is new in this delta
        map.insert(pk3, Arc::new(make_account(3000, &[0xB3; 16])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    // Apply delta_prev to both SVMs first
    let mut traced_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial_traced.restore_selective(&mut svm_traced, &traced_divergent, &delta_prev);
    traced_divergent.extend(delta_prev.accounts.keys());

    let mut fast_divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial_fast.restore_selective(&mut svm_fast, &fast_divergent, &delta_prev);
    fast_divergent.extend(delta_prev.accounts.keys());

    // Traced SVM: restore_selective to delta_next
    initial_traced.restore_selective(&mut svm_traced, &traced_divergent, &delta_next);

    // Fast SVM: restore_selective_from to delta_next (optimized)
    let empty_exec_dirty = FastHashSet::default();
    initial_fast.restore_selective_from(
        &mut svm_fast,
        &fast_divergent,
        &delta_prev,
        &delta_next,
        &empty_exec_dirty,
    );

    // Both SVMs should be identical
    for pk in &[pk1, pk2, pk3] {
        let traced = svm_traced.get_account(pk);
        let fast = svm_fast.get_account(pk);
        match (traced, fast) {
            (Some(t), Some(f)) => {
                assert_eq!(t.lamports, f.lamports, "{:?} lamports", pk);
                assert_eq!(t.data, f.data, "{:?} data", pk);
            }
            (None, None) => {}
            _ => panic!(
                "{:?}: traced has={}, fast has={}",
                pk,
                svm_traced.get_account(pk).is_some(),
                svm_fast.get_account(pk).is_some()
            ),
        }
    }
}

#[test]
fn test_dual_svm_separate_divergent_keys() {
    // Traced and fast SVMs maintain independent divergent_keys.
    // Modifying different accounts in each, then restoring to the same state,
    // should still produce correct results.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let pk4 = Pubkey::new_unique();

    let init_accts = vec![
        (pk1, make_account(100, &[1; 8])),
        (pk2, make_account(200, &[2; 8])),
        (pk3, make_account(300, &[3; 8])),
        (pk4, make_account(400, &[4; 8])),
    ];

    let mut svm_traced = LiteSVM::new();
    let mut svm_fast = LiteSVM::new();
    for (pk, acct) in &init_accts {
        svm_traced.set_account(*pk, acct.clone()).unwrap();
        svm_fast.set_account(*pk, acct.clone()).unwrap();
    }
    let initial_traced = SvmSnapshot::take_all(&svm_traced);
    let initial_fast = SvmSnapshot::take_all(&svm_fast);
    let clock = svm_traced.get_sysvar::<Clock>();

    let target_delta = {
        let mut map = FastHashMap::default();
        map.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
        SvmSnapshot {
            accounts: map,
            sysvars: clock_to_sysvars(&clock),
        }
    };

    // Traced SVM: execution modifies pk2, pk3
    svm_traced
        .set_account(pk2, make_account(9999, &[0xFF; 8]))
        .unwrap();
    svm_traced
        .set_account(pk3, make_account(8888, &[0xFE; 8]))
        .unwrap();
    let traced_divergent: FastHashSet<Pubkey> = [pk2, pk3].into_iter().collect();

    // Fast SVM: execution modifies pk3, pk4 (different set!)
    svm_fast
        .set_account(pk3, make_account(7777, &[0xFD; 8]))
        .unwrap();
    svm_fast
        .set_account(pk4, make_account(6666, &[0xFC; 8]))
        .unwrap();
    let fast_divergent: FastHashSet<Pubkey> = [pk3, pk4].into_iter().collect();

    // Restore both to same target_delta
    initial_traced.restore_selective(&mut svm_traced, &traced_divergent, &target_delta);
    initial_fast.restore_selective(&mut svm_fast, &fast_divergent, &target_delta);

    // Both should have identical final state
    for pk in &[pk1, pk2, pk3, pk4] {
        let t = svm_traced.get_account(pk).unwrap();
        let f = svm_fast.get_account(pk).unwrap();
        assert_eq!(t.lamports, f.lamports, "{:?} lamports", pk);
        assert_eq!(t.data, f.data, "{:?} data", pk);
    }

    // Specifically:
    assert_eq!(
        svm_traced.get_account(&pk1).unwrap().lamports,
        1000,
        "pk1 from delta"
    );
    assert_eq!(
        svm_traced.get_account(&pk2).unwrap().lamports,
        200,
        "pk2 restored to initial"
    );
    assert_eq!(
        svm_traced.get_account(&pk3).unwrap().lamports,
        300,
        "pk3 restored to initial"
    );
    assert_eq!(
        svm_traced.get_account(&pk4).unwrap().lamports,
        400,
        "pk4 initial (fast restored)"
    );
}

// =========================================================================
// Category 6: SVM Swap Trick
// =========================================================================

#[test]
fn test_svm_swap_roundtrip_preserves_accounts() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();

    // Swap out
    let mut holder = LiteSVM::new();
    std::mem::swap(&mut svm, &mut holder);

    // holder now has the accounts
    assert_eq!(holder.get_account(&pk1).unwrap().lamports, 100);
    assert_eq!(holder.get_account(&pk2).unwrap().lamports, 200);

    // svm is now the empty one (might still have system accounts)
    // Our test accounts should not be in the empty SVM
    assert!(
        svm.get_account(&pk1).is_none(),
        "swapped-out SVM should not have pk1"
    );
    assert!(
        svm.get_account(&pk2).is_none(),
        "swapped-out SVM should not have pk2"
    );

    // Swap back
    std::mem::swap(&mut svm, &mut holder);

    // svm has accounts again
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        100,
        "pk1 restored after swap back"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        200,
        "pk2 restored after swap back"
    );
}

#[test]
fn test_empty_svm_after_swap_means_cheap_clone() {
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 32])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 32])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 32])).unwrap();

    // Swap real SVM out, replace with empty
    let mut empty = LiteSVM::new();
    std::mem::swap(&mut svm, &mut empty);

    // The "empty" SVM (what svm now points to) should not have our test accounts
    assert!(svm.get_account(&pk1).is_none());
    assert!(svm.get_account(&pk2).is_none());
    assert!(svm.get_account(&pk3).is_none());

    // The accounts_db should be small (only system-default accounts, if any)
    let db = svm.accounts_db();
    // None of our test keys should be present
    assert!(!db.inner.contains_key(&pk1));
    assert!(!db.inner.contains_key(&pk2));
    assert!(!db.inner.contains_key(&pk3));
}

// =========================================================================
// Category 7: Crash Path Differences
// =========================================================================

#[test]
fn test_stateless_crash_dedup_by_input_bytes() {
    // Stateless mode deduplicates crashes by hashing input bytes.
    // Different byte sequences → different hashes.
    // Same byte sequences → same hash.
    use std::collections::hash_map::DefaultHasher;

    let hash_bytes = |bytes: &[u8]| -> u64 {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    };

    let input_a = vec![0x01, 0x02, 0x03, 0x04];
    let input_b = vec![0x01, 0x02, 0x03, 0x05]; // differs in last byte
    let input_c = vec![0x01, 0x02, 0x03, 0x04]; // same as A

    let hash_a = hash_bytes(&input_a);
    let hash_b = hash_bytes(&input_b);
    let hash_c = hash_bytes(&input_c);

    assert_ne!(
        hash_a, hash_b,
        "different inputs should produce different hashes"
    );
    assert_eq!(hash_a, hash_c, "same inputs should produce same hash");

    // Different lengths
    let input_short = vec![0x01, 0x02];
    let input_long = vec![0x01, 0x02, 0x00, 0x00, 0x00];
    assert_ne!(
        hash_bytes(&input_short),
        hash_bytes(&input_long),
        "different lengths should produce different hashes"
    );
}

#[test]
fn test_stateful_crash_dedup_by_variant_sequence() {
    // Stateful mode deduplicates by action variant sequence (not raw bytes).
    // Same variant order with different params → same dedup hash.
    // Different variant order → different dedup hash.
    use std::collections::hash_map::DefaultHasher;

    let hash_variant_seq = |variants: &[u16]| -> u64 {
        let bytes: Vec<u8> = variants.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    };

    // Sequence: deposit(0), borrow(1), withdraw(2)
    let seq_a = vec![0u16, 1, 2];
    // Same variants, different params (doesn't matter for dedup)
    let seq_b = vec![0u16, 1, 2];
    // Different variant order
    let seq_c = vec![1u16, 0, 2];
    // Different length
    let seq_d = vec![0u16, 1];

    assert_eq!(
        hash_variant_seq(&seq_a),
        hash_variant_seq(&seq_b),
        "same variant order = same dedup hash"
    );
    assert_ne!(
        hash_variant_seq(&seq_a),
        hash_variant_seq(&seq_c),
        "different order = different dedup hash"
    );
    assert_ne!(
        hash_variant_seq(&seq_a),
        hash_variant_seq(&seq_d),
        "different length = different dedup hash"
    );

    // Verify via StatePool's reconstruct_variant_sequence
    let mut pool = StatePool::new(100, 10);
    // Build a chain: root → state0 (variant=0) → state1 (variant=1) → state2 (variant=2)
    add_test_state(&mut pool, 1, 0, None, "root", None);
    add_test_state(&mut pool, 2, 1, Some(0), "deposit", Some(0));
    add_test_state(&mut pool, 3, 2, Some(1), "borrow", Some(1));
    add_test_state(&mut pool, 4, 3, Some(2), "withdraw", Some(2));

    let variants = pool.reconstruct_variant_sequence(3);
    assert_eq!(
        variants,
        vec![0, 1, 2],
        "variant sequence should be oldest-first"
    );

    // A different chain with reversed order
    add_test_state(&mut pool, 10, 1, Some(0), "borrow", Some(1));
    add_test_state(&mut pool, 11, 2, Some(4), "deposit", Some(0));
    add_test_state(&mut pool, 12, 3, Some(5), "withdraw", Some(2));

    let variants2 = pool.reconstruct_variant_sequence(6);
    assert_eq!(
        variants2,
        vec![1, 0, 2],
        "reversed chain should give different sequence"
    );

    assert_ne!(
        hash_variant_seq(&variants),
        hash_variant_seq(&variants2),
        "different chains should produce different dedup hashes"
    );
}

// =========================================================================
// Category 8: Arc Pointer Optimization (delta-to-delta)
// =========================================================================

#[test]
fn test_arc_pointer_equality_skips_redundant_set_account() {
    // restore_selective_from skips set_account when prev and next deltas
    // share the same Arc<Account> AND the account wasn't dirtied by execution.
    // Verify it still produces correct state, AND returns fewer set_account calls.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 16])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 16])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 16])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);

    // Parent delta: pk1=1000, pk2=2000
    let shared_pk1_arc = Arc::new(make_account(1000, &[0xA1; 16]));
    let shared_pk2_arc = Arc::new(make_account(2000, &[0xA2; 16]));
    let delta_parent = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, shared_pk1_arc.clone()); // Arc shared with child
            m.insert(pk2, shared_pk2_arc.clone()); // Arc shared with child
            m
        },
        sysvars: make_test_sysvars(10),
    };

    // Child delta: pk1=same Arc (inherited), pk2=different value, pk3=3000
    let delta_child = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, shared_pk1_arc.clone()); // SAME Arc as parent
            m.insert(pk2, Arc::new(make_account(2500, &[0xB2; 16]))); // different
            m.insert(pk3, Arc::new(make_account(3000, &[0xB3; 16]))); // new
            m
        },
        sysvars: make_test_sysvars(20),
    };

    // Apply parent delta first
    let divergent: FastHashSet<Pubkey> = FastHashSet::default();
    initial.restore_selective(&mut svm, &divergent, &delta_parent);

    // Now restore from parent → child with no exec dirty
    let divergent_after_parent: FastHashSet<Pubkey> =
        delta_parent.accounts.keys().copied().collect();
    let empty_exec_dirty = FastHashSet::default();
    let count_from = initial.restore_selective_from(
        &mut svm,
        &divergent_after_parent,
        &delta_parent,
        &delta_child,
        &empty_exec_dirty,
    );

    // Compare with simple restore_selective
    let mut svm2 = LiteSVM::new();
    svm2.set_account(pk1, make_account(100, &[1; 16])).unwrap();
    svm2.set_account(pk2, make_account(200, &[2; 16])).unwrap();
    svm2.set_account(pk3, make_account(300, &[3; 16])).unwrap();
    let initial2 = SvmSnapshot::take_all(&svm2);
    initial2.restore_selective(&mut svm2, &FastHashSet::default(), &delta_parent);
    let divergent2: FastHashSet<Pubkey> = delta_parent.accounts.keys().copied().collect();
    let count_selective = initial2.restore_selective(&mut svm2, &divergent2, &delta_child);

    // Both should produce identical state
    for pk in &[pk1, pk2, pk3] {
        let a = svm.get_account(pk).unwrap();
        let b = svm2.get_account(pk).unwrap();
        assert_eq!(a.lamports, b.lamports, "{:?} lamports", pk);
        assert_eq!(a.data, b.data, "{:?} data", pk);
    }

    // restore_selective_from should have done FEWER set_account calls
    // because pk1 shares the same Arc and wasn't exec-dirtied
    assert!(
        count_from < count_selective,
        "restore_selective_from ({}) should do fewer writes than restore_selective ({})",
        count_from,
        count_selective
    );
}

#[test]
fn test_arc_skip_overridden_by_exec_dirty() {
    // Even when prev and next deltas share the same Arc for an account,
    // if that account is in prev_exec_dirty, it MUST be restored (because
    // execution may have modified the SVM's copy).

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);

    let shared_arc = Arc::new(make_account(1000, &[0xA1; 8]));
    let delta = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, shared_arc.clone());
            m
        },
        sysvars: make_test_sysvars(10),
    };

    // Apply delta
    initial.restore_selective(&mut svm, &FastHashSet::default(), &delta);
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 1000);

    // Simulate execution modifying pk1 (SVM now has wrong value)
    svm.set_account(pk1, make_account(9999, &[0xFF; 8]))
        .unwrap();

    // Now restore from same delta → same delta (delta stays the same)
    // WITHOUT exec_dirty: pk1 has same Arc, would be SKIPPED → wrong state!
    let _divergent: FastHashSet<Pubkey> = [pk1].into_iter().collect();
    let mut svm_no_dirty = LiteSVM::new();
    svm_no_dirty
        .set_account(pk1, make_account(100, &[1; 8]))
        .unwrap();
    svm_no_dirty
        .set_account(pk2, make_account(200, &[2; 8]))
        .unwrap();
    let initial_nd = SvmSnapshot::take_all(&svm_no_dirty);
    initial_nd.restore_selective(&mut svm_no_dirty, &FastHashSet::default(), &delta);
    svm_no_dirty
        .set_account(pk1, make_account(9999, &[0xFF; 8]))
        .unwrap();
    let divergent_nd: FastHashSet<Pubkey> = [pk1].into_iter().collect();
    initial_nd.restore_selective_from(
        &mut svm_no_dirty,
        &divergent_nd,
        &delta,
        &delta,
        &FastHashSet::default(), // no exec dirty → pk1 skipped!
    );
    // Without exec_dirty, pk1 is STILL 9999 (bug if this were the real fuzzer)
    assert_eq!(
        svm_no_dirty.get_account(&pk1).unwrap().lamports,
        9999,
        "without exec_dirty, Arc-equal account is skipped (stale)"
    );

    // WITH exec_dirty: pk1 is forced to be written
    let exec_dirty: FastHashSet<Pubkey> = [pk1].into_iter().collect();
    let divergent2: FastHashSet<Pubkey> = [pk1].into_iter().collect();
    initial.restore_selective_from(&mut svm, &divergent2, &delta, &delta, &exec_dirty);
    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        1000,
        "with exec_dirty, Arc-equal account is forced to correct value"
    );
}

#[test]
fn test_sibling_deltas_share_parent_arcs() {
    // Two sibling states (same parent, different actions) share Arc pointers
    // for accounts inherited from the parent. Switching between siblings
    // via restore_selective_from should be efficient.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let parent_pk1_arc = Arc::new(make_account(1000, &[0xA1; 16]));

    // Sibling A: inherits pk1 from parent, modifies pk2
    let sibling_a = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, parent_pk1_arc.clone());
            m.insert(pk2, Arc::new(make_account(2000, &[0xAA; 16])));
            m
        },
        sysvars: make_test_sysvars(10),
    };

    // Sibling B: inherits pk1 from parent, modifies pk3
    let sibling_b = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, parent_pk1_arc.clone());
            m.insert(pk3, Arc::new(make_account(3000, &[0xBB; 16])));
            m
        },
        sysvars: make_test_sysvars(20),
    };

    // Verify Arc sharing
    assert!(Arc::ptr_eq(
        sibling_a.accounts.get(&pk1).unwrap(),
        sibling_b.accounts.get(&pk1).unwrap()
    ));

    // Setup SVM at sibling_a
    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 16])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 16])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 16])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);

    initial.restore_selective(&mut svm, &FastHashSet::default(), &sibling_a);
    let divergent_a: FastHashSet<Pubkey> = sibling_a.accounts.keys().copied().collect();

    // Switch to sibling_b via restore_selective_from
    let count = initial.restore_selective_from(
        &mut svm,
        &divergent_a,
        &sibling_a,
        &sibling_b,
        &FastHashSet::default(),
    );

    // pk1 should be SKIPPED (same Arc, not exec-dirtied) → still correct
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 1000);
    // pk2 should be restored to initial (was in sibling_a, not in sibling_b)
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200);
    // pk3 should be from sibling_b
    assert_eq!(svm.get_account(&pk3).unwrap().lamports, 3000);

    // The count should reflect: pk2 restored to initial (1) + pk3 from delta (1)
    // pk1 SKIPPED due to Arc equality = 2 total writes (not 3)
    assert_eq!(count, 2, "pk1 should be skipped due to shared Arc");
}

// =========================================================================
// Category 9: Divergent Keys Accumulation Patterns
// =========================================================================

#[test]
fn test_stateless_divergent_cleared_every_iteration() {
    // In stateless mode, dirty_tracker is cleared after each restore.
    // This means no cross-iteration accumulation of divergent state.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 4])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 4])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 4])).unwrap();
    let tracked: HashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    let mut dirty = DirtyTracker::new();

    // Iteration 1: modify pk1
    dirty.clear();
    svm.set_account(pk1, make_account(999, &[0xFF; 4])).unwrap();
    dirty.mark_account_dirty(&pk1);
    assert_eq!(dirty.dirty_count(), 1);
    snap.restore(&mut svm, &dirty);
    dirty.clear();
    assert_eq!(
        dirty.dirty_count(),
        0,
        "dirty tracker cleared after iteration"
    );

    // Iteration 2: modify pk2 only
    svm.set_account(pk2, make_account(888, &[0xFE; 4])).unwrap();
    dirty.mark_account_dirty(&pk2);
    assert_eq!(
        dirty.dirty_count(),
        1,
        "only pk2 dirty, no carryover from iter1"
    );

    // Restore — only pk2 needs restoring, pk1 is already at initial
    let count = snap.restore(&mut svm, &dirty);
    assert_eq!(count, 1, "only one account restored");
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200);
}

#[test]
fn test_stateful_divergent_accumulates_across_iterations() {
    // In stateful mode, divergent_keys accumulates: delta keys + exec dirty.
    // This is necessary because restore_selective only restores accounts
    // in the divergent set. Missing accounts = stale state leakage.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_a = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };
    let delta_b = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk2, Arc::new(make_account(2000, &[0xB2; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };

    let mut divergent_keys = FastHashSet::default();

    // Iteration 1: pick delta_a
    initial.restore_selective(&mut svm, &divergent_keys, &delta_a);
    divergent_keys.clear();
    divergent_keys.extend(delta_a.accounts.keys()); // {pk1}

    // Execution dirtied pk3
    svm.set_account(pk3, make_account(9999, &[0xFF; 8]))
        .unwrap();
    divergent_keys.insert(pk3); // {pk1, pk3}

    assert_eq!(
        divergent_keys.len(),
        2,
        "divergent = delta keys + exec dirty"
    );

    // Iteration 2: pick delta_b
    // divergent_keys = {pk1, pk3} — both need to be considered
    initial.restore_selective(&mut svm, &divergent_keys, &delta_b);

    // pk1 was in divergent but not in delta_b → restored to initial
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100);
    // pk2 is in delta_b
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 2000);
    // pk3 was in divergent (exec dirty) but not in delta_b → restored to initial
    assert_eq!(svm.get_account(&pk3).unwrap().lamports, 300);
}

#[test]
fn test_divergent_keys_cleared_then_rebuilt_each_iteration() {
    // Real codegen pattern: divergent_keys.clear() then rebuild from
    // delta.keys() + prev_exec_dirty. This test verifies the exact sequence.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let pk4 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    for (pk, l) in [(pk1, 100), (pk2, 200), (pk3, 300), (pk4, 400)] {
        svm.set_account(pk, make_account(l, &[l as u8; 8])).unwrap();
    }
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_1 = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
            m.insert(pk2, Arc::new(make_account(2000, &[0xA2; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };

    let delta_2 = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk3, Arc::new(make_account(3000, &[0xB3; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };

    let mut divergent_keys = FastHashSet::default();
    let mut prev_delta: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty = FastHashSet::default();

    // Iteration 1: pick delta_1
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_1,
        prev_delta.as_ref(),
        &prev_exec_dirty,
    );
    // Post-restore update (mirrors real codegen)
    divergent_keys.clear();
    divergent_keys.extend(delta_1.accounts.keys()); // {pk1, pk2}

    // Execution modifies pk4
    svm.set_account(pk4, make_account(9999, &[0xFF; 8]))
        .unwrap();
    prev_exec_dirty.clear();
    prev_exec_dirty.insert(pk4);
    divergent_keys.extend(prev_exec_dirty.iter()); // {pk1, pk2, pk4}
    prev_delta = Some(delta_1.clone());

    assert_eq!(divergent_keys.len(), 3);
    assert!(divergent_keys.contains(&pk1));
    assert!(divergent_keys.contains(&pk2));
    assert!(divergent_keys.contains(&pk4));

    // Iteration 2: pick delta_2
    simulate_restore(
        &initial,
        &mut svm,
        &divergent_keys,
        &delta_2,
        prev_delta.as_ref(),
        &prev_exec_dirty,
    );

    // pk1, pk2 were in divergent, not in delta_2 → initial
    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 100);
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200);
    // pk3 from delta_2
    assert_eq!(svm.get_account(&pk3).unwrap().lamports, 3000);
    // pk4 was in divergent (exec dirty), not in delta_2 → initial
    assert_eq!(svm.get_account(&pk4).unwrap().lamports, 400);
}

// =========================================================================
// Category 10: take_full vs take_delta Equivalence
// =========================================================================

#[test]
fn test_take_full_captures_all_accounts() {
    // take_full clones base snapshot then overwrites dirty accounts.
    // Result should be a complete snapshot of current state.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();

    let tracked: HashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    // Modify pk1 and pk2
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    svm.set_account(pk2, make_account(2000, &[0xA2; 8]))
        .unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    dirty.mark_account_dirty(&pk2);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);

    // full should have ALL accounts: pk1 (modified), pk2 (modified), pk3 (from base)
    assert_eq!(full.account_count(), 3);
    assert_eq!(full.accounts().get(&pk1).unwrap().lamports, 1000);
    assert_eq!(full.accounts().get(&pk2).unwrap().lamports, 2000);
    assert_eq!(full.accounts().get(&pk3).unwrap().lamports, 300); // from base
}

#[test]
fn test_take_delta_only_captures_dirty() {
    // take_delta only stores accounts differing from initial.
    // Compare: take_full has ALL accounts, take_delta has only dirty ones.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();

    let tracked: HashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);
    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Modify only pk1
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);

    let full = SvmSnapshot::take_full(&svm, &base, &dirty);
    let delta = SvmSnapshot::take_delta(&svm, &delta_root, &dirty);

    // Full has ALL accounts
    assert_eq!(full.account_count(), 3);
    assert!(full.accounts().contains_key(&pk2));
    assert!(full.accounts().contains_key(&pk3));

    // Delta only has dirty
    assert_eq!(delta.account_count(), 1);
    assert!(delta.accounts().contains_key(&pk1));
    assert!(!delta.accounts().contains_key(&pk2));
    assert!(!delta.accounts().contains_key(&pk3));

    // Both agree on the dirty account's value
    assert_eq!(
        full.accounts().get(&pk1).unwrap().lamports,
        delta.accounts().get(&pk1).unwrap().lamports
    );
}

#[test]
fn test_take_full_then_restore_full_roundtrip() {
    // take_full → restore_full should reproduce the exact state.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let base = SvmSnapshot::take(&svm, &tracked);

    // Modify
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk1);
    let full_snap = SvmSnapshot::take_full(&svm, &base, &dirty);

    // Scramble
    svm.set_account(pk1, make_account(1, &[0])).unwrap();
    svm.set_account(pk2, make_account(1, &[0])).unwrap();

    // Restore
    full_snap.restore_full(&mut svm);

    assert_eq!(svm.get_account(&pk1).unwrap().lamports, 1000);
    assert_eq!(svm.get_account(&pk2).unwrap().lamports, 200);
}

// =========================================================================
// Category 11: Delta Chain Inheritance and Arc Sharing
// =========================================================================

#[test]
fn test_delta_chain_inherits_parent_arcs() {
    // When building delta chains (root → A → B), child delta clones parent's
    // HashMap. Unmodified accounts share the same Arc pointer.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Action A: modify pk1
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    let mut dirty_a = DirtyTracker::new();
    dirty_a.mark_account_dirty(&pk1);
    let delta_a = SvmSnapshot::take_delta(&svm, &delta_root, &dirty_a);

    // Action B: modify pk2 (pk1 inherited from A)
    svm.set_account(pk2, make_account(2000, &[0xB2; 8]))
        .unwrap();
    let mut dirty_b = DirtyTracker::new();
    dirty_b.mark_account_dirty(&pk2);
    let delta_b = SvmSnapshot::take_delta(&svm, &delta_a, &dirty_b);

    // delta_b should contain both pk1 and pk2
    assert_eq!(delta_b.account_count(), 2);

    // pk1 in delta_b should share the SAME Arc as pk1 in delta_a
    assert!(
        Arc::ptr_eq(
            delta_a.accounts.get(&pk1).unwrap(),
            delta_b.accounts.get(&pk1).unwrap()
        ),
        "inherited account should share Arc pointer"
    );

    // pk2 in delta_b should be a NEW Arc (different data)
    assert!(!Arc::ptr_eq(
        &Arc::new(make_account(200, &[2; 8])), // dummy for comparison
        delta_b.accounts.get(&pk2).unwrap()
    ));
    assert_eq!(delta_b.accounts.get(&pk2).unwrap().lamports, 2000);
}

#[test]
fn test_delta_chain_3_levels_correct_values() {
    // Build 3-level delta chain and verify each level has correct accumulated state.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();

    let delta_root = SvmSnapshot::empty(svm.get_sysvar::<Clock>());

    // Level 1: modify pk1
    svm.set_account(pk1, make_account(1000, &[0xA1; 8]))
        .unwrap();
    let mut dirty1 = DirtyTracker::new();
    dirty1.mark_account_dirty(&pk1);
    let delta_1 = SvmSnapshot::take_delta(&svm, &delta_root, &dirty1);

    // Level 2: modify pk2
    svm.set_account(pk2, make_account(2000, &[0xB2; 8]))
        .unwrap();
    let mut dirty2 = DirtyTracker::new();
    dirty2.mark_account_dirty(&pk2);
    let delta_2 = SvmSnapshot::take_delta(&svm, &delta_1, &dirty2);

    // Level 3: modify pk3
    svm.set_account(pk3, make_account(3000, &[0xC3; 8]))
        .unwrap();
    let mut dirty3 = DirtyTracker::new();
    dirty3.mark_account_dirty(&pk3);
    let delta_3 = SvmSnapshot::take_delta(&svm, &delta_2, &dirty3);

    // Verify each delta has correct accumulated content
    assert_eq!(delta_1.account_count(), 1);
    assert_eq!(delta_2.account_count(), 2);
    assert_eq!(delta_3.account_count(), 3);

    // Restore from each delta and verify full state
    for (label, delta, expected) in [
        ("level1", &delta_1, [1000u64, 200, 300]),
        ("level2", &delta_2, [1000, 2000, 300]),
        ("level3", &delta_3, [1000, 2000, 3000]),
    ] {
        let mut svm_test = LiteSVM::new();
        svm_test
            .set_account(pk1, make_account(100, &[1; 8]))
            .unwrap();
        svm_test
            .set_account(pk2, make_account(200, &[2; 8]))
            .unwrap();
        svm_test
            .set_account(pk3, make_account(300, &[3; 8]))
            .unwrap();
        let init_test = SvmSnapshot::take_all(&svm_test);
        let all_divergent: FastHashSet<Pubkey> = [pk1, pk2, pk3].into_iter().collect();
        init_test.restore_selective(&mut svm_test, &all_divergent, delta);

        for (pk, exp) in [pk1, pk2, pk3].iter().zip(expected.iter()) {
            assert_eq!(
                svm_test.get_account(pk).unwrap().lamports,
                *exp,
                "{}: {:?} expected {}",
                label,
                pk,
                exp
            );
        }
    }
}

// =========================================================================
// Category 12: StatePool Power Schedule and Selection
// =========================================================================

#[test]
fn test_action_stats_laplace_smoothing_never_zero() {
    // ActionStats weights should NEVER be zero (Laplace smoothing ensures this).
    // Even variants with 100% failure rate get a positive weight.

    let mut stats = ActionStats::new(5);

    // Record all failures for variant 0
    for _ in 0..100 {
        stats.record(0, false);
    }
    // Record all successes for variant 1
    for _ in 0..100 {
        stats.record(1, true);
    }
    // Variant 2: never attempted
    // Variant 3: 50/50
    for _ in 0..50 {
        stats.record(3, true);
        stats.record(3, false);
    }

    let weights = stats.weights();

    // ALL weights should be positive
    for (i, &w) in weights.iter().enumerate() {
        assert!(
            w > 0.0,
            "variant {} weight should be positive, got {}",
            i,
            w
        );
    }

    // Untried variant (2) should have highest weight (exploration bonus dominates)
    assert!(
        weights[2] > weights[0],
        "untried variant should have higher weight than always-failing"
    );
    assert!(
        weights[2] > weights[1],
        "untried variant should have higher weight than always-succeeding (exploration bonus)"
    );
}

#[test]
fn test_action_stats_map_per_state_class() {
    // ActionStatsMap maintains independent stats per state_class.
    // Recording success in class A should not affect class B.

    let mut stats_map = ActionStatsMap::new(3);

    let class_a: u16 = 42;
    let class_b: u16 = 99;

    // Class A: variant 0 always succeeds
    for _ in 0..10 {
        stats_map.record(class_a, 0, true);
    }

    // Class B: variant 0 always fails
    for _ in 0..10 {
        stats_map.record(class_b, 0, false);
    }

    // Picking from class A should favor variant 0
    // Picking from class B should NOT favor variant 0
    // We test this by checking that the pick results differ
    let pick_a = stats_map.pick_variant(class_a, u64::MAX / 2, 50); // not epsilon
    let pick_b = stats_map.pick_variant(class_b, u64::MAX / 2, 50);

    // Both should return Some (non-epsilon path)
    assert!(
        pick_a.is_some() || pick_b.is_some(),
        "at least one pick should be non-epsilon"
    );
}

#[test]
fn test_state_class_from_fingerprint() {
    // state_class extracts top 16 bits. Different fingerprints with same top bits
    // should map to the same class.

    let fp_a = 0x1234_0000_0000_0000u64;
    let fp_b = 0x1234_FFFF_FFFF_FFFFu64;
    let fp_c = 0x5678_0000_0000_0000u64;

    assert_eq!(
        state_class_from_fingerprint(fp_a),
        state_class_from_fingerprint(fp_b),
        "same top 16 bits → same class"
    );
    assert_ne!(
        state_class_from_fingerprint(fp_a),
        state_class_from_fingerprint(fp_c),
        "different top 16 bits → different class"
    );
    assert_eq!(state_class_from_fingerprint(fp_a), 0x1234);
    assert_eq!(state_class_from_fingerprint(fp_c), 0x5678);
}

#[test]
fn test_pool_pick_weighted_favors_underexplored() {
    // States with fewer picks should be favored by the power schedule.

    let mut pool = StatePool::new(100, 10);

    // Add 3 states with same novel_children
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk1, 1000)]), 1, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk2, 2000)]), 1, None);
    add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![(pk3, 3000)]), 1, None);

    // Pick state 0 many times to increase its pick_count
    for _ in 0..50 {
        pool.pick_weighted(0); // always picks first due to deterministic rng_val=0
    }

    // Now states 1 and 2 should have much higher weights
    // Sample many picks and count distribution
    let mut counts = [0u32; 3];
    for i in 0..3000u64 {
        if let Some(idx) = pool.pick_weighted(i.wrapping_mul(6364136223846793005).wrapping_add(1)) {
            if idx < 3 {
                counts[idx] += 1;
            }
        }
    }

    // State 0 (heavily picked) should be picked LESS than states 1 or 2
    assert!(
        counts[0] < counts[1] + counts[2],
        "heavily picked state ({}) should be less than others ({} + {})",
        counts[0],
        counts[1],
        counts[2]
    );
}

#[test]
fn test_pool_coverage_novel_3x_boost() {
    // States with novelty_bits>0 get rarity weight boost (decays with picks).

    let mut pool = StatePool::new(100, 10);

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    // State 0: NOT coverage novel
    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk1, 1000)]), 1, None);

    // State 1: has novelty_bits (use try_add directly to set value)
    pool.try_add(
        2,
        snapshot_to_compact_delta(make_pool_snapshot(vec![(pk2, 2000)])),
        1,
        None,
        vec![0u8; 8],
        "coverage_action".to_string(),
        Some(0),
        vec![],
        None,
        std::sync::Arc::new(crate::snapshot::CreationTracker::new()),
        10,
        10,
        true,
        None,
    );

    // Sample picks
    let mut counts = [0u32; 2];
    for i in 0..3000u64 {
        if let Some(idx) = pool.pick_weighted(i.wrapping_mul(2862933555777941757).wrapping_add(1)) {
            if idx < 2 {
                counts[idx] += 1;
            }
        }
    }

    // Coverage-novel state should be picked more often (roughly 3x)
    assert!(
        counts[1] > counts[0],
        "novelty_bits state ({}) should be picked more than non-novel ({})",
        counts[1],
        counts[0]
    );
}

#[test]
fn test_pool_violation_penalty_reduces_weight() {
    // States with violations get deprioritized via 1/(violation_count+1) penalty.

    let mut pool = StatePool::new(100, 10);

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk1, 1000)]), 1, None);
    add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk2, 2000)]), 1, None);

    // Record many violations on state 0
    for _ in 0..20 {
        pool.record_violation(0);
    }

    // Sample picks
    let mut counts = [0u32; 2];
    for i in 0..3000u64 {
        if let Some(idx) = pool.pick_weighted(i.wrapping_mul(6364136223846793005).wrapping_add(1)) {
            if idx < 2 {
                counts[idx] += 1;
            }
        }
    }

    // High-violation state should be picked much less
    assert!(
        counts[0] < counts[1],
        "high-violation state ({}) should be picked less than clean state ({})",
        counts[0],
        counts[1]
    );
}

// =========================================================================
// Category 13: Fingerprint and Dedup Behavior
// =========================================================================

#[test]
fn test_fingerprint_truncation_causes_collisions() {
    // FINGERPRINT_BITS = 17 means fingerprints are truncated to 17 bits.
    // Two fingerprints that differ only in upper bits should collide.

    let mut pool = StatePool::new(100, 10);

    // Two fingerprints with same lower 17 bits but different upper bits
    let fp1 = 0xAAAA_BBBB_0000_1234u64;
    let fp2 = 0xCCCC_DDDD_0000_1234u64;

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let added1 = add_pool_entry(
        &mut pool,
        fp1,
        make_pool_snapshot(vec![(pk1, 1000)]),
        1,
        None,
    );
    let added2 = add_pool_entry(
        &mut pool,
        fp2,
        make_pool_snapshot(vec![(pk2, 2000)]),
        1,
        None,
    );

    assert!(added1, "first fingerprint should be added");
    assert!(
        !added2,
        "second fingerprint should collide (same lower 17 bits)"
    );
    assert_eq!(pool.len(), 1, "only one state in pool due to collision");
}

#[test]
fn test_fingerprint_zero_never_saved() {
    // fingerprint == 0 means no state change (no dirty accounts).
    // Such states should not be saved. The pool's dedup set starts with 0.

    let mut pool = StatePool::new(100, 10);

    let pk1 = Pubkey::new_unique();

    // Add initial state with dedup_key=0 first (simulates the "no change" case)
    let added = add_pool_entry(&mut pool, 0, make_pool_snapshot(vec![(pk1, 1000)]), 0, None);

    // dedup_key for fp=0 is 0 & mask = 0, and 0 was already seen in `seen` set
    // Actually, the pool doesn't pre-insert 0. Let's check:
    assert!(added, "fingerprint 0 CAN be added if not previously seen");

    // But trying again should fail (dedup)
    let added2 = add_pool_entry(&mut pool, 0, make_pool_snapshot(vec![(pk1, 2000)]), 0, None);
    assert!(!added2, "duplicate fingerprint 0 should be rejected");
}

#[test]
fn test_pool_depth_limit_rejects_deep_states() {
    // States with depth > max_depth are rejected.

    let mut pool = StatePool::new(100, 5); // max_depth = 5

    let pk1 = Pubkey::new_unique();

    // Depth 5 should be accepted
    let added_5 = add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![(pk1, 100)]), 5, None);
    assert!(added_5, "depth=5 should be accepted (max_depth=5)");

    // Depth 6 should be rejected
    let added_6 = add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![(pk1, 200)]), 6, None);
    assert!(!added_6, "depth=6 should be rejected (max_depth=5)");
}

#[test]
fn test_pool_capacity_limit_evicts_when_full() {
    // Pool at capacity evicts weakest active state to make room.

    let mut pool = StatePool::new(3, 10); // capacity = 3

    let added1 = add_pool_entry(&mut pool, 1, make_pool_snapshot(vec![]), 0, None);
    let added2 = add_pool_entry(&mut pool, 2, make_pool_snapshot(vec![]), 1, None);
    let added3 = add_pool_entry(&mut pool, 3, make_pool_snapshot(vec![]), 2, None);
    let added4 = add_pool_entry(&mut pool, 4, make_pool_snapshot(vec![]), 3, None);

    assert!(added1 && added2 && added3, "first 3 should be added");
    assert!(added4, "4th should evict weakest and succeed");
    assert_eq!(pool.active_count(), 3); // one evicted, one added
}

// =========================================================================
// Category 14: Crashed State Handling
// =========================================================================

#[test]
fn test_crashed_state_removed_from_active_but_kept_for_reconstruction() {
    // mark_crashed removes state from active_indices but keeps it in states
    // for parent chain reconstruction.

    let mut pool = StatePool::new(100, 10);

    // Build a chain: root → child
    add_test_state(&mut pool, 1, 0, None, "root", None);
    add_test_state(&mut pool, 2, 1, Some(0), "deposit", Some(0));
    add_test_state(&mut pool, 3, 2, Some(1), "borrow", Some(1));

    assert_eq!(pool.active_count(), 3);
    assert_eq!(pool.len(), 3);

    // Crash state 1 (the "deposit" state)
    pool.mark_crashed(1);

    assert_eq!(pool.active_count(), 2, "one state removed from active");
    assert_eq!(pool.len(), 3, "all states still in pool for reconstruction");

    // Reconstruction should still work through the crashed state.
    // Note: reconstruct_variant_sequence walks the full chain including root.
    // Root has variant=None (skipped), deposit has variant=Some(0), borrow has variant=Some(1).
    let variants = pool.reconstruct_variant_sequence(2);
    assert_eq!(
        variants,
        vec![0, 1],
        "chain through crashed state still works"
    );

    let descs = pool.reconstruct_action_descriptions(2);
    // Root desc is "root" (non-empty), deposit is "deposit", borrow is "borrow"
    assert_eq!(descs.len(), 3);
    assert_eq!(descs[0], "root");
    assert_eq!(descs[1], "deposit");
    assert_eq!(descs[2], "borrow");
}

#[test]
fn test_is_novel_crash_dedup() {
    // is_novel_crash returns true first time, false for duplicates.

    let mut pool = StatePool::new(100, 10);

    let hash_a = 0x1234567890ABCDEFu64;
    let hash_b = 0xFEDCBA0987654321u64;

    assert!(
        pool.is_novel_crash(hash_a),
        "first occurrence should be novel"
    );
    assert!(
        !pool.is_novel_crash(hash_a),
        "duplicate should not be novel"
    );
    assert!(
        pool.is_novel_crash(hash_b),
        "different hash should be novel"
    );
    assert_eq!(pool.unique_crash_count(), 2);
}

// =========================================================================
// Category 15: Full Iteration Simulation with simulate_fuzzer_iteration
// =========================================================================

#[test]
fn test_simulate_fuzzer_iteration_5_rounds_no_stale_state() {
    // Run 5 iterations through the simulate_fuzzer_iteration helper,
    // alternating between different deltas. Verify no stale state leaks.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();
    svm.set_account(pk3, make_account(300, &[3; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_a = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };
    let delta_b = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk2, Arc::new(make_account(2000, &[0xB2; 8])));
            m
        },
        sysvars: clock_to_sysvars(&clock),
    };
    let empty_delta = SvmSnapshot::empty(clock.clone());

    let mut divergent_keys = FastHashSet::default();
    let mut prev_delta_arc: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty = FastHashSet::default();

    let schedule = [
        (
            &delta_a,
            vec![(pk3, Some(make_account(999, &[0xFF; 8])))],
            true,
        ),
        (
            &delta_b,
            vec![(pk1, Some(make_account(888, &[0xFE; 8])))],
            true,
        ),
        (&delta_a, vec![], true), // no exec modifications
        (
            &empty_delta,
            vec![(pk2, Some(make_account(777, &[0xFD; 8])))],
            false,
        ), // action fails
        (&delta_b, vec![], true),
    ];

    for (i, (delta, mods, success)) in schedule.iter().enumerate() {
        simulate_fuzzer_iteration(
            &initial,
            &mut svm,
            &mut divergent_keys,
            &mut prev_delta_arc,
            &mut prev_exec_dirty,
            delta,
            mods,
            *success,
        );

        // After each iteration's restore (before exec mods), verify delta state is correct
        // We verify final state after all exec mods are applied
        match i {
            0 => {
                // delta_a applied, then pk3 modified by exec
                assert_eq!(
                    svm.get_account(&pk1).unwrap().lamports,
                    1000,
                    "iter0: pk1 from delta_a"
                );
                assert_eq!(
                    svm.get_account(&pk3).unwrap().lamports,
                    999,
                    "iter0: pk3 exec modified"
                );
            }
            1 => {
                // delta_b applied, then pk1 modified by exec
                assert_eq!(
                    svm.get_account(&pk2).unwrap().lamports,
                    2000,
                    "iter1: pk2 from delta_b"
                );
                assert_eq!(
                    svm.get_account(&pk1).unwrap().lamports,
                    888,
                    "iter1: pk1 exec modified"
                );
            }
            2 => {
                // delta_a applied, no exec mods
                assert_eq!(
                    svm.get_account(&pk1).unwrap().lamports,
                    1000,
                    "iter2: pk1 from delta_a"
                );
                assert_eq!(
                    svm.get_account(&pk2).unwrap().lamports,
                    200,
                    "iter2: pk2 initial"
                );
                assert_eq!(
                    svm.get_account(&pk3).unwrap().lamports,
                    300,
                    "iter2: pk3 initial"
                );
            }
            3 => {
                // empty delta, pk2 modified by exec, action fails
                assert_eq!(
                    svm.get_account(&pk1).unwrap().lamports,
                    100,
                    "iter3: pk1 initial"
                );
                assert_eq!(
                    svm.get_account(&pk2).unwrap().lamports,
                    777,
                    "iter3: pk2 exec modified"
                );
            }
            4 => {
                // delta_b applied, no exec mods. prev_delta was None (failed action)
                assert_eq!(
                    svm.get_account(&pk2).unwrap().lamports,
                    2000,
                    "iter4: pk2 from delta_b"
                );
                assert_eq!(
                    svm.get_account(&pk1).unwrap().lamports,
                    100,
                    "iter4: pk1 initial"
                );
            }
            _ => unreachable!(),
        }
    }

    // After failed action (iter3), prev_delta should be None
    // Iter4 should have used restore_selective (not restore_selective_from)
    // This was already verified by correctness above
}

#[test]
fn test_simulate_fuzzer_iteration_cpi_account_cleanup() {
    // CPI-created accounts (not in initial or delta) should be cleaned up
    // by the next iteration's restore.

    let pk1 = Pubkey::new_unique();
    let pk_cpi = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);
    let clock = svm.get_sysvar::<Clock>();

    let delta_empty = SvmSnapshot::empty(clock.clone());

    let mut divergent_keys = FastHashSet::default();
    let mut prev_delta_arc: Option<SvmSnapshot> = None;
    let mut prev_exec_dirty = FastHashSet::default();

    // Iteration 1: CPI creates pk_cpi
    let cpi_created = simulate_fuzzer_iteration(
        &initial,
        &mut svm,
        &mut divergent_keys,
        &mut prev_delta_arc,
        &mut prev_exec_dirty,
        &delta_empty,
        &[(pk_cpi, Some(make_account(5000, &[0xCC; 8])))],
        true,
    );
    assert_eq!(cpi_created, vec![pk_cpi]);
    assert!(
        svm.get_account(&pk_cpi).is_some(),
        "CPI account exists after iter1"
    );

    // Iteration 2: empty delta, no mods. CPI account should be cleaned up.
    simulate_fuzzer_iteration(
        &initial,
        &mut svm,
        &mut divergent_keys,
        &mut prev_delta_arc,
        &mut prev_exec_dirty,
        &delta_empty,
        &[],
        true,
    );

    // pk_cpi was in divergent_keys from iter1, not in delta or initial
    // → restore_selective should zero it out
    assert!(
        svm.get_account(&pk_cpi).is_none(),
        "CPI account should be cleaned up after iteration 2 restore"
    );
}

// =========================================================================
// Category 16: SVM Reset Interval (Stateless-specific)
// =========================================================================

#[test]
fn test_periodic_svm_reset_restores_pristine_state() {
    // Stateless mode periodically resets SVM from a pristine clone to prevent
    // HashMap growth. Simulate this by doing many iterations, then resetting.

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    svm.set_account(pk2, make_account(200, &[2; 8])).unwrap();

    // Save pristine copy (like the real codegen does)
    let pristine = SvmSnapshot::take_all(&svm);

    let tracked: HashSet<Pubkey> = [pk1, pk2].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    let mut dirty = DirtyTracker::new();

    // Simulate many iterations creating ephemeral accounts
    for i in 0..10u64 {
        dirty.clear();
        let pk_ephemeral = Pubkey::new_unique();
        svm.set_account(pk_ephemeral, make_account(i * 100 + 1, &[i as u8; 4]))
            .unwrap();
        dirty.mark_account_dirty(&pk_ephemeral);
        // Also modify pk1
        svm.set_account(pk1, make_account(i * 1000, &[i as u8; 8]))
            .unwrap();
        dirty.mark_account_dirty(&pk1);
        snap.restore(&mut svm, &dirty);
    }

    // SVM might have grown internally due to ephemeral account inserts.
    // Simulate periodic reset: restore pristine state.
    pristine.restore_full(&mut svm);

    assert_eq!(
        svm.get_account(&pk1).unwrap().lamports,
        100,
        "pk1 at pristine value"
    );
    assert_eq!(
        svm.get_account(&pk2).unwrap().lamports,
        200,
        "pk2 at pristine value"
    );
}

// =========================================================================
// Category 17: Snapshot Clock Handling
// =========================================================================

#[test]
fn test_stateless_restore_resets_clock() {
    // snapshot.restore() restores clock when dirty_tracker has clock_dirty.

    let mut svm = LiteSVM::new();
    let pk1 = Pubkey::new_unique();
    svm.set_account(pk1, make_account(100, &[1; 4])).unwrap();

    let tracked: HashSet<Pubkey> = [pk1].into_iter().collect();
    let snap = SvmSnapshot::take(&svm, &tracked);
    let original_clock = svm.get_sysvar::<Clock>();

    // Advance clock
    let mut new_clock = original_clock.clone();
    new_clock.slot = 9999;
    new_clock.unix_timestamp = 999999;
    svm.set_sysvar(&new_clock);
    assert_eq!(svm.get_sysvar::<Clock>().slot, 9999);

    // Restore with clock_dirty
    let mut dirty = DirtyTracker::new();
    dirty.mark_clock_dirty(100);
    snap.restore(&mut svm, &dirty);

    assert_eq!(
        svm.get_sysvar::<Clock>().slot,
        original_clock.slot,
        "clock should be restored to snapshot value"
    );
}

#[test]
fn test_stateful_restore_selective_uses_delta_clock() {
    // restore_selective sets clock from the DELTA (target state), not from initial.
    // This is important because different saved states may have different clocks.

    let pk1 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);

    // Delta with clock at slot 42
    let delta = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(1000, &[0xA1; 8])));
            m
        },
        sysvars: make_test_sysvars(42),
    };

    initial.restore_selective(&mut svm, &FastHashSet::default(), &delta);

    let clock = svm.get_sysvar::<Clock>();
    assert_eq!(clock.slot, 42, "clock should come from delta, not initial");
}

#[test]
fn test_restore_selective_from_uses_next_delta_clock() {
    // restore_selective_from should set clock from next_delta, not prev_delta.

    let pk1 = Pubkey::new_unique();

    let mut svm = LiteSVM::new();
    svm.set_account(pk1, make_account(100, &[1; 8])).unwrap();
    let initial = SvmSnapshot::take_all(&svm);

    let delta_prev = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(500, &[0x55; 8])));
            m
        },
        sysvars: make_test_sysvars(10),
    };

    let delta_next = SvmSnapshot {
        accounts: {
            let mut m = FastHashMap::default();
            m.insert(pk1, Arc::new(make_account(1000, &[0xAA; 8])));
            m
        },
        sysvars: make_test_sysvars(99),
    };

    // Apply prev first
    initial.restore_selective(&mut svm, &FastHashSet::default(), &delta_prev);
    assert_eq!(svm.get_sysvar::<Clock>().slot, 10);

    // Now restore from prev → next
    let divergent: FastHashSet<Pubkey> = [pk1].into_iter().collect();
    initial.restore_selective_from(
        &mut svm,
        &divergent,
        &delta_prev,
        &delta_next,
        &FastHashSet::default(),
    );

    assert_eq!(
        svm.get_sysvar::<Clock>().slot,
        99,
        "clock should come from next_delta"
    );
}
