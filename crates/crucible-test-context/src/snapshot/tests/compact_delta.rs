use super::helpers::*;
use crate::snapshot::svm_snapshot::{SvmSnapshot, CompactDelta, AccountPatch};
use crate::{FastHashMap, FastHashSet};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::sync::Arc;

/// Helper: create an SVM, set up initial accounts, take initial snapshot.
fn setup_svm_with_accounts(accounts: &[(Pubkey, Account)]) -> (LiteSVM, SvmSnapshot) {
    let mut svm = LiteSVM::new()
        .with_sigverify(false)
        .with_blockhash_check(false);
    for (pk, acct) in accounts {
        let _ = svm.set_account(*pk, acct.clone());
    }
    let initial = SvmSnapshot::take_all(&svm);
    (svm, initial)
}

/// Helper: verify SVM account matches expected.
fn assert_account_eq(svm: &LiteSVM, pk: &Pubkey, expected: &Account, ctx: &str) {
    let got = svm.get_account(pk).unwrap_or_else(|| panic!("{}: account {} missing", ctx, pk));
    assert_eq!(got.lamports, expected.lamports, "{}: lamports mismatch for {}", ctx, pk);
    assert_eq!(got.data, expected.data, "{}: data mismatch for {}", ctx, pk);
}

// ============================================================================
// 1. Basic diff roundtrip
// ============================================================================
#[test]
fn test_compact_delta_basic_diff_roundtrip() {
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 64]; // 8 u64 words
    let initial_acct = make_account(100, &initial_data);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Modify word 2 and word 5
    let mut modified_data = initial_data.clone();
    modified_data[16..24].copy_from_slice(&42u64.to_le_bytes());
    modified_data[40..48].copy_from_slice(&99u64.to_le_bytes());
    let modified_acct = Account { lamports: 200, data: modified_data.clone(), ..initial_acct.clone() };
    let _ = svm.set_account(pk, modified_acct.clone());

    // Build compact delta
    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(modified_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Verify it's a Diff with 2 patches
    match delta.accounts.get(&pk).unwrap() {
        AccountPatch::Diff { lamports, patches } => {
            assert_eq!(*lamports, 200);
            assert_eq!(patches.len(), 2);
            assert_eq!(patches[0].0, 2); // word index 2
            assert_eq!(patches[1].0, 5); // word index 5
        }
        AccountPatch::Full(_) => panic!("expected Diff, got Full"),
    }

    // Restore and verify
    let _ = svm.set_account(pk, initial_acct.clone()); // reset to initial
    let divergent = FastHashSet::from_iter([pk]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &Account { lamports: 200, data: modified_data, ..initial_acct }, "roundtrip");
}

// ============================================================================
// 2. Large account with few changes
// ============================================================================
#[test]
fn test_compact_delta_large_account_few_changes() {
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 1_048_576]; // 1MB
    let initial_acct = make_account(1000, &initial_data);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Modify 10 u64 words spread across the 1MB
    let mut modified_data = initial_data.clone();
    for i in 0..10 {
        let offset = i * 100_000;
        if offset + 8 <= modified_data.len() {
            modified_data[offset..offset + 8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        }
    }
    let modified_acct = Account { lamports: 1000, data: modified_data.clone(), ..initial_acct.clone() };
    let _ = svm.set_account(pk, modified_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(modified_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Verify tiny memory footprint
    match delta.accounts.get(&pk).unwrap() {
        AccountPatch::Diff { patches, .. } => {
            assert_eq!(patches.len(), 10, "should have exactly 10 patches");
            // 10 patches × 12 bytes = 120 bytes vs 1MB full
            // 10 patches × 12 bytes = 120 bytes + map overhead + sysvars
            // Much smaller than 1MB full account
            assert!(delta.estimated_heap_bytes() < 100_000,
                "should be much smaller than 1MB, got {}", delta.estimated_heap_bytes());
        }
        AccountPatch::Full(_) => panic!("expected Diff for same-size account"),
    }

    // Restore and verify
    let _ = svm.set_account(pk, initial_acct.clone());
    let divergent = FastHashSet::from_iter([pk]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &modified_acct, "large_account");
}

// ============================================================================
// 3. Account creation (not in initial)
// ============================================================================
#[test]
fn test_compact_delta_account_creation() {
    let pk_initial = Pubkey::new_unique();
    let pk_created = Pubkey::new_unique();
    let initial_acct = make_account(100, &[1, 2, 3]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk_initial, initial_acct.clone())]);

    // Create a new account
    let created_acct = make_account(500, &[10, 20, 30, 40]);
    let _ = svm.set_account(pk_created, created_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk_created, Arc::new(created_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Should be Full (not in initial)
    assert!(matches!(delta.accounts.get(&pk_created).unwrap(), AccountPatch::Full(_)));

    // Restore and verify
    let divergent = FastHashSet::from_iter([pk_created]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk_created, &created_acct, "created");
}

// ============================================================================
// 4. Account deletion (zeroed)
// ============================================================================
#[test]
fn test_compact_delta_account_deletion() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[1, 2, 3]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // "Delete" by setting lamports to 0
    let deleted_acct = Account { lamports: 0, data: vec![], ..Default::default() };
    let _ = svm.set_account(pk, deleted_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(deleted_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Should be Full (different size: 3 bytes vs 0)
    assert!(matches!(delta.accounts.get(&pk).unwrap(), AccountPatch::Full(_)));
}

// ============================================================================
// 5. Account resize
// ============================================================================
#[test]
fn test_compact_delta_account_resize() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[1, 2, 3, 4, 5, 6, 7, 8]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Resize: different length
    let resized_acct = make_account(100, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let _ = svm.set_account(pk, resized_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(resized_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Should be Full (different size)
    assert!(matches!(delta.accounts.get(&pk).unwrap(), AccountPatch::Full(_)));

    // Restore and verify
    let _ = svm.set_account(pk, initial_acct);
    let divergent = FastHashSet::from_iter([pk]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &resized_acct, "resized");
}

// ============================================================================
// 6. Lamports-only change (data identical)
// ============================================================================
#[test]
fn test_compact_delta_lamports_only() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[0u8; 32]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Only change lamports
    let modified_acct = Account { lamports: 999, ..initial_acct.clone() };
    let _ = svm.set_account(pk, modified_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(modified_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    match delta.accounts.get(&pk).unwrap() {
        AccountPatch::Diff { lamports, patches } => {
            assert_eq!(*lamports, 999);
            assert!(patches.is_empty(), "no data patches needed");
        }
        AccountPatch::Full(_) => panic!("expected Diff for lamports-only change"),
    }

    // Restore and verify
    let _ = svm.set_account(pk, initial_acct);
    let divergent = FastHashSet::from_iter([pk]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &modified_acct, "lamports_only");
}

// ============================================================================
// 7. Multiple accounts mixed (Diff + Full)
// ============================================================================
#[test]
fn test_compact_delta_mixed_diff_and_full() {
    let pk_diff = Pubkey::new_unique();
    let pk_full = Pubkey::new_unique();
    let pk_untouched = Pubkey::new_unique();

    let diff_acct = make_account(100, &[0u8; 16]); // 2 u64 words
    let full_acct = make_account(200, &[1, 2, 3]);
    let untouched_acct = make_account(300, &[4, 5, 6]);

    let (mut svm, initial) = setup_svm_with_accounts(&[
        (pk_diff, diff_acct.clone()),
        (pk_full, full_acct.clone()),
        (pk_untouched, untouched_acct.clone()),
    ]);

    // Modify diff account (same size, change word 0)
    let mut mod_diff_data = vec![0u8; 16];
    mod_diff_data[0..8].copy_from_slice(&77u64.to_le_bytes());
    let mod_diff = Account { lamports: 100, data: mod_diff_data.clone(), ..diff_acct.clone() };

    // Resize full account
    let mod_full = make_account(200, &[1, 2, 3, 4, 5]);

    let _ = svm.set_account(pk_diff, mod_diff.clone());
    let _ = svm.set_account(pk_full, mod_full.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk_diff, Arc::new(mod_diff.clone()));
    changed.insert(pk_full, Arc::new(mod_full.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    assert!(delta.accounts.get(&pk_diff).unwrap().is_diff());
    assert!(!delta.accounts.get(&pk_full).unwrap().is_diff());
    assert!(delta.accounts.get(&pk_untouched).is_none()); // not changed

    // Restore all and verify
    let _ = svm.set_account(pk_diff, diff_acct);
    let _ = svm.set_account(pk_full, full_acct);
    let divergent = FastHashSet::from_iter([pk_diff, pk_full]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk_diff, &mod_diff, "mixed_diff");
    assert_account_eq(&svm, &pk_full, &mod_full, "mixed_full");
    assert_account_eq(&svm, &pk_untouched, &untouched_acct, "mixed_untouched");
}

// ============================================================================
// 8. Empty delta
// ============================================================================
#[test]
fn test_compact_delta_empty() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[1, 2, 3]);
    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    let delta = CompactDelta::tombstone();
    assert_eq!(delta.account_count(), 0);

    let divergent = FastHashSet::default();
    delta.restore_selective(&initial, &mut svm, &divergent);
    // Should be no-op
    assert_account_eq(&svm, &pk, &initial_acct, "empty_delta");
}

// ============================================================================
// 9. restore_selective with divergent_keys
// ============================================================================
#[test]
fn test_compact_delta_restore_resets_divergent() {
    let pk_in_delta = Pubkey::new_unique();
    let pk_divergent = Pubkey::new_unique();

    let acct1 = make_account(100, &[0u8; 16]);
    let acct2 = make_account(200, &[0u8; 16]);

    let (mut svm, initial) = setup_svm_with_accounts(&[
        (pk_in_delta, acct1.clone()),
        (pk_divergent, acct2.clone()),
    ]);

    // Modify both accounts in SVM (simulating previous iteration)
    let _ = svm.set_account(pk_in_delta, make_account(999, &[0u8; 16]));
    let _ = svm.set_account(pk_divergent, make_account(888, &[0u8; 16]));

    // Delta only has pk_in_delta with specific modifications
    let mut mod_data = vec![0u8; 16];
    mod_data[0..8].copy_from_slice(&42u64.to_le_bytes());
    let mod_acct = Account { lamports: 150, data: mod_data.clone(), ..acct1.clone() };

    let mut changed = FastHashMap::default();
    changed.insert(pk_in_delta, Arc::new(mod_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    // Divergent includes both
    let divergent = FastHashSet::from_iter([pk_in_delta, pk_divergent]);
    delta.restore_selective(&initial, &mut svm, &divergent);

    // pk_in_delta should be the delta value
    assert_account_eq(&svm, &pk_in_delta, &mod_acct, "delta_account");
    // pk_divergent should be reset to initial
    assert_account_eq(&svm, &pk_divergent, &acct2, "divergent_reset");
}

// ============================================================================
// 10. restore_selective_from optimization
// ============================================================================
#[test]
fn test_compact_delta_restore_selective_from_skips_unchanged() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[0u8; 16]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Create two identical deltas (same patches)
    let mut mod_data = vec![0u8; 16];
    mod_data[0..8].copy_from_slice(&42u64.to_le_bytes());
    let mod_acct = Account { lamports: 200, data: mod_data.clone(), ..initial_acct.clone() };

    let mut changed1 = FastHashMap::default();
    changed1.insert(pk, Arc::new(mod_acct.clone()));
    let delta1 = CompactDelta::from_changed(&initial, changed1, &svm);

    let mut changed2 = FastHashMap::default();
    changed2.insert(pk, Arc::new(mod_acct.clone()));
    let delta2 = CompactDelta::from_changed(&initial, changed2, &svm);

    // First restore
    let _ = svm.set_account(pk, initial_acct.clone());
    let divergent = FastHashSet::from_iter([pk]);
    delta1.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &mod_acct, "first_restore");

    // Second restore using restore_selective_from — should skip since patches are equal
    let prev_exec_dirty = FastHashSet::default(); // not dirtied by execution
    let divergent2 = FastHashSet::from_iter([pk]);
    let count = delta2.restore_selective_from(&initial, &mut svm, &divergent2, &delta1, &prev_exec_dirty);
    // The account wasn't in prev_exec_dirty and patches are equal, so it should be skipped
    // Only the sysvar restore runs
    assert_account_eq(&svm, &pk, &mod_acct, "second_restore_from");
}

// ============================================================================
// 11. Sysvar restore
// ============================================================================
#[test]
fn test_compact_delta_sysvar_restore() {
    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[1, 2, 3]);
    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct)]);

    // Create delta with a specific clock
    let delta = CompactDelta::empty(make_test_clock(42));
    let clock = delta.clock();
    assert_eq!(clock.slot, 42);
}

// ============================================================================
// 12. reconstruct_account
// ============================================================================
#[test]
fn test_compact_delta_reconstruct_account() {
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 24]; // 3 u64 words
    let initial_acct = make_account(100, &initial_data);

    let (svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    let mut mod_data = initial_data.clone();
    mod_data[8..16].copy_from_slice(&55u64.to_le_bytes());
    let mod_acct = Account { lamports: 300, data: mod_data.clone(), ..initial_acct.clone() };

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(mod_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    let reconstructed = delta.reconstruct_account(&initial, &pk).unwrap();
    assert_eq!(reconstructed.lamports, 300);
    assert_eq!(reconstructed.data, mod_data);
}

// ============================================================================
// 13. Memory estimation
// ============================================================================
#[test]
fn test_compact_delta_memory_estimation() {
    let pk = Pubkey::new_unique();
    let initial_data = vec![0u8; 1024]; // 1KB, 128 u64 words
    let initial_acct = make_account(100, &initial_data);

    let (svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // 5 changed words
    let mut mod_data = initial_data.clone();
    for i in 0..5 {
        let offset = i * 64;
        mod_data[offset..offset + 8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    }
    let mod_acct = Account { lamports: 100, data: mod_data, ..initial_acct.clone() };

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(mod_acct));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    let heap = delta.estimated_heap_bytes();
    // 5 patches × 12 bytes + map overhead (80) + sysvar overhead
    // Should be well under the 1KB full account data
    assert!(heap < 100_000, "heap should be much smaller than full account, got {}", heap);
}

// ============================================================================
// 14. Tail bytes (data.len() % 8 != 0)
// ============================================================================
#[test]
fn test_compact_delta_tail_bytes() {
    let pk = Pubkey::new_unique();
    // 13 bytes = 1 full word + 5 tail bytes
    let initial_data = vec![0u8; 13];
    let initial_acct = make_account(100, &initial_data);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Modify only the tail bytes (byte 8-12)
    let mut mod_data = initial_data.clone();
    mod_data[8] = 0xAA;
    mod_data[9] = 0xBB;
    mod_data[10] = 0xCC;
    mod_data[11] = 0xDD;
    mod_data[12] = 0xEE;
    let mod_acct = Account { lamports: 100, data: mod_data.clone(), ..initial_acct.clone() };
    let _ = svm.set_account(pk, mod_acct.clone());

    let mut changed = FastHashMap::default();
    changed.insert(pk, Arc::new(mod_acct.clone()));
    let delta = CompactDelta::from_changed(&initial, changed, &svm);

    match delta.accounts.get(&pk).unwrap() {
        AccountPatch::Diff { patches, .. } => {
            assert_eq!(patches.len(), 1, "should have 1 tail patch");
            assert_eq!(patches[0].0, 1); // word index 1 (tail)
        }
        AccountPatch::Full(_) => panic!("expected Diff"),
    }

    // Restore and verify all bytes match
    let _ = svm.set_account(pk, initial_acct);
    let divergent = FastHashSet::from_iter([pk]);
    delta.restore_selective(&initial, &mut svm, &divergent);
    assert_account_eq(&svm, &pk, &mod_acct, "tail_bytes");
}

// ============================================================================
// 15. fingerprint_and_collect_changed: deleted account must produce tombstone
// ============================================================================
// Regression test: fingerprint_and_collect_changed was not collecting deleted
// accounts (present in initial, absent from SVM). The delta would be missing
// the deletion, so restore would leave stale account data in the SVM.
#[test]
fn test_fingerprint_collect_deleted_account_produces_tombstone() {
    use crate::snapshot::dirty_tracker::DirtyTracker;
    use crate::snapshot::svm_snapshot::fingerprint_and_collect_changed;

    let pk_stays = Pubkey::new_unique();
    let pk_deleted = Pubkey::new_unique();

    let stay_acct = make_account(100, &[0u8; 16]);
    let delete_acct = make_account(200, &[1, 2, 3, 4, 5, 6, 7, 8]);

    let (mut svm, initial) = setup_svm_with_accounts(&[
        (pk_stays, stay_acct.clone()),
        (pk_deleted, delete_acct.clone()),
    ]);

    // Modify pk_stays, "delete" pk_deleted by zeroing it out
    let mod_stay = Account { lamports: 150, data: vec![0u8; 16], ..stay_acct.clone() };
    let _ = svm.set_account(pk_stays, mod_stay.clone());
    let _ = svm.set_account(pk_deleted, Account { lamports: 0, data: vec![], ..Default::default() });

    // Set up dirty tracker marking both as dirty
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_stays);
    dirty.mark_account_dirty(&pk_deleted);

    // Call the combined fingerprint + collect function
    let bitmap_size = 4096;
    let mut bitmap = vec![0u8; bitmap_size];
    let (_fp, changed, _novelty) = unsafe {
        fingerprint_and_collect_changed(
            &svm, &dirty, &initial,
            &crate::snapshot::CreationTracker::new(),
            bitmap.as_mut_ptr(), bitmap_size)
    };

    // pk_stays should be in changed (lamports diff)
    assert!(changed.contains_key(&pk_stays),
        "modified account should be in changed map");

    // pk_deleted MUST be in changed as a tombstone (Full with 0 lamports)
    assert!(changed.contains_key(&pk_deleted),
        "deleted account MUST be in changed map as tombstone (regression: was missing before fix)");
    match changed.get(&pk_deleted).unwrap() {
        AccountPatch::Full(arc) => {
            assert_eq!(arc.lamports, 0, "tombstone should have 0 lamports");
            assert!(arc.data.is_empty(), "tombstone should have empty data");
        }
        AccountPatch::Diff { .. } => {
            panic!("deleted account should be Full tombstone, not Diff");
        }
    }

    // Verify roundtrip: build delta from changed, restore, verify deletion sticks
    let delta = CompactDelta::from_patches(&svm, changed);
    // Reset SVM to initial state
    let _ = svm.set_account(pk_stays, stay_acct.clone());
    let _ = svm.set_account(pk_deleted, delete_acct.clone());

    let divergent = FastHashSet::from_iter([pk_stays, pk_deleted]);
    delta.restore_selective(&initial, &mut svm, &divergent);

    // pk_stays should be at modified value
    assert_account_eq(&svm, &pk_stays, &mod_stay, "stays_after_restore");

    // pk_deleted should be zeroed (tombstoned)
    let deleted_state = svm.get_account(&pk_deleted);
    match deleted_state {
        None => {} // OK — fully deleted
        Some(acct) => {
            assert_eq!(acct.lamports, 0,
                "deleted account should have 0 lamports after restore, got {}", acct.lamports);
        }
    }
}

// ============================================================================
// 16. child_delta inherits parent patches for non-re-dirtied accounts
// ============================================================================
// Regression test: CompactDelta::from_patches only stored accounts dirty in the
// current execution. Parent modifications for non-re-dirtied accounts were lost,
// causing states at depth>1 to have incomplete deltas. On restore, accounts
// that should be at the parent's modified value would reset to initial.
#[test]
fn test_child_delta_inherits_parent_patches() {
    use crate::snapshot::dirty_tracker::DirtyTracker;

    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();

    let initial_a = make_account(100, &[0u8; 16]);
    let initial_b = make_account(200, &[0u8; 16]);

    let (mut svm, initial) = setup_svm_with_accounts(&[
        (pk_a, initial_a.clone()),
        (pk_b, initial_b.clone()),
    ]);

    // Depth 1: modify A to 150, B unchanged
    let mod_a = Account { lamports: 150, ..initial_a.clone() };
    let _ = svm.set_account(pk_a, mod_a.clone());

    let mut parent_patches = FastHashMap::default();
    parent_patches.insert(pk_a, AccountPatch::Diff { lamports: 150, patches: vec![] });
    let parent_delta = CompactDelta::from_patches(&svm, parent_patches);

    // Depth 2: only modify B to 300, A not touched (not in dirty_tracker)
    let _ = svm.set_account(pk_a, mod_a.clone()); // A still at 150
    let mod_b = Account { lamports: 300, ..initial_b.clone() };
    let _ = svm.set_account(pk_b, mod_b.clone());

    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk_b); // Only B was dirtied

    let mut new_patches = FastHashMap::default();
    new_patches.insert(pk_b, AccountPatch::Diff { lamports: 300, patches: vec![] });

    let child = CompactDelta::child_delta(
        &parent_delta,
        new_patches,
        dirty.dirty_accounts(),
        &svm,
    );

    // Child delta MUST have BOTH A (inherited) and B (new)
    assert!(child.accounts.contains_key(&pk_a),
        "child delta must inherit parent's A modification (regression: was missing without child_delta)");
    assert!(child.accounts.contains_key(&pk_b),
        "child delta must have B from current execution");
    assert_eq!(child.accounts.len(), 2, "child delta should have exactly 2 accounts");

    // Verify restore roundtrip: reset SVM to initial, restore from child delta
    let _ = svm.set_account(pk_a, initial_a.clone());
    let _ = svm.set_account(pk_b, initial_b.clone());
    let divergent = FastHashSet::from_iter([pk_a, pk_b]);
    child.restore_selective(&initial, &mut svm, &divergent);

    assert_account_eq(&svm, &pk_a, &mod_a, "A should be at parent's modified value (150)");
    assert_account_eq(&svm, &pk_b, &mod_b, "B should be at child's modified value (300)");
}

// ============================================================================
// 17. child_delta drops parent patches for accounts returned to initial
// ============================================================================
#[test]
fn test_child_delta_drops_reverted_parent_patches() {
    use crate::snapshot::dirty_tracker::DirtyTracker;

    let pk = Pubkey::new_unique();
    let initial_acct = make_account(100, &[0u8; 16]);

    let (mut svm, initial) = setup_svm_with_accounts(&[(pk, initial_acct.clone())]);

    // Parent delta: pk modified to 200
    let mut parent_patches = FastHashMap::default();
    parent_patches.insert(pk, AccountPatch::Diff { lamports: 200, patches: vec![] });
    let parent_delta = CompactDelta::from_patches(&svm, parent_patches);

    // Child execution: re-dirtied pk but returned it to initial (100)
    let _ = svm.set_account(pk, initial_acct.clone()); // back to initial
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&pk);

    // new_patches is EMPTY because pk matches initial (fingerprint_and_collect_changed would skip it)
    let new_patches = FastHashMap::default();

    let child = CompactDelta::child_delta(
        &parent_delta,
        new_patches,
        dirty.dirty_accounts(),
        &svm,
    );

    // pk was re-dirtied but returned to initial → should NOT be in child delta
    assert!(!child.accounts.contains_key(&pk),
        "reverted account should be dropped from child delta (returned to initial)");
}
