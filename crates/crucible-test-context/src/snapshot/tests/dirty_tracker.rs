use super::super::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

#[test]
fn test_dirty_tracker_record_tx() {
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();
    let writable_acc = Pubkey::new_unique();
    let readonly_acc = Pubkey::new_unique();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(writable_acc, false),
            AccountMeta::new_readonly(readonly_acc, false),
        ],
        data: vec![],
    };

    tracker.record_tx(&[ix], &fee_payer);

    // fee_payer + writable_acc should be in writable set
    assert!(tracker.dirty_accounts().contains(&fee_payer));
    assert!(tracker.dirty_accounts().contains(&writable_acc));
    assert!(!tracker.dirty_accounts().contains(&readonly_acc));

    // program_id + readonly_acc should be in read_only set
    assert!(tracker.read_accounts().contains(&program_id));
    assert!(tracker.read_accounts().contains(&readonly_acc));

    assert_eq!(tracker.dirty_count(), 2);
    assert!(!tracker.is_clock_dirty());
}

#[test]
fn test_dirty_tracker_accumulates() {
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();

    let acc1 = Pubkey::new_unique();
    let acc2 = Pubkey::new_unique();

    let ix1 = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(acc1, false)],
        data: vec![],
    };
    let ix2 = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(acc2, false)],
        data: vec![],
    };

    tracker.record_tx(&[ix1], &fee_payer);
    tracker.record_tx(&[ix2], &fee_payer);

    // Both accounts + fee_payer should be tracked
    assert_eq!(tracker.dirty_count(), 3); // fee_payer, acc1, acc2
    assert!(tracker.dirty_accounts().contains(&acc1));
    assert!(tracker.dirty_accounts().contains(&acc2));
}

#[test]
fn test_dirty_tracker_multi_instruction_batch() {
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();

    let acc1 = Pubkey::new_unique();
    let acc2 = Pubkey::new_unique();

    let ix1 = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(acc1, false)],
        data: vec![],
    };
    let ix2 = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(acc2, false)],
        data: vec![],
    };

    // Record multi-instruction batch in a single call
    tracker.record_tx(&[ix1, ix2], &fee_payer);

    assert_eq!(tracker.dirty_count(), 3); // fee_payer, acc1, acc2
}

#[test]
fn test_dirty_tracker_clear() {
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();

    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
        data: vec![],
    };

    tracker.record_tx(&[ix], &fee_payer);
    tracker.mark_clock_dirty(100);

    assert!(tracker.dirty_count() > 0);
    assert!(tracker.is_clock_dirty());

    tracker.clear();

    assert_eq!(tracker.dirty_count(), 0);
    assert!(!tracker.is_clock_dirty());
    assert!(tracker.read_accounts().is_empty());
}

#[test]
fn test_dirty_tracker_mark_account() {
    let mut tracker = DirtyTracker::new();
    let pubkey = Pubkey::new_unique();

    tracker.mark_account_dirty(&pubkey);
    assert!(tracker.dirty_accounts().contains(&pubkey));
    assert_eq!(tracker.dirty_count(), 1);
}

#[test]
fn test_dirty_tracker_clone_is_fresh() {
    let mut tracker = DirtyTracker::new();
    tracker.mark_account_dirty(&Pubkey::new_unique());
    tracker.mark_clock_dirty(100);

    let cloned = tracker.clone();
    assert_eq!(cloned.dirty_count(), 0);
    assert!(!cloned.is_clock_dirty());
}

// ---- Category 7: DirtyTracker Edge Cases ----

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
    tracker.mark_clock_dirty(100);

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
    let ix1 = Instruction::new_with_bytes(
        program,
        &[],
        vec![
            AccountMeta::new(pk_shared, false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ],
    );
    let ix2 = Instruction::new_with_bytes(program, &[], vec![AccountMeta::new(pk_shared, false)]);
    tracker.record_tx(&[ix1, ix2], &fee_payer);

    // Tx 2: pk_shared again
    let ix3 = Instruction::new_with_bytes(program, &[], vec![AccountMeta::new(pk_shared, false)]);
    tracker.record_tx(&[ix3], &fee_payer);

    // pk_shared should appear only once
    let count = tracker
        .dirty_accounts()
        .iter()
        .filter(|&&pk| pk == pk_shared)
        .count();
    assert_eq!(count, 1, "pk_shared should be deduplicated in dirty set");

    // But total dirty count includes fee_payer + pk_shared + the unique one
    assert!(
        tracker.dirty_count() >= 2,
        "should have at least fee_payer and pk_shared"
    );
}

#[test]
fn test_edge_dirty_tracker_clone_is_fresh() {
    // Clone a dirty tracker with 5 recorded accounts.
    // Clone should be empty (by design — Clone impl returns fresh).
    let mut tracker = DirtyTracker::new();
    let fee_payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();

    for _ in 0..5 {
        let ix = Instruction::new_with_bytes(
            program,
            &[],
            vec![AccountMeta::new(Pubkey::new_unique(), false)],
        );
        tracker.record_tx(&[ix], &fee_payer);
    }
    tracker.mark_clock_dirty(100);

    assert!(tracker.dirty_count() > 0);
    assert!(tracker.is_clock_dirty());

    let cloned = tracker.clone();
    assert_eq!(cloned.dirty_count(), 0, "cloned tracker should be empty");
    assert!(cloned.dirty_accounts().is_empty());
    assert!(cloned.read_accounts().is_empty());
    assert!(
        !cloned.is_clock_dirty(),
        "cloned tracker should not have clock dirty"
    );
}

// =========================================================================
// CreationTracker — deterministic creation-ordinal assignment
// =========================================================================

#[test]
fn test_creation_tracker_assigns_sequential_ordinals() {
    let mut tracker = CreationTracker::new();
    let pk0 = Pubkey::new_unique();
    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();

    assert_eq!(tracker.observe(pk0), 0);
    assert_eq!(tracker.observe(pk1), 1);
    assert_eq!(tracker.observe(pk2), 2);
    // Idempotent: re-observing keeps the original ordinal
    assert_eq!(tracker.observe(pk1), 1);
    assert_eq!(tracker.len(), 3);

    assert_eq!(tracker.ordinal(&pk0), Some(0));
    assert_eq!(tracker.ordinal(&pk1), Some(1));
    assert_eq!(tracker.ordinal(&pk2), Some(2));
    assert_eq!(tracker.ordinal(&Pubkey::new_unique()), None);
}

#[test]
fn test_creation_tracker_extends_in_first_mark_order() {
    // Ordinals must follow DirtyTracker first-mark order, not HashMap iteration.
    let initial = SvmSnapshot {
        accounts: crate::FastHashMap::default(),
        sysvars: Vec::new(),
    };
    let pks: Vec<Pubkey> = (0..8).map(|_| Pubkey::new_unique()).collect();
    let mut dirty = DirtyTracker::new();
    for pk in &pks {
        dirty.mark_account_dirty(pk);
        dirty.mark_account_dirty(pk); // duplicate marks don't re-append
    }

    let tracker =
        CreationTracker::extended_with_iteration(&CreationTracker::new(), &dirty, &initial);
    for (i, pk) in pks.iter().enumerate() {
        assert_eq!(
            tracker.ordinal(pk),
            Some(i as u32),
            "ordinal must match mark order"
        );
    }
}

#[test]
fn test_creation_tracker_extends_from_seeded_base() {
    let mut base = CreationTracker::new();
    let path_a = Pubkey::new_unique();
    let path_b = Pubkey::new_unique();
    base.observe(path_a); // 0
    base.observe(path_b); // 1

    // Initial snapshot contains a pre-existing account that must be skipped.
    let preexisting = Pubkey::new_unique();
    let mut accounts = crate::FastHashMap::default();
    accounts.insert(preexisting, std::sync::Arc::new(make_account_simple(100)));
    let initial = SvmSnapshot {
        accounts,
        sysvars: Vec::new(),
    };

    // This iteration re-touches a path account, touches the pre-existing one,
    // and creates a new account.
    let created = Pubkey::new_unique();
    let mut dirty = DirtyTracker::new();
    dirty.mark_account_dirty(&path_b);
    dirty.mark_account_dirty(&preexisting);
    dirty.mark_account_dirty(&created);

    let tracker = CreationTracker::extended_with_iteration(&base, &dirty, &initial);
    assert_eq!(tracker.ordinal(&path_a), Some(0), "base ordinals preserved");
    assert_eq!(
        tracker.ordinal(&path_b),
        Some(1),
        "re-touched path account keeps its ordinal"
    );
    assert_eq!(
        tracker.ordinal(&preexisting),
        None,
        "pre-existing accounts are skipped"
    );
    assert_eq!(
        tracker.ordinal(&created),
        Some(2),
        "new creation continues the sequence"
    );
    // The base is not mutated (clone-on-extend)
    assert_eq!(base.len(), 2);
}

#[test]
fn test_dirty_tracker_mark_order_resets_on_clear() {
    let mut tracker = DirtyTracker::new();
    let pk = Pubkey::new_unique();
    tracker.mark_account_dirty(&pk);
    assert_eq!(tracker.mark_order(), &[pk]);

    tracker.clear();
    assert!(tracker.mark_order().is_empty());

    let pk2 = Pubkey::new_unique();
    tracker.mark_account_dirty(&pk2);
    assert_eq!(tracker.mark_order(), &[pk2]);
}

fn make_account_simple(lamports: u64) -> solana_account::Account {
    solana_account::Account {
        lamports,
        data: vec![],
        owner: Pubkey::new_unique(),
        executable: false,
        rent_epoch: 0,
    }
}
