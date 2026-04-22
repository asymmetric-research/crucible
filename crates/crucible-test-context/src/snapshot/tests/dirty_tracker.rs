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
