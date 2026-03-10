use super::super::*;
use crate::AccountChangeKind;
use anchor_lang::solana_program::instruction::{Instruction, AccountMeta};
use solana_account::Account;
use solana_pubkey::Pubkey;

#[test]
fn test_iteration_taint_log() {
    let mut log = IterationTaintLog::new();
    assert!(log.records.is_empty());

    let record = TxTaintRecord {
        read_accounts: vec![Pubkey::new_unique()],
        write_accounts: vec![Pubkey::new_unique()],
        programs: vec![Pubkey::new_unique()],
        diffs: None,
    };
    log.push(record);
    assert_eq!(log.records.len(), 1);

    log.clear();
    assert!(log.records.is_empty());
}

// -------------------------------------------------------------------------
// build_action_taint_summary tests
// -------------------------------------------------------------------------

#[test]
fn test_taint_summary_empty_log() {
    let log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };
    // No txs and no diffs → None
    let result = build_action_taint_summary(&log, 0, 0);
    assert!(result.is_none());
}

#[test]
fn test_taint_summary_single_tx() {
    let pk_write = Pubkey::new_unique();
    let pk_read = Pubkey::new_unique();
    let pk_prog = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![pk_read, pk_prog],
        write_accounts: vec![pk_write],
        programs: vec![pk_prog],
        diffs: None,
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    assert_eq!(summary.tx_count, 1);
    assert_eq!(summary.written_accounts.len(), 1);
    assert!(summary.written_accounts.contains(&pk_write.to_string()));
    // pk_read and pk_prog should be in read set (not in write set)
    assert!(summary.read_accounts.contains(&pk_read.to_string()));
    assert!(summary.account_changes.is_none());
}

#[test]
fn test_taint_summary_multi_tx() {
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let pk_c = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };

    // Tx 0: writes A, reads B
    log.push(TxTaintRecord {
        read_accounts: vec![pk_b],
        write_accounts: vec![pk_a],
        programs: vec![],
        diffs: None,
    });

    // Tx 1: writes B, reads C
    log.push(TxTaintRecord {
        read_accounts: vec![pk_c],
        write_accounts: vec![pk_b],
        programs: vec![],
        diffs: None,
    });

    let summary = build_action_taint_summary(&log, 0, 2).unwrap();
    assert_eq!(summary.tx_count, 2);
    // A and B are written
    assert!(summary.written_accounts.contains(&pk_a.to_string()));
    assert!(summary.written_accounts.contains(&pk_b.to_string()));
    // B is written so not in read set; C is only read
    assert!(!summary.read_accounts.contains(&pk_b.to_string()));
    assert!(summary.read_accounts.contains(&pk_c.to_string()));
}

#[test]
fn test_taint_summary_with_diffs() {
    let pk = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let pre_account = Account {
        lamports: 100,
        data: vec![1, 2, 3, 4],
        owner,
        executable: false,
        rent_epoch: 0,
    };
    let post_account = Account {
        lamports: 200,
        data: vec![1, 9, 3, 4],
        owner,
        executable: false,
        rent_epoch: 0,
    };

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: Some(pre_account),
            post: Some(post_account),
        }]),
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    assert_eq!(summary.tx_count, 1);
    let changes = summary.account_changes.unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].lamports, (100, 200));
    assert!(matches!(changes[0].kind, AccountChangeKind::Modified));
    // Byte 1 changed
    assert!(changes[0].changed_ranges.contains(&(1, 1)));
}

#[test]
fn test_taint_summary_range_slicing() {
    // log has 3 records, but we only look at index 1..2
    let pk_before = Pubkey::new_unique();
    let pk_target = Pubkey::new_unique();
    let pk_after = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };

    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk_before],
        programs: vec![],
        diffs: None,
    });
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk_target],
        programs: vec![],
        diffs: None,
    });
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk_after],
        programs: vec![],
        diffs: None,
    });

    let summary = build_action_taint_summary(&log, 1, 2).unwrap();
    assert_eq!(summary.tx_count, 1);
    assert!(summary.written_accounts.contains(&pk_target.to_string()));
    assert!(!summary.written_accounts.contains(&pk_before.to_string()));
    assert!(!summary.written_accounts.contains(&pk_after.to_string()));
}

#[test]
fn test_taint_log_len() {
    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };
    assert_eq!(log.len(), 0);
    assert!(log.is_empty());

    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![],
        programs: vec![],
        diffs: None,
    });
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

#[test]
fn test_taint_summary_created_account() {
    let pk = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: None,
            post: Some(Account {
                lamports: 1_000_000,
                data: vec![0; 32],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
        }]),
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    let changes = summary.account_changes.unwrap();
    assert_eq!(changes.len(), 1);
    assert!(matches!(changes[0].kind, AccountChangeKind::Created));
    assert_eq!(changes[0].lamports, (0, 1_000_000));
}

#[test]
fn test_taint_summary_deleted_account() {
    let pk = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: Some(Account {
                lamports: 500,
                data: vec![1, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
            post: None,
        }]),
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    let changes = summary.account_changes.unwrap();
    assert_eq!(changes.len(), 1);
    assert!(matches!(changes[0].kind, AccountChangeKind::Deleted));
    assert_eq!(changes[0].lamports, (500, 0));
}

#[test]
fn test_taint_summary_overlapping_writes_across_txs() {
    // Same account written in two txs — should merge first pre / last post
    let pk = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };

    // Tx 0: account goes 100 -> 200 lamports, data[0] changes 1 -> 5
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: Some(Account {
                lamports: 100,
                data: vec![1, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
            post: Some(Account {
                lamports: 200,
                data: vec![5, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
        }]),
    });

    // Tx 1: account goes 200 -> 300 lamports, data[2] changes 3 -> 9
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: Some(Account {
                lamports: 200,
                data: vec![5, 2, 3],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
            post: Some(Account {
                lamports: 300,
                data: vec![5, 2, 9],
                owner,
                executable: false,
                rent_epoch: 0,
            }),
        }]),
    });

    let summary = build_action_taint_summary(&log, 0, 2).unwrap();
    assert_eq!(summary.tx_count, 2);
    let changes = summary.account_changes.unwrap();
    assert_eq!(changes.len(), 1); // Only one account
    // Should use first pre (100) and last post (300)
    assert_eq!(changes[0].lamports, (100, 300));
    assert!(matches!(changes[0].kind, AccountChangeKind::Modified));
    // data[0]: 1->5 and data[2]: 3->9 are both changed relative to first pre vs last post
    assert!(changes[0].changed_ranges.contains(&(0, 1)));
    assert!(changes[0].changed_ranges.contains(&(2, 1)));
}

#[test]
fn test_taint_summary_unchanged_account_skipped() {
    // Account is in diffs but pre == post (unchanged) — should be filtered out
    let pk = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let account = Account {
        lamports: 100,
        data: vec![1, 2, 3],
        owner,
        executable: false,
        rent_epoch: 0,
    };

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk],
        programs: vec![],
        diffs: Some(vec![AccountDiff {
            pubkey: pk,
            pre: Some(account.clone()),
            post: Some(account),
        }]),
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    // account_changes should be None since the only account was unchanged
    assert!(summary.account_changes.is_none());
}

#[test]
fn test_taint_summary_zero_tx_with_diffs_enabled() {
    // No txs but collect_diffs is true → should return Some with tx_count=0
    let log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };

    let summary = build_action_taint_summary(&log, 0, 0).unwrap();
    assert_eq!(summary.tx_count, 0);
    assert!(summary.written_accounts.is_empty());
    assert!(summary.read_accounts.is_empty());
    assert!(summary.account_changes.is_none());
}

#[test]
fn test_taint_summary_write_removes_from_read_set() {
    // Account appears in both read and write sets across txs —
    // should be in written_accounts only (removed from read_accounts)
    let pk_both = Pubkey::new_unique();
    let pk_read_only = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };

    // Tx 0: reads pk_both and pk_read_only
    log.push(TxTaintRecord {
        read_accounts: vec![pk_both, pk_read_only],
        write_accounts: vec![],
        programs: vec![],
        diffs: None,
    });

    // Tx 1: writes pk_both
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk_both],
        programs: vec![],
        diffs: None,
    });

    let summary = build_action_taint_summary(&log, 0, 2).unwrap();
    // pk_both was written, so it should NOT be in read_accounts
    assert!(summary.written_accounts.contains(&pk_both.to_string()));
    assert!(!summary.read_accounts.contains(&pk_both.to_string()));
    // pk_read_only should only be in read_accounts
    assert!(summary.read_accounts.contains(&pk_read_only.to_string()));
    assert!(!summary.written_accounts.contains(&pk_read_only.to_string()));
}

#[test]
fn test_taint_summary_multiple_accounts_in_diffs() {
    // Two different accounts modified in same tx
    let pk_a = Pubkey::new_unique();
    let pk_b = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: true,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![],
        write_accounts: vec![pk_a, pk_b],
        programs: vec![],
        diffs: Some(vec![
            AccountDiff {
                pubkey: pk_a,
                pre: Some(Account {
                    lamports: 100,
                    data: vec![1, 2],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
                post: Some(Account {
                    lamports: 200,
                    data: vec![1, 2],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
            },
            AccountDiff {
                pubkey: pk_b,
                pre: Some(Account {
                    lamports: 50,
                    data: vec![0, 0, 0],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
                post: Some(Account {
                    lamports: 50,
                    data: vec![0, 1, 0],
                    owner,
                    executable: false,
                    rent_epoch: 0,
                }),
            },
        ]),
    });

    let summary = build_action_taint_summary(&log, 0, 1).unwrap();
    let changes = summary.account_changes.unwrap();
    assert_eq!(changes.len(), 2);

    // Find each account's change
    let change_a = changes.iter().find(|c| c.pubkey == pk_a.to_string()).unwrap();
    let change_b = changes.iter().find(|c| c.pubkey == pk_b.to_string()).unwrap();

    // Account A: only lamports changed
    assert_eq!(change_a.lamports, (100, 200));
    assert!(change_a.changed_ranges.is_empty()); // data unchanged

    // Account B: only data[1] changed
    assert_eq!(change_b.lamports, (50, 50));
    assert_eq!(change_b.changed_ranges, vec![(1, 1)]);
}

#[test]
fn test_taint_summary_out_of_bounds_range() {
    // If start_idx == end_idx (empty range), should behave like no txs
    let mut log = IterationTaintLog {
        records: Vec::new(),
        collect_diffs: false,
    };
    log.push(TxTaintRecord {
        read_accounts: vec![Pubkey::new_unique()],
        write_accounts: vec![Pubkey::new_unique()],
        programs: vec![],
        diffs: None,
    });

    // Range 5..5 is empty, beyond log size — should return None
    let result = build_action_taint_summary(&log, 5, 5);
    assert!(result.is_none());
}

// ---- capture_tx_meta tests ----

#[test]
fn test_capture_tx_meta() {
    let fee_payer = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();
    let writable = Pubkey::new_unique();
    let readonly = Pubkey::new_unique();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(writable, false),
            AccountMeta::new_readonly(readonly, false),
        ],
        data: vec![1, 2, 3],
    };

    let meta = capture_tx_meta(&[ix], &fee_payer);

    assert!(meta.write_accounts.contains(&fee_payer));
    assert!(meta.write_accounts.contains(&writable));
    assert!(!meta.write_accounts.contains(&readonly));
    assert!(meta.read_accounts.contains(&readonly));
    assert!(meta.read_accounts.contains(&program_id));
    assert!(meta.programs.contains(&program_id));
}

#[test]
fn test_capture_tx_meta_multi_instruction() {
    let fee_payer = Pubkey::new_unique();
    let prog1 = Pubkey::new_unique();
    let prog2 = Pubkey::new_unique();
    let acc_a = Pubkey::new_unique();
    let acc_b = Pubkey::new_unique();

    let ix1 = Instruction {
        program_id: prog1,
        accounts: vec![AccountMeta::new(acc_a, false)],
        data: vec![],
    };
    let ix2 = Instruction {
        program_id: prog2,
        accounts: vec![AccountMeta::new_readonly(acc_b, false)],
        data: vec![],
    };

    let meta = capture_tx_meta(&[ix1, ix2], &fee_payer);

    assert_eq!(meta.programs, vec![prog1, prog2]);
    assert!(meta.write_accounts.contains(&acc_a));
    assert!(meta.read_accounts.contains(&acc_b));
}
