use super::super::*;
use solana_account::Account;
use solana_pubkey::Pubkey;

#[test]
fn test_account_diff_unchanged() {
    let account = Account {
        lamports: 100,
        data: vec![1, 2, 3],
        owner: Pubkey::new_unique(),
        executable: false,
        rent_epoch: 0,
    };
    let diff = AccountDiff {
        pubkey: Pubkey::new_unique(),
        pre: Some(account.clone()),
        post: Some(account),
    };
    assert!(!diff.is_changed());
    assert!(!diff.was_created());
    assert!(!diff.was_deleted());
    assert_eq!(diff.lamports_delta(), (100, 100));
    assert!(diff.changed_data_ranges().is_empty());
}

#[test]
fn test_account_diff_created() {
    let diff = AccountDiff {
        pubkey: Pubkey::new_unique(),
        pre: None,
        post: Some(Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
    };
    assert!(diff.is_changed());
    assert!(diff.was_created());
    assert!(!diff.was_deleted());
    assert_eq!(diff.lamports_delta(), (0, 100));
}

#[test]
fn test_account_diff_deleted() {
    let diff = AccountDiff {
        pubkey: Pubkey::new_unique(),
        pre: Some(Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
        post: None,
    };
    assert!(diff.is_changed());
    assert!(!diff.was_created());
    assert!(diff.was_deleted());
    assert_eq!(diff.lamports_delta(), (100, 0));
}

#[test]
fn test_account_diff_data_changes() {
    let diff = AccountDiff {
        pubkey: Pubkey::new_unique(),
        pre: Some(Account {
            lamports: 100,
            data: vec![1, 2, 3, 4, 5],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
        post: Some(Account {
            lamports: 100,
            data: vec![1, 9, 3, 9, 5],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
    };
    let ranges = diff.changed_data_ranges();
    // Bytes at index 1 and 3 changed (non-contiguous)
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0], (1, 1));
    assert_eq!(ranges[1], (3, 1));
}

#[test]
fn test_account_diff_length_change() {
    let diff = AccountDiff {
        pubkey: Pubkey::new_unique(),
        pre: Some(Account {
            lamports: 100,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
        post: Some(Account {
            lamports: 100,
            data: vec![1, 2, 3, 4, 5],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        }),
    };
    let ranges = diff.changed_data_ranges();
    // Trailing 2 bytes are "new"
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0], (3, 2));
}
