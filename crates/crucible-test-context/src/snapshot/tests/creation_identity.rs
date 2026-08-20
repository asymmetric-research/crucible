//! Regression tests for canonical state identity via creation ordinals.
//!
//! Accounts created during fuzzing (Anchor `init`, ATAs, PDAs from fresh
//! keypairs) carry a never-before-seen pubkey every run. The fingerprint must
//! identify them by their position in the deterministic creation sequence —
//! not the random pubkey — or semantically identical states hash as novel and
//! the state pool fills as fast as the fuzzer executes.

use super::super::*;
use super::helpers::*;
use crate::FastHashMap;
use anchor_lang::prelude::Clock;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::sync::Arc;

/// Fixed "program" owner shared across simulated runs (a real owner is the
/// same program id in every run).
fn fixed_owner() -> Pubkey {
    Pubkey::new_from_array([7u8; 32])
}

fn second_owner() -> Pubkey {
    Pubkey::new_from_array([8u8; 32])
}

fn account_with(owner: Pubkey, lamports: u64, data: &[u8]) -> Account {
    Account {
        lamports,
        data: data.to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

/// Empty initial snapshot whose clock matches the given SVM (slot_diff = 0).
fn empty_initial(svm: &LiteSVM) -> SvmSnapshot {
    SvmSnapshot {
        accounts: FastHashMap::default(),
        sysvars: clock_to_sysvars(&svm.get_sysvar::<Clock>()),
    }
}

/// Simulate one fuzzer iteration that creates `accounts` in order on a fresh
/// SVM and returns (fingerprint, extended tracker).
fn run_creating(base: &CreationTracker, accounts: &[(Pubkey, Account)]) -> (u64, CreationTracker) {
    let mut svm = LiteSVM::new();
    let initial = empty_initial(&svm);
    let mut dirty = DirtyTracker::new();
    for (pk, acct) in accounts {
        svm.set_account(*pk, acct.clone()).unwrap();
        dirty.mark_account_dirty(pk);
    }
    let creation = CreationTracker::extended_with_iteration(base, &dirty, &initial);
    let fp = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial, &creation);
    (fp, creation)
}

/// Core regression test: the same accounts created in the same order with
/// DIFFERENT fresh pubkeys must produce EQUAL fingerprints. With pubkey-based
/// identity every run hashed as novel and the pool saturated immediately.
#[test]
fn test_identical_state_different_fresh_pubkeys_same_fingerprint() {
    let owner = fixed_owner();
    let data_a = [0x11u8; 32];
    let data_b = [0x22u8; 32];

    // Run A: fresh pubkeys
    let (fp_a, _) = run_creating(
        &CreationTracker::new(),
        &[
            (Pubkey::new_unique(), account_with(owner, 1_000, &data_a)),
            (Pubkey::new_unique(), account_with(owner, 2_000, &data_b)),
        ],
    );
    // Run B: same logical state, different fresh pubkeys
    let (fp_b, _) = run_creating(
        &CreationTracker::new(),
        &[
            (Pubkey::new_unique(), account_with(owner, 1_000, &data_a)),
            (Pubkey::new_unique(), account_with(owner, 2_000, &data_b)),
        ],
    );

    assert_eq!(
        fp_a, fp_b,
        "semantically identical states with different fresh pubkeys must collapse to one fingerprint"
    );
}

#[test]
fn test_embedded_created_pubkey_bytes_are_canonicalized() {
    let owner = fixed_owner();

    let run = || -> u64 {
        let holder = Pubkey::new_unique();
        let embedded = Pubkey::new_unique();
        let mut holder_data = Vec::new();
        holder_data.extend_from_slice(&[0xAB; 8]);
        holder_data.extend_from_slice(&embedded.to_bytes());
        holder_data.extend_from_slice(&42u64.to_le_bytes());

        run_creating(
            &CreationTracker::new(),
            &[
                (holder, account_with(owner, 1_000, &holder_data)),
                (embedded, account_with(owner, 2_000, &[0x55; 24])),
            ],
        )
        .0
    };

    assert_eq!(
        run(),
        run(),
        "created pubkeys stored inside account data must hash by creation ordinal, not raw bytes"
    );
}

#[test]
fn test_created_account_identity_ignores_fresh_bytes_without_registered_discriminator() {
    let owner = fixed_owner();

    let run = || -> u64 {
        let pk = Pubkey::new_unique();
        let mut data = pk.to_bytes().to_vec();
        data.extend_from_slice(&[0x66; 16]);

        run_creating(
            &CreationTracker::new(),
            &[(pk, account_with(owner, 1_000, &data))],
        )
        .0
    };

    assert_eq!(
        run(),
        run(),
        "size-discriminated/no-tag accounts must not salt identity with arbitrary fresh data bytes"
    );
}

/// Identity tracks the creation slot, not the key: ordinals follow first-mark
/// order, and swapping the creation order of two differently-typed accounts
/// changes the fingerprint.
#[test]
fn test_creation_order_drives_identity() {
    // Distinguish the two account "types" by owner (always part of identity),
    // not by arbitrary body bytes — those are intentionally canonicalized /
    // ignored for created accounts without a registered discriminator, so a
    // body-only difference is not a robust distinguisher across the test suite's
    // shared discriminator registry.
    let vault_owner = fixed_owner();
    let token_owner = second_owner();
    let body = [0xAAu8; 32];

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let (fp_fwd, tracker) = run_creating(
        &CreationTracker::new(),
        &[
            (pk1, account_with(vault_owner, 1_000, &body)),
            (pk2, account_with(token_owner, 1_000, &body)),
        ],
    );
    assert_eq!(tracker.ordinal(&pk1), Some(0));
    assert_eq!(tracker.ordinal(&pk2), Some(1));

    // Same accounts, swapped creation order → ordinal 0 now holds the other
    // type, so the state is distinguishable.
    let (fp_swapped, tracker2) = run_creating(
        &CreationTracker::new(),
        &[
            (
                Pubkey::new_unique(),
                account_with(token_owner, 1_000, &body),
            ),
            (
                Pubkey::new_unique(),
                account_with(vault_owner, 1_000, &body),
            ),
        ],
    );
    assert_eq!(tracker2.len(), 2);
    assert_ne!(
        fp_fwd, fp_swapped,
        "swapping which account type occupies creation slot 0 must change the fingerprint"
    );
}

/// Salting the ordinal with owner + discriminator prevents over-collapse:
/// slot #0 holding a vault vs a token account are different states.
#[test]
fn test_same_slot_different_type_differ() {
    let data = [0x33u8; 32];

    let (fp_vault, _) = run_creating(
        &CreationTracker::new(),
        &[(
            Pubkey::new_unique(),
            account_with(fixed_owner(), 1_000, &data),
        )],
    );
    let (fp_token, _) = run_creating(
        &CreationTracker::new(),
        &[(
            Pubkey::new_unique(),
            account_with(second_owner(), 1_000, &data),
        )],
    );

    assert_ne!(
        fp_vault, fp_token,
        "same creation slot with a different owner (account type) must not collapse"
    );
}

/// Regression test for the per-snapshot (lineage-relative) tracker: a restored
/// state's path-created accounts keep their ordinals, and an account created
/// after restore continues the sequence — identically across two simulated
/// runs with completely different pubkeys.
#[test]
fn test_lineage_ordinal_continues_after_restore() {
    let owner = fixed_owner();
    let c0 = [0x44u8; 32];
    let c1 = [0x55u8; 32];
    let c2 = [0x66u8; 32];

    // One "run": iteration 1 creates two accounts (saved with the state),
    // iteration 2 restores that state, re-touches the first account, and
    // creates a third.
    let simulate_run = || -> (u64, CreationTracker, Vec<Pubkey>) {
        let pks = vec![
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ];

        // Iteration 1
        let (_fp1, tracker1) = run_creating(
            &CreationTracker::new(),
            &[
                (pks[0], account_with(owner, 1_000, &c0)),
                (pks[1], account_with(owner, 2_000, &c1)),
            ],
        );

        // Iteration 2: SVM holds the restored state (accounts 0 and 1) plus
        // the newly created account 2. Dirty set = re-touched 0 + created 2.
        let mut svm = LiteSVM::new();
        let initial = empty_initial(&svm);
        svm.set_account(pks[0], account_with(owner, 1_500, &c0))
            .unwrap();
        svm.set_account(pks[1], account_with(owner, 2_000, &c1))
            .unwrap();
        svm.set_account(pks[2], account_with(owner, 3_000, &c2))
            .unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pks[0]);
        dirty.mark_account_dirty(&pks[2]);
        let tracker2 = CreationTracker::extended_with_iteration(&tracker1, &dirty, &initial);
        let fp2 = compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial, &tracker2);
        (fp2, tracker2, pks)
    };

    let (fp_a, tracker_a, pks_a) = simulate_run();
    let (fp_b, tracker_b, pks_b) = simulate_run();

    // Path-created accounts keep 0,1; the post-restore creation gets 2.
    assert_eq!(tracker_a.ordinal(&pks_a[0]), Some(0));
    assert_eq!(tracker_a.ordinal(&pks_a[1]), Some(1));
    assert_eq!(tracker_a.ordinal(&pks_a[2]), Some(2));
    assert_eq!(tracker_b.ordinal(&pks_b[2]), Some(2));

    assert_eq!(
        fp_a, fp_b,
        "lineage-relative ordinals must make the extended state's fingerprint \
         identical across runs with different pubkeys"
    );
}

/// Accounts present in the initial snapshot keep pubkey identity: the same
/// modification applied to two different pre-existing accounts is two
/// different states.
#[test]
fn test_preexisting_account_still_keyed_by_pubkey() {
    let owner = fixed_owner();

    let run_with_preexisting = |pk: Pubkey| -> u64 {
        let mut svm = LiteSVM::new();
        let original = account_with(owner, 1_000, &[0u8; 32]);
        let mut initial = empty_initial(&svm);
        initial.accounts.insert(pk, Arc::new(original.clone()));
        // Modify the pre-existing account
        svm.set_account(pk, account_with(owner, 9_000, &[0x77u8; 32]))
            .unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk);
        let creation =
            CreationTracker::extended_with_iteration(&CreationTracker::new(), &dirty, &initial);
        assert_eq!(
            creation.ordinal(&pk),
            None,
            "pre-existing accounts must not receive creation ordinals"
        );
        compute_state_fingerprint_from_snapshot(&svm, &dirty, &initial, &creation)
    };

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    assert_eq!(
        run_with_preexisting(pk1),
        run_with_preexisting(pk1),
        "same pre-existing account modified the same way → same fingerprint"
    );
    assert_ne!(
        run_with_preexisting(pk1),
        run_with_preexisting(pk2),
        "different pre-existing accounts retain distinct pubkey identity"
    );
}

/// The combined fingerprint/novelty pass agrees with the standalone
/// fingerprint path on creation-ordinal identity (both must collapse
/// fresh-pubkey runs).
#[test]
fn test_combined_pass_collapses_fresh_pubkeys() {
    let owner = fixed_owner();
    let data = [0x88u8; 32];

    let run = || -> u64 {
        let mut svm = LiteSVM::new();
        let initial = empty_initial(&svm);
        let pk = Pubkey::new_unique();
        svm.set_account(pk, account_with(owner, 5_000, &data))
            .unwrap();
        let mut dirty = DirtyTracker::new();
        dirty.mark_account_dirty(&pk);
        let creation =
            CreationTracker::extended_with_iteration(&CreationTracker::new(), &dirty, &initial);
        let (fp, _changed, _novel) = unsafe {
            fingerprint_and_collect_changed(
                &svm,
                &dirty,
                &initial,
                &creation,
                std::ptr::null_mut(),
                0,
            )
        };
        fp
    };

    assert_eq!(
        run(),
        run(),
        "combined pass must be pubkey-independent for created accounts"
    );
}
