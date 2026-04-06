use super::super::*;
use crate::{FastHashMap, FastHashSet};
use anchor_lang::prelude::Clock;
use anchor_lang::prelude::sysvar::SysvarId;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;

/// Create a test Clock with a unique slot for unique fingerprints.
pub fn make_test_clock(slot: u64) -> Clock {
    Clock {
        slot,
        epoch_start_timestamp: 0,
        epoch: 0,
        leader_schedule_epoch: 0,
        unix_timestamp: slot as i64,
    }
}

/// Convert a Clock into a sysvars vec suitable for SvmSnapshot construction.
pub fn clock_to_sysvars(clock: &Clock) -> Vec<(Pubkey, Option<Account>)> {
    vec![(Clock::id(), Some(Account {
        lamports: 1,
        data: bincode::serialize(clock).unwrap(),
        owner: Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111"),
        executable: false,
        rent_epoch: 0,
    }))]
}

/// Create test sysvars (containing a Clock with the given slot) for SvmSnapshot construction.
pub fn make_test_sysvars(slot: u64) -> Vec<(Pubkey, Option<Account>)> {
    clock_to_sysvars(&make_test_clock(slot))
}

/// Build action_bytes in the FuzzInput format: 4-byte LE count header + payload.
pub fn make_action_bytes(count: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = count.to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

/// Add a simple state to the pool with the given fingerprint and depth.
/// Returns true if added.
pub fn add_test_state(
    pool: &mut StatePool,
    fingerprint: u64,
    depth: u32,
    parent_idx: Option<usize>,
    action_desc: &str,
    action_variant: Option<u16>,
) -> bool {
    let action_bytes = make_action_bytes(1, &[0xAA, 0xBB]);
    pool.try_add(
        fingerprint,
        SvmSnapshot::empty(make_test_clock(depth as u64)),
        depth,
        parent_idx,
        action_bytes,
        action_desc.to_string(),
        action_variant,
        vec![0xCC],
        None,
        0,
        0,
        true,
        None,
    )
}

/// Helper: create a non-executable test account with the given lamports and data.
pub fn make_account(lamports: u64, data: &[u8]) -> Account {
    Account {
        lamports,
        data: data.to_vec(),
        owner: Pubkey::new_unique(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Helper: simulate the stateful restore logic used in the real fuzzer loop.
/// If prev_delta is Some, uses restore_selective_from; otherwise restore_selective.
pub fn simulate_restore(
    initial: &SvmSnapshot,
    svm: &mut LiteSVM,
    divergent_keys: &FastHashSet<Pubkey>,
    delta: &SvmSnapshot,
    prev_delta: Option<&SvmSnapshot>,
    prev_exec_dirty: &FastHashSet<Pubkey>,
) {
    if let Some(prev) = prev_delta {
        initial.restore_selective_from(svm, divergent_keys, prev, delta, prev_exec_dirty);
    } else {
        initial.restore_selective(svm, divergent_keys, delta);
    }
}

/// Full-state verification: asserts EVERY account in the SVM matches the
/// expected state (initial + delta overlay). Accounts in delta get delta
/// value; all other initial accounts get initial value; CPI accounts not
/// in delta must be gone.
pub fn verify_full_state(
    svm: &LiteSVM,
    initial: &SvmSnapshot,
    delta: &SvmSnapshot,
    extra_must_be_gone: &[Pubkey],
    context: &str,
) {
    // All initial accounts should be at initial or delta value
    for (pk, initial_acct) in initial.accounts() {
        let expected = delta.accounts().get(pk).unwrap_or(initial_acct);
        if expected.lamports == 0 {
            assert!(svm.get_account(pk).is_none(),
                "{}: pk {:?} should be tombstoned (0 lamports)", context, pk);
        } else {
            let got = svm.get_account(pk);
            assert!(got.is_some(),
                "{}: pk {:?} expected lamports={} but account missing", context, pk, expected.lamports);
            let got = got.unwrap();
            assert_eq!(got.lamports, expected.lamports,
                "{}: pk {:?} lamports mismatch", context, pk);
            assert_eq!(got.data, expected.data,
                "{}: pk {:?} data mismatch", context, pk);
            assert_eq!(got.owner, expected.owner,
                "{}: pk {:?} owner mismatch", context, pk);
        }
    }
    // Delta accounts NOT in initial must also be set
    for (pk, delta_acct) in delta.accounts() {
        if initial.accounts().contains_key(pk) { continue; }
        if delta_acct.lamports == 0 {
            assert!(svm.get_account(pk).is_none(),
                "{}: CPI pk {:?} should be tombstoned", context, pk);
        } else {
            let got = svm.get_account(pk).unwrap_or_else(||
                panic!("{}: CPI pk {:?} expected lamports={} but missing", context, pk, delta_acct.lamports));
            assert_eq!(got.lamports, delta_acct.lamports,
                "{}: CPI pk {:?} lamports mismatch", context, pk);
        }
    }
    // Extra accounts must be gone
    for pk in extra_must_be_gone {
        assert!(svm.get_account(pk).is_none(),
            "{}: stale pk {:?} should be gone", context, pk);
    }
}

/// Simulate one full fuzzer iteration: restore, execute (creating/modifying
/// accounts), update tracking variables. Returns CPI accounts created.
pub fn simulate_fuzzer_iteration(
    initial: &SvmSnapshot,
    svm: &mut LiteSVM,
    divergent_keys: &mut FastHashSet<Pubkey>,
    prev_delta_arc: &mut Option<SvmSnapshot>,
    prev_exec_dirty: &mut FastHashSet<Pubkey>,
    delta: &SvmSnapshot,
    exec_modifications: &[(Pubkey, Option<Account>)], // None = "SVM already has it from CPI"
    action_succeeds: bool,
) -> Vec<Pubkey> {
    // 1. Restore
    if let Some(ref prev) = prev_delta_arc {
        initial.restore_selective_from(svm, divergent_keys, prev, delta, prev_exec_dirty);
    } else {
        initial.restore_selective(svm, divergent_keys, delta);
    }
    divergent_keys.clear();
    divergent_keys.extend(delta.accounts().keys().copied());

    // 2. Execute — apply modifications
    let mut cpi_created = Vec::new();
    let mut dirty = DirtyTracker::new();
    for (pk, maybe_acct) in exec_modifications {
        if let Some(acct) = maybe_acct {
            svm.set_account(*pk, acct.clone()).unwrap();
        }
        dirty.mark_account_dirty(pk);
        if !initial.accounts().contains_key(pk) && !delta.accounts().contains_key(pk) {
            cpi_created.push(*pk);
        }
    }

    // 3. Update tracking (mirrors real codegen lines 727-737)
    prev_exec_dirty.clear();
    prev_exec_dirty.extend(dirty.dirty_accounts().iter().copied());
    divergent_keys.extend(prev_exec_dirty.iter().copied());
    if action_succeeds {
        *prev_delta_arc = Some(delta.clone());
    } else {
        *prev_delta_arc = None;
    }

    cpi_created
}

/// Helper to create a minimal SvmSnapshot with specific accounts for pool tests.
pub fn make_pool_snapshot(accounts: Vec<(Pubkey, u64)>) -> SvmSnapshot {
    let mut map = FastHashMap::default();
    for (pk, lamports) in accounts {
        map.insert(pk, std::sync::Arc::new(make_account(lamports, &[])));
    }
    SvmSnapshot { accounts: map, sysvars: make_test_sysvars(0) }
}

/// Helper to create a pool entry with minimal boilerplate.
pub fn add_pool_entry(
    pool: &mut StatePool,
    fingerprint: u64,
    delta: SvmSnapshot,
    depth: u32,
    parent_idx: Option<usize>,
) -> bool {
    pool.try_add(
        fingerprint, delta, depth, parent_idx,
        vec![0u8; 8], // action_bytes (dummy 4-byte header + 4-byte action)
        format!("action_fp_{:x}", fingerprint),
        Some((fingerprint & 0xF) as u16),
        vec![],
        None,
        0,
        0,
        true,
        None,
    )
}
