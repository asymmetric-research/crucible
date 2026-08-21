//! Diagnostic tests for the stateful fuzzer's novelty detection system.
//!
//! These tests simulate the 5-step crash chain from the Solana stake program bug
//! to identify why stateful mode can't discover the sequence:
//!   delegate_stake → advance_slots(54520) → deactivate → withdraw → delegate_stake
//!
//! The core hypothesis: `advance_slots` produces near-zero novelty (no BPF execution,
//! only clock sysvar changes), and subsequent `deactivate` produces zero novelty because
//! the deactivation code path / field changes were already seen from other states.

use super::helpers::*;
use super::super::*;
use super::super::svm_snapshot::FINGERPRINT_BITS;
use crate::FastHashSet;
use anchor_lang::prelude::Clock;
use anchor_lang::prelude::sysvar::SysvarId;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;

/// Allocate a fresh field novelty bitmap (zeroed).
fn fresh_bitmap() -> Vec<u8> {
    vec![0u8; FIELD_NOVELTY_BITMAP_SIZE]
}

/// Set up an SVM with a "stake-like" account + clock, take initial snapshot.
/// Returns (svm, stake_pubkey, initial_snapshot).
fn setup_stake_scenario() -> (LiteSVM, Pubkey, SvmSnapshot) {
    let mut svm = LiteSVM::new();
    let stake_pk = Pubkey::new_unique();

    // Simulate initialized stake account: 200 bytes of data, some initial fields set
    let mut initial_data = vec![0u8; 200];
    // Bytes 0-3: discriminant (StakeStateV2::Initialized = 1)
    initial_data[0..4].copy_from_slice(&1u32.to_le_bytes());
    // Bytes 4-67: authorized (staker + withdrawer pubkeys)
    initial_data[4..36].copy_from_slice(&[0xAA; 32]); // staker
    initial_data[36..68].copy_from_slice(&[0xBB; 32]); // withdrawer

    svm.set_account(stake_pk, Account {
        lamports: 10_000_000_000, // 10 SOL
        data: initial_data,
        owner: Pubkey::from_str_const("Stake11111111111111111111111111111111111111"),
        executable: false,
        rent_epoch: 0,
    }).unwrap();

    let mut tracked = HashSet::new();
    tracked.insert(stake_pk);
    let initial = SvmSnapshot::take(&svm, &tracked);

    (svm, stake_pk, initial)
}

// =========================================================================
// Test 1: slot_diff_bucket collapse for large advances
// =========================================================================

#[test]
fn advance_slots_novelty_collapse() {
    // Verify that slot_diff_bucket collapses large values into the overflow bucket,
    // causing advance_slots to produce zero novelty after a moderately large advance.

    // Bucket boundaries from slot_diff_bucket:
    //   0-9: individual
    //   10-99: per-10 (buckets 10-18)
    //   100-999: per-100 (buckets 19-27)
    //   1000-2000: per-1000 (buckets 28-29)
    //   >2000: overflow bucket 30
    assert_eq!(slot_diff_bucket(0), 0);
    assert_eq!(slot_diff_bucket(5), 5);
    assert_eq!(slot_diff_bucket(50), 9 + 5);    // 14
    assert_eq!(slot_diff_bucket(500), 18 + 5);   // 23
    assert_eq!(slot_diff_bucket(1500), 27 + 1);  // 28
    assert_eq!(slot_diff_bucket(2000), 27 + 2);  // 29

    // Extended granularity: per-1K (28-36), per-10K (37-45), per-100K (46-54)
    assert_eq!(slot_diff_bucket(2001), 27 + 2);  // 29
    assert_eq!(slot_diff_bucket(5000), 27 + 5);  // 32
    assert_eq!(slot_diff_bucket(9999), 27 + 9);  // 36
    assert_eq!(slot_diff_bucket(10000), 36 + 1);  // 37
    assert_eq!(slot_diff_bucket(54520), 36 + 5);  // 41
    assert_eq!(slot_diff_bucket(99999), 36 + 9);  // 45
    assert_eq!(slot_diff_bucket(100_000), 45 + 1); // 46
    assert_eq!(slot_diff_bucket(999_999), 45 + 9); // 54
    assert_eq!(slot_diff_bucket(1_000_000), 55);   // overflow

    // Key: advance(5000) and advance(54520) now produce DIFFERENT buckets
    assert_ne!(slot_diff_bucket(5000), slot_diff_bucket(54520));

    // Now verify that this collapse causes novelty loss.
    // Simulate: advance_slots with different values, sharing a single bitmap.
    let (mut svm, _stake_pk, initial) = setup_stake_scenario();

    // The initial snapshot has slot=0. Advancing to different slots simulates advance_slots.
    let mut bitmap = fresh_bitmap();
    let tracker = DirtyTracker::new(); // empty — advance_slots doesn't mark accounts dirty

    // Advance to slot 100 (bucket 14) — should be novel
    svm.warp_to_slot(100);
    let novel_100 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_100 >= 1, "advance to slot 100 should be novel, got {}", novel_100);

    // Advance to slot 1000 (bucket 23) — should be novel (different bucket)
    svm.warp_to_slot(1000);
    let novel_1000 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_1000 >= 1, "advance to slot 1000 should be novel, got {}", novel_1000);

    // Advance to slot 3000 (bucket 30 = 27+3) — should be novel
    svm.warp_to_slot(3000);
    let novel_3000 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_3000 >= 1, "advance to slot 3000 should be novel, got {}", novel_3000);

    // Advance to slot 54520 (bucket 41 = 36+5) — NOW NOVEL with extended bucketing!
    // Previously this was bucket 30 (same as 3000), causing the advance_slots intermediate
    // to get zero novelty and be evicted. With extended slot_diff_bucket, different
    // large advances produce different buckets.
    svm.warp_to_slot(54520);
    let novel_54520 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_54520 >= 1,
        "advance to slot 54520 should now be novel (bucket {} vs {}), got {}",
        slot_diff_bucket(54520), slot_diff_bucket(3000), novel_54520
    );
}

// =========================================================================
// Test 2: deactivate after advance produces zero novelty when deactivate
//         was already seen from a different parent
// =========================================================================

#[test]
fn deactivate_after_advance_not_novel() {
    let (mut svm, stake_pk, initial) = setup_stake_scenario();

    let mut bitmap = fresh_bitmap();

    // --- Scenario A: "deactivate from initial" (no advance_slots) ---
    // Simulate deactivation by modifying the stake account: set deactivation_epoch
    let mut deactivated_data_a = svm.get_account(&stake_pk).unwrap().data.clone();
    // Bytes 0-3: change discriminant to Stake (2)
    deactivated_data_a[0..4].copy_from_slice(&2u32.to_le_bytes());
    // Bytes 128-135: deactivation_epoch = 1 (set during deactivation)
    deactivated_data_a[128..136].copy_from_slice(&1u64.to_le_bytes());
    // Bytes 136-143: activation_epoch = 0
    deactivated_data_a[136..144].copy_from_slice(&0u64.to_le_bytes());

    svm.set_account(stake_pk, Account {
        lamports: 10_000_000_000,
        data: deactivated_data_a,
        owner: Pubkey::from_str_const("Stake11111111111111111111111111111111111111"),
        executable: false,
        rent_epoch: 0,
    }).unwrap();

    let mut tracker_a = DirtyTracker::new();
    tracker_a.mark_account_dirty(&stake_pk);

    let novel_a = unsafe {
        check_field_novelty(&svm, &tracker_a, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_a >= 1, "first deactivation should be novel, got {}", novel_a);
    eprintln!("[diag] scenario A (deactivate from initial): {} novel bits", novel_a);

    // --- Scenario B: "deactivate after advance_slots(54520)" ---
    // Same account modifications (deactivation_epoch set), but clock is advanced.
    // Reset to initial state first
    let initial_account = initial.accounts().get(&stake_pk).unwrap();
    svm.set_account(stake_pk, (**initial_account).clone()).unwrap();

    // Advance clock (simulating advance_slots)
    svm.warp_to_slot(54520);

    // Now apply same deactivation change
    let mut deactivated_data_b = (**initial_account).data.clone();
    deactivated_data_b[0..4].copy_from_slice(&2u32.to_le_bytes());
    // Key difference: deactivation_epoch might be different (e.g., epoch 50 vs 1)
    // But we're testing the case where the value buckets overlap
    deactivated_data_b[128..136].copy_from_slice(&50u64.to_le_bytes());
    deactivated_data_b[136..144].copy_from_slice(&0u64.to_le_bytes());

    svm.set_account(stake_pk, Account {
        lamports: 10_000_000_000,
        data: deactivated_data_b,
        owner: Pubkey::from_str_const("Stake11111111111111111111111111111111111111"),
        executable: false,
        rent_epoch: 0,
    }).unwrap();

    let mut tracker_b = DirtyTracker::new();
    tracker_b.mark_account_dirty(&stake_pk);

    let novel_b = unsafe {
        check_field_novelty(&svm, &tracker_b, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    eprintln!("[diag] scenario B (deactivate after advance 54520): {} novel bits", novel_b);

    // If novel_b == 0, the hypothesis is confirmed: the deactivation after advance
    // produces zero novelty because the field changes were already covered by scenario A.
    //
    // If novel_b > 0, the epoch-based clock×account novelty might be saving us,
    // and the issue is elsewhere (e.g., eviction of the advance_slots intermediate).
    //
    // Either result is informative.
    eprintln!(
        "[diag] DIAGNOSIS: scenario B novelty = {}. If 0, confirms hypothesis \
         (deactivate novelty eaten by prior states). If >0, issue is advance_slots \
         eviction or action selection.",
        novel_b
    );
}

// =========================================================================
// Test 3: epoch value bucketing — does epoch distinguish states?
// =========================================================================

#[test]
fn epoch_distinguishes_clock_novelty() {
    let (mut svm, _stake_pk, initial) = setup_stake_scenario();

    let mut bitmap = fresh_bitmap();
    let tracker = DirtyTracker::new(); // empty for clock-only changes

    // Set clock to epoch 1 (slot doesn't matter much, use a small slot diff)
    let clock_e1 = Clock { slot: 500, epoch: 1, epoch_start_timestamp: 0, leader_schedule_epoch: 0, unix_timestamp: 500 };
    svm.set_sysvar(&clock_e1);

    let novel_e1 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    assert!(novel_e1 >= 1, "epoch 1 should be novel");
    eprintln!("[diag] epoch 1: {} novel bits", novel_e1);

    // Set clock to epoch 5
    let clock_e5 = Clock { slot: 2500, epoch: 5, epoch_start_timestamp: 0, leader_schedule_epoch: 0, unix_timestamp: 2500 };
    svm.set_sysvar(&clock_e5);

    let novel_e5 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    eprintln!("[diag] epoch 5: {} novel bits (should be >0 if epoch buckets differ)", novel_e5);

    // Set clock to epoch 50
    let clock_e50 = Clock { slot: 25000, epoch: 50, epoch_start_timestamp: 0, leader_schedule_epoch: 0, unix_timestamp: 25000 };
    svm.set_sysvar(&clock_e50);

    let novel_e50 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    eprintln!("[diag] epoch 50: {} novel bits", novel_e50);

    // value_bucket(1) vs value_bucket(5) vs value_bucket(50):
    // From value_bucket: 1-9 are individual buckets, 10-99 are per-10 buckets
    // So epoch 1 → bucket 1, epoch 5 → bucket 5 (different), epoch 50 → bucket 14 (different)
    let b1 = value_bucket(1);
    let b5 = value_bucket(5);
    let b50 = value_bucket(50);
    eprintln!("[diag] value_bucket: epoch 1 → {}, epoch 5 → {}, epoch 50 → {}", b1, b5, b50);
    assert_ne!(b1, b5, "epochs 1 and 5 should be in different value buckets");
    assert_ne!(b5, b50, "epochs 5 and 50 should be in different value buckets");

    // But note: slot_diff_bucket might collapse the slot differences
    let s500 = slot_diff_bucket(500);
    let s2500 = slot_diff_bucket(2500);
    let s25000 = slot_diff_bucket(25000);
    eprintln!("[diag] slot_diff_bucket: slot 500 → {}, slot 2500 → {}, slot 25000 → {}", s500, s2500, s25000);
    // slot_diff_bucket(2500) = 30 (overflow), slot_diff_bucket(25000) = 30 (overflow)
    // So epochs 5 and 50 have the SAME slot_diff_bucket despite different epochs.
    // The epoch bucket field_hash is separate, so epochs should still be distinguished.

    // Key question: does the epoch novelty check fire even when no accounts are dirty?
    // Looking at check_field_novelty: it checks `if slot_diff > 0 || clock.epoch != initial_clock.epoch`
    // and sets bits for CLOCK_TYPE_KEY offset 0 (slot_diff_bucket) and offset 1 (value_bucket(epoch)).
    // So yes, epoch novelty is checked even with no dirty accounts.
}

// =========================================================================
// Test 4: combined account × clock novelty — does the clock×account hash
//         distinguish "same field change at different epochs"?
// =========================================================================

#[test]
fn clock_x_account_novelty_distinguishes_epochs() {
    let (mut svm, stake_pk, initial) = setup_stake_scenario();

    let mut bitmap = fresh_bitmap();

    // --- State A: modify stake data at epoch 0 ---
    let initial_account = initial.accounts().get(&stake_pk).unwrap();
    let mut data_a = (**initial_account).data.clone();
    data_a[0..4].copy_from_slice(&2u32.to_le_bytes()); // change discriminant
    data_a[128..136].copy_from_slice(&1u64.to_le_bytes()); // deactivation_epoch = 1

    svm.set_account(stake_pk, Account {
        lamports: 10_000_000_000,
        data: data_a,
        owner: (**initial_account).owner,
        executable: false,
        rent_epoch: 0,
    }).unwrap();

    let mut tracker_a = DirtyTracker::new();
    tracker_a.mark_account_dirty(&stake_pk);

    // Clock stays at initial (slot=0, epoch=0)
    let novel_a = unsafe {
        check_field_novelty(&svm, &tracker_a, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    eprintln!("[diag] state A (deactivate at epoch 0): {} novel bits", novel_a);
    assert!(novel_a >= 1);

    // --- State B: same data modification but at epoch 50 (after advance_slots) ---
    svm.set_account(stake_pk, (**initial_account).clone()).unwrap();
    let clock_e50 = Clock { slot: 54520, epoch: 50, epoch_start_timestamp: 0, leader_schedule_epoch: 0, unix_timestamp: 54520 };
    svm.set_sysvar(&clock_e50);

    let mut data_b = (**initial_account).data.clone();
    data_b[0..4].copy_from_slice(&2u32.to_le_bytes()); // same discriminant change
    data_b[128..136].copy_from_slice(&50u64.to_le_bytes()); // deactivation_epoch = 50 (different!)

    svm.set_account(stake_pk, Account {
        lamports: 10_000_000_000,
        data: data_b,
        owner: (**initial_account).owner,
        executable: false,
        rent_epoch: 0,
    }).unwrap();

    let mut tracker_b = DirtyTracker::new();
    tracker_b.mark_account_dirty(&stake_pk);

    let novel_b = unsafe {
        check_field_novelty(&svm, &tracker_b, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    eprintln!("[diag] state B (deactivate at epoch 50): {} novel bits", novel_b);

    // The critical question: does the clock×account novelty hash distinguish these?
    // check_field_novelty hashes: field_hash(type_key, LAMPORTS_SENTINEL - 1, sdb)
    // where sdb = slot_diff_bucket(slot_diff). For state B, sdb = 30 (overflow).
    // This is a combined account×clock hash. If state A had sdb = 0 (no advance),
    // then the combined hash is different. But ONLY if the account was dirty in BOTH cases.
    //
    // Also: per-identity×clock hash at line 728-735 uses pubkey + lamports_bucket + sdb.
    // If lamports are the same, the only difference is sdb (slot_diff_bucket).
    // State A: sdb = 0 (no advance). State B: sdb = 30 (overflow).
    // These ARE different → novel_b should be > 0.
    //
    // HOWEVER: in the real fuzzer, the "deactivate from initial" (state A) happens
    // WITHOUT advance_slots, so sdb = 0. The "deactivate after advance" (state B)
    // has sdb = 30. These produce different hashes! So the combined clock×account
    // novelty SHOULD distinguish them.
    //
    // If novel_b > 0: the issue is NOT field novelty — it's either:
    //   (a) the advance_slots intermediate was evicted before deactivate was tried
    //   (b) the deactivation produces the same EDGE coverage (already explored code path)
    //       AND field novelty alone isn't enough to save the state (needs edge OR field)
    //
    // Actually, re-reading the save condition in stateful.rs:
    //   if __field_novel_bits > 0 || __edge_novel_bits > 0 → save
    // So field novelty alone IS sufficient to save a state.
    //
    // This means: if novel_b > 0, the real issue is the advance_slots intermediate
    // being evicted (low weight due to near-zero novelty), not the deactivation itself.

    eprintln!(
        "[diag] CONCLUSION: novel_b = {}. If >0, the deactivate-after-advance IS \
         distinguishable — the real bottleneck is the advance_slots intermediate being \
         evicted from the pool before the fuzzer tries deactivate from it.",
        novel_b
    );
}

// =========================================================================
// Test 5: advance_slots intermediate — quantify exactly how much novelty
//         it produces, and whether it would survive eviction
// =========================================================================

#[test]
fn advance_slots_intermediate_novelty_budget() {
    let (mut svm, _stake_pk, initial) = setup_stake_scenario();

    let mut bitmap = fresh_bitmap();
    let tracker = DirtyTracker::new(); // empty — no accounts dirty

    // Simulate: advance_slots(54520) as the FIRST action (from initial)
    svm.warp_to_slot(54520);

    let novel = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };

    eprintln!("[diag] advance_slots(54520) from initial:");
    eprintln!("[diag]   novel bits = {}", novel);
    eprintln!("[diag]   slot_diff_bucket = {}", slot_diff_bucket(54520));

    let clock: Clock = svm.get_sysvar();
    eprintln!("[diag]   epoch = {}", clock.epoch);
    eprintln!("[diag]   value_bucket(epoch) = {}", value_bucket(clock.epoch));

    // Now simulate: the SECOND advance_slots is tried from a state that already
    // had advance_slots. The bitmap already has the bits from the first advance.
    // A new advance_slots with a different slot count should get zero novelty
    // if it falls in the same slot_diff_bucket.

    svm.warp_to_slot(100_000); // much larger, still bucket 30
    let novel2 = unsafe {
        check_field_novelty(&svm, &tracker, &initial, bitmap.as_mut_ptr(), bitmap.len())
    };
    let clock2: Clock = svm.get_sysvar();
    eprintln!("[diag] advance_slots(100000) after advance_slots(54520):");
    eprintln!("[diag]   novel bits = {}", novel2);
    eprintln!("[diag]   epoch = {}, value_bucket = {}", clock2.epoch, value_bucket(clock2.epoch));

    // The advance_slots intermediate gets at most 2 novelty bits (clock fields).
    // In the pool's compute_weight(), states with 0 edge novelty and low field novelty
    // get minimal weight → they're the first to be evicted.
    //
    // Compare: state 64 (delegate_stake → advance_slots → deactivate_delinquent) has
    // 33 novel bits and 32 edge novelty. The advance_slots intermediate had maybe 2
    // novel bits and 0 edge novelty. In the weight function:
    //   - Coverage states (edge > 0): floor weight 2-1000x
    //   - Non-coverage, field-novel: depth_bonus + decay at 200 picks
    //   - Non-coverage, no novelty: decay at 50 picks
    // The advance_slots intermediate falls in "non-coverage, field-novel" with only
    // 2 bits. It gets a small depth bonus but decays quickly.
    eprintln!(
        "[diag] DIAGNOSIS: advance_slots produces {} novelty bits and 0 edge coverage. \
         This makes it a low-weight state that gets evicted early, preventing the fuzzer \
         from ever trying deactivate from delegate_stake → advance_slots.",
        novel
    );
}

// =========================================================================
// Test 6: fingerprint determinism — do different advance_slots amounts
//         produce different fingerprints?
// =========================================================================

#[test]
fn advance_slots_fingerprint_discrimination() {
    let (mut svm, stake_pk, initial) = setup_stake_scenario();

    let mut tracker = DirtyTracker::new();
    // Mark clock dirty (advance_slots does this)
    tracker.mark_clock_dirty(100);

    // Fingerprint after advance_slots(100)
    svm.warp_to_slot(100);
    let fp_100 = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial, &crate::snapshot::CreationTracker::new());

    // Reset and fingerprint after advance_slots(1000)
    initial.restore_full(&mut svm);
    svm.warp_to_slot(1000);
    let fp_1000 = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial, &crate::snapshot::CreationTracker::new());

    // Reset and fingerprint after advance_slots(3000)
    initial.restore_full(&mut svm);
    svm.warp_to_slot(3000);
    let fp_3000 = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial, &crate::snapshot::CreationTracker::new());

    // Reset and fingerprint after advance_slots(54520)
    initial.restore_full(&mut svm);
    svm.warp_to_slot(54520);
    let fp_54520 = compute_state_fingerprint_from_snapshot(&svm, &tracker, &initial, &crate::snapshot::CreationTracker::new());

    eprintln!("[diag] fingerprints:");
    eprintln!("[diag]   advance(100):   {:#018x}", fp_100);
    eprintln!("[diag]   advance(1000):  {:#018x}", fp_1000);
    eprintln!("[diag]   advance(3000):  {:#018x}", fp_3000);
    eprintln!("[diag]   advance(54520): {:#018x}", fp_54520);

    // Different slot_diff_buckets should give different fingerprints
    assert_ne!(fp_100, fp_1000, "different slot_diff buckets should differ");
    assert_ne!(fp_1000, fp_3000, "slot 1000 (bucket 28) vs 3000 (bucket 30) should differ");

    // With extended slot_diff_bucket, 3000 (bucket 30) and 54520 (bucket 41) should
    // now produce DIFFERENT fingerprints even if epoch is the same.
    assert_ne!(fp_3000, fp_54520,
        "advance(3000) and advance(54520) should now have different fingerprints \
         (slot_diff_bucket {} vs {})", slot_diff_bucket(3000), slot_diff_bucket(54520));
}
