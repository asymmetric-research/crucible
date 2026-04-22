#![cfg(feature = "rpc-clone")]

use crucible_test_context::rpc_clone::{is_program, is_upgradeable_program, AccountCloner};
use solana_account::Account;
use solana_pubkey::Pubkey;
use tempfile::TempDir;

/// Helper: create a dummy Account with given data
fn make_account(data: &[u8], owner: Pubkey, lamports: u64, executable: bool) -> Account {
    Account {
        lamports,
        data: data.to_vec(),
        owner,
        executable,
        rent_epoch: 42,
    }
}

/// Helper: build an AccountCloner with a temp cache dir (no RPC calls).
/// Returns (cloner, temp_dir) - temp_dir must be held alive for the duration.
fn make_cloner_with_cache(
    ctx: &mut crucible_test_context::TestContext,
) -> (AccountCloner<'_>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let cache_dir = tmp.path().join("cache");
    let cloner = AccountCloner::new(ctx, "http://localhost:0") // dummy URL
        .cache_dir(cache_dir);
    (cloner, tmp)
}

fn make_test_context() -> crucible_test_context::TestContext {
    crucible_test_context::TestContext::new()
}

#[test]
fn test_cache_round_trip() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pubkey = Pubkey::new_unique();
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let owner = Pubkey::new_unique();
    let account = make_account(&data, owner, 1_000_000, false);

    // Write to cache
    cloner.write_cache(&pubkey, &account).unwrap();

    // Read back
    let cached = cloner
        .read_cache(&pubkey)
        .unwrap()
        .expect("should find cached account");

    assert_eq!(cached.lamports, 1_000_000);
    assert_eq!(cached.owner, owner);
    assert_eq!(cached.data, data);
    assert!(!cached.executable);
    assert_eq!(cached.rent_epoch, 42);
}

#[test]
fn test_cache_round_trip_large_data() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pubkey = Pubkey::new_unique();
    // 1 MB of data (simulating a large program account)
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let owner = Pubkey::new_unique();
    let account = make_account(&data, owner, 100_000_000, true);

    cloner.write_cache(&pubkey, &account).unwrap();
    let cached = cloner
        .read_cache(&pubkey)
        .unwrap()
        .expect("should find cached account");

    assert_eq!(cached.data.len(), 1_000_000);
    assert_eq!(cached.data, data);
    assert!(cached.executable);
}

#[test]
fn test_cache_miss_returns_none() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pubkey = Pubkey::new_unique();
    let result = cloner.read_cache(&pubkey).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_invalidate_single() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pubkey = Pubkey::new_unique();
    let account = make_account(&[10, 20], Pubkey::new_unique(), 500, false);

    cloner.write_cache(&pubkey, &account).unwrap();
    assert!(cloner.read_cache(&pubkey).unwrap().is_some());

    cloner.invalidate(&pubkey).unwrap();
    assert!(cloner.read_cache(&pubkey).unwrap().is_none());
}

#[test]
fn test_clear_cache() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let pk3 = Pubkey::new_unique();
    let account = make_account(&[1], Pubkey::new_unique(), 100, false);

    cloner.write_cache(&pk1, &account).unwrap();
    cloner.write_cache(&pk2, &account).unwrap();
    cloner.write_cache(&pk3, &account).unwrap();

    cloner.clear_cache().unwrap();

    assert!(cloner.read_cache(&pk1).unwrap().is_none());
    assert!(cloner.read_cache(&pk2).unwrap().is_none());
    assert!(cloner.read_cache(&pk3).unwrap().is_none());
}

#[test]
fn test_program_detection_upgradeable() {
    let bpf_upgradeable: Pubkey = "BPFLoaderUpgradeab1e11111111111111111111111"
        .parse()
        .unwrap();
    let account = make_account(&[0; 36], bpf_upgradeable, 1_000_000, true);

    assert!(is_upgradeable_program(&account));
    assert!(is_program(&account));
}

#[test]
fn test_non_program_account() {
    let system_program: Pubkey = "11111111111111111111111111111111".parse().unwrap();
    let account = make_account(&[1, 2, 3], system_program, 500, false);

    assert!(!is_upgradeable_program(&account));
    assert!(!is_program(&account));
}

#[test]
fn test_program_non_upgradeable() {
    // An executable account with some other loader
    let other_loader = Pubkey::new_unique();
    let account = make_account(&[0xEF; 100], other_loader, 1_000_000, true);

    assert!(!is_upgradeable_program(&account));
    assert!(is_program(&account)); // still a program, just not upgradeable
}

#[test]
fn test_cache_dir_created_on_write() {
    let mut ctx = make_test_context();
    let tmp = TempDir::new().unwrap();
    let cache_dir = tmp.path().join("deeply").join("nested").join("cache");

    let cloner = AccountCloner::new(&mut ctx, "http://localhost:0").cache_dir(&cache_dir);

    assert!(!cache_dir.exists());

    let pubkey = Pubkey::new_unique();
    let account = make_account(&[42], Pubkey::new_unique(), 100, false);
    cloner.write_cache(&pubkey, &account).unwrap();

    assert!(cache_dir.exists());
    assert!(cloner.read_cache(&pubkey).unwrap().is_some());
}

#[test]
fn test_force_refresh_flag() {
    let mut ctx = make_test_context();
    let tmp = TempDir::new().unwrap();
    let cache_dir = tmp.path().join("cache");

    // Create a cloner without force_refresh and cache an account
    let cloner = AccountCloner::new(&mut ctx, "http://localhost:0").cache_dir(&cache_dir);

    let pubkey = Pubkey::new_unique();
    let account = make_account(&[1, 2, 3], Pubkey::new_unique(), 100, false);
    cloner.write_cache(&pubkey, &account).unwrap();

    // Verify cache hit works
    let cached = cloner.read_cache(&pubkey).unwrap();
    assert!(cached.is_some());

    // With force_refresh, the cloner would skip cache and go to RPC.
    // We can't test the full flow without RPC, but we verify the flag is set
    // by checking that clone_account would attempt RPC (and fail with connection error).
    let mut cloner_refresh = AccountCloner::new(&mut ctx, "http://localhost:0")
        .cache_dir(&cache_dir)
        .force_refresh();

    // This should try RPC (skip cache) and fail since localhost:0 isn't listening
    let result = cloner_refresh.clone_account(&pubkey);
    assert!(
        result.is_err(),
        "force_refresh should skip cache and hit RPC"
    );
}

#[test]
fn test_invalidate_nonexistent_is_ok() {
    let mut ctx = make_test_context();
    let (cloner, _tmp) = make_cloner_with_cache(&mut ctx);

    let pubkey = Pubkey::new_unique();
    // Should not error when invalidating a key that doesn't exist
    cloner.invalidate(&pubkey).unwrap();
}

#[test]
fn test_clear_nonexistent_cache_is_ok() {
    let mut ctx = make_test_context();
    let tmp = TempDir::new().unwrap();
    let cache_dir = tmp.path().join("nonexistent");

    let cloner = AccountCloner::new(&mut ctx, "http://localhost:0").cache_dir(cache_dir);

    // Should not error when clearing a cache that doesn't exist
    cloner.clear_cache().unwrap();
}
