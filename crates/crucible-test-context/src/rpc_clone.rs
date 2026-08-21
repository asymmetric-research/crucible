use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::filter::RpcFilterType;

use crate::TestContext;

/// BPF Loader Upgradeable program ID
const BPF_LOADER_UPGRADEABLE: Pubkey =
    solana_pubkey::pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");

/// Default cache directory name (relative to working directory)
const DEFAULT_CACHE_DIR: &str = ".fuzz-cache/accounts";

/// Max accounts returned by `clone_program_accounts` before bailing
const DEFAULT_MAX_PROGRAM_ACCOUNTS: usize = 1000;

/// Max accounts per `getMultipleAccounts` RPC call
const BATCH_CHUNK_SIZE: usize = 100;

/// Metadata stored alongside cached account data
#[derive(Debug, Serialize, Deserialize)]
struct CachedAccountMeta {
    pubkey: String,
    owner: String,
    lamports: u64,
    executable: bool,
    rent_epoch: u64,
    data_len: usize,
}

impl CachedAccountMeta {
    fn from_account(pubkey: &Pubkey, account: &Account) -> Self {
        Self {
            pubkey: pubkey.to_string(),
            owner: account.owner.to_string(),
            lamports: account.lamports,
            executable: account.executable,
            rent_epoch: account.rent_epoch,
            data_len: account.data.len(),
        }
    }

    fn to_account(&self, data: Vec<u8>) -> Result<Account> {
        Ok(Account {
            lamports: self.lamports,
            data,
            owner: self
                .owner
                .parse()
                .context("invalid owner pubkey in cache")?,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        })
    }
}

/// Clones accounts from a Solana RPC endpoint into a local `TestContext`,
/// with transparent disk caching.
///
/// Accounts are cached to `.fuzz-cache/accounts/` by default. Subsequent
/// runs load from cache without making RPC calls.
pub struct AccountCloner<'a> {
    ctx: &'a mut TestContext,
    rpc: RpcClient,
    cache_dir: PathBuf,
    force_refresh: bool,
    max_program_accounts: usize,
}

impl<'a> AccountCloner<'a> {
    /// Create a new `AccountCloner` targeting the given RPC URL.
    pub fn new(ctx: &'a mut TestContext, rpc_url: &str) -> Self {
        Self {
            ctx,
            rpc: RpcClient::new(rpc_url.to_string()),
            cache_dir: PathBuf::from(DEFAULT_CACHE_DIR),
            force_refresh: false,
            max_program_accounts: DEFAULT_MAX_PROGRAM_ACCOUNTS,
        }
    }

    /// Override the cache directory (default: `.fuzz-cache/accounts/`).
    pub fn cache_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_dir = path.into();
        self
    }

    /// Always fetch from RPC, ignoring any cached data.
    pub fn force_refresh(mut self) -> Self {
        self.force_refresh = true;
        self
    }

    /// Set max accounts for `clone_program_accounts` (default: 1000).
    pub fn max_program_accounts(mut self, max: usize) -> Self {
        self.max_program_accounts = max;
        self
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Clone a single account from RPC into the local SVM.
    ///
    /// Automatically detects BPF Upgradeable programs and handles the
    /// two-account structure (program account + ProgramData account).
    pub fn clone_account(&mut self, pubkey: &Pubkey) -> Result<()> {
        let account = self.fetch_or_cached(pubkey)?;
        self.load_account(pubkey, &account)
    }

    /// Clone multiple accounts in a single batched RPC call.
    ///
    /// Uses `getMultipleAccounts` in chunks of 100.
    pub fn clone_accounts(&mut self, pubkeys: &[Pubkey]) -> Result<()> {
        if pubkeys.is_empty() {
            return Ok(());
        }

        // Split into cached vs needs-fetch
        let mut to_fetch: Vec<(usize, Pubkey)> = Vec::new();
        let mut accounts: Vec<Option<Account>> = vec![None; pubkeys.len()];

        for (i, pk) in pubkeys.iter().enumerate() {
            if !self.force_refresh {
                if let Some(cached) = self.read_cache(pk)? {
                    accounts[i] = Some(cached);
                    continue;
                }
            }
            to_fetch.push((i, *pk));
        }

        // Batch-fetch uncached accounts
        for chunk in to_fetch.chunks(BATCH_CHUNK_SIZE) {
            let keys: Vec<Pubkey> = chunk.iter().map(|(_, pk)| *pk).collect();
            let fetched = self
                .rpc
                .get_multiple_accounts(&keys)
                .context("RPC getMultipleAccounts failed")?;

            for ((idx, pk), maybe_account) in chunk.iter().zip(fetched.into_iter()) {
                let account = maybe_account
                    .ok_or_else(|| anyhow::anyhow!("Account {} not found on RPC", pk))?;
                self.write_cache(pk, &account)?;
                accounts[*idx] = Some(account);
            }
        }

        // Load all into SVM
        for (i, pk) in pubkeys.iter().enumerate() {
            let account = accounts[i]
                .take()
                .ok_or_else(|| anyhow::anyhow!("Account {} missing after fetch", pk))?;
            self.load_account(pk, &account)?;
        }

        Ok(())
    }

    /// Clone all accounts owned by `program_id` matching the given filters.
    ///
    /// **Requires at least one filter** (data size or memcmp) to prevent
    /// accidentally fetching millions of accounts from programs like SPL Token.
    ///
    /// Returns the pubkeys of all cloned accounts.
    pub fn clone_program_accounts(
        &mut self,
        program_id: &Pubkey,
        filters: &[RpcFilterType],
    ) -> Result<Vec<Pubkey>> {
        if filters.is_empty() {
            bail!(
                "clone_program_accounts requires at least one filter. \
                 Unfiltered getProgramAccounts can return millions of results."
            );
        }

        let config = solana_rpc_client_api::config::RpcProgramAccountsConfig {
            filters: Some(filters.to_vec()),
            account_config: solana_rpc_client_api::config::RpcAccountInfoConfig {
                encoding: Some(solana_rpc_client_api::config::UiAccountEncoding::Base64),
                ..Default::default()
            },
            ..Default::default()
        };

        let keyed_accounts = self
            .rpc
            .get_program_ui_accounts_with_config(program_id, config)
            .context("RPC getProgramAccounts failed")?;

        if keyed_accounts.len() > self.max_program_accounts {
            bail!(
                "getProgramAccounts returned {} accounts (max: {}). \
                 Add stricter filters or increase max with .max_program_accounts().",
                keyed_accounts.len(),
                self.max_program_accounts,
            );
        }

        eprintln!(
            "clone_program_accounts: fetched {} accounts for program {}",
            keyed_accounts.len(),
            program_id,
        );

        let mut pubkeys = Vec::with_capacity(keyed_accounts.len());
        for (pk, ui_account) in keyed_accounts {
            let account = ui_account.to_account().with_context(|| {
                format!("RPC returned undecodable binary account data for {pk}")
            })?;
            self.write_cache(&pk, &account)?;
            self.load_account(&pk, &account)?;
            pubkeys.push(pk);
        }

        Ok(pubkeys)
    }

    /// Remove a single account from the disk cache.
    pub fn invalidate(&self, pubkey: &Pubkey) -> Result<()> {
        let key_str = pubkey.to_string();
        let meta_path = self.cache_dir.join(format!("{}.json", key_str));
        let data_path = self.cache_dir.join(format!("{}.bin", key_str));
        if meta_path.exists() {
            fs::remove_file(&meta_path)
                .with_context(|| format!("failed to remove {}", meta_path.display()))?;
        }
        if data_path.exists() {
            fs::remove_file(&data_path)
                .with_context(|| format!("failed to remove {}", data_path.display()))?;
        }
        Ok(())
    }

    /// Remove all cached accounts.
    pub fn clear_cache(&self) -> Result<()> {
        if self.cache_dir.exists() {
            fs::remove_dir_all(&self.cache_dir).with_context(|| {
                format!("failed to clear cache at {}", self.cache_dir.display())
            })?;
        }
        Ok(())
    }

    // ========================================================================
    // Cache layer
    // ========================================================================

    /// Read an account from the disk cache. Returns `None` on cache miss.
    #[doc(hidden)]
    pub fn read_cache(&self, pubkey: &Pubkey) -> Result<Option<Account>> {
        let key_str = pubkey.to_string();
        let meta_path = self.cache_dir.join(format!("{}.json", key_str));
        let data_path = self.cache_dir.join(format!("{}.bin", key_str));

        if !meta_path.exists() || !data_path.exists() {
            return Ok(None);
        }

        let meta_bytes = fs::read(&meta_path)
            .with_context(|| format!("failed to read cache meta {}", meta_path.display()))?;
        let meta: CachedAccountMeta = serde_json::from_slice(&meta_bytes)
            .with_context(|| format!("failed to parse cache meta {}", meta_path.display()))?;
        let data = fs::read(&data_path)
            .with_context(|| format!("failed to read cache data {}", data_path.display()))?;

        Ok(Some(meta.to_account(data)?))
    }

    /// Write an account to the disk cache.
    #[doc(hidden)]
    pub fn write_cache(&self, pubkey: &Pubkey, account: &Account) -> Result<()> {
        fs::create_dir_all(&self.cache_dir)
            .with_context(|| format!("failed to create cache dir {}", self.cache_dir.display()))?;

        let key_str = pubkey.to_string();
        let meta = CachedAccountMeta::from_account(pubkey, account);
        let meta_json = serde_json::to_string_pretty(&meta)?;

        fs::write(
            self.cache_dir.join(format!("{}.json", key_str)),
            meta_json.as_bytes(),
        )?;
        fs::write(
            self.cache_dir.join(format!("{}.bin", key_str)),
            &account.data,
        )?;

        Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Fetch from cache (if available and not force_refresh) or from RPC.
    fn fetch_or_cached(&mut self, pubkey: &Pubkey) -> Result<Account> {
        if !self.force_refresh {
            if let Some(cached) = self.read_cache(pubkey)? {
                return Ok(cached);
            }
        }

        let account = self
            .rpc
            .get_account(pubkey)
            .with_context(|| format!("RPC getAccount failed for {}", pubkey))?;
        self.write_cache(pubkey, &account)?;
        Ok(account)
    }

    /// Load an account into the SVM, handling program detection.
    fn load_account(&mut self, pubkey: &Pubkey, account: &Account) -> Result<()> {
        if account.executable && account.owner == BPF_LOADER_UPGRADEABLE {
            self.load_upgradeable_program(pubkey, account)
        } else if account.executable {
            // BPF Loader v1/v2: account data IS the ELF
            self.ctx.add_program_from_bytes(pubkey, &account.data)
        } else {
            self.ctx.write_account(pubkey, account.clone())
        }
    }

    /// Handle BPF Upgradeable Loader program: fetch ProgramData, extract ELF.
    fn load_upgradeable_program(&mut self, program_id: &Pubkey, account: &Account) -> Result<()> {
        let programdata_address = parse_programdata_address(&account.data)
            .with_context(|| format!("Program account {}", program_id))?;

        // Fetch the ProgramData account
        let programdata = self.fetch_or_cached(&programdata_address)?;

        let elf_bytes = extract_elf_bytes(&programdata.data)
            .with_context(|| format!("ProgramData {}", programdata_address))?;
        self.ctx.add_program_from_bytes(program_id, elf_bytes)?;

        // Order matters: write the ProgramData account BEFORE the program
        // account. LiteSVM's `add_account` triggers `load_program(&account)`
        // for executable accounts owned by BPFLoaderUpgradeab1e, which in
        // turn looks up the programdata account by pubkey. If programdata
        // isn't present yet, the load fails with `MissingAccount` and
        // litesvm logs:
        //   "Program data account <pk> not found"
        // Writing programdata first avoids that spurious error.
        self.ctx.write_account(&programdata_address, programdata)?;
        self.ctx.write_account(program_id, account.clone())?;

        Ok(())
    }
}

/// Parse the ProgramData address from a BPF Upgradeable program account's data.
///
/// Layout: bytes 0..4 = account type (u32 LE), bytes 4..36 = ProgramData pubkey.
fn parse_programdata_address(program_account_data: &[u8]) -> Result<Pubkey> {
    if program_account_data.len() < 36 {
        bail!(
            "Program account data too short ({} bytes) for BPF Upgradeable Loader",
            program_account_data.len(),
        );
    }
    Ok(Pubkey::from(
        <[u8; 32]>::try_from(&program_account_data[4..36]).expect("slice is 32 bytes"),
    ))
}

/// Extract ELF bytes from a ProgramData account's data.
///
/// Layout: 45-byte header, then ELF binary.
fn extract_elf_bytes(programdata_data: &[u8]) -> Result<&[u8]> {
    const PROGRAMDATA_HEADER_SIZE: usize = 45;
    if programdata_data.len() < PROGRAMDATA_HEADER_SIZE {
        bail!(
            "ProgramData data too short ({} bytes)",
            programdata_data.len(),
        );
    }
    Ok(&programdata_data[PROGRAMDATA_HEADER_SIZE..])
}

/// Returns true if the account appears to be a BPF Upgradeable program.
pub fn is_upgradeable_program(account: &Account) -> bool {
    account.executable && account.owner == BPF_LOADER_UPGRADEABLE
}

/// Returns true if the account is executable (any loader).
pub fn is_program(account: &Account) -> bool {
    account.executable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    /// Helper: create a test account with given data.
    fn make_account(owner: Pubkey, lamports: u64, data: Vec<u8>, executable: bool) -> Account {
        Account {
            lamports,
            data,
            owner,
            executable,
            rent_epoch: 42,
        }
    }

    /// Helper: build an AccountCloner pointing at a temp cache dir.
    /// RPC URL is bogus — only use for cache/invalidate/clear_cache tests.
    fn make_cloner<'a>(ctx: &'a mut TestContext, cache_dir: &Path) -> AccountCloner<'a> {
        AccountCloner::new(ctx, "http://localhost:0").cache_dir(cache_dir)
    }

    // ====================================================================
    // CachedAccountMeta round-trip
    // ====================================================================

    #[test]
    fn cached_account_meta_roundtrip() {
        let owner = Pubkey::new_unique();
        let pubkey = Pubkey::new_unique();
        let data = vec![1, 2, 3, 4, 5];
        let account = make_account(owner, 999, data.clone(), true);

        let meta = CachedAccountMeta::from_account(&pubkey, &account);
        assert_eq!(meta.pubkey, pubkey.to_string());
        assert_eq!(meta.owner, owner.to_string());
        assert_eq!(meta.lamports, 999);
        assert!(meta.executable);
        assert_eq!(meta.rent_epoch, 42);
        assert_eq!(meta.data_len, 5);

        let restored = meta.to_account(data.clone()).unwrap();
        assert_eq!(restored.lamports, account.lamports);
        assert_eq!(restored.data, account.data);
        assert_eq!(restored.owner, account.owner);
        assert_eq!(restored.executable, account.executable);
        assert_eq!(restored.rent_epoch, account.rent_epoch);
    }

    #[test]
    fn cached_account_meta_invalid_owner() {
        let meta = CachedAccountMeta {
            pubkey: Pubkey::new_unique().to_string(),
            owner: "not-a-pubkey".to_string(),
            lamports: 0,
            executable: false,
            rent_epoch: 0,
            data_len: 0,
        };
        assert!(meta.to_account(vec![]).is_err());
    }

    // ====================================================================
    // Cache read/write/invalidate/clear
    // ====================================================================

    #[test]
    fn cache_write_then_read() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, tmp.path());

        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let data = vec![10, 20, 30];
        let account = make_account(owner, 500, data.clone(), false);

        cloner.write_cache(&pubkey, &account).unwrap();
        let loaded = cloner.read_cache(&pubkey).unwrap().expect("cache hit");

        assert_eq!(loaded.lamports, 500);
        assert_eq!(loaded.data, data);
        assert_eq!(loaded.owner, owner);
        assert!(!loaded.executable);
        assert_eq!(loaded.rent_epoch, 42);
    }

    #[test]
    fn cache_miss_returns_none() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, tmp.path());

        let result = cloner.read_cache(&Pubkey::new_unique()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cache_creates_directory_on_write() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, &nested);

        let pk = Pubkey::new_unique();
        let account = make_account(Pubkey::new_unique(), 1, vec![], false);
        cloner.write_cache(&pk, &account).unwrap();

        assert!(nested.exists());
        assert!(cloner.read_cache(&pk).unwrap().is_some());
    }

    #[test]
    fn invalidate_removes_cached_account() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, tmp.path());

        let pk = Pubkey::new_unique();
        let account = make_account(Pubkey::new_unique(), 1, vec![0xFF], false);
        cloner.write_cache(&pk, &account).unwrap();
        assert!(cloner.read_cache(&pk).unwrap().is_some());

        cloner.invalidate(&pk).unwrap();
        assert!(cloner.read_cache(&pk).unwrap().is_none());

        // Files should be gone
        let key_str = pk.to_string();
        assert!(!tmp.path().join(format!("{}.json", key_str)).exists());
        assert!(!tmp.path().join(format!("{}.bin", key_str)).exists());
    }

    #[test]
    fn invalidate_nonexistent_is_ok() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, tmp.path());

        // Should not error on missing files
        cloner.invalidate(&Pubkey::new_unique()).unwrap();
    }

    #[test]
    fn clear_cache_removes_everything() {
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("cache");
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, &cache_dir);

        // Write a few accounts
        for _ in 0..3 {
            let pk = Pubkey::new_unique();
            let account = make_account(Pubkey::new_unique(), 1, vec![1, 2], false);
            cloner.write_cache(&pk, &account).unwrap();
        }
        assert!(cache_dir.exists());

        cloner.clear_cache().unwrap();
        assert!(!cache_dir.exists());
    }

    #[test]
    fn clear_cache_nonexistent_dir_is_ok() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does_not_exist");
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, &missing);

        cloner.clear_cache().unwrap();
    }

    #[test]
    fn cache_overwrite_updates_data() {
        let tmp = TempDir::new().unwrap();
        let mut ctx = TestContext::new();
        let cloner = make_cloner(&mut ctx, tmp.path());

        let pk = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let v1 = make_account(owner, 100, vec![1], false);
        let v2 = make_account(owner, 200, vec![2, 3], true);

        cloner.write_cache(&pk, &v1).unwrap();
        cloner.write_cache(&pk, &v2).unwrap();

        let loaded = cloner.read_cache(&pk).unwrap().unwrap();
        assert_eq!(loaded.lamports, 200);
        assert_eq!(loaded.data, vec![2, 3]);
        assert!(loaded.executable);
    }

    // ====================================================================
    // Upgradeable program byte parsing
    // ====================================================================

    #[test]
    fn parse_programdata_address_valid() {
        let expected_pk = Pubkey::new_unique();
        let mut data = vec![0u8; 36];
        // bytes 0..4: account type
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        // bytes 4..36: pubkey
        data[4..36].copy_from_slice(expected_pk.as_ref());

        let result = parse_programdata_address(&data).unwrap();
        assert_eq!(result, expected_pk);
    }

    #[test]
    fn parse_programdata_address_extra_data_is_fine() {
        let expected_pk = Pubkey::new_unique();
        let mut data = vec![0u8; 100];
        data[4..36].copy_from_slice(expected_pk.as_ref());

        let result = parse_programdata_address(&data).unwrap();
        assert_eq!(result, expected_pk);
    }

    #[test]
    fn parse_programdata_address_too_short() {
        assert!(parse_programdata_address(&[0u8; 35]).is_err());
        assert!(parse_programdata_address(&[]).is_err());
    }

    #[test]
    fn extract_elf_bytes_valid() {
        let elf = b"ELF_PAYLOAD";
        let mut data = vec![0u8; 45 + elf.len()];
        data[45..].copy_from_slice(elf);

        let result = extract_elf_bytes(&data).unwrap();
        assert_eq!(result, elf);
    }

    #[test]
    fn extract_elf_bytes_exact_header_returns_empty() {
        let data = vec![0u8; 45];
        let result = extract_elf_bytes(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn extract_elf_bytes_too_short() {
        assert!(extract_elf_bytes(&[0u8; 44]).is_err());
        assert!(extract_elf_bytes(&[]).is_err());
    }

    // ====================================================================
    // Free functions
    // ====================================================================

    #[test]
    fn is_upgradeable_program_checks_owner_and_executable() {
        let upgradeable = make_account(BPF_LOADER_UPGRADEABLE, 1, vec![], true);
        assert!(is_upgradeable_program(&upgradeable));

        // Not executable
        let not_exec = make_account(BPF_LOADER_UPGRADEABLE, 1, vec![], false);
        assert!(!is_upgradeable_program(&not_exec));

        // Wrong owner
        let wrong_owner = make_account(Pubkey::new_unique(), 1, vec![], true);
        assert!(!is_upgradeable_program(&wrong_owner));
    }

    #[test]
    fn is_program_checks_executable_flag() {
        let exec = make_account(Pubkey::new_unique(), 1, vec![], true);
        assert!(is_program(&exec));

        let not_exec = make_account(Pubkey::new_unique(), 1, vec![], false);
        assert!(!is_program(&not_exec));
    }

    // ====================================================================
    // Builder API
    // ====================================================================

    #[test]
    fn builder_defaults() {
        let mut ctx = TestContext::new();
        let cloner = AccountCloner::new(&mut ctx, "http://example.com");
        assert_eq!(cloner.cache_dir, PathBuf::from(DEFAULT_CACHE_DIR));
        assert!(!cloner.force_refresh);
        assert_eq!(cloner.max_program_accounts, DEFAULT_MAX_PROGRAM_ACCOUNTS);
    }

    #[test]
    fn builder_overrides() {
        let mut ctx = TestContext::new();
        let cloner = AccountCloner::new(&mut ctx, "http://example.com")
            .cache_dir("/tmp/my-cache")
            .force_refresh()
            .max_program_accounts(50);
        assert_eq!(cloner.cache_dir, PathBuf::from("/tmp/my-cache"));
        assert!(cloner.force_refresh);
        assert_eq!(cloner.max_program_accounts, 50);
    }
}
