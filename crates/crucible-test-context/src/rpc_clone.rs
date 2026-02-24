use std::path::PathBuf;
use std::fs;

use anyhow::{Context, Result, bail};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::filter::RpcFilterType;
use serde::{Serialize, Deserialize};

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
            owner: self.owner.parse().context("invalid owner pubkey in cache")?,
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
            let fetched = self.rpc.get_multiple_accounts(&keys)
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
            let account = accounts[i].take()
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

        #[allow(deprecated)] // new API returns UI types, we need Account
        let keyed_accounts = self.rpc
            .get_program_accounts_with_config(program_id, config)
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
        for (pk, account) in &keyed_accounts {
            self.write_cache(pk, account)?;
            self.load_account(pk, account)?;
            pubkeys.push(*pk);
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
            fs::remove_dir_all(&self.cache_dir)
                .with_context(|| format!("failed to clear cache at {}", self.cache_dir.display()))?;
        }
        Ok(())
    }

    // ========================================================================
    // Cache layer
    // ========================================================================

    /// Read an account from the disk cache. Returns `None` on cache miss.
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

        let account = self.rpc.get_account(pubkey)
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
        // Upgradeable program account data layout:
        // bytes 0..4  : account type (u32 LE) = 2 for Program
        // bytes 4..36 : ProgramData address (Pubkey)
        if account.data.len() < 36 {
            bail!(
                "Program account {} data too short ({} bytes) for BPF Upgradeable Loader",
                program_id,
                account.data.len(),
            );
        }

        let programdata_address = Pubkey::from(<[u8; 32]>::try_from(&account.data[4..36])
            .expect("slice is 32 bytes"));

        // Fetch the ProgramData account
        let programdata = self.fetch_or_cached(&programdata_address)?;

        // ProgramData layout:
        // bytes 0..4  : account type (u32 LE) = 3 for ProgramData
        // bytes 4..5  : Option<Pubkey> tag (1 byte, 0 = None, 1 = Some)
        // bytes 5..37 : upgrade authority (if tag == 1)
        // bytes 37..45: slot (u64 LE)
        // bytes 45..  : ELF binary
        const PROGRAMDATA_HEADER_SIZE: usize = 45;
        if programdata.data.len() < PROGRAMDATA_HEADER_SIZE {
            bail!(
                "ProgramData {} data too short ({} bytes)",
                programdata_address,
                programdata.data.len(),
            );
        }

        let elf_bytes = &programdata.data[PROGRAMDATA_HEADER_SIZE..];
        self.ctx.add_program_from_bytes(program_id, elf_bytes)?;

        // Also write both accounts to SVM so account queries work
        self.ctx.write_account(program_id, account.clone())?;
        self.ctx.write_account(&programdata_address, programdata)?;

        Ok(())
    }
}

/// Returns true if the account appears to be a BPF Upgradeable program.
pub fn is_upgradeable_program(account: &Account) -> bool {
    account.executable && account.owner == BPF_LOADER_UPGRADEABLE
}

/// Returns true if the account is executable (any loader).
pub fn is_program(account: &Account) -> bool {
    account.executable
}
