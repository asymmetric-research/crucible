use anchor_test::*;
#[allow(unused_imports)]
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::{rc::Rc, collections::HashMap};

use anchor_test::anchor_spl::token::spl_token;
use anchor_test::anchor_spl::token_2022::spl_token_2022;

// Local types module with klend account structs for zero-copy access
mod types;

// Generate types from IDL
anchor_fuzz_gen::declare_fuzz_program!("idls/klend.json");

use kamino_lending::instruction;
use kamino_lending::accounts;
use kamino_lending::types::{InitObligationArgs, UpdateConfigMode};

// ============================================================================
// Constants
// ============================================================================

// Set to true to enable debug output
const DEBUG: bool = false;

// Diagnostic module - tracks early returns, program errors, and successes
mod action_stats {
    use std::sync::atomic::{AtomicU32, Ordering};

    // Success/fail counters per action
    pub static DEPOSIT_OK: AtomicU32 = AtomicU32::new(0);
    pub static DEPOSIT_FAIL: AtomicU32 = AtomicU32::new(0);
    pub static DEPOSIT_COLL_OK: AtomicU32 = AtomicU32::new(0);
    pub static DEPOSIT_COLL_FAIL: AtomicU32 = AtomicU32::new(0);
    pub static BORROW_OK: AtomicU32 = AtomicU32::new(0);
    pub static BORROW_FAIL: AtomicU32 = AtomicU32::new(0);
    pub static REPAY_OK: AtomicU32 = AtomicU32::new(0);
    pub static REPAY_FAIL: AtomicU32 = AtomicU32::new(0);
    pub static WITHDRAW_OK: AtomicU32 = AtomicU32::new(0);
    pub static WITHDRAW_FAIL: AtomicU32 = AtomicU32::new(0);
    pub static LIQUIDATE_OK: AtomicU32 = AtomicU32::new(0);
    pub static LIQUIDATE_FAIL: AtomicU32 = AtomicU32::new(0);

    // Early return counters per action
    pub static DEPOSIT_EARLY: AtomicU32 = AtomicU32::new(0);
    pub static DEPOSIT_COLL_EARLY: AtomicU32 = AtomicU32::new(0);
    pub static BORROW_EARLY: AtomicU32 = AtomicU32::new(0);
    pub static REPAY_EARLY: AtomicU32 = AtomicU32::new(0);
    pub static WITHDRAW_EARLY: AtomicU32 = AtomicU32::new(0);
    pub static LIQUIDATE_EARLY: AtomicU32 = AtomicU32::new(0);

    pub static TOTAL_ACTIONS: AtomicU32 = AtomicU32::new(0);

    // Per-action log limits (2 per action type = 12 total)
    static DEPOSIT_LOG: AtomicU32 = AtomicU32::new(0);
    static DEPOSIT_COLL_LOG: AtomicU32 = AtomicU32::new(0);
    static BORROW_LOG: AtomicU32 = AtomicU32::new(0);
    static REPAY_LOG: AtomicU32 = AtomicU32::new(0);
    static WITHDRAW_LOG: AtomicU32 = AtomicU32::new(0);
    static LIQUIDATE_LOG: AtomicU32 = AtomicU32::new(0);

    fn get_log_counter(action: &str) -> &'static AtomicU32 {
        match action {
            "deposit" => &DEPOSIT_LOG,
            "deposit_coll" => &DEPOSIT_COLL_LOG,
            "borrow" => &BORROW_LOG,
            "repay" => &REPAY_LOG,
            "withdraw" => &WITHDRAW_LOG,
            "liquidate" => &LIQUIDATE_LOG,
            _ => &DEPOSIT_LOG,
        }
    }

    pub fn log_early_return(action: &str, reason: &str, early_counter: &AtomicU32) {
        early_counter.fetch_add(1, Ordering::Relaxed);
        // Also count toward total for summary printing
        let total = TOTAL_ACTIONS.fetch_add(1, Ordering::Relaxed) + 1;

        // Log first 2 early returns per action
        let log_counter = get_log_counter(action);
        if log_counter.fetch_add(1, Ordering::Relaxed) < 2 && super::DEBUG {
            eprintln!("[EARLY] {}: {}", action, reason);
        }

        maybe_print_summary(total);
    }

    pub fn log_program_error(action: &str, err: &str, logs: &[String]) {
        // Log first 2 program errors per action
        let log_counter = get_log_counter(action);
        if log_counter.load(Ordering::Relaxed) < 4 && super::DEBUG {
            log_counter.fetch_add(1, Ordering::Relaxed);
            eprintln!("[PROG_ERR] {}: {}", action, err);
            for log in logs.iter().take(3) {
                eprintln!("  {}", log);
            }
        }
    }

    pub fn record(ok: &AtomicU32, fail: &AtomicU32, success: bool) {
        if success {
            ok.fetch_add(1, Ordering::Relaxed);
        } else {
            fail.fetch_add(1, Ordering::Relaxed);
        }
        let total = TOTAL_ACTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        maybe_print_summary(total);
    }

    fn maybe_print_summary(total: u32) {
        // Print diagnostic summary every 100 actions
        if total % 100 == 0 && super::DEBUG {
            eprintln!("[DIAG @{}] deposit: ok={} fail={} early={} | coll: ok={} fail={} early={} | borrow: ok={} fail={} early={}",
                total,
                DEPOSIT_OK.load(Ordering::Relaxed), DEPOSIT_FAIL.load(Ordering::Relaxed), DEPOSIT_EARLY.load(Ordering::Relaxed),
                DEPOSIT_COLL_OK.load(Ordering::Relaxed), DEPOSIT_COLL_FAIL.load(Ordering::Relaxed), DEPOSIT_COLL_EARLY.load(Ordering::Relaxed),
                BORROW_OK.load(Ordering::Relaxed), BORROW_FAIL.load(Ordering::Relaxed), BORROW_EARLY.load(Ordering::Relaxed),
            );
            eprintln!("[DIAG @{}] repay: ok={} fail={} early={} | withdraw: ok={} fail={} early={} | liq: ok={} fail={} early={}",
                total,
                REPAY_OK.load(Ordering::Relaxed), REPAY_FAIL.load(Ordering::Relaxed), REPAY_EARLY.load(Ordering::Relaxed),
                WITHDRAW_OK.load(Ordering::Relaxed), WITHDRAW_FAIL.load(Ordering::Relaxed), WITHDRAW_EARLY.load(Ordering::Relaxed),
                LIQUIDATE_OK.load(Ordering::Relaxed), LIQUIDATE_FAIL.load(Ordering::Relaxed), LIQUIDATE_EARLY.load(Ordering::Relaxed),
            );
        }
    }
}

const LENDING_MARKET_SIZE: usize = 4656;
const RESERVE_SIZE: usize = types::RESERVE_SIZE;
const OBLIGATION_SIZE: usize = types::OBLIGATION_SIZE;
const USER_METADATA_SIZE: usize = types::USER_METADATA_SIZE;
const GLOBAL_CONFIG_SIZE: usize = types::GLOBAL_CONFIG_SIZE;

// Default min deposit for reserves
const MIN_INITIAL_DEPOSIT: u64 = 100_000;

// Seeds
const LENDING_MARKET_AUTH: &[u8] = b"lma";
const RESERVE_LIQ_SUPPLY: &[u8] = b"reserve_liq_supply";
const FEE_RECEIVER: &[u8] = b"fee_receiver";
const RESERVE_COLL_MINT: &[u8] = b"reserve_coll_mint";
const RESERVE_COLL_SUPPLY: &[u8] = b"reserve_coll_supply";
const BASE_SEED_USER_METADATA: &[u8] = b"user_meta";
const GLOBAL_CONFIG_STATE: &[u8] = b"global_config";

// Sysvar IDs for Solana v3
mod sysvar_ids {
    pub fn rent_id() -> solana_pubkey::Pubkey {
        solana_pubkey::Pubkey::new_from_array([
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51,
            0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f,
            0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
            0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    pub fn instructions_id() -> solana_pubkey::Pubkey {
        solana_pubkey::Pubkey::new_from_array([
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66,
            0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
            0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5,
            0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
        ])
    }
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Clone)]
struct ReserveData {
    reserve: Pubkey,
    mint: Pubkey,
    liquidity_supply: Pubkey,
    collateral_mint: Pubkey,
    collateral_supply: Pubkey,
    fee_receiver: Pubkey,
    decimals: u8,
}

#[derive(Clone)]
#[allow(dead_code)]
struct UserData {
    keypair: Rc<Keypair>,
    obligation: Pubkey,
    user_metadata: Pubkey,
    token_accounts: HashMap<Pubkey, Pubkey>,  // mint -> token account
}

#[derive(Clone)]
#[allow(dead_code)]
struct KlendFixture {
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    lending_market: Pubkey,
    lending_market_authority: Pubkey,
    reserves: Vec<ReserveData>,
    users: Vec<UserData>,
}

#[fuzz_fixture]
impl KlendFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = kamino_lending::ID;

        // Load program
        ctx.add_program(&program_id, "../../kamino_lending.so")
            .expect("Failed to load klend program");

        fixture_helpers::initialize_state(&mut ctx, &program_id)
    }

    // Directly patch reserve's last_update to bypass staleness checks
    // This avoids needing to call RefreshReserve (which requires valid oracles)
    fn patch_reserve_freshness(&mut self, reserve_idx: usize) {
        let reserve_pubkey = self.reserves[reserve_idx].reserve;
        if let Ok(mut reserve) = self.ctx.read_zero_copy_account::<types::Reserve>(&reserve_pubkey) {
            let current_slot = self.ctx.slot();
            reserve.last_update.mark_fresh(current_slot);
            let _ = self.ctx.write_zero_copy_account(&reserve_pubkey, &reserve);
        }
    }

    // Patch obligation's last_update to bypass staleness checks
    fn patch_obligation_freshness(&mut self, user_idx: usize) {
        let obligation_pubkey = self.users[user_idx].obligation;
        if let Ok(mut obligation) = self.ctx.read_zero_copy_account::<types::Obligation>(&obligation_pubkey) {
            let current_slot = self.ctx.slot();
            obligation.last_update.mark_fresh(current_slot);
            let _ = self.ctx.write_zero_copy_account(&obligation_pubkey, &obligation);
        }
    }

    // Refresh all reserves and obligation by patching their last_update timestamps
    fn patch_freshness_all(&mut self, user_idx: usize) {
        for i in 0..self.reserves.len() {
            self.patch_reserve_freshness(i);
        }
        self.patch_obligation_freshness(user_idx);
    }

    // Legacy helpers for compatibility
    fn queue_refresh_all(&mut self, user_idx: usize) {
        // Now just patches accounts directly instead of queueing RefreshReserve calls
        self.patch_freshness_all(user_idx);
    }

    // ========================================================================
    // Deposit Action
    // ========================================================================

    pub fn action_deposit(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(1..10_000_000)] amount: u64,
    ) {
        // Patch reserve freshness to pass staleness check
        self.patch_reserve_freshness(reserve_idx);

        let reserve = self.reserves[reserve_idx].clone();
        let user_pubkey = self.users[user_idx].keypair.pubkey();

        let token_account = match self.users[user_idx].token_accounts.get(&reserve.mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("deposit", "no_token_account", &action_stats::DEPOSIT_EARLY);
                return;
            }
        };

        let balance = self.ctx.token_balance(&token_account);
        let amount = amount.min(balance);
        if amount == 0 {
            action_stats::log_early_return("deposit", &format!("zero_balance (bal={})", balance), &action_stats::DEPOSIT_EARLY);
            return;
        }

        // Create or get destination collateral account for the user
        let user_collateral_account = match self.users[user_idx].token_accounts.get(&reserve.collateral_mint) {
            Some(acc) => *acc,
            None => {
                // Create collateral token account for user
                let collateral_acc = self.ctx.create_token_account()
                    .pubkey(Keypair::new().pubkey())
                    .mint(reserve.collateral_mint)
                    .token_owner(user_pubkey)
                    .create()
                    .unwrap();
                // Save it to user's token_accounts so deposit_collateral can find it
                self.users[user_idx].token_accounts.insert(reserve.collateral_mint, collateral_acc);
                collateral_acc
            }
        };

        // Use the simpler deposit_reserve_liquidity instruction
        let user_keypair = &self.users[user_idx].keypair;
        let result = self.ctx.program(self.program_id)
            .call(instruction::DepositReserveLiquidity {
                liquidity_amount: amount,
            })
            .accounts(accounts::DepositReserveLiquidity {
                owner: user_pubkey,
                reserve: reserve.reserve,
                lending_market: self.lending_market,
                lending_market_authority: self.lending_market_authority,
                reserve_liquidity_mint: reserve.mint,
                reserve_liquidity_supply: reserve.liquidity_supply,
                reserve_collateral_mint: reserve.collateral_mint,
                user_source_liquidity: token_account,
                user_destination_collateral: user_collateral_account,
                collateral_token_program: spl_token::id(),
                liquidity_token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .signers(&[&**user_keypair])
            .send();

        // Track result and log errors
        let success = matches!(result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = result {
            action_stats::log_program_error("deposit", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::DEPOSIT_OK, &action_stats::DEPOSIT_FAIL, success);
    }

    // ========================================================================
    // Deposit Collateral to Obligation Action
    // ========================================================================

    pub fn action_deposit_collateral(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(1..10_000_000)] amount: u64,
    ) {
        let collateral_mint = self.reserves[reserve_idx].collateral_mint;

        // If user doesn't have cTokens, do a deposit first (smart harness)
        if self.users[user_idx].token_accounts.get(&collateral_mint).is_none() {
            // Call deposit to get cTokens - use amount as the deposit amount
            self.action_deposit(user_idx, reserve_idx, amount);
        }

        // Extract values early to avoid borrow checker issues
        let collateral_mint = self.reserves[reserve_idx].collateral_mint;

        // User needs cTokens (collateral tokens) from a previous deposit
        let user_collateral_account = match self.users[user_idx].token_accounts.get(&collateral_mint) {
            Some(acc) => *acc,
            None => {
                // Deposit failed to create cToken account
                action_stats::log_early_return("deposit_coll", "deposit_failed_no_ctokens", &action_stats::DEPOSIT_COLL_EARLY);
                return;
            }
        };

        // Check balance and limit amount
        let balance = self.ctx.token_balance(&user_collateral_account);
        let amount = amount.min(balance);
        if amount == 0 {
            action_stats::log_early_return("deposit_coll", &format!("zero_ctoken_balance (bal={})", balance), &action_stats::DEPOSIT_COLL_EARLY);
            return;
        }

        // Extract remaining values before mutable borrow
        let user_keypair = self.users[user_idx].keypair.clone();
        let user_obligation = self.users[user_idx].obligation;
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let collateral_supply = self.reserves[reserve_idx].collateral_supply;

        // Patch freshness to bypass staleness checks
        self.queue_refresh_all(user_idx);

        let result = self.ctx.program(self.program_id)
            .call(instruction::DepositObligationCollateral {
                collateral_amount: amount,
            })
            .accounts(accounts::DepositObligationCollateral {
                owner: user_keypair.pubkey(),
                obligation: user_obligation,
                lending_market: self.lending_market,
                deposit_reserve: reserve_addr,
                reserve_destination_collateral: collateral_supply,
                user_source_collateral: user_collateral_account,
                token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .signers(&[&*user_keypair])
            .send();

        let success = matches!(&result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = &result {
            action_stats::log_program_error("deposit_coll", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::DEPOSIT_COLL_OK, &action_stats::DEPOSIT_COLL_FAIL, success);
    }

    // ========================================================================
    // Borrow Action
    // ========================================================================

    pub fn action_borrow(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(1..1_000_000)] amount: u64,
    ) {
        let reserve_mint = self.reserves[reserve_idx].mint;

        let token_account = match self.users[user_idx].token_accounts.get(&reserve_mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("borrow", "no_token_account", &action_stats::BORROW_EARLY);
                return;
            }
        };

        if amount == 0 {
            action_stats::log_early_return("borrow", "zero_amount", &action_stats::BORROW_EARLY);
            return;
        }

        // Extract values before mutable borrow
        let user_keypair = self.users[user_idx].keypair.clone();
        let user_obligation = self.users[user_idx].obligation;
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let reserve_liquidity_supply = self.reserves[reserve_idx].liquidity_supply;
        let borrow_reserve_liquidity_fee_receiver = self.reserves[reserve_idx].fee_receiver;

        // Build remaining accounts with all deposit reserves for health check
        let remaining_accounts: Vec<Pubkey> = self.reserves.iter()
            .map(|r| r.reserve)
            .collect();

        // Patch freshness to bypass staleness checks
        self.queue_refresh_all(user_idx);

        let result = self.ctx.program(self.program_id)
            .call(instruction::BorrowObligationLiquidity {
                liquidity_amount: amount,
            })
            .accounts(accounts::BorrowObligationLiquidity {
                owner: user_keypair.pubkey(),
                obligation: user_obligation,
                lending_market: self.lending_market,
                lending_market_authority: self.lending_market_authority,
                borrow_reserve: reserve_addr,
                borrow_reserve_liquidity_mint: reserve_mint,
                reserve_source_liquidity: reserve_liquidity_supply,
                borrow_reserve_liquidity_fee_receiver: borrow_reserve_liquidity_fee_receiver,
                user_destination_liquidity: token_account,
                referrer_token_state: Some(self.program_id), // Use program ID for None optional
                token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .remaining_accounts(remaining_accounts)
            .signers(&[&*user_keypair])
            .send();

        let success = matches!(&result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = &result {
            action_stats::log_program_error("borrow", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::BORROW_OK, &action_stats::BORROW_FAIL, success);
    }

    // ========================================================================
    // Repay Action
    // ========================================================================

    pub fn action_repay(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(1..10_000_000)] amount: u64,
    ) {
        let reserve_mint = self.reserves[reserve_idx].mint;

        let token_account = match self.users[user_idx].token_accounts.get(&reserve_mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("repay", "no_token_account", &action_stats::REPAY_EARLY);
                return;
            }
        };

        let balance = self.ctx.token_balance(&token_account);
        let amount = amount.min(balance);
        if amount == 0 {
            action_stats::log_early_return("repay", &format!("zero_balance (bal={})", balance), &action_stats::REPAY_EARLY);
            return;
        }

        // Extract values before mutable borrow
        let user_keypair = self.users[user_idx].keypair.clone();
        let user_obligation = self.users[user_idx].obligation;
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let reserve_liquidity_supply = self.reserves[reserve_idx].liquidity_supply;

        // Build remaining accounts with all deposit reserves
        let remaining_accounts: Vec<Pubkey> = self.reserves.iter()
            .map(|r| r.reserve)
            .collect();

        // Patch freshness to bypass staleness checks
        self.queue_refresh_all(user_idx);

        let result = self.ctx.program(self.program_id)
            .call(instruction::RepayObligationLiquidity {
                liquidity_amount: amount,
            })
            .accounts(accounts::RepayObligationLiquidity {
                owner: user_keypair.pubkey(),
                obligation: user_obligation,
                lending_market: self.lending_market,
                repay_reserve: reserve_addr,
                reserve_liquidity_mint: reserve_mint,
                reserve_destination_liquidity: reserve_liquidity_supply,
                user_source_liquidity: token_account,
                token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .remaining_accounts(remaining_accounts)
            .signers(&[&*user_keypair])
            .send();

        let success = matches!(&result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = &result {
            action_stats::log_program_error("repay", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::REPAY_OK, &action_stats::REPAY_FAIL, success);
    }

    // ========================================================================
    // Withdraw Action
    // ========================================================================

    pub fn action_withdraw(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(1..10_000_000)] collateral_amount: u64,
    ) {
        let reserve_mint = self.reserves[reserve_idx].mint;

        let token_account = match self.users[user_idx].token_accounts.get(&reserve_mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("withdraw", "no_token_account", &action_stats::WITHDRAW_EARLY);
                return;
            }
        };

        if collateral_amount == 0 {
            action_stats::log_early_return("withdraw", "zero_amount", &action_stats::WITHDRAW_EARLY);
            return;
        }

        // Extract values before mutable borrow
        let user_keypair = self.users[user_idx].keypair.clone();
        let user_obligation = self.users[user_idx].obligation;
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let reserve_collateral_mint = self.reserves[reserve_idx].collateral_mint;
        let reserve_liquidity_supply = self.reserves[reserve_idx].liquidity_supply;
        let reserve_collateral_supply = self.reserves[reserve_idx].collateral_supply;

        // Queue refreshes and action in same batch to avoid staleness
        self.queue_refresh_all(user_idx);

        let result = self.ctx.program(self.program_id)
            .call(instruction::WithdrawObligationCollateralAndRedeemReserveCollateral {
                collateral_amount,
            })
            .accounts(accounts::WithdrawObligationCollateralAndRedeemReserveCollateral {
                owner: user_keypair.pubkey(),
                obligation: user_obligation,
                lending_market: self.lending_market,
                lending_market_authority: self.lending_market_authority,
                withdraw_reserve: reserve_addr,
                reserve_liquidity_mint: reserve_mint,
                reserve_collateral_mint: reserve_collateral_mint,
                reserve_liquidity_supply: reserve_liquidity_supply,
                reserve_source_collateral: reserve_collateral_supply,
                user_destination_liquidity: token_account,
                placeholder_user_destination_collateral: Some(self.program_id), // Use program ID for None optional
                collateral_token_program: spl_token::id(),
                liquidity_token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .signers(&[&*user_keypair])
            .send();

        let success = matches!(&result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = &result {
            action_stats::log_program_error("withdraw", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::WITHDRAW_OK, &action_stats::WITHDRAW_FAIL, success);
    }

    // ========================================================================
    // Refresh Reserve Action (now patches directly instead of calling RefreshReserve)
    // ========================================================================

    pub fn action_refresh_reserve(&mut self, #[range(0..2)] reserve_idx: usize) {
        // Patch freshness directly instead of calling RefreshReserve (which needs oracles)
        self.patch_reserve_freshness(reserve_idx);
    }

    // ========================================================================
    // Refresh Obligation Action (now patches directly instead of calling RefreshObligation)
    // ========================================================================

    pub fn action_refresh_obligation(&mut self, #[range(0..2)] user_idx: usize) {
        // Patch freshness directly instead of calling RefreshObligation
        self.patch_obligation_freshness(user_idx);
    }

    // ========================================================================
    // Liquidation Action
    // ========================================================================

    pub fn action_liquidate(
        &mut self,
        #[range(0..2)] liquidator_idx: usize,
        #[range(0..2)] target_idx: usize,
        #[range(0..2)] repay_reserve_idx: usize,
        #[range(0..2)] withdraw_reserve_idx: usize,
        #[range(1..1_000_000)] liquidity_amount: u64,
    ) {
        // Can't liquidate yourself
        if liquidator_idx == target_idx {
            action_stats::log_early_return("liquidate", "self_liquidation", &action_stats::LIQUIDATE_EARLY);
            return;
        }

        let repay_reserve = self.reserves[repay_reserve_idx].clone();
        let withdraw_reserve = self.reserves[withdraw_reserve_idx].clone();

        // Get liquidator pubkey for creating accounts
        let liquidator_pubkey = self.users[liquidator_idx].keypair.pubkey();

        // Liquidator needs tokens to repay the target's debt
        let user_source_liquidity = match self.users[liquidator_idx].token_accounts.get(&repay_reserve.mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("liquidate", "no_repay_token_account", &action_stats::LIQUIDATE_EARLY);
                return;
            }
        };

        // Check liquidator has enough balance
        let balance = self.ctx.token_balance(&user_source_liquidity);
        let amount = liquidity_amount.min(balance);
        if amount == 0 {
            action_stats::log_early_return("liquidate", &format!("zero_balance (bal={})", balance), &action_stats::LIQUIDATE_EARLY);
            return;
        }

        // Get or create destination collateral account for liquidator
        let user_destination_collateral = match self.users[liquidator_idx].token_accounts.get(&withdraw_reserve.collateral_mint) {
            Some(acc) => *acc,
            None => {
                let acc = self.ctx.create_token_account()
                    .pubkey(Keypair::new().pubkey())
                    .mint(withdraw_reserve.collateral_mint)
                    .token_owner(liquidator_pubkey)
                    .create()
                    .unwrap();
                self.users[liquidator_idx].token_accounts.insert(withdraw_reserve.collateral_mint, acc);
                acc
            }
        };

        // Get or create destination liquidity account (for the withdraw reserve's liquidity mint)
        let user_destination_liquidity = match self.users[liquidator_idx].token_accounts.get(&withdraw_reserve.mint) {
            Some(acc) => *acc,
            None => {
                let acc = self.ctx.create_token_account()
                    .pubkey(Keypair::new().pubkey())
                    .mint(withdraw_reserve.mint)
                    .token_owner(liquidator_pubkey)
                    .create()
                    .unwrap();
                self.users[liquidator_idx].token_accounts.insert(withdraw_reserve.mint, acc);
                acc
            }
        };

        // Get values needed for instruction (before borrowing for send)
        let target_obligation = self.users[target_idx].obligation;
        let liquidator_keypair = self.users[liquidator_idx].keypair.clone();

        // Patch freshness for both liquidator and target
        self.queue_refresh_all(liquidator_idx);
        self.patch_obligation_freshness(target_idx);

        let result = self.ctx.program(self.program_id)
            .call(instruction::LiquidateObligationAndRedeemReserveCollateral {
                liquidity_amount: amount,
                min_acceptable_received_liquidity_amount: 0, // Accept any amount
                max_allowed_ltv_override_percent: 100, // Allow up to 100% LTV
            })
            .accounts(accounts::LiquidateObligationAndRedeemReserveCollateral {
                liquidator: liquidator_pubkey,
                obligation: target_obligation,
                lending_market: self.lending_market,
                lending_market_authority: self.lending_market_authority,
                repay_reserve: repay_reserve.reserve,
                repay_reserve_liquidity_mint: repay_reserve.mint,
                repay_reserve_liquidity_supply: repay_reserve.liquidity_supply,
                withdraw_reserve: withdraw_reserve.reserve,
                withdraw_reserve_liquidity_mint: withdraw_reserve.mint,
                withdraw_reserve_collateral_mint: withdraw_reserve.collateral_mint,
                withdraw_reserve_collateral_supply: withdraw_reserve.collateral_supply,
                withdraw_reserve_liquidity_supply: withdraw_reserve.liquidity_supply,
                withdraw_reserve_liquidity_fee_receiver: withdraw_reserve.fee_receiver,
                user_source_liquidity,
                user_destination_collateral,
                user_destination_liquidity,
                collateral_token_program: spl_token::id(),
                repay_liquidity_token_program: spl_token::id(),
                withdraw_liquidity_token_program: spl_token::id(),
                instruction_sysvar_account: sysvar_ids::instructions_id(),
            })
            .signers(&[&*liquidator_keypair])
            .send();

        let success = matches!(&result, Ok(Ok(_)));
        if let Ok(Err(ref failed)) = &result {
            action_stats::log_program_error("liquidate", &format!("{:?}", failed.err), &failed.meta.logs);
        }
        action_stats::record(&action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL, success);
    }
}

// ============================================================================
// Initialization Helpers
// ============================================================================

mod fixture_helpers {
    use super::*;

    pub fn initialize_state(ctx: &mut TestContext, program_id: &Pubkey) -> KlendFixture {
        // Create admin account
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        if DEBUG { eprintln!("[SETUP] Admin created: {}", admin.pubkey()); }

        // Create global config (mock account - bypasses program_data requirement)
        let (global_config, _) = Pubkey::find_program_address(&[GLOBAL_CONFIG_STATE], program_id);
        create_global_config_account(ctx, &global_config, &admin.pubkey(), program_id);
        if DEBUG { eprintln!("[SETUP] GlobalConfig created: {}", global_config); }

        // Create lending market zero account
        // Rent-exempt minimum for 4664 bytes is ~32M lamports, use 100M to be safe
        let lending_market = Keypair::new();
        let lending_market_data = vec![0u8; 8 + LENDING_MARKET_SIZE];
        ctx.create_account()
            .pubkey(lending_market.pubkey())
            .lamports(100_000_000)
            .owner(*program_id)
            .data(&lending_market_data)
            .create()
            .unwrap();

        // Calculate lending market authority PDA
        let (lending_market_authority, _bump) = Pubkey::find_program_address(
            &[LENDING_MARKET_AUTH, lending_market.pubkey().as_ref()],
            program_id,
        );

        // Initialize lending market
        let result = ctx.program(*program_id)
            .call(instruction::InitLendingMarket {
                quote_currency: [0u8; 32], // USD
            })
            .accounts(accounts::InitLendingMarket {
                lending_market_owner: admin.pubkey(),
                lending_market: lending_market.pubkey(),
                lending_market_authority,
                system_program: system_program::ID,
                rent: sysvar_ids::rent_id(),
            })
            .signers(&[&*admin])
            .send();

        match result {
            Ok(Ok(_)) => if DEBUG { eprintln!("[SETUP] InitLendingMarket SUCCESS"); },
            Ok(Err(failed)) => {
                if DEBUG {
                    eprintln!("[SETUP] InitLendingMarket TX_FAILED: {:?}", failed.err);
                    for log in &failed.meta.logs { eprintln!("  {}", log); }
                }
                panic!("Setup failed: InitLendingMarket");
            }
            Err(e) => {
                if DEBUG { eprintln!("[SETUP] InitLendingMarket SEND_FAILED: {:?}", e); }
                panic!("Setup failed: InitLendingMarket");
            }
        }

        // Create token mints
        let sol_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
        eprintln!("[SETUP] SOL mint created: {}", sol_mint);

        let usdc_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(6)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
        eprintln!("[SETUP] USDC mint created: {}", usdc_mint);

        // Create reserves
        let sol_reserve = create_reserve(
            ctx, program_id, &lending_market.pubkey(), &lending_market_authority,
            &global_config, &sol_mint, 9, &admin,
        );
        eprintln!("[SETUP] SOL reserve created: {}", sol_reserve.reserve);

        let usdc_reserve = create_reserve(
            ctx, program_id, &lending_market.pubkey(), &lending_market_authority,
            &global_config, &usdc_mint, 6, &admin,
        );
        eprintln!("[SETUP] USDC reserve created: {}", usdc_reserve.reserve);

        let reserves = vec![sol_reserve, usdc_reserve];

        // Create users
        let users: Vec<_> = (0..3)
            .map(|i| {
                let user = create_user(
                    ctx, program_id, &lending_market.pubkey(),
                    &reserves, &admin, i,
                );
                eprintln!("[SETUP] User {} created: {}", i, user.keypair.pubkey());
                user
            })
            .collect();

        KlendFixture {
            ctx: std::mem::replace(ctx, TestContext::new()),
            program_id: *program_id,
            admin,
            lending_market: lending_market.pubkey(),
            lending_market_authority,
            reserves,
            users,
        }
    }

    fn create_global_config_account(
        ctx: &mut TestContext,
        pubkey: &Pubkey,
        admin: &Pubkey,
        program_id: &Pubkey,
    ) {
        // Create GlobalConfig using typed struct
        let global_config = types::GlobalConfig {
            global_admin: admin.to_bytes(),
            ..Default::default()
        };

        // Build account data with discriminator + struct bytes
        let discriminator: [u8; 8] = [149, 8, 156, 75, 31, 54, 147, 229];
        let struct_bytes = bytemuck::bytes_of(&global_config);
        let mut data = Vec::with_capacity(8 + struct_bytes.len());
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(struct_bytes);

        ctx.create_account()
            .pubkey(*pubkey)
            .lamports(100_000_000)
            .owner(*program_id)
            .data(&data)
            .create()
            .unwrap();
    }

    fn create_reserve(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        lending_market: &Pubkey,
        lending_market_authority: &Pubkey,
        global_config: &Pubkey,
        mint: &Pubkey,
        decimals: u8,
        admin: &Rc<Keypair>,
    ) -> ReserveData {
        // Create reserve zero account (rent-exempt for 8624 bytes needs ~60M lamports)
        let reserve_kp = Keypair::new();
        let reserve_data = vec![0u8; 8 + RESERVE_SIZE];
        ctx.create_account()
            .pubkey(reserve_kp.pubkey())
            .lamports(100_000_000)
            .owner(*program_id)
            .data(&reserve_data)
            .create()
            .unwrap();

        // Calculate PDAs
        let (liquidity_supply, _) = Pubkey::find_program_address(
            &[RESERVE_LIQ_SUPPLY, reserve_kp.pubkey().as_ref()],
            program_id,
        );
        let (fee_receiver, _) = Pubkey::find_program_address(
            &[FEE_RECEIVER, reserve_kp.pubkey().as_ref()],
            program_id,
        );
        let (collateral_mint, _) = Pubkey::find_program_address(
            &[RESERVE_COLL_MINT, reserve_kp.pubkey().as_ref()],
            program_id,
        );
        let (collateral_supply, _) = Pubkey::find_program_address(
            &[RESERVE_COLL_SUPPLY, reserve_kp.pubkey().as_ref()],
            program_id,
        );

        // Create admin's source token account for initial liquidity
        let initial_liquidity_source = ctx.create_token_account()
            .pubkey(Keypair::new().pubkey())
            .mint(*mint)
            .token_owner(admin.pubkey())
            .create()
            .unwrap();

        // Mint initial liquidity to admin
        ctx.mint_to(mint, &initial_liquidity_source, MIN_INITIAL_DEPOSIT * 10, admin).unwrap();

        // Init reserve
        let result = ctx.program(*program_id)
            .call(instruction::InitReserve {})
            .accounts(accounts::InitReserve {
                signer: admin.pubkey(),
                lending_market: *lending_market,
                lending_market_authority: *lending_market_authority,
                reserve: reserve_kp.pubkey(),
                reserve_liquidity_mint: *mint,
                reserve_liquidity_supply: liquidity_supply,
                fee_receiver,
                reserve_collateral_mint: collateral_mint,
                reserve_collateral_supply: collateral_supply,
                initial_liquidity_source,
                rent: sysvar_ids::rent_id(),
                liquidity_token_program: spl_token::id(),
                collateral_token_program: spl_token::id(),
                system_program: system_program::ID,
            })
            .signers(&[&**admin])
            .send();

        match result {
            Ok(Ok(_)) => eprintln!("[SETUP] InitReserve SUCCESS for mint {}", mint),
            Ok(Err(failed)) => {
                eprintln!("[SETUP] InitReserve TX_FAILED: {:?}", failed.err);
                for log in &failed.meta.logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitReserve");
            }
            Err(e) => {
                eprintln!("[SETUP] InitReserve SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitReserve");
            }
        }

        // Debug: print token_program from reserve before patching
        if DEBUG {
            if let Ok(reserve_data) = ctx.read_zero_copy_account::<types::Reserve>(&reserve_kp.pubkey()) {
                let token_prog = solana_pubkey::Pubkey::new_from_array(reserve_data.liquidity.token_program);
                eprintln!("[DEBUG] Reserve token_program BEFORE patch: {}", token_prog);
                eprintln!("[DEBUG] Expected spl_token::id(): {}", spl_token::id());
            }
        }

        // Configure reserve with proper price and status (use current SVM slot)
        let current_slot = ctx.slot();
        configure_reserve_manually(ctx, program_id, &reserve_kp.pubkey(), current_slot);

        // Use update_reserve_config to properly set deposit_limit and borrow_limit
        // UpdateConfigMode::UpdateDepositLimit = 8, UpdateBorrowLimit = 9
        {
            // Set deposit limit to u64::MAX
            let result = ctx.program(*program_id)
                .call(instruction::UpdateReserveConfig {
                    mode: UpdateConfigMode::UpdateDepositLimit,
                    value: u64::MAX.to_le_bytes().to_vec(),
                    skip_config_integrity_validation: true,
                })
                .accounts(accounts::UpdateReserveConfig {
                    signer: admin.pubkey(),
                    global_config: *global_config,
                    lending_market: *lending_market,
                    reserve: reserve_kp.pubkey(),
                })
                .signers(&[&**admin])
                .send();
            if let Ok(Err(e)) = &result {
                eprintln!("[DEBUG] UpdateReserveConfig (deposit_limit) failed: {:?}", e.err);
            }

            // Set borrow limit to u64::MAX
            let result = ctx.program(*program_id)
                .call(instruction::UpdateReserveConfig {
                    mode: UpdateConfigMode::UpdateBorrowLimit,
                    value: u64::MAX.to_le_bytes().to_vec(),
                    skip_config_integrity_validation: true,
                })
                .accounts(accounts::UpdateReserveConfig {
                    signer: admin.pubkey(),
                    global_config: *global_config,
                    lending_market: *lending_market,
                    reserve: reserve_kp.pubkey(),
                })
                .signers(&[&**admin])
                .send();
            if let Ok(Err(e)) = &result {
                eprintln!("[DEBUG] UpdateReserveConfig (borrow_limit) failed: {:?}", e.err);
            }
        }

        // Debug: print token_program and deposit_limit from reserve after patching
        if DEBUG {
            if let Ok(reserve_data) = ctx.read_zero_copy_account::<types::Reserve>(&reserve_kp.pubkey()) {
                let token_prog = solana_pubkey::Pubkey::new_from_array(reserve_data.liquidity.token_program);
                eprintln!("[DEBUG] Reserve token_program AFTER patch: {}", token_prog);
                eprintln!("[DEBUG] Reserve deposit_limit: {}", reserve_data.config.deposit_limit);
                eprintln!("[DEBUG] Reserve borrow_limit: {}", reserve_data.config.borrow_limit);
                eprintln!("[DEBUG] Reserve status: {}", reserve_data.config.status);
                eprintln!("[DEBUG] Reserve loan_to_value_pct: {}", reserve_data.config.loan_to_value_pct);
            }
        }

        ReserveData {
            reserve: reserve_kp.pubkey(),
            mint: *mint,
            liquidity_supply,
            collateral_mint,
            collateral_supply,
            fee_receiver,
            decimals,
        }
    }

    fn configure_reserve_manually(
        ctx: &mut TestContext,
        _program_id: &Pubkey,
        reserve: &Pubkey,
        current_slot: u64,
    ) {
        // Read the reserve account using typed zero-copy access
        let Ok(mut reserve_data) = ctx.read_zero_copy_account::<types::Reserve>(reserve) else {
            eprintln!("[WARN] configure_reserve_manually: could not read reserve");
            return;
        };

        // === Fix last_update ===
        reserve_data.last_update.mark_fresh(current_slot);

        // === Fix liquidity.market_price_sf ===
        // Set price: $100 with 60-bit precision (klend Fraction uses 2^60 scale)
        let price_sf: u128 = 100 * (1u128 << 60);
        reserve_data.liquidity.market_price_sf = types::u128_to_u64_pair(price_sf);

        // === Fix liquidity.cumulative_borrow_rate_bsf ===
        // Set to 1.0 (2^60) for interest calculations
        reserve_data.liquidity.cumulative_borrow_rate_bsf.value[0] = 1u64 << 60;

        // === Fix liquidity.token_program ===
        reserve_data.liquidity.token_program = spl_token::id().to_bytes();

        // === Fix config ===
        reserve_data.config.status = 0;  // Active
        reserve_data.config.loan_to_value_pct = 80;
        reserve_data.config.liquidation_threshold_pct = 85;
        reserve_data.config.min_liquidation_bonus_bps = 500;
        reserve_data.config.deposit_limit = u64::MAX;
        reserve_data.config.borrow_limit = u64::MAX;

        if DEBUG {
            eprintln!("[DEBUG] configure_reserve_manually: set config via typed access");
        }

        // Write the modified reserve back
        let _ = ctx.write_zero_copy_account(reserve, &reserve_data);
    }

    fn create_user(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        lending_market: &Pubkey,
        reserves: &[ReserveData],
        admin: &Rc<Keypair>,
        _user_idx: usize,
    ) -> UserData {
        let keypair = Rc::new(Keypair::new());

        // Fund user
        ctx.create_account()
            .pubkey(keypair.pubkey())
            .lamports(10_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // Calculate user_metadata PDA
        let (user_metadata, user_metadata_bump) = Pubkey::find_program_address(
            &[BASE_SEED_USER_METADATA, keypair.pubkey().as_ref()],
            program_id,
        );

        // Create user_metadata account (bypassing InitUserMetadata for simplicity)
        create_user_metadata_account(ctx, program_id, &user_metadata, &keypair.pubkey(), user_metadata_bump);

        // Calculate obligation PDA
        // seeds = [tag, id, owner, lending_market, seed1, seed2]
        // For tag=0, id=0, seed1=default, seed2=default
        let (obligation, _) = Pubkey::find_program_address(
            &[
                &[0u8],  // tag
                &[0u8],  // id
                keypair.pubkey().as_ref(),
                lending_market.as_ref(),
                Pubkey::default().as_ref(),  // seed1
                Pubkey::default().as_ref(),  // seed2
            ],
            program_id,
        );

        // Create obligation via InitObligation
        let result = ctx.program(*program_id)
            .call(instruction::InitObligation {
                args: InitObligationArgs {
                    tag: 0,
                    id: 0,
                },
            })
            .accounts(accounts::InitObligation {
                obligation_owner: keypair.pubkey(),
                fee_payer: keypair.pubkey(),
                obligation,
                lending_market: *lending_market,
                seed1_account: Pubkey::default(),
                seed2_account: Pubkey::default(),
                owner_user_metadata: user_metadata,
                rent: sysvar_ids::rent_id(),
                system_program: system_program::ID,
            })
            .signers(&[&*keypair])
            .send();

        match result {
            Ok(Ok(_)) => eprintln!("[SETUP] InitObligation SUCCESS for user {}", keypair.pubkey()),
            Ok(Err(failed)) => {
                eprintln!("[SETUP] InitObligation TX_FAILED: {:?}", failed.err);
                for log in &failed.meta.logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitObligation");
            }
            Err(e) => {
                eprintln!("[SETUP] InitObligation SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitObligation");
            }
        }

        // Create token accounts for each reserve mint and fund them
        let mut token_accounts = HashMap::new();
        for reserve in reserves {
            let token_account = ctx.create_token_account()
                .pubkey(Keypair::new().pubkey())
                .mint(reserve.mint)
                .token_owner(keypair.pubkey())
                .create()
                .unwrap();

            // Fund with tokens
            let amount = 10_000 * 10_u64.pow(reserve.decimals as u32);
            ctx.mint_to(&reserve.mint, &token_account, amount, admin).unwrap();

            token_accounts.insert(reserve.mint, token_account);
        }

        UserData {
            keypair,
            obligation,
            user_metadata,
            token_accounts,
        }
    }

    fn create_user_metadata_account(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        pubkey: &Pubkey,
        owner: &Pubkey,
        bump: u8,
    ) {
        // Create UserMetadata using typed struct
        let user_metadata = types::UserMetadata {
            referrer: [0u8; 32],
            bump: bump as u64,
            user_lookup_table: [0u8; 32],
            owner: owner.to_bytes(),
            ..Default::default()
        };

        // Build account data with discriminator + struct bytes
        let discriminator: [u8; 8] = [157, 214, 220, 235, 98, 135, 171, 28];
        let struct_bytes = bytemuck::bytes_of(&user_metadata);
        let mut data = Vec::with_capacity(8 + struct_bytes.len());
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(struct_bytes);

        ctx.create_account()
            .pubkey(*pubkey)
            .lamports(100_000_000)
            .owner(*program_id)
            .data(&data)
            .create()
            .unwrap();
    }
}

// ============================================================================
// Invariant Test
// ============================================================================

#[invariant_test]
fn invariant_test(fixture: &mut KlendFixture) {
    solvency_check(fixture);
}

fn solvency_check(fixture: &mut KlendFixture) {
    // Check each user's obligation for bad debt
    for user in &fixture.users {
        // Read obligation using typed zero-copy access
        let Ok(obligation) = fixture.ctx.read_zero_copy_account::<types::Obligation>(&user.obligation) else {
            continue;
        };

        // Convert [u64; 2] fields to u128 for comparison
        let deposited_value = types::u64_pair_to_u128(obligation.deposited_value_sf);
        let borrowed_value = types::u64_pair_to_u128(obligation.borrowed_assets_market_value_sf);

        // Solvency check: borrowed should not exceed deposited significantly
        if borrowed_value > 0 && deposited_value > 0 {
            // Allow 10% margin for rounding, fees, and interest
            let margin = deposited_value / 10;
            assert!(
                borrowed_value <= deposited_value + margin,
                "SOLVENCY VIOLATION: user {} has borrowed {} > deposited {} + margin {}",
                user.keypair.pubkey(),
                borrowed_value,
                deposited_value,
                margin
            );
        }
    }
}
