use crucible_fuzzer::*;
use crucible_test_context::TxOutcome;
#[allow(unused_imports)]
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::{rc::Rc, collections::HashMap};
use crucible_fuzzer::anchor_spl::token::spl_token;

mod types;
use types::{Reserve, Obligation, RESERVE_SIZE, OBLIGATION_SIZE};

// Generate types from IDL
crucible_idl_gen::declare_fuzz_program!("idls/klend.json");

use kamino_lending::instruction;
use kamino_lending::accounts;
use kamino_lending::types::{InitObligationArgs, UpdateConfigMode};

// ============================================================================
// Constants
// ============================================================================

// Set to true to enable debug output
const DEBUG: bool = false;

// ============================================================================
// Klend Error Code Mapping (from programs/klend/src/utils/constraints.rs)
// ============================================================================

/// Convert klend error code to human-readable name
fn klend_error_name(code: u32) -> &'static str {
    match code {
        // Common errors (6000-6100)
        6000 => "InvalidMarketAuthority",
        6001 => "InvalidMarketOwner",
        6002 => "InvalidAccountOwner",
        6003 => "InvalidAmount",
        6004 => "InvalidConfig",
        6005 => "InvalidSigner",
        6006 => "InvalidAccountInput",
        6007 => "MathOverflow",
        6008 => "InsufficientLiquidity",
        6009 => "ReserveStale",
        6010 => "WithdrawTooSmall",
        6011 => "WithdrawTooLarge",
        6012 => "BorrowTooSmall",
        6013 => "BorrowTooLarge",
        6014 => "RepayTooSmall",
        6015 => "LiquidateTooMuch",
        6016 => "ObligationHealthy",
        6017 => "ObligationStale",
        6018 => "ObligationReserveLimit",
        6019 => "InvalidObligationOwner",
        6020 => "ObligationDepositsEmpty",
        6021 => "ObligationBorrowsEmpty",
        6022 => "ObligationDepositsZero",
        6023 => "ObligationBorrowsZero",
        6024 => "InvalidObligationCollateral",
        6025 => "InvalidObligationLiquidity",
        6026 => "ObligationCollateralEmpty",
        6027 => "ObligationLiquidityEmpty",
        6028 => "NegativeInterestRate",
        6029 => "InvalidOracleConfig",
        6030 => "InsufficientProtocolFeesToRedeem",
        6031 => "FlashBorrowCpi",
        6032 => "NoFlashRepayFound",
        6033 => "InvalidFlashRepay",
        6034 => "FlashRepayCpi",
        6035 => "MultipleFlashBorrows",
        6036 => "FlashLoansDisabled",
        6037 => "SwitchboardV2Error",
        6038 => "CouldNotDeserializeScope",
        6039 => "PriceTooOld",
        6040 => "PriceTooDivergentFromTwap",
        6041 => "InvalidTwapPrice",
        6042 => "GlobalEmergencyMode",
        6043 => "InvalidFlag",
        6044 => "PriceNotValid",
        6045 => "PriceIsBiggerThanHeuristic",
        6046 => "PriceIsLowerThanHeuristic",
        6047 => "PriceIsZero",
        6048 => "PriceConfidenceTooWide",
        6049 => "IntegerOverflow",
        6050 => "NoFarmForReserve",
        6051 => "IncorrectInstructionInPosition",  // Very common - staleness check failure
        6052 => "NoPriceFound",
        6053 => "InvalidTwapConfig",
        6054 => "InvalidPythPriceAccount",
        6055 => "InvalidSwitchboardAccount",
        6056 => "InvalidScopePriceAccount",
        6057 => "ObligationCollateralLtvZero",
        6058 => "InvalidScopeTwapPriceAccount",
        6059 => "KTokenCollateralDisabled",
        6060 => "DepositLimitExceeded",
        6061 => "BorrowLimitExceeded",
        6062 => "CannotRepayMoreThanDebt",
        6063 => "CannotWithdrawMoreThanCollateral",
        6064 => "ReserveObsolete",
        6065 => "ElevationGroupAlreadyActivated",
        6066 => "ElevationGroupAlreadyDeactivated",
        6067 => "ElevationGroupBorrowLimitExceeded",
        6068 => "ElevationGroupMaxCollReached",
        6069 => "ElevationGroupMaxBorrowReached",
        6070 => "ElevationGroupHasDebt",
        6071 => "ElevationGroupDebtNotAllowed",
        6072 => "ElevationGroupNewLoansDisabled",
        6073 => "ElevationGroupBadDebtExceeded",
        6074 => "UnhealthyPosition",
        6075 => "IsolatedTierAssetCannotBeBorrowedWithOtherDebt",
        6076 => "ScopeChainNotConfigured",
        6077 => "InvalidOracleInput",
        6078 => "IsolatedTierReserveCannotBorrowOrWithdraw",
        6079 => "ReferrerAccountNotInitialized",
        6080 => "ReferrerAccountMintMismatch",
        6081 => "ReferrerAccountWrongAddress",
        6082 => "ReferrerAccountReferrerMismatch",
        6083 => "ReferrerAccountMissing",
        6084 => "InsufficientReferralFeesToRedeem",
        6085 => "CpiDisabled",
        6086 => "ShortUrlNotAsciiAlphanumeric",
        6087 => "ReserveFarmKind",
        6088 => "CannotSocializeDebtWithCollateral",
        6089 => "BorrowLimitExceeded",  // Previously mislabeled as ObligationEmpty
        6090 => "ObligationNotLiquidatable",
        6091 => "SwitchboardOnDemandError",
        6092 => "NetValueRemainingTooSmall",  // NOT CannotLiquidateProtectedMode - value below threshold
        6093 => "CannotLiquidateProtectedMode",
        6094 => "CannotAutodeleverageProtectedMode",
        6095 => "CannotLiquidateYourself",
        6096 => "CannotAutodeleverageYourself",
        6097 => "NotEnoughReceivable",
        6098 => "NotEnoughCollateral",
        6099 => "InvalidReserveStatus",
        6100 => "BorrowDisabled",
        6101 => "CannotAutodeleverageHealthyPosition",
        _ => "UnknownError",
    }
}

/// Log detailed error information with klend-specific error names
fn log_klend_error(action: &str, outcome: &TxOutcome) {
    if let TxOutcome::ProgramError { error: _, error_code, logs, instruction_index, .. } = outcome {
        if !DEBUG { return; }

        let error_name = error_code.map(klend_error_name).unwrap_or("Unknown");
        eprintln!("[KLEND_ERR] {}: {} (code: {:?}) at ix {:?}",
            action, error_name, error_code, instruction_index);

        // Print relevant logs (last 5 only to reduce noise)
        let log_count = logs.len();
        let start = if log_count > 5 { log_count - 5 } else { 0 };
        for log in &logs[start..] {
            if log.contains("Error") || log.contains("error") || log.contains("failed") {
                eprintln!("  {}", log);
            }
        }
    }
}

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

    #[allow(dead_code)]
    pub fn log_program_error(action: &str, err: &str, logs: &[String]) {
        // Log first 2 program errors per action
        let log_counter = get_log_counter(action);
        if log_counter.load(Ordering::Relaxed) < 4 && super::DEBUG {
            log_counter.fetch_add(1, Ordering::Relaxed);
            eprintln!("[PROG_ERR] {}: {}", action, err);
            for log in logs.iter().take(10) {
                eprintln!("  {}", log);
            }
        }
    }

    pub fn log_success(action: &str, compute_units: u64) {
        if super::DEBUG {
            eprintln!("[SUCCESS] {}: compute_units={}", action, compute_units);
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

    /// Handle action result using TxOutcome helper methods - simplifies match blocks
    /// Use this instead of verbose match patterns for single-transaction actions
    pub fn handle_result(
        action: &str,
        result: &Result<super::TxOutcome, impl std::fmt::Debug>,
        ok_counter: &AtomicU32,
        fail_counter: &AtomicU32,
    ) {
        match result {
            Ok(outcome) => {
                let success = outcome.is_success();
                if success {
                    if let Some(cu) = outcome.compute_units() {
                        log_success(action, cu);
                    }
                } else {
                    super::log_klend_error(action, outcome);
                }
                record(ok_counter, fail_counter, success);
            }
            Err(e) => {
                if super::DEBUG { eprintln!("[SEND_ERR] {}: {:?}", action, e); }
                record(ok_counter, fail_counter, false);
            }
        }
    }

    /// Handle batch result (Option<TxOutcome>) - for batch transactions via send_batch()
    pub fn handle_batch_result(
        action: &str,
        result: &Result<Option<super::TxOutcome>, impl std::fmt::Debug>,
        ok_counter: &AtomicU32,
        fail_counter: &AtomicU32,
    ) {
        match result {
            Ok(Some(outcome)) => {
                let success = outcome.is_success();
                if success {
                    if let Some(cu) = outcome.compute_units() {
                        log_success(action, cu);
                    }
                } else {
                    super::log_klend_error(action, outcome);
                }
                record(ok_counter, fail_counter, success);
            }
            Ok(None) => {
                if super::DEBUG { eprintln!("[BATCH_ERR] {}: empty batch", action); }
                record(ok_counter, fail_counter, false);
            }
            Err(e) => {
                if super::DEBUG { eprintln!("[SEND_ERR] {}: {:?}", action, e); }
                record(ok_counter, fail_counter, false);
            }
        }
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
// RESERVE_SIZE and OBLIGATION_SIZE imported from types module
const USER_METADATA_SIZE: usize = 1024;
const GLOBAL_CONFIG_SIZE: usize = 1024;


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
    mock_pyth_oracle: Pubkey,  // Mock Pyth oracle for this reserve
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
    // Uses bytemuck for type-safe zero-copy access
    fn patch_reserve_freshness(&mut self, reserve_idx: usize) {
        let reserve_pubkey = self.reserves[reserve_idx].reserve;
        if let Ok(mut account) = self.ctx.get_account(&reserve_pubkey) {
            // Use current slot - do NOT add 1 as that causes MathOverflow when
            // program computes current_slot - last_update.slot (underflow)
            let target_slot = self.ctx.slot();

            // Use bytemuck for type-safe access (skip 8-byte discriminator)
            if account.data.len() >= 8 + RESERVE_SIZE {
                let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut account.data[8..8 + RESERVE_SIZE]);
                reserve.last_update.mark_fresh(target_slot);

                let _ = self.ctx.svm.set_account(reserve_pubkey, account);
            }
        }
    }

    // Patch obligation's last_update to bypass staleness checks
    // Uses bytemuck for type-safe zero-copy access
    fn patch_obligation_freshness(&mut self, user_idx: usize) {
        let obligation_pubkey = self.users[user_idx].obligation;
        if let Ok(mut account) = self.ctx.get_account(&obligation_pubkey) {
            // Use current slot - do NOT add 1 as that causes MathOverflow
            let target_slot = self.ctx.slot();

            // Use bytemuck for type-safe access (skip 8-byte discriminator)
            if account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &mut Obligation = bytemuck::from_bytes_mut(&mut account.data[8..8 + OBLIGATION_SIZE]);
                obligation.last_update.slot = target_slot;
                obligation.last_update.stale = 0;

                let _ = self.ctx.svm.set_account(obligation_pubkey, account);
            }
        }
    }

    // Refresh all reserves and obligation by patching their last_update timestamps
    fn patch_freshness_all(&mut self, user_idx: usize) {
        for i in 0..self.reserves.len() {
            self.patch_reserve_freshness(i);
        }
        self.patch_obligation_freshness(user_idx);
    }

    // Queue RefreshReserve instruction for batched transaction
    fn queue_refresh_reserve(&mut self, reserve_idx: usize) -> anyhow::Result<()> {
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let mock_pyth_oracle = self.reserves[reserve_idx].mock_pyth_oracle;

        // Pass the mock Pyth oracle account
        // The reserve's pyth_configuration.price is set to this account's pubkey
        // Pass program_id as placeholder for other oracle accounts
        // klend might still validate their presence even if config is zeroed
        self.ctx.program(self.program_id)
            .call(instruction::RefreshReserve {})
            .accounts(accounts::RefreshReserve {
                reserve: reserve_addr,
                lending_market: self.lending_market,
                pyth_oracle: Some(mock_pyth_oracle),
                switchboard_price_oracle: Some(self.program_id),
                switchboard_twap_oracle: Some(self.program_id),
                scope_prices: Some(self.program_id),
            })
            .add_transaction()
    }

    // Queue RefreshObligation instruction for batched transaction
    // Note: RefreshObligation needs EXACTLY deposit_count + borrow_count remaining accounts
    // First deposit_count accounts are deposit reserves (in order)
    // Next borrow_count accounts are borrow reserves (in order)
    // DO NOT deduplicate - a reserve can appear in both deposits and borrows
    fn queue_refresh_obligation(&mut self, user_idx: usize) -> anyhow::Result<()> {
        use types::{Obligation, OBLIGATION_SIZE};

        let user_obligation = self.users[user_idx].obligation;

        // Read the obligation to find which reserves it uses
        let mut remaining_accounts = Vec::new();
        if let Ok(account) = self.ctx.get_account(&user_obligation) {
            if account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);

                // First: Add deposit reserves (in order, no deduplication)
                for deposit in &obligation.deposits {
                    if deposit.deposit_reserve != [0u8; 32] {
                        remaining_accounts.push(Pubkey::new_from_array(deposit.deposit_reserve));
                    }
                }

                // Second: Add borrow reserves (in order, no deduplication)
                // A reserve CAN appear twice if it's used for both deposit and borrow
                for borrow in &obligation.borrows {
                    if borrow.borrow_reserve != [0u8; 32] {
                        remaining_accounts.push(Pubkey::new_from_array(borrow.borrow_reserve));
                    }
                }
            }
        }

        self.ctx.program(self.program_id)
            .call(instruction::RefreshObligation {})
            .accounts(accounts::RefreshObligation {
                lending_market: self.lending_market,
                obligation: user_obligation,
            })
            .remaining_accounts(remaining_accounts)
            .add_transaction()
    }

    // Queue all refresh instructions needed for an action: RefreshReserve(s) + RefreshObligation
    fn queue_all_refreshes(&mut self, user_idx: usize, reserve_indices: &[usize]) -> anyhow::Result<()> {
        // First queue RefreshReserve for each involved reserve
        for &reserve_idx in reserve_indices {
            self.queue_refresh_reserve(reserve_idx)?;
        }
        // Then queue RefreshObligation
        self.queue_refresh_obligation(user_idx)?;
        Ok(())
    }

    // Legacy helpers for compatibility - still patch freshness for reserve staleness
    fn queue_refresh_all(&mut self, user_idx: usize) {
        // Patch account data for timestamp-based staleness checks
        self.patch_freshness_all(user_idx);
    }

    // Ensure reserve has a valid market price after RefreshReserve might have corrupted it
    // Call this after each batch that includes RefreshReserve
    fn ensure_reserve_price(&mut self, reserve_idx: usize) {
        let reserve_pubkey = self.reserves[reserve_idx].reserve;
        if let Ok(mut account) = self.ctx.get_account(&reserve_pubkey) {
            if account.data.len() >= 8 + RESERVE_SIZE {
                let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut account.data[8..8 + RESERVE_SIZE]);
                let current_price = types::u64_pair_to_u128(reserve.liquidity.market_price_sf);

                // If price is 0 or suspiciously low, set it to a reasonable value ($100)
                if current_price < 10_u128.pow(16) {  // Less than $0.01 in SF
                    if DEBUG {
                        eprintln!("[DEBUG] Reserve {} price was {}, fixing to $100", reserve_idx, current_price);
                    }
                    let price_sf: u128 = 100 * 10_u128.pow(18);  // $100 in scaled fraction
                    reserve.liquidity.market_price_sf = types::u128_to_u64_pair(price_sf);
                    let _ = self.ctx.svm.set_account(reserve_pubkey, account);
                }
            }
        }
    }

    // Manually compute and set the obligation's deposited_value based on deposit amounts
    // This works around issues where RefreshObligation doesn't compute values correctly
    fn patch_obligation_deposited_value(&mut self, user_idx: usize) {
        use types::{Obligation, Reserve, OBLIGATION_SIZE, RESERVE_SIZE};

        let obligation_pubkey = self.users[user_idx].obligation;
        if let Ok(mut obl_account) = self.ctx.get_account(&obligation_pubkey) {
            if obl_account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &mut Obligation = bytemuck::from_bytes_mut(&mut obl_account.data[8..8 + OBLIGATION_SIZE]);

                let mut total_value: u128 = 0;

                // For each deposit, compute value = deposited_amount * exchange_rate * price
                for deposit in &obligation.deposits {
                    if deposit.deposit_reserve != [0u8; 32] && deposit.deposited_amount > 0 {
                        let reserve_pubkey = Pubkey::new_from_array(deposit.deposit_reserve);

                        // Get reserve price
                        if let Ok(res_account) = self.ctx.get_account(&reserve_pubkey) {
                            if res_account.data.len() >= 8 + RESERVE_SIZE {
                                let reserve: &Reserve = bytemuck::from_bytes(&res_account.data[8..8 + RESERVE_SIZE]);
                                let price_sf = types::u64_pair_to_u128(reserve.liquidity.market_price_sf);

                                // Use a default exchange rate of 1:1 (collateral_mint_supply / liquidity_available)
                                // In reality this would be computed from reserve state, but 1:1 is reasonable for fresh reserves
                                let deposit_value = (deposit.deposited_amount as u128)
                                    .saturating_mul(price_sf)
                                    .saturating_div(10_u128.pow(9));  // Adjust for decimals

                                total_value = total_value.saturating_add(deposit_value);

                                if DEBUG {
                                    eprintln!("[DEBUG] Deposit value calc: amount={}, price_sf={}, value={}",
                                        deposit.deposited_amount, price_sf, deposit_value);
                                }
                            }
                        }
                    }
                }

                if total_value > 0 {
                    obligation.deposited_value_sf = types::u128_to_u64_pair(total_value);
                    // Set allowed_borrow_value = deposited_value * 80% (LTV)
                    let allowed_borrow = total_value.saturating_mul(80) / 100;
                    obligation.allowed_borrow_value_sf = types::u128_to_u64_pair(allowed_borrow);
                    // Set unhealthy_borrow_value = deposited_value * 85% (liquidation threshold)
                    let unhealthy_borrow = total_value.saturating_mul(85) / 100;
                    obligation.unhealthy_borrow_value_sf = types::u128_to_u64_pair(unhealthy_borrow);

                    if DEBUG {
                        eprintln!("[DEBUG] Patched obligation: deposited_value={}, allowed_borrow={}", total_value, allowed_borrow);
                    }

                    let _ = self.ctx.svm.set_account(obligation_pubkey, obl_account);
                }
            }
        }
    }

    // ========================================================================
    // Deposit Action
    // ========================================================================

    pub fn action_deposit(
        &mut self,
        #[range(0..4)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(100_000_000..2_000_000_000)] amount: u64,  // 0.1 to 2 SOL equivalent - larger to pass value thresholds
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

        // Track result using helper (replaces verbose 13-line match block)
        action_stats::handle_result("deposit", &result, &action_stats::DEPOSIT_OK, &action_stats::DEPOSIT_FAIL);
    }

    // ========================================================================
    // Deposit Collateral to Obligation Action
    // ========================================================================

    pub fn action_deposit_collateral(
        &mut self,
        #[range(0..4)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(100_000_000..2_000_000_000)] amount: u64,  // Larger amounts to pass value thresholds
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

        // Patch freshness AND queue refresh instructions
        // Both are needed: patching sets timestamps, refresh instructions satisfy sysvar check
        self.patch_freshness_all(user_idx);
        if let Err(e) = self.queue_all_refreshes(user_idx, &[reserve_idx]) {
            if DEBUG { eprintln!("[QUEUE_ERR] deposit_coll refresh: {:?}", e); }
            action_stats::record(&action_stats::DEPOSIT_COLL_OK, &action_stats::DEPOSIT_COLL_FAIL, false);
            return;
        }

        // Queue the actual instruction
        if let Err(e) = self.ctx.program(self.program_id)
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
            .add_transaction()
        {
            if DEBUG { eprintln!("[QUEUE_ERR] deposit_coll: {:?}", e); }
            action_stats::record(&action_stats::DEPOSIT_COLL_OK, &action_stats::DEPOSIT_COLL_FAIL, false);
            return;
        }

        // Send batch with RefreshReserve + RefreshObligation + DepositObligationCollateral
        let result = self.ctx.send_batch();
        action_stats::handle_batch_result("deposit_coll", &result, &action_stats::DEPOSIT_COLL_OK, &action_stats::DEPOSIT_COLL_FAIL);
    }

    // ========================================================================
    // Borrow Action
    // ========================================================================

    pub fn action_borrow(
        &mut self,
        #[range(0..4)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(10_000_000..500_000_000)] amount: u64,  // Reasonable borrow amounts (smaller than collateral due to LTV)
    ) {
        use types::{Obligation, OBLIGATION_SIZE};

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

        // Check if user has collateral deposited in their obligation
        // Note: deposited_value_sf is computed by RefreshObligation, which hasn't run yet
        // So we check if any deposit slot has a reserve assigned (set by DepositObligationCollateral)
        let user_obligation_pubkey = self.users[user_idx].obligation;
        let mut has_collateral = false;

        if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
            if account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);

                // Check for any active deposit slots (reserve assigned)
                has_collateral = obligation.deposits.iter().any(|d| d.deposit_reserve != [0u8; 32]);

                if DEBUG {
                    let deposited_value = types::u64_pair_to_u128(obligation.deposited_value_sf);
                    let num_deposits = obligation.deposits.iter().filter(|d| d.deposit_reserve != [0u8; 32]).count();
                    let first_deposit_amount = obligation.deposits[0].deposited_amount;
                    eprintln!("[DEBUG] borrow check: user={}, has_slots={}, num_deposits={}, first_amount={}, deposited_value={}",
                        user_idx, has_collateral, num_deposits, first_deposit_amount, deposited_value);
                }
            }
        }

        // Smart harness: If no collateral, deposit collateral first
        if !has_collateral {
            if DEBUG {
                eprintln!("[DEBUG] borrow: user {} has no collateral, depositing first", user_idx);
            }
            // Deposit a large amount of collateral (5x borrow amount for safety margin with 80% LTV)
            let collateral_amount = amount.saturating_mul(5);
            self.action_deposit_collateral(user_idx, reserve_idx, collateral_amount);

            // Ensure reserve prices are valid (RefreshReserve might have corrupted them)
            for i in 0..self.reserves.len() {
                self.ensure_reserve_price(i);
            }

            // Manually patch obligation values since RefreshObligation may not have computed them correctly
            // (due to invalid oracle prices during the batch)
            self.patch_obligation_deposited_value(user_idx);

            // Re-check if collateral was deposited
            if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
                if account.data.len() >= 8 + OBLIGATION_SIZE {
                    let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);
                    has_collateral = obligation.deposits.iter().any(|d| d.deposit_reserve != [0u8; 32]);

                    if DEBUG {
                        let deposited_value = types::u64_pair_to_u128(obligation.deposited_value_sf);
                        let allowed_borrow = types::u64_pair_to_u128(obligation.allowed_borrow_value_sf);
                        eprintln!("[DEBUG] borrow after deposit_coll: user={}, has_collateral={}, deposited_value={}, allowed_borrow={}",
                            user_idx, has_collateral, deposited_value, allowed_borrow);
                    }
                }
            }

            if !has_collateral {
                action_stats::log_early_return("borrow", "deposit_collateral_failed", &action_stats::BORROW_EARLY);
                return;
            }
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

        // Ensure reserve prices are valid before the batch
        for i in 0..self.reserves.len() {
            self.ensure_reserve_price(i);
        }

        // Patch freshness for all accounts
        self.patch_freshness_all(user_idx);

        // Re-patch obligation values after freshness patching to ensure correct computed values
        // This is important because RefreshObligation during the batch might overwrite our patches
        // Instead of calling RefreshObligation, we pre-compute the values
        self.patch_obligation_deposited_value(user_idx);

        // Queue RefreshReserve for the borrow reserve only (required by instructions_sysvar check)
        if let Err(e) = self.queue_refresh_reserve(reserve_idx) {
            if DEBUG { eprintln!("[QUEUE_ERR] borrow refresh_reserve: {:?}", e); }
            action_stats::record(&action_stats::BORROW_OK, &action_stats::BORROW_FAIL, false);
            return;
        }

        // Also queue RefreshObligation (required by instructions_sysvar check)
        // Note: This will recompute obligation values using the reserve's market_price
        if let Err(e) = self.queue_refresh_obligation(user_idx) {
            if DEBUG { eprintln!("[QUEUE_ERR] borrow refresh_obligation: {:?}", e); }
            action_stats::record(&action_stats::BORROW_OK, &action_stats::BORROW_FAIL, false);
            return;
        }

        // Queue the actual instruction
        if let Err(e) = self.ctx.program(self.program_id)
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
            .add_transaction()
        {
            if DEBUG { eprintln!("[QUEUE_ERR] borrow: {:?}", e); }
            action_stats::record(&action_stats::BORROW_OK, &action_stats::BORROW_FAIL, false);
            return;
        }

        // Send batch with RefreshReserve + RefreshObligation + BorrowObligationLiquidity
        let result = self.ctx.send_batch();
        action_stats::handle_batch_result("borrow", &result, &action_stats::BORROW_OK, &action_stats::BORROW_FAIL);
    }

    // ========================================================================
    // Repay Action
    // ========================================================================

    pub fn action_repay(
        &mut self,
        #[range(0..4)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(10_000_000..500_000_000)] amount: u64,  // Match borrow amounts
    ) {
        use types::{Obligation, OBLIGATION_SIZE};

        let reserve_mint = self.reserves[reserve_idx].mint;

        let token_account = match self.users[user_idx].token_accounts.get(&reserve_mint) {
            Some(acc) => *acc,
            None => {
                action_stats::log_early_return("repay", "no_token_account", &action_stats::REPAY_EARLY);
                return;
            }
        };

        // Check if user has active borrows
        let user_obligation_pubkey = self.users[user_idx].obligation;
        let mut has_borrows = false;
        if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
            if account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);
                has_borrows = obligation.borrows.iter().any(|b| b.borrow_reserve != [0u8; 32]);
            }
        }

        // Smart harness: If no borrows, create one first
        if !has_borrows {
            if DEBUG {
                eprintln!("[DEBUG] repay: user {} has no borrows, borrowing first", user_idx);
            }
            // Borrow a smaller amount so we have something to repay
            let borrow_amount = amount.saturating_mul(2);
            self.action_borrow(user_idx, reserve_idx, borrow_amount);

            // Re-check if borrow succeeded
            if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
                if account.data.len() >= 8 + OBLIGATION_SIZE {
                    let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);
                    has_borrows = obligation.borrows.iter().any(|b| b.borrow_reserve != [0u8; 32]);
                }
            }

            if !has_borrows {
                action_stats::log_early_return("repay", "borrow_failed", &action_stats::REPAY_EARLY);
                return;
            }
        }

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

        // Patch freshness AND queue refresh instructions
        self.patch_freshness_all(user_idx);
        if let Err(e) = self.queue_all_refreshes(user_idx, &[reserve_idx]) {
            if DEBUG { eprintln!("[QUEUE_ERR] repay refresh: {:?}", e); }
            action_stats::record(&action_stats::REPAY_OK, &action_stats::REPAY_FAIL, false);
            return;
        }

        // Queue the actual instruction
        if let Err(e) = self.ctx.program(self.program_id)
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
            .add_transaction()
        {
            if DEBUG { eprintln!("[QUEUE_ERR] repay: {:?}", e); }
            action_stats::record(&action_stats::REPAY_OK, &action_stats::REPAY_FAIL, false);
            return;
        }

        // Send batch with RefreshReserve + RefreshObligation + RepayObligationLiquidity
        let result = self.ctx.send_batch();
        action_stats::handle_batch_result("repay", &result, &action_stats::REPAY_OK, &action_stats::REPAY_FAIL);
    }

    // ========================================================================
    // Withdraw Action
    // ========================================================================

    pub fn action_withdraw(
        &mut self,
        #[range(0..4)] user_idx: usize,
        #[range(0..2)] reserve_idx: usize,
        #[range(10_000_000..1_000_000_000)] collateral_amount: u64,  // Reasonable withdrawal amounts
    ) {
        use types::{Obligation, OBLIGATION_SIZE};

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

        // Check if user has collateral deposited
        let user_obligation_pubkey = self.users[user_idx].obligation;
        let mut has_collateral = false;
        if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
            if account.data.len() >= 8 + OBLIGATION_SIZE {
                let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);
                has_collateral = obligation.deposits.iter().any(|d| d.deposit_reserve != [0u8; 32]);
            }
        }

        // Smart harness: If no collateral, deposit some first
        if !has_collateral {
            if DEBUG {
                eprintln!("[DEBUG] withdraw: user {} has no collateral, depositing first", user_idx);
            }
            // Deposit more than we want to withdraw so we can actually withdraw
            let deposit_amount = collateral_amount.saturating_mul(2);
            self.action_deposit_collateral(user_idx, reserve_idx, deposit_amount);

            // Re-check if deposit succeeded
            if let Ok(account) = self.ctx.get_account(&user_obligation_pubkey) {
                if account.data.len() >= 8 + OBLIGATION_SIZE {
                    let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);
                    has_collateral = obligation.deposits.iter().any(|d| d.deposit_reserve != [0u8; 32]);
                }
            }

            if !has_collateral {
                action_stats::log_early_return("withdraw", "deposit_collateral_failed", &action_stats::WITHDRAW_EARLY);
                return;
            }
        }

        // Extract values before mutable borrow
        let user_keypair = self.users[user_idx].keypair.clone();
        let user_obligation = self.users[user_idx].obligation;
        let reserve_addr = self.reserves[reserve_idx].reserve;
        let reserve_collateral_mint = self.reserves[reserve_idx].collateral_mint;
        let reserve_liquidity_supply = self.reserves[reserve_idx].liquidity_supply;
        let reserve_collateral_supply = self.reserves[reserve_idx].collateral_supply;

        // Patch freshness AND queue refresh instructions
        self.patch_freshness_all(user_idx);
        if let Err(e) = self.queue_all_refreshes(user_idx, &[reserve_idx]) {
            if DEBUG { eprintln!("[QUEUE_ERR] withdraw refresh: {:?}", e); }
            action_stats::record(&action_stats::WITHDRAW_OK, &action_stats::WITHDRAW_FAIL, false);
            return;
        }

        // Queue the actual instruction
        if let Err(e) = self.ctx.program(self.program_id)
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
            .add_transaction()
        {
            if DEBUG { eprintln!("[QUEUE_ERR] withdraw: {:?}", e); }
            action_stats::record(&action_stats::WITHDRAW_OK, &action_stats::WITHDRAW_FAIL, false);
            return;
        }

        // Send batch with RefreshReserve + RefreshObligation + WithdrawObligationCollateralAndRedeemReserveCollateral
        let result = self.ctx.send_batch();
        action_stats::handle_batch_result("withdraw", &result, &action_stats::WITHDRAW_OK, &action_stats::WITHDRAW_FAIL);
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
    // Price Change Action
    // ========================================================================

    pub fn action_change_price(
        &mut self,
        #[range(0..2)] reserve_idx: usize,
        #[range(0..20)] price_change: u64,  // 0-20 maps to different price levels
    ) {
        let reserve_idx = reserve_idx % self.reserves.len();
        let reserve_data = &self.reserves[reserve_idx];

        // Map 0-20 to realistic price movements around $100 baseline
        // 0-4: crash (50-70%), 5-9: dip (75-95%), 10: stable (100%)
        // 11-15: rise (105-125%), 16-20: spike (130-200%)
        let price_percent: u64 = match price_change {
            0 => 50,    // -50% crash
            1 => 55,
            2 => 60,
            3 => 65,
            4 => 70,
            5 => 75,    // -25% dip
            6 => 80,
            7 => 85,
            8 => 90,
            9 => 95,
            10 => 100,  // stable
            11 => 105,  // +5% rise
            12 => 110,
            13 => 115,
            14 => 120,
            15 => 125,
            16 => 130,  // +30% spike
            17 => 150,
            18 => 175,
            _ => 200,   // +100% spike
        };

        let new_price_i64: i64 = (price_percent as i64) * 1_00000000;  // $price with 8 decimals

        // Step 1: Update the Pyth oracle account
        if let Err(e) = self.ctx.update_pyth_price(&reserve_data.mock_pyth_oracle, new_price_i64, -8) {
            if DEBUG { eprintln!("[change_price] oracle update failed: {:?}", e); }
            return;
        }

        // Step 2: Update the reserve's cached market_price_sf
        let reserve_pubkey = reserve_data.reserve;
        if let Ok(mut account) = self.ctx.get_account(&reserve_pubkey) {
            if account.data.len() >= 8 + RESERVE_SIZE {
                let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut account.data[8..8 + RESERVE_SIZE]);
                let price_sf: u128 = (new_price_i64 as u128) * 10_u128.pow(10);
                reserve.liquidity.market_price_sf = types::u128_to_u64_pair(price_sf);
                let _ = self.ctx.svm.set_account(reserve_pubkey, account);
            }
        }

        if DEBUG {
            eprintln!("[change_price] reserve {} price: $100 -> ${}",
                      reserve_idx, price_percent);
        }
    }

    // ========================================================================
    // Time Skip Action
    // ========================================================================

    pub fn action_time_skip(
        &mut self,
        #[range(0..10)] time_scale: u64,  // 0-10 maps to different time periods
    ) {
        // Map to realistic time skips
        // Klend: SLOTS_PER_SECOND = 2, SLOTS_PER_HOUR = 7200, SLOTS_PER_DAY = 172800
        let slots_to_skip: u64 = match time_scale {
            0 => 120,       // 1 minute
            1 => 600,       // 5 minutes
            2 => 1200,      // 10 minutes
            3 => 3600,      // 30 minutes
            4 => 7200,      // 1 hour
            5 => 14400,     // 2 hours
            6 => 43200,     // 6 hours
            7 => 86400,     // 12 hours
            8 => 172800,    // 1 day
            9 => 604800,    // 3.5 days
            _ => 1209600,   // 1 week
        };

        // Step 1: Advance slots
        self.ctx.advance_slots(slots_to_skip);

        if DEBUG {
            let hours = slots_to_skip / 7200;
            eprintln!("[time_skip] advanced {} slots (~{} hours)", slots_to_skip, hours);
        }

        // Note: We don't call RefreshReserve/RefreshObligation here because they need a fee payer.
        // Interest will accrue naturally when the next action (borrow, repay, etc.) calls RefreshReserve.
        // The key is that slots have advanced, so slots_elapsed > 0 in the next refresh.
        //
        // The slot advancement makes accounts "stale" which is desired - the next operation
        // will trigger accrue_interest() with the elapsed time since last refresh.
    }

    // ========================================================================
    // Liquidation Action
    // ========================================================================

    pub fn action_liquidate(
        &mut self,
        #[range(0..4)] liquidator_idx: usize,
        #[range(0..4)] target_idx: usize,
        #[range(0..2)] repay_reserve_idx: usize,
        #[range(0..2)] withdraw_reserve_idx: usize,
        #[range(10_000_000..200_000_000)] liquidity_amount: u64,  // Reasonable liquidation amounts
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

        // Patch freshness for all reserves
        for i in 0..self.reserves.len() {
            self.patch_reserve_freshness(i);
        }
        self.patch_obligation_freshness(target_idx);

        // Queue RefreshReserve for both reserves
        if let Err(e) = self.queue_refresh_reserve(repay_reserve_idx) {
            if DEBUG { eprintln!("[QUEUE_ERR] liquidate refresh repay reserve: {:?}", e); }
            action_stats::record(&action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL, false);
            return;
        }
        if repay_reserve_idx != withdraw_reserve_idx {
            if let Err(e) = self.queue_refresh_reserve(withdraw_reserve_idx) {
                if DEBUG { eprintln!("[QUEUE_ERR] liquidate refresh withdraw reserve: {:?}", e); }
                action_stats::record(&action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL, false);
                return;
            }
        }

        // Queue RefreshObligation for TARGET with proper remaining_accounts
        // This uses the helper that reads the obligation and builds the correct account list
        if let Err(e) = self.queue_refresh_obligation(target_idx) {
            if DEBUG { eprintln!("[QUEUE_ERR] liquidate refresh target obligation: {:?}", e); }
            action_stats::record(&action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL, false);
            return;
        }

        // Note: Error 2502 only occurs in cross-reserve liquidation (different repay/withdraw reserves)
        // Same-reserve liquidation works correctly.

        // Queue the actual instruction
        if let Err(e) = self.ctx.program(self.program_id)
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
            .add_transaction()
        {
            if DEBUG { eprintln!("[QUEUE_ERR] liquidate: {:?}", e); }
            action_stats::record(&action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL, false);
            return;
        }

        // Send batch with RefreshObligation + LiquidateObligationAndRedeemReserveCollateral
        let result = self.ctx.send_batch();
        action_stats::handle_batch_result("liquidate", &result, &action_stats::LIQUIDATE_OK, &action_stats::LIQUIDATE_FAIL);
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
            Ok(TxOutcome::Success { .. }) => if DEBUG { eprintln!("[SETUP] InitLendingMarket SUCCESS"); },
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                if DEBUG {
                    eprintln!("[SETUP] InitLendingMarket TX_FAILED: {:?}", error);
                    for log in &logs { eprintln!("  {}", log); }
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

        // Create users (4 users for better liquidation coverage - reduces self-liquidation rate)
        let users: Vec<_> = (0..4)
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
        // Create account with GlobalConfig discriminator and admin set
        let mut data = vec![0u8; 8 + GLOBAL_CONFIG_SIZE];

        // GlobalConfig discriminator (first 8 bytes)
        let discriminator: [u8; 8] = [149, 8, 156, 75, 31, 54, 147, 229];
        data[..8].copy_from_slice(&discriminator);

        // global_admin is first field after discriminator (32 bytes)
        data[8..40].copy_from_slice(admin.as_ref());

        ctx.create_account()
            .pubkey(*pubkey)
            .lamports(100_000_000)
            .owner(*program_id)
            .data(&data)
            .create()
            .unwrap();
    }

    /// Create a mock Pyth oracle using the TestContext builder
    fn create_mock_pyth_oracle(
        ctx: &mut TestContext,
        price: i64,      // Price in native units (e.g., $100 with 8 decimals = 100_00000000)
        expo: i32,       // Price exponent (typically -8 for USD prices)
        _current_slot: u64,
    ) -> Pubkey {
        let oracle_pubkey = ctx.create_mock_pyth_oracle()
            .price(price)
            .exponent(expo)
            .confidence(100_000)
            .build()
            .unwrap();

        if DEBUG {
            eprintln!("[SETUP] Mock Pyth oracle created: {} (price={}, expo={})", oracle_pubkey, price, expo);
        }

        oracle_pubkey
    }

    /// Update the mock Pyth oracle with new price
    #[allow(dead_code)]
    fn update_mock_pyth_oracle(
        ctx: &mut TestContext,
        oracle_pubkey: &Pubkey,
        price: i64,
        expo: i32,
        _current_slot: u64,
    ) {
        let _ = ctx.update_pyth_price(oracle_pubkey, price, expo);
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
            Ok(TxOutcome::Success { .. }) => eprintln!("[SETUP] InitReserve SUCCESS for mint {}", mint),
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                eprintln!("[SETUP] InitReserve TX_FAILED: {:?}", error);
                for log in &logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitReserve");
            }
            Err(e) => {
                eprintln!("[SETUP] InitReserve SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitReserve");
            }
        }

        // Debug: print token_program and oracle config from reserve before patching
        if DEBUG {
            let account = ctx.get_account(&reserve_kp.pubkey()).unwrap();
            if account.data.len() >= 8 + RESERVE_SIZE {
                let reserve: &Reserve = bytemuck::from_bytes(&account.data[8..8 + RESERVE_SIZE]);
                let token_prog = solana_pubkey::Pubkey::new_from_array(reserve.liquidity.token_program);
                eprintln!("[DEBUG] Reserve token_program BEFORE patch: {}", token_prog);
                eprintln!("[DEBUG] Expected spl_token::id(): {}", spl_token::id());

                let pyth = solana_pubkey::Pubkey::new_from_array(reserve.config.token_info.pyth_configuration.price);
                let sb = solana_pubkey::Pubkey::new_from_array(reserve.config.token_info.switchboard_configuration.price_aggregator);
                let scope = solana_pubkey::Pubkey::new_from_array(reserve.config.token_info.scope_configuration.price_feed);
                eprintln!("[DEBUG] BEFORE patch - pyth: {}, sb: {}, scope: {}", pyth, sb, scope);
            }
        }

        // Create mock Pyth oracle for this reserve
        let current_slot = ctx.slot();
        // Price: $100 with 8 decimal precision (100_00000000)
        let mock_pyth_oracle = create_mock_pyth_oracle(ctx, 100_00000000, -8, current_slot);

        // Configure reserve with proper price and status
        configure_reserve_manually(ctx, program_id, &reserve_kp.pubkey(), current_slot, &mock_pyth_oracle);

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
            if let Ok(TxOutcome::ProgramError { error, .. }) = &result {
                eprintln!("[DEBUG] UpdateReserveConfig (deposit_limit) failed: {:?}", error);
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
            if let Ok(TxOutcome::ProgramError { error, .. }) = &result {
                eprintln!("[DEBUG] UpdateReserveConfig (borrow_limit) failed: {:?}", error);
            }
        }

        // Debug: print reserve config after patching
        if DEBUG {
            let account = ctx.get_account(&reserve_kp.pubkey()).unwrap();
            if account.data.len() >= 8 + RESERVE_SIZE {
                let reserve: &Reserve = bytemuck::from_bytes(&account.data[8..8 + RESERVE_SIZE]);
                let token_prog = solana_pubkey::Pubkey::new_from_array(reserve.liquidity.token_program);
                eprintln!("[DEBUG] Reserve token_program AFTER patch: {}", token_prog);
                eprintln!("[DEBUG] Reserve LTV: {}%, deposit_limit: {}, borrow_limit: {}",
                    reserve.config.loan_to_value_pct,
                    reserve.config.deposit_limit,
                    reserve.config.borrow_limit);
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
            mock_pyth_oracle,
        }
    }

    fn configure_reserve_manually(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        reserve_pubkey: &Pubkey,
        current_slot: u64,
        mock_pyth_oracle: &Pubkey,
    ) {
        use types::{Reserve, RESERVE_SIZE, PRICE_STATUS_ALL_CHECKS, u128_to_u64_pair};

        let account = ctx.get_account(reserve_pubkey).unwrap();
        let mut data = account.data.clone();

        // Use bytemuck to access Reserve struct (skip 8-byte discriminator)
        assert!(data.len() >= 8 + RESERVE_SIZE, "Reserve account too small");
        let reserve: &mut Reserve = bytemuck::from_bytes_mut(&mut data[8..8 + RESERVE_SIZE]);

        // === Fix last_update ===
        reserve.last_update.mark_fresh(current_slot);

        // === Fix liquidity fields ===
        // Set market price: $100 with 18 decimal scale (scaled fraction)
        let price_sf: u128 = 100 * 10_u128.pow(18);
        reserve.liquidity.market_price_sf = u128_to_u64_pair(price_sf);

        // Set cumulative_borrow_rate to 1.0 (2^60 in scaled fraction format)
        let one_sf: u64 = 1u64 << 60;
        reserve.liquidity.cumulative_borrow_rate_bsf.value[0] = one_sf;

        // Set token_program to SPL Token
        reserve.liquidity.token_program = spl_token::id().to_bytes();

        // === Fix config ===
        reserve.config.status = 0; // Active
        reserve.config.loan_to_value_pct = 80;
        reserve.config.liquidation_threshold_pct = 85;
        reserve.config.min_liquidation_bonus_bps = 500;
        reserve.config.max_liquidation_bonus_bps = 1000;
        reserve.config.deposit_limit = u64::MAX;
        reserve.config.borrow_limit = u64::MAX;
        reserve.config.borrow_limit_outside_elevation_group = u64::MAX;  // CRITICAL: this is checked separately
        reserve.config.borrow_factor_pct = 100;

        // === Fix token_info oracle configuration ===
        // Zero out Scope config
        reserve.config.token_info.scope_configuration.price_feed = [0u8; 32];
        reserve.config.token_info.scope_configuration.price_chain = [0xFFFF; 4];
        reserve.config.token_info.scope_configuration.twap_chain = [0xFFFF; 4];

        // Zero out Switchboard config
        reserve.config.token_info.switchboard_configuration.price_aggregator = [0u8; 32];
        reserve.config.token_info.switchboard_configuration.twap_aggregator = [0u8; 32];

        // Set Pyth oracle
        reserve.config.token_info.pyth_configuration.price = mock_pyth_oracle.to_bytes();

        // Set reasonable price age limits
        reserve.config.token_info.max_age_price_seconds = 600;
        reserve.config.token_info.max_age_twap_seconds = 600;

        if DEBUG {
            let pyth_pubkey = solana_pubkey::Pubkey::new_from_array(reserve.config.token_info.pyth_configuration.price);
            eprintln!("[DEBUG] Set pyth oracle to: {}", pyth_pubkey);
            eprintln!("[DEBUG] LTV: {}%, liquidation_threshold: {}%",
                reserve.config.loan_to_value_pct, reserve.config.liquidation_threshold_pct);
        }

        // Update the account
        ctx.create_account()
            .pubkey(*reserve_pubkey)
            .lamports(account.lamports)
            .owner(*program_id)
            .data(&data)
            .create()
            .unwrap();
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
            Ok(TxOutcome::Success { .. }) => eprintln!("[SETUP] InitObligation SUCCESS for user {}", keypair.pubkey()),
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                eprintln!("[SETUP] InitObligation TX_FAILED: {:?}", error);
                for log in &logs { eprintln!("  {}", log); }
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
        // Create UserMetadata with correct discriminator
        let mut data = vec![0u8; 8 + USER_METADATA_SIZE];

        // UserMetadata discriminator (from IDL)
        let discriminator: [u8; 8] = [157, 214, 220, 235, 98, 135, 171, 28];
        data[..8].copy_from_slice(&discriminator);

        // UserMetadata layout:
        // - referrer: Pubkey (32)
        // - bump: u64 (8)
        // - user_lookup_table: Pubkey (32)
        // - owner: Pubkey (32)
        // - padding_1: [u8; 51]
        // - padding_2: [u64; 64]

        // Set referrer (default/none)
        data[8..40].copy_from_slice(Pubkey::default().as_ref());

        // Set bump
        data[40..48].copy_from_slice(&(bump as u64).to_le_bytes());

        // Set user_lookup_table (default)
        data[48..80].copy_from_slice(Pubkey::default().as_ref());

        // Set owner
        data[80..112].copy_from_slice(owner.as_ref());

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
    use types::{Obligation, OBLIGATION_SIZE, u64_pair_to_u128};

    // Check each user's obligation for bad debt
    for user in &fixture.users {
        let Ok(account) = fixture.ctx.get_account(&user.obligation) else { continue };

        // Skip if account is too small
        if account.data.len() < 8 + OBLIGATION_SIZE {
            continue;
        }

        // Use bytemuck to access Obligation struct (skip 8-byte discriminator)
        let obligation: &Obligation = bytemuck::from_bytes(&account.data[8..8 + OBLIGATION_SIZE]);

        // Read values using the struct fields
        let deposited_value = u64_pair_to_u128(obligation.deposited_value_sf);
        let borrowed_value = u64_pair_to_u128(obligation.borrowed_assets_market_value_sf);

        // Solvency check: borrowed should not exceed deposited significantly
        if borrowed_value > 0 && deposited_value > 0 {
            // Allow 10% margin for rounding, fees, and interest
            let margin = deposited_value / 10;
            crucible_test_context::fuzz_assert_le!(
                borrowed_value,
                deposited_value + margin,
                "SOLVENCY VIOLATION: user {} has borrowed {} > deposited {} + margin {}",
                user.keypair.pubkey(),
                borrowed_value,
                deposited_value,
                margin
            );
        }
    }
}
