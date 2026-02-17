use crucible_fuzzer::*;
use crucible_test_context::TxOutcome;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crucible_fuzzer::anchor_spl::associated_token;

// Generate types from IDL (no crate dependency - avoids version conflicts)
crucible_idl_gen::declare_fuzz_program!("idls/whirlpool.json");

use whirlpool::instruction;
use whirlpool::accounts;
use whirlpool::types::{WhirlpoolBumps, OpenPositionBumps};

// ============================================================================
// Debug Flag
// ============================================================================

/// Set to true to enable debug output for all actions
const DEBUG: bool = false;

macro_rules! debug_print {
    ($($arg:tt)*) => {
        if DEBUG {
            eprintln!($($arg)*);
        }
    };
}

// ============================================================================
// Action Stats Tracking
// ============================================================================

mod action_stats {
    use std::sync::atomic::{AtomicU32, Ordering};

    macro_rules! define_counters {
        ($($name:ident),*) => {
            $(pub static $name: (AtomicU32, AtomicU32) = (AtomicU32::new(0), AtomicU32::new(0));)*
        }
    }

    define_counters!(
        SWAP, INCREASE_LIQUIDITY, DECREASE_LIQUIDITY,
        UPDATE_FEES, COLLECT_FEES, OPEN_POSITION, CLOSE_POSITION
    );

    pub fn record(counter: &(AtomicU32, AtomicU32), success: bool) {
        if success {
            counter.0.fetch_add(1, Ordering::Relaxed);
        } else {
            counter.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn print_summary() {
        eprintln!("=== Action Stats ===");
        eprintln!("swap:           {:>5} ok / {:>5} fail", SWAP.0.load(Ordering::Relaxed), SWAP.1.load(Ordering::Relaxed));
        eprintln!("increase_liq:   {:>5} ok / {:>5} fail", INCREASE_LIQUIDITY.0.load(Ordering::Relaxed), INCREASE_LIQUIDITY.1.load(Ordering::Relaxed));
        eprintln!("decrease_liq:   {:>5} ok / {:>5} fail", DECREASE_LIQUIDITY.0.load(Ordering::Relaxed), DECREASE_LIQUIDITY.1.load(Ordering::Relaxed));
        eprintln!("update_fees:    {:>5} ok / {:>5} fail", UPDATE_FEES.0.load(Ordering::Relaxed), UPDATE_FEES.1.load(Ordering::Relaxed));
        eprintln!("collect_fees:   {:>5} ok / {:>5} fail", COLLECT_FEES.0.load(Ordering::Relaxed), COLLECT_FEES.1.load(Ordering::Relaxed));
        eprintln!("open_position:  {:>5} ok / {:>5} fail", OPEN_POSITION.0.load(Ordering::Relaxed), OPEN_POSITION.1.load(Ordering::Relaxed));
        eprintln!("close_position: {:>5} ok / {:>5} fail", CLOSE_POSITION.0.load(Ordering::Relaxed), CLOSE_POSITION.1.load(Ordering::Relaxed));
    }
}

// ============================================================================
// Constants from Whirlpool Program
// ============================================================================

// Tick spacing for our pool (common values: 1, 8, 64, 128)
const TICK_SPACING: u16 = 64;

// Default fee rate (3000 = 0.30%)
const DEFAULT_FEE_RATE: u16 = 3000;

// Initial sqrt price for 1:1 ratio (Q64.64 format)
// sqrt(1) * 2^64 = 2^64 = 18446744073709551616
const INITIAL_SQRT_PRICE: u128 = 18446744073709551616;

// Tick array size (fixed at 88 ticks per array)
const TICK_ARRAY_SIZE: i32 = 88;

// Min/max tick from whirlpool program (src/state/tick.rs)
const MIN_TICK_INDEX: i32 = -443636;
const MAX_TICK_INDEX: i32 = 443636;

// Sqrt price bounds from whirlpool program
const MAX_SQRT_PRICE_X64: u128 = 79226673515401279992447579055;
const MIN_SQRT_PRICE_X64: u128 = 4295048016;

// ============================================================================
// Fixture Data Structures
// ============================================================================

#[derive(Clone)]
struct PoolData {
    whirlpool: Pubkey,
    token_mint_a: Pubkey,
    token_mint_b: Pubkey,
    token_vault_a: Pubkey,
    token_vault_b: Pubkey,
    tick_arrays: Vec<(i32, Pubkey)>,  // (start_tick_index, pubkey)
    oracle: Pubkey,
}

#[derive(Clone)]
struct PositionData {
    position: Pubkey,
    #[allow(dead_code)]
    position_mint: Pubkey,
    position_token_account: Pubkey,
    tick_lower_index: i32,
    tick_upper_index: i32,
    owner_idx: usize,
    has_liquidity: bool,
}

#[derive(Clone)]
struct UserData {
    keypair: Rc<Keypair>,
    token_account_a: Pubkey,
    token_account_b: Pubkey,
}

#[derive(Clone)]
struct WhirlpoolFixture {
    ctx: TestContext,
    program_id: Pubkey,
    #[allow(dead_code)]
    admin: Rc<Keypair>,
    #[allow(dead_code)]
    config: Pubkey,
    #[allow(dead_code)]
    fee_tier: Pubkey,
    pool: PoolData,
    users: Vec<UserData>,
    positions: Vec<PositionData>,
    // Tracking for invariants
    total_liquidity_added: u128,
    total_swaps: u64,
    successful_swaps: u64,
}

#[fuzz_fixture]
impl WhirlpoolFixture {
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = whirlpool::ID;

        // Load program binary (built separately from fuzz harness)
        ctx.add_program(&program_id, "../../whirlpool.so").unwrap();

        fixture_helpers::initialize_state(&mut ctx, &program_id)
    }

    // ========================================================================
    // Swap Actions
    // ========================================================================

    /// Swap token A for token B (small amounts)
    pub fn action_swap_a_to_b(&mut self, #[range(0..3)] user_idx: usize, amount: u64) {
        let amount = (amount % 1_000_000) + 1; // Cap at 1M tokens, min 1
        self.do_swap(user_idx, amount, true, None);
    }

    /// Swap token B for token A (small amounts)
    pub fn action_swap_b_to_a(&mut self, #[range(0..3)] user_idx: usize, amount: u64) {
        let amount = (amount % 1_000_000) + 1;
        self.do_swap(user_idx, amount, false, None);
    }

    /// Large swap that can cross multiple ticks (to trigger tick crossing logic)
    pub fn action_large_swap_a_to_b(&mut self, #[range(0..3)] user_idx: usize, amount: u64) {
        // Large amounts: 100M - 1B tokens
        let amount = (amount % 900_000_000) + 100_000_000;
        self.do_swap(user_idx, amount, true, None);
    }

    /// Large swap B to A (to trigger tick crossing logic)
    pub fn action_large_swap_b_to_a(&mut self, #[range(0..3)] user_idx: usize, amount: u64) {
        let amount = (amount % 900_000_000) + 100_000_000;
        self.do_swap(user_idx, amount, false, None);
    }

    /// Tiny swap (edge case - minimum amounts)
    pub fn action_tiny_swap(&mut self, #[range(0..3)] user_idx: usize, a_to_b: bool) {
        self.do_swap(user_idx, 1, a_to_b, None);
    }

    /// Swap with a partial price limit (not all the way to MIN/MAX)
    /// This can trigger different code paths when the swap stops early
    pub fn action_swap_with_limit(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
        limit_pct: u64,  // 0-100 percentage of the way to the limit
    ) {
        let amount = (amount % 1_000_000) + 1;
        let limit_pct = (limit_pct % 101) as u128;

        // Calculate a sqrt_price_limit between current price and min/max
        // Current price is INITIAL_SQRT_PRICE (2^64 for 1:1 ratio)
        let sqrt_price_limit = if a_to_b {
            // Going down: limit between current and MIN
            let range = INITIAL_SQRT_PRICE - MIN_SQRT_PRICE_X64;
            let offset = (range * limit_pct) / 100;
            INITIAL_SQRT_PRICE - offset
        } else {
            // Going up: limit between current and MAX
            let range = MAX_SQRT_PRICE_X64 - INITIAL_SQRT_PRICE;
            let offset = (range * limit_pct) / 100;
            INITIAL_SQRT_PRICE + offset
        };

        self.do_swap(user_idx, amount, a_to_b, Some(sqrt_price_limit));
    }

    fn do_swap(&mut self, user_idx: usize, amount: u64, a_to_b: bool, custom_limit: Option<u128>) {
        self.total_swaps += 1;

        let user = &self.users[user_idx];
        let pool = &self.pool;

        // Need at least 3 tick arrays for swap
        if pool.tick_arrays.len() < 3 {
            debug_print!("[SWAP] ERROR: Not enough tick arrays ({})", pool.tick_arrays.len());
            return;
        }

        let sqrt_price_limit = custom_limit.unwrap_or(if a_to_b {
            MIN_SQRT_PRICE_X64
        } else {
            MAX_SQRT_PRICE_X64
        });

        // Select tick arrays based on swap direction
        // For a_to_b (price decreasing): need arrays at current tick and below (descending)
        // For b_to_a (price increasing): need arrays at current tick and above (ascending)
        // Current tick is 0, tick arrays are sorted by start_tick_index
        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap(a_to_b);

        let result = self.ctx.program(self.program_id)
            .call(instruction::Swap {
                amount,
                other_amount_threshold: 0,
                sqrt_price_limit,
                amount_specified_is_input: true,
                a_to_b,
            })
            .accounts(accounts::Swap {
                token_authority: user.keypair.pubkey(),
                whirlpool: pool.whirlpool,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.successful_swaps += 1;
                debug_print!("[SWAP] SUCCESS: {} {} (user {})",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx);
                for log in logs {
                    debug_print!("[SWAP]   {}", log);
                }
                false
            }
            Err(e) => {
                debug_print!("[SWAP] SEND_FAILED: {} amount={} user={}: {:?}",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP, success);
    }

    // ========================================================================
    // Liquidity Actions
    // ========================================================================

    /// Increase liquidity in an existing position (normal amounts)
    pub fn action_increase_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,  // Use u64 for arbitrary compatibility
    ) {
        if position_idx >= self.positions.len() {
            return;
        }

        let liquidity_amount = ((liquidity_amount % 1_000_000_000) + 1000) as u128; // Min 1000
        self.do_increase_liquidity(position_idx, liquidity_amount);
    }

    /// Add very large liquidity (edge case - near u128 overflow regions)
    pub fn action_massive_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
    ) {
        if position_idx >= self.positions.len() {
            return;
        }

        // Very large liquidity: 10^18 (1 quintillion)
        let liquidity_amount = 1_000_000_000_000_000_000u128;
        self.do_increase_liquidity(position_idx, liquidity_amount);
    }

    /// Add minimum liquidity (edge case)
    pub fn action_tiny_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
    ) {
        if position_idx >= self.positions.len() {
            return;
        }

        self.do_increase_liquidity(position_idx, 1);
    }

    fn do_increase_liquidity(&mut self, position_idx: usize, liquidity_amount: u128) {
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        // Get tick arrays for position's tick range
        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
            })
            .accounts(accounts::IncreaseLiquidity {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.total_liquidity_added += liquidity_amount;
                self.positions[position_idx].has_liquidity = true;
                debug_print!("[INCREASE_LIQ] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INCREASE_LIQ] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INCREASE_LIQ] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::INCREASE_LIQUIDITY, success);
    }

    /// Decrease liquidity from an existing position
    pub fn action_decrease_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,  // Use u64 for arbitrary compatibility
    ) {
        if position_idx >= self.positions.len() {
            return;
        }

        // Only try to decrease if position has liquidity
        if !self.positions[position_idx].has_liquidity {
            return;
        }

        let liquidity_amount = ((liquidity_amount % 100_000) + 1) as u128; // Smaller amounts
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[DECREASE_LIQ] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DECREASE_LIQ] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DECREASE_LIQ] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQUIDITY, success);
    }

    // ========================================================================
    // Fee Collection Actions
    // ========================================================================

    /// Update fees and rewards for a position (must be called before collecting)
    pub fn action_update_fees_and_rewards(&mut self, #[range(0..5)] position_idx: usize) {
        if position_idx >= self.positions.len() {
            return;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Transaction needs a fee payer even if instruction doesn't require signers
        let result = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: pool.whirlpool,
                position: position.position,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])  // Fee payer
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[UPDATE_FEES] SUCCESS: pos={}", position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[UPDATE_FEES] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[UPDATE_FEES] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::UPDATE_FEES, success);
    }

    /// Collect fees from a position
    pub fn action_collect_fees(&mut self, #[range(0..5)] position_idx: usize) {
        if position_idx >= self.positions.len() {
            return;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let result = self.ctx.program(self.program_id)
            .call(instruction::CollectFees {})
            .accounts(accounts::CollectFees {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[COLLECT_FEES] SUCCESS: pos={}", position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[COLLECT_FEES] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[COLLECT_FEES] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_FEES, success);
    }

    // ========================================================================
    // Position Management Actions
    // ========================================================================

    /// Open a new position for a user
    pub fn action_open_position(
        &mut self,
        #[range(0..3)] user_idx: usize,
        tick_lower_offset: i64,
        tick_upper_offset: i64,
    ) {
        // Limit to 10 positions to avoid memory issues
        if self.positions.len() >= 10 {
            return;
        }

        // Calculate tick indices (must be multiples of tick_spacing)
        // Keep within a reasonable range around current tick (0)
        let tick_lower_offset = tick_lower_offset as i32;
        let tick_upper_offset = tick_upper_offset as i32;
        let tick_lower_raw = ((tick_lower_offset % 50) - 25) * (TICK_SPACING as i32);
        let tick_upper_raw = tick_lower_raw + ((tick_upper_offset.abs() % 20 + 1) * (TICK_SPACING as i32));

        let tick_lower_index = tick_lower_raw.max(MIN_TICK_INDEX).min(MAX_TICK_INDEX - TICK_SPACING as i32);
        let tick_upper_index = tick_upper_raw.max(tick_lower_index + TICK_SPACING as i32).min(MAX_TICK_INDEX);

        let user = &self.users[user_idx];
        let pool = &self.pool;

        let position_mint = Keypair::new();

        let (position, position_bump) = Pubkey::find_program_address(
            &[b"position", position_mint.pubkey().as_ref()],
            &self.program_id,
        );

        let position_token_account = associated_token::get_associated_token_address(
            &user.keypair.pubkey(),
            &position_mint.pubkey(),
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::OpenPosition {
                bumps: OpenPositionBumps { position_bump },
                tick_lower_index,
                tick_upper_index,
            })
            .accounts(accounts::OpenPosition {
                funder: user.keypair.pubkey(),
                owner: user.keypair.pubkey(),
                position,
                position_mint: position_mint.pubkey(),
                position_token_account,
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions.push(PositionData {
                    position,
                    position_mint: position_mint.pubkey(),
                    position_token_account,
                    tick_lower_index,
                    tick_upper_index,
                    owner_idx: user_idx,
                    has_liquidity: false,
                });
                debug_print!("[OPEN_POS] SUCCESS: user={} ticks=[{},{}]", user_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_POS] TX_FAILED: user={} ticks=[{},{}]",
                    user_idx, tick_lower_index, tick_upper_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_POS] SEND_FAILED: user={} ticks=[{},{}]: {:?}",
                    user_idx, tick_lower_index, tick_upper_index, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION, success);
    }

    /// Close an empty position (no liquidity)
    pub fn action_close_position(&mut self, #[range(0..5)] position_idx: usize) {
        if position_idx >= self.positions.len() {
            return;
        }

        // Only close positions without liquidity
        if self.positions[position_idx].has_liquidity {
            debug_print!("[CLOSE_POS] SKIP: pos={} has liquidity", position_idx);
            return;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        let result = self.ctx.program(self.program_id)
            .call(instruction::ClosePosition {})
            .accounts(accounts::ClosePosition {
                position_authority: user.keypair.pubkey(),
                receiver: user.keypair.pubkey(),
                position: position.position,
                position_mint: position.position_mint,
                position_token_account: position.position_token_account,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[CLOSE_POS] SUCCESS: pos={}", position_idx);
                self.positions.remove(position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[CLOSE_POS] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[CLOSE_POS] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::CLOSE_POSITION, success);
    }

    /// Open a full-range position (maximum tick range)
    pub fn action_open_full_range_position(&mut self, #[range(0..3)] user_idx: usize) {
        if self.positions.len() >= 10 {
            return;
        }

        let user = &self.users[user_idx];
        let pool = &self.pool;

        // Full range ticks (aligned to tick spacing)
        let tick_lower_index = (MIN_TICK_INDEX / (TICK_SPACING as i32)) * (TICK_SPACING as i32);
        let tick_upper_index = (MAX_TICK_INDEX / (TICK_SPACING as i32)) * (TICK_SPACING as i32);

        let position_mint = Keypair::new();

        let (position, position_bump) = Pubkey::find_program_address(
            &[b"position", position_mint.pubkey().as_ref()],
            &self.program_id,
        );

        let position_token_account = associated_token::get_associated_token_address(
            &user.keypair.pubkey(),
            &position_mint.pubkey(),
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::OpenPosition {
                bumps: OpenPositionBumps { position_bump },
                tick_lower_index,
                tick_upper_index,
            })
            .accounts(accounts::OpenPosition {
                funder: user.keypair.pubkey(),
                owner: user.keypair.pubkey(),
                position,
                position_mint: position_mint.pubkey(),
                position_token_account,
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions.push(PositionData {
                    position,
                    position_mint: position_mint.pubkey(),
                    position_token_account,
                    tick_lower_index,
                    tick_upper_index,
                    owner_idx: user_idx,
                    has_liquidity: false,
                });
                debug_print!("[OPEN_FULL_RANGE] SUCCESS: user={} ticks=[{},{}]", user_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_FULL_RANGE] TX_FAILED: user={}", user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_FULL_RANGE] SEND_FAILED: user={}: {:?}", user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION, success);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    fn get_tick_array_for_tick(&self, tick_index: i32) -> Pubkey {
        let target_start = self.get_start_tick_index(tick_index);

        // Find the tick array that covers this tick
        for (start, pubkey) in &self.pool.tick_arrays {
            if *start == target_start {
                return *pubkey;
            }
        }

        // Fallback: find the closest tick array
        let mut closest = self.pool.tick_arrays[0];
        let mut closest_dist = i32::MAX;
        for (start, pubkey) in &self.pool.tick_arrays {
            let dist = (start - target_start).abs();
            if dist < closest_dist {
                closest_dist = dist;
                closest = (*start, *pubkey);
            }
        }

        closest.1
    }

    fn get_start_tick_index(&self, tick_index: i32) -> i32 {
        let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
        // Floor division for negative numbers
        let array_index = if tick_index >= 0 {
            tick_index / ticks_in_array
        } else {
            (tick_index - ticks_in_array + 1) / ticks_in_array
        };
        array_index * ticks_in_array
    }

    /// Get tick arrays ordered correctly for swap direction
    /// - a_to_b (price decreasing): need arrays at current tick and below (descending order by start_tick)
    /// - b_to_a (price increasing): need arrays at current tick and above (ascending order by start_tick)
    fn get_tick_arrays_for_swap(&self, a_to_b: bool) -> (Pubkey, Pubkey, Pubkey) {
        let mut sorted_arrays = self.pool.tick_arrays.clone();

        if a_to_b {
            // For a_to_b: sort descending (highest start_tick first, then going lower)
            // We want tick arrays that cover current tick and below
            sorted_arrays.sort_by(|a, b| b.0.cmp(&a.0));

            // Find arrays starting from current tick (0) and going down
            // Filter to arrays with start_tick <= current_tick (0) or covering current area
            let current_tick = 0i32;

            // Find arrays that could be relevant for a_to_b swap starting at tick 0
            // Tick array 0 covers [0, 5632), array -5632 covers [-5632, 0), etc.
            let relevant: Vec<_> = sorted_arrays.iter()
                .filter(|(start, _)| *start <= current_tick)
                .take(3)
                .collect();

            if relevant.len() >= 3 {
                (relevant[0].1, relevant[1].1, relevant[2].1)
            } else {
                // Fallback: use any 3 arrays in descending order
                let len = sorted_arrays.len();
                (
                    sorted_arrays[0].1,
                    sorted_arrays[1.min(len-1)].1,
                    sorted_arrays[2.min(len-1)].1,
                )
            }
        } else {
            // For b_to_a: sort ascending (lowest start_tick first, then going higher)
            // We want tick arrays that cover current tick and above
            sorted_arrays.sort_by(|a, b| a.0.cmp(&b.0));

            let current_tick = 0i32;

            // Find arrays that could be relevant for b_to_a swap starting at tick 0
            // We need the array containing current tick and arrays above it
            let relevant: Vec<_> = sorted_arrays.iter()
                .filter(|(start, _)| *start >= 0) // Arrays at or above current tick
                .take(3)
                .collect();

            if relevant.len() >= 3 {
                (relevant[0].1, relevant[1].1, relevant[2].1)
            } else {
                // Fallback: use any 3 arrays in ascending order
                let len = sorted_arrays.len();
                (
                    sorted_arrays[0].1,
                    sorted_arrays[1.min(len-1)].1,
                    sorted_arrays[2.min(len-1)].1,
                )
            }
        }
    }

    // ========================================================================
    // After-Action Callback
    // ========================================================================

    pub fn after_action(&self) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);

        if count > 0 && count % 1000 == 0 {
            action_stats::print_summary();

            // State snapshot - show pool stats
            eprintln!("\n=== State Snapshot (action {}) ===", count);
            eprintln!("positions: {}", self.positions.len());
            eprintln!("total_swaps: {} (successful: {})", self.total_swaps, self.successful_swaps);
            eprintln!("total_liquidity_added: {}", self.total_liquidity_added);
            eprintln!();
        }
    }
}

// ============================================================================
// Initialization Helpers
// ============================================================================

mod fixture_helpers {
    use super::*;

    /// Load the localnet admin keypair from the whirlpool program's auth directory.
    /// This keypair is in the ADMINS whitelist required by InitializeConfig.
    fn load_localnet_admin() -> Keypair {
        // Hardcoded from programs/whirlpool/src/auth/localnet/localnet-admin-keypair-0.json
        // Pubkey: tstYmkF9JHjZbSugJe1H3ygUTox1bqSxpn5QjxMwVrm
        let bytes: [u8; 64] = [
            177, 132, 153, 219, 3, 29, 214, 174, 187, 166, 254, 107, 173, 113, 207, 134,
            17, 53, 203, 189, 22, 128, 45, 37, 77, 187, 57, 146, 226, 162, 184, 112, 13,
            74, 41, 78, 251, 147, 132, 170, 77, 107, 238, 244, 51, 111, 207, 234, 88, 212,
            14, 239, 228, 185, 130, 71, 111, 173, 229, 157, 218, 8, 156, 70
        ];
        Keypair::try_from(bytes.as_slice()).expect("Invalid localnet admin keypair")
    }

    pub fn initialize_state(ctx: &mut TestContext, program_id: &Pubkey) -> WhirlpoolFixture {
        // Use the predefined localnet admin keypair from the whirlpool ADMINS whitelist
        let admin = Rc::new(load_localnet_admin());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        eprintln!("[SETUP] Admin pubkey: {} (localnet admin)", admin.pubkey());

        // Initialize WhirlpoolsConfig
        let config = init_config(ctx, &admin, program_id);
        eprintln!("[SETUP] Config: {}", config);

        // Initialize FeeTier
        let fee_tier = init_fee_tier(ctx, &admin, &config, program_id);
        eprintln!("[SETUP] Fee tier: {}", fee_tier);

        // Create token mints (must be ordered: mint_a < mint_b by pubkey)
        let (mint_a, mint_b) = create_ordered_mints(ctx, &admin);
        eprintln!("[SETUP] Mint A: {}", mint_a);
        eprintln!("[SETUP] Mint B: {}", mint_b);

        // Initialize Whirlpool
        let pool = init_pool(ctx, &admin, &config, &fee_tier, &mint_a, &mint_b, program_id);
        eprintln!("[SETUP] Whirlpool: {}", pool.whirlpool);

        // Initialize tick arrays around current price
        let tick_arrays = init_tick_arrays(ctx, &admin, &pool.whirlpool, program_id);
        // tick array count is printed in init_tick_arrays

        let pool = PoolData {
            tick_arrays,
            ..pool
        };

        // Create users with token accounts
        let users: Vec<_> = (0..3)
            .map(|i| {
                let user = create_user(ctx, &admin, &mint_a, &mint_b);
                eprintln!("[SETUP] User {}: {}", i, user.keypair.pubkey());
                user
            })
            .collect();

        // Create some initial positions with liquidity
        let positions = create_initial_positions(ctx, &users, &pool, program_id);
        // position count is printed in create_initial_positions

        WhirlpoolFixture {
            ctx: std::mem::replace(ctx, TestContext::new()),
            program_id: *program_id,
            admin: admin.clone(),
            config,
            fee_tier,
            pool,
            users,
            positions,
            total_liquidity_added: 0,
            total_swaps: 0,
            successful_swaps: 0,
        }
    }

    fn init_config(ctx: &mut TestContext, admin: &Rc<Keypair>, program_id: &Pubkey) -> Pubkey {
        let config = Keypair::new();

        let result = ctx.program(*program_id)
            .call(instruction::InitializeConfig {
                fee_authority: admin.pubkey(),
                collect_protocol_fees_authority: admin.pubkey(),
                reward_emissions_super_authority: admin.pubkey(),
                default_protocol_fee_rate: 300, // 0.03%
            })
            .accounts(accounts::InitializeConfig {
                config: config.pubkey(),
                funder: admin.pubkey(),
            })
            .signers(&[&**admin, &config])
            .send();

        match result {
            Ok(TxOutcome::Success { .. }) => eprintln!("[SETUP] InitializeConfig SUCCESS"),
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                eprintln!("[SETUP] InitializeConfig TX_FAILED: {:?}", error);
                for log in &logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitializeConfig");
            }
            Err(e) => {
                eprintln!("[SETUP] InitializeConfig SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitializeConfig");
            }
        }

        config.pubkey()
    }

    fn init_fee_tier(
        ctx: &mut TestContext,
        admin: &Rc<Keypair>,
        config: &Pubkey,
        program_id: &Pubkey,
    ) -> Pubkey {
        let (fee_tier, _) = Pubkey::find_program_address(
            &[b"fee_tier", config.as_ref(), &TICK_SPACING.to_le_bytes()],
            program_id,
        );

        let result = ctx.program(*program_id)
            .call(instruction::InitializeFeeTier {
                tick_spacing: TICK_SPACING,
                default_fee_rate: DEFAULT_FEE_RATE,
            })
            .accounts(accounts::InitializeFeeTier {
                config: *config,
                fee_tier,
                funder: admin.pubkey(),
                fee_authority: admin.pubkey(),
            })
            .signers(&[&**admin])
            .send();

        match result {
            Ok(TxOutcome::Success { .. }) => eprintln!("[SETUP] InitializeFeeTier SUCCESS"),
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                eprintln!("[SETUP] InitializeFeeTier TX_FAILED: {:?}", error);
                for log in &logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitializeFeeTier");
            }
            Err(e) => {
                eprintln!("[SETUP] InitializeFeeTier SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitializeFeeTier");
            }
        }

        fee_tier
    }

    fn create_ordered_mints(ctx: &mut TestContext, admin: &Rc<Keypair>) -> (Pubkey, Pubkey) {
        // Create two mints and order them by pubkey
        let mint1 = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();

        let mint2 = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();

        // Whirlpool requires mint_a < mint_b
        if mint1 < mint2 {
            (mint1, mint2)
        } else {
            (mint2, mint1)
        }
    }

    fn init_pool(
        ctx: &mut TestContext,
        admin: &Rc<Keypair>,
        config: &Pubkey,
        fee_tier: &Pubkey,
        mint_a: &Pubkey,
        mint_b: &Pubkey,
        program_id: &Pubkey,
    ) -> PoolData {
        let (whirlpool, whirlpool_bump) = Pubkey::find_program_address(
            &[
                b"whirlpool",
                config.as_ref(),
                mint_a.as_ref(),
                mint_b.as_ref(),
                &TICK_SPACING.to_le_bytes(),
            ],
            program_id,
        );

        let token_vault_a = Keypair::new();
        let token_vault_b = Keypair::new();

        let (oracle, _) = Pubkey::find_program_address(
            &[b"oracle", whirlpool.as_ref()],
            program_id,
        );

        let result = ctx.program(*program_id)
            .call(instruction::InitializePool {
                bumps: WhirlpoolBumps { whirlpool_bump },
                tick_spacing: TICK_SPACING,
                initial_sqrt_price: INITIAL_SQRT_PRICE,
            })
            .accounts(accounts::InitializePool {
                whirlpools_config: *config,
                token_mint_a: *mint_a,
                token_mint_b: *mint_b,
                funder: admin.pubkey(),
                whirlpool,
                token_vault_a: token_vault_a.pubkey(),
                token_vault_b: token_vault_b.pubkey(),
                fee_tier: *fee_tier,
            })
            .signers(&[&**admin, &token_vault_a, &token_vault_b])
            .send();

        match result {
            Ok(TxOutcome::Success { .. }) => eprintln!("[SETUP] InitializePool SUCCESS"),
            Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                eprintln!("[SETUP] InitializePool TX_FAILED: {:?}", error);
                for log in &logs { eprintln!("  {}", log); }
                panic!("Setup failed: InitializePool");
            }
            Err(e) => {
                eprintln!("[SETUP] InitializePool SEND_FAILED: {:?}", e);
                panic!("Setup failed: InitializePool");
            }
        }

        PoolData {
            whirlpool,
            token_mint_a: *mint_a,
            token_mint_b: *mint_b,
            token_vault_a: token_vault_a.pubkey(),
            token_vault_b: token_vault_b.pubkey(),
            tick_arrays: vec![],
            oracle,
        }
    }

    fn init_tick_arrays(
        ctx: &mut TestContext,
        admin: &Rc<Keypair>,
        whirlpool: &Pubkey,
        program_id: &Pubkey,
    ) -> Vec<(i32, Pubkey)> {
        let mut tick_arrays = Vec::new();

        // Initialize tick arrays around the current tick (0)
        // Each array covers TICK_ARRAY_SIZE * TICK_SPACING ticks = 88 * 64 = 5632
        let array_span = TICK_ARRAY_SIZE * (TICK_SPACING as i32);

        // Create more tick arrays for better coverage
        for i in -5..=5 {
            let start_tick_index = i * array_span;

            // Note: Whirlpool uses string representation of tick index in seeds
            // seeds = [b"tick_array", whirlpool, start_tick_index.to_string().as_bytes()]
            let start_tick_str = start_tick_index.to_string();
            let (tick_array, _) = Pubkey::find_program_address(
                &[
                    b"tick_array",
                    whirlpool.as_ref(),
                    start_tick_str.as_bytes(),
                ],
                program_id,
            );

            let result = ctx.program(*program_id)
                .call(instruction::InitializeTickArray { start_tick_index })
                .accounts(accounts::InitializeTickArray {
                    whirlpool: *whirlpool,
                    funder: admin.pubkey(),
                    tick_array,
                })
                .signers(&[&**admin])
                .send();

            match result {
                Ok(TxOutcome::Success { .. }) => {
                    tick_arrays.push((start_tick_index, tick_array));
                    eprintln!("[SETUP] TickArray SUCCESS at start_tick={}", start_tick_index);
                }
                Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                    eprintln!("[SETUP] TickArray TX_FAILED at start_tick={}: {:?}", start_tick_index, error);
                    for log in &logs { eprintln!("  {}", log); }
                    panic!("Setup failed: InitializeTickArray at start_tick={}", start_tick_index);
                }
                Err(e) => {
                    eprintln!("[SETUP] TickArray SEND_FAILED at start_tick={}: {:?}", start_tick_index, e);
                    panic!("Setup failed: InitializeTickArray at start_tick={}", start_tick_index);
                }
            }
        }

        if tick_arrays.is_empty() {
            panic!("Setup failed: No tick arrays were created!");
        }

        eprintln!("[SETUP] Created {} tick arrays", tick_arrays.len());
        tick_arrays
    }

    fn create_user(
        ctx: &mut TestContext,
        admin: &Rc<Keypair>,
        mint_a: &Pubkey,
        mint_b: &Pubkey,
    ) -> UserData {
        let keypair = Rc::new(Keypair::new());

        ctx.create_account()
            .pubkey(keypair.pubkey())
            .lamports(10_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // Create token accounts
        let token_account_a = ctx.create_token_account()
            .pubkey(Keypair::new().pubkey())
            .mint(*mint_a)
            .token_owner(keypair.pubkey())
            .create()
            .unwrap();

        let token_account_b = ctx.create_token_account()
            .pubkey(Keypair::new().pubkey())
            .mint(*mint_b)
            .token_owner(keypair.pubkey())
            .create()
            .unwrap();

        // Mint tokens to user
        let amount = 1_000_000_000_000u64; // 1000 tokens with 9 decimals
        ctx.mint_to(mint_a, &token_account_a, amount, admin).unwrap();
        ctx.mint_to(mint_b, &token_account_b, amount, admin).unwrap();

        UserData {
            keypair,
            token_account_a,
            token_account_b,
        }
    }

    fn create_initial_positions(
        ctx: &mut TestContext,
        users: &[UserData],
        pool: &PoolData,
        program_id: &Pubkey,
    ) -> Vec<PositionData> {
        let mut positions = Vec::new();

        // Create positions with varying ranges around current price
        let ranges = [
            (-10, 10),   // Narrow around current price
            (-20, 20),   // Medium range
            (-5, 5),     // Very narrow
        ];

        for (user_idx, user) in users.iter().enumerate() {
            let (lower_mult, upper_mult) = ranges[user_idx % ranges.len()];
            let tick_lower_index = lower_mult * (TICK_SPACING as i32);
            let tick_upper_index = upper_mult * (TICK_SPACING as i32);

            let position_mint = Keypair::new();

            let (position, position_bump) = Pubkey::find_program_address(
                &[b"position", position_mint.pubkey().as_ref()],
                program_id,
            );

            let position_token_account = associated_token::get_associated_token_address(
                &user.keypair.pubkey(),
                &position_mint.pubkey(),
            );

            let result = ctx.program(*program_id)
                .call(instruction::OpenPosition {
                    bumps: OpenPositionBumps { position_bump },
                    tick_lower_index,
                    tick_upper_index,
                })
                .accounts(accounts::OpenPosition {
                    funder: user.keypair.pubkey(),
                    owner: user.keypair.pubkey(),
                    position,
                    position_mint: position_mint.pubkey(),
                    position_token_account,
                    whirlpool: pool.whirlpool,
                })
                .signers(&[&*user.keypair, &position_mint])
                .send();

            match result {
                Ok(TxOutcome::Success { .. }) => {
                    positions.push(PositionData {
                        position,
                        position_mint: position_mint.pubkey(),
                        position_token_account,
                        tick_lower_index,
                        tick_upper_index,
                        owner_idx: user_idx,
                        has_liquidity: false,
                    });
                    eprintln!("[SETUP] Position {} created: ticks=[{},{}]", positions.len(), tick_lower_index, tick_upper_index);
                }
                Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                    eprintln!("[SETUP] Position TX_FAILED for user {}: {:?}", user_idx, error);
                    for log in &logs { eprintln!("  {}", log); }
                    panic!("Setup failed: OpenPosition for user {}", user_idx);
                }
                Err(e) => {
                    eprintln!("[SETUP] Position SEND_FAILED for user {}: {:?}", user_idx, e);
                    panic!("Setup failed: OpenPosition for user {}", user_idx);
                }
            }
        }

        // Add initial liquidity to positions so swaps can work
        for (pos_idx, position) in positions.iter_mut().enumerate() {
            let user = &users[position.owner_idx];

            // Find tick arrays for this position
            let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
            let lower_array_start = if position.tick_lower_index >= 0 {
                (position.tick_lower_index / ticks_in_array) * ticks_in_array
            } else {
                ((position.tick_lower_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };
            let upper_array_start = if position.tick_upper_index >= 0 {
                (position.tick_upper_index / ticks_in_array) * ticks_in_array
            } else {
                ((position.tick_upper_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };

            let tick_array_lower = pool.tick_arrays.iter()
                .find(|(start, _)| *start == lower_array_start)
                .map(|(_, pk)| *pk)
                .unwrap_or(pool.tick_arrays[0].1);

            let tick_array_upper = pool.tick_arrays.iter()
                .find(|(start, _)| *start == upper_array_start)
                .map(|(_, pk)| *pk)
                .unwrap_or(pool.tick_arrays[0].1);

            let result = ctx.program(*program_id)
                .call(instruction::IncreaseLiquidity {
                    liquidity_amount: 1_000_000_000, // 1B liquidity units
                    token_max_a: u64::MAX,
                    token_max_b: u64::MAX,
                })
                .accounts(accounts::IncreaseLiquidity {
                    whirlpool: pool.whirlpool,
                    position_authority: user.keypair.pubkey(),
                    position: position.position,
                    position_token_account: position.position_token_account,
                    token_owner_account_a: user.token_account_a,
                    token_owner_account_b: user.token_account_b,
                    token_vault_a: pool.token_vault_a,
                    token_vault_b: pool.token_vault_b,
                    tick_array_lower,
                    tick_array_upper,
                })
                .signers(&[&*user.keypair])
                .send();

            match result {
                Ok(TxOutcome::Success { .. }) => {
                    position.has_liquidity = true;
                    eprintln!("[SETUP] Added initial liquidity to position {}", pos_idx);
                }
                Ok(TxOutcome::ProgramError { error, logs, .. }) => {
                    eprintln!("[SETUP] Initial liquidity TX_FAILED for position {}: {:?}", pos_idx, error);
                    for log in &logs { eprintln!("  {}", log); }
                    panic!("Setup failed: IncreaseLiquidity for position {}", pos_idx);
                }
                Err(e) => {
                    eprintln!("[SETUP] Initial liquidity SEND_FAILED for position {}: {:?}", pos_idx, e);
                    panic!("Setup failed: IncreaseLiquidity for position {}", pos_idx);
                }
            }
        }

        if positions.is_empty() {
            panic!("Setup failed: No positions were created!");
        }

        eprintln!("[SETUP] Created {} positions with liquidity", positions.len());
        positions
    }
}

// ============================================================================
// Invariant Test
// ============================================================================

#[invariant_test]
fn invariant_test(fixture: &mut WhirlpoolFixture) {
    debug_print!("[INVARIANT] swaps: {}/{}, positions: {}, liq_added: {}",
        fixture.successful_swaps, fixture.total_swaps,
        fixture.positions.len(), fixture.total_liquidity_added);

    // Check that all positions have valid tick ranges
    for (idx, position) in fixture.positions.iter().enumerate() {
        fuzz_assert_lt!(
            position.tick_lower_index, position.tick_upper_index,
            "Position {} tick range invalid: {} >= {}",
            idx, position.tick_lower_index, position.tick_upper_index
        );

        // Ticks must be multiples of tick_spacing
        fuzz_assert_eq!(
            position.tick_lower_index % (TICK_SPACING as i32), 0,
            "Position {} lower tick not aligned to tick spacing",
            idx
        );
        fuzz_assert_eq!(
            position.tick_upper_index % (TICK_SPACING as i32), 0,
            "Position {} upper tick not aligned to tick spacing",
            idx
        );

        // Ticks must be within bounds
        fuzz_assert_ge!(
            position.tick_lower_index, MIN_TICK_INDEX,
            "Position {} lower tick below min: {} < {}",
            idx, position.tick_lower_index, MIN_TICK_INDEX
        );
        fuzz_assert_le!(
            position.tick_upper_index, MAX_TICK_INDEX,
            "Position {} upper tick above max: {} > {}",
            idx, position.tick_upper_index, MAX_TICK_INDEX
        );
    }

    // Verify we have tick arrays
    fuzz_assert_ge!(
        fixture.pool.tick_arrays.len(), 3,
        "Not enough tick arrays: {}",
        fixture.pool.tick_arrays.len()
    );
}
