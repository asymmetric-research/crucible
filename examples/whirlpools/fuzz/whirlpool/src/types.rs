use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use std::rc::Rc;

#[derive(Clone)]
pub struct PoolData {
    pub whirlpool: Pubkey,
    pub token_mint_a: Pubkey,
    pub token_mint_b: Pubkey,
    pub token_vault_a: Pubkey,
    pub token_vault_b: Pubkey,
    pub tick_arrays: Vec<(i32, Pubkey)>,  // (start_tick_index, pubkey)
    pub oracle: Pubkey,
    pub reward_mints: Vec<Pubkey>,
    pub reward_vaults: Vec<Pubkey>,
    pub reward_initialized: [bool; 3],
}

#[derive(Clone)]
pub struct BundleData {
    pub position_bundle: Pubkey,
    pub position_bundle_mint: Pubkey,
    pub position_bundle_token_account: Pubkey,
    pub owner_idx: usize,
    pub open_bundle_indices: Vec<u16>,  // Which 0-255 slots are open
}

#[derive(Clone)]
pub struct BundlePositionInfo {
    pub bundle_idx: usize,     // Index into fixture.bundles
    pub bundle_index: u16,     // 0-255 slot in the bundle
}

#[derive(Clone)]
pub struct PositionData {
    pub position: Pubkey,
    pub position_mint: Pubkey,
    pub position_token_account: Pubkey,
    pub tick_lower_index: i32,
    pub tick_upper_index: i32,
    pub owner_idx: usize,
    pub has_liquidity: bool,
    pub bundle_info: Option<BundlePositionInfo>,  // None for regular positions
    /// Previous fee_owed values for monotonicity tracking (detects wrapping_add overflow)
    pub prev_fee_owed_a: u64,
    pub prev_fee_owed_b: u64,
    /// Set true after collect_fees, cleared in invariant check
    pub fees_just_collected: bool,
}

#[derive(Clone)]
pub struct UserData {
    pub keypair: Rc<Keypair>,
    pub token_account_a: Pubkey,
    pub token_account_b: Pubkey,
    pub token_account_c: Pubkey,
    pub token_account_d: Pubkey,
    pub reward_accounts: Vec<Pubkey>,
}

#[derive(Clone)]
pub struct WhirlpoolFixture {
    pub ctx: TestContext,
    pub program_id: Pubkey,
    pub admin: Rc<Keypair>,
    pub config: Pubkey,
    #[allow(dead_code)]
    pub fee_tier: Pubkey,
    pub pool: PoolData,
    /// Second pool for TwoHopSwap (shares token_mint_b with pool one as the intermediary)
    /// Pool two trades: token_mint_b (pool one's B) vs token_mint_c (a third mint)
    pub pool_two: Option<PoolData>,
    pub token_mint_c: Pubkey,
    pub users: Vec<UserData>,
    pub positions: Vec<PositionData>,
    pub bundles: Vec<BundleData>,
    /// Current fee authority (may change via SetFeeAuthority)
    pub fee_authority: Rc<Keypair>,
    /// Current collect-protocol-fees authority
    pub collect_protocol_fees_authority: Rc<Keypair>,
    /// Current reward emissions super authority
    pub reward_emissions_super_authority: Rc<Keypair>,
    // Tracking for invariants
    pub total_liquidity_added: u128,
    pub total_swaps: u64,
    pub successful_swaps: u64,
    pub initial_total_token_a: u64,
    pub initial_total_token_b: u64,
    pub initial_total_token_c: u64,
    pub prev_fee_growth_global_a: u128,
    pub prev_fee_growth_global_b: u128,
    pub prev_reward_growths: [u128; 3],
    pub prev_tick_current: i32,
    pub prev_sqrt_price_val: u128,
    pub prev_reward_timestamp: u64,
    pub prev_p2_fee_growth_a: u128,
    pub prev_p2_fee_growth_b: u128,
    pub prev_p1_zero_liquidity: bool,
    pub prev_p2_zero_liquidity: bool,
    pub prev_protocol_fee_owed_a: u64,
    pub prev_protocol_fee_owed_b: u64,
    pub protocol_fees_just_collected: bool,
    /// Config extension PDA (None until initialized)
    pub config_extension: Option<Pubkey>,
    /// Authority for config extension operations
    pub config_extension_authority: Rc<Keypair>,
    /// Token badge authority (initially fee_authority when config_extension is created)
    pub token_badge_authority: Rc<Keypair>,
    /// Token badges created: (token_mint, token_badge_pubkey)
    pub token_badges: Vec<(Pubkey, Pubkey)>,
    /// Whether TOKEN_BADGE feature flag is enabled on config
    pub token_badge_feature_enabled: bool,
    /// Positions on pool two (tracked separately from pool one positions)
    pub pool_two_positions: Vec<PositionData>,
    /// Fourth token mint for pool three
    pub mint_d: Pubkey,
    /// Third pool: adaptive fee pool (mint_a/mint_d)
    pub pool_three: Option<PoolData>,
    /// Positions on pool three
    pub pool_three_positions: Vec<PositionData>,
    /// Adaptive fee tier PDA
    pub adaptive_fee_tier: Option<Pubkey>,
    /// Adaptive fee tier index (128)
    pub adaptive_fee_tier_index: u16,
    /// Delegated fee authority for pool three
    pub delegated_fee_authority: Rc<Keypair>,
    /// Pool three invariant tracking
    pub prev_p3_fee_growth_global_a: u128,
    pub prev_p3_fee_growth_global_b: u128,
    pub prev_p3_sqrt_price_val: u128,
    pub prev_p3_tick_current: i32,
    pub prev_p3_zero_liquidity: bool,
    /// Pool two reward growth tracking
    pub prev_p2_reward_growths: [u128; 3],
    pub prev_p2_reward_timestamp: u64,
    /// Pool three reward growth tracking
    pub prev_p3_reward_growths: [u128; 3],
    pub prev_p3_reward_timestamp: u64,
    /// Dynamic tick arrays: (pubkey, start_tick_index)
    pub dynamic_tick_arrays: Vec<(Pubkey, i32)>,
    /// Pool two invariant tracking
    pub prev_p2_tick_current: i32,
    pub prev_p2_sqrt_price_val: u128,
    pub prev_p2_protocol_fee_owed_a: u64,
    pub prev_p2_protocol_fee_owed_b: u64,
    pub p2_protocol_fees_just_collected: bool,
    /// Initial total token D balance for conservation
    pub initial_total_token_d: u64,
    /// Expected fee_rate for pool one (tracks SetFeeRate mutations)
    pub expected_fee_rate: u16,
    /// Pool three protocol fee tracking
    pub prev_p3_protocol_fee_owed_a: u64,
    pub prev_p3_protocol_fee_owed_b: u64,
    pub p3_protocol_fees_just_collected: bool,
    /// Pool three adaptive fee constants snapshot (should be immutable)
    pub p3_adaptive_fee_constants_snapshot: Option<[u8; 34]>,
    /// Pool three oracle timestamp tracking (for monotonicity)
    pub prev_p3_oracle_last_ref_update_ts: u64,
    pub prev_p3_oracle_last_major_swap_ts: u64,
}
