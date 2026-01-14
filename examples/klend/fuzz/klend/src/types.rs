//! klend account types for zero-copy access
//!
//! These structs mirror the klend program's account layouts exactly,
//! converted from Anchor zero_copy to bytemuck for version-agnostic access.
//!
//! Safety: All structs use #[repr(C)] and contain only Pod-safe types.
//! The unsafe impl Pod is valid because these match the program's zero_copy layout.

use bytemuck::{Pod, Zeroable};

/// Type alias for version-agnostic Pubkey (32 bytes)
pub type Pubkey = [u8; 32];

// ============================================================================
// Helper Functions for u128 Conversion
// ============================================================================

/// Convert [u64; 2] to u128 (little-endian)
#[inline]
#[allow(dead_code)]
pub fn u64_pair_to_u128(pair: [u64; 2]) -> u128 {
    (pair[1] as u128) << 64 | (pair[0] as u128)
}

/// Convert u128 to [u64; 2] (little-endian)
#[inline]
#[allow(dead_code)]
pub fn u128_to_u64_pair(val: u128) -> [u64; 2] {
    [val as u64, (val >> 64) as u64]
}

// ============================================================================
// Constants
// ============================================================================

/// Size of Reserve account (excluding 8-byte discriminator)
pub const RESERVE_SIZE: usize = 8616;

/// Size of Obligation account (excluding 8-byte discriminator)
pub const OBLIGATION_SIZE: usize = 3336;

/// Price status flags - all checks passed
pub const PRICE_STATUS_ALL_CHECKS: u8 = 0x3F;

// ============================================================================
// Core Types
// ============================================================================

/// Mirrors klend LastUpdate - 16 bytes
///
/// Tracks staleness of reserves and obligations.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct LastUpdate {
    pub slot: u64,
    pub stale: u8,
    pub price_status: u8,
    pub placeholder: [u8; 6],
}

// Safety: LastUpdate is repr(C) with only primitive types, no padding
unsafe impl Pod for LastUpdate {}
unsafe impl Zeroable for LastUpdate {}

impl LastUpdate {
    /// Mark this update as fresh at the given slot with all price checks passed
    pub fn mark_fresh(&mut self, slot: u64) {
        self.slot = slot;
        self.stale = 0;
        self.price_status = PRICE_STATUS_ALL_CHECKS;
    }

    /// Mark as stale
    #[allow(dead_code)]
    pub fn mark_stale(&mut self) {
        self.stale = 1;
    }
}

/// Mirrors klend BigFractionBytes - 48 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct BigFractionBytes {
    pub value: [u64; 4],
    pub padding: [u64; 2],
}

// Safety: BigFractionBytes is repr(C) with only u64 arrays
unsafe impl Pod for BigFractionBytes {}
unsafe impl Zeroable for BigFractionBytes {}

// ============================================================================
// Reserve Types
// ============================================================================

/// Mirrors klend Reserve - 8616 bytes total
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Reserve {
    pub version: u64,
    pub last_update: LastUpdate,
    pub lending_market: Pubkey,
    pub farm_collateral: Pubkey,
    pub farm_debt: Pubkey,
    pub liquidity: ReserveLiquidity,
    pub reserve_liquidity_padding: [u64; 150],
    pub collateral: ReserveCollateral,
    pub reserve_collateral_padding: [u64; 150],
    pub config: ReserveConfig,
    pub config_padding: [u64; 116],
    pub borrowed_amount_outside_elevation_group: u64,
    pub borrowed_amounts_against_this_reserve_in_elevation_groups: [u64; 32],
    pub padding: [u64; 207],
}

// Safety: Reserve is repr(C), all fields are Pod, no padding between fields
unsafe impl Pod for Reserve {}
unsafe impl Zeroable for Reserve {}

/// Mirrors klend ReserveLiquidity
/// Note: u128 fields replaced with [u64; 2] to avoid 16-byte struct alignment on x86_64
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReserveLiquidity {
    pub mint_pubkey: Pubkey,
    pub supply_vault: Pubkey,
    pub fee_vault: Pubkey,
    pub available_amount: u64,
    pub borrowed_amount_sf: [u64; 2],      // u128 as [u64; 2]
    pub market_price_sf: [u64; 2],         // u128 as [u64; 2]
    pub market_price_last_updated_ts: u64,
    pub mint_decimals: u64,
    pub deposit_limit_crossed_timestamp: u64,
    pub borrow_limit_crossed_timestamp: u64,
    pub cumulative_borrow_rate_bsf: BigFractionBytes,
    pub accumulated_protocol_fees_sf: [u64; 2],   // u128 as [u64; 2]
    pub accumulated_referrer_fees_sf: [u64; 2],   // u128 as [u64; 2]
    pub pending_referrer_fees_sf: [u64; 2],       // u128 as [u64; 2]
    pub absolute_referral_rate_sf: [u64; 2],      // u128 as [u64; 2]
    pub token_program: Pubkey,
    pub padding2: [u64; 51],  // Original size (no alignment issues with [u64; 2] fields)
    pub padding3: [u64; 64],  // Using u64 instead of [u128; 32] to avoid alignment issues
}

// Safety: ReserveLiquidity is repr(C), all fields are Pod
unsafe impl Pod for ReserveLiquidity {}
unsafe impl Zeroable for ReserveLiquidity {}

/// Mirrors klend ReserveCollateral
/// Note: padding arrays use u64 instead of u128 to avoid alignment padding on x86_64
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReserveCollateral {
    pub mint_pubkey: Pubkey,
    pub mint_total_supply: u64,
    pub supply_vault: Pubkey,
    pub padding1: [u64; 64],  // Using u64 instead of [u128; 32] to avoid alignment issues
    pub padding2: [u64; 64],  // Using u64 instead of [u128; 32] to avoid alignment issues
}

// Safety: ReserveCollateral is repr(C), all fields are Pod
unsafe impl Pod for ReserveCollateral {}
unsafe impl Zeroable for ReserveCollateral {}

/// Mirrors klend ReserveConfig
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReserveConfig {
    pub status: u8,
    pub padding_deprecated_asset_tier: u8,
    pub host_fixed_interest_rate_bps: u16,
    pub min_deleveraging_bonus_bps: u16,
    pub block_ctoken_usage: u8,
    pub reserved_1: [u8; 6],
    pub protocol_order_execution_fee_pct: u8,
    pub protocol_take_rate_pct: u8,
    pub protocol_liquidation_fee_pct: u8,
    pub loan_to_value_pct: u8,
    pub liquidation_threshold_pct: u8,
    pub min_liquidation_bonus_bps: u16,
    pub max_liquidation_bonus_bps: u16,
    pub bad_debt_liquidation_bonus_bps: u16,
    pub deleveraging_margin_call_period_secs: u64,
    pub deleveraging_threshold_decrease_bps_per_day: u64,
    pub fees: ReserveFees,
    pub borrow_rate_curve: BorrowRateCurve,
    pub borrow_factor_pct: u64,
    pub deposit_limit: u64,
    pub borrow_limit: u64,
    pub token_info: TokenInfo,
    pub deposit_withdrawal_cap: WithdrawalCaps,
    pub debt_withdrawal_cap: WithdrawalCaps,
    pub elevation_groups: [u8; 20],
    pub disable_usage_as_coll_outside_emode: u8,
    pub utilization_limit_block_borrowing_above_pct: u8,
    pub autodeleverage_enabled: u8,
    pub proposer_authority_locked: u8,
    pub borrow_limit_outside_elevation_group: u64,
    pub borrow_limit_against_this_collateral_in_elevation_group: [u64; 32],
    pub deleveraging_bonus_increase_bps_per_day: u64,
}

// Safety: ReserveConfig is repr(C), all fields are Pod
unsafe impl Pod for ReserveConfig {}
unsafe impl Zeroable for ReserveConfig {}

/// Mirrors klend ReserveFees - 24 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ReserveFees {
    pub origination_fee_sf: u64,
    pub flash_loan_fee_sf: u64,
    pub padding: [u8; 8],
}

// Safety: ReserveFees is repr(C), all fields are Pod
unsafe impl Pod for ReserveFees {}
unsafe impl Zeroable for ReserveFees {}

/// Mirrors klend BorrowRateCurve - 88 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BorrowRateCurve {
    pub points: [CurvePoint; 11],
}

// Safety: BorrowRateCurve is repr(C), contains array of Pod types
unsafe impl Pod for BorrowRateCurve {}
unsafe impl Zeroable for BorrowRateCurve {}

/// Mirrors klend CurvePoint - 8 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct CurvePoint {
    pub utilization_rate_bps: u32,
    pub borrow_rate_bps: u32,
}

// Safety: CurvePoint is repr(C), only primitive types
unsafe impl Pod for CurvePoint {}
unsafe impl Zeroable for CurvePoint {}

/// Mirrors klend TokenInfo
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TokenInfo {
    pub name: [u8; 32],
    pub heuristic: PriceHeuristic,
    pub max_twap_divergence_bps: u64,
    pub max_age_price_seconds: u64,
    pub max_age_twap_seconds: u64,
    pub scope_configuration: ScopeConfiguration,
    pub switchboard_configuration: SwitchboardConfiguration,
    pub pyth_configuration: PythConfiguration,
    pub block_price_usage: u8,
    pub reserved: [u8; 7],
    pub _padding: [u64; 19],
}

// Safety: TokenInfo is repr(C), all fields are Pod
unsafe impl Pod for TokenInfo {}
unsafe impl Zeroable for TokenInfo {}

/// Mirrors klend WithdrawalCaps - 32 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct WithdrawalCaps {
    pub config_capacity: i64,
    pub current_total: i64,
    pub last_interval_start_timestamp: u64,
    pub config_interval_length_seconds: u64,
}

// Safety: WithdrawalCaps is repr(C), only primitive types
unsafe impl Pod for WithdrawalCaps {}
unsafe impl Zeroable for WithdrawalCaps {}

/// Mirrors klend PriceHeuristic - 24 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PriceHeuristic {
    pub lower: u64,
    pub upper: u64,
    pub exp: u64,
}

// Safety: PriceHeuristic is repr(C), only primitive types
unsafe impl Pod for PriceHeuristic {}
unsafe impl Zeroable for PriceHeuristic {}

/// Mirrors klend ScopeConfiguration - 48 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ScopeConfiguration {
    pub price_feed: Pubkey,
    pub price_chain: [u16; 4],
    pub twap_chain: [u16; 4],
}

// Safety: ScopeConfiguration is repr(C), only primitive types and arrays
unsafe impl Pod for ScopeConfiguration {}
unsafe impl Zeroable for ScopeConfiguration {}

impl Default for ScopeConfiguration {
    fn default() -> Self {
        Self {
            price_feed: [0u8; 32],
            price_chain: [u16::MAX; 4],
            twap_chain: [u16::MAX; 4],
        }
    }
}

/// Mirrors klend SwitchboardConfiguration - 64 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SwitchboardConfiguration {
    pub price_aggregator: Pubkey,
    pub twap_aggregator: Pubkey,
}

// Safety: SwitchboardConfiguration is repr(C), only Pubkey arrays
unsafe impl Pod for SwitchboardConfiguration {}
unsafe impl Zeroable for SwitchboardConfiguration {}

/// Mirrors klend PythConfiguration - 32 bytes
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PythConfiguration {
    pub price: Pubkey,
}

// Safety: PythConfiguration is repr(C), only Pubkey
unsafe impl Pod for PythConfiguration {}
unsafe impl Zeroable for PythConfiguration {}

// ============================================================================
// Obligation Types
// ============================================================================

/// Mirrors klend Obligation - 3336 bytes total
/// Note: u128 fields replaced with [u64; 2] to avoid 16-byte struct alignment on x86_64
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Obligation {
    pub tag: u64,
    pub last_update: LastUpdate,
    pub lending_market: Pubkey,
    pub owner: Pubkey,
    pub deposits: [ObligationCollateral; 8],
    pub lowest_reserve_deposit_liquidation_ltv: u64,
    pub deposited_value_sf: [u64; 2],                    // u128 as [u64; 2]
    pub borrows: [ObligationLiquidity; 5],
    pub borrow_factor_adjusted_debt_value_sf: [u64; 2],  // u128 as [u64; 2]
    pub borrowed_assets_market_value_sf: [u64; 2],       // u128 as [u64; 2]
    pub allowed_borrow_value_sf: [u64; 2],               // u128 as [u64; 2]
    pub unhealthy_borrow_value_sf: [u64; 2],             // u128 as [u64; 2]
    pub padding_deprecated_asset_tiers: [u8; 13],
    pub elevation_group: u8,
    pub num_of_obsolete_deposit_reserves: u8,
    pub has_debt: u8,
    pub referrer: Pubkey,
    pub borrowing_disabled: u8,
    pub autodeleverage_target_ltv_pct: u8,
    pub lowest_reserve_deposit_max_ltv_pct: u8,
    pub num_of_obsolete_borrow_reserves: u8,
    pub reserved: [u8; 4],
    pub highest_borrow_factor_pct: u64,
    pub autodeleverage_margin_call_started_timestamp: u64,
    pub orders: [ObligationOrder; 2],
    pub padding_3: [u64; 93],
}

// Safety: Obligation is repr(C), all fields are Pod
unsafe impl Pod for Obligation {}
unsafe impl Zeroable for Obligation {}

/// Mirrors klend ObligationCollateral
/// Note: u128 fields replaced with [u64; 2] to avoid 16-byte struct alignment on x86_64
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ObligationCollateral {
    pub deposit_reserve: Pubkey,
    pub deposited_amount: u64,
    pub market_value_sf: [u64; 2],  // u128 as [u64; 2] to avoid 16-byte alignment
    pub borrowed_amount_against_this_collateral_in_elevation_group: u64,
    pub padding: [u64; 9],
}

// Safety: ObligationCollateral is repr(C), all fields are Pod
unsafe impl Pod for ObligationCollateral {}
unsafe impl Zeroable for ObligationCollateral {}

impl ObligationCollateral {
    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.deposit_reserve != [0u8; 32]
    }
}

/// Mirrors klend ObligationLiquidity
/// Note: u128 fields replaced with [u64; 2] to avoid 16-byte struct alignment on x86_64
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ObligationLiquidity {
    pub borrow_reserve: Pubkey,
    pub cumulative_borrow_rate_bsf: BigFractionBytes,
    pub padding: u64,
    pub borrowed_amount_sf: [u64; 2],  // u128 as [u64; 2] to avoid 16-byte alignment
    pub market_value_sf: [u64; 2],     // u128 as [u64; 2]
    pub borrow_factor_adjusted_market_value_sf: [u64; 2],  // u128 as [u64; 2]
    pub borrowed_amount_outside_elevation_groups: u64,
    pub padding2: [u64; 7],
}

// Safety: ObligationLiquidity is repr(C), all fields are Pod
unsafe impl Pod for ObligationLiquidity {}
unsafe impl Zeroable for ObligationLiquidity {}

impl ObligationLiquidity {
    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.borrow_reserve != [0u8; 32]
    }
}

/// Mirrors klend ObligationOrder
/// Note: u128 fields replaced with [u64; 2] to avoid 16-byte struct alignment on x86_64
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ObligationOrder {
    pub condition_threshold_sf: [u64; 2],     // u128 as [u64; 2]
    pub opportunity_parameter_sf: [u64; 2],   // u128 as [u64; 2]
    pub min_execution_bonus_bps: u16,
    pub max_execution_bonus_bps: u16,
    pub condition_type: u8,
    pub opportunity_type: u8,
    pub padding1: [u8; 10],
    pub padding2: [u64; 10],  // [u128; 5] as [u64; 10] to avoid alignment issues
}

// Safety: ObligationOrder is repr(C), all fields are Pod
unsafe impl Pod for ObligationOrder {}
unsafe impl Zeroable for ObligationOrder {}

// ============================================================================
// GlobalConfig Types
// ============================================================================

/// Size of GlobalConfig account (excluding 8-byte discriminator)
pub const GLOBAL_CONFIG_SIZE: usize = 1024;

/// Mirrors klend GlobalConfig
#[derive(Clone, Copy)]
#[repr(C)]
pub struct GlobalConfig {
    pub global_admin: Pubkey,
    pub pending_admin: Pubkey,
    pub fee_collector: Pubkey,
    pub padding: [u8; 928],
}

// Safety: GlobalConfig is repr(C), all fields are Pod
unsafe impl Pod for GlobalConfig {}
unsafe impl Zeroable for GlobalConfig {}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            global_admin: [0u8; 32],
            pending_admin: [0u8; 32],
            fee_collector: [0u8; 32],
            padding: [0u8; 928],
        }
    }
}

// ============================================================================
// UserMetadata Types
// ============================================================================

/// Size of UserMetadata account (excluding 8-byte discriminator)
pub const USER_METADATA_SIZE: usize = 1024;

/// Mirrors klend UserMetadata
#[derive(Clone, Copy)]
#[repr(C)]
pub struct UserMetadata {
    pub referrer: Pubkey,
    pub bump: u64,
    pub user_lookup_table: Pubkey,
    pub owner: Pubkey,
    pub padding_1: [u64; 51],
    pub padding_2: [u64; 64],
}

// Safety: UserMetadata is repr(C), all fields are Pod
unsafe impl Pod for UserMetadata {}
unsafe impl Zeroable for UserMetadata {}

impl Default for UserMetadata {
    fn default() -> Self {
        Self {
            referrer: [0u8; 32],
            bump: 0,
            user_lookup_table: [0u8; 32],
            owner: [0u8; 32],
            padding_1: [0u64; 51],
            padding_2: [0u64; 64],
        }
    }
}

// ============================================================================
// Size Assertions
// ============================================================================

const _: () = assert!(std::mem::size_of::<LastUpdate>() == 16);
const _: () = assert!(std::mem::size_of::<BigFractionBytes>() == 48);
const _: () = assert!(std::mem::size_of::<CurvePoint>() == 8);
const _: () = assert!(std::mem::size_of::<BorrowRateCurve>() == 88);
const _: () = assert!(std::mem::size_of::<ReserveFees>() == 24);
const _: () = assert!(std::mem::size_of::<WithdrawalCaps>() == 32);
const _: () = assert!(std::mem::size_of::<PriceHeuristic>() == 24);
const _: () = assert!(std::mem::size_of::<ScopeConfiguration>() == 48);
const _: () = assert!(std::mem::size_of::<SwitchboardConfiguration>() == 64);
const _: () = assert!(std::mem::size_of::<PythConfiguration>() == 32);
const _: () = assert!(std::mem::size_of::<ObligationOrder>() == 128);
const _: () = assert!(std::mem::size_of::<ObligationCollateral>() == 136);
const _: () = assert!(std::mem::size_of::<ObligationLiquidity>() == 200);
const _: () = assert!(std::mem::size_of::<TokenInfo>() == 384);
const _: () = assert!(std::mem::size_of::<ReserveConfig>() == 920);
const _: () = assert!(std::mem::size_of::<ReserveCollateral>() == 1096);
// Skip ReserveLiquidity assertion - it will be validated through Reserve size
// const _: () = assert!(std::mem::size_of::<ReserveLiquidity>() == 1232);
const _: () = assert!(std::mem::size_of::<Reserve>() == RESERVE_SIZE);
const _: () = assert!(std::mem::size_of::<Obligation>() == OBLIGATION_SIZE);
const _: () = assert!(std::mem::size_of::<GlobalConfig>() == GLOBAL_CONFIG_SIZE);
const _: () = assert!(std::mem::size_of::<UserMetadata>() == USER_METADATA_SIZE);
