// Tick spacing for our pool (common values: 1, 8, 64, 128)
pub const TICK_SPACING: u16 = 64;

// Default fee rate (3000 = 0.30%)
pub const DEFAULT_FEE_RATE: u16 = 3000;

// Initial sqrt price for 1:1 ratio (Q64.64 format)
// sqrt(1) * 2^64 = 2^64 = 18446744073709551616
pub const INITIAL_SQRT_PRICE: u128 = 18446744073709551616;

// Tick array size (fixed at 88 ticks per array)
pub const TICK_ARRAY_SIZE: i32 = 88;

// Min/max tick from whirlpool program (src/state/tick.rs)
pub const MIN_TICK_INDEX: i32 = -443636;
pub const MAX_TICK_INDEX: i32 = 443636;

// Sqrt price bounds from whirlpool program
pub const MAX_SQRT_PRICE_X64: u128 = 79226673515401279992447579055;
pub const MIN_SQRT_PRICE_X64: u128 = 4295048016;

// Fee rate bounds from whirlpool program (math/token_math.rs)
pub const MAX_FEE_RATE: u16 = 60_000;       // 6%
pub const MAX_PROTOCOL_FEE_RATE: u16 = 2_500; // 25%

// Token-2022 program ID (for open_position_with_token_extensions, lock_position, etc.)
pub const TOKEN_2022_PROGRAM_ID: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

// Metadata update auth for position token extensions (fixed in IDL)
pub const METADATA_UPDATE_AUTH: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::from_str_const("3axbTs2z5GBy6usVbNVoqEgZMng3vZvMnAoX29BFfwhr");

// Rent sysvar (for initialize_reward_v2)
pub const RENT_SYSVAR_ID: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
