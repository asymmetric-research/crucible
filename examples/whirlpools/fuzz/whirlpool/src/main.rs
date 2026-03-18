use crucible_fuzzer::*;
use crucible_test_context::TxOutcome;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;

use crucible_fuzzer::anchor_spl::associated_token;

// Generate types from IDL (no crate dependency - avoids version conflicts)
crucible_idl_gen::declare_fuzz_program!("idls/whirlpool.json");

use whirlpool::instruction;
use whirlpool::accounts;
use whirlpool::types::{WhirlpoolBumps, OpenPositionBumps};

// ============================================================================
// Modules
// ============================================================================

mod action_stats;
pub mod keypair;
pub mod types;
pub mod constants;
pub mod math;
pub mod helpers;
mod setup;

pub use types::*;
pub use constants::*;
pub use math::*;
pub use keypair::*;

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
// Fixture + Actions
// ============================================================================

#[fuzz_fixture]
impl WhirlpoolFixture {
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = whirlpool::ID;

        // Load program binary (built separately from fuzz harness)
        ctx.add_program(&program_id, "../../whirlpool.so").unwrap();

        setup::initialize_state(&mut ctx, &program_id)
    }

    include!("actions/swaps.rs");
    include!("actions/positions.rs");
    include!("actions/liquidity.rs");
    include!("actions/fees.rs");
    include!("actions/rewards.rs");
    include!("actions/two_hop.rs");
    include!("actions/config.rs");
    include!("actions/pool_two.rs");
    include!("actions/pool_three.rs");
    include!("actions/stress.rs");
}

// ============================================================================
// Invariant Test (from invariants.rs — 284 assertions)
// ============================================================================

include!("invariants.rs");
