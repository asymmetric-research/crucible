//! Compatibility utilities for converting between different Solana SDK versions.
//!
//! This module provides conversion functions between types from different versions
//! of the Solana SDK crates that are used by anchor-lang (v4.x types) and other
//! dependencies like spl-token-2022 and pyth-solana-receiver-sdk (v3.x types).
//!
//! The types are structurally identical (32-byte arrays) but Rust treats them as
//! different types because they come from different crate versions.

use anchor_lang::prelude::{Clock, Pubkey};

/// The Clock type from older solana-clock v2.2.2 (used by pyth-sdk)
pub use solana_clock_legacy::Clock as LegacyClock;

/// Get the pyth-solana-receiver-sdk program ID as an anchor Pubkey
///
/// This converts from pyth SDK's Pubkey type to anchor's Pubkey via byte conversion.
pub fn pyth_receiver_id() -> Pubkey {
    Pubkey::from(pyth_solana_receiver_sdk::id().to_bytes())
}

/// Get the pyth push oracle program ID as an anchor Pubkey
pub fn pyth_push_oracle_id() -> Pubkey {
    Pubkey::from(pyth_solana_receiver_sdk::PYTH_PUSH_ORACLE_ID.to_bytes())
}

/// Compare an anchor Pubkey (Address) with a pyth SDK Pubkey for equality
///
/// Uses byte comparison since the types are from different crate versions.
#[inline]
pub fn eq_pyth_id(anchor_pubkey: &Pubkey) -> bool {
    anchor_pubkey.to_bytes() == pyth_solana_receiver_sdk::id().to_bytes()
}

/// Compare an anchor Pubkey (Address) with a given 32-byte key for equality
#[inline]
pub fn eq_bytes(anchor_pubkey: &Pubkey, bytes: &[u8; 32]) -> bool {
    anchor_pubkey.to_bytes() == *bytes
}

/// Convert anchor's Clock to the legacy Clock type expected by pyth SDK
///
/// Both Clock types have the same fields, just from different crate versions.
pub fn to_legacy_clock(clock: &Clock) -> LegacyClock {
    LegacyClock {
        slot: clock.slot,
        epoch_start_timestamp: clock.epoch_start_timestamp,
        epoch: clock.epoch,
        leader_schedule_epoch: clock.leader_schedule_epoch,
        unix_timestamp: clock.unix_timestamp,
    }
}

/// Deserialize PriceUpdateV2 using pyth SDK's compatible anchor-lang
///
/// The pyth SDK uses borsh 0.10 which is incompatible with our local anchor's borsh 1.x.
/// This function uses the crates.io anchor-lang to properly deserialize.
pub fn deserialize_price_update_v2(
    data: &[u8],
) -> Result<pyth_solana_receiver_sdk::price_update::PriceUpdateV2, anchor_lang::error::Error> {
    use anchor_lang_pyth::AccountDeserialize;
    pyth_solana_receiver_sdk::price_update::PriceUpdateV2::try_deserialize(&mut &*data)
        .map_err(|_| anchor_lang::error::Error::from(anchor_lang::error::ErrorCode::AccountDidNotDeserialize))
}

use anchor_lang::prelude::AccountInfo;

/// Wrapper for spl_token_2022::onchain::invoke_transfer_checked that handles type conversions.
///
/// This function works around the type incompatibility between our local anchor-lang
/// (using solana types v3.1+) and spl-token-2022 (using solana types v3.0).
/// Uses anchor_spl's re-export of spl_token_2022 for compatible types.
pub fn invoke_transfer_checked_compat<'info>(
    token_program_key: &Pubkey,
    from: AccountInfo<'info>,
    mint_info: AccountInfo<'info>,
    to: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    additional_accounts: &[AccountInfo<'info>],
    amount: u64,
    decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> anchor_lang::Result<()> {
    use anchor_lang::solana_program::program::invoke_signed;
    use anchor_spl::token_2022::spl_token_2022;

    // Create the transfer_checked instruction
    let ix = spl_token_2022::instruction::transfer_checked(
        token_program_key,
        from.key,
        mint_info.key,
        to.key,
        authority.key,
        &[], // multisig_signers - not used
        amount,
        decimals,
    )?;

    // Build account infos for invocation - include additional accounts for transfer hooks
    let mut account_infos = vec![from, mint_info.clone(), to, authority];
    account_infos.extend(additional_accounts.iter().cloned());

    // Invoke with proper signer seeds
    invoke_signed(&ix, &account_infos, signer_seeds).map_err(Into::into)
}
