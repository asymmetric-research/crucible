#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("2eJW8mrzmW3Gy88VZ5oqn4qSRoTRYqQfucG69mx99F1b");

/// Stand-in for a foreign program that is *supposed* to own certain accounts (e.g. an SPL token
/// program or an oracle program). The harness creates the relevant config account with this owner.
pub const FOREIGN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0x0A; 32]);

#[program]
pub mod owner_mutation_airdrop {
    use super::*;

    // ---- CC-1 true positives: read an account's data without verifying its owner ----

    /// Program-owned config, missing owner check (the canonical bug).
    pub fn claim_airdrop(ctx: Context<ClaimAirdrop>) -> Result<()> {
        // BUG: trusts config data without verifying `config.owner == crate::ID`.
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// A second program-owned account in a different role, same missing-owner-check class.
    pub fn read_state_no_check(ctx: Context<ReadState>) -> Result<()> {
        // BUG: trusts state data without verifying `state.owner == crate::ID`.
        let amount = read_u64(&ctx.accounts.state)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Account expected to be owned by a *foreign* program (token/oracle flavor), missing check.
    pub fn read_foreign_owned_no_check(ctx: Context<ReadForeign>) -> Result<()> {
        // BUG: trusts foreign-owned data without verifying `config.owner == FOREIGN_PROGRAM_ID`.
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Tiny (<= 8 byte) config read without an owner check (exercises the relevance-gate
    /// small-account path).
    pub fn read_tiny_config_no_check(ctx: Context<ReadTiny>) -> Result<()> {
        // BUG: trusts a 4-byte config without verifying its owner.
        let amount = read_u32(&ctx.accounts.config)? as u64;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-1 negatives / edges ----

    /// Program-owned config *with* the owner check present.
    pub fn claim_with_owner_check(ctx: Context<ClaimAirdrop>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Foreign-owned config *with* the owner check present.
    pub fn read_foreign_owned_with_check(ctx: Context<ReadForeign>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &FOREIGN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Pays a fixed amount and never reads the `inert` account passed alongside. The inert
    /// account is a data account with no influence on execution, so the relevance gate must skip
    /// it instead of reporting a (non-exploitable) missing owner check.
    pub fn with_inert_account(ctx: Context<WithInert>) -> Result<()> {
        let _ = &ctx.accounts.inert; // intentionally unused
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Reads a PDA config without an owner check. The detector includes PDA-like addresses by
    /// default so closed-source and PDA-heavy programs do not silently miss this owner-check class.
    pub fn read_pda_config_no_check(ctx: Context<ReadPda>) -> Result<()> {
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Reads a *writable* config without an owner check. The account is only read, so owner mutation
    /// can still produce a conclusive finding even though the meta is writable.
    pub fn read_writable_config_no_check(ctx: Context<ReadWritable>) -> Result<()> {
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-4 true positives / negatives: signer authorization ----

    /// Pays out without verifying that the `authority` actually signed (missing signer check).
    pub fn withdraw_no_signer_check(ctx: Context<Withdraw>) -> Result<()> {
        // BUG: never checks `ctx.accounts.authority.is_signer`.
        let _ = &ctx.accounts.authority;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Same payout, but with the signer check present.
    pub fn withdraw_with_signer_check(ctx: Context<Withdraw>) -> Result<()> {
        require!(
            ctx.accounts.authority.is_signer,
            AirdropError::MissingSigner
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Two declared signers, but only `admin` is checked — `cosigner`'s signature is never
    /// enforced, so the engine must flag the co-signer (and not the admin).
    pub fn withdraw_multisig_one_unchecked(ctx: Context<WithdrawMultisig>) -> Result<()> {
        require!(ctx.accounts.admin.is_signer, AirdropError::MissingSigner);
        // BUG: never checks `ctx.accounts.cosigner.is_signer`.
        let _ = &ctx.accounts.cosigner;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }
}

fn read_u64(account: &UncheckedAccount) -> Result<u64> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 8, AirdropError::InvalidConfig);
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

fn read_u32(account: &UncheckedAccount) -> Result<u32> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 4, AirdropError::InvalidConfig);
    let amount = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

fn payout(vault: &AccountInfo, recipient: &AccountInfo, amount: u64) -> Result<()> {
    let vault_lamports = **vault.try_borrow_lamports()?;
    require!(vault_lamports >= amount, AirdropError::InsufficientVault);
    **vault.try_borrow_mut_lamports()? -= amount;
    **recipient.try_borrow_mut_lamports()? += amount;
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimAirdrop<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only config; owner deliberately unchecked in the no-check variant.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault, mutated for lamport movement.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadState<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only program-owned state; owner unchecked in the no-check variant.
    pub state: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadForeign<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only foreign-owned config; owner unchecked in the no-check variant.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTiny<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only tiny config; owner unchecked.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithInert<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only account the program never reads.
    pub inert: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadPda<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only PDA config; owner unchecked.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadWritable<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: writable config that is only read; owner unchecked.
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: payout destination.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: intended signing authority; its `is_signer` is unchecked in the no-check variant.
    pub authority: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithdrawMultisig<'info> {
    /// CHECK: payout destination.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: admin signer (its signature is checked).
    pub admin: UncheckedAccount<'info>,
    /// CHECK: co-signer whose signature is never checked (the bug).
    pub cosigner: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[error_code]
pub enum AirdropError {
    #[msg("Invalid config")]
    InvalidConfig,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient vault balance")]
    InsufficientVault,
    #[msg("Wrong owner")]
    WrongOwner,
    #[msg("Missing required signer")]
    MissingSigner,
}
