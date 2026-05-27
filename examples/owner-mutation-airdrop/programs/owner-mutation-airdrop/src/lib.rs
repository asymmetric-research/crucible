#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("2eJW8mrzmW3Gy88VZ5oqn4qSRoTRYqQfucG69mx99F1b");

#[program]
pub mod owner_mutation_airdrop {
    use super::*;

    pub fn claim_airdrop(ctx: Context<ClaimAirdrop>) -> Result<()> {
        let config_data = ctx.accounts.config.try_borrow_data()?;
        require!(config_data.len() >= 8, AirdropError::InvalidConfig);

        // BUG: this should verify that `config.owner == crate::ID` before
        // trusting config data.
        let amount = u64::from_le_bytes(config_data[0..8].try_into().unwrap());
        require!(amount > 0, AirdropError::InvalidAmount);

        let vault_lamports = **ctx.accounts.vault.to_account_info().try_borrow_lamports()?;
        require!(vault_lamports >= amount, AirdropError::InsufficientVault);

        **ctx
            .accounts
            .vault
            .to_account_info()
            .try_borrow_mut_lamports()? -= amount;
        **ctx
            .accounts
            .recipient
            .to_account_info()
            .try_borrow_mut_lamports()? += amount;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClaimAirdrop<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,

    /// CHECK: Intentionally unchecked for the owner-mutation e2e regression.
    pub config: UncheckedAccount<'info>,

    /// CHECK: Test vault account. It is program-owned in setup.
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
}
