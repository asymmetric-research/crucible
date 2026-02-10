//! Simple counter program for fuzz testing
//!
//! This is a minimal Anchor program used for:
//! - Performance regression tests (fast compile, deterministic behavior)
//! - CLI integration tests
//! - Unit test fixtures

use anchor_lang::prelude::*;

declare_id!("TestProg1111111111111111111111111111111111");

#[program]
pub mod test_program {
    use super::*;

    /// Initialize a new counter account
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = 0;
        counter.bump = ctx.bumps.counter;
        Ok(())
    }

    /// Increment the counter by 1
    pub fn increment(ctx: Context<Mutate>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = counter.count.checked_add(1).ok_or(ErrorCode::Overflow)?;
        Ok(())
    }

    /// Decrement the counter by 1
    pub fn decrement(ctx: Context<Mutate>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = counter.count.checked_sub(1).ok_or(ErrorCode::Underflow)?;
        Ok(())
    }

    /// Add a specific amount to the counter
    pub fn add(ctx: Context<Mutate>, amount: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = counter.count.checked_add(amount).ok_or(ErrorCode::Overflow)?;
        Ok(())
    }

    /// Subtract a specific amount from the counter
    pub fn sub(ctx: Context<Mutate>, amount: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = counter.count.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
        Ok(())
    }

    /// Reset the counter to zero
    pub fn reset(ctx: Context<Mutate>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = 0;
        Ok(())
    }

    /// Set the counter to a specific value (for testing edge cases)
    pub fn set(ctx: Context<Mutate>, value: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = 8 + Counter::INIT_SPACE,
        seeds = [b"counter", payer.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, Counter>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Mutate<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump
    )]
    pub counter: Account<'info, Counter>,
}

#[account]
#[derive(InitSpace)]
pub struct Counter {
    pub count: u64,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Counter overflow")]
    Overflow,
    #[msg("Counter underflow")]
    Underflow,
}
