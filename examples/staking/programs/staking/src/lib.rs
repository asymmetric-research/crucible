#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use anchor_lang::prelude::program::invoke;
use anchor_lang::system_program::{transfer, Transfer};

declare_id!("Stake11111111111111111111111111111111111111");

#[program]
pub mod staking_pool {
    use super::*;
    
    pub fn initialize_pool(ctx: Context<InitializePool>, reward_rate_per_slot: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_staked = 0;
        pool.reward_rate_per_slot = reward_rate_per_slot;
        pool.last_update_slot = Clock::get()?.slot;
        pool.accumulated_rewards_per_share = 0;
        Ok(())
    }
    
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        user.owner = ctx.accounts.staker.key();
        user.staked_amount = 0;
        user.reward_debt = 0;
        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        require!(amount > 0, StakingError::InvalidAmount);
        
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;
       
        update_pool(pool)?;
        
        // Calculate pending rewards
        if user.staked_amount > 0 {
            let pending = (user.staked_amount as u128)
                .saturating_mul(pool.accumulated_rewards_per_share)
                .saturating_div(1_000_000_000)
                .saturating_sub(user.reward_debt as u128) as u64;
            
            if pending > 0 {
                **pool.to_account_info().try_borrow_mut_lamports()? -= pending;
                **ctx.accounts.staker.to_account_info().try_borrow_mut_lamports()? += pending;
            }
        }
        
        // FIX: Use invoke to transfer SOL from staker to pool
        invoke(
            &system_instruction::transfer(
                &ctx.accounts.staker.key(),
                &pool.key(),
                amount,
            ),
            &[
                ctx.accounts.staker.to_account_info(),
                pool.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        
        
        // BUG: reward_debt calculation uses old staked_amount
        user.reward_debt = ((user.staked_amount as u128)
            .saturating_mul(pool.accumulated_rewards_per_share)
            .saturating_div(1_000_000_000)) as u64;

        user.staked_amount += amount;
        pool.total_staked += amount;
        
        Ok(())
    }
    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        require!(amount > 0, StakingError::InvalidAmount);
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;
        
        require!(user.staked_amount >= amount, StakingError::InsufficientStake);
        
        update_pool(pool)?;
        
        let pending = (user.staked_amount as u128)
            .saturating_mul(pool.accumulated_rewards_per_share)
            .saturating_div(1_000_000_000)
            .saturating_sub(user.reward_debt as u128) as u64;
        
        if pending > 0 {
            **pool.to_account_info().try_borrow_mut_lamports()? -= pending;
            **ctx.accounts.staker.to_account_info().try_borrow_mut_lamports()? += pending;
        }
        
        user.staked_amount -= amount;
        pool.total_staked -= amount;
        
        // FIX: Use invoke to transfer SOL from pool to staker
        invoke(
            &system_instruction::transfer(
                &pool.key(),
                &ctx.accounts.staker.key(),
                amount,
            ),
            &[
                pool.to_account_info(),
                ctx.accounts.staker.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        
        user.reward_debt = (user.staked_amount as u128)
            .saturating_mul(pool.accumulated_rewards_per_share)
            .saturating_div(1_000_000_000) as u64;
        
        Ok(())
    }
    
    
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_account;
        
        update_pool(pool)?;
        
        let pending = (user.staked_amount as u128)
            .saturating_mul(pool.accumulated_rewards_per_share)
            .saturating_div(1_000_000_000)
            .saturating_sub(user.reward_debt as u128) as u64;
        
        require!(pending > 0, StakingError::NoRewards);
        
        **pool.to_account_info().try_borrow_mut_lamports()? -= pending;
        **ctx.accounts.staker.to_account_info().try_borrow_mut_lamports()? += pending;
        
        user.reward_debt = (user.staked_amount as u128)
            .saturating_mul(pool.accumulated_rewards_per_share)
            .saturating_div(1_000_000_000) as u64;
        
        Ok(())
    }
    
    pub fn fund_rewards(ctx: Context<FundRewards>, amount: u64) -> Result<()> {
        **ctx.accounts.funder.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.pool.to_account_info().try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

fn update_pool(pool: &mut Pool) -> Result<()> {
    let current_slot = Clock::get()?.slot;
    
    if pool.total_staked == 0 {
        pool.last_update_slot = current_slot;
        return Ok(());
    }
    
    let slots_elapsed = current_slot.saturating_sub(pool.last_update_slot);
    let rewards = pool.reward_rate_per_slot.saturating_mul(slots_elapsed);
    let rewards_per_share = (rewards as u128)
        .saturating_mul(1_000_000_000)
        .saturating_div(pool.total_staked as u128);
    
    pool.accumulated_rewards_per_share = pool.accumulated_rewards_per_share.saturating_add(rewards_per_share);
    pool.last_update_slot = current_slot;
    
    Ok(())
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(init, payer = payer, space = 8 + Pool::INIT_SPACE, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeUser<'info> {
    #[account(init, payer = staker, space = 8 + UserAccount::INIT_SPACE, seeds = [b"user", staker.key().as_ref()], bump)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub staker: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"user", staker.key().as_ref()], bump)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub staker: Signer<'info>,
    pub system_program: Program<'info, System>, 
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"user", staker.key().as_ref()], bump)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub staker: Signer<'info>,
    pub system_program: Program<'info, System>,  
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut, seeds = [b"user", staker.key().as_ref()], bump)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct FundRewards<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub funder: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub total_staked: u64,
    pub reward_rate_per_slot: u64,
    pub last_update_slot: u64,
    pub accumulated_rewards_per_share: u128,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub staked_amount: u64,
    pub reward_debt: u64,
}

#[error_code]
pub enum StakingError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient stake")]
    InsufficientStake,
    #[msg("No rewards")]
    NoRewards,
}
