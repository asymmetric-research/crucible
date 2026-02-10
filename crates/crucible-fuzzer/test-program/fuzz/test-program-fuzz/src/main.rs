//! Fuzz harness using staking program for e2e testing
//!
//! This is a copy of the staking example harness, used for CLI e2e tests.

use staking::*;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use crucible_fuzzer::anchor_lang::system_program;
use std::rc::Rc;

const INITIAL_BALANCE: u64 = 100_000_000_000;
const REWARD_RATE: u64 = 1000;

#[derive(Clone)]
struct User {
    keypair: Rc<Keypair>,
    user_pda: Pubkey,
    initial_balance: u64,
    stake_time: u128,
    last_update_slot: u64,
}

#[derive(Clone)]
struct StakingFixture {
    ctx: TestContext,
    pool_pda: Pubkey,
    program_id: Pubkey,
    users: Vec<User>,
    funder: Rc<Keypair>,
}

#[fuzz_fixture]
impl StakingFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());

        // Load program - path relative to test-program-fuzz directory
        ctx.add_program(&program_id, "../../../../../examples/staking/target/deploy/staking.so").unwrap();

        let (pool_pda, _) = Pubkey::find_program_address(&[b"pool"], &program_id);
        let current_slot = ctx.slot();

        // Create users
        let mut users = Vec::new();
        for _i in 0..3 {
            let keypair = Rc::new(Keypair::new());

            ctx.create_account()
                .pubkey(keypair.pubkey())
                .lamports(INITIAL_BALANCE)
                .owner(system_program::ID)
                .create()
                .unwrap();

            let (user_pda, _) = Pubkey::find_program_address(&[b"user", keypair.pubkey().as_ref()], &program_id);
            users.push(User {
                keypair,
                user_pda,
                initial_balance: INITIAL_BALANCE,
                stake_time: 0,
                last_update_slot: current_slot,
            });
        }

        // Create funder
        let funder = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(funder.pubkey())
            .lamports(1_000_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // Initialize pool
        ctx.program(program_id)
            .call(instruction::InitializePool { reward_rate_per_slot: REWARD_RATE })
            .accounts(accounts::InitializePool {
                pool: pool_pda,
                payer: users[0].keypair.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*users[0].keypair])
            .send()
            .unwrap();

        // Initialize all users
        for user in &users {
            ctx.program(program_id)
                .call(instruction::InitializeUser {})
                .accounts(accounts::InitializeUser {
                    user_account: user.user_pda,
                    staker: user.keypair.pubkey(),
                    system_program: system_program::ID,
                })
                .signers(&[&*user.keypair])
                .send()
                .unwrap();
        }

        // Fund rewards
        ctx.program(program_id)
            .call(instruction::FundRewards { amount: 100_000_000_000 })
            .accounts(accounts::FundRewards { pool: pool_pda, funder: funder.pubkey() })
            .signers(&[&*funder])
            .send()
            .unwrap();

        Self { ctx, pool_pda, program_id, users, funder }
    }

    fn update_user_stake_time(&mut self, user_idx: usize) {
        let current_slot = self.ctx.slot();
        let user = &mut self.users[user_idx];

        if let Ok(user_account) = self.ctx.read_anchor_account::<UserAccount>(&user.user_pda) {
            let slots_elapsed = current_slot.saturating_sub(user.last_update_slot);
            let stake_time_delta = (user_account.staked_amount as u128) * (slots_elapsed as u128);
            user.stake_time += stake_time_delta;
        }

        user.last_update_slot = current_slot;
    }

    pub fn action_stake(&mut self, #[range(0..3)] user_idx: usize, #[range(0..50_000_000_000)] amount: u64) -> bool {
        self.update_user_stake_time(user_idx);
        let user = &self.users[user_idx];
        let balance = self.ctx.get_account(&user.keypair.pubkey()).unwrap().lamports;
        let safe_amount = amount.min(balance.saturating_sub(10_000_000));

        self.ctx.program(self.program_id)
            .call(instruction::Stake { amount: safe_amount })
            .accounts(accounts::Stake {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*user.keypair])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_unstake(&mut self, #[range(0..3)] user_idx: usize, #[range(0..50_000_000_000)] amount: u64) -> bool {
        self.update_user_stake_time(user_idx);
        let user = &self.users[user_idx];
        if self.ctx.get_account(&user.user_pda).is_err() { return false; }

        let user_account = self.ctx.read_anchor_account::<UserAccount>(&user.user_pda).unwrap();
        let safe_amount = amount.min(user_account.staked_amount);
        if safe_amount == 0 { return false; }

        self.ctx.program(self.program_id)
            .call(instruction::Unstake { amount: safe_amount })
            .accounts(accounts::Unstake {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*user.keypair])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_claim(&mut self, #[range(0..3)] user_idx: usize) -> bool {
        self.update_user_stake_time(user_idx);

        let user = &self.users[user_idx];
        if self.ctx.get_account(&user.user_pda).is_err() { return false; }

        self.ctx.program(self.program_id)
            .call(instruction::ClaimRewards {})
            .accounts(accounts::ClaimRewards {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
            })
            .signers(&[&*user.keypair])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_advance_slots(&mut self, #[range(0..10000)] slots: u64) -> bool {
        for i in 0..self.users.len() {
            self.update_user_stake_time(i);
        }

        let new_slot = self.ctx.slot() + slots;
        self.ctx.warp_to_slot(new_slot);
        true
    }
}

/// Invariant: users should not receive more rewards than their proportional stake-time
/// The staking program has a known bug (reward_debt calculated with old staked_amount)
#[invariant_test]
fn invariant_test(fixture: &mut StakingFixture) {
    let current_slot = fixture.ctx.slot();

    let mut total_stake_time = 0u128;
    for user in &fixture.users {
        if let Ok(user_account) = fixture.ctx.read_anchor_account::<UserAccount>(&user.user_pda) {
            let slots_elapsed = current_slot.saturating_sub(user.last_update_slot);
            let stake_time_delta = (user_account.staked_amount as u128) * (slots_elapsed as u128);
            let user_stake_time = user.stake_time + stake_time_delta;
            total_stake_time += user_stake_time;

            let balance = fixture.ctx.get_account(&user.keypair.pubkey()).unwrap().lamports;
            let total_value = balance + user_account.staked_amount;
            let actual_rewards = total_value.saturating_sub(user.initial_balance);

            let total_rewards_available = REWARD_RATE as u128 * current_slot as u128;
            let expected_rewards = if total_stake_time > 0 {
                (user_stake_time * total_rewards_available / total_stake_time) as u64
            } else {
                0
            };

            fuzz_assert!(
                actual_rewards <= expected_rewards,
                "User stake-time {} but earned {} vs expected {}",
                user_stake_time, actual_rewards, expected_rewards
            );
        }
    }
}
