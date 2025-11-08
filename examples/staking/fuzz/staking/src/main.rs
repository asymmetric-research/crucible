use staking::*;
use anchor_test::*;
use arbitrary::Arbitrary;
use solana_sdk::{signature::Keypair, system_program, pubkey::Pubkey, signature::Signer};

const INITIAL_BALANCE: u64 = 100_000_000_000;
const REWARD_RATE: u64 = 1000;

struct StakingFixture<'a> {
    ctx: &'a mut TestContext,
    pool_pda: Pubkey,
    program_id: Pubkey,
    users: Vec<User>,
    funder: Keypair,
}

struct User {
    keypair: Keypair,
    user_pda: Pubkey,
    initial_balance: u64,
    stake_time: u128,  // ADD: accumulated (stake × slots)
    last_update_slot: u64,  // ADD: when we last updated stake_time
}

#[fuzz_fixture]
impl<'a> StakingFixture<'a> {
    pub fn setup(ctx: &'a mut TestContext) -> Self {
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        ctx.add_program(&program_id, "target/deploy/staking.so").unwrap();

        let (pool_pda, _) = Pubkey::find_program_address(&[b"pool"], &program_id);
        
        let current_slot = ctx.slot();  // GET CURRENT SLOT
        
        let mut users = Vec::new();
        for _ in 0..3 {
            let keypair = Keypair::new();
            ctx.create_account()
                .pubkey(keypair.pubkey())
                .lamports(INITIAL_BALANCE)
                .owner(system_program::id())
                .create()
                .unwrap();
            
            let (user_pda, _) = Pubkey::find_program_address(&[b"user", keypair.pubkey().as_ref()], &program_id);
            users.push(User { 
                keypair, 
                user_pda, 
                initial_balance: INITIAL_BALANCE,
                stake_time: 0,
                last_update_slot: current_slot,  // INITIALIZE TO CURRENT SLOT, NOT 0
            });
        }
        
        let funder = Keypair::new();
        ctx.create_account()
            .pubkey(funder.pubkey())
            .lamports(1_000_000_000_000)
            .owner(system_program::id())
            .create()
            .unwrap();
        
        // Initialize pool
        ctx.program(program_id)
            .call(instruction::InitializePool { reward_rate_per_slot: REWARD_RATE })
            .accounts(accounts::InitializePool {
                pool: pool_pda,
                payer: users[0].keypair.pubkey(),
                system_program: system_program::id(),
            })
            .signers(&[&users[0].keypair])
            .send()
            .unwrap();
        
        for user in &users {
            ctx.program(program_id)
                .call(instruction::InitializeUser {})
                .accounts(accounts::InitializeUser {
                    user_account: user.user_pda,
                    staker: user.keypair.pubkey(),
                    system_program: system_program::id(),
                })
                .signers(&[&user.keypair])
                .send()
                .unwrap();
        }
        
        // Fund rewards
        ctx.program(program_id)
            .call(instruction::FundRewards { amount: 100_000_000_000 })
            .accounts(accounts::FundRewards { pool: pool_pda, funder: funder.pubkey() })
            .signers(&[&funder])
            .send()
            .unwrap();

        Self { ctx, pool_pda, program_id, users, funder }
    }

    /// HELPERS

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

    /// ACTIONS

    pub fn action_stake(&mut self, user_idx: usize, amount: u64) {
        
        self.update_user_stake_time(user_idx % self.users.len());  
        let user = &self.users[user_idx % self.users.len()];
        let balance = self.ctx.get_account(&user.keypair.pubkey()).unwrap().lamports;
        let safe_amount = amount.min(balance.saturating_sub(10_000_000));
        
        let ct = self.ctx.program(self.program_id)
            .call(instruction::Stake { amount: safe_amount })
            .accounts(accounts::Stake {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
                system_program: system_program::id(),  
            })
            .signers(&[&user.keypair])
            .send();
    }
    
    pub fn action_unstake(&mut self, user_idx: usize, amount: u64) {
        self.update_user_stake_time(user_idx % self.users.len());
        let user = &self.users[user_idx % self.users.len()];
        if self.ctx.get_account(&user.user_pda).is_err() { return; }
        
        let user_account = self.ctx.read_anchor_account::<UserAccount>(&user.user_pda).unwrap();
        let safe_amount = amount.min(user_account.staked_amount);
        if safe_amount == 0 { return; }
        
        let ct = self.ctx.program(self.program_id)
            .call(instruction::Unstake { amount: safe_amount })
            .accounts(accounts::Unstake {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
                system_program: system_program::id(),  
            })
            .signers(&[&user.keypair])
            .send()
            .unwrap();
    }
    
    pub fn action_claim(&mut self, user_idx: usize) {
        self.update_user_stake_time(user_idx % self.users.len());  
        
        let user = &self.users[user_idx % self.users.len()];
        if self.ctx.get_account(&user.user_pda).is_err() { return; }
        
        let ct = self.ctx.program(self.program_id)
            .call(instruction::ClaimRewards {})
            .accounts(accounts::ClaimRewards {
                pool: self.pool_pda,
                user_account: user.user_pda,
                staker: user.keypair.pubkey(),
            })
            .signers(&[&user.keypair])
            .send()
            .unwrap();
    }
    
    pub fn action_advance_slots(&mut self, slots: u64) {
        // Update all users before advancing time
        for i in 0..self.users.len() {
            self.update_user_stake_time(i);
        }
        
        let new_slot = self.ctx.slot() + (slots % 10_000);
        self.ctx.warp_to_slot(new_slot);
    }
}

#[test]
fn test_stake_reward_debt_exploit() {
    let mut ctx = TestContext::new();
    let mut fixture = StakingFixture::setup(&mut ctx);
    
    fixture.action_stake(0, 1000);
    fixture.action_stake(1, 1000);
    fixture.action_advance_slots(100);
    fixture.action_stake(0, 10_000_000);
    
    let before1 = fixture.ctx.get_account(&fixture.users[1].keypair.pubkey()).unwrap().lamports;
    fixture.action_claim(1);
    let after1 = fixture.ctx.get_account(&fixture.users[1].keypair.pubkey()).unwrap().lamports;
    let rewards1 = after1.saturating_sub(before1);
    
    let user0 = fixture.ctx.read_anchor_account::<UserAccount>(&fixture.users[0].user_pda).unwrap();
    let pool = fixture.ctx.read_anchor_account::<Pool>(&fixture.pool_pda).unwrap();
    
    let pending_exploited = (user0.staked_amount as u128)
        .saturating_mul(pool.accumulated_rewards_per_share)
        .saturating_div(1_000_000_000)
        .saturating_sub(user0.reward_debt as u128) as u64;
    
    println!("User 0 can claim: {} ({}x more than User 1's {})", 
        pending_exploited, pending_exploited / rewards1.max(1), rewards1);
    
    assert!(pending_exploited > rewards1 * 100);
}


#[derive(Arbitrary, Debug, Clone)]
enum Action {
    Stake { user_idx: u8, amount: u64 },
    Unstake { user_idx: u8, amount: u64 },
    Claim { user_idx: u8 },
    AdvanceSlots { slots: u64 },
}

#[anchor_fuzz]
fn fuzz_staking(ctx: &mut TestContext, actions: Vec<Action>) {
    let mut fixture = StakingFixture::setup(ctx);
    
    for action in actions.iter().take(20) {
        match action {
            Action::Stake { user_idx, amount } => 
                fixture.action_stake(*user_idx as usize % 3, *amount % 10_000_000),
            Action::Unstake { user_idx, amount } => 
                fixture.action_unstake(*user_idx as usize % 3, *amount % 10_000_000),
            Action::Claim { user_idx } => 
                fixture.action_claim(*user_idx as usize % 3),
            Action::AdvanceSlots { slots } => 
                fixture.action_advance_slots(*slots % 1000),
        }
    }
}

#[invariant_test(StakingFixture::setup, num_actions_before_reset = 4)]
fn invariant_fuzz(fixture: &StakingFixture) {
    let current_slot = fixture.ctx.slot();
    
    // Update stake-time for all users
    let mut total_stake_time = 0u128;
    for user in &fixture.users {
        if let Ok(user_account) = fixture.ctx.read_anchor_account::<UserAccount>(&user.user_pda) {
            // Calculate stake-time since last check
            let slots_elapsed = current_slot.saturating_sub(user.last_update_slot);
            let stake_time_delta = (user_account.staked_amount as u128) * (slots_elapsed as u128);
            let user_stake_time = user.stake_time + stake_time_delta;
            total_stake_time += user_stake_time;
            
            // Calculate actual rewards earned
            let balance = fixture.ctx.get_account(&user.keypair.pubkey()).unwrap().lamports;
            let total_value = balance + user_account.staked_amount;
            let actual_rewards = total_value.saturating_sub(user.initial_balance);
            
            // Calculate expected rewards based on stake-time proportion
            let total_rewards_available = REWARD_RATE as u128 * current_slot as u128;
            let expected_rewards = if total_stake_time > 0 {
                (user_stake_time * total_rewards_available / total_stake_time) as u64
            } else {
                0
            };
            
            assert!(
                actual_rewards <= expected_rewards, 
                "User stake-time {} but earned {} vs expected {}",
                user_stake_time, actual_rewards, expected_rewards
            );
        }
    }
}
