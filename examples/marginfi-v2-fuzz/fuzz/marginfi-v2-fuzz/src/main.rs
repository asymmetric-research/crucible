use crucible_fuzzer::*;
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;

// Generate complete types from IDL (including state types for deserialization)
crucible_idl_gen::declare_fuzz_program!("idls/marginfi.json");

use marginfi::instruction;
use marginfi::accounts;
use marginfi::types::{
    BankConfigCompact, WrappedI80F48,
    BankOperationalState, RiskTier, InterestRateConfigCompact,
};
use marginfi::state::MarginfiAccount;

// ACCOUNT_DISABLED constant - may need to be defined locally if not in IDL
const ACCOUNT_DISABLED: u64 = 1;

// Sysvar IDs for Solana v3
mod sysvar {
    pub mod rent {
        // SysvarRent111111111111111111111111111111111
        pub fn id() -> solana_pubkey::Pubkey {
            solana_pubkey::Pubkey::new_from_array([
                0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51,
                0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f,
                0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
                0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
            ])
        }
    }
    pub mod instructions {
        // Sysvar1nstructions1111111111111111111111111
        pub fn id() -> solana_pubkey::Pubkey {
            solana_pubkey::Pubkey::new_from_array([
                0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66,
                0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
                0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5,
                0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
            ])
        }
    }
}
use std::{rc::Rc, collections::HashMap};
use fixed::types::I80F48;
use fixed_macro::types::I80F48;
use crucible_fuzzer::anchor_spl::token::spl_token;
use crucible_fuzzer::anchor_lang::InstructionData;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Action Stats Tracking
// ============================================================================

mod action_stats {
    use std::sync::atomic::{AtomicU32, Ordering};

    macro_rules! define_counters {
        ($($name:ident),*) => {
            $(pub static $name: (AtomicU32, AtomicU32) = (AtomicU32::new(0), AtomicU32::new(0));)*
        }
    }

    define_counters!(DEPOSIT, BORROW, REPAY, WITHDRAW, LIQUIDATE, TRANSFER);

    pub fn record(counter: &(AtomicU32, AtomicU32), success: bool) {
        if success {
            counter.0.fetch_add(1, Ordering::Relaxed);
        } else {
            counter.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn print_summary() {
        // Gate verbose output behind FUZZ_VERBOSE for cleaner multi-core output
        if std::env::var("FUZZ_VERBOSE").is_err() {
            return;
        }
        eprintln!("=== Action Stats ===");
        eprintln!("deposit:   {:>5} ok / {:>5} fail", DEPOSIT.0.load(Ordering::Relaxed), DEPOSIT.1.load(Ordering::Relaxed));
        eprintln!("borrow:    {:>5} ok / {:>5} fail", BORROW.0.load(Ordering::Relaxed), BORROW.1.load(Ordering::Relaxed));
        eprintln!("repay:     {:>5} ok / {:>5} fail", REPAY.0.load(Ordering::Relaxed), REPAY.1.load(Ordering::Relaxed));
        eprintln!("withdraw:  {:>5} ok / {:>5} fail", WITHDRAW.0.load(Ordering::Relaxed), WITHDRAW.1.load(Ordering::Relaxed));
        eprintln!("liquidate: {:>5} ok / {:>5} fail", LIQUIDATE.0.load(Ordering::Relaxed), LIQUIDATE.1.load(Ordering::Relaxed));
        eprintln!("transfer:  {:>5} ok / {:>5} fail", TRANSFER.0.load(Ordering::Relaxed), TRANSFER.1.load(Ordering::Relaxed));
    }
}

// ============================================================================
// Fixture Data Structures
// ============================================================================

#[derive(Clone)]
struct BankData {
    bank: Pubkey,
    mint: Pubkey,
    oracle: Pubkey,
    liquidity_vault: Pubkey,
    decimals: u8,
    price: I80F48,  
}

#[derive(Clone)]
struct UserData {
    keypair: Rc<Keypair>,
    marginfi_account: Pubkey,
    token_accounts: HashMap<Pubkey, Pubkey>,
}

#[derive(Clone)]
struct MarginfiFixture {
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    group: Pubkey,
    fee_state: Pubkey,
    global_fee_wallet: Pubkey,
    banks: Vec<BankData>,
    users: Vec<UserData>,
    all_marginfi_accounts: Vec<Pubkey>,
}

#[fuzz_fixture]
impl MarginfiFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = marginfi::ID;

        ctx.add_program(&program_id, "../../marginfi.so")
            .expect("Failed to load marginfi program");

        fixture_helpers::initialize_state(&mut ctx, &program_id)
    }

    // ========================================================================
    // Actions
    // ========================================================================

    pub fn action_deposit(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] bank_idx: usize,
        #[range(1..100_000_000)] amount: u64,
    ) -> bool {
        let success = self.build_deposit(user_idx, bank_idx, self.constrain_amount(amount))
            .send().map(|o| o.is_success()).unwrap_or(false);
        action_stats::record(&action_stats::DEPOSIT, success);
        success
    }

    pub fn action_borrow(
        &mut self,
        #[range(0..2)] user_idx: usize,
        #[range(0..2)] bank_idx: usize,
        #[range(1..100_000_000)] amount: u64,
    ) -> bool {
        if amount == 0 { return true; }
        let success = self.build_borrow(user_idx, bank_idx, amount % 100_000_000)
            .send().map(|o| o.is_success()).unwrap_or(false);
        action_stats::record(&action_stats::BORROW, success);
        success
    }

    pub fn action_transfer_account(&mut self, #[range(0..2)] user_idx: usize) -> bool {
        let new_account = Keypair::new();
        let new_account_pubkey = new_account.pubkey();
        let success = self.build_transfer_account_from(user_idx, user_idx, self.users[user_idx].marginfi_account, &new_account)
            .send().map(|o| o.is_success()).unwrap_or(false);
        self.all_marginfi_accounts.push(new_account_pubkey);
        action_stats::record(&action_stats::TRANSFER, success);
        success
    }

    pub fn action_repay(
        &mut self,
        #[range(0..3)] user_idx: usize,
        #[range(0..2)] bank_idx: usize,
        #[range(1..100_000_000)] amount: u64,
        repay_all: bool,
    ) -> bool {
        let amount = self.constrain_amount(amount);
        let amount = self.cap_to_balance(user_idx, bank_idx, amount);
        if amount == 0 && !repay_all { return true; }
        let success = self.build_repay(user_idx, bank_idx, amount, repay_all)
            .send().map(|o| o.is_success()).unwrap_or(false);
        action_stats::record(&action_stats::REPAY, success);
        success
    }

    pub fn action_withdraw(
        &mut self,
        #[range(0..3)] user_idx: usize,
        #[range(0..2)] bank_idx: usize,
        #[range(1..100_000_000)] amount: u64,
        withdraw_all: bool,
    ) -> bool {
        if amount == 0 && !withdraw_all { return true; }
        let amount = self.constrain_amount(amount);
        let success = self.build_withdraw(user_idx, bank_idx, amount, withdraw_all)
            .send().map(|o| o.is_success()).unwrap_or(false);
        action_stats::record(&action_stats::WITHDRAW, success);
        success
    }

    pub fn action_liquidate(
        &mut self,
        #[range(0..3)] liquidator_idx: usize,
        #[range(0..3)] liquidatee_idx: usize,
        #[range(0..2)] asset_bank_idx: usize,
        #[range(0..2)] liab_bank_idx: usize,
        #[range(1..100_000_000)] asset_amount: u64,
    ) -> bool {
        if liquidator_idx == liquidatee_idx { return true; }
        if asset_bank_idx == liab_bank_idx { return true; }

        let liquidator = &self.users[liquidator_idx];
        let liquidatee = &self.users[liquidatee_idx];
        let asset_bank = &self.banks[asset_bank_idx];
        let liab_bank = &self.banks[liab_bank_idx];

        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", liab_bank.bank.as_ref()],
            &self.program_id,
        );
        let (insurance_vault, _) = Pubkey::find_program_address(
            &[b"insurance_vault", liab_bank.bank.as_ref()],
            &self.program_id,
        );

        let mut remaining = vec![asset_bank.oracle, liab_bank.oracle];
        for b in &self.banks {
            remaining.push(b.bank);
            remaining.push(b.oracle);
        }
        for b in &self.banks {
            remaining.push(b.bank);
            remaining.push(b.oracle);
        }

        let success = self.ctx.program(self.program_id)
            .call(instruction::LendingAccountLiquidate { asset_amount })
            .accounts(accounts::LendingAccountLiquidate {
                group: self.group,
                asset_bank: asset_bank.bank,
                liab_bank: liab_bank.bank,
                liquidator_marginfi_account: liquidator.marginfi_account,
                authority: liquidator.keypair.pubkey(),
                liquidatee_marginfi_account: liquidatee.marginfi_account,
                bank_liquidity_vault_authority: liquidity_vault_authority,
                bank_liquidity_vault: liab_bank.liquidity_vault,
                bank_insurance_vault: insurance_vault,
                token_program: spl_token::id(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*liquidator.keypair])
            .send().map(|o| o.is_success()).unwrap_or(false);
        action_stats::record(&action_stats::LIQUIDATE, success);
        success
    }

    // ========================================================================
    // Flashloan (combined: start + inner actions + end in single batch)
    // ========================================================================

    /// Combined flashloan: start + inner ops + end, all in one batch.
    /// ops[i] % 5 selects: 0=deposit, 1=borrow, 2=repay, 3=withdraw, 4=transfer
    /// banks[i] % 2 selects which bank, amounts[i] is the amount for that op.
    pub fn action_flashloan(
        &mut self,
        #[range(0..3)] user_idx: usize,
        #[max_len(4)] amounts: Vec<u64>,
        #[max_len(4)] banks: Vec<u8>,
        #[max_len(4)] ops: Vec<u8>,
    ) {
        if ops.len() < 2 { return; }
        let n = ops.len().min(4);
        let end_index = (1 + n) as u64;

        let user = &self.users[user_idx];
        let user_keypair = user.keypair.clone();
        let current_marginfi_account = user.marginfi_account;

        // Instruction 0: Start flashloan
        let _ = self.ctx.program(self.program_id)
            .call(instruction::LendingAccountStartFlashloan { end_index })
            .accounts(accounts::LendingAccountStartFlashloan {
                marginfi_account: current_marginfi_account,
                authority: user_keypair.pubkey(),
            })
            .signers(&[&*user_keypair])
            .add_transaction();

        // Instructions 1..N: Inner actions
        for i in 0..n {
            let op_type = ops[i] as usize;
            let bank_idx = self.constrain_bank_idx(*banks.get(i).unwrap_or(&0) as usize);
            let amount = *amounts.get(i).unwrap_or(&1_000_000);
            match op_type % 5 {
                0 => {
                    let amount = self.cap_to_balance(user_idx, bank_idx, self.constrain_amount(amount));
                    let _ = self.build_deposit(user_idx, bank_idx, amount).add_transaction();
                }
                1 => {
                    let _ = self.build_borrow(user_idx, bank_idx, amount % 100_000_000).add_transaction();
                }
                2 => {
                    let amount = self.cap_to_balance(user_idx, bank_idx, self.constrain_amount(amount));
                    let _ = self.build_repay(user_idx, bank_idx, amount, false).add_transaction();
                }
                3 => {
                    let amount = self.constrain_amount(amount);
                    let _ = self.build_withdraw(user_idx, bank_idx, amount, false).add_transaction();
                }
                4 => {
                    let new_account = Keypair::new();
                    let new_account_pubkey = new_account.pubkey();
                    let _ = self.build_transfer_account_from(
                        user_idx, user_idx, current_marginfi_account, &new_account,
                    ).add_transaction();
                    self.all_marginfi_accounts.push(new_account_pubkey);
                }
                _ => unreachable!(),
            }
        }

        // Final instruction: End flashloan
        let remaining = self.build_health_remaining_accounts();
        let _ = self.ctx.program(self.program_id)
            .call(instruction::LendingAccountEndFlashloan {})
            .accounts(accounts::LendingAccountEndFlashloan {
                marginfi_account: current_marginfi_account,
                authority: user_keypair.pubkey(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user_keypair])
            .add_transaction();

        let _ = self.ctx.send_batch();
    }

    // ========================================================================
    // Builder helpers (return ProgramCallBuilder for .send() or .add_transaction())
    // ========================================================================

    fn constrain_bank_idx(&self, idx: usize) -> usize { idx % self.banks.len() }
    fn constrain_user_idx(&self, idx: usize) -> usize { idx % self.users.len() }
    fn constrain_amount(&self, amount: u64) -> u64 { amount.max(1).min(100_000_000) }

    fn cap_to_balance(&self, user_idx: usize, bank_idx: usize, amount: u64) -> u64 {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        let balance = self.ctx.token_balance(&token_account);
        amount.min(balance)
    }

    fn build_deposit(&mut self, user_idx: usize, bank_idx: usize, amount: u64) -> crucible_test_context::ProgramBuilder<'_> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        let balance = self.ctx.token_balance(&token_account);
        let amount = amount.min(balance).max(1);

        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountDeposit { amount, deposit_up_to_limit: None })
            .accounts(accounts::LendingAccountDeposit {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                signer_token_account: token_account,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .signers(&[&*user.keypair])
    }

    fn build_borrow(&mut self, user_idx: usize, bank_idx: usize, amount: u64) -> crucible_test_context::ProgramBuilder<'_> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.bank.as_ref()], &self.program_id,
        );
        let mut remaining = Vec::new();
        for b in &self.banks { remaining.push(b.bank); remaining.push(b.oracle); }

        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountBorrow { amount })
            .accounts(accounts::LendingAccountBorrow {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                destination_token_account: token_account,
                bank_liquidity_vault_authority: liquidity_vault_authority,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user.keypair])
    }

    fn build_repay(&mut self, user_idx: usize, bank_idx: usize, amount: u64, repay_all: bool) -> crucible_test_context::ProgramBuilder<'_> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();

        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountRepay { amount, repay_all: Some(repay_all) })
            .accounts(accounts::LendingAccountRepay {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                signer_token_account: token_account,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .signers(&[&*user.keypair])
    }

    fn build_withdraw(&mut self, user_idx: usize, bank_idx: usize, amount: u64, withdraw_all: bool) -> crucible_test_context::ProgramBuilder<'_> {
        let user = &self.users[user_idx];
        let bank = &self.banks[bank_idx];
        let token_account = *user.token_accounts.get(&bank.mint).unwrap();
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.bank.as_ref()], &self.program_id,
        );
        let mut remaining = Vec::new();
        for b in &self.banks { remaining.push(b.bank); remaining.push(b.oracle); }

        self.ctx.program(self.program_id)
            .call(instruction::LendingAccountWithdraw { amount, withdraw_all: Some(withdraw_all) })
            .accounts(accounts::LendingAccountWithdraw {
                group: self.group,
                marginfi_account: user.marginfi_account,
                authority: user.keypair.pubkey(),
                bank: bank.bank,
                destination_token_account: token_account,
                bank_liquidity_vault_authority: liquidity_vault_authority,
                liquidity_vault: bank.liquidity_vault,
                token_program: spl_token::id(),
            })
            .remaining_accounts(remaining)
            .signers(&[&*user.keypair])
    }

    fn build_transfer_account_from(&mut self, from_user_idx: usize, _to_user_idx: usize, old_account: Pubkey, new_account: &Keypair) -> crucible_test_context::ProgramBuilder<'_> {
        let user = &self.users[from_user_idx];
        self.ctx.program(self.program_id)
            .call(instruction::TransferToNewAccount {})
            .accounts(accounts::TransferToNewAccount {
                group: self.group,
                old_marginfi_account: old_account,
                new_marginfi_account: new_account.pubkey(),
                authority: user.keypair.pubkey(),
                new_authority: user.keypair.pubkey(),
                global_fee_wallet: self.global_fee_wallet,
            })
            .signers(&[&*user.keypair, new_account])
    }

    fn build_health_remaining_accounts(&self) -> Vec<Pubkey> {
        let mut remaining = Vec::new();
        for bank in &self.banks {
            remaining.push(bank.bank);
            remaining.push(bank.oracle);
        }
        remaining
    }

    // ========================================================================
    // After-Action Callback (called after every action)
    // ========================================================================

    pub fn after_action(&self) {
        // Only print periodically and only when FUZZ_VERBOSE is set
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);

        if count > 0 && count % 1000 == 0 {
            action_stats::print_summary();

            // State snapshot - show user token balances (gated by FUZZ_VERBOSE)
            if std::env::var("FUZZ_VERBOSE").is_ok() {
                eprintln!("\n=== State Snapshot (action {}) ===", count);
                for (u_idx, user) in self.users.iter().enumerate() {
                    for (m_idx, mint) in user.token_accounts.keys().enumerate() {
                        let ta = user.token_accounts[mint];
                        let balance = self.ctx.token_balance(&ta);
                        if balance > 0 {
                            eprintln!("user[{}] token[{}]: {}", u_idx, m_idx, balance);
                        }
                    }
                }
                eprintln!();
            }
        }
    }
}

// ============================================================================
// Initialization Helpers
// ============================================================================

mod fixture_helpers {
    use super::*;

    pub fn initialize_state(
        ctx: &mut TestContext, 
        program_id: &Pubkey, 
    ) -> MarginfiFixture {
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        let fee_state = init_fee_state(ctx, &admin, program_id);
        let group = init_group(ctx, &admin, &fee_state, program_id);
        
        let sol_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
            
        let usdc_mint = ctx.create_mint()
            .pubkey(Keypair::new().pubkey())
            .decimals(6)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap();
        
        let sol_oracle = create_oracle(ctx, I80F48!(100.0), 9);
        let usdc_oracle = create_oracle(ctx, I80F48!(1.0), 6);
        
        let sol_bank = create_bank(
            ctx, program_id, &group, &fee_state, 
            &sol_mint, &sol_oracle, 9, &admin, sol_bank_config()
        );
        
        let usdc_bank = create_bank(
            ctx, program_id, &group, &fee_state,
            &usdc_mint, &usdc_oracle, 6, &admin, usdc_bank_config()
        );
        
        let banks = vec![
            BankData { 
                bank: sol_bank.0, mint: sol_mint, oracle: sol_oracle, 
                liquidity_vault: sol_bank.1, decimals: 9, price: I80F48!(100.0) 
            },
            BankData { 
                bank: usdc_bank.0, mint: usdc_mint, oracle: usdc_oracle, 
                liquidity_vault: usdc_bank.1, decimals: 6, price: I80F48!(1.0) 
            },
        ];

        let users: Vec<_> = (0..3)
            .map(|_| create_user(ctx, program_id, &group, &banks, &admin))
            .collect();
        
        let all_marginfi_accounts: Vec<Pubkey> = users.iter()
            .map(|u| u.marginfi_account)
            .collect();
            
        MarginfiFixture {
            ctx: std::mem::replace(ctx, TestContext::new()),
            program_id: *program_id, 
            admin: admin.clone(),
            group, 
            fee_state, 
            global_fee_wallet: admin.pubkey(),
            banks, 
            users,
            all_marginfi_accounts,
        }
    }

    fn init_fee_state(ctx: &mut TestContext, admin: &Rc<Keypair>, program_id: &Pubkey) -> Pubkey {
        let (fee_state, _) = Pubkey::find_program_address(&[b"feestate"], program_id);
        
        ctx.program(*program_id)
            .call(instruction::InitGlobalFeeState {
                admin: admin.pubkey(),
                fee_wallet: admin.pubkey(),
                bank_init_flat_sol_fee: 0,
                program_fee_fixed: WrappedI80F48::from(I80F48::ZERO),
                program_fee_rate: WrappedI80F48::from(I80F48::ZERO),
            })
            .accounts(accounts::InitGlobalFeeState {
                payer: admin.pubkey(),
                fee_state,
            })
            .signers(&[&**admin])
            .send()
            .unwrap();
        
        fee_state
    }
    
    fn init_group(
        ctx: &mut TestContext, 
        admin: &Rc<Keypair>, 
        fee_state: &Pubkey, 
        program_id: &Pubkey
    ) -> Pubkey {
        let group = Keypair::new();
        
        ctx.program(*program_id)
            .call(instruction::MarginfiGroupInitialize { is_arena_group: false })
            .accounts(accounts::MarginfiGroupInitialize {
                marginfi_group: group.pubkey(),
                admin: admin.pubkey(),
                fee_state: *fee_state,
            })
            .signers(&[&**admin, &group])
            .send()
            .unwrap();
        
        group.pubkey()
    }
    
    fn create_oracle(ctx: &mut TestContext, price: I80F48, decimals: u8) -> Pubkey {
        let native_price = (price * I80F48::from_num(10_i64.pow(decimals as u32))).to_num::<i64>();

        ctx.create_mock_pyth_oracle()
            .price(native_price)
            .exponent(-(decimals as i32))
            .confidence(100_000)
            .build()
            .unwrap()
    }
    
    fn create_bank(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        group: &Pubkey,
        fee_state: &Pubkey,
        mint: &Pubkey,
        oracle: &Pubkey,
        _decimals: u8,
        admin: &Rc<Keypair>,
        config: BankConfigCompact,
    ) -> (Pubkey, Pubkey) {
        let bank = Keypair::new();
        
        let (liquidity_vault, _) = Pubkey::find_program_address(
            &[b"liquidity_vault", bank.pubkey().as_ref()], program_id
        );
        let (liquidity_vault_authority, _) = Pubkey::find_program_address(
            &[b"liquidity_vault_auth", bank.pubkey().as_ref()], program_id
        );
        let (insurance_vault, _) = Pubkey::find_program_address(
            &[b"insurance_vault", bank.pubkey().as_ref()], program_id
        );
        let (insurance_vault_authority, _) = Pubkey::find_program_address(
            &[b"insurance_vault_auth", bank.pubkey().as_ref()], program_id
        );
        let (fee_vault, _) = Pubkey::find_program_address(
            &[b"fee_vault", bank.pubkey().as_ref()], program_id
        );
        let (fee_vault_authority, _) = Pubkey::find_program_address(
            &[b"fee_vault_auth", bank.pubkey().as_ref()], program_id
        );
        
        ctx.program(*program_id)
            .call(instruction::LendingPoolAddBank { bank_config: config })
            .accounts(accounts::LendingPoolAddBank {
                marginfi_group: *group,
                admin: admin.pubkey(),
                fee_payer: admin.pubkey(),
                fee_state: *fee_state,
                global_fee_wallet: admin.pubkey(),
                bank_mint: *mint,
                bank: bank.pubkey(),
                liquidity_vault_authority,
                liquidity_vault,
                insurance_vault_authority,
                insurance_vault,
                fee_vault_authority,
                fee_vault,
                token_program: spl_token::id(),
            })
            .signers(&[&**admin, &bank])
            .send()
            .unwrap();
        
        ctx.program(*program_id)
            .call(instruction::LendingPoolConfigureBankOracle {
                setup: 3,
                oracle: *oracle,
            })
            .accounts(accounts::LendingPoolConfigureBankOracle {
                group: *group,
                admin: admin.pubkey(),
                bank: bank.pubkey(),
            })
            .remaining_accounts(vec![*oracle])
            .signers(&[&**admin])
            .send()
            .unwrap();
        
        (bank.pubkey(), liquidity_vault)
    }
    
    fn create_user(
        ctx: &mut TestContext,
        program_id: &Pubkey,
        group: &Pubkey,
        banks: &[BankData],
        admin: &Rc<Keypair>,
    ) -> UserData {
        let keypair = Rc::new(Keypair::new());
        
        ctx.create_account()
            .pubkey(keypair.pubkey())
            .lamports(10_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();
        
        let marginfi_account = Keypair::new();
        ctx.program(*program_id)
            .call(instruction::MarginfiAccountInitialize {})
            .accounts(accounts::MarginfiAccountInitialize {
                marginfi_group: *group,
                marginfi_account: marginfi_account.pubkey(),
                authority: keypair.pubkey(),
                fee_payer: keypair.pubkey(),
            })
            .signers(&[&*keypair, &marginfi_account])
            .send()
            .unwrap();
        
        let mut token_accounts = HashMap::new();
        for bank in banks {
            let token_account = ctx.create_token_account()
                .pubkey(Keypair::new().pubkey())
                .mint(bank.mint)
                .token_owner(keypair.pubkey())
                .create()
                .unwrap();
            
            let amount = 1_000 * 10_u64.pow(bank.decimals as u32);
            ctx.mint_to(&bank.mint, &token_account, amount, admin).unwrap();
            
            token_accounts.insert(bank.mint, token_account);
        }
        
        UserData { keypair, marginfi_account: marginfi_account.pubkey(), token_accounts }
    }
}

// ============================================================================
// Bank Configs
// ============================================================================

fn sol_bank_config() -> BankConfigCompact {
    BankConfigCompact {
        asset_weight_init: WrappedI80F48::from(I80F48!(0.8)),
        asset_weight_maint: WrappedI80F48::from(I80F48!(0.9)),
        liability_weight_init: WrappedI80F48::from(I80F48!(1.2)),
        liability_weight_maint: WrappedI80F48::from(I80F48!(1.1)),
        deposit_limit: u64::MAX,
        borrow_limit: u64::MAX,
        operational_state: BankOperationalState::Operational,
        risk_tier: RiskTier::Collateral,
        oracle_max_age: 100,
        interest_rate_config: InterestRateConfigCompact {
            optimal_utilization_rate: WrappedI80F48::from(I80F48!(0.5)),
            plateau_interest_rate: WrappedI80F48::from(I80F48!(0.5)),
            max_interest_rate: WrappedI80F48::from(I80F48!(4.0)),
            insurance_fee_fixed_apr: WrappedI80F48::from(I80F48!(0.01)),
            insurance_ir_fee: WrappedI80F48::from(I80F48!(0.05)),
            protocol_fixed_fee_apr: WrappedI80F48::from(I80F48!(0.01)),
            protocol_ir_fee: WrappedI80F48::from(I80F48!(0.1)),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn usdc_bank_config() -> BankConfigCompact {
    BankConfigCompact {
        asset_weight_init: WrappedI80F48::from(I80F48!(0.95)),
        asset_weight_maint: WrappedI80F48::from(I80F48!(0.98)),
        liability_weight_init: WrappedI80F48::from(I80F48!(1.05)),
        liability_weight_maint: WrappedI80F48::from(I80F48!(1.02)),
        deposit_limit: u64::MAX,
        borrow_limit: u64::MAX,
        operational_state: BankOperationalState::Operational,
        risk_tier: RiskTier::Collateral,
        oracle_max_age: 100,
        interest_rate_config: InterestRateConfigCompact {
            optimal_utilization_rate: WrappedI80F48::from(I80F48!(0.8)),
            plateau_interest_rate: WrappedI80F48::from(I80F48!(0.1)),
            max_interest_rate: WrappedI80F48::from(I80F48!(3.0)),
            insurance_fee_fixed_apr: WrappedI80F48::from(I80F48!(0.005)),
            insurance_ir_fee: WrappedI80F48::from(I80F48!(0.02)),
            protocol_fixed_fee_apr: WrappedI80F48::from(I80F48!(0.005)),
            protocol_ir_fee: WrappedI80F48::from(I80F48!(0.05)),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ============================================================================
// Invariant Test
// ============================================================================

#[cfg(feature = "invariant_test")]
#[invariant_test]
fn invariant_test(fixture: &mut MarginfiFixture) {
    bad_debt_check(fixture);
}

fn bad_debt_check(fixture: &mut MarginfiFixture) {
    for account_pubkey in fixture.all_marginfi_accounts.clone() {
        let Ok(account_data) = fixture.ctx.get_account(&account_pubkey) else { continue };
        let account: &MarginfiAccount = bytemuck::from_bytes(&account_data.data[8..]);
        
        // Check if account is disabled by checking bit flag
        if (account.account_flags & ACCOUNT_DISABLED) != 0 { continue }
        
        let mut assets_usd = I80F48::ZERO;
        let mut liabs_usd = I80F48::ZERO;
        
        for bal in account.lending_account.balances.iter() {
            if bal.active == 0 { continue }
            let Some(bank) = fixture.banks.iter().find(|b| b.bank == bal.bank_pk) else { continue };
            
            let a: I80F48 = bal.asset_shares.into();
            let l: I80F48 = bal.liability_shares.into();
            let scale = I80F48::from_num(10_u64.pow(bank.decimals as u32));
            
            assets_usd += a * bank.price / scale;
            liabs_usd += l * bank.price / scale;
        }
        
        crucible_test_context::fuzz_assert_le!(liabs_usd, assets_usd, "BAD DEBT: {} > {}", liabs_usd, assets_usd);
    }
}
