//! Fuzz harness for the owner-mutation-airdrop example.
//!
//! It drives the program through every positive (missing-check) and negative (check-present)
//! instruction path. On its own it fuzzes a lamport-conservation invariant; run with
//! `--mutate-accounts` it additionally reports seeded owner, signer, PDA, type-tag,
//! sysvar, SPL-token, field-reference, bidirectional/shared-root, semantic-swap,
//! cross-authority, and duplicate-account bugs as account-mutation findings.
//!
//!   crucible run owner-mutation-airdrop invariant_test --release
//!   crucible run owner-mutation-airdrop invariant_test --release --mutate-accounts

use anchor_lang::prelude::sysvar::SysvarId;
use anchor_lang::prelude::Clock;
use anchor_lang::InstructionData;
use crucible_fuzzer::anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use crucible_fuzzer::anchor_lang::solana_program::system_program;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

// Generate instruction/account types from the program IDL (no dependency on the program crate).
crucible_idl_gen::declare_fuzz_program!("idls/owner_mutation_airdrop.json");
use owner_mutation_airdrop::{accounts, instruction};

/// Foreign program that is meant to own `foreign_config` (matches the program's
/// `FOREIGN_PROGRAM_ID = [0x0A; 32]`).
const FOREIGN_OWNER: [u8; 32] = [0x0A; 32];

const INITIAL_VAULT_BALANCE: u64 = 1_000_000_000;
const INITIAL_RECIPIENT_BALANCE: u64 = 1_000_000;
const CLAIM_AMOUNT: u64 = 1_000;
const STATE_AMOUNT: u64 = 1_000;
const FOREIGN_AMOUNT: u64 = 1_000;
const TINY_AMOUNT: u32 = 1_000;
const TOKEN_AMOUNT: u64 = 1_000;
const MINT_DECIMALS: u8 = 6;
const CONFIG_DISCRIMINATOR: [u8; 8] = [155, 12, 170, 224, 30, 250, 204, 130];
const ALTERNATE_CONFIG_DISCRIMINATOR: [u8; 8] = [112, 26, 206, 10, 180, 130, 5, 4];
const TRADER_STATE_DISCRIMINATOR: [u8; 8] = [124, 33, 101, 17, 158, 79, 26, 140];
const POOL_STATE_DISCRIMINATOR: [u8; 8] = [247, 237, 227, 245, 215, 195, 222, 70];
const LINKED_STATE_DISCRIMINATOR: [u8; 8] = [178, 163, 210, 62, 47, 48, 13, 148];
const TARGET_STATE_DISCRIMINATOR: [u8; 8] = [147, 73, 167, 190, 147, 166, 153, 37];
const VALUE_SOURCE_STATE_DISCRIMINATOR: [u8; 8] = [54, 98, 108, 196, 246, 208, 150, 132];
const PRICE_STATE_DISCRIMINATOR: [u8; 8] = [202, 40, 37, 157, 73, 117, 152, 251];
const ROOT_STATE_DISCRIMINATOR: [u8; 8] = [168, 212, 194, 223, 236, 239, 59, 86];
const AUTHORITY_STATE_DISCRIMINATOR: [u8; 8] = [217, 219, 18, 179, 143, 126, 98, 123];
const PAIR_LEFT_STATE_DISCRIMINATOR: [u8; 8] = [139, 52, 59, 189, 192, 91, 80, 216];
const PAIR_RIGHT_STATE_DISCRIMINATOR: [u8; 8] = [67, 248, 77, 163, 40, 119, 172, 151];
const SEMANTIC_STATE_DISCRIMINATOR: [u8; 8] = [35, 220, 247, 206, 91, 179, 102, 198];
const GATE_STATE_DISCRIMINATOR: [u8; 8] = [70, 225, 126, 160, 254, 17, 57, 176];
const GATED_CONFIG_STATE_DISCRIMINATOR: [u8; 8] = [31, 236, 184, 163, 59, 200, 22, 213];
const EXPECTED_SEMANTIC_CONTEXT: Pubkey = Pubkey::new_from_array([0x86; 32]);
const ALT_SEMANTIC_CONTEXT: Pubkey = Pubkey::new_from_array([0x87; 32]);

#[derive(Clone)]
struct OwnerMutationAirdropFixture {
    ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Rc<Keypair>,
    recipient: Rc<Keypair>,
    authority: Rc<Keypair>,
    cosigner: Rc<Keypair>,
    vault: Pubkey,
    // CC-1 owner-check targets (read-only data accounts).
    program_config: Pubkey,  // program-owned
    state: Pubkey,           // second program-owned account
    foreign_config: Pubkey,  // owned by a foreign program
    tiny_config: Pubkey,     // <= 8 bytes
    inert: Pubkey,           // program-owned but never read
    pda_config: Pubkey,      // off-curve PDA data account
    pda_authority: Pubkey,   // off-curve PDA authority with no data read
    inert_pda: Pubkey,       // off-curve PDA passed but never read
    writable_config: Pubkey, // program-owned, declared writable
    typed_config: Pubkey,    // Anchor-discriminated Config account (CC-5 target)
    alternate_config: Pubkey, // valid-but-wrong type account (documented FN)
    mint: Pubkey,            // SPL mint-shaped account
    token_account: Pubkey,   // SPL token-account-shaped account
    pool_state: Pubkey,      // pool state containing the canonical LP mint
    source_trader: Pubkey,   // custom invariant source account (documented FN)
    destination_trader: Pubkey, // custom invariant destination account (documented FN)
    linked_source: Pubkey,   // CC-7 same-class source containing a target pubkey
    linked_target: Pubkey,   // CC-7 same-class referenced target
    value_source: Pubkey,    // CC-7 value-ref source containing a price account pubkey
    price: Pubkey,           // CC-7 value-ref referenced value account
    root: Pubkey,            // CC-7 singleton/root account containing a child pubkey
    root_child: Pubkey,
    pair_root: Pubkey,        // CC-7.3 root/counterpart account
    pair_left: Pubkey,        // CC-7.3 left side with right/root fields
    pair_right: Pubkey,       // CC-7.3 right side with left/root fields
    shared_left: Pubkey,      // CC-7.3 shared-root left side
    shared_right: Pubkey,     // CC-7.3 shared-root right side
    semantic_state: Pubkey,   // CC-7.7 same-class account with embedded semantic context
    authority_state: Pubkey, // CC-9 state containing the expected signer pubkey
    gate: Pubkey,            // T4 gate holding the fast_path flag (toggled to drive states)
    gated_config: Pubkey,    // T4 config whose CC-1 owner check is skipped on the fast path
    cpi_dest: Pubkey,        // CC-13 account forwarded into a system-transfer CPI
}

#[fuzz_fixture]
impl OwnerMutationAirdropFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(owner_mutation_airdrop::ID.to_bytes());
        ctx.add_program(&program_id, "../../target/deploy/owner_mutation_airdrop.so")
            .unwrap();

        // Seed the Clock sysvar with a positive unix_timestamp (CC-2 target).
        ctx.set_sysvar(&Clock {
            slot: 10,
            epoch_start_timestamp: 1_700_000_000,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp: 1_700_000_000,
        });

        let fee_payer = Rc::new(Keypair::new());
        let recipient = Rc::new(Keypair::new());
        let authority = Rc::new(Keypair::new());
        let cosigner = Rc::new(Keypair::new());
        for kp in [&fee_payer, &authority, &cosigner] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(INITIAL_VAULT_BALANCE)
                .owner(system_program::id())
                .owner_unverified()
                .create()
                .unwrap();
        }
        ctx.create_account()
            .pubkey(recipient.pubkey())
            .lamports(INITIAL_RECIPIENT_BALANCE)
            .owner(system_program::id())
            .owner_unverified()
            .create()
            .unwrap();

        let foreign_owner = Pubkey::new_from_array(FOREIGN_OWNER);
        let program_config = Self::new_data(&mut ctx, program_id, &CLAIM_AMOUNT.to_le_bytes());
        let state = Self::new_data(&mut ctx, program_id, &STATE_AMOUNT.to_le_bytes());
        let foreign_config = Self::new_data(&mut ctx, foreign_owner, &FOREIGN_AMOUNT.to_le_bytes());
        let tiny_config = Self::new_data(&mut ctx, program_id, &TINY_AMOUNT.to_le_bytes());
        let inert = Self::new_data(&mut ctx, program_id, &CLAIM_AMOUNT.to_le_bytes());
        let writable_config = Self::new_data(&mut ctx, program_id, &CLAIM_AMOUNT.to_le_bytes());

        let (pda_config, _) = Pubkey::find_program_address(&[b"config"], &program_id);
        ctx.create_account()
            .pubkey(pda_config)
            .lamports(1_000_000)
            .owner(program_id)
            .data(&CLAIM_AMOUNT.to_le_bytes())
            .create()
            .unwrap();

        let (pda_authority, _) = Pubkey::find_program_address(&[b"authority"], &program_id);
        ctx.create_account()
            .pubkey(pda_authority)
            .lamports(1_000_000)
            .owner(program_id)
            .data(&[])
            .create()
            .unwrap();

        let (inert_pda, _) = Pubkey::find_program_address(&[b"inert"], &program_id);
        ctx.create_account()
            .pubkey(inert_pda)
            .lamports(1_000_000)
            .owner(program_id)
            .data(&[])
            .create()
            .unwrap();

        let mut typed_data = CONFIG_DISCRIMINATOR.to_vec();
        typed_data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
        let typed_config = Self::new_data(&mut ctx, program_id, &typed_data);

        let mut alternate_data = ALTERNATE_CONFIG_DISCRIMINATOR.to_vec();
        alternate_data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
        let alternate_config = Self::new_data(&mut ctx, program_id, &alternate_data);

        let mint = Keypair::new().pubkey();
        ctx.create_mint()
            .pubkey(mint)
            .decimals(MINT_DECIMALS)
            .create()
            .unwrap();

        let token_account = Keypair::new().pubkey();
        ctx.create_token_account()
            .pubkey(token_account)
            .mint(mint)
            .token_owner(recipient.pubkey())
            .amount(TOKEN_AMOUNT)
            .create()
            .unwrap();

        let pool_state = Self::new_data(
            &mut ctx,
            program_id,
            &Self::pool_state_data(mint, CLAIM_AMOUNT),
        );

        let mut source_trader_data = TRADER_STATE_DISCRIMINATOR.to_vec();
        source_trader_data.extend_from_slice(authority.pubkey().as_ref());
        source_trader_data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
        let source_trader = Self::new_data(&mut ctx, program_id, &source_trader_data);

        let mut destination_trader_data = TRADER_STATE_DISCRIMINATOR.to_vec();
        destination_trader_data.extend_from_slice(Pubkey::new_unique().as_ref());
        destination_trader_data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
        let destination_trader = Self::new_data(&mut ctx, program_id, &destination_trader_data);

        let linked_target =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));
        let linked_target_alt =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));
        let linked_source = Self::new_data(
            &mut ctx,
            program_id,
            &Self::linked_state_data(linked_target, CLAIM_AMOUNT),
        );
        let _linked_source_alt = Self::new_data(
            &mut ctx,
            program_id,
            &Self::linked_state_data(linked_target_alt, CLAIM_AMOUNT),
        );

        let price = Self::new_data(&mut ctx, program_id, &Self::price_state_data(CLAIM_AMOUNT));
        let price_alt = Self::new_data(&mut ctx, program_id, &Self::price_state_data(CLAIM_AMOUNT));
        let value_source = Self::new_data(
            &mut ctx,
            program_id,
            &Self::value_source_state_data(price, CLAIM_AMOUNT),
        );
        let _value_source_alt = Self::new_data(
            &mut ctx,
            program_id,
            &Self::value_source_state_data(price_alt, CLAIM_AMOUNT),
        );

        let root_child =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));
        let _root_child_alt =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));
        let root = Self::new_data(
            &mut ctx,
            program_id,
            &Self::root_state_data(root_child, CLAIM_AMOUNT),
        );

        let pair_root =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));
        let pair_root_alt =
            Self::new_data(&mut ctx, program_id, &Self::target_state_data(CLAIM_AMOUNT));

        let pair_left = Keypair::new().pubkey();
        let pair_right = Keypair::new().pubkey();
        Self::new_data_at(
            &mut ctx,
            pair_left,
            program_id,
            &Self::pair_left_state_data(pair_right, pair_root, CLAIM_AMOUNT),
        );
        Self::new_data_at(
            &mut ctx,
            pair_right,
            program_id,
            &Self::pair_right_state_data(pair_left, pair_root, CLAIM_AMOUNT),
        );

        let pair_left_alt = Keypair::new().pubkey();
        let pair_right_alt = Keypair::new().pubkey();
        Self::new_data_at(
            &mut ctx,
            pair_left_alt,
            program_id,
            &Self::pair_left_state_data(pair_right_alt, pair_root_alt, CLAIM_AMOUNT),
        );
        Self::new_data_at(
            &mut ctx,
            pair_right_alt,
            program_id,
            &Self::pair_right_state_data(pair_left_alt, pair_root_alt, CLAIM_AMOUNT),
        );

        let shared_left = Keypair::new().pubkey();
        let shared_right = Keypair::new().pubkey();
        Self::new_data_at(
            &mut ctx,
            shared_left,
            program_id,
            &Self::pair_left_state_data(Pubkey::default(), pair_root, CLAIM_AMOUNT),
        );
        Self::new_data_at(
            &mut ctx,
            shared_right,
            program_id,
            &Self::pair_right_state_data(Pubkey::default(), pair_root, CLAIM_AMOUNT),
        );

        let shared_left_alt = Keypair::new().pubkey();
        let shared_right_alt = Keypair::new().pubkey();
        Self::new_data_at(
            &mut ctx,
            shared_left_alt,
            program_id,
            &Self::pair_left_state_data(Pubkey::default(), pair_root_alt, CLAIM_AMOUNT),
        );
        Self::new_data_at(
            &mut ctx,
            shared_right_alt,
            program_id,
            &Self::pair_right_state_data(Pubkey::default(), pair_root_alt, CLAIM_AMOUNT),
        );

        Self::new_data_at(
            &mut ctx,
            EXPECTED_SEMANTIC_CONTEXT,
            program_id,
            &Self::target_state_data(CLAIM_AMOUNT),
        );
        Self::new_data_at(
            &mut ctx,
            ALT_SEMANTIC_CONTEXT,
            program_id,
            &Self::target_state_data(CLAIM_AMOUNT),
        );
        let semantic_state = Self::new_data(
            &mut ctx,
            program_id,
            &Self::semantic_state_data(EXPECTED_SEMANTIC_CONTEXT, CLAIM_AMOUNT),
        );
        let _semantic_state_alt = Self::new_data(
            &mut ctx,
            program_id,
            &Self::semantic_state_data(ALT_SEMANTIC_CONTEXT, CLAIM_AMOUNT),
        );

        let authority_state = Self::new_data(
            &mut ctx,
            program_id,
            &Self::authority_state_data(authority.pubkey(), CLAIM_AMOUNT),
        );

        // T4: gate starts on the slow path (fast_path = 0), so the first time `read_gated_config`
        // is probed the CC-1 owner check is present and a mutated owner is rejected — the old
        // probe-once gate burned its single probe here. `action_set_gate_fast_path` flips the flag
        // to reach the fast-path state where the check is dropped and the mutation survives.
        let gate = Self::new_data(&mut ctx, program_id, &Self::gate_state_data(0));
        let gated_config = Self::new_data(
            &mut ctx,
            program_id,
            &Self::gated_config_state_data(CLAIM_AMOUNT),
        );

        // CC-13: a system-owned account forwarded into a system-transfer CPI.
        let cpi_dest = Keypair::new().pubkey();
        ctx.create_account()
            .pubkey(cpi_dest)
            .lamports(1_000_000)
            .owner(system_program::id())
            .owner_unverified()
            .create()
            .unwrap();

        let vault = Keypair::new().pubkey();
        ctx.create_account()
            .pubkey(vault)
            .lamports(INITIAL_VAULT_BALANCE)
            .owner(program_id)
            .owner_unverified()
            .create()
            .unwrap();

        Self {
            ctx,
            program_id,
            fee_payer,
            recipient,
            authority,
            cosigner,
            vault,
            program_config,
            state,
            foreign_config,
            tiny_config,
            inert,
            pda_config,
            pda_authority,
            inert_pda,
            writable_config,
            typed_config,
            alternate_config,
            mint,
            token_account,
            pool_state,
            source_trader,
            destination_trader,
            linked_source,
            linked_target,
            value_source,
            price,
            root,
            root_child,
            pair_root,
            pair_left,
            pair_right,
            shared_left,
            shared_right,
            semantic_state,
            authority_state,
            gate,
            gated_config,
            cpi_dest,
        }
    }

    fn new_data(ctx: &mut TestContext, owner: Pubkey, data: &[u8]) -> Pubkey {
        let pubkey = Keypair::new().pubkey();
        ctx.create_account()
            .pubkey(pubkey)
            .lamports(1_000_000)
            .owner(owner)
            .data(data)
            .create()
            .unwrap();
        pubkey
    }

    fn new_data_at(ctx: &mut TestContext, pubkey: Pubkey, owner: Pubkey, data: &[u8]) {
        ctx.create_account()
            .pubkey(pubkey)
            .lamports(1_000_000)
            .owner(owner)
            .data(data)
            .create()
            .unwrap();
    }

    fn linked_state_data(target: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = LINKED_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(target.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn target_state_data(amount: u64) -> Vec<u8> {
        let mut data = TARGET_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn pool_state_data(lp_mint: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = POOL_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(lp_mint.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn value_source_state_data(price: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = VALUE_SOURCE_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(price.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn price_state_data(price: u64) -> Vec<u8> {
        let mut data = PRICE_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&price.to_le_bytes());
        data
    }

    fn root_state_data(child: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = ROOT_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(child.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn pair_left_state_data(right: Pubkey, root: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = PAIR_LEFT_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(right.as_ref());
        data.extend_from_slice(root.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn pair_right_state_data(left: Pubkey, root: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = PAIR_RIGHT_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(left.as_ref());
        data.extend_from_slice(root.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn semantic_state_data(context: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = SEMANTIC_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(context.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn authority_state_data(authority: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = AUTHORITY_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(authority.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    fn gate_state_data(fast_path: u8) -> Vec<u8> {
        let mut data = GATE_STATE_DISCRIMINATOR.to_vec();
        data.push(fast_path);
        data
    }

    fn gated_config_state_data(amount: u64) -> Vec<u8> {
        let mut data = GATED_CONFIG_STATE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    }

    // ---- CC-1 owner-check paths (typed API; config accounts are read-only) ----

    pub fn action_claim_airdrop(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ClaimAirdrop {})
            .accounts(accounts::ClaimAirdrop {
                recipient: self.recipient.pubkey(),
                config: self.program_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_claim_with_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ClaimWithOwnerCheck {})
            .accounts(accounts::ClaimWithOwnerCheck {
                recipient: self.recipient.pubkey(),
                config: self.program_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_state_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadStateNoCheck {})
            .accounts(accounts::ReadStateNoCheck {
                recipient: self.recipient.pubkey(),
                state: self.state,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_foreign_owned_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadForeignOwnedNoCheck {})
            .accounts(accounts::ReadForeignOwnedNoCheck {
                recipient: self.recipient.pubkey(),
                config: self.foreign_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_foreign_owned_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadForeignOwnedWithCheck {})
            .accounts(accounts::ReadForeignOwnedWithCheck {
                recipient: self.recipient.pubkey(),
                config: self.foreign_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_tiny_config_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTinyConfigNoCheck {})
            .accounts(accounts::ReadTinyConfigNoCheck {
                recipient: self.recipient.pubkey(),
                config: self.tiny_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_with_inert_account(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::WithInertAccount {})
            .accounts(accounts::WithInertAccount {
                recipient: self.recipient.pubkey(),
                inert: self.inert,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pda_config_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPdaConfigNoCheck {})
            .accounts(accounts::ReadPdaConfigNoCheck {
                recipient: self.recipient.pubkey(),
                config: self.pda_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pda_config_with_pda_check_no_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPdaConfigWithPdaCheckNoOwnerCheck {})
            .accounts(accounts::ReadPdaConfigWithPdaCheckNoOwnerCheck {
                recipient: self.recipient.pubkey(),
                config: self.pda_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pda_config_with_owner_and_pda_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPdaConfigWithOwnerAndPdaCheck {})
            .accounts(accounts::ReadPdaConfigWithOwnerAndPdaCheck {
                recipient: self.recipient.pubkey(),
                config: self.pda_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_use_pda_authority_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::UsePdaAuthorityNoCheck {})
            .accounts(accounts::UsePdaAuthorityNoCheck {
                recipient: self.recipient.pubkey(),
                authority: self.pda_authority,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_use_pda_authority_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::UsePdaAuthorityWithCheck {})
            .accounts(accounts::UsePdaAuthorityWithCheck {
                recipient: self.recipient.pubkey(),
                authority: self.pda_authority,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_use_pda_authority_key_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::UsePdaAuthorityKeyNoCheck {})
            .accounts(accounts::UsePdaAuthorityKeyNoCheck {
                recipient: self.recipient.pubkey(),
                authority: self.pda_authority,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_with_inert_pda_account(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::WithInertPdaAccount {})
            .accounts(accounts::WithInertPdaAccount {
                recipient: self.recipient.pubkey(),
                inert_pda: self.inert_pda,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_writable_config_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadWritableConfigNoCheck {})
            .accounts(accounts::ReadWritableConfigNoCheck {
                recipient: self.recipient.pubkey(),
                config: self.writable_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- Token owner and mint-relation paths ----

    pub fn action_read_mint_no_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadMintNoOwnerCheck {})
            .accounts(accounts::ReadMintNoOwnerCheck {
                recipient: self.recipient.pubkey(),
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_mint_with_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadMintWithOwnerCheck {})
            .accounts(accounts::ReadMintWithOwnerCheck {
                recipient: self.recipient.pubkey(),
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_token_account_no_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTokenAccountNoOwnerCheck {})
            .accounts(accounts::ReadTokenAccountNoOwnerCheck {
                recipient: self.recipient.pubkey(),
                token_account: self.token_account,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_token_account_with_owner_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTokenAccountWithOwnerCheck {})
            .accounts(accounts::ReadTokenAccountWithOwnerCheck {
                recipient: self.recipient.pubkey(),
                token_account: self.token_account,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_token_with_mint_no_mint_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTokenWithMintNoMintCheck {})
            .accounts(accounts::ReadTokenWithMintNoMintCheck {
                recipient: self.recipient.pubkey(),
                token_account: self.token_account,
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_token_with_mint_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTokenWithMintCheck {})
            .accounts(accounts::ReadTokenWithMintCheck {
                recipient: self.recipient.pubkey(),
                token_account: self.token_account,
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_lp_pair_no_canonical_mint_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadLpPairNoCanonicalMintCheck {})
            .accounts(accounts::ReadLpPairNoCanonicalMintCheck {
                recipient: self.recipient.pubkey(),
                pool_state: self.pool_state,
                token_account: self.token_account,
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_lp_pair_with_canonical_mint_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadLpPairWithCanonicalMintCheck {})
            .accounts(accounts::ReadLpPairWithCanonicalMintCheck {
                recipient: self.recipient.pubkey(),
                pool_state: self.pool_state,
                token_account: self.token_account,
                mint: self.mint,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_token_without_mint_relation_context(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTokenWithoutMintRelationContext {})
            .accounts(accounts::ReadTokenWithoutMintRelationContext {
                recipient: self.recipient.pubkey(),
                token_account: self.token_account,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- CC-5 type-tag paths (typed Config account) ----

    pub fn action_read_typed_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTypedNoCheck {})
            .accounts(accounts::ReadTypedNoCheck {
                recipient: self.recipient.pubkey(),
                config: self.typed_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_optional_typed_config(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadOptionalTypedConfig {})
            .accounts(accounts::ReadOptionalTypedConfig {
                recipient: self.recipient.pubkey(),
                config: self.typed_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_allowed_type_no_expected_type_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadAllowedTypeNoExpectedTypeCheck {})
            .accounts(accounts::ReadAllowedTypeNoExpectedTypeCheck {
                recipient: self.recipient.pubkey(),
                config: self.alternate_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_transfer_between_traders_no_cross_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::TransferBetweenTradersNoCrossCheck {})
            .accounts(accounts::TransferBetweenTradersNoCrossCheck {
                recipient: self.recipient.pubkey(),
                authority: self.authority.pubkey(),
                source_trader: self.source_trader,
                destination_trader: self.destination_trader,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient, &*self.authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- CC-7 / CC-9 relation paths ----

    pub fn action_read_linked_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadLinkedNoCheck {})
            .accounts(accounts::ReadLinkedNoCheck {
                recipient: self.recipient.pubkey(),
                source: self.linked_source,
                target: self.linked_target,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_linked_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadLinkedWithCheck {})
            .accounts(accounts::ReadLinkedWithCheck {
                recipient: self.recipient.pubkey(),
                source: self.linked_source,
                target: self.linked_target,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_price_ref_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPriceRefNoCheck {})
            .accounts(accounts::ReadPriceRefNoCheck {
                recipient: self.recipient.pubkey(),
                source: self.value_source,
                price: self.price,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_price_ref_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPriceRefWithCheck {})
            .accounts(accounts::ReadPriceRefWithCheck {
                recipient: self.recipient.pubkey(),
                source: self.value_source,
                price: self.price,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_root_child_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadRootChildNoCheck {})
            .accounts(accounts::ReadRootChildNoCheck {
                recipient: self.recipient.pubkey(),
                root: self.root,
                child: self.root_child,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_root_child_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadRootChildWithCheck {})
            .accounts(accounts::ReadRootChildWithCheck {
                recipient: self.recipient.pubkey(),
                root: self.root,
                child: self.root_child,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pair_bidirectional_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPairBidirectionalNoCheck {})
            .accounts(accounts::ReadPairBidirectionalNoCheck {
                recipient: self.recipient.pubkey(),
                left: self.pair_left,
                right: self.pair_right,
                root: self.pair_root,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pair_bidirectional_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPairBidirectionalWithCheck {})
            .accounts(accounts::ReadPairBidirectionalWithCheck {
                recipient: self.recipient.pubkey(),
                left: self.pair_left,
                right: self.pair_right,
                root: self.pair_root,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pair_shared_root_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPairSharedRootNoCheck {})
            .accounts(accounts::ReadPairSharedRootNoCheck {
                recipient: self.recipient.pubkey(),
                left: self.shared_left,
                right: self.shared_right,
                root: self.pair_root,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_pair_shared_root_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPairSharedRootWithCheck {})
            .accounts(accounts::ReadPairSharedRootWithCheck {
                recipient: self.recipient.pubkey(),
                left: self.shared_left,
                right: self.shared_right,
                root: self.pair_root,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_consume_semantic_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ConsumeSemanticNoCheck {})
            .accounts(accounts::ConsumeSemanticNoCheck {
                recipient: self.recipient.pubkey(),
                semantic: self.semantic_state,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_consume_semantic_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ConsumeSemanticWithCheck {})
            .accounts(accounts::ConsumeSemanticWithCheck {
                recipient: self.recipient.pubkey(),
                semantic: self.semantic_state,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_withdraw_authority_no_authority_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::WithdrawAuthorityNoAuthorityCheck {})
            .accounts(accounts::WithdrawAuthorityNoAuthorityCheck {
                recipient: self.recipient.pubkey(),
                authority: self.authority.pubkey(),
                state: self.authority_state,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_withdraw_authority_with_authority_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::WithdrawAuthorityWithAuthorityCheck {})
            .accounts(accounts::WithdrawAuthorityWithAuthorityCheck {
                recipient: self.recipient.pubkey(),
                authority: self.authority.pubkey(),
                state: self.authority_state,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_typed_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadTypedWithCheck {})
            .accounts(accounts::ReadTypedWithCheck {
                recipient: self.recipient.pubkey(),
                config: self.typed_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- CC-2 sysvar paths (Clock read from a passed account) ----

    pub fn action_read_clock_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadClockNoCheck {})
            .accounts(accounts::ReadClockNoCheck {
                recipient: self.recipient.pubkey(),
                clock: Clock::id(),
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_read_clock_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadClockWithCheck {})
            .accounts(accounts::ReadClockWithCheck {
                recipient: self.recipient.pubkey(),
                clock: Clock::id(),
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- CC-4 signer paths (raw_call so the authority is a signer in the account meta) ----

    pub fn action_withdraw_no_signer_check(&mut self) -> bool {
        let data = instruction::WithdrawNoSignerCheck {}.data();
        let accounts = vec![
            AccountMeta::new(self.recipient.pubkey(), false),
            AccountMeta::new_readonly(self.authority.pubkey(), true),
            AccountMeta::new(self.vault, false),
        ];
        let (fee_payer, authority) = (self.fee_payer.clone(), self.authority.clone());
        self.send_raw(data, accounts, &[&*fee_payer, &*authority])
    }

    pub fn action_withdraw_with_signer_check(&mut self) -> bool {
        let data = instruction::WithdrawWithSignerCheck {}.data();
        let accounts = vec![
            AccountMeta::new(self.recipient.pubkey(), false),
            AccountMeta::new_readonly(self.authority.pubkey(), true),
            AccountMeta::new(self.vault, false),
        ];
        let (fee_payer, authority) = (self.fee_payer.clone(), self.authority.clone());
        self.send_raw(data, accounts, &[&*fee_payer, &*authority])
    }

    pub fn action_withdraw_multisig_one_unchecked(&mut self) -> bool {
        let data = instruction::WithdrawMultisigOneUnchecked {}.data();
        let accounts = vec![
            AccountMeta::new(self.recipient.pubkey(), false),
            AccountMeta::new_readonly(self.authority.pubkey(), true), // admin (checked)
            AccountMeta::new_readonly(self.cosigner.pubkey(), true),  // cosigner (unchecked)
            AccountMeta::new(self.vault, false),
        ];
        let (fee_payer, authority, cosigner) = (
            self.fee_payer.clone(),
            self.authority.clone(),
            self.cosigner.clone(),
        );
        self.send_raw(data, accounts, &[&*fee_payer, &*authority, &*cosigner])
    }

    // ---- T4 state-conditional owner check: probe-once decouple demo (J.1#1) ----
    // `read_gated_config`'s CC-1 owner check on `config` is present only while the gate's fast_path
    // flag is 0. The fuzzer first reaches it in the slow-path state (check present, mutated owner
    // rejected) — the old single-state probe burned its slot there. `set_gate_fast_path` flips the
    // gate, changing the instruction's pre-state signature so the state-keyed probe re-probes the
    // fast-path state, where the owner check is gone and the CC-1 mutation survives.

    pub fn action_read_gated_config(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadGatedConfig {})
            .accounts(accounts::ReadGatedConfig {
                recipient: self.recipient.pubkey(),
                gate: self.gate,
                config: self.gated_config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_set_gate_fast_path(&mut self, fast_path: u8) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::SetGateFastPath { fast_path })
            .accounts(accounts::SetGateFastPath {
                recipient: self.recipient.pubkey(),
                gate: self.gate,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // ---- CC-13: forward an account into a downstream CPI ----

    pub fn action_forward_to_cpi_no_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ForwardToCpiNoCheck {})
            .accounts(accounts::ForwardToCpiNoCheck {
                payer: self.recipient.pubkey(),
                dest: self.cpi_dest,
                system_program: system_program::ID,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_forward_to_cpi_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ForwardToCpiWithCheck {})
            .accounts(accounts::ForwardToCpiWithCheck {
                payer: self.recipient.pubkey(),
                dest: self.cpi_dest,
                system_program: system_program::ID,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    fn send_raw(&mut self, data: Vec<u8>, accounts: Vec<AccountMeta>, signers: &[&Keypair]) -> bool {
        self.ctx
            .raw_call(Instruction {
                program_id: self.program_id,
                accounts,
                data,
            })
            .signers(signers)
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

/// Payouts only move lamports from the vault to the recipient, so their sum is conserved.
#[invariant_test]
fn invariant_test(fixture: &mut OwnerMutationAirdropFixture) {
    let vault = fixture
        .ctx
        .get_account(&fixture.vault)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let recipient = fixture
        .ctx
        .get_account(&fixture.recipient.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    fuzz_assert_eq!(
        vault + recipient,
        INITIAL_VAULT_BALANCE + INITIAL_RECIPIENT_BALANCE,
        "vault + recipient lamports must be conserved by payouts"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_actions_succeed() {
        let mut fixture = OwnerMutationAirdropFixture::setup();
        assert_eq!(
            instruction::ConsumeSemanticNoCheck {}.data()[..8],
            [93, 197, 193, 73, 47, 57, 141, 90]
        );
        let result = fixture
            .ctx
            .program(fixture.program_id)
            .call(instruction::ConsumeSemanticNoCheck {})
            .accounts(accounts::ConsumeSemanticNoCheck {
                recipient: fixture.recipient.pubkey(),
                semantic: fixture.semantic_state,
                vault: fixture.vault,
            })
            .signers(&[&*fixture.fee_payer, &*fixture.recipient])
            .send()
            .unwrap();
        assert!(result.is_success(), "{result:?}");

        let mut fixture = OwnerMutationAirdropFixture::setup();
        let result = fixture
            .ctx
            .program(fixture.program_id)
            .call(instruction::ConsumeSemanticWithCheck {})
            .accounts(accounts::ConsumeSemanticWithCheck {
                recipient: fixture.recipient.pubkey(),
                semantic: fixture.semantic_state,
                vault: fixture.vault,
            })
            .signers(&[&*fixture.fee_payer, &*fixture.recipient])
            .send()
            .unwrap();
        assert!(result.is_success(), "{result:?}");
    }

    /// CC-13: forwarding `dest` into a system-transfer CPI without validating it is flagged; the
    /// with-check variant (validates `dest.owner` first) is not.
    #[test]
    fn forward_to_cpi_flags_unvalidated_forwarded_account() {
        let mut fixture = OwnerMutationAirdropFixture::setup();
        fixture.ctx.enable_account_mutation();
        crucible_test_context::reset_probed_account_mutations();
        let _ = crucible_test_context::take_violation();

        assert!(fixture.action_forward_to_cpi_no_check());
        let violation = crucible_test_context::take_violation()
            .expect("expected a CC-13 forwarded-account finding");
        assert!(
            violation.contains("[CC-13 forwarded-account]"),
            "unexpected violation: {violation}"
        );

        let mut fixture = OwnerMutationAirdropFixture::setup();
        fixture.ctx.enable_account_mutation();
        crucible_test_context::reset_probed_account_mutations();
        let _ = crucible_test_context::take_violation();

        assert!(fixture.action_forward_to_cpi_with_check());
        assert!(
            !crucible_test_context::has_violation(),
            "with-check must not flag: {:?}",
            crucible_test_context::take_violation()
        );
    }

    /// T4: the missing owner check on `read_gated_config` is reachable only in the gate's fast-path
    /// state. The state-keyed probe burns no slot — toggling the gate re-probes the new state and
    /// flags the CC-1 owner bug that the old probe-once gate would have missed.
    #[test]
    fn read_gated_config_reprobed_after_fast_path_toggle() {
        let mut fixture = OwnerMutationAirdropFixture::setup();
        fixture.ctx.enable_account_mutation();
        crucible_test_context::reset_probed_account_mutations();
        let _ = crucible_test_context::take_violation();

        // Slow path: owner check present -> nothing flagged.
        assert!(fixture.action_read_gated_config());
        assert!(
            !crucible_test_context::has_violation(),
            "slow-path read should not flag: {:?}",
            crucible_test_context::take_violation()
        );

        // Toggle to the fast path, then re-probe: the owner check is gone -> CC-1 finding.
        assert!(fixture.action_set_gate_fast_path(1));
        assert!(fixture.action_read_gated_config());
        let violation = crucible_test_context::take_violation()
            .expect("expected a CC-1 owner finding in the fast-path state");
        assert!(
            violation.contains("[CC-1 owner]"),
            "unexpected violation: {violation}"
        );
    }
}
