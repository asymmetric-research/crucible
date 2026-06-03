//! Fuzz harness for the owner-mutation-airdrop example.
//!
//! It drives the program through every positive (missing-check) and negative (check-present)
//! instruction path. On its own it fuzzes a lamport-conservation invariant; run with
//! `--mutate-accounts` it additionally reports the seeded missing owner (CC-1) and signer (CC-4)
//! checks as `[CC-1 owner]` / `[CC-4 signer]` findings.
//!
//!   crucible run owner-mutation-airdrop invariant_test --release
//!   crucible run owner-mutation-airdrop invariant_test --release --mutate-accounts

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
    pda_config: Pubkey,      // off-curve PDA
    writable_config: Pubkey, // program-owned, declared writable
    typed_config: Pubkey,    // Anchor-discriminated Config account (CC-5 target)
}

#[fuzz_fixture]
impl OwnerMutationAirdropFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(owner_mutation_airdrop::ID.to_bytes());
        ctx.add_program(&program_id, "../../target/deploy/owner_mutation_airdrop.so")
            .unwrap();

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

        let mut typed_data = owner_mutation_airdrop::state::Config::DISCRIMINATOR.to_vec();
        typed_data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
        let typed_config = Self::new_data(&mut ctx, program_id, &typed_data);

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
            writable_config,
            typed_config,
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

    pub fn action_read_pda_config_with_check(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::ReadPdaConfigWithCheck {})
            .accounts(accounts::ReadPdaConfigWithCheck {
                recipient: self.recipient.pubkey(),
                config: self.pda_config,
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
