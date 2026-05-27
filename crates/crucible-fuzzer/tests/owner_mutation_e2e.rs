//! End-to-end regression for owner mutation through a generated fuzz harness.
//!
//! The external SBPF program models a small airdrop: a program-owned config
//! account defines the claim amount, and a program-owned vault funds the
//! recipient. The intentional bug is that the program reads the config data
//! without verifying that the config account is still owned by the program.

#![allow(unexpected_cfgs)]

use crucible_fuzzer::anchor_lang::solana_program::system_program;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

const CLAIM_AMOUNT: u64 = 10_000;
const INITIAL_RECIPIENT_BALANCE: u64 = 1_000_000;
const INITIAL_VAULT_BALANCE: u64 = 1_000_000_000;

#[derive(Clone)]
struct OwnerMutationAirdropFixture {
    ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Rc<Keypair>,
    recipient: Rc<Keypair>,
    config: Pubkey,
    vault: Pubkey,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_airdrop_program() -> PathBuf {
    let example_dir = project_root().join("examples/owner-mutation-airdrop");
    let manifest_path = example_dir.join("programs/owner-mutation-airdrop/Cargo.toml");
    let so_path = example_dir.join("target/deploy/owner_mutation_airdrop.so");

    let output = Command::new("cargo")
        .current_dir(&example_dir)
        .args(["build-sbf", "--tools-version", "v1.54", "--manifest-path"])
        .arg(&manifest_path)
        .output()
        .expect("failed to run cargo build-sbf");

    if !output.status.success() {
        panic!(
            "cargo build-sbf failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert!(
        so_path.exists(),
        "expected built program at {}",
        so_path.display()
    );
    so_path
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("path must be UTF-8")
}

#[fuzz_fixture]
impl OwnerMutationAirdropFixture {
    pub fn setup() -> Self {
        let _ = crucible_test_context::take_violation();

        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(owner_mutation_airdrop::ID.to_bytes());
        let program_so = build_airdrop_program();
        let fee_payer = Rc::new(Keypair::new());
        let recipient = Rc::new(Keypair::new());
        let config = Keypair::new().pubkey();
        let vault = Keypair::new().pubkey();

        ctx.add_program(&program_id, path_str(&program_so)).unwrap();
        ctx.enable_owner_mutation();
        ctx.set_owner_mutation_sample_rate(1);

        ctx.create_account()
            .pubkey(fee_payer.pubkey())
            .lamports(INITIAL_RECIPIENT_BALANCE)
            .owner(system_program::id())
            .owner_unverified()
            .create()
            .unwrap();

        ctx.create_account()
            .pubkey(recipient.pubkey())
            .lamports(INITIAL_RECIPIENT_BALANCE)
            .owner(system_program::id())
            .owner_unverified()
            .create()
            .unwrap();

        ctx.create_account()
            .pubkey(config)
            .lamports(1_000_000)
            .owner(program_id)
            .data(&CLAIM_AMOUNT.to_le_bytes())
            .create()
            .unwrap();

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
            config,
            vault,
        }
    }

    pub fn action_claim_airdrop(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(owner_mutation_airdrop::instruction::ClaimAirdrop {})
            .accounts(owner_mutation_airdrop::accounts::ClaimAirdrop {
                recipient: self.recipient.pubkey(),
                config: self.config,
                vault: self.vault,
            })
            .signers(&[&*self.fee_payer, &*self.recipient])
            .send()
            .map(|outcome| outcome.is_success())
            .unwrap_or(false)
    }
}

#[invariant_test]
fn owner_mutation_airdrop_invariant(_fixture: &mut OwnerMutationAirdropFixture) {}

#[test]
fn owner_mutation_harness_finds_missing_airdrop_owner_check() {
    let mut fixture = OwnerMutationAirdropFixture::setup();

    owner_mutation_airdrop_invariant(
        &mut fixture,
        vec![
            __owner_mutation_airdrop_fixture_fuzz::OwnerMutationAirdropFixtureActions::ClaimAirdrop,
        ],
    );

    let violation = crucible_test_context::take_violation()
        .expect("owner mutation should flag the missing config owner check");

    assert!(violation.contains("owner mutation succeeded"));
    assert!(violation.contains(&fixture.config.to_string()));

    let recipient_balance = fixture
        .ctx
        .get_account(&fixture.recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(recipient_balance, INITIAL_RECIPIENT_BALANCE + CLAIM_AMOUNT);

    let config_owner = fixture.ctx.get_account(&fixture.config).unwrap().owner;
    assert_eq!(config_owner, fixture.program_id);
}
