//! End-to-end regression for the account-mutation engine (CC-1 owner checks).
//!
//! The external SBPF program (`examples/owner-mutation-airdrop`) exposes one instruction per
//! flavor of the missing-owner-check class plus its negatives/edges. Each test enables account
//! mutation, runs one instruction, and asserts whether the engine reports a `[CC-1 owner]`
//! finding. Together they prove both detection power and false-positive discipline.

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
const STATE_AMOUNT: u64 = 5_000;
const FOREIGN_AMOUNT: u64 = 8_000;
const TINY_AMOUNT: u32 = 7_000;
const INITIAL_RECIPIENT_BALANCE: u64 = 1_000_000;
const INITIAL_VAULT_BALANCE: u64 = 1_000_000_000;

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

fn program_id() -> Pubkey {
    Pubkey::new_from_array(owner_mutation_airdrop::ID.to_bytes())
}

fn foreign_owner() -> Pubkey {
    Pubkey::new_from_array(owner_mutation_airdrop::FOREIGN_PROGRAM_ID.to_bytes())
}

/// Shared per-test setup: program loaded, vault funded, recipient + fee payer funded, account
/// mutation enabled, and the per-run probed-instruction set reset so each test probes freshly.
struct Harness {
    ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Keypair,
    recipient: Keypair,
    vault: Pubkey,
}

fn harness() -> Harness {
    let _ = crucible_test_context::take_violation();
    crucible_test_context::reset_probed_account_mutations();

    let mut ctx = TestContext::new();
    let program_id = program_id();
    let program_so = build_airdrop_program();
    ctx.add_program(&program_id, path_str(&program_so)).unwrap();
    ctx.enable_account_mutation();

    let fee_payer = Keypair::new();
    let recipient = Keypair::new();
    let vault = Keypair::new().pubkey();

    for kp in [&fee_payer, &recipient] {
        ctx.create_account()
            .pubkey(kp.pubkey())
            .lamports(INITIAL_RECIPIENT_BALANCE)
            .owner(system_program::id())
            .owner_unverified()
            .create()
            .unwrap();
    }
    ctx.create_account()
        .pubkey(vault)
        .lamports(INITIAL_VAULT_BALANCE)
        .owner(program_id)
        .owner_unverified()
        .create()
        .unwrap();

    Harness {
        ctx,
        program_id,
        fee_payer,
        recipient,
        vault,
    }
}

fn create_data_account(ctx: &mut TestContext, pubkey: Pubkey, owner: Pubkey, data: &[u8]) {
    ctx.create_account()
        .pubkey(pubkey)
        .lamports(1_000_000)
        .owner(owner)
        .data(data)
        .create()
        .unwrap();
}

fn expect_owner_finding(account: Pubkey) {
    let violation = crucible_test_context::take_violation().expect("expected a CC-1 owner finding");
    assert!(
        violation.contains("[CC-1 owner]"),
        "unexpected violation: {violation}"
    );
    assert!(
        violation.contains(&account.to_string()),
        "finding should name account {account}: {violation}"
    );
}

fn expect_no_finding() {
    assert!(
        !crucible_test_context::has_violation(),
        "unexpected finding: {:?}",
        crucible_test_context::take_violation()
    );
}

// ---- CC-1 true positives: the engine must flag a missing owner check ----

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_owner_check_on_program_config() {
    let mut h = harness();
    let config = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ClaimAirdrop {})
        .accounts(owner_mutation_airdrop::accounts::ClaimAirdrop {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_owner_finding(config);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_owner_check_on_second_program_account() {
    let mut h = harness();
    let state = Keypair::new().pubkey();
    create_data_account(&mut h.ctx, state, h.program_id, &STATE_AMOUNT.to_le_bytes());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadStateNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadState {
            recipient: h.recipient.pubkey(),
            state,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_owner_finding(state);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_owner_check_on_foreign_owned_account() {
    let mut h = harness();
    let config = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        config,
        foreign_owner(),
        &FOREIGN_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadForeignOwnedNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadForeign {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_owner_finding(config);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_owner_check_on_tiny_account() {
    let mut h = harness();
    let config = Keypair::new().pubkey();
    create_data_account(&mut h.ctx, config, h.program_id, &TINY_AMOUNT.to_le_bytes());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTinyConfigNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTiny {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_owner_finding(config);
}

// ---- CC-1 negatives / edges: the engine must NOT flag ----

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_program_owner_check_present() {
    let mut h = harness();
    let config = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ClaimWithOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ClaimAirdrop {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_foreign_owner_check_present() {
    let mut h = harness();
    let config = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        config,
        foreign_owner(),
        &FOREIGN_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadForeignOwnedWithCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadForeign {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_inert_account() {
    let mut h = harness();
    // A data account the program never reads. The relevance gate must mark it inert and skip it.
    let inert = Keypair::new().pubkey();
    create_data_account(&mut h.ctx, inert, h.program_id, &CLAIM_AMOUNT.to_le_bytes());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::WithInertAccount {})
        .accounts(owner_mutation_airdrop::accounts::WithInert {
            recipient: h.recipient.pubkey(),
            inert,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_pda_config() {
    let mut h = harness();
    // PDAs are off-curve and cannot be reassigned by an external signer; engine skips them.
    let (config, _bump) = Pubkey::find_program_address(&[b"config"], &h.program_id);
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadPdaConfigNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadPda {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_writable_config() {
    let mut h = harness();
    // Config is declared writable (but only read); engine excludes writable accounts.
    let config = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadWritableConfigNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadWritable {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

// ---- Integration through the generated #[fuzz_fixture] / #[invariant_test] harness ----

#[derive(Clone)]
struct OwnerMutationAirdropFixture {
    ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Rc<Keypair>,
    recipient: Rc<Keypair>,
    config: Pubkey,
    vault: Pubkey,
}

#[fuzz_fixture]
impl OwnerMutationAirdropFixture {
    pub fn setup() -> Self {
        let _ = crucible_test_context::take_violation();
        crucible_test_context::reset_probed_account_mutations();

        let mut ctx = TestContext::new();
        let program_id = program_id();
        let program_so = build_airdrop_program();
        let fee_payer = Rc::new(Keypair::new());
        let recipient = Rc::new(Keypair::new());
        let config = Keypair::new().pubkey();
        let vault = Keypair::new().pubkey();

        ctx.add_program(&program_id, path_str(&program_so)).unwrap();
        ctx.enable_account_mutation();

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
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
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

    assert!(violation.contains("[CC-1 owner]"), "violation: {violation}");
    assert!(violation.contains(&fixture.config.to_string()));

    let config_owner = fixture.ctx.get_account(&fixture.config).unwrap().owner;
    assert_eq!(config_owner, fixture.program_id);
}
