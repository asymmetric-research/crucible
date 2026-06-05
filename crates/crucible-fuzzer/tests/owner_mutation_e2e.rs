//! End-to-end regression for the account-mutation engine.
//!
//! The external SBPF program (`examples/owner-mutation-airdrop`) exposes one instruction per
//! flavor of the seeded account-constraint classes plus their negatives/edges. Each test enables
//! account mutation, runs one instruction, and asserts the expected CC label. Together they prove
//! both detection power and false-positive discipline.

#![allow(unexpected_cfgs)]

use crucible_fuzzer::anchor_lang::prelude::sysvar::SysvarId;
use crucible_fuzzer::anchor_lang::prelude::Clock;
use crucible_fuzzer::anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use crucible_fuzzer::anchor_lang::solana_program::system_program;
use crucible_fuzzer::anchor_lang::{Discriminator, InstructionData};
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
const TOKEN_AMOUNT: u64 = 9_000;
const MINT_DECIMALS: u8 = 6;
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

// ---- CC-1 negatives / edges ----

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
fn flags_pda_substitution_when_no_derivation_check() {
    let mut h = harness();
    // The CC-3 strategy substitutes a clone at a different address with a different owner.
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

    expect_finding("[CC-3 pda-spoof]", config);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_same_owner_singleton_pda_content_binding() {
    let mut h = harness();
    let (config, _bump) = Pubkey::find_program_address(&[b"singleton"], &h.program_id);
    seed_config(&mut h.ctx, config, h.program_id, CLAIM_AMOUNT);

    h.ctx
        .program(h.program_id)
        .call(
            owner_mutation_airdrop::instruction::ReadSingletonPdaWithOwnerTypeCheckNoDerivationCheck {},
        )
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
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
fn no_finding_when_pda_derivation_checked_without_owner_check() {
    let mut h = harness();
    let (config, _bump) = Pubkey::find_program_address(&[b"config"], &h.program_id);
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadPdaConfigWithPdaCheckNoOwnerCheck {})
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
fn no_finding_when_pda_derivation_and_owner_checked() {
    let mut h = harness();
    let (config, _bump) = Pubkey::find_program_address(&[b"config"], &h.program_id);
    create_data_account(
        &mut h.ctx,
        config,
        h.program_id,
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadPdaConfigWithOwnerAndPdaCheck {})
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
fn flags_pda_address_check_without_data_read() {
    let mut h = harness();
    let (authority, _bump) = Pubkey::find_program_address(&[b"authority"], &h.program_id);
    create_data_account(&mut h.ctx, authority, h.program_id, &[]);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::UsePdaAuthorityNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::UsePdaAuthority {
            recipient: h.recipient.pubkey(),
            authority,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-3 pda-spoof]", authority);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_pda_authority_checked_without_data_read() {
    let mut h = harness();
    let (authority, _bump) = Pubkey::find_program_address(&[b"authority"], &h.program_id);
    create_data_account(&mut h.ctx, authority, h.program_id, &[]);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::UsePdaAuthorityWithCheck {})
        .accounts(owner_mutation_airdrop::accounts::UsePdaAuthority {
            recipient: h.recipient.pubkey(),
            authority,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_key_only_pda_authority_bug() {
    let mut h = harness();
    let (authority, _bump) = Pubkey::find_program_address(&[b"authority"], &h.program_id);
    create_data_account(&mut h.ctx, authority, h.program_id, &[]);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::UsePdaAuthorityKeyNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::UsePdaAuthority {
            recipient: h.recipient.pubkey(),
            authority,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_for_inert_empty_pda_account() {
    let mut h = harness();
    let (inert_pda, _bump) = Pubkey::find_program_address(&[b"inert"], &h.program_id);
    create_data_account(&mut h.ctx, inert_pda, h.program_id, &[]);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::WithInertPdaAccount {})
        .accounts(owner_mutation_airdrop::accounts::WithInertPda {
            recipient: h.recipient.pubkey(),
            inert_pda,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_owner_check_on_writable_config() {
    let mut h = harness();
    // Config is declared writable but only read, so an owner mutation that still succeeds is a
    // conclusive missing-owner-check finding.
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

    expect_owner_finding(config);
}

// ---- Token account owner and mint-relation checks ----

fn seed_mint(ctx: &mut TestContext, pubkey: Pubkey) {
    ctx.create_mint()
        .pubkey(pubkey)
        .decimals(MINT_DECIMALS)
        .create()
        .unwrap();
}

fn seed_token_account(ctx: &mut TestContext, pubkey: Pubkey, mint: Pubkey, owner: Pubkey) {
    ctx.create_token_account()
        .pubkey(pubkey)
        .mint(mint)
        .token_owner(owner)
        .amount(TOKEN_AMOUNT)
        .create()
        .unwrap();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_fake_mint_owner() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadMintNoOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadMint {
            recipient: h.recipient.pubkey(),
            mint,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-token fake-mint-owner]", mint);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_mint_owner_checked() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadMintWithOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadMint {
            recipient: h.recipient.pubkey(),
            mint,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_fake_token_account_owner() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    let token_account = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);
    seed_token_account(&mut h.ctx, token_account, mint, h.recipient.pubkey());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTokenAccountNoOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTokenAccountOnly {
            recipient: h.recipient.pubkey(),
            token_account,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-token fake-account-owner]", token_account);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_token_account_owner_checked() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    let token_account = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);
    seed_token_account(&mut h.ctx, token_account, mint, h.recipient.pubkey());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTokenAccountWithOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTokenAccountOnly {
            recipient: h.recipient.pubkey(),
            token_account,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_wrong_token_mint_relation() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    let token_account = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);
    seed_token_account(&mut h.ctx, token_account, mint, h.recipient.pubkey());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTokenWithMintNoMintCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTokenWithMint {
            recipient: h.recipient.pubkey(),
            token_account,
            mint,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-token wrong-mint]", token_account);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_token_mint_relation_checked() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    let token_account = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);
    seed_token_account(&mut h.ctx, token_account, mint, h.recipient.pubkey());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTokenWithMintCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTokenWithMint {
            recipient: h.recipient.pubkey(),
            token_account,
            mint,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_wrong_mint_probe_without_mint_account() {
    let mut h = harness();
    let mint = Keypair::new().pubkey();
    let token_account = Keypair::new().pubkey();
    seed_mint(&mut h.ctx, mint);
    seed_token_account(&mut h.ctx, token_account, mint, h.recipient.pubkey());

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTokenWithoutMintRelationContext {})
        .accounts(owner_mutation_airdrop::accounts::ReadTokenAccountOnly {
            recipient: h.recipient.pubkey(),
            token_account,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

// ---- CC-4 signer checks ----

fn create_system_account(ctx: &mut TestContext, pubkey: Pubkey) {
    ctx.create_account()
        .pubkey(pubkey)
        .lamports(INITIAL_RECIPIENT_BALANCE)
        .owner(system_program::id())
        .owner_unverified()
        .create()
        .unwrap();
}

fn raw_send(
    ctx: &mut TestContext,
    program_id: Pubkey,
    data: Vec<u8>,
    accounts: Vec<AccountMeta>,
    signers: &[&Keypair],
) {
    ctx.raw_call(Instruction {
        program_id,
        accounts,
        data,
    })
    .signers(signers)
    .send()
    .unwrap();
}

fn expect_signer_finding(account: Pubkey) {
    let violation =
        crucible_test_context::take_violation().expect("expected a CC-4 signer finding");
    assert!(
        violation.contains("[CC-4 signer]"),
        "unexpected violation: {violation}"
    );
    assert!(
        violation.contains(&account.to_string()),
        "finding should name account {account}: {violation}"
    );
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_signer_check() {
    let mut h = harness();
    let authority = Keypair::new();
    let dest = Keypair::new().pubkey();
    create_system_account(&mut h.ctx, authority.pubkey());
    create_system_account(&mut h.ctx, dest);

    let data = owner_mutation_airdrop::instruction::WithdrawNoSignerCheck {}.data();
    let accounts = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(authority.pubkey(), true),
        AccountMeta::new(h.vault, false),
    ];
    raw_send(
        &mut h.ctx,
        h.program_id,
        data,
        accounts,
        &[&h.fee_payer, &authority],
    );

    expect_signer_finding(authority.pubkey());
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_signer_check_present() {
    let mut h = harness();
    let authority = Keypair::new();
    let dest = Keypair::new().pubkey();
    create_system_account(&mut h.ctx, authority.pubkey());
    create_system_account(&mut h.ctx, dest);

    let data = owner_mutation_airdrop::instruction::WithdrawWithSignerCheck {}.data();
    let accounts = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(authority.pubkey(), true),
        AccountMeta::new(h.vault, false),
    ];
    raw_send(
        &mut h.ctx,
        h.program_id,
        data,
        accounts,
        &[&h.fee_payer, &authority],
    );

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_unchecked_cosigner_in_multisig() {
    let mut h = harness();
    let admin = Keypair::new();
    let cosigner = Keypair::new();
    let dest = Keypair::new().pubkey();
    create_system_account(&mut h.ctx, admin.pubkey());
    create_system_account(&mut h.ctx, cosigner.pubkey());
    create_system_account(&mut h.ctx, dest);

    let data = owner_mutation_airdrop::instruction::WithdrawMultisigOneUnchecked {}.data();
    let accounts = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(admin.pubkey(), true),
        AccountMeta::new_readonly(cosigner.pubkey(), true),
        AccountMeta::new(h.vault, false),
    ];
    raw_send(
        &mut h.ctx,
        h.program_id,
        data,
        accounts,
        &[&h.fee_payer, &admin, &cosigner],
    );

    // The unchecked co-signer is flagged; the checked admin is not.
    let violation =
        crucible_test_context::take_violation().expect("expected a CC-4 signer finding");
    assert!(
        violation.contains("[CC-4 signer]"),
        "violation: {violation}"
    );
    assert!(
        violation.contains(&cosigner.pubkey().to_string()),
        "violation: {violation}"
    );
    assert!(
        !violation.contains(&admin.pubkey().to_string()),
        "violation: {violation}"
    );
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn documents_false_positive_for_redundant_cosigner() {
    let mut h = harness();
    let admin = Keypair::new();
    let cosigner = Keypair::new();
    let dest = Keypair::new().pubkey();
    create_system_account(&mut h.ctx, admin.pubkey());
    create_system_account(&mut h.ctx, cosigner.pubkey());
    create_system_account(&mut h.ctx, dest);

    let data = owner_mutation_airdrop::instruction::WithdrawRedundantCosigner {}.data();
    let accounts = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(admin.pubkey(), true),
        AccountMeta::new_readonly(cosigner.pubkey(), true),
        AccountMeta::new(h.vault, false),
    ];
    raw_send(
        &mut h.ctx,
        h.program_id,
        data,
        accounts,
        &[&h.fee_payer, &admin, &cosigner],
    );

    expect_signer_finding(cosigner.pubkey());
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_signer_is_fee_payer() {
    let mut h = harness();
    let dest = Keypair::new().pubkey();
    create_system_account(&mut h.ctx, dest);

    // The only signer in the instruction is the fee payer; the engine must skip it.
    let data = owner_mutation_airdrop::instruction::WithdrawNoSignerCheck {}.data();
    let accounts = vec![
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(h.fee_payer.pubkey(), true),
        AccountMeta::new(h.vault, false),
    ];
    raw_send(&mut h.ctx, h.program_id, data, accounts, &[&h.fee_payer]);

    expect_no_finding();
}

// ---- CC-5 type-tag (typed account discriminator) ----

/// The program-crate path has no IDL-gen `#[ctor]`, so account schemas must be registered explicitly
/// for the type-tag strategy to know discriminator lengths. Process-global + set-once.
fn register_config_schema() {
    if !crucible_test_context::schema::has_schemas() {
        crucible_test_context::register_account_schemas(vec![
            crucible_test_context::AccountSchema {
                type_name: "Config".into(),
                discriminator: owner_mutation_airdrop::Config::DISCRIMINATOR.to_vec(),
                diff_fn: Box::new(|_, _| Vec::new()),
            },
            crucible_test_context::AccountSchema {
                type_name: "AlternateConfig".into(),
                discriminator: owner_mutation_airdrop::AlternateConfig::DISCRIMINATOR.to_vec(),
                diff_fn: Box::new(|_, _| Vec::new()),
            },
            crucible_test_context::AccountSchema {
                type_name: "TraderState".into(),
                discriminator: owner_mutation_airdrop::TraderState::DISCRIMINATOR.to_vec(),
                diff_fn: Box::new(|_, _| Vec::new()),
            },
        ]);
    }
}

fn seed_config(ctx: &mut TestContext, pubkey: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = owner_mutation_airdrop::Config::DISCRIMINATOR.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    create_data_account(ctx, pubkey, owner, &data);
}

fn seed_alternate_config(ctx: &mut TestContext, pubkey: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = owner_mutation_airdrop::AlternateConfig::DISCRIMINATOR.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    create_data_account(ctx, pubkey, owner, &data);
}

fn seed_trader_state(ctx: &mut TestContext, pubkey: Pubkey, owner: Pubkey, authority: Pubkey) {
    let mut data = owner_mutation_airdrop::TraderState::DISCRIMINATOR.to_vec();
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(&CLAIM_AMOUNT.to_le_bytes());
    create_data_account(ctx, pubkey, owner, &data);
}

fn expect_finding(label: &str, account: Pubkey) {
    let violation = crucible_test_context::take_violation()
        .unwrap_or_else(|| panic!("expected a {label} finding"));
    assert!(
        violation.contains(label),
        "unexpected violation: {violation}"
    );
    assert!(
        violation.contains(&account.to_string()),
        "finding should name account {account}: {violation}"
    );
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_missing_type_tag_check() {
    register_config_schema();
    let mut h = harness();
    let config = Keypair::new().pubkey();
    seed_config(&mut h.ctx, config, h.program_id, CLAIM_AMOUNT);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTypedNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
            recipient: h.recipient.pubkey(),
            config,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-5 type-tag]", config);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_type_tag_check_present() {
    register_config_schema();
    let mut h = harness();
    let config = Keypair::new().pubkey();
    seed_config(&mut h.ctx, config, h.program_id, CLAIM_AMOUNT);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadTypedWithCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTypedChecked {
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
fn no_finding_when_optional_type_tag_fallback_noops() {
    register_config_schema();
    let mut h = harness();
    let config = Keypair::new().pubkey();
    seed_config(&mut h.ctx, config, h.program_id, CLAIM_AMOUNT);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadOptionalTypedConfig {})
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
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
fn no_finding_for_valid_but_wrong_type_confusion() {
    register_config_schema();
    let mut h = harness();
    let config = Keypair::new().pubkey();
    seed_alternate_config(&mut h.ctx, config, h.program_id, CLAIM_AMOUNT);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadAllowedTypeNoExpectedTypeCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
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
fn no_finding_for_custom_cross_account_invariant_bug() {
    register_config_schema();
    let mut h = harness();
    let authority = Keypair::new();
    create_system_account(&mut h.ctx, authority.pubkey());
    let source_trader = Keypair::new().pubkey();
    let destination_trader = Keypair::new().pubkey();
    let other_authority = Pubkey::new_unique();
    seed_trader_state(&mut h.ctx, source_trader, h.program_id, authority.pubkey());
    seed_trader_state(
        &mut h.ctx,
        destination_trader,
        h.program_id,
        other_authority,
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::TransferBetweenTradersNoCrossCheck {})
        .accounts(owner_mutation_airdrop::accounts::TransferBetweenTraders {
            recipient: h.recipient.pubkey(),
            authority: authority.pubkey(),
            source_trader,
            destination_trader,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient, &authority])
        .send()
        .unwrap();

    expect_no_finding();
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_first_success_cache_hides_later_present_account_bug() {
    let mut h = harness();
    let placeholder = Keypair::new().pubkey();
    create_data_account(&mut h.ctx, placeholder, system_program::id(), &[]);

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadMaybeConfigNoOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
            recipient: h.recipient.pubkey(),
            config: placeholder,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();
    expect_no_finding();

    let present = Keypair::new().pubkey();
    create_data_account(
        &mut h.ctx,
        present,
        foreign_owner(),
        &CLAIM_AMOUNT.to_le_bytes(),
    );

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadMaybeConfigNoOwnerCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadTyped {
            recipient: h.recipient.pubkey(),
            config: present,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_no_finding();
}

// ---- CC-2 sysvar substitution ----

/// Seed the Clock sysvar with a positive unix_timestamp so the program's `ts > 0` check passes for
/// the real clock (and fails when the relevance gate corrupts it).
fn seed_clock(ctx: &mut TestContext) {
    ctx.set_sysvar(&Clock {
        slot: 10,
        epoch_start_timestamp: 1_700_000_000,
        epoch: 0,
        leader_schedule_epoch: 0,
        unix_timestamp: 1_700_000_000,
    });
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn flags_sysvar_substitution_when_no_identity_check() {
    let mut h = harness();
    seed_clock(&mut h.ctx);
    let clock = Clock::id();

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadClockNoCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadClock {
            recipient: h.recipient.pubkey(),
            clock,
            vault: h.vault,
        })
        .signers(&[&h.fee_payer, &h.recipient])
        .send()
        .unwrap();

    expect_finding("[CC-2 sysvar]", clock);
}

#[test]
#[ignore = "requires cargo-build-sbf / Solana platform tools"]
fn no_finding_when_sysvar_identity_checked() {
    let mut h = harness();
    seed_clock(&mut h.ctx);
    let clock = Clock::id();

    h.ctx
        .program(h.program_id)
        .call(owner_mutation_airdrop::instruction::ReadClockWithCheck {})
        .accounts(owner_mutation_airdrop::accounts::ReadClock {
            recipient: h.recipient.pubkey(),
            clock,
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
