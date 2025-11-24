use marginfi_program::*;
use anchor_test::*;
use solana_sdk::{signature::Keypair, system_program, pubkey::Pubkey, signature::Signer};
use std::rc::Rc;

#[derive(Clone)]
struct MarginfiFixture {
    ctx: TestContext,
    program_id: Pubkey,
    // TODO: Add your state here (users, accounts, etc.)
}

#[fuzz_fixture]
impl MarginfiFixture {
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        
        // Load program
        ctx.add_program(&program_id, "target/deploy/marginfi.so").unwrap();
        
        Self { ctx, program_id }
    }

    /// ACTIONS - need at least one action for the macro to work
    pub fn action_noop(&mut self) {
        // placeholder
    }
}

#[test]
fn test_basic() {
    let fixture = MarginfiFixture::setup();
}

// Simple single-input fuzz test
#[anchor_fuzz]
fn fuzz_single(fixture: &mut MarginfiFixture, amount: u64) {
    // TODO: Call your actions with the fuzzed input
}

// Stateful invariant test - fuzzer generates random action sequences
#[invariant_test]
fn invariant_test(fixture: &mut MarginfiFixture) {
    // TODO: Add invariant checks that should hold after every action
}
