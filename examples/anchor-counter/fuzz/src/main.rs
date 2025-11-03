
/// Testing Begins
use anchor_counter::{Counter, ID as PROGRAM_ID, accounts, instruction};
use anchor_test_context::TestContext;
use anchor_test_context::AccountBuilderBase;
use anchor_test::anchor_fuzz;  
use arbitrary::Arbitrary;
use solana_sdk::{signature::Keypair, system_program, pubkey::Pubkey};
use solana_sdk::signature::Signer;

struct CounterFixture {
    ctx: TestContext,
    counter_pda: Pubkey,
    program_id: Pubkey,
    payer: Keypair,
}

impl CounterFixture {
    pub fn setup() -> Self {
        let program_id = Pubkey::new_from_array(PROGRAM_ID.to_bytes());
        let ctx = TestContext::new();
        ctx.add_program(&program_id, "../target/deploy/anchor_counter.so").unwrap();

        let payer = Keypair::new();
        // Create payer account
        ctx.create_account()
            .pubkey(payer.pubkey())
            .lamports(10_000_000)
            .owner(system_program::id())
            .create()
            .unwrap();
        // Derive counter PDA
        let (counter_pda, _) = Pubkey::find_program_address(&[b"counter"], &program_id);
        // Initialize counter
        let res = ctx.program(program_id)
            .call(instruction::Initialize {})
            .accounts(accounts::Initialize {
                counter: counter_pda,
                payer: payer.pubkey(),
                system_program: system_program::id(),
            })
            .signers(&[&payer])
            .send()
            .unwrap();
        Self { ctx, counter_pda, program_id, payer }
    }
    // ===== ACTIONS =====
    pub fn increment(&mut self) {
        let result = self.ctx
            .program(self.program_id)
            .call(instruction::Increment {})
            .accounts(accounts::Update {
                counter: self.counter_pda,
            })
            .signers(&[&self.payer])
            .send()
            .unwrap();
    }
    pub fn decrement(&mut self) {
        self.ctx
            .program(self.program_id)
            .call(instruction::Decrement {})
            .accounts(accounts::Update {
                counter: self.counter_pda,
            })
            .signers(&[&self.payer])
            .send()
            .unwrap();
    }
}

// Basic unit test using fixture
#[test]
fn test_increment() {
    let mut fixture = CounterFixture::setup();
    fixture.increment();
    fixture.increment();
    fixture.increment();
    let mut counter = fixture.ctx
        .read_anchor_account::<Counter>(&fixture.counter_pda)
        .unwrap();
    assert_eq!(counter.count, 3);
}

#[derive(Arbitrary, Debug, Clone)]
enum Action {
    Increment,
    Decrement,
}

#[anchor_fuzz(setup=CounterFixture::setup, runs=256)]
fn fuzz_increment(fixture: &mut CounterFixture, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::Increment => fixture.increment(),
            Action::Decrement => fixture.decrement(),
        }
    }
}
