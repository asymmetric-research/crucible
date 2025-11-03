
/// Testing Begins
use anchor_counter::{Counter, ID as PROGRAM_ID, accounts, instruction};
use anchor_test_context::TestContext;
use anchor_test_context::AccountBuilderBase;
use anchor_test::anchor_fuzz;  
use arbitrary::Arbitrary;
use solana_sdk::{signature::Keypair, system_program, pubkey::Pubkey};
use solana_sdk::signature::Signer;

struct CounterFixture<'a> {
    ctx: &'a mut TestContext,
    counter_pda: Pubkey,
    program_id: Pubkey,
    payer: Keypair,
}

impl<'a> CounterFixture<'a> {
    pub fn setup(ctx: &'a mut TestContext) -> Self {
        let program_id = Pubkey::new_from_array(PROGRAM_ID.to_bytes());
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
        let _ = ctx.program(program_id)
            .call(instruction::Initialize {})
            .accounts(accounts::Initialize {
                counter: counter_pda,
                payer: payer.pubkey(),
                system_program: system_program::id(),
            })
            .signers(&[&payer])
            .send()
            .unwrap()
            .unwrap();
        Self { ctx, counter_pda, program_id, payer }
    }
    // ===== ACTIONS =====
    pub fn increment(&mut self) {
        let _ = self.ctx
            .program(self.program_id)
            .call(instruction::Increment {})
            .accounts(accounts::Update {
                counter: self.counter_pda,
            })
            .signers(&[&self.payer])
            .send()
            .unwrap()
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
            .unwrap()
            .unwrap();
    }
}

// Basic unit test using fixture
#[test]
fn test_increment() {
    let mut ctx = TestContext::new();
    let mut fixture = CounterFixture::setup(&mut ctx);
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

#[anchor_fuzz]
fn fuzz_increment(ctx: &mut TestContext, actions: Vec<Action>) {
    let mut fixture = CounterFixture::setup(ctx);
    for action in actions {
        match action {
            Action::Increment => fixture.increment(),
            Action::Decrement => fixture.decrement(),
        }
    }
}
