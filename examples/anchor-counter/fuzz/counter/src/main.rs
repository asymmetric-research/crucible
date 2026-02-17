use anchor_counter::*;
use crucible_fuzzer::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use crucible_fuzzer::anchor_lang::system_program;
use std::rc::Rc;

#[derive(Clone)]
struct CounterFixture {
    ctx: TestContext,
    counter_pda: Pubkey,
    program_id: Pubkey,
    payer: Rc<Keypair>,
}

#[fuzz_fixture]
impl CounterFixture {
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        
        ctx.add_program(&program_id, "../../target/deploy/anchor_counter.so").unwrap();

        let payer = Rc::new(Keypair::new());
        
        // Create payer account
        ctx.create_account()
            .pubkey(payer.pubkey())
            .lamports(10_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();
        
        // Derive counter PDA
        let (counter_pda, _) = Pubkey::find_program_address(&[b"counter"], &program_id);
        
        // Initialize counter
        ctx.program(program_id)
            .call(instruction::Initialize {})
            .accounts(accounts::Initialize {
                counter: counter_pda,
                payer: payer.pubkey(),
                system_program: system_program::ID,
            })
            .signers(&[&*payer])
            .send()
            .unwrap();
        
        Self { ctx, counter_pda, program_id, payer }
    }

    // ===== ACTIONS =====
    
    pub fn action_increment(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::Increment {})
            .accounts(accounts::Update {
                counter: self.counter_pda,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_decrement(&mut self) -> bool {
        self.ctx
            .program(self.program_id)
            .call(instruction::Decrement {})
            .accounts(accounts::Update {
                counter: self.counter_pda,
            })
            .signers(&[&*self.payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// Stateful invariant test - fuzzer generates random action sequences automatically
#[invariant_test]
fn invariant_counter(fixture: &mut CounterFixture) {
    // This runs after EACH action in the sequence
    let counter = fixture.ctx
        .read_anchor_account::<Counter>(&fixture.counter_pda)
        .unwrap();
    
    // Example invariant: count should stay below some threshold
    fuzz_assert_lt!(counter.count, 1000, "Counter exceeded max value: {}", counter.count);
}
