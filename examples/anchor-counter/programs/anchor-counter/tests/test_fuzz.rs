// tests/test_counter.rs

use anchor_counter::{Counter, ID as PROGRAM_ID};
use anchor_test::anchor_test;
use anchor_test::anchor_fuzz;

use mollusk_svm::{Mollusk, result::Check};
use solana_sdk::{
    account::Account,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
};
use mollusk_svm::program::keyed_account_for_system_program;
use anchor_test::helpers;
use anchor_test::generator::RangeGenerator;
use anchor_test::generator::InputGenerator;

struct CounterTest {
    mollusk: Mollusk,
    counter_pda: Pubkey,
    counter_bump: u8,
    payer: Keypair,
    counter_account: Account,
    program_id: Pubkey
}

impl CounterTest {
    fn setup() -> Self {
        let program_id = Pubkey::new_from_array(PROGRAM_ID.to_bytes());
        
        let mut mollusk = Mollusk::new(&program_id, "../../target/deploy/anchor_counter");
        
        let payer = Keypair::new();
        let payer_account = helpers::mollusk::create_payer_account(10_000_000);
        
        // Derive the PDA - can we have a helper calc this maybe?
        let (counter_pda, counter_bump) = Pubkey::find_program_address(
            &[b"counter"],
            &program_id,
        );
        
        // Create empty account for initialization using helper
        let counter_account = helpers::mollusk::create_empty_account::<Counter>(&system_program::id());
        
        // Build instruction using helper
        let init_ix = helpers::mollusk::build_anchor_instruction(
            program_id,
            anchor_counter::instruction::Initialize {},
            anchor_counter::accounts::Initialize {
                counter: counter_pda,
                user: payer.pubkey(),
                system_program: system_program::id(),
            },
        ).unwrap();
        
        let (system_program, system_program_account) = keyed_account_for_system_program();
        
        // Process initialization
        let result = mollusk.process_and_validate_instruction(
            &init_ix,
            &[
                (counter_pda, counter_account),
                (payer.pubkey(), payer_account),
                (system_program, system_program_account),
            ],
            &[Check::success()],
        );
        
        // Get the initialized account
        let counter_account = result.get_account(&counter_pda).unwrap().clone();
        
        Self {
            mollusk,
            counter_pda,
            counter_bump,
            payer,
            counter_account,
            program_id,
        }
    }
}

#[anchor_test(CounterTest)]
fn test_increment(ctx: &mut CounterTest) {
    
    // Read counter before increment using helper
    let counter_before = helpers::mollusk::read_anchor_account::<Counter>(&ctx.counter_account).unwrap();
    assert_eq!(counter_before.count, 0);
    
    // Build increment instruction using helper
    let increment_ix = helpers::mollusk::build_anchor_instruction(
        ctx.program_id,
        anchor_counter::instruction::Increment {},
        anchor_counter::accounts::Increment {
            counter: ctx.counter_pda,
            user: ctx.payer.pubkey(),
        },
    ).unwrap();
    
    let payer_account = helpers::mollusk::create_payer_account(10_000_000);
    
    // Process increment
    let result = ctx.mollusk.process_and_validate_instruction(
        &increment_ix,
        &[
            (ctx.counter_pda, ctx.counter_account.clone()),
            (ctx.payer.pubkey(), payer_account),
        ],
        &[Check::success()],
    );
    
    let updated_account = result.get_account(&ctx.counter_pda).unwrap();
    
    // Read counter after increment using helper
    let counter_after = helpers::mollusk::read_anchor_account::<Counter>(&updated_account).unwrap();
    assert_eq!(counter_after.count, 1);
}

#[anchor_test(CounterTest)]
fn test_multiple_increments(ctx: &mut CounterTest) {
    // Build increment instruction using helper
    let increment_ix = helpers::mollusk::build_anchor_instruction(
        ctx.program_id,
        anchor_counter::instruction::Increment {},
        anchor_counter::accounts::Increment {
            counter: ctx.counter_pda,
            user: ctx.payer.pubkey(),
        },
    ).unwrap();
    
    let payer_account = helpers::mollusk::create_payer_account(10_000_000);
    
    // Increment 5 times
    let mut current_account = ctx.counter_account.clone();
    for i in 1..=5 {
        let result = ctx.mollusk.process_and_validate_instruction(
            &increment_ix,
            &[
                (ctx.counter_pda, current_account.clone()),
                (ctx.payer.pubkey(), payer_account.clone()),
            ],
            &[Check::success()],
        );
        
        current_account = result.get_account(&ctx.counter_pda).unwrap().clone();
        
        // Verify count using helper
        let counter = helpers::mollusk::read_anchor_account::<Counter>(&current_account).unwrap();
        assert_eq!(counter.count, i);
    }
}

#[anchor_test(CounterTest)]
fn test_counter_starts_at_zero(ctx: &mut CounterTest) {
    // Read counter using helper
    let counter = helpers::mollusk::read_anchor_account::<Counter>(&ctx.counter_account).unwrap();
    assert_eq!(counter.count, 0);
}

//#[anchor_fuzz(CounterTest, runs = 50, seed = 42)]
#[anchor_fuzz(CounterTest, runs = 10)]
fn fuzz_increment(
    ctx: CounterTest,
    #[range(1..100)] increment_count: u32,
    #[range(0..10)] multiplier: u8,
) {
    println!("here {:?} {:?}", increment_count, multiplier);
    // Test logic
    assert!(increment_count < 100);
    assert!(multiplier < 10);
}
