#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use anchor_counter::{Counter, ID as PROGRAM_ID, accounts, instruction};
use anchor_test::TestContext;
use anchor_test::AccountBuilderBase;
use anchor_test::anchor_fuzz;
use anchor_test::fuzz_fixture;
use anchor_test::invariant_test;
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
        ctx.add_program(&program_id, "../../target/deploy/anchor_counter.so").unwrap();
        let payer = Keypair::new();
        ctx.create_account()
            .pubkey(payer.pubkey())
            .lamports(10_000_000)
            .owner(system_program::id())
            .create()
            .unwrap();
        let (counter_pda, _) = Pubkey::find_program_address(&[b"counter"], &program_id);
        let _ = ctx
            .program(program_id)
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
        Self {
            ctx,
            counter_pda,
            program_id,
            payer,
        }
    }
    pub fn action_increment(&mut self) {
        let _ = self
            .ctx
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
    pub fn action_decrement(&mut self) {
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
#[doc(hidden)]
pub mod __counter_fixture_fuzz {
    use super::*;
    use arbitrary::Arbitrary;
    pub enum CounterFixtureActions {
        Increment,
        Decrement,
    }
    const _: () = {
        #[automatically_derived]
        impl<'arbitrary> arbitrary::Arbitrary<'arbitrary> for CounterFixtureActions {
            fn arbitrary(
                u: &mut arbitrary::Unstructured<'arbitrary>,
            ) -> arbitrary::Result<Self> {
                Ok(
                    match (u64::from(<u32 as arbitrary::Arbitrary>::arbitrary(u)?)
                        * 2u64) >> 32
                    {
                        0u64 => CounterFixtureActions::Increment,
                        1u64 => CounterFixtureActions::Decrement,
                        _ => {
                            ::core::panicking::panic(
                                "internal error: entered unreachable code",
                            )
                        }
                    },
                )
            }
            fn arbitrary_take_rest(
                mut u: arbitrary::Unstructured<'arbitrary>,
            ) -> arbitrary::Result<Self> {
                Ok(
                    match (u64::from(<u32 as arbitrary::Arbitrary>::arbitrary(&mut u)?)
                        * 2u64) >> 32
                    {
                        0u64 => CounterFixtureActions::Increment,
                        1u64 => CounterFixtureActions::Decrement,
                        _ => {
                            ::core::panicking::panic(
                                "internal error: entered unreachable code",
                            )
                        }
                    },
                )
            }
            fn size_hint(depth: usize) -> (usize, ::core::option::Option<usize>) {
                <u32 as arbitrary::Arbitrary>::size_hint(depth)
            }
        }
    };
    #[automatically_derived]
    impl ::core::fmt::Debug for CounterFixtureActions {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(
                f,
                match self {
                    CounterFixtureActions::Increment => "Increment",
                    CounterFixtureActions::Decrement => "Decrement",
                },
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for CounterFixtureActions {
        #[inline]
        fn clone(&self) -> CounterFixtureActions {
            match self {
                CounterFixtureActions::Increment => CounterFixtureActions::Increment,
                CounterFixtureActions::Decrement => CounterFixtureActions::Decrement,
            }
        }
    }
    impl<'a> CounterFixture<'a> {
        #[doc(hidden)]
        pub fn __dispatch_action(&mut self, action: CounterFixtureActions) {
            match action {
                CounterFixtureActions::Increment => self.action_increment(),
                CounterFixtureActions::Decrement => self.action_decrement(),
            }
        }
    }
}
enum Action {
    Increment,
    Decrement,
}
const _: () = {
    #[automatically_derived]
    impl<'arbitrary> arbitrary::Arbitrary<'arbitrary> for Action {
        fn arbitrary(
            u: &mut arbitrary::Unstructured<'arbitrary>,
        ) -> arbitrary::Result<Self> {
            Ok(
                match (u64::from(<u32 as arbitrary::Arbitrary>::arbitrary(u)?) * 2u64)
                    >> 32
                {
                    0u64 => Action::Increment,
                    1u64 => Action::Decrement,
                    _ => {
                        ::core::panicking::panic(
                            "internal error: entered unreachable code",
                        )
                    }
                },
            )
        }
        fn arbitrary_take_rest(
            mut u: arbitrary::Unstructured<'arbitrary>,
        ) -> arbitrary::Result<Self> {
            Ok(
                match (u64::from(<u32 as arbitrary::Arbitrary>::arbitrary(&mut u)?)
                    * 2u64) >> 32
                {
                    0u64 => Action::Increment,
                    1u64 => Action::Decrement,
                    _ => {
                        ::core::panicking::panic(
                            "internal error: entered unreachable code",
                        )
                    }
                },
            )
        }
        fn size_hint(depth: usize) -> (usize, ::core::option::Option<usize>) {
            <u32 as arbitrary::Arbitrary>::size_hint(depth)
        }
    }
};
#[automatically_derived]
impl ::core::fmt::Debug for Action {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::write_str(
            f,
            match self {
                Action::Increment => "Increment",
                Action::Decrement => "Decrement",
            },
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for Action {
    #[inline]
    fn clone(&self) -> Action {
        match self {
            Action::Increment => Action::Increment,
            Action::Decrement => Action::Decrement,
        }
    }
}
fn fuzz_increment(ctx: &mut TestContext, actions: Vec<Action>) {
    let mut fixture = CounterFixture::setup(ctx);
    for action in actions {
        match action {
            Action::Increment => fixture.action_increment(),
            Action::Decrement => fixture.action_decrement(),
        }
    }
}
fn invariant_increment(
    ctx: &mut anchor_test_context::TestContext,
    actions: Vec<__counter_fixture_fuzz::CounterFixtureActions>,
) {
    let mut fixture = CounterFixture::setup(ctx);
    for (i, action) in actions.iter().enumerate() {
        if i > 0 && i % 5usize == 0 {
            fixture = CounterFixture::setup(ctx);
        }
        fixture.__dispatch_action(action.clone());
        let fixture_ref = &fixture;
        let result = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                {
                    let mut counter = fixture
                        .ctx
                        .read_anchor_account::<Counter>(&fixture.counter_pda)
                        .unwrap();
                    if !(counter.count < 3) {
                        ::core::panicking::panic("assertion failed: counter.count < 3")
                    }
                }
            }),
        );
        if let Err(err) = result {
            {
                ::std::io::_eprint(format_args!("\n[FAIL] Invariant violation\n"));
            };
            {
                ::std::io::_eprint(format_args!("\nCall sequence:\n"));
            };
            for (j, act) in actions.iter().enumerate() {
                if j == i {
                    {
                        ::std::io::_eprint(
                            format_args!("  {0}:  {1:?} ← failed here\n", j + 1, act),
                        );
                    };
                } else if j < i {
                    {
                        ::std::io::_eprint(format_args!("  {0}:  {1:?}\n", j + 1, act));
                    };
                }
            }
            {
                ::std::io::_eprint(format_args!("\n"));
            };
            std::panic::resume_unwind(err);
        }
    }
}
