use {
    solana_account_info::AccountInfo,
    solana_msg::msg,
    solana_program_error::ProgramResult,
    solana_pubkey::{declare_id, Pubkey},
};


declare_id!("Fuzz111111111111111111111111111111111111111");

#[cfg(not(feature = "no-entrypoint"))]
use solana_program_entrypoint::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[allow(clippy::unnecessary_wraps)]
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Clock
    if instruction_data.len() >= 11 {
        if instruction_data[0] == 0x41 {
            if instruction_data[1] == 0x42 {
                if instruction_data[5] == 0xAA {
                    msg!("Success");
                }
            }
        }

    }
    Ok(())
}
