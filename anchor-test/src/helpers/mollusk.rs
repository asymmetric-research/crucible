// anchor-test/src/helpers/mollusk.rs


use anchor_lang::prelude::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};
use anyhow::Result;

pub fn build_anchor_instruction<I, A>(
    program_id: Pubkey,
    instruction: I,
    accounts: A,
) -> Result<Instruction>
where
    I: anchor_lang::InstructionData,
    A: anchor_lang::ToAccountMetas,
{
    Ok(Instruction {
        program_id,
        accounts: accounts.to_account_metas(None),
        data: instruction.data(),
    })
}

pub fn create_empty_account<T: Space + Discriminator>(owner: &Pubkey) -> Account {
    Account {
        lamports: 0,
        data: vec![],
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub fn create_anchor_account<T>(
    owner: &Pubkey,
    data: &T,
) -> Result<Account>
where
    T: Space + Discriminator + AnchorSerialize,
{
    let mut account_data = T::DISCRIMINATOR.to_vec();
    data.serialize(&mut account_data)?;
    
    let rent = Rent::default();
    let lamports = rent.minimum_balance(8 + T::INIT_SPACE);
    
    Ok(Account {
        lamports,
        data: account_data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    })
}

pub fn read_anchor_account<T: AnchorDeserialize + anchor_lang::AccountDeserialize>(account: &Account) -> Result<T> {
    if account.data.len() < 8 {
        return Err(anyhow::anyhow!("Account data too small for discriminator"));
    }
    
    T::deserialize(&mut &account.data[8..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize account: {}", e))
}

pub fn create_payer_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}
