use crate::TestContext;
use anchor_lang::solana_program::program_pack::Pack;
use anyhow::Result;
use solana_account::Account;
use solana_pubkey::Pubkey;
use spl_token::solana_program::program_option::COption;

pub struct GenericAccountBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) address: Pubkey,
    pub(crate) account_state: Account,
}

pub trait AccountBuilderBase: Sized {
    fn account_state_mut(&mut self) -> &mut Account;
    fn address_mut(&mut self) -> &mut Pubkey;

    fn pubkey(mut self, pk: Pubkey) -> Self {
        *self.address_mut() = pk;
        self
    }

    fn owner(mut self, pk: Pubkey) -> Self {
        self.account_state_mut().owner = pk;
        self
    }

    fn executable(mut self, val: bool) -> Self {
        self.account_state_mut().executable = val;
        self
    }

    fn rent_epoch(mut self, val: u64) -> Self {
        self.account_state_mut().rent_epoch = val;
        self
    }

    fn lamports(mut self, amount: u64) -> Self {
        self.account_state_mut().lamports = amount;
        self
    }

    fn size(mut self, length: usize) -> Self {
        self.account_state_mut().data = vec![0; length];
        self
    }

    fn data(mut self, bytes: &[u8]) -> Self {
        self.account_state_mut().data = Vec::from(bytes);
        self
    }
}

impl AccountBuilderBase for GenericAccountBuilder<'_> {
    fn account_state_mut(&mut self) -> &mut Account {
        &mut self.account_state
    }
    fn address_mut(&mut self) -> &mut Pubkey {
        &mut self.address
    }
}

impl GenericAccountBuilder<'_> {
    pub fn create(self) -> Result<Pubkey> {
        // Ensure address has been set
        if self.address == Pubkey::default() {
            return Err(anyhow::anyhow!("Address must be set with .pubkey()"));
        }
        self.ctx.track_account(self.address);
        let _ = self.ctx.svm.set_account(self.address, self.account_state);
        Ok(self.address)
    }
}

pub struct MintAccountBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) address: Pubkey,
    pub(crate) account_state: Account,
    pub(crate) mint: spl_token::state::Mint,
}

impl AccountBuilderBase for MintAccountBuilder<'_> {
    fn account_state_mut(&mut self) -> &mut Account {
        &mut self.account_state
    }
    fn address_mut(&mut self) -> &mut Pubkey {
        &mut self.address
    }
}

impl MintAccountBuilder<'_> {
    pub fn create(self) -> Result<Pubkey> {
        if self.address == Pubkey::default() {
            return Err(anyhow::anyhow!("Address must be set with .pubkey()"));
        }

        let mut account = self.account_state;
        spl_token::state::Mint::pack(self.mint, &mut account.data)?;
        self.ctx.track_account(self.address);
        let _ = self.ctx.svm.set_account(self.address, account);
        Ok(self.address)
    }

    pub fn mint_authority(mut self, authority: Pubkey) -> Self {
        self.mint.mint_authority = COption::Some(authority);
        self
    }

    pub fn supply(mut self, supply: u64) -> Self {
        self.mint.supply = supply;
        self
    }

    pub fn decimals(mut self, decimals: u8) -> Self {
        self.mint.decimals = decimals;
        self
    }

    pub fn is_initialized(mut self, initialized: bool) -> Self {
        self.mint.is_initialized = initialized;
        self
    }

    pub fn freeze_authority(mut self, authority: Option<Pubkey>) -> Self {
        self.mint.freeze_authority = match authority {
            Some(pk) => COption::Some(pk),
            None => COption::None,
        };
        self
    }
}

pub struct TokenAccountBuilder<'a> {
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) address: Pubkey,
    pub(crate) account_state: Account,
    pub(crate) token_state: spl_token::state::Account,
}

impl AccountBuilderBase for TokenAccountBuilder<'_> {
    fn account_state_mut(&mut self) -> &mut Account {
        &mut self.account_state
    }
    fn address_mut(&mut self) -> &mut Pubkey {
        &mut self.address
    }
}

impl TokenAccountBuilder<'_> {
    pub fn create(self) -> Result<Pubkey> {
        if self.address == Pubkey::default() {
            return Err(anyhow::anyhow!("Address must be set with .pubkey()"));
        }

        if self.token_state.mint == Pubkey::default() {
            return Err(anyhow::anyhow!("Mint must be set with .mint()"));
        }

        if self.token_state.owner == Pubkey::default() {
            return Err(anyhow::anyhow!("Owner must be set with .token_owner()"));
        }

        let mut account = self.account_state;
        spl_token::state::Account::pack(self.token_state, &mut account.data)?;
        self.ctx.track_account(self.address);
        let _ = self.ctx.svm.set_account(self.address, account);
        Ok(self.address)
    }

    pub fn mint(mut self, mint: Pubkey) -> Self {
        self.token_state.mint = mint;
        self
    }

    pub fn token_owner(mut self, owner: Pubkey) -> Self {
        self.token_state.owner = owner;
        self
    }

    pub fn amount(mut self, amount: u64) -> Self {
        self.token_state.amount = amount;
        self
    }

    pub fn delegate(mut self, delegate: Option<Pubkey>) -> Self {
        self.token_state.delegate = match delegate {
            Some(pk) => COption::Some(pk),
            None => COption::None,
        };
        self
    }

    pub fn state(mut self, state: spl_token::state::AccountState) -> Self {
        self.token_state.state = state;
        self
    }

    pub fn is_native(mut self, native_amount: Option<u64>) -> Self {
        self.token_state.is_native = match native_amount {
            Some(amount) => COption::Some(amount),
            None => COption::None,
        };
        self
    }

    pub fn delegated_amount(mut self, amount: u64) -> Self {
        self.token_state.delegated_amount = amount;
        self
    }

    pub fn close_authority(mut self, authority: Option<Pubkey>) -> Self {
        self.token_state.close_authority = match authority {
            Some(pk) => COption::Some(pk),
            None => COption::None,
        };
        self
    }
}
