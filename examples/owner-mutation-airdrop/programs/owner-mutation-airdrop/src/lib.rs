#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::SysvarId;

declare_id!("2eJW8mrzmW3Gy88VZ5oqn4qSRoTRYqQfucG69mx99F1b");

/// Stand-in for a foreign program that is *supposed* to own certain accounts (e.g. an SPL token
/// program or an oracle program). The harness creates the relevant config account with this owner.
pub const FOREIGN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0x0A; 32]);
pub const TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const EXPECTED_SEMANTIC_CONTEXT: Pubkey = Pubkey::new_from_array([0x86; 32]);
pub const ALT_SEMANTIC_CONTEXT: Pubkey = Pubkey::new_from_array([0x87; 32]);

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;
const MINT_DECIMALS_OFFSET: usize = 44;
const MINT_INITIALIZED_OFFSET: usize = 45;
const TOKEN_MINT_OFFSET: usize = 0;
const TOKEN_AMOUNT_OFFSET: usize = 64;
const TOKEN_STATE_OFFSET: usize = 108;

#[program]
pub mod owner_mutation_airdrop {
    use super::*;

    // ---- CC-1 true positives: read an account's data without verifying its owner ----

    /// Program-owned config, missing owner check (the canonical bug).
    pub fn claim_airdrop(ctx: Context<ClaimAirdrop>) -> Result<()> {
        // BUG: trusts config data without verifying `config.owner == crate::ID`.
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// A second program-owned account in a different role, same missing-owner-check class.
    pub fn read_state_no_check(ctx: Context<ReadState>) -> Result<()> {
        // BUG: trusts state data without verifying `state.owner == crate::ID`.
        let amount = read_u64(&ctx.accounts.state)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Account expected to be owned by a *foreign* program (token/oracle flavor), missing check.
    pub fn read_foreign_owned_no_check(ctx: Context<ReadForeign>) -> Result<()> {
        // BUG: trusts foreign-owned data without verifying `config.owner == FOREIGN_PROGRAM_ID`.
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Tiny (<= 8 byte) config read without an owner check (exercises the relevance-gate
    /// small-account path).
    pub fn read_tiny_config_no_check(ctx: Context<ReadTiny>) -> Result<()> {
        // BUG: trusts a 4-byte config without verifying its owner.
        let amount = read_u32(&ctx.accounts.config)? as u64;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-1 negatives / edges ----

    /// Program-owned config *with* the owner check present.
    pub fn claim_with_owner_check(ctx: Context<ClaimAirdrop>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Foreign-owned config *with* the owner check present.
    pub fn read_foreign_owned_with_check(ctx: Context<ReadForeign>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &FOREIGN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Pays a fixed amount and never reads the `inert` account passed alongside. The inert
    /// account is a data account with no influence on execution, so the relevance gate must skip
    /// it instead of reporting a (non-exploitable) missing owner check.
    pub fn with_inert_account(ctx: Context<WithInert>) -> Result<()> {
        let _ = &ctx.accounts.inert; // intentionally unused
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Reads a PDA config without verifying its derivation or owner.
    pub fn read_pda_config_no_check(ctx: Context<ReadPda>) -> Result<()> {
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Singleton-style PDA: owner and type are checked, but the key is not. The account mutator
    /// should not report this as CC-3 because the spoofed owner is rejected.
    pub fn read_singleton_pda_with_owner_type_check_no_derivation_check(
        ctx: Context<ReadTyped>,
    ) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = {
            let data = ctx.accounts.config.try_borrow_data()?;
            require!(data.len() >= 16, AirdropError::InvalidConfig);
            require!(
                &data[0..8] == Config::DISCRIMINATOR,
                AirdropError::InvalidConfig
            );
            u64::from_le_bytes(data[8..16].try_into().unwrap())
        };
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Verifies the PDA address but omits the owner check. The owner-mutation engine skips
    /// key-pinned PDAs by default because an attacker cannot normally create this wrong-owner state.
    pub fn read_pda_config_with_pda_check_no_owner_check(ctx: Context<ReadPda>) -> Result<()> {
        let (expected, _) = Pubkey::find_program_address(&[b"config"], &crate::ID);
        require!(
            ctx.accounts.config.key() == expected,
            AirdropError::WrongPda
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same read, but verifies both the expected `[b"config"]` PDA and its owner.
    pub fn read_pda_config_with_owner_and_pda_check(ctx: Context<ReadPda>) -> Result<()> {
        let (expected, _) = Pubkey::find_program_address(&[b"config"], &crate::ID);
        require!(
            ctx.accounts.config.key() == expected,
            AirdropError::WrongPda
        );
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Passes an empty PDA account that the instruction never reads. The CC-3 relevance gate should
    /// suppress this instead of treating every successful substitution as a missing derivation check.
    pub fn with_inert_pda_account(ctx: Context<WithInertPda>) -> Result<()> {
        let _ = &ctx.accounts.inert_pda;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Reads a *writable* config without an owner check. The account is only read, so owner mutation
    /// can still produce a conclusive finding even though the meta is writable.
    pub fn read_writable_config_no_check(ctx: Context<ReadWritable>) -> Result<()> {
        let amount = read_u64(&ctx.accounts.config)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Uses a PDA-like authority account without reading data and without verifying its address.
    pub fn use_pda_authority_no_check(ctx: Context<UsePdaAuthority>) -> Result<()> {
        // BUG: never checks `authority.key() == PDA([b"authority"], crate::ID)`.
        require!(
            ctx.accounts.authority.lamports() > 0,
            AirdropError::InvalidConfig
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Same authority path, but verifies the PDA address.
    pub fn use_pda_authority_with_check(ctx: Context<UsePdaAuthority>) -> Result<()> {
        let (expected, _) = Pubkey::find_program_address(&[b"authority"], &crate::ID);
        require!(
            ctx.accounts.authority.key() == expected,
            AirdropError::WrongPda
        );
        require!(
            ctx.accounts.authority.lamports() > 0,
            AirdropError::InvalidConfig
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Uses the PDA account's key as the intended authority but never verifies it. This is a
    /// key-only PDA bug: no data or lamports are semantically relevant, so the account mutator's
    /// relevance gates intentionally miss it.
    pub fn use_pda_authority_key_no_check(ctx: Context<UsePdaAuthority>) -> Result<()> {
        // BUG: any non-default key is accepted as the intended PDA authority.
        require!(
            ctx.accounts.authority.key() != Pubkey::default(),
            AirdropError::InvalidConfig
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    // ---- Token account checks: fake owners and mint relation ----

    /// Reads mint-shaped data without verifying the account is owned by the token program.
    pub fn read_mint_no_owner_check(ctx: Context<ReadMint>) -> Result<()> {
        let decimals = read_mint_decimals(&ctx.accounts.mint)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            u64::from(decimals) + 1,
        )
    }

    /// Same mint read, with the token-program owner check present.
    pub fn read_mint_with_owner_check(ctx: Context<ReadMint>) -> Result<()> {
        require!(
            ctx.accounts.mint.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let decimals = read_mint_decimals(&ctx.accounts.mint)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            u64::from(decimals) + 1,
        )
    }

    /// Reads token-account-shaped data without verifying the token-program owner.
    pub fn read_token_account_no_owner_check(ctx: Context<ReadTokenAccountOnly>) -> Result<()> {
        let (_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same token-account read, with the token-program owner check present.
    pub fn read_token_account_with_owner_check(ctx: Context<ReadTokenAccountOnly>) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let (_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Receives a token account and mint but never checks `token_account.mint == mint.key()`.
    pub fn read_token_with_mint_no_mint_check(ctx: Context<ReadTokenWithMint>) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        require!(
            ctx.accounts.mint.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let _decimals = read_mint_decimals(&ctx.accounts.mint)?;
        let (_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same pair, with the token-account-to-mint relation checked.
    pub fn read_token_with_mint_check(ctx: Context<ReadTokenWithMint>) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        require!(
            ctx.accounts.mint.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let decimals = read_mint_decimals(&ctx.accounts.mint)?;
        let (token_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        require!(
            token_mint == ctx.accounts.mint.key(),
            AirdropError::WrongMint
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount + u64::from(decimals),
        )
    }

    /// Owner is checked, but no mint account is present; the wrong-mint oracle must not run here.
    pub fn read_token_without_mint_relation_context(
        ctx: Context<ReadTokenAccountOnly>,
    ) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let (_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Pool embeds the canonical LP mint, but this path only checks the supplied token pair.
    pub fn read_lp_pair_no_canonical_mint_check(ctx: Context<ReadLpPair>) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        require!(
            ctx.accounts.mint.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let (_pool_mint, _pool_amount) = read_pool_state(&ctx.accounts.pool_state)?;
        let decimals = read_mint_decimals(&ctx.accounts.mint)?;
        let (token_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        require!(
            token_mint == ctx.accounts.mint.key(),
            AirdropError::WrongMint
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount + u64::from(decimals),
        )
    }

    /// Same LP pair, with the pool-state canonical mint binding checked.
    pub fn read_lp_pair_with_canonical_mint_check(ctx: Context<ReadLpPair>) -> Result<()> {
        require!(
            ctx.accounts.token_account.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        require!(
            ctx.accounts.mint.owner == &TOKEN_PROGRAM_ID,
            AirdropError::WrongOwner
        );
        let (pool_mint, _pool_amount) = read_pool_state(&ctx.accounts.pool_state)?;
        let _decimals = read_mint_decimals(&ctx.accounts.mint)?;
        let (token_mint, amount) = read_token_account_data(&ctx.accounts.token_account)?;
        require!(
            token_mint == ctx.accounts.mint.key(),
            AirdropError::WrongMint
        );
        require!(
            pool_mint == ctx.accounts.mint.key(),
            AirdropError::WrongMint
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-4 true positives / negatives: signer authorization ----

    /// Pays out without verifying that the `authority` actually signed (missing signer check).
    pub fn withdraw_no_signer_check(ctx: Context<Withdraw>) -> Result<()> {
        // BUG: never checks `ctx.accounts.authority.is_signer`.
        let _ = &ctx.accounts.authority;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Same payout, but with the signer check present.
    pub fn withdraw_with_signer_check(ctx: Context<Withdraw>) -> Result<()> {
        require!(
            ctx.accounts.authority.is_signer,
            AirdropError::MissingSigner
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Two declared signers, but only `admin` is checked — `cosigner`'s signature is never
    /// enforced, so the engine must flag the co-signer (and not the admin).
    pub fn withdraw_multisig_one_unchecked(ctx: Context<WithdrawMultisig>) -> Result<()> {
        require!(ctx.accounts.admin.is_signer, AirdropError::MissingSigner);
        // BUG: never checks `ctx.accounts.cosigner.is_signer`.
        let _ = &ctx.accounts.cosigner;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// `cosigner` is intentionally redundant metadata. The account mutator will still report a
    /// missing signer check because it cannot infer that this signer is not an authority boundary.
    pub fn withdraw_redundant_cosigner(ctx: Context<WithdrawMultisig>) -> Result<()> {
        require!(ctx.accounts.admin.is_signer, AirdropError::MissingSigner);
        let _ = &ctx.accounts.cosigner;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    // ---- CC-5 type-tag: typed account read with / without discriminator check ----

    /// Reads a typed `Config` via `UncheckedAccount`: verifies the owner but trusts the data layout
    /// without checking the 8-byte discriminator (missing type-tag check).
    pub fn read_typed_no_check(ctx: Context<ReadTyped>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = {
            let data = ctx.accounts.config.try_borrow_data()?;
            require!(data.len() >= 16, AirdropError::InvalidConfig);
            // BUG: never checks `data[0..8] == Config` discriminator.
            u64::from_le_bytes(data[8..16].try_into().unwrap())
        };
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same read via `Account<'info, Config>`, which verifies the discriminator (and owner).
    pub fn read_typed_with_check(ctx: Context<ReadTypedChecked>) -> Result<()> {
        let amount = ctx.accounts.config.amount;
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Optional-account pattern: a valid `Config` pays out, but a malformed/placeholder account is
    /// deliberately treated as absent. A discriminator flip should not be reported as exploitable
    /// because the mutated execution no-ops instead of matching the baseline effects.
    pub fn read_optional_typed_config(ctx: Context<ReadTyped>) -> Result<()> {
        if ctx.accounts.config.owner != &crate::ID {
            return Ok(());
        }
        let amount = {
            let data = ctx.accounts.config.try_borrow_data()?;
            if data.len() < 16 || &data[0..8] != Config::DISCRIMINATOR {
                return Ok(());
            }
            u64::from_le_bytes(data[8..16].try_into().unwrap())
        };
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Checks that the account has *some* valid known type, but not the expected type. A bit-flip
    /// probe is rejected, while a real `AlternateConfig` is incorrectly accepted.
    pub fn read_allowed_type_no_expected_type_check(ctx: Context<ReadTyped>) -> Result<()> {
        require!(
            ctx.accounts.config.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let amount = {
            let data = ctx.accounts.config.try_borrow_data()?;
            require!(data.len() >= 16, AirdropError::InvalidConfig);
            let disc = &data[0..8];
            require!(
                disc == Config::DISCRIMINATOR || disc == AlternateConfig::DISCRIMINATOR,
                AirdropError::InvalidConfig
            );
            // BUG: accepts AlternateConfig where Config is expected.
            u64::from_le_bytes(data[8..16].try_into().unwrap())
        };
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Optional-present path with a missing owner check. If the instruction is first observed with
    /// an empty placeholder, the per-instruction probe cache suppresses the later present-account bug.
    pub fn read_maybe_config_no_owner_check(ctx: Context<ReadTyped>) -> Result<()> {
        let data = ctx.accounts.config.try_borrow_data()?;
        let amount = if data.is_empty() {
            1
        } else {
            // BUG: reads present config data without checking owner.
            require!(data.len() >= 8, AirdropError::InvalidConfig);
            u64::from_le_bytes(data[0..8].try_into().unwrap())
        };
        require!(amount > 0, AirdropError::InvalidAmount);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Both trader accounts are individually valid and signer authorization is checked, but the
    /// destination trader is not required to belong to the same authority. This is the custom
    /// invariant class: valid-but-wrong counterpart accounts must be constructed by the harness.
    pub fn transfer_between_traders_no_cross_check(
        ctx: Context<TransferBetweenTraders>,
    ) -> Result<()> {
        let (src_authority, amount) = read_trader_state(&ctx.accounts.source_trader)?;
        let (_dst_authority, _) = read_trader_state(&ctx.accounts.destination_trader)?;
        require!(
            src_authority == ctx.accounts.authority.key(),
            AirdropError::WrongAuthority
        );
        // BUG: never checks destination_trader.authority == source_trader.authority.
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-7 / CC-9 relation checks ----

    /// Source embeds the expected target key, but the instruction never checks that relation.
    pub fn read_linked_no_check(ctx: Context<ReadLinked>) -> Result<()> {
        let (_expected_target, source_amount) = read_linked_state(&ctx.accounts.source)?;
        let target_amount = read_target_state(&ctx.accounts.target)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            source_amount + target_amount,
        )
    }

    /// Same linked-source read, with `source.target == target.key()` checked.
    pub fn read_linked_with_check(ctx: Context<ReadLinked>) -> Result<()> {
        let (expected_target, source_amount) = read_linked_state(&ctx.accounts.source)?;
        require!(
            expected_target == ctx.accounts.target.key(),
            AirdropError::WrongTarget
        );
        let target_amount = read_target_state(&ctx.accounts.target)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            source_amount + target_amount,
        )
    }

    /// Source embeds the expected price/value account key, but the instruction accepts any
    /// same-class price account. The price is read but does not affect this test's post-state,
    /// matching economic-value inputs whose byte corruption is a weak relevance signal.
    pub fn read_price_ref_no_check(ctx: Context<ReadPriceRef>) -> Result<()> {
        let (_expected_price, source_amount) = read_value_source_state(&ctx.accounts.source)?;
        let _price = read_price_value(&ctx.accounts.price)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            source_amount,
        )
    }

    /// Same price/value read, with `source.price == price.key()` checked.
    pub fn read_price_ref_with_check(ctx: Context<ReadPriceRef>) -> Result<()> {
        let (expected_price, source_amount) = read_value_source_state(&ctx.accounts.source)?;
        require!(
            expected_price == ctx.accounts.price.key(),
            AirdropError::WrongTarget
        );
        let _price = read_price_value(&ctx.accounts.price)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            source_amount,
        )
    }

    /// Singleton/root account embeds a child key, but the instruction accepts a wrong child.
    pub fn read_root_child_no_check(ctx: Context<ReadRootChild>) -> Result<()> {
        let (_expected_child, root_amount) = read_root_state(&ctx.accounts.root)?;
        let child_amount = read_target_state(&ctx.accounts.child)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            root_amount + child_amount,
        )
    }

    /// Same root-child read, with `root.child == child.key()` checked.
    pub fn read_root_child_with_check(ctx: Context<ReadRootChild>) -> Result<()> {
        let (expected_child, root_amount) = read_root_state(&ctx.accounts.root)?;
        require!(
            expected_child == ctx.accounts.child.key(),
            AirdropError::WrongTarget
        );
        let child_amount = read_target_state(&ctx.accounts.child)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            root_amount + child_amount,
        )
    }

    /// Pair accounts each carry their expected counterpart, but the instruction never verifies the
    /// bidirectional binding.
    pub fn read_pair_bidirectional_no_check(ctx: Context<ReadPair>) -> Result<()> {
        let (_expected_right, _left_root, left_amount) = read_pair_left_state(&ctx.accounts.left)?;
        let (_expected_left, _right_root, right_amount) =
            read_pair_right_state(&ctx.accounts.right)?;
        let root_amount = read_target_state(&ctx.accounts.root)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            left_amount + right_amount + root_amount,
        )
    }

    /// Same pair read, with both counterpart directions and root bindings checked.
    pub fn read_pair_bidirectional_with_check(ctx: Context<ReadPair>) -> Result<()> {
        let (expected_right, left_root, left_amount) = read_pair_left_state(&ctx.accounts.left)?;
        let (expected_left, right_root, right_amount) = read_pair_right_state(&ctx.accounts.right)?;
        require!(
            expected_right == ctx.accounts.right.key(),
            AirdropError::WrongTarget
        );
        require!(
            expected_left == ctx.accounts.left.key(),
            AirdropError::WrongTarget
        );
        require!(
            left_root == ctx.accounts.root.key(),
            AirdropError::WrongTarget
        );
        require!(
            right_root == ctx.accounts.root.key(),
            AirdropError::WrongTarget
        );
        let root_amount = read_target_state(&ctx.accounts.root)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            left_amount + right_amount + root_amount,
        )
    }

    /// Both accounts point at a root/counterpart, but the instruction never verifies that the root
    /// fields match the provided root.
    pub fn read_pair_shared_root_no_check(ctx: Context<ReadPair>) -> Result<()> {
        let (_expected_right, _left_root, left_amount) = read_pair_left_state(&ctx.accounts.left)?;
        let (_expected_left, _right_root, right_amount) =
            read_pair_right_state(&ctx.accounts.right)?;
        let root_amount = read_target_state(&ctx.accounts.root)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            left_amount + right_amount + root_amount,
        )
    }

    /// Same shared-root read, with both root fields checked against the provided root account.
    pub fn read_pair_shared_root_with_check(ctx: Context<ReadPair>) -> Result<()> {
        let (_expected_right, left_root, left_amount) = read_pair_left_state(&ctx.accounts.left)?;
        let (_expected_left, right_root, right_amount) =
            read_pair_right_state(&ctx.accounts.right)?;
        require!(
            left_root == ctx.accounts.root.key(),
            AirdropError::WrongTarget
        );
        require!(
            right_root == ctx.accounts.root.key(),
            AirdropError::WrongTarget
        );
        let root_amount = read_target_state(&ctx.accounts.root)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            left_amount + right_amount + root_amount,
        )
    }

    /// Semantic account has an embedded context key, but the instruction accepts any same-class
    /// account and consumes it.
    pub fn consume_semantic_no_check(ctx: Context<ConsumeSemantic>) -> Result<()> {
        let (_context, amount) = consume_semantic_state(&ctx.accounts.semantic, None)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same consume path, with the expected semantic context checked before mutation.
    pub fn consume_semantic_with_check(ctx: Context<ConsumeSemantic>) -> Result<()> {
        let (_context, amount) =
            consume_semantic_state(&ctx.accounts.semantic, Some(EXPECTED_SEMANTIC_CONTEXT))?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// State embeds the required authority, but any signer is accepted.
    pub fn withdraw_authority_no_authority_check(
        ctx: Context<WithdrawAuthorityState>,
    ) -> Result<()> {
        let (_expected_authority, amount) = read_authority_state(&ctx.accounts.state)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same authority-state read, with `state.authority == authority.key()` checked.
    pub fn withdraw_authority_with_authority_check(
        ctx: Context<WithdrawAuthorityState>,
    ) -> Result<()> {
        let (expected_authority, amount) = read_authority_state(&ctx.accounts.state)?;
        require!(
            expected_authority == ctx.accounts.authority.key(),
            AirdropError::WrongAuthority
        );
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-2 sysvar: read the Clock from a passed account with / without an identity check ----

    /// Reads the clock's `unix_timestamp` from the passed account without verifying its key — a
    /// program that trusts a sysvar by position (the Wormhole class).
    pub fn read_clock_no_check(ctx: Context<ReadClock>) -> Result<()> {
        // BUG: never checks `ctx.accounts.clock.key() == Clock::id()`.
        let ts = read_clock_unix_timestamp(&ctx.accounts.clock)?;
        require!(ts > 0, AirdropError::InvalidClock);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    /// Same read, but verifies the account is the real Clock sysvar.
    pub fn read_clock_with_check(ctx: Context<ReadClock>) -> Result<()> {
        require!(
            ctx.accounts.clock.key() == Clock::id(),
            AirdropError::WrongSysvar
        );
        let ts = read_clock_unix_timestamp(&ctx.accounts.clock)?;
        require!(ts > 0, AirdropError::InvalidClock);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            1,
        )
    }

    // ---- CC-9.5: scoped / cross-authority ----

    /// Two scoped traders, each authorizing the same `delegate` signer via their `delegate` field.
    /// The instruction verifies the delegate but never checks that the two traders share the same
    /// `authority` (owner). With both traders owned by the same authority in the legit baseline, a
    /// mutation that breaks `destination.authority` while preserving the delegate reference still
    /// succeeds — the CC-9.5 cross-authority drain shape (Phoenix #2749/#2750).
    pub fn transfer_scoped_no_owner_check(ctx: Context<TransferScopedTraders>) -> Result<()> {
        let (_src_authority, src_delegate, amount) =
            read_scoped_trader_state(&ctx.accounts.source_trader)?;
        let (_dst_authority, dst_delegate, _) =
            read_scoped_trader_state(&ctx.accounts.destination_trader)?;
        require!(
            src_delegate == ctx.accounts.delegate.key()
                && dst_delegate == ctx.accounts.delegate.key(),
            AirdropError::WrongAuthority
        );
        // BUG: never checks destination.authority == source.authority.
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Same scoped transfer, with the cross-authority owner binding enforced.
    pub fn transfer_scoped_owner_checked(ctx: Context<TransferScopedTraders>) -> Result<()> {
        let (src_authority, src_delegate, amount) =
            read_scoped_trader_state(&ctx.accounts.source_trader)?;
        let (dst_authority, dst_delegate, _) =
            read_scoped_trader_state(&ctx.accounts.destination_trader)?;
        require!(
            src_delegate == ctx.accounts.delegate.key()
                && dst_delegate == ctx.accounts.delegate.key(),
            AirdropError::WrongAuthority
        );
        require!(src_authority == dst_authority, AirdropError::WrongAuthority);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    // ---- CC-14: duplicate / aliasing ----

    /// Borrows against two collateral accounts that must be distinct, releasing the *sum* of their
    /// values. There is no `c1 != c2` check, so aliasing one onto the other double-counts a single
    /// collateral position (over-borrow) — the divergent CC-14 shape.
    pub fn borrow_against_two_collateral(ctx: Context<BorrowTwoCollateral>) -> Result<()> {
        let first = read_collateral_value(&ctx.accounts.collateral_a)?;
        let second = read_collateral_value(&ctx.accounts.collateral_b)?;
        // BUG: never checks collateral_a.key() != collateral_b.key().
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            first + second,
        )
    }

    /// Same borrow, with the distinctness check enforced.
    pub fn borrow_against_two_collateral_checked(ctx: Context<BorrowTwoCollateral>) -> Result<()> {
        require!(
            ctx.accounts.collateral_a.key() != ctx.accounts.collateral_b.key(),
            AirdropError::WrongTarget
        );
        let first = read_collateral_value(&ctx.accounts.collateral_a)?;
        let second = read_collateral_value(&ctx.accounts.collateral_b)?;
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            first + second,
        )
    }

    // ---- T4 state-conditional: owner check gated by another account's flag ----
    // Demonstrates the probe-once-single-state blindspot (account_constraints.md J.1#1). The CC-1
    // owner check on `config` is present only when `gate.fast_path == 0`. In the first-reached state
    // (fast_path = 0) the check holds and a mutated owner is rejected, so the old engine — which
    // probed each instruction type in exactly one state — burned its single probe here and reported
    // nothing. The `set_gate_fast_path` toggle drives the gate to fast_path = 1, a state where the
    // check is dropped and a mutated owner survives; the state-keyed probe re-probes that state and
    // reports the CC-1 finding the old probe-once gate missed.
    pub fn read_gated_config(ctx: Context<ReadGatedConfig>) -> Result<()> {
        let fast_path = read_gate_flag(&ctx.accounts.gate)?;
        let cfg = ctx.accounts.config.try_borrow_data()?;
        require!(cfg.len() >= 16, AirdropError::InvalidConfig);
        require!(
            &cfg[0..8] == GatedConfigState::DISCRIMINATOR,
            AirdropError::InvalidConfig
        );
        if !fast_path {
            // Slow path keeps the CC-1 owner check; fast path drops it (the bug).
            require!(
                ctx.accounts.config.owner == &crate::ID,
                AirdropError::WrongOwner
            );
        }
        let amount = u64::from_le_bytes(cfg[8..16].try_into().unwrap());
        require!(amount > 0, AirdropError::InvalidAmount);
        drop(cfg);
        payout(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.recipient.to_account_info(),
            amount,
        )
    }

    /// Toggle action: flips the gate's `fast_path` flag so the fuzzer can drive `read_gated_config`
    /// through both states. The gate is always program-owned and discriminator-checked here.
    pub fn set_gate_fast_path(ctx: Context<SetGate>, fast_path: u8) -> Result<()> {
        require!(
            ctx.accounts.gate.owner == &crate::ID,
            AirdropError::WrongOwner
        );
        let mut data = ctx.accounts.gate.try_borrow_mut_data()?;
        require!(data.len() >= 9, AirdropError::InvalidConfig);
        require!(
            &data[0..8] == GateState::DISCRIMINATOR,
            AirdropError::InvalidConfig
        );
        data[8] = fast_path;
        Ok(())
    }

    // ---- CC-13: forward an account into a downstream CPI without validating it ----

    /// Forwards `dest` into a system-program transfer CPI WITHOUT validating it (the bug): a wrong
    /// `dest` is passed straight through to the CPI.
    pub fn forward_to_cpi_no_check(ctx: Context<ForwardToCpi>) -> Result<()> {
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.payer.key(),
            &ctx.accounts.dest.key(),
            1,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.dest.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    /// Same forward, but validates the forwarded account's owner before the CPI (the fix).
    pub fn forward_to_cpi_with_check(ctx: Context<ForwardToCpi>) -> Result<()> {
        require!(
            ctx.accounts.dest.owner == &anchor_lang::solana_program::system_program::ID,
            AirdropError::WrongOwner
        );
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.payer.key(),
            &ctx.accounts.dest.key(),
            1,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.payer.to_account_info(),
                ctx.accounts.dest.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    // ---- FP-1 reachability: loader-owned (program) account, owner not attacker-settable ----
}

fn read_u64(account: &UncheckedAccount) -> Result<u64> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 8, AirdropError::InvalidConfig);
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

fn read_u32(account: &UncheckedAccount) -> Result<u32> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 4, AirdropError::InvalidConfig);
    let amount = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

/// Read the Clock's `unix_timestamp` (i64 at byte offset 32) directly from the account data,
/// without going through `Clock::from_account_info` (which would verify the key).
fn read_clock_unix_timestamp(account: &UncheckedAccount) -> Result<i64> {
    let data = account.try_borrow_data()?;
    require!(data.len() >= 40, AirdropError::InvalidClock);
    Ok(i64::from_le_bytes(data[32..40].try_into().unwrap()))
}

fn read_mint_decimals(account: &UncheckedAccount) -> Result<u8> {
    let data = account.try_borrow_data()?;
    require!(data.len() == MINT_LEN, AirdropError::InvalidConfig);
    require!(
        data[MINT_INITIALIZED_OFFSET] != 0,
        AirdropError::InvalidConfig
    );
    Ok(data[MINT_DECIMALS_OFFSET])
}

fn read_token_account_data(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    let data = account.try_borrow_data()?;
    require!(data.len() == TOKEN_ACCOUNT_LEN, AirdropError::InvalidConfig);
    require!(data[TOKEN_STATE_OFFSET] != 0, AirdropError::InvalidConfig);
    let mint = Pubkey::new_from_array(
        data[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32]
            .try_into()
            .unwrap(),
    );
    let amount = u64::from_le_bytes(
        data[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((mint, amount))
}

fn read_pool_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == PoolState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let mint = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((mint, amount))
}

fn read_trader_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == TraderState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let authority = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((authority, amount))
}

fn read_linked_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == LinkedState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let target = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((target, amount))
}

fn read_target_state(account: &UncheckedAccount) -> Result<u64> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 16, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == TargetState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

fn read_value_source_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == ValueSourceState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let price = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((price, amount))
}

fn read_price_value(account: &UncheckedAccount) -> Result<u64> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 16, AirdropError::InvalidConfig);
    let price = u64::from_le_bytes(data[8..16].try_into().unwrap());
    require!(price > 0, AirdropError::InvalidAmount);
    Ok(price)
}

fn read_root_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == RootState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let child = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((child, amount))
}

fn read_pair_left_state(account: &UncheckedAccount) -> Result<(Pubkey, Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 80, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == PairLeftState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let right = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let root = Pubkey::new_from_array(data[40..72].try_into().unwrap());
    let amount = u64::from_le_bytes(data[72..80].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((right, root, amount))
}

fn read_pair_right_state(account: &UncheckedAccount) -> Result<(Pubkey, Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 80, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == PairRightState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let left = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let root = Pubkey::new_from_array(data[40..72].try_into().unwrap());
    let amount = u64::from_le_bytes(data[72..80].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((left, root, amount))
}

fn consume_semantic_state(
    account: &UncheckedAccount,
    expected_context: Option<Pubkey>,
) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let mut data = account.try_borrow_mut_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == SemanticState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let context = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    if let Some(expected_context) = expected_context {
        require!(context == expected_context, AirdropError::WrongTarget);
    }
    data[40..48].copy_from_slice(&(amount - 1).to_le_bytes());
    Ok((context, amount))
}

fn read_authority_state(account: &UncheckedAccount) -> Result<(Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 48, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == AuthorityState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let authority = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((authority, amount))
}

fn read_scoped_trader_state(account: &UncheckedAccount) -> Result<(Pubkey, Pubkey, u64)> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 80, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == ScopedTraderState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let authority = Pubkey::new_from_array(data[8..40].try_into().unwrap());
    let delegate = Pubkey::new_from_array(data[40..72].try_into().unwrap());
    let amount = u64::from_le_bytes(data[72..80].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok((authority, delegate, amount))
}

fn read_gate_flag(account: &UncheckedAccount) -> Result<bool> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 9, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == GateState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    Ok(data[8] != 0)
}

fn read_collateral_value(account: &UncheckedAccount) -> Result<u64> {
    require!(account.owner == &crate::ID, AirdropError::WrongOwner);
    let data = account.try_borrow_data()?;
    require!(data.len() >= 16, AirdropError::InvalidConfig);
    require!(
        &data[0..8] == CollateralState::DISCRIMINATOR,
        AirdropError::InvalidConfig
    );
    let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
    require!(amount > 0, AirdropError::InvalidAmount);
    Ok(amount)
}

fn payout(vault: &AccountInfo, recipient: &AccountInfo, amount: u64) -> Result<()> {
    let vault_lamports = **vault.try_borrow_lamports()?;
    require!(vault_lamports >= amount, AirdropError::InsufficientVault);
    **vault.try_borrow_mut_lamports()? -= amount;
    **recipient.try_borrow_mut_lamports()? += amount;
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimAirdrop<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only config; owner deliberately unchecked in the no-check variant.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault, mutated for lamport movement.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadState<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only program-owned state; owner unchecked in the no-check variant.
    pub state: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadForeign<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only foreign-owned config; owner unchecked in the no-check variant.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTiny<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only tiny config; owner unchecked.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithInert<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only account the program never reads.
    pub inert: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadPda<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: read-only PDA config; owner unchecked.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UsePdaAuthority<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: PDA-like authority; key checked only in the checked variant.
    pub authority: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithInertPda<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: empty PDA-like account the instruction never reads.
    pub inert_pda: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadWritable<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: writable config that is only read; owner unchecked.
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadMint<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: SPL mint-shaped data; owner checked only in the checked variant.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTokenAccountOnly<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: SPL token-account-shaped data; owner checked only in the checked variants.
    pub token_account: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTokenWithMint<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: SPL token-account-shaped data.
    pub token_account: UncheckedAccount<'info>,
    /// CHECK: SPL mint-shaped data.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadLpPair<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: program-owned pool state containing the canonical LP mint.
    pub pool_state: UncheckedAccount<'info>,
    /// CHECK: SPL token-account-shaped LP account.
    pub token_account: UncheckedAccount<'info>,
    /// CHECK: SPL mint-shaped LP mint.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: payout destination.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: intended signing authority; its `is_signer` is unchecked in the no-check variant.
    pub authority: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithdrawMultisig<'info> {
    /// CHECK: payout destination.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: admin signer (its signature is checked).
    pub admin: UncheckedAccount<'info>,
    /// CHECK: co-signer whose signature is never checked (the bug).
    pub cosigner: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[account]
pub struct Config {
    pub amount: u64,
}

#[account]
pub struct AlternateConfig {
    pub amount: u64,
}

#[account]
pub struct TraderState {
    pub authority: Pubkey,
    pub amount: u64,
}

#[account]
pub struct PoolState {
    pub lp_mint: Pubkey,
    pub amount: u64,
}

#[account]
pub struct LinkedState {
    pub target: Pubkey,
    pub amount: u64,
}

#[account]
pub struct TargetState {
    pub amount: u64,
}

#[account]
pub struct ValueSourceState {
    pub price: Pubkey,
    pub amount: u64,
}

#[account]
pub struct PriceState {
    pub price: u64,
}

#[account]
pub struct RootState {
    pub child: Pubkey,
    pub amount: u64,
}

#[account]
pub struct PairLeftState {
    pub right: Pubkey,
    pub root: Pubkey,
    pub amount: u64,
}

#[account]
pub struct PairRightState {
    pub left: Pubkey,
    pub root: Pubkey,
    pub amount: u64,
}

#[account]
pub struct SemanticState {
    pub context: Pubkey,
    pub amount: u64,
}

#[account]
pub struct AuthorityState {
    pub authority: Pubkey,
    pub amount: u64,
}

#[account]
pub struct ScopedTraderState {
    pub authority: Pubkey,
    pub delegate: Pubkey,
    pub amount: u64,
}

#[account]
pub struct CollateralState {
    pub amount: u64,
}

#[account]
pub struct GateState {
    pub fast_path: u8,
}

#[account]
pub struct GatedConfigState {
    pub amount: u64,
}

#[derive(Accounts)]
pub struct ReadGatedConfig<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: program-owned gate holding the fast_path flag.
    pub gate: UncheckedAccount<'info>,
    /// CHECK: program-owned config; owner checked only on the slow path.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetGate<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: program-owned gate; the fast_path flag is mutated in place.
    #[account(mut)]
    pub gate: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ForwardToCpi<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: forwarded into the system-transfer CPI; validated only in the with-check variant.
    #[account(mut)]
    pub dest: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferScopedTraders<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    pub delegate: Signer<'info>,
    /// CHECK: individually validated in the instruction.
    pub source_trader: UncheckedAccount<'info>,
    /// CHECK: individually validated in the instruction.
    pub destination_trader: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct BorrowTwoCollateral<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub collateral_a: UncheckedAccount<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub collateral_b: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTyped<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: typed config read without a discriminator check in the no-check variant.
    pub config: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadTypedChecked<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    pub config: Account<'info, Config>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct TransferBetweenTraders<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    pub authority: Signer<'info>,
    /// CHECK: individually validated in the instruction.
    pub source_trader: UncheckedAccount<'info>,
    /// CHECK: individually validated in the instruction.
    pub destination_trader: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadLinked<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub source: UncheckedAccount<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub target: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadPriceRef<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub source: UncheckedAccount<'info>,
    /// CHECK: owner checked manually; discriminator intentionally not checked by the reader.
    pub price: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadRootChild<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub root: UncheckedAccount<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub child: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadPair<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub left: UncheckedAccount<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub right: UncheckedAccount<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub root: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ConsumeSemantic<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    #[account(mut)]
    pub semantic: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct WithdrawAuthorityState<'info> {
    /// CHECK: payout destination.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    /// CHECK: owner and discriminator checked manually.
    pub state: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ReadClock<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    /// CHECK: clock sysvar; its key is unchecked in the no-check variant.
    pub clock: UncheckedAccount<'info>,
    /// CHECK: program-owned vault.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

#[error_code]
pub enum AirdropError {
    #[msg("Invalid config")]
    InvalidConfig,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient vault balance")]
    InsufficientVault,
    #[msg("Wrong owner")]
    WrongOwner,
    #[msg("Missing required signer")]
    MissingSigner,
    #[msg("Wrong PDA")]
    WrongPda,
    #[msg("Wrong sysvar")]
    WrongSysvar,
    #[msg("Invalid clock")]
    InvalidClock,
    #[msg("Wrong authority")]
    WrongAuthority,
    #[msg("Wrong mint")]
    WrongMint,
    #[msg("Wrong target")]
    WrongTarget,
}
