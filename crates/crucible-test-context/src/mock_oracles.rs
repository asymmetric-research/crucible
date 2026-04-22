//! Mock oracle builders for testing DeFi protocols
//!
//! Provides builders for creating mock Pyth price feed accounts.
//! Both marginfi and klend use identical Pyth Solana Receiver (PriceUpdateV2) format.

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::account_builders::AccountBuilderBase;
use crate::TestContext;

// ============================================================================
// Pyth Solana Receiver Types (PriceUpdateV2)
// ============================================================================

/// PriceUpdateV2 discriminator: sha256("account:PriceUpdateV2")[0..8]
pub const PYTH_DISCRIMINATOR: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];

/// Default Pyth Solana Receiver program ID
/// rec5EKMGg6MxZYaMdyBps2bnnCNHi6KCYuQedA7GsAuW
pub const DEFAULT_PYTH_RECEIVER_ID: Pubkey = Pubkey::new_from_array([
    0x02, 0xe1, 0xae, 0xce, 0x70, 0xcc, 0x1b, 0xac, 0x7a, 0x72, 0xa9, 0x36, 0x74, 0xe4, 0x5a, 0x7b,
    0xe1, 0xa8, 0xbd, 0x5a, 0x03, 0xbd, 0x7c, 0x50, 0xfd, 0x3f, 0xa2, 0xc5, 0xa4, 0x92, 0x88, 0x28,
]);

/// Pyth verification level for price updates
#[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[repr(u8)]
pub enum VerificationLevel {
    Partial { num_signatures: u8 },
    Full,
}

/// Pyth price feed message containing price data
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[repr(C)]
pub struct PriceFeedMessage {
    pub feed_id: [u8; 32],
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    pub publish_time: i64,
    pub prev_publish_time: i64,
    pub ema_price: i64,
    pub ema_conf: u64,
}

/// Pyth PriceUpdateV2 account structure (Pyth Solana Receiver format)
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[repr(C)]
pub struct PriceUpdateV2 {
    pub write_authority: Pubkey,
    pub verification_level: VerificationLevel,
    pub price_message: PriceFeedMessage,
    pub posted_slot: u64,
}

// ============================================================================
// Mock Pyth Oracle Builder
// ============================================================================

/// Builder for creating mock Pyth price feed accounts
///
/// # Example
/// ```ignore
/// let oracle = ctx.create_mock_pyth_oracle()
///     .price(100_00000000)  // $100 with 8 decimals
///     .exponent(-8)
///     .confidence(100_000)
///     .build()?;
/// ```
pub struct MockPythOracleBuilder<'a> {
    ctx: &'a mut TestContext,
    price: i64,
    exponent: i32,
    confidence: u64,
    publish_time: Option<i64>,
    feed_id: Option<[u8; 32]>,
    program_id: Pubkey,
}

impl<'a> MockPythOracleBuilder<'a> {
    pub fn new(ctx: &'a mut TestContext) -> Self {
        Self {
            ctx,
            price: 0,
            exponent: -8,
            confidence: 100_000,
            publish_time: None,
            feed_id: None,
            program_id: DEFAULT_PYTH_RECEIVER_ID,
        }
    }

    /// Set the price value (in smallest units based on exponent)
    /// For example, $100 with exponent -8 = 100_00000000
    pub fn price(mut self, price: i64) -> Self {
        self.price = price;
        self
    }

    /// Set the price exponent (typically -8 for USD prices)
    pub fn exponent(mut self, exp: i32) -> Self {
        self.exponent = exp;
        self
    }

    /// Set the confidence interval
    pub fn confidence(mut self, conf: u64) -> Self {
        self.confidence = conf;
        self
    }

    /// Set the publish time (defaults to current system time)
    pub fn publish_time(mut self, time: i64) -> Self {
        self.publish_time = Some(time);
        self
    }

    /// Set a custom feed ID (defaults to oracle pubkey bytes)
    pub fn feed_id(mut self, id: [u8; 32]) -> Self {
        self.feed_id = Some(id);
        self
    }

    /// Override the Pyth program ID (defaults to Pyth Solana Receiver)
    pub fn program_id(mut self, id: Pubkey) -> Self {
        self.program_id = id;
        self
    }

    /// Build and create the mock Pyth oracle account
    /// Returns the oracle's public key
    pub fn build(self) -> Result<Pubkey> {
        let oracle_keypair = Keypair::new();
        let oracle_pubkey = oracle_keypair.pubkey();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let publish_time = self.publish_time.unwrap_or(current_time);
        let feed_id = self.feed_id.unwrap_or(oracle_pubkey.to_bytes());

        let price_update = PriceUpdateV2 {
            write_authority: Pubkey::default(),
            verification_level: VerificationLevel::Full,
            price_message: PriceFeedMessage {
                feed_id,
                price: self.price,
                conf: self.confidence,
                exponent: self.exponent,
                publish_time,
                prev_publish_time: publish_time - 1,
                ema_price: self.price,
                ema_conf: self.confidence,
            },
            posted_slot: self.ctx.slot(),
        };

        // Serialize: discriminator + borsh data
        let mut data = PYTH_DISCRIMINATOR.to_vec();
        price_update.serialize(&mut data)?;

        self.ctx
            .create_account()
            .pubkey(oracle_pubkey)
            .owner(self.program_id)
            .lamports(1_000_000_000)
            .data(&data)
            .create()?;

        Ok(oracle_pubkey)
    }
}

// ============================================================================
// TestContext Helper Methods for Pyth Oracles
// ============================================================================

impl TestContext {
    /// Create a mock Pyth oracle builder
    ///
    /// # Example
    /// ```ignore
    /// let oracle = ctx.create_mock_pyth_oracle()
    ///     .price(100_00000000)  // $100
    ///     .exponent(-8)
    ///     .build()?;
    /// ```
    pub fn create_mock_pyth_oracle(&mut self) -> MockPythOracleBuilder<'_> {
        MockPythOracleBuilder::new(self)
    }

    /// Update the price on an existing Pyth oracle
    ///
    /// # Arguments
    /// * `oracle` - The oracle account pubkey
    /// * `price` - New price value
    /// * `exponent` - Price exponent (typically -8)
    pub fn update_pyth_price(&mut self, oracle: &Pubkey, price: i64, exponent: i32) -> Result<()> {
        let account = self.read_account(oracle)?;

        // Skip discriminator (8 bytes), deserialize, update, reserialize
        let mut price_update: PriceUpdateV2 =
            BorshDeserialize::deserialize(&mut &account.data[8..])?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        price_update.price_message.price = price;
        price_update.price_message.exponent = exponent;
        price_update.price_message.ema_price = price;
        price_update.price_message.prev_publish_time = price_update.price_message.publish_time;
        price_update.price_message.publish_time = current_time;
        price_update.posted_slot = self.slot();

        // Reserialize
        let mut new_data = PYTH_DISCRIMINATOR.to_vec();
        price_update.serialize(&mut new_data)?;

        self.write_account(
            oracle,
            Account {
                data: new_data,
                ..account
            },
        )
    }

    /// Refresh a Pyth oracle's timestamp and slot to make it "fresh"
    /// Use this before operations that check oracle staleness
    pub fn refresh_pyth_oracle(&mut self, oracle: &Pubkey) -> Result<()> {
        let account = self.read_account(oracle)?;

        let mut price_update: PriceUpdateV2 =
            BorshDeserialize::deserialize(&mut &account.data[8..])?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        price_update.price_message.prev_publish_time = price_update.price_message.publish_time;
        price_update.price_message.publish_time = current_time;
        price_update.posted_slot = self.slot();

        let mut new_data = PYTH_DISCRIMINATOR.to_vec();
        price_update.serialize(&mut new_data)?;

        self.write_account(
            oracle,
            Account {
                data: new_data,
                ..account
            },
        )
    }
}
