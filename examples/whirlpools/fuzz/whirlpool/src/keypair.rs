use solana_keypair::Keypair;
use std::cell::RefCell;

thread_local! {
    static KEYPAIR_SEED_COUNTER: RefCell<u64> = const { RefCell::new(0) };
}

/// Generate a deterministic keypair from a monotonically increasing seed.
/// Call `reset_keypair_counter()` at the start of setup() to ensure reproducibility.
pub fn next_keypair() -> Keypair {
    KEYPAIR_SEED_COUNTER.with(|c| {
        let idx = *c.borrow();
        *c.borrow_mut() = idx + 1;
        let mut seed = [0u8; 32];
        // Use a prefix to avoid collisions with other potential seed usage
        seed[0] = 0xFE; // marker byte
        seed[1..9].copy_from_slice(&idx.to_le_bytes());
        solana_keypair::keypair_from_seed(&seed)
            .unwrap_or_else(|_| panic!("Failed to create keypair from seed {}", idx))
    })
}

pub fn reset_keypair_counter() {
    KEYPAIR_SEED_COUNTER.with(|c| *c.borrow_mut() = 0);
}
