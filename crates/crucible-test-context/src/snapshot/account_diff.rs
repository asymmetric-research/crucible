use solana_account::Account;
use solana_pubkey::Pubkey;

/// Before/after diff for a single account across a transaction.
pub struct AccountDiff {
    pub pubkey: Pubkey,
    /// Account state before the transaction. None if account didn't exist.
    pub pre: Option<Account>,
    /// Account state after the transaction. None if account was deleted.
    pub post: Option<Account>,
}

impl AccountDiff {
    /// Whether the account data actually changed.
    pub fn is_changed(&self) -> bool {
        self.pre != self.post
    }

    /// Whether the account was created by this transaction.
    pub fn was_created(&self) -> bool {
        self.pre.is_none() && self.post.is_some()
    }

    /// Whether the account was deleted by this transaction.
    pub fn was_deleted(&self) -> bool {
        self.pre.is_some() && self.post.is_none()
    }

    /// Lamports before and after. Returns (pre_lamports, post_lamports).
    pub fn lamports_delta(&self) -> (u64, u64) {
        let pre = self.pre.as_ref().map(|a| a.lamports).unwrap_or(0);
        let post = self.post.as_ref().map(|a| a.lamports).unwrap_or(0);
        (pre, post)
    }

    /// Byte ranges in data that differ. Returns vec of (offset, len).
    /// Compares overlapping portion and reports any trailing data as changed.
    pub fn changed_data_ranges(&self) -> Vec<(usize, usize)> {
        let pre_data = self.pre.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);
        let post_data = self.post.as_ref().map(|a| a.data.as_slice()).unwrap_or(&[]);

        let mut ranges = Vec::new();
        let min_len = pre_data.len().min(post_data.len());
        let mut i = 0;

        while i < min_len {
            if pre_data[i] != post_data[i] {
                let start = i;
                while i < min_len && pre_data[i] != post_data[i] {
                    i += 1;
                }
                ranges.push((start, i - start));
            } else {
                i += 1;
            }
        }

        // Report any trailing data (different lengths) as a single range
        let max_len = pre_data.len().max(post_data.len());
        if max_len > min_len {
            ranges.push((min_len, max_len - min_len));
        }

        ranges
    }
}
