use crate::{FastHashMap, FastHashSet};
use anchor_lang::solana_program::instruction::Instruction;
use litesvm::LiteSVM;
use solana_account::Account;
use solana_pubkey::Pubkey;

use super::account_diff::AccountDiff;

/// Per-transaction record of which accounts were read and written.
/// Only recorded for successful transactions.
pub struct TxTaintRecord {
    /// Read-only AccountMetas + program_ids.
    pub read_accounts: Vec<Pubkey>,
    /// Writable AccountMetas + fee_payer.
    pub write_accounts: Vec<Pubkey>,
    /// Program IDs invoked.
    pub programs: Vec<Pubkey>,
    /// Before/after diffs. None when FUZZ_TAINT_DIFFS is off.
    pub diffs: Option<Vec<AccountDiff>>,
}

/// Collects TxTaintRecords across all transactions in an iteration.
pub struct IterationTaintLog {
    pub records: Vec<TxTaintRecord>,
    /// Whether to collect before/after diffs (from FUZZ_TAINT_DIFFS env var).
    pub(crate) collect_diffs: bool,
}

impl IterationTaintLog {
    pub fn new() -> Self {
        let collect_diffs = std::env::var("FUZZ_TAINT_DIFFS").is_ok();
        Self {
            records: Vec::new(),
            collect_diffs,
        }
    }

    /// Whether diffs collection is enabled.
    pub fn collects_diffs(&self) -> bool {
        self.collect_diffs
    }

    /// Push a taint record.
    pub fn push(&mut self, record: TxTaintRecord) {
        self.records.push(record);
    }

    /// Number of taint records collected so far.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether taint log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records (called at start of each iteration).
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Clone for IterationTaintLog {
    fn clone(&self) -> Self {
        // Fresh log for cloned contexts
        Self {
            records: Vec::new(),
            collect_diffs: self.collect_diffs,
        }
    }
}

// ============================================================================
// Helper functions for taint recording in send paths
// ============================================================================

/// Snapshot writable accounts before a transaction executes.
/// Only called when `FUZZ_TAINT_DIFFS=1` is set.
pub fn snapshot_writable_accounts(
    svm: &LiteSVM,
    instructions: &[Instruction],
    fee_payer: &Pubkey,
) -> FastHashMap<Pubkey, Option<Account>> {
    let mut pre = FastHashMap::default();
    pre.insert(*fee_payer, svm.get_account(fee_payer));
    for ix in instructions {
        for meta in &ix.accounts {
            if meta.is_writable {
                pre.entry(meta.pubkey)
                    .or_insert_with(|| svm.get_account(&meta.pubkey));
            }
        }
    }
    pre
}

/// Build a TxTaintRecord from instruction metadata.
/// Diffs are populated only if `pre_state` is Some (i.e., FUZZ_TAINT_DIFFS=1).
#[allow(dead_code)]
pub fn build_taint_record(
    svm: &LiteSVM,
    instructions: &[Instruction],
    fee_payer: &Pubkey,
    pre_state: Option<&FastHashMap<Pubkey, Option<Account>>>,
) -> TxTaintRecord {
    let mut read_accounts = Vec::new();
    let mut write_accounts = vec![*fee_payer];
    let mut programs = Vec::new();

    for ix in instructions {
        programs.push(ix.program_id);
        read_accounts.push(ix.program_id);
        for meta in &ix.accounts {
            if meta.is_writable {
                write_accounts.push(meta.pubkey);
            } else {
                read_accounts.push(meta.pubkey);
            }
        }
    }

    let diffs = pre_state.map(|pre| {
        pre.iter()
            .map(|(pubkey, pre_account)| AccountDiff {
                pubkey: *pubkey,
                pre: pre_account.clone(),
                post: svm.get_account(pubkey),
            })
            .collect()
    });

    TxTaintRecord {
        read_accounts,
        write_accounts,
        programs,
        diffs,
    }
}

/// Captured transaction metadata before instructions are consumed by send.
/// This allows building taint records even after instructions are moved.
pub struct CapturedTxMeta {
    pub read_accounts: Vec<Pubkey>,
    pub write_accounts: Vec<Pubkey>,
    pub programs: Vec<Pubkey>,
}

/// Capture metadata from instructions before they are consumed by send.
pub fn capture_tx_meta(instructions: &[Instruction], fee_payer: &Pubkey) -> CapturedTxMeta {
    let mut read_accounts = Vec::new();
    let mut write_accounts = vec![*fee_payer];
    let mut programs = Vec::new();

    for ix in instructions {
        programs.push(ix.program_id);
        read_accounts.push(ix.program_id);
        for meta in &ix.accounts {
            if meta.is_writable {
                write_accounts.push(meta.pubkey);
            } else {
                read_accounts.push(meta.pubkey);
            }
        }
    }

    CapturedTxMeta {
        read_accounts,
        write_accounts,
        programs,
    }
}

/// Build a TxTaintRecord from captured metadata and optional pre-state.
/// Used after instructions have been consumed by send.
pub fn build_taint_record_from_captured(
    svm: &LiteSVM,
    meta: CapturedTxMeta,
    pre_state: Option<&FastHashMap<Pubkey, Option<Account>>>,
) -> TxTaintRecord {
    let diffs = pre_state.map(|pre| {
        pre.iter()
            .map(|(pubkey, pre_account)| AccountDiff {
                pubkey: *pubkey,
                pre: pre_account.clone(),
                post: svm.get_account(pubkey),
            })
            .collect()
    });

    TxTaintRecord {
        read_accounts: meta.read_accounts,
        write_accounts: meta.write_accounts,
        programs: meta.programs,
        diffs,
    }
}

// ============================================================================
// Per-Action Taint Summary Builder
// ============================================================================

use crate::{ActionTaintSummary, AccountChangeSummary, AccountChangeKind};

/// Build a taint summary from TxTaintRecords in a range of the iteration log.
///
/// `start_idx..end_idx` covers the transactions produced by a single action dispatch.
/// Returns `None` if taint tracking is disabled (no records and no diffs).
pub fn build_action_taint_summary(
    log: &IterationTaintLog,
    start_idx: usize,
    end_idx: usize,
) -> Option<ActionTaintSummary> {
    let tx_count = end_idx.saturating_sub(start_idx);

    // If no transactions were recorded and we're not collecting diffs, skip
    if tx_count == 0 && !log.collects_diffs() {
        return None;
    }

    let mut written = FastHashSet::default();
    let mut read = FastHashSet::default();

    for record in log.records.get(start_idx..end_idx).unwrap_or(&[]) {
        for pk in &record.write_accounts {
            written.insert(*pk);
        }
        for pk in &record.read_accounts {
            read.insert(*pk);
        }
    }

    // Remove written accounts from read set (if you write it, it's not read-only)
    for pk in &written {
        read.remove(pk);
    }

    let written_accounts: Vec<String> = written.iter().map(|pk| pk.to_string()).collect();
    let read_accounts: Vec<String> = read.iter().map(|pk| pk.to_string()).collect();

    // Build account change details if diffs are available
    let account_changes = if log.collects_diffs() {
        build_account_changes(log, start_idx, end_idx)
    } else {
        None
    };

    Some(ActionTaintSummary {
        tx_count,
        written_accounts,
        read_accounts,
        account_changes,
    })
}

/// Merge per-tx AccountDiffs into per-account change summaries.
/// For each account, uses the first pre-state and last post-state across all txs.
fn build_account_changes(
    log: &IterationTaintLog,
    start_idx: usize,
    end_idx: usize,
) -> Option<Vec<AccountChangeSummary>> {
    use solana_pubkey::Pubkey;
    use solana_account::Account;

    // Collect first pre and last post per pubkey
    let mut first_pre: FastHashMap<Pubkey, Option<Account>> = FastHashMap::default();
    let mut last_post: FastHashMap<Pubkey, Option<Account>> = FastHashMap::default();

    for record in log.records.get(start_idx..end_idx).unwrap_or(&[]) {
        if let Some(ref diffs) = record.diffs {
            for diff in diffs {
                first_pre.entry(diff.pubkey).or_insert_with(|| diff.pre.clone());
                last_post.insert(diff.pubkey, diff.post.clone());
            }
        }
    }

    if first_pre.is_empty() {
        return None;
    }

    let mut changes = Vec::new();
    for (pubkey, pre) in &first_pre {
        let post = last_post.get(pubkey).cloned().flatten();
        let pre_ref = pre.as_ref();

        // Determine change kind
        let kind = match (pre_ref, &post) {
            (None, Some(_)) => AccountChangeKind::Created,
            (Some(_), None) => AccountChangeKind::Deleted,
            _ => AccountChangeKind::Modified,
        };

        // Compute lamports
        let pre_lamports = pre_ref.map(|a| a.lamports).unwrap_or(0);
        let post_lamports = post.as_ref().map(|a| a.lamports).unwrap_or(0);

        // Build a temporary AccountDiff to reuse changed_data_ranges()
        let temp_diff = AccountDiff {
            pubkey: *pubkey,
            pre: pre.clone(),
            post: post.clone(),
        };

        // Skip unchanged accounts
        if !temp_diff.is_changed() {
            continue;
        }

        let changed_ranges = temp_diff.changed_data_ranges();

        // Try semantic diff via schema registry
        let field_diffs = if let (Some(pre_acc), Some(post_acc)) = (pre_ref, &post) {
            crate::schema::lookup_diff_fn(&post_acc.data)
                .and_then(|diff_fn| {
                    let deltas = diff_fn(&pre_acc.data, &post_acc.data);
                    if deltas.is_empty() { None } else { Some(deltas) }
                })
        } else {
            None
        };

        changes.push(AccountChangeSummary {
            pubkey: pubkey.to_string(),
            kind,
            lamports: (pre_lamports, post_lamports),
            changed_ranges,
            field_diffs,
        });
    }

    if changes.is_empty() { None } else { Some(changes) }
}
