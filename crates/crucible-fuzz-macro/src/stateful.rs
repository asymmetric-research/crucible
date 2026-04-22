//! ItyFuzz-style stateful fuzzing mode for the anchor-fuzz macro.
//!
//! Instead of executing full action sequences per iteration, this mode:
//! 1. Maintains a pool of saved SVM states (snapshots)
//! 2. Each iteration: pick a random saved state, restore SVM, execute ONE action
//! 3. If the resulting state is novel (fingerprint-based dedup), save it to the pool
//! 4. If an invariant violation is detected, write a crash
//!
//! State novelty drives exploration instead of LibAFL's corpus/scheduler/feedback.
//! Coverage is still tracked for display but doesn't drive the fuzzing loop.
//!
//! Supports:
//! - Single-threaded mode (default, `FUZZ_STATEFUL=1`)
//! - Multi-threaded mode (`FUZZ_STATEFUL=1` + `FUZZ_CORES > 1`)
//! - No-tracing mode (`FUZZ_NO_TRACING=1`) for ~2.3x throughput

use quote::quote;

use crate::codegen;

/// Generate the stateful fuzzing mode code.
///
/// Activated when `FUZZ_STATEFUL=1` is set. This is checked before
/// the multicore/singlecore modes in the generated main().
pub fn stateful_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    fixture_param_name: &syn::Ident,
    feature_name: &str,
    structured: bool,
    action_type: Option<&proc_macro2::TokenStream>,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    if !structured {
        // Stateful mode only works with structured/invariant tests
        return quote! {
            if std::env::var("FUZZ_STATEFUL").is_ok() {
                eprintln!("[STATEFUL] ERROR: stateful mode only supports structured/invariant tests");
                std::process::exit(1);
            }
        };
    }

    let action_ty = match action_type {
        Some(ty) => ty,
        None => {
            return quote! {
                if std::env::var("FUZZ_STATEFUL").is_ok() {
                    eprintln!("[STATEFUL] ERROR: stateful mode requires an action type");
                    std::process::exit(1);
                }
            };
        }
    };

    let template_setup_code = codegen::template_setup(fixture_name, mod_name);

    // Extra context helpers for the parent quote block (snapshot + swap-out)
    let extra_take_snapshot = codegen::stateful_extra_take_snapshot(contexts);
    let extra_swap_out = codegen::stateful_extra_swap_out(contexts);

    let singlecore_body = stateful_singlecore_body(
        mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        feature_name,
        action_ty,
        contexts,
    );
    let multicore_body = stateful_multicore_body(
        mod_name,
        fixture_name,
        fn_name,
        fixture_param_name,
        feature_name,
        action_ty,
        contexts,
    );

    quote! {
        // === STATEFUL FUZZING MODE (ItyFuzz-style) ===
        if std::env::var("FUZZ_STATEFUL").is_ok() {
            use crucible_test_context::snapshot::{
                StatePool, SvmSnapshot, CompactDelta, compute_state_fingerprint_from_snapshot,
            };
            use libafl_bolts::rands::{Rand, StdRand};

            eprintln!("[STATEFUL] ItyFuzz-style stateful fuzzing mode");

            // Parse pool capacity from env or default to 10_000.
            // Smaller pools focus exploration: each state gets picked more often,
            // enabling deeper chain building. With 100K pool and 1 action/iter,
            // each state averages <1 pick, preventing productive depth exploration.
            let pool_capacity: usize = match std::env::var("FUZZ_STATE_POOL_SIZE") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_STATE_POOL_SIZE='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => 256_000, // 256k
            };

            // Parse max depth from env. Falls back to FUZZ_MAX_ACTIONS, then 10.
            let max_depth: u32 = match std::env::var("FUZZ_MAX_DEPTH") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_MAX_DEPTH='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => match std::env::var("FUZZ_MAX_ACTIONS") {
                    Ok(s) => s.parse().unwrap_or_else(|e| {
                        panic!("[STATEFUL] FUZZ_MAX_ACTIONS='{}' is not a valid number: {}", s, e);
                    }),
                    Err(_) => 10,
                },
            };


            // Use seed from env var if provided, otherwise use current time
            let seed = match std::env::var("FUZZ_SEED") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_SEED='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => libafl_bolts::current_nanos().max(1),
            };

            let timeout_secs: Option<u64> = match std::env::var("FUZZ_TIMEOUT_SECS") {
                Ok(s) => Some(s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_TIMEOUT_SECS='{}' is not a valid number: {}", s, e);
                })),
                Err(_) => None,
            };

            let crash_dir = crashes_dir_env.unwrap_or_else(|| format!("crashes/{}", #feature_name));
            std::fs::create_dir_all(&crash_dir).expect("failed to create crash directory");

            let stop_on_crash = std::env::var("FUZZ_STOP_ON_CRASH").is_ok();
            let no_tracing = std::env::var("FUZZ_NO_TRACING").is_ok();

            // Trace interval: how often to collect coverage via the traced SVM.
            // Default 1 = every iteration traced (shared bitmap sync handles scaling).
            // Set to N > 1 for dual-SVM mode (fast SVM most iters, traced every Nth).
            // --no-tracing overrides this to 0.
            let trace_interval: u64 = if no_tracing {
                0
            } else {
                match std::env::var("FUZZ_TRACE_INTERVAL") {
                    Ok(s) => s.parse().unwrap_or_else(|e| {
                        panic!("[STATEFUL] FUZZ_TRACE_INTERVAL='{}' is not a valid number: {}", s, e);
                    }),
                    Err(_) => 1,
                }
            };

            // Global signal flag for clean Ctrl+C / SIGTERM shutdown
            static SIGNAL_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            extern "C" fn __signal_handler(_sig: libc::c_int) {
                SIGNAL_STOP.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            unsafe {
                libc::signal(libc::SIGINT, __signal_handler as libc::sighandler_t);
                libc::signal(libc::SIGTERM, __signal_handler as libc::sighandler_t);
            }

            // Coverage map for FuzzCallback — also used for hitcount-based novelty detection.
            // After each iteration the map is scanned: if any byte's bucketed hitcount
            // exceeds the corresponding virgin_map entry, we treat this as new coverage.
            // This mirrors LibAFL's MaxMapFeedback and prevents the coverage plateau
            // that occurs when only new unique edges (not hitcount changes) are detected.
            let mut __stateful_coverage_map = vec![0u8; #mod_name::MAP_SIZE];
            let __stateful_cov_ptr = __stateful_coverage_map.as_mut_ptr();
            // Virgin map: tracks the maximum bucketed hitcount seen for each map position.
            // Initialized to 0 (no coverage seen). Updated after each iteration.
            let mut __virgin_map = vec![0u8; #mod_name::MAP_SIZE];
            let mut __field_novelty_bitmap = vec![0u8; crucible_test_context::snapshot::FIELD_NOVELTY_BITMAP_SIZE];
            // Account novelty bitmap: tracks per-account (pubkey, exponentially-binned state)
            // Setup fixture (always with tracing initially for coverage baseline)
            #template_setup_code

            // Take snapshot of initial state (all contexts)
            #[allow(unused_mut)]
            let mut template_fixture = template_fixture;
            template_fixture.ctx.take_snapshot();
            #extra_take_snapshot

            let base_snapshot = template_fixture.ctx.snapshot.as_ref()
                .expect("snapshot must exist after take_snapshot()")
                .clone();

            // SVM swap trick (same as singlecore): move real SVM out of template
            // Use LiteSVM::default() as placeholder — bare minimum struct with no builtins
            // or program cache. LiteSVM::new() would load all built-in programs (~hundreds of MB)
            // which is wasted since the placeholder is never executed (always replaced via swap).
            // With 33k pool entries each cloning the fixture, this saves GBs of memory.
            let mut __real_svm = std::mem::replace(
                &mut template_fixture.ctx.svm,
                crucible_test_context::litesvm::LiteSVM::default(),
            );
            // Swap out additional context SVMs
            #extra_swap_out

            // Create initial snapshot capturing ALL accounts (not just dirty-tracked ones).
            // This is critical for multicore: workers restore from this snapshot
            // and need every account that was set up on the main thread.
            // Wrapped in Arc for cheap sharing across worker threads.
            let initial_snapshot = std::sync::Arc::new(SvmSnapshot::take_all(&__real_svm));

            // === Dual-SVM setup ===
            // traced SVM = debuggable (slow, collects register traces for coverage)
            // fast SVM = non-debuggable (fast, no tracing overhead)
            //
            // When trace_interval > 0, workers use the fast SVM most of the time
            // and switch to the traced SVM every `trace_interval` iterations.
            // When trace_interval == 0 (--no-tracing), only the fast SVM is used.
            // When trace_interval == 1, only the traced SVM is used (old behavior).
            let mut __traced_svm: Option<crucible_test_context::litesvm::LiteSVM> = if trace_interval != 1 {
                // Keep the traced SVM for periodic coverage collection
                Some(__real_svm.clone())
            } else {
                None
            };

            // Helper closure: create an SVM with performance settings.
            // Consolidates all SVM creation to avoid duplicated env var manipulation.
            let __create_svm = |debuggable: bool| -> crucible_test_context::litesvm::LiteSVM {
                let svm = if debuggable {
                    crucible_test_context::litesvm::LiteSVM::new_debuggable(true)
                } else {
                    crucible_test_context::litesvm::LiteSVM::new()
                };
                svm.with_transaction_history(0)
                    .with_sigverify(false)
                    .with_blockhash_check(false)
            };

            // Create fast (non-debuggable) SVM by restoring snapshot into a fresh SVM.
            // This avoids re-running setup() which would produce different keypairs/addresses.
            let __fast_svm: Option<crucible_test_context::litesvm::LiteSVM> = if trace_interval != 1 {
                let mut fast = __create_svm(false);
                initial_snapshot.restore_full(&mut fast);
                if trace_interval == 0 {
                    eprintln!("[STATEFUL] No-tracing mode: all iterations use fast SVM");
                } else {
                    eprintln!("[STATEFUL] Dual-SVM: tracing every {} iterations", trace_interval);
                }
                Some(fast)
            } else {
                eprintln!("[STATEFUL] Full tracing mode (trace_interval=1)");
                None
            };

            // Primary SVM = fast if available, otherwise traced
            if let Some(ref fast) = __fast_svm {
                __real_svm = fast.clone();
            }

            // Type-erased fixture wrapper for storing in StatePool.
            // Send+Sync are required because StatePool is behind Arc<RwLock<>> in multicore.
            // Safety: all pool access is behind RwLock (multicore) or single-threaded (singlecore).
            // Fixture cloning (which touches Rc refcounts) happens under the write lock.
            struct __FixtureWrapper(#fixture_name);
            unsafe impl Send for __FixtureWrapper {}
            unsafe impl Sync for __FixtureWrapper {}

            // Store initial fixture state (SVM already swapped out = cheap clone)
            let __initial_fixture_state: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                Some(std::sync::Arc::new(__FixtureWrapper(template_fixture.clone())));

            let num_cores: usize = match std::env::var("FUZZ_CORES") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_CORES='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => 1,
            };

            if num_cores > 1 {
                #multicore_body
            } else {
                #singlecore_body
            }
        }
    }
}

// =============================================================================
// Shared helpers — extracted to avoid duplication between singlecore/multicore
// =============================================================================

/// Post-execution truncation: if the chain broke early (stateful_chain_mode
/// break on failure), strip unexecuted actions from `__single_action_buf` so
/// crash files and pool entries don't contain bytes for actions that never ran.
fn gen_post_exec_truncation() -> proc_macro2::TokenStream {
    quote! {
        {
            let __actually_executed = crucible_test_context::get_action_history().len();
            if __actually_executed < __chain_len {
                let __truncate_at = __action_byte_offsets[__actually_executed];
                __single_action_buf.truncate(__truncate_at);
                __chain_len = __actually_executed;
                // Update variant index and descriptions to match truncated chain.
                // __action_variant_idx was set from __action_chain.last() (the last
                // GENERATED action), but after truncation we need the last EXECUTED
                // action's variant. Read it from the serialized buffer (2-byte LE prefix).
                if __chain_len > 0 {
                    let __last_offset = __action_byte_offsets[__chain_len - 1];
                    if __last_offset + 2 <= __single_action_buf.len() {
                        __action_variant_idx = u16::from_le_bytes(
                            __single_action_buf[__last_offset..__last_offset + 2].try_into().unwrap()
                        ) as usize;
                    }
                }
                __chain_descs.truncate(__chain_len);
            }
        }
    }
}

/// Generate the action chain: adaptive chain length, crossover/splice/parent
/// mutation, guided variant selection, action serialization, byte offset
/// tracking, and chain description pre-computation.
///
/// Parameters:
/// - `pool_fill_expr`: expression for pool fill ratio (e.g. `state_pool.len()` or `__cached_pool_len`)
/// - `pending_selects_var`: variable to push state_class into (e.g. `__pending_selects` or `pending_selects`)
fn gen_action_chain(
    action_ty: &proc_macro2::TokenStream,
    pool_fill_expr: &proc_macro2::TokenStream,
    pending_selects_var: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        let __state_class = crucible_test_context::snapshot::state_class_from_fingerprint(parent_fingerprint);
        #pending_selects_var.push(__state_class);

        let mut __action_chain: Vec<#action_ty>;
        __single_action_buf.clear();

        if let Some(__spliced) = __splice_chain {
            // Subsequence splice: use pre-built chain from donor state
            __action_chain = __spliced;
            for __a in &__action_chain {
                __single_action_buf.extend_from_slice(&(__a.variant_index() as u16).to_le_bytes());
                __a.serialize_fields(&mut __single_action_buf);
            }
        } else {
            // Adaptive chain length: longer chains early (depth exploration),
            // shorter chains as pool fills (exploit discovered states).
            let __pool_fill = #pool_fill_expr as f64 / pool_capacity as f64;
            let __chain_roll = rng.next() % 100;
            let __chain_len: usize = if __pool_fill < 0.05 {
                // Bootstrap (<5%): very aggressive depth — mean ~2.8
                if __chain_roll < 20 { 1 } else if __chain_roll < 45 { 2 } else if __chain_roll < 70 { 3 } else if __chain_roll < 85 { 4 } else { 5 }
            } else if __pool_fill < 0.25 {
                // Early (<25%): depth-heavy — mean ~2.15
                if __chain_roll < 35 { 1 } else if __chain_roll < 65 { 2 } else if __chain_roll < 85 { 3 } else if __chain_roll < 95 { 4 } else { 5 }
            } else if __pool_fill < 0.6 {
                // Mid (<60%): balanced — mean ~1.76
                if __chain_roll < 55 { 1 } else if __chain_roll < 80 { 2 } else if __chain_roll < 92 { 3 } else if __chain_roll < 97 { 4 } else { 5 }
            } else {
                // Mature (≥60%): exploit — mean ~1.22
                if __chain_roll < 85 { 1 } else if __chain_roll < 95 { 2 } else if __chain_roll < 98 { 3 } else if __chain_roll < 99 { 4 } else { 5 }
            };

            __action_chain = Vec::with_capacity(__chain_len);

            for __ci in 0..__chain_len {
                let __replay_roll = rng.next() % 100;
                let __one_action = if __replay_roll < 35 && !__crossover_buf.is_empty() {
                    // 35%: Crossover EXACT replay (exploit known-good params)
                    let __cross_idx = rng.next() as usize % __crossover_buf.len();
                    let (cross_vi, ref cross_fields) = __crossover_buf[__cross_idx];
                    if !cross_fields.is_empty() {
                        let mut cursor = 0usize;
                        match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(cross_vi, &*cross_fields, &mut cursor) {
                            Some(a) => a,
                            None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                        }
                    } else {
                        <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(cross_vi, &mut rng)
                    }
                } else if __replay_roll < 45 && !__crossover_buf.is_empty() {
                    // 10%: Crossover + mutate (secondary exploration)
                    let __cross_idx = rng.next() as usize % __crossover_buf.len();
                    let (cross_vi, ref cross_fields) = __crossover_buf[__cross_idx];
                    if !cross_fields.is_empty() {
                        let mut cursor = 0usize;
                        match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(cross_vi, &*cross_fields, &mut cursor) {
                            Some(mut a) => {
                                <#action_ty as crucible_fuzzer::FuzzAction>::mutate(&mut a, &mut rng);
                                a
                            }
                            None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                        }
                    } else {
                        <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(cross_vi, &mut rng)
                    }
                } else if __replay_roll < 55 && parent_variant.is_some() && !parent_field_bytes.is_empty() {
                    // 10%: Mutate parent's actual action
                    let pv = parent_variant.unwrap() as usize;
                    let mut cursor = 0usize;
                    match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(pv, &*parent_field_bytes, &mut cursor) {
                        Some(mut a) => {
                            <#action_ty as crucible_fuzzer::FuzzAction>::mutate(&mut a, &mut rng);
                            a
                        }
                        None => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(pv, &mut rng),
                    }
                } else {
                    // 45%: Guided variant selection (epsilon-greedy from ActionStatsMap)
                    match action_stats.pick_variant(__state_class, rng.next(), rng.next()) {
                        Some(vi) => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(vi, &mut rng),
                        None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                    }
                };
                // Serialize this action's bytes
                __single_action_buf.extend_from_slice(&(__one_action.variant_index() as u16).to_le_bytes());
                __one_action.serialize_fields(&mut __single_action_buf);
                __action_chain.push(__one_action);
            }
        }
        let mut __chain_len = __action_chain.len();
        // Track byte offset of each action in __single_action_buf for post-execution truncation
        let __action_byte_offsets: Vec<usize> = {
            let mut offsets = Vec::with_capacity(__chain_len + 1);
            let mut pos = 0usize;
            for __a in &__action_chain {
                offsets.push(pos);
                pos += 2 + <#action_ty as crucible_fuzzer::FuzzAction>::field_byte_count(__a.variant_index());
            }
            offsets.push(pos); // sentinel: end of last action
            offsets
        };
        // Use last action's variant for stats recording (updated by truncation if chain breaks early)
        let mut __action_variant_idx = __action_chain.last().unwrap().variant_index();

        // Pre-compute action descriptions with params BEFORE the chain is consumed
        // by the test function. Without this, pool entries only get action names
        // (no params) because push_action_record_lite defers param serialization.
        let mut __chain_descs: Vec<String> = __action_chain.iter().map(|__a| {
            let __params = __a.to_json_params();
            let __ps = if let serde_json::Value::Object(ref __map) = __params {
                __map.iter()
                    .map(|(k, v)| format!("{}={}", k, crucible_test_context::format_json_value(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else { String::new() };
            if __ps.is_empty() {
                __a.action_name().to_string()
            } else {
                format!("{}({})", __a.action_name(), __ps)
            }
        }).collect();
    }
}

/// Generate the corpus seeding loop (CORPUS-IN: seed pool from disk).
///
/// This is the shared implementation used by both singlecore and multicore
/// stateful modes. Parameters capture the differences:
///
/// - `pool_var`: token for pool access (e.g. `state_pool` or `pool`)
/// - `swap_in_seed` / `swap_back_seed`: extra context swap tokens for seed fixture
/// - `callback_expr`: FuzzCallback constructor (from_raw vs with_shared_memory)
/// - `pre_loop`: code before the file iteration (e.g. acquiring a write lock)
/// - `post_exec_flush`: optional bitmap flush after each seed action (multicore only)
/// - `debug_diag`: optional debug replay diagnostic block (singlecore only)
/// - `edge_count_expr`: how to count edges after seeding
/// - `post_seeding`: code after seeding completes (drop lock, mark boundary)
fn gen_corpus_seeding(
    _mod_name: &syn::Ident,
    fn_name: &syn::Ident,
    action_ty: &proc_macro2::TokenStream,
    pool_var: &proc_macro2::TokenStream,
    swap_in_seed: &proc_macro2::TokenStream,
    swap_back_seed: &proc_macro2::TokenStream,
    callback_expr: &proc_macro2::TokenStream,
    pre_loop: &proc_macro2::TokenStream,
    post_exec_flush: &proc_macro2::TokenStream,
    debug_diag: &proc_macro2::TokenStream,
    edge_count_expr: &proc_macro2::TokenStream,
    post_seeding: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        if let Some(ref __corpus_in_path) = corpus_in_dir {
            let mut __seed_files: Vec<std::path::PathBuf> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(__corpus_in_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && is_corpus_input(&path) {
                        __seed_files.push(path);
                    }
                }
            }
            __seed_files.sort();

            let __seed_depth_limit: u32 = match std::env::var("FUZZ_SEED_DEPTH") {
                Ok(s) => s.parse().unwrap_or_else(|e| {
                    panic!("[STATEFUL] FUZZ_SEED_DEPTH='{}' is not a valid number: {}", s, e);
                }),
                Err(_) => u32::MAX,
            };

            let mut __seeded = 0u64;
            #pre_loop
            for __seed_path in &__seed_files {
                let __seed_bytes = match std::fs::read(__seed_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let __fuzz_input = crucible_fuzzer::FuzzInput::<#action_ty>::from_bytes(&__seed_bytes);
                if __fuzz_input.actions.is_empty() { continue; }

                // Reset SVM to initial state for this sequence
                initial_snapshot.restore_full(&mut __real_svm);

                // One fixture per sequence — accumulates mutable state across actions
                let mut __seed_fixture = template_fixture.clone();

                let mut __parent_idx: Option<usize> = Some(0); // initial state
                let mut __current_depth: u32 = 0;
                let mut __current_action_bytes: Vec<u8> = 0u32.to_le_bytes().to_vec();
                let mut __current_delta = std::sync::Arc::new(
                    CompactDelta::empty(initial_snapshot.clock().clone())
                );

                for __seed_action in &__fuzz_input.actions {
                    if __current_depth >= max_depth.min(__seed_depth_limit) { break; }
                    if #pool_var.is_full() { break; }

                    // Swap SVMs into fixture (primary + additional contexts)
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                    #swap_in_seed

                    let callback = #callback_expr;
                    __seed_fixture.ctx.set_invocation_callback(callback);
                    crucible_test_context::clear_iteration_state();
                    crucible_test_context::reset_iteration_dispatch_count();

                    let __seed_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        #fn_name(&mut __seed_fixture, vec![__seed_action.clone()]);
                    }));
                    #post_exec_flush

                    // Check success
                    let __seed_ok = __seed_panic.is_ok() && {
                        crucible_test_context::get_first_action_success().unwrap_or(false)
                    };

                    #debug_diag

                    if !__seed_ok {
                        // Swap SVMs back and stop this sequence
                        #swap_back_seed
                        std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                        break;
                    }

                    // Serialize the single action
                    let __single_bytes = {
                        let mut buf = Vec::new();
                        buf.extend_from_slice(&(__seed_action.variant_index() as u16).to_le_bytes());
                        __seed_action.serialize_fields(&mut buf);
                        buf
                    };

                    // Build accumulated action bytes
                    let mut __accum = __current_action_bytes.clone();
                    let __count = u32::from_le_bytes(__accum[0..4].try_into().unwrap());
                    __accum[0..4].copy_from_slice(&(__count + 1).to_le_bytes());
                    __accum.extend_from_slice(&__single_bytes);

                    // Take compact delta: build per-execution patches, then inherit parent
                    let __exec_delta = crucible_test_context::snapshot::CompactDelta::from_dirty(
                        &*initial_snapshot,
                        &__seed_fixture.ctx.svm,
                        __seed_fixture.ctx.dirty_tracker.dirty_accounts(),
                    );
                    // Merge: inherit parent patches for non-re-dirtied accounts
                    let __new_delta = crucible_test_context::snapshot::CompactDelta::child_delta_from(
                        &__current_delta,
                        __exec_delta,
                        __seed_fixture.ctx.dirty_tracker.dirty_accounts(),
                        &__seed_fixture.ctx.svm,
                    );

                    // Fingerprint
                    let __fp = compute_state_fingerprint_from_snapshot(
                        &__seed_fixture.ctx.svm, &__seed_fixture.ctx.dirty_tracker, &*initial_snapshot,
                    );

                    __current_depth += 1;
                    // Backfill params so the stored action_desc includes them in crash output
                    crucible_test_context::backfill_action_params(0, __seed_action.to_json_params());
                    let __action_desc = crucible_test_context::format_last_action_oneline();
                    let __variant = __seed_action.variant_index() as u16;
                    let __field_bytes = if __single_bytes.len() > 2 {
                        __single_bytes[2..].to_vec()
                    } else { Vec::new() };

                    // Store fixture state (swap SVMs out for cheap clone)
                    #swap_back_seed
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                    let __fs: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                        Some(std::sync::Arc::new(__FixtureWrapper(__seed_fixture.clone())));
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                    #swap_in_seed

                    // Seeded states get minimum novelty so they're competitive in the
                    // power schedule. edge_novelty=1 puts them in the coverage weight
                    // tier; without this they get 0 novelty → almost never picked.
                    // Seeds use fallback rarity (no coverage_positions) because the
                    // cumulative coverage map doesn't represent per-seed coverage.
                    if __fp != 0 && #pool_var.try_add(
                        __fp, __new_delta.clone(), __current_depth, __parent_idx,
                        __accum.clone(), __action_desc, Some(__variant), __field_bytes,
                        __fs, 8, 1, true, None,
                    ) {
                        __parent_idx = Some(#pool_var.len() - 1);
                        __seeded += 1;
                    }

                    __current_delta = std::sync::Arc::new(__new_delta);
                    __current_action_bytes = __accum;

                    // Swap SVMs back for next action (SVM stays modified = correct sequential state)
                    #swap_back_seed
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                }
            }

            // Reset SVM to initial for the main loop
            initial_snapshot.restore_full(&mut __real_svm);
            let __seed_edges = #edge_count_expr;
            eprintln!("[STATEFUL] Seeded {} states from {} corpus files, edges after loading: {}",
                __seeded, __seed_files.len(), __seed_edges);
        }
        #post_seeding
    }
}

/// Generate the single-threaded stateful fuzzing loop body.
fn stateful_singlecore_body(
    mod_name: &syn::Ident,
    _fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    fixture_param_name: &syn::Ident,
    _feature_name: &str,
    action_ty: &proc_macro2::TokenStream,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    // Extra context helpers (for contexts[1..])
    let extra_swap_in_fixture = codegen::stateful_extra_swap_in(fixture_param_name, contexts);
    let extra_restore_swap_back_fixture =
        codegen::stateful_extra_restore_and_swap_back(fixture_param_name, contexts);
    // For seed phase, we use __seed_fixture as the param name
    let seed_ident = quote::format_ident!("__seed_fixture");
    let extra_swap_in_seed = codegen::stateful_extra_swap_in(&seed_ident, contexts);
    let extra_swap_back_seed = codegen::stateful_extra_swap_back(&seed_ident, contexts);

    let seed_code = gen_corpus_seeding(
        mod_name,
        fn_name,
        action_ty,
        &quote! { state_pool },
        &extra_swap_in_seed,
        &extra_swap_back_seed,
        &quote! { #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE) },
        &quote! {}, // no pre-loop setup in singlecore (pool is local)
        &quote! {}, // no post-exec flush in singlecore
        &quote! {   // debug diagnostics (singlecore only)
            if crucible_test_context::is_debug_replay() {
                let __dirty_keys: Vec<_> = __seed_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied().collect();
                let (__sh, __sl) = crucible_test_context::compute_svm_debug_hash(
                    &__seed_fixture.ctx.svm, &__dirty_keys,
                );
                let __dbg_file = __seed_path.file_name().unwrap_or_default().to_string_lossy();
                eprintln!("[SEED_DIAG] file={} action={}/{} variant={} success={} slot={} hash={:016x}",
                    __dbg_file, __current_depth + 1, __fuzz_input.actions.len(),
                    __seed_action.action_name(), __seed_ok, __sl, __sh);
            }
        },
        &quote! { #mod_name::TOTAL_EDGES_ATOMIC.load(std::sync::atomic::Ordering::Relaxed) },
        &quote! { state_pool.mark_seed_boundary(); },
    );

    let action_chain_code = gen_action_chain(
        action_ty,
        &quote! { state_pool.len() },
        &quote! { __pending_selects },
    );
    let truncation_code = gen_post_exec_truncation();

    quote! {
        // === SINGLE-THREADED STATEFUL ===
        let mut state_pool = StatePool::new(pool_capacity, max_depth);
        // Initial pool entry: empty delta (state is identical to initial_snapshot)
        let initial_clock = initial_snapshot.clock().clone();
        state_pool.try_add(0, CompactDelta::empty(initial_clock), 0, None, 0u32.to_le_bytes().to_vec(), String::new(), None, Vec::new(), __initial_fixture_state.clone(), 0, 0, true, None);

        // Action success tracking: learns which actions work from which state classes
        let mut action_stats = crucible_test_context::snapshot::ActionStatsMap::new(
            <#action_ty as crucible_fuzzer::FuzzAction>::variant_count(),
        );

        crucible_test_context::set_stateful_chain_mode(true);

        let mut rng = StdRand::with_seed(seed);
        let mut iteration: u64 = 0;
        let mut crashes_found: u64 = 0;
        let mut novel_states: u64 = 0;

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = #mod_name::FUZZER_START_TIME.set(start_time);

        // Rate-limited monitor variables
        let mut last_print_time = std::time::Instant::now();
        let mut last_print_iter: u64 = 0;

        // Track accounts that currently differ from initial in the SVM.
        // Used for selective restore: only reset these accounts instead of all ~200.
        let mut divergent_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
            crucible_test_context::FastHashSet::default();

        // Track previous iteration's delta for Arc-pointer-based restore optimization.
        // When consecutive picks share common ancestry, many delta accounts have the
        // same Arc pointer — skipping those set_account calls saves ~175µs per iteration.
        let mut prev_delta_arc: Option<std::sync::Arc<CompactDelta>> = None;
        // Accounts dirtied by the previous execution. Must NOT be skipped by Arc
        // pointer comparison — the SVM has post-execution values, not delta values.
        let mut prev_exec_dirty: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
            crucible_test_context::FastHashSet::default();

        // Dual-SVM: take ownership of traced SVM for periodic coverage collection.
        // When trace_interval > 1, this holds the debuggable SVM used every Nth iteration.
        // When trace_interval <= 1, this is None (single-SVM mode).
        let mut __dual_traced_svm = if trace_interval > 1 { __traced_svm.take() } else { None };
        let mut traced_divergent: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
            crucible_test_context::FastHashSet::default();

        eprintln!("[STATEFUL] Pool capacity: {}k, max depth: {}, seed: {}", pool_capacity / 1024, max_depth, seed);

        #seed_code

        eprintln!("[STATEFUL] Starting stateful fuzzing loop...\n");

        let mut __phase_pick_ns: u64 = 0;
        let mut __phase_pick_flush_ns: u64 = 0;
        let mut __phase_pick_batch_ns: u64 = 0;
        let mut __phase_pick_crossover_ns: u64 = 0;
        let mut __phase_pick_splice_ns: u64 = 0;
        let mut __phase_restore_ns: u64 = 0;
        let mut __phase_action_gen_ns: u64 = 0;
        let mut __phase_clone_ns: u64 = 0;
        let mut __phase_svm_exec_ns: u64 = 0;
        let mut __phase_tx_pre_ns: u64 = 0;
        let mut __phase_tx_svm_ns: u64 = 0;
        let mut __phase_tx_post_ns: u64 = 0;
        let mut __phase_tx_blockhash_ns: u64 = 0;
        let mut __phase_tx_sign_ns: u64 = 0;
        let mut __phase_tx_exec_ns: u64 = 0;
        let mut __phase_coverage_ns: u64 = 0;
        let mut __phase_field_novelty_ns: u64 = 0;
        let mut __phase_fingerprint_ns: u64 = 0;
        let mut __phase_save_ns: u64 = 0;
        let mut __phase_crash_ns: u64 = 0;
        let mut __phase_cleanup_ns: u64 = 0;
        let mut __phase_total_ns: u64 = 0;
        let mut __profiled_iters: u64 = 0;
        let __profile_interval: u64 = 64;
        let mut __single_action_buf: Vec<u8> = Vec::with_capacity(64);

        // Batched picks: compute weights once per batch, O(1) per iteration instead of O(n).
        const __BATCH_SIZE: usize = 64;
        type __PickTuple = (std::sync::Arc<CompactDelta>, u32, usize, std::sync::Arc<Vec<u8>>, Option<u16>, std::sync::Arc<Vec<u8>>, u64, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);
        let mut __pick_batch: Vec<__PickTuple> = Vec::with_capacity(__BATCH_SIZE);
        let mut __rng_vals: Vec<u64> = Vec::with_capacity(__BATCH_SIZE);
        let mut __crossover_buf: Vec<(usize, std::sync::Arc<Vec<u8>>)> = Vec::with_capacity(16);
        let mut __pending_selects: Vec<u16> = Vec::with_capacity(__BATCH_SIZE);

        // Cached weight distribution — rebuilt at batch boundaries, reused for crossover + splice
        let mut __weight_cumulative: Vec<f64> = Vec::new();
        let mut __weight_total: f64 = 0.0;

        loop {
            if SIGNAL_STOP.load(std::sync::atomic::Ordering::Relaxed) { break; }
            iteration += 1;

            // Timeout check (rate-limited)
            if let Some(timeout) = timeout_secs {
                if iteration % 1000 == 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if now - start_time >= timeout {
                        eprintln!("\n[STATEFUL] Timeout reached ({}s). Exiting.", timeout);
                        if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                            #mod_name::write_lcov_coverage("coverage.lcov");
                        }
                        if let Some(ref __corpus_out_path) = corpus_out_dir {
                            match state_pool.export_corpus(__corpus_out_path, corpus_in_dir.as_deref()) {
                                Ok(n) => eprintln!("[STATEFUL] Saved {} corpus entries to {}", n, __corpus_out_path),
                                Err(e) => eprintln!("[STATEFUL] Failed to save corpus: {}", e),
                            }
                        }
                        std::process::exit(0);
                    }
                }
            }

            let __do_profile = (iteration % __profile_interval) == 0;
            let __iter_start = if __do_profile { Some(std::time::Instant::now()) } else { None };

            // 1. Refill batch when empty (amortizes O(n) weight computation over BATCH_SIZE iterations)
            let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
            if __pick_batch.is_empty() {
                let __t_flush = if __do_profile { Some(std::time::Instant::now()) } else { None };
                // Flush pending selects into registry
                for __sc in __pending_selects.drain(..) {
                    state_pool.registry_mut().record_select(__sc);
                }
                state_pool.set_current_iteration(iteration);
                state_pool.maybe_advance_phase();
                if let Some(__t) = __t_flush { __phase_pick_flush_ns += __t.elapsed().as_nanos() as u64; }

                let __t_batch = if __do_profile { Some(std::time::Instant::now()) } else { None };
                __rng_vals.clear();
                for _ in 0..__BATCH_SIZE {
                    __rng_vals.push(rng.next());
                }
                // Build weight distribution once, reuse for batch + crossover + splice
                let (__wc, __wt) = state_pool.build_weight_distribution();
                __weight_cumulative = __wc;
                __weight_total = __wt;
                state_pool.pick_weighted_batch_from(&__weight_cumulative, __weight_total, &__rng_vals, &mut __pick_batch);
                if let Some(__t) = __t_batch { __phase_pick_batch_ns += __t.elapsed().as_nanos() as u64; }

                let __t_cross = if __do_profile { Some(std::time::Instant::now()) } else { None };
                // Refresh crossover candidates using pre-built distribution (O(log n) per pick)
                __crossover_buf.clear();
                for _ in 0..16usize {
                    if let Some(idx) = state_pool.sample_from_distribution(&__weight_cumulative, __weight_total, rng.next()) {

                        if let Some(entry) = state_pool.get(idx) {
                            if let Some(vi) = entry.action_variant {
                                __crossover_buf.push((vi as usize, entry.action_field_bytes.clone()));
                            }
                        }
                    }
                }
                if let Some(__t) = __t_cross { __phase_pick_crossover_ns += __t.elapsed().as_nanos() as u64; }
                if __pick_batch.is_empty() {
                    eprintln!("[STATEFUL] All active states exhausted (all led to crashes). Stopping.");
                    break;
                }
            }
            let (mut delta_arc, mut parent_depth, mut state_idx, mut parent_action_bytes, parent_variant, parent_field_bytes, mut parent_fingerprint, mut __picked_fixture_state) =
                __pick_batch.pop().unwrap();

            // Subsequence splice (5%): pick a random contiguous subsequence (len 2-5) from
            // a donor pool state's action chain and execute it from the initial state.
            // Tests whether mid-chain subsequences trigger bugs from clean state.
            let __t_splice = if __do_profile { Some(std::time::Instant::now()) } else { None };
            let __splice_roll = rng.next() % 100;
            let mut __splice_chain: Option<Vec<#action_ty>> = None;
            if __splice_roll < 5 && state_pool.len() > 10 {
                // 5%: Donor splice — extract subsequence from an existing chain
                let __donor_idx = state_pool.sample_from_distribution(&__weight_cumulative, __weight_total, rng.next()).unwrap_or(0);
                let __donor_seq = state_pool.reconstruct_variant_field_sequence(__donor_idx);
                if __donor_seq.len() >= 2 {
                    let __splice_len = (2 + rng.next() as usize % 4).min(__donor_seq.len());
                    let __splice_start = rng.next() as usize % (__donor_seq.len() - __splice_len + 1);
                    let mut __spliced_actions: Vec<#action_ty> = Vec::with_capacity(__splice_len);
                    for (vi, ref fb) in &__donor_seq[__splice_start..__splice_start + __splice_len] {
                        let action = if !fb.is_empty() {
                            let mut cursor = 0usize;
                            match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(*vi, &*fb, &mut cursor) {
                                Some(a) => a,
                                None => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng),
                            }
                        } else {
                            <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng)
                        };
                        __spliced_actions.push(action);
                    }
                    if !__spliced_actions.is_empty() {
                        // Override pick to initial state
                        if let Some(entry) = state_pool.get(0) {
                            delta_arc = entry.delta.clone();
                            parent_depth = 0;
                            state_idx = 0;
                            parent_action_bytes = entry.action_bytes.clone();
                            parent_fingerprint = entry.fingerprint;
                            __picked_fixture_state = entry.fixture_state.clone();
                        }
                        __splice_chain = Some(__spliced_actions);
                    }
                }
            }
            if let Some(__t) = __t_splice { __phase_pick_splice_ns += __t.elapsed().as_nanos() as u64; }
            if let Some(__t) = __t { __phase_pick_ns += __t.elapsed().as_nanos() as u64; }

            // 2. Selective restore with dual-SVM support.
            let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };

            // Dual-SVM flags:
            // is_traced_iter: true when we should swap to the traced SVM (only trace_interval > 1)
            // has_tracing: true when any coverage collection happens this iteration
            let is_traced_iter = __dual_traced_svm.is_some() && (iteration % trace_interval == 0);
            let has_tracing = trace_interval == 1 || is_traced_iter;

            if is_traced_iter {
                // Swap traced SVM into __real_svm position for this iteration
                if let Some(ref mut traced) = __dual_traced_svm {
                    std::mem::swap(&mut __real_svm, traced);
                }
                // Simple selective restore for traced SVM (no delta-to-delta optimization
                // since the traced SVM is used infrequently — prior state may be stale)
                delta_arc.restore_selective(&*initial_snapshot, &mut __real_svm, &traced_divergent);
                traced_divergent.clear();
                traced_divergent.extend(delta_arc.keys().copied());
            } else {
                // Optimized delta-to-delta restore for fast SVM (or always-traced when trace_interval==1)
                if let Some(ref prev) = prev_delta_arc {
                    delta_arc.restore_selective_from(&*initial_snapshot, &mut __real_svm, &divergent_keys, prev, &prev_exec_dirty);
                } else {
                    delta_arc.restore_selective(&*initial_snapshot, &mut __real_svm, &divergent_keys);
                }
                divergent_keys.clear();
                divergent_keys.extend(delta_arc.keys().copied());
            }
            if let Some(__t) = __t { __phase_restore_ns += __t.elapsed().as_nanos() as u64; }

            // Debug: verify restore fidelity by comparing state hash
            if crucible_test_context::is_debug_replay() {
                let __saved_hash = state_pool.get_debug_hash(state_idx);
                if __saved_hash != 0 {
                    let __restored_hash = initial_snapshot.hash_tracked_state(&__real_svm);
                    if __saved_hash != __restored_hash {
                        eprintln!("[RESTORE_MISMATCH] state_idx={} depth={} save_hash={:016x} restore_hash={:016x}",
                            state_idx, parent_depth, __saved_hash, __restored_hash);
                    }
                }
            }

            // 3. Generate action chain using adaptive scheduling.
            let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
            #action_chain_code
            if let Some(__t) = __t { __phase_action_gen_ns += __t.elapsed().as_nanos() as u64; }


            // 5. Execute the action chain using the existing invariant test function.
            //    Restore fixture from pool state (correct mutable fields for this state),
            //    then swap in the real SVM.
            let __t_clone = if __do_profile { Some(std::time::Instant::now()) } else { None };
            let mut #fixture_param_name = if let Some(ref arc) = __picked_fixture_state {
                arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed").0.clone()
            } else {
                template_fixture.clone()
            };
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
            #extra_swap_in_fixture

            // Set up coverage callback only when tracing is active this iteration
            if has_tracing {
                // Clear coverage map so hitcount buckets are per-iteration, not accumulated.
                // Without this, buckets saturate and no new coverage is ever detected.
                unsafe { std::ptr::write_bytes(__stateful_cov_ptr, 0, #mod_name::MAP_SIZE); }
                let callback = #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE);
                #fixture_param_name.ctx.set_invocation_callback(callback);
            }

            crucible_test_context::set_current_iteration(iteration);
            crucible_test_context::clear_iteration_state();

            // Snapshot edge count before execution for coverage-driven pool insertion
            // Only track on iterations where tracing is active
            let __edges_before = if has_tracing {
                #mod_name::TOTAL_EDGES_ATOMIC.load(std::sync::atomic::Ordering::Relaxed)
            } else { 0 };
            if let Some(__t) = __t_clone { __phase_clone_ns += __t.elapsed().as_nanos() as u64; }

            // Execute action chain (reuses all invariant/dispatch logic)
            let __t_exec = if __do_profile { Some(std::time::Instant::now()) } else { None };
            if __do_profile { crucible_test_context::reset_send_batch_timers(); }
            crucible_test_context::reset_iteration_dispatch_count();
            let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #fn_name(&mut #fixture_param_name, __action_chain);
            }));
            let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();
            if let Some(__t) = __t_exec {
                __phase_svm_exec_ns += __t.elapsed().as_nanos() as u64;
                let (__pre, __svm, __post) = crucible_test_context::get_send_batch_timers();
                __phase_tx_pre_ns += __pre;
                __phase_tx_svm_ns += __svm;
                __phase_tx_post_ns += __post;
                let (__bh, __sg, __ex) = crucible_test_context::get_send_tx_breakdown();
                __phase_tx_blockhash_ns += __bh;
                __phase_tx_sign_ns += __sg;
                __phase_tx_exec_ns += __ex;
            }

            // Truncate chain to actually-executed actions (strip unexecuted bytes)
            #truncation_code

            // Check if this action produced new coverage:
            // 1. New unique edge (TOTAL_EDGES_ATOMIC increased)
            // 2. New hitcount bucket on the AFL map (same edge hit at novel frequency)
            // Both signals drive state saving — (2) is critical for avoiding the plateau
            // where all unique edges are found but deeper state sequences remain unexplored.
            // Edge coverage (drives dedup bypass — real code coverage)
            let __t_cov = if __do_profile { Some(std::time::Instant::now()) } else { None };
            let __edge_novel_bits: u32 = if has_tracing {
                let mut bits: u32 = 0;
                // New unique edges count as novel bits
                let new_edges = #mod_name::TOTAL_EDGES_ATOMIC.load(std::sync::atomic::Ordering::Relaxed) - __edges_before;
                bits += new_edges as u32;
                // Scan coverage map for new hitcount buckets (O(MAP_SIZE) but fast — ~10µs for 64KB)
                unsafe {
                    let map = std::slice::from_raw_parts(__stateful_cov_ptr, #mod_name::MAP_SIZE);
                    let mut i = 0usize;
                    while i + 8 <= #mod_name::MAP_SIZE {
                        let chunk = *(map.as_ptr().add(i) as *const u64);
                        if chunk != 0 {
                            for j in 0..8 {
                                let pos = i + j;
                                let hitcount = map[pos];
                                if hitcount != 0 {
                                    let bucket = #mod_name::to_bucket(hitcount);
                                    if bucket > __virgin_map[pos] {
                                        __virgin_map[pos] = bucket;
                                        bits += 1;
                                    }
                                }
                            }
                        }
                        i += 8;
                    }
                    while i < #mod_name::MAP_SIZE {
                        let hitcount = map[i];
                        if hitcount != 0 {
                            let bucket = #mod_name::to_bucket(hitcount);
                            if bucket > __virgin_map[i] {
                                __virgin_map[i] = bucket;
                                bits += 1;
                            }
                        }
                        i += 1;
                    }
                }
                bits
            } else { 0u32 };
            if let Some(__t) = __t_cov { __phase_coverage_ns += __t.elapsed().as_nanos() as u64; }

            // Combined fingerprint + field novelty + patch collection in one pass.
            // This replaces the separate check_field_novelty call.
            let __t_fn = if __do_profile { Some(std::time::Instant::now()) } else { None };
            let (mut __combined_fingerprint, __changed_accounts, __field_novel_bits) = unsafe {
                crucible_test_context::snapshot::fingerprint_and_collect_changed(
                    &#fixture_param_name.ctx.svm,
                    &#fixture_param_name.ctx.dirty_tracker,
                    &*initial_snapshot,
                    __field_novelty_bitmap.as_mut_ptr(),
                    __field_novelty_bitmap.len(),
                )
            };
            if let Some(__t) = __t_fn { __phase_field_novelty_ns += __t.elapsed().as_nanos() as u64; }
            let __novel_bits = __edge_novel_bits + __field_novel_bits;
            let __new_coverage = __edge_novel_bits > 0;
            let __is_novel = __field_novel_bits > 0;

            // Count actual SVM executions (includes success-seeking retries)
            #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                let exec_count = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                #mod_name::maybe_write_coverage(exec_count);
            }

            // Check for violation BEFORE swapping SVM back
            let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
            let violation = crucible_test_context::take_violation();

            if let Some(ref msg) = violation {
                let __violation_action_idx = crucible_test_context::get_violation_action_index();
                let __history_len = crucible_test_context::get_action_history().len();
                eprintln!("[CRASH_DIAG] violation at chain action {}/{} (parent depth={}, total={}), history_len={}",
                    __violation_action_idx.map(|i| i + 1).unwrap_or(0), __chain_len,
                    parent_depth, parent_depth + __chain_len as u32, __history_len);
                // Reconstruct full action sequence for crash file (strip inherited ghosts)
                let mut crash_bytes = {
                    let raw = state_pool.reconstruct_action_sequence(state_idx);
                    let stored = if raw.len() >= 4 { u32::from_le_bytes(raw[0..4].try_into().unwrap()) } else { 0 };
                    if stored != parent_depth { state_pool.rebuild_action_bytes_clean(state_idx) } else { raw }
                };
                let __parent_count = if crash_bytes.len() >= 4 {
                    u32::from_le_bytes(crash_bytes[0..4].try_into().unwrap())
                } else { 0 };
                if crash_bytes.len() >= 4 {
                    let old_count = __parent_count;
                    crash_bytes[0..4].copy_from_slice(&(old_count + __chain_len as u32).to_le_bytes());
                    crash_bytes.extend_from_slice(&__single_action_buf);
                }
                // Debug: verify binary matches description chain
                let __desc_chain = state_pool.reconstruct_action_descriptions(state_idx);
                eprintln!("[CRASH_DEBUG] parent state_idx={}, parent depth={}, parent action_bytes count={}, desc chain len={}, chain_len={}, total binary count={}",
                    state_idx, parent_depth, __parent_count, __desc_chain.len(), __chain_len,
                    __parent_count + __chain_len as u32);

                // Dedup by action variant sequence (coarse: same action types = same crash class)
                let mut __variant_seq = state_pool.reconstruct_variant_sequence(state_idx);
                __variant_seq.push(__action_variant_idx as u16);
                let input_hash = libafl_bolts::hash_std(
                    &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                );
                if state_pool.is_novel_crash(input_hash) {
                    crashes_found += 1;
                    println!("[FUZZ_FINDING] reproduces:true summary:{}", msg);
                    eprintln!("\n[FUZZ_FINDING] at iteration {}: {}", iteration, msg);
                    // Print full action chain from root to violation.
                    // Include ALL actions from the current chain (chain_len may be >1 with splice).
                    let parent_descs = state_pool.reconstruct_action_descriptions(state_idx);
                    let history = crucible_test_context::get_action_history();
                    let current_descs: Vec<String> = __chain_descs.iter().enumerate().map(|(i, desc)| {
                        let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                        format!("{} -> {}", desc, status)
                    }).collect();
                    let total = parent_descs.len() + current_descs.len();
                    eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                    for (i, desc) in parent_descs.iter().enumerate() {
                        eprintln!("  {}. {}", i + 1, desc);
                    }
                    for (i, desc) in current_descs.iter().enumerate() {
                        let tag = if i == current_descs.len() - 1 { " [VIOLATION]" } else { "" };
                        eprintln!("  {}. {}{}", parent_descs.len() + i + 1, desc, tag);
                    }
                    eprintln!("===================================");

                    // Build full action records for metadata (parent chain + ALL current actions)
                    let mut __full_actions: Vec<crucible_test_context::ActionRecord> = parent_descs
                        .iter()
                        .map(|d| crucible_test_context::parse_action_desc(d))
                        .collect();
                    for desc in &current_descs {
                        __full_actions.push(crucible_test_context::parse_action_desc(desc));
                    }
                    crucible_test_context::write_crash_metadata_with_actions(
                        &crash_dir, input_hash, Some(seed), &crash_bytes, Some(__full_actions),
                    );

                    if stop_on_crash {
                        eprintln!("[STATEFUL] First crash found. Exiting (--stop-on-crash).");
                        std::process::exit(0);
                    }
                }
                // Record violation against this state — after enough violations it gets
                // removed from the active pool to prevent toxic states from wasting cycles.
                state_pool.record_violation(state_idx);
            }
            if let Some(__t) = __t { __phase_crash_ns += __t.elapsed().as_nanos() as u64; }

            // 6. Compute fingerprint and potentially add to pool (only if no violation and no panic)
            //
            // Field-novelty gate: only save states where per-field value bucketing
            // detected a never-before-seen (account, offset, bucket) combination,
            // or where new code-edge coverage was found.
            let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                let succeeded = crucible_test_context::get_first_action_success().unwrap_or(false);

                // Record success/failure in action stats for this state class
                action_stats.record(__state_class, __action_variant_idx, succeeded);

                if __is_novel || __new_coverage {
                    let __t_fp = if __do_profile { Some(std::time::Instant::now()) } else { None };
                    // Use fingerprint + patches from the combined pass above
                    let mut fingerprint = __combined_fingerprint;
                    // Clock-only changes (e.g., advance_slots): incorporate parent state
                    // so identical time advances from different parents don't collide.
                    if #fixture_param_name.ctx.dirty_tracker.dirty_accounts().is_empty() {
                        fingerprint = fingerprint ^ parent_fingerprint.wrapping_mul(0x517cc1b727220a95);
                    }
                    // Only bypass fingerprint dedup when real code-edge coverage is found.
                    if __edge_novel_bits > 0 {
                        fingerprint = fingerprint
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .wrapping_add(iteration);
                    }
                    if let Some(__t) = __t_fp { __phase_fingerprint_ns += __t.elapsed().as_nanos() as u64; }

                    // Only compute expensive delta snapshot if fingerprint is novel
                    // (not already in pool's seen set) or if we have new edge coverage.
                    if fingerprint != 0 && (state_pool.is_novel(fingerprint) || __new_coverage) {
                        let __t_save = if __do_profile { Some(std::time::Instant::now()) } else { None };
                        // Create delta from only accounts that actually changed from initial.
                        // Dirty-but-unchanged accounts (e.g., 1MB orderbooks that were writable
                        // but unmodified) are excluded, saving massive memory in the pool.
                        // Parent patches for non-re-dirtied accounts are inherited so the
                        // delta is a complete diff from initial (not just this execution).
                        let new_delta = CompactDelta::child_delta(
                            &delta_arc,
                            __changed_accounts,
                            #fixture_param_name.ctx.dirty_tracker.dirty_accounts(),
                            &#fixture_param_name.ctx.svm,
                        );

                        // Deep-clone parent action bytes to build accumulated sequence
                        let mut accumulated_bytes = (*parent_action_bytes).clone();
                        if accumulated_bytes.len() >= 4 {
                            // Validate parent count matches depth to strip inherited ghosts
                            let stored_count = u32::from_le_bytes(
                                accumulated_bytes[0..4].try_into().unwrap()
                            );
                            if stored_count != parent_depth {
                                accumulated_bytes = state_pool.rebuild_action_bytes_clean(state_idx);
                            }
                            let count = u32::from_le_bytes(
                                accumulated_bytes[0..4].try_into().unwrap()
                            );
                            accumulated_bytes[0..4].copy_from_slice(&(count + __chain_len as u32).to_le_bytes());
                            accumulated_bytes.extend_from_slice(&__single_action_buf);
                        }

                        // Extract field bytes for parent-action replay (skip 2-byte variant header)
                        // Use the LAST action in the chain for crossover source
                        let __fbc = <#action_ty as crucible_fuzzer::FuzzAction>::field_byte_count(__action_variant_idx);
                        let __last_action_start = __single_action_buf.len().saturating_sub(2 + __fbc);
                        let __field_bytes = if __last_action_start + 2 < __single_action_buf.len() {
                            __single_action_buf[__last_action_start + 2..].to_vec()
                        } else {
                            Vec::new()
                        };

                        // Use pre-computed descriptions (with params) instead of TLS history
                        // (which only has action names from push_action_record_lite).
                        let action_desc = {
                            let history = crucible_test_context::get_action_history();
                            __chain_descs.iter().enumerate().map(|(i, desc)| {
                                let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                                format!("{} -> {}", desc, status)
                            }).collect::<Vec<_>>().join("\n")
                        };

                        // Swap SVMs out before storing fixture (makes clone cheap)
                        #extra_restore_swap_back_fixture
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
                        let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                            Some(std::sync::Arc::new(__FixtureWrapper(#fixture_param_name.clone())));
                        // Swap SVM back in for remaining iteration logic (divergent_keys)
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
                        #extra_swap_in_fixture

                        let __coverage_positions: Option<Vec<u16>> = if __novel_bits > 0 && has_tracing {
                            Some(crucible_test_context::snapshot::extract_coverage_positions(&__stateful_coverage_map))
                        } else { None };
                        if state_pool.try_add(
                            fingerprint,
                            new_delta,
                            parent_depth + __chain_len as u32,
                            Some(state_idx),
                            accumulated_bytes,
                            action_desc,
                            Some(__action_variant_idx as u16),
                            __field_bytes,
                            __fixture_for_storage,
                            __novel_bits,
                            __edge_novel_bits,
                            succeeded,
                            __coverage_positions,
                        ) {
                            novel_states += 1;
                            // Debug: store state hash at save time for restore verification
                            if crucible_test_context::is_debug_replay() {
                                let __save_hash = initial_snapshot.hash_tracked_state(&#fixture_param_name.ctx.svm);
                                state_pool.set_last_debug_hash(__save_hash);
                            }
                            // Write to corpus incrementally if --corpus-out is set
                            if let Some(ref __cop) = corpus_out_dir {
                                state_pool.write_corpus_entry(state_pool.len() - 1, __cop);
                            }
                        }
                        if let Some(__t) = __t_save { __phase_save_ns += __t.elapsed().as_nanos() as u64; }
                    }
                }
                succeeded
            } else {
                // Record failure in action stats even for violations/panics
                action_stats.record(__state_class, __action_variant_idx, false);
                false
            };

            // Record barren pick for exponential weight decay.
            if !(__is_novel || __new_coverage) && violation.is_none() && __panic_result.is_ok() {
                state_pool.record_barren_pick(state_idx);
            }

            // 7. Update divergent_keys, prev_delta_arc, and prev_exec_dirty for next iteration
            // IMPORTANT: Always track dirty accounts regardless of action success/failure.
            // Failed actions can still create/delete/modify accounts, and if we don't track
            // those in divergent_keys, restore_selective_from will skip restoring them,
            // causing state leakage across iterations.
            let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
            if is_traced_iter {
                // Traced SVM: always update divergent tracking
                traced_divergent.extend(#fixture_param_name.ctx.dirty_tracker.dirty_accounts().iter().copied());
            } else {
                // Fast SVM (or always-traced): update delta optimization state
                prev_exec_dirty.clear();
                prev_exec_dirty.extend(#fixture_param_name.ctx.dirty_tracker.dirty_accounts().iter().copied());
                divergent_keys.extend(prev_exec_dirty.iter().copied());
                if __action_succeeded {
                    prev_delta_arc = Some(delta_arc);
                } else {
                    // Force simple restore_selective next iteration — the delta from a failed
                    // action shouldn't be used as an optimization base.
                    prev_delta_arc = None;
                }
            }

            // 8. Swap SVMs back out of fixture
            #extra_restore_swap_back_fixture
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
            // If traced iteration, swap traced SVM back to its dedicated slot
            if is_traced_iter {
                if let Some(ref mut traced) = __dual_traced_svm {
                    std::mem::swap(&mut __real_svm, traced);
                }
            }
            // fixture is dropped here
            if let Some(__t) = __t { __phase_cleanup_ns += __t.elapsed().as_nanos() as u64; }

            // On panic: resume unwinding
            if let Err(__panic_payload) = __panic_result {
                std::panic::resume_unwind(__panic_payload);
            }

            // 9. Rate-limited monitor output
            if let Some(__t) = __iter_start {
                __phase_total_ns += __t.elapsed().as_nanos() as u64;
                __profiled_iters += 1;
            }

            let now = std::time::Instant::now();
            if now.duration_since(last_print_time).as_millis() >= 2000 {
                let elapsed_secs = now.duration_since(last_print_time).as_secs_f64();
                let total_execs_now = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                let execs_since = total_execs_now - last_print_iter;
                let iter_sec = execs_since as f64 / elapsed_secs;

                let state = #mod_name::COVERAGE_STATE.lock().unwrap();
                let edges = state.total_edges;
                let branches = state.total_branches;
                drop(state);
                let total_edges: usize = #mod_name::PROGRAM_TOTALS.get()
                    .map(|t| t.values().sum()).unwrap_or(0);
                let total_branches = total_edges / 2;

                let edge_pct = if total_edges > 0 {
                    (edges as f64 / total_edges as f64) * 100.0
                } else { 0.0 };

                let pool_pct = if pool_capacity > 0 {
                    (state_pool.len() as f64 / pool_capacity as f64) * 100.0
                } else { 0.0 };

                let total_actions = crucible_test_context::TOTAL_ACTIONS_DISPATCHED.load(std::sync::atomic::Ordering::Relaxed);
                let total_ok = crucible_test_context::TOTAL_ACTIONS_SUCCEEDED.load(std::sync::atomic::Ordering::Relaxed);
                let ok_pct = if total_actions > 0 { (total_ok as f64 / total_actions as f64) * 100.0 } else { 0.0 };

                let discovered = crucible_test_context::succeeded_variant_count();
                let total_variants = crucible_test_context::TOTAL_ACTION_VARIANTS.load(std::sync::atomic::Ordering::Relaxed);

                let elapsed_total = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                    .saturating_sub(start_time);
                let mins = elapsed_total / 60;
                let secs = elapsed_total % 60;
                let __memory_kib = {
                    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
                    if cfg!(target_os = "macos") { (usage.ru_maxrss / 1024) as u64 } else { usage.ru_maxrss as u64 }
                };
                let __show_stats = std::env::var("FUZZ_STATS").is_ok();
                let __mem_suffix = if __show_stats { format!(", memory_kib: {}", __memory_kib) } else { String::new() };
                eprintln!(
                    "[FUZZ_PULSE] [{:02}:{:02}] iter: {}, iter/sec: {:.0}, pool: {}/{}k ({:.1}%), \
                     crashes: {}, ok: {}/{} ({:.1}%), discovered: {}/{} actions, edges: {}/{} ({:.1}%), branches: {}/{}{}",
                    mins, secs,
                    iteration, iter_sec,
                    state_pool.len(), pool_capacity / 1024, pool_pct,
                    crashes_found,
                    total_ok, total_actions, ok_pct,
                    discovered, total_variants,
                    edges, total_edges, edge_pct,
                    branches, total_branches,
                    __mem_suffix,
                );

                if __profiled_iters > 0 && __show_stats {
                    let total = __phase_total_ns;
                    let n = __profiled_iters;
                    let pct = |ns: u64| -> f64 { if total > 0 { (ns as f64 / total as f64) * 100.0 } else { 0.0 } };
                    let avg = |ns: u64| -> u64 { ns / n / 1000 }; // avg µs per iter
                    let other_ns = total.saturating_sub(
                        __phase_pick_ns + __phase_restore_ns + __phase_action_gen_ns
                        + __phase_clone_ns + __phase_svm_exec_ns + __phase_coverage_ns + __phase_field_novelty_ns
                        + __phase_fingerprint_ns + __phase_save_ns
                        + __phase_crash_ns + __phase_cleanup_ns
                    );
                    let avg_us = total / n / 1000;
                    eprintln!(
                        "[PROFILE] pick: {:.1}% ({}µs) | restore: {:.1}% ({}µs) | gen: {:.1}% ({}µs) | \
                         clone: {:.1}% ({}µs) | exec: {:.1}% ({}µs) | cov: {:.1}% ({}µs) | field: {:.1}% ({}µs) | \
                         fp: {:.1}% ({}µs) | save: {:.1}% ({}µs) | \
                         crash: {:.1}% ({}µs) | cleanup: {:.1}% ({}µs) | other: {:.1}% ({}µs) — avg: {}µs/iter",
                        pct(__phase_pick_ns), avg(__phase_pick_ns),
                        pct(__phase_restore_ns), avg(__phase_restore_ns),
                        pct(__phase_action_gen_ns), avg(__phase_action_gen_ns),
                        pct(__phase_clone_ns), avg(__phase_clone_ns),
                        pct(__phase_svm_exec_ns), avg(__phase_svm_exec_ns),
                        pct(__phase_coverage_ns), avg(__phase_coverage_ns),
                        pct(__phase_field_novelty_ns), avg(__phase_field_novelty_ns),
                        pct(__phase_fingerprint_ns), avg(__phase_fingerprint_ns),
                        pct(__phase_save_ns), avg(__phase_save_ns),
                        pct(__phase_crash_ns), avg(__phase_crash_ns),
                        pct(__phase_cleanup_ns), avg(__phase_cleanup_ns),
                        pct(other_ns), avg(other_ns),
                        avg_us,
                    );
                    // pick breakdown: flush (registry+phase), batch (weight computation), crossover (16x pick_weighted)
                    if __phase_pick_ns > 0 {
                        let ppct = |ns: u64| -> f64 { (ns as f64 / __phase_pick_ns as f64) * 100.0 };
                        let pick_other = __phase_pick_ns.saturating_sub(__phase_pick_flush_ns + __phase_pick_batch_ns + __phase_pick_crossover_ns + __phase_pick_splice_ns);
                        eprintln!(
                            "[PICK]    flush: {:.1}% ({}µs) | batch: {:.1}% ({}µs) | crossover: {:.1}% ({}µs) | splice: {:.1}% ({}µs) | other: {:.1}% ({}µs)",
                            ppct(__phase_pick_flush_ns), avg(__phase_pick_flush_ns),
                            ppct(__phase_pick_batch_ns), avg(__phase_pick_batch_ns),
                            ppct(__phase_pick_crossover_ns), avg(__phase_pick_crossover_ns),
                            ppct(__phase_pick_splice_ns), avg(__phase_pick_splice_ns),
                            ppct(pick_other), avg(pick_other),
                        );
                    }
                    __phase_pick_flush_ns = 0;
                    __phase_pick_batch_ns = 0;
                    __phase_pick_crossover_ns = 0;
                    __phase_pick_splice_ns = 0;
                    // exec breakdown: tx_pre (dirty), tx_svm (litesvm), tx_post (outcome), dispatch overhead
                    let tx_total = __phase_tx_pre_ns + __phase_tx_svm_ns + __phase_tx_post_ns;
                    let dispatch_ns = __phase_svm_exec_ns.saturating_sub(tx_total);
                    let epct = |ns: u64| -> f64 { if __phase_svm_exec_ns > 0 { (ns as f64 / __phase_svm_exec_ns as f64) * 100.0 } else { 0.0 } };
                    eprintln!(
                        "[EXEC]    tx_pre: {:.1}% ({}µs) | tx_svm: {:.1}% ({}µs) [blockhash: {}µs, sign: {}µs, exec: {}µs] | tx_post: {:.1}% ({}µs) | dispatch: {:.1}% ({}µs)",
                        epct(__phase_tx_pre_ns), avg(__phase_tx_pre_ns),
                        epct(__phase_tx_svm_ns), avg(__phase_tx_svm_ns),
                        avg(__phase_tx_blockhash_ns), avg(__phase_tx_sign_ns), avg(__phase_tx_exec_ns),
                        epct(__phase_tx_post_ns), avg(__phase_tx_post_ns),
                        epct(dispatch_ns), avg(dispatch_ns),
                    );
                    __phase_pick_ns = 0;
                    __phase_restore_ns = 0;
                    __phase_action_gen_ns = 0;
                    __phase_clone_ns = 0;
                    __phase_svm_exec_ns = 0;
                    __phase_tx_pre_ns = 0;
                    __phase_tx_svm_ns = 0;
                    __phase_tx_post_ns = 0;
                    __phase_tx_blockhash_ns = 0;
                    __phase_tx_sign_ns = 0;
                    __phase_tx_exec_ns = 0;
                    __phase_coverage_ns = 0;
                    __phase_field_novelty_ns = 0;
                    __phase_fingerprint_ns = 0;
                    __phase_save_ns = 0;
                    __phase_crash_ns = 0;
                    __phase_cleanup_ns = 0;
                    __phase_total_ns = 0;
                    __profiled_iters = 0;
                }

                if std::env::var("FUZZ_STATS").is_ok() {
                    let __mem_stats = state_pool.memory_stats();
                    let __rss_mb = {
                        #[cfg(target_os = "macos")]
                        {
                            let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
                            let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
                                / std::mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
                            let kr = unsafe {
                                libc::task_info(
                                    libc::mach_task_self(),
                                    libc::MACH_TASK_BASIC_INFO,
                                    &mut info as *mut _ as libc::task_info_t,
                                    &mut count,
                                )
                            };
                            if kr == libc::KERN_SUCCESS {
                                info.resident_size as f64 / 1_048_576.0
                            } else {
                                __memory_kib as f64 / 1024.0
                            }
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
                                let rss_pages = statm.split_whitespace().nth(1)
                                    .and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                                (rss_pages * 4096) as f64 / 1_048_576.0
                            } else {
                                __memory_kib as f64 / 1024.0
                            }
                        }
                    };
                    eprintln!(
                        "[MEMORY]  rss: {:.0}MB (peak: {:.0}MB) | {}",
                        __rss_mb,
                        __memory_kib as f64 / 1024.0,
                        __mem_stats.format_breakdown(),
                    );
                } // FUZZ_STATS

                last_print_time = now;
                last_print_iter = total_execs_now;
            }
        }

        // Loop exited (all active states exhausted or signal)
        if let Some(ref __corpus_out_path) = corpus_out_dir {
            match state_pool.export_corpus(__corpus_out_path, corpus_in_dir.as_deref()) {
                Ok(n) => eprintln!("[STATEFUL] Saved {} corpus entries to {}", n, __corpus_out_path),
                Err(e) => eprintln!("[STATEFUL] Failed to save corpus: {}", e),
            }
        }
        eprintln!("\n[STATEFUL] Final stats: {} iterations, {} novel states, {} crashes, pool: {} (active: {})",
            iteration, novel_states, crashes_found, state_pool.len(), state_pool.active_count());
        std::process::exit(0);
    }
}

/// Generate the multi-threaded stateful fuzzing body.
///
/// Setup happens ONCE on the main thread. The fixture + SVM are cloned for
/// each worker so all threads share the same keypairs/pubkeys. Workers share
/// a single `Arc<RwLock<StatePool>>`.
///
/// The fixture contains `Rc<Keypair>` which is not `Send`, and LiteSVM contains
/// `Rc<RefCell<LogCollector>>` deep in its type parameters (also `!Send`).
/// Since each worker gets its own independent clone (no cross-thread sharing),
/// we bundle both in `__SendableWorkerState` with `unsafe impl Send`.
///
/// Workers reuse their fixture directly (no per-iteration clone) to avoid
/// `Rc::clone`/`Rc::drop` races. `ManuallyDrop` prevents refcount decrements
/// on worker threads at exit.
fn stateful_multicore_body(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    _fixture_param_name: &syn::Ident,
    _feature_name: &str,
    action_ty: &proc_macro2::TokenStream,
    contexts: &[syn::Ident],
) -> proc_macro2::TokenStream {
    // Extra context helpers (for contexts[1..]) — multicore stateful
    // For multicore, the iteration fixture is __iter_fixture
    let iter_ident = quote::format_ident!("__iter_fixture");
    let extra_swap_in_iter = codegen::stateful_extra_swap_in(&iter_ident, contexts);
    let extra_restore_swap_back_iter =
        codegen::stateful_extra_restore_and_swap_back(&iter_ident, contexts);
    // Seed phase uses __seed_fixture
    let seed_ident_mc = quote::format_ident!("__seed_fixture");
    let extra_swap_in_seed_mc = codegen::stateful_extra_swap_in(&seed_ident_mc, contexts);
    let extra_swap_back_seed_mc = codegen::stateful_extra_swap_back(&seed_ident_mc, contexts);

    let mc_seed_code = gen_corpus_seeding(
        mod_name,
        fn_name,
        action_ty,
        &quote! { pool },
        &extra_swap_in_seed_mc,
        &extra_swap_back_seed_mc,
        &quote! {
            #mod_name::FuzzCallback::with_shared_memory(
                __stateful_cov_ptr, #mod_name::MAP_SIZE,
                shared_edge_addr as *mut u8, shared_branch_addr as *mut u8,
            )
        },
        &quote! { let mut pool = state_pool.write().unwrap(); }, // pre-loop: acquire write lock
        &quote! { // post-exec: flush to shared bitmap
            #mod_name::flush_local_bitmap_buffers(
                shared_edge_addr as *mut u8, shared_branch_addr as *mut u8,
            );
        },
        &quote! {}, // no debug diagnostics in multicore (yet)
        &quote! {
            #mod_name::FuzzCallback::count_shared_bits(
                shared_edge_addr as *const u8,
                #mod_name::SHARED_EDGE_BITMAP_SIZE / 2,
            )
        },
        &quote! { // post-seeding: drop lock, mark boundary
            {
                let mut pool = state_pool.write().unwrap();
                pool.mark_seed_boundary();
            }
        },
    );

    // Worker threads use __cached_pool_len (read-lock-free snapshot), W0 uses cached_pool_len
    let mc_worker_action_chain = gen_action_chain(
        action_ty,
        &quote! { __cached_pool_len },
        &quote! { pending_selects },
    );
    let mc_w0_action_chain = gen_action_chain(
        action_ty,
        &quote! { cached_pool_len },
        &quote! { pending_selects },
    );
    let mc_truncation_code = gen_post_exec_truncation();

    quote! {
        // === MULTI-THREADED STATEFUL ===
        use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};

        eprintln!("[STATEFUL] Multi-threaded mode with {} workers", num_cores);

        // Shared bitmaps for lock-free coverage tracking across worker threads.
        // Workers use FuzzCallback::with_shared_memory() which writes to these
        // via atomic fetch_or, avoiding the COVERAGE_STATE Mutex entirely.
        // Kept alive via _shared_edge_bitmap_owner / _shared_branch_bitmap_owner.
        //
        // Pointers stored as usize (Send) to avoid *mut u8 poisoning closures.
        // Cast back to *mut u8 inside each worker scope.
        let mut _shared_edge_bitmap_owner = vec![0u8; #mod_name::SHARED_EDGE_BITMAP_SIZE];
        let mut _shared_branch_bitmap_owner = vec![0u8; #mod_name::SHARED_BRANCH_BITMAP_SIZE];
        let mut _shared_field_novelty_owner = vec![0u8; crucible_test_context::snapshot::FIELD_NOVELTY_BITMAP_SIZE];
        let shared_edge_addr: usize = _shared_edge_bitmap_owner.as_mut_ptr() as usize;
        let shared_branch_addr: usize = _shared_branch_bitmap_owner.as_mut_ptr() as usize;
        let shared_field_novelty_addr: usize = _shared_field_novelty_owner.as_mut_ptr() as usize;

        // Unsafe Send wrapper for ALL non-Send data: fixture (Rc<Keypair>) and
        // LiteSVM (Rc<RefCell<LogCollector>> in type params). Each worker gets
        // its own independent clone — all cloning happens sequentially on the
        // main thread before any spawn().
        // Fields: (fixture, fast_svm, Option<traced_svm>)
        struct __SendableWorkerState(#fixture_name, crucible_test_context::litesvm::LiteSVM, Option<crucible_test_context::litesvm::LiteSVM>);
        unsafe impl Send for __SendableWorkerState {}

        let state_pool = Arc::new(RwLock::new(StatePool::new(pool_capacity, max_depth)));

        // Add initial state to shared pool (empty delta = identical to initial_snapshot)
        {
            let initial_clock = initial_snapshot.clock().clone();
            let mut pool = state_pool.write().unwrap();
            pool.try_add(0, CompactDelta::empty(initial_clock), 0, None, 0u32.to_le_bytes().to_vec(), String::new(), None, Vec::new(), __initial_fixture_state.clone(), 0, 0, true, None);
        }

        // Shared atomics
        let shared_iters = Arc::new(AtomicU64::new(0));
        let shared_crashes = Arc::new(AtomicU64::new(0));
        let shared_novel = Arc::new(AtomicU64::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));
        // Guard: discovered variant bitmap supports max 256 variants
        {
            let __variant_count = crucible_test_context::TOTAL_ACTION_VARIANTS
                .load(std::sync::atomic::Ordering::Relaxed);
            assert!(__variant_count <= 256,
                "Action enum has {} variants but discovered bitmap supports max 256. \
                 File a bug if you need >256 action variants.", __variant_count);
        }
        // Shared discovered-variants bitmap: each byte is 0/1 for up to 256 variants.
        // Workers atomically set bytes to 1 when they discover a new variant;
        // monitor counts non-zero bytes to display "discovered: X/Y actions".
        let shared_discovered: Arc<Vec<std::sync::atomic::AtomicU8>> = Arc::new(
            (0..256).map(|_| std::sync::atomic::AtomicU8::new(0)).collect()
        );
        // Lock-free bitmap for fingerprint novelty pre-checking.
        // Workers check this BEFORE doing expensive save-phase work (take_delta,
        // fixture clone). Eliminates ~99.8% of wasted mutex acquisitions.
        let fingerprint_bitmap = Arc::new(crucible_test_context::snapshot::FingerprintBitmap::new());
        // Serializes fixture cloning (Rc::clone is not thread-safe) WITHOUT
        // blocking pool operations. Decoupled from RwLock so workers can
        // flush novel states and pick batches while one worker clones fixtures.
        let fixture_clone_mutex = Arc::new(std::sync::Mutex::new(()));

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = #mod_name::FUZZER_START_TIME.set(start_time);

        let crash_dir = Arc::new(crash_dir);

        // Install Ctrl+C / SIGTERM handler for clean exit
        {
            let stop = stop_flag.clone();
            let _ = ctrlc::set_handler(move || {
                eprintln!("\n[STATEFUL] Signal received, shutting down...");
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            });
        }

        eprintln!("[STATEFUL] Pool capacity: {}k, max depth: {}, seed: {}", pool_capacity / 1024, max_depth, seed);

        #mc_seed_code

        eprintln!("[STATEFUL] Starting multi-threaded stateful fuzzing...\n");

        // Clone fixture + SVM on the main thread for each worker.
        // All cloning is sequential here — no Rc races.
        let mut worker_handles = Vec::new();
        for worker_id in 1..num_cores {
            // Clone BEFORE spawning (sequential, safe Rc::clone)
            // Create traced SVM for this worker if dual-SVM mode is active
            let worker_traced = if trace_interval > 1 {
                let mut svm = __create_svm(true);
                initial_snapshot.restore_full(&mut svm);
                Some(svm)
            } else {
                None
            };
            let worker_state = __SendableWorkerState(
                template_fixture.clone(),
                __real_svm.clone(),
                worker_traced,
            );
            let worker_initial = initial_snapshot.clone();

            let pool = state_pool.clone();
            let iters = shared_iters.clone();
            let crashes = shared_crashes.clone();
            let novel = shared_novel.clone();
            let stop = stop_flag.clone();
            let crash_dir = crash_dir.clone();
            let corpus_out_for_worker = corpus_out_dir.clone();
            let fixture_clone_lock = fixture_clone_mutex.clone();
            let fp_bitmap = fingerprint_bitmap.clone();
            let discovered_bitmap = shared_discovered.clone();
            let worker_seed = seed + worker_id as u64;
            let w_edge_addr = shared_edge_addr;
            let w_branch_addr = shared_branch_addr;
            let w_field_novelty_addr = shared_field_novelty_addr;

            let handle = std::thread::Builder::new()
                .name(format!("stateful-worker-{}", worker_id))
                .spawn(move || {
                    let shared_edge_ptr = w_edge_addr as *mut u8;
                    let shared_branch_ptr = w_branch_addr as *mut u8;
                    let shared_field_novelty_ptr = w_field_novelty_addr as *mut u8;
                    // Force capture of the WHOLE __SendableWorkerState value.
                    // In Rust 2021+, closures use precise field captures: `worker_state.0`
                    // would capture just the EternalFixture field (which is !Send), bypassing
                    // the `unsafe impl Send for __SendableWorkerState` wrapper. By rebinding
                    // the whole struct first, we ensure the closure captures the Send wrapper.
                    let worker_state = worker_state;
                    // ManuallyDrop prevents Rc refcount decrements on the worker thread.
                    // Fixture Rcs are shared with pool entries (via Arc<FixtureWrapper>),
                    // so dropping here would race. Process exit reclaims all memory.
                    let mut worker_fixture = std::mem::ManuallyDrop::new(worker_state.0);
                    let mut worker_svm = std::mem::ManuallyDrop::new(worker_state.1);
                    let mut worker_traced_svm = worker_state.2.map(|svm| std::mem::ManuallyDrop::new(svm));

                    // Per-worker coverage map + virgin map for hitcount novelty detection
                    let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
                    let worker_cov_ptr = worker_cov_map.as_mut_ptr();

                    crucible_test_context::set_stateful_chain_mode(true);

                    let mut rng = StdRand::with_seed(worker_seed);
                    let mut local_iter: u64 = 0;
                    let mut __cached_pool_len: usize = 1;
                    let mut divergent_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                        crucible_test_context::FastHashSet::default();
                    let mut prev_delta_arc: Option<std::sync::Arc<CompactDelta>> = None;
                    let mut prev_exec_dirty: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                        crucible_test_context::FastHashSet::default();
                    // Dual-SVM: divergent tracking for the traced SVM
                    let mut traced_divergent: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                        crucible_test_context::FastHashSet::default();

                    // Per-worker action stats (no synchronization needed)
                    let mut action_stats = crucible_test_context::snapshot::ActionStatsMap::new(
                        <#action_ty as crucible_fuzzer::FuzzAction>::variant_count(),
                    );

                    // Batched pool access: pick BATCH_SIZE states under one read lock
                    // (pick_count/total_picks are atomic — no write lock needed for picking),
                    // accumulate results locally, flush with one write lock per batch.
                    const BATCH_SIZE: usize = 512;
                    // (delta, depth, state_idx, action_bytes, parent_variant, parent_field_bytes, fingerprint, fixture_state)
                    type PickTuple = (std::sync::Arc<CompactDelta>, u32, usize, std::sync::Arc<Vec<u8>>, Option<u16>, std::sync::Arc<Vec<u8>>, u64, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);
                    // Reuse rng_vals allocation across batch refills (C4)
                    let mut rng_vals: Vec<u64> = Vec::with_capacity(BATCH_SIZE);
                    let mut local_batch: Vec<PickTuple> = Vec::with_capacity(BATCH_SIZE);
                    // Success crossover: (variant_idx, field_bytes) from random pool states, refreshed each batch
                    let mut __crossover_buf: Vec<(usize, std::sync::Arc<Vec<u8>>)> = Vec::with_capacity(16);
                    // Pre-cloned fixtures for the current batch
                    let mut fixture_batch: Vec<#fixture_name> = Vec::with_capacity(BATCH_SIZE);
                    // Deferred fixture drops: Rc::drop must not race with Rc::clone across threads.
                    // Instead of dropping __iter_fixture immediately (outside mutex), we defer it
                    // and clear the list inside the mutex alongside the next batch of clones.
                    let mut pending_fixture_drops: Vec<#fixture_name> = Vec::with_capacity(BATCH_SIZE + 1);
                    // Accumulated results to flush after each batch
                    // (fingerprint, delta, depth, parent_idx, action_bytes, desc, variant, field_bytes, fixture_state, novelty_bits, edge_novelty, succeeded, coverage_positions)
                    let mut pending_novel: Vec<(u64, CompactDelta, u32, Option<usize>, Vec<u8>, String, Option<u16>, Vec<u8>, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>, u32, u32, bool, Option<Vec<u16>>)> = Vec::new();
                    // Crash info: (action_variant, msg, current_action_desc, parent_state_idx, crash_bytes)
                    let mut pending_crashes: Vec<(u16, String, Vec<String>, usize, Vec<u8>)> = Vec::new();
                    // Track pending violations: state indices that need record_violation() in the flush
                    let mut pending_violations: Vec<usize> = Vec::new();
                    let mut pending_barren: Vec<usize> = Vec::new();
                    // Pending state_class selects to flush into registry
                    let mut pending_selects: Vec<u16> = Vec::with_capacity(BATCH_SIZE);
                    // Thread-local seen variant hashes to skip duplicate crash accumulation
                    let mut seen_variant_hashes: crucible_test_context::FastHashSet<u64> = crucible_test_context::FastHashSet::default();
                    let mut __single_action_buf: Vec<u8> = Vec::with_capacity(64);
                    // Cached weight distribution — rebuilt at batch boundaries, reused for splice
                    let mut __weight_cumulative: Vec<f64> = Vec::new();
                    let mut __weight_total: f64 = 0.0;

                    loop {
                        if stop.load(Ordering::Relaxed) || SIGNAL_STOP.load(Ordering::Relaxed) { break; }

                        // Refill batch when empty
                        if local_batch.is_empty() {
                            // Flush pending writes from the previous batch (one write lock)
                            // Fix 3: Collect crash outputs inside lock, write to disk outside
                            let mut __crash_outputs: Vec<(String, Vec<String>, Vec<String>, u64, Vec<u8>)> = Vec::new();
                            if !pending_novel.is_empty() || !pending_crashes.is_empty() || !pending_violations.is_empty() || !pending_selects.is_empty() || !pending_barren.is_empty() {
                                if let Ok(mut pool) = pool.try_write() {
                                    for sc in pending_selects.drain(..) {
                                        pool.registry_mut().record_select(sc);
                                    }
                                    pool.set_current_iteration(iters.load(Ordering::Relaxed));
                                    pool.maybe_advance_phase();
                                    for (fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel, edge_novel, succ, cov_pos) in pending_novel.drain(..) {
                                        if pool.try_add(fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel, edge_novel, succ, cov_pos) {
                                            novel.fetch_add(1, Ordering::Relaxed);
                                            fp_bitmap.mark(fp);
                                            if let Some(ref __cop) = corpus_out_for_worker {
                                                pool.write_corpus_entry(pool.len() - 1, __cop);
                                            }
                                        }
                                    }
                                    // Record violations against parent states
                                    for vi_idx in pending_violations.drain(..) {
                                        pool.record_violation(vi_idx);
                                    }
                                    for bi_idx in pending_barren.drain(..) {
                                        pool.record_barren_pick(bi_idx);
                                    }
                                    for (cur_variant, msg, current_descs, parent_idx, crash_bytes) in pending_crashes.drain(..) {
                                        // Compute variant-only hash inside the lock
                                        let mut __variant_seq = pool.reconstruct_variant_sequence(parent_idx);
                                        __variant_seq.push(cur_variant);
                                        let vh = libafl_bolts::hash_std(
                                            &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                                        );
                                        if pool.is_novel_crash(vh) {
                                            crashes.fetch_add(1, Ordering::Relaxed);
                                            let parent_descs = pool.reconstruct_action_descriptions(parent_idx);
                                            __crash_outputs.push((msg, parent_descs, current_descs, vh, crash_bytes));
                                            if stop_on_crash {
                                                eprintln!("[STATEFUL W{}] First crash found, signaling stop (--stop-on-crash).", worker_id);
                                                stop.store(true, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                } else {
                                    // Couldn't get write lock — keep pending_novel for retry next batch.
                                    // Cap to prevent unbounded growth if write lock is always contended.
                                    if pending_novel.len() > 2048 {
                                        let dropped = pending_novel.len() - 1024;
                                        pending_novel.drain(..dropped);
                                        eprintln!("[WORKER W{}] Warning: dropped {} pending novel states (write lock contention)", worker_id, dropped);
                                    }
                                }
                            }
                            // Crash disk I/O outside write lock (Fix 3)
                            for (msg, parent_descs, current_descs, vh, crash_bytes) in __crash_outputs {
                                let total = parent_descs.len() + current_descs.len();
                                println!("[FUZZ_FINDING] reproduces:true summary:{}", msg);
                                eprintln!("\n[FUZZ_FINDING] {}", msg);
                                eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                                for (i, desc) in parent_descs.iter().enumerate() {
                                    eprintln!("  {}. {}", i + 1, desc);
                                }
                                for (i, desc) in current_descs.iter().enumerate() {
                                    let tag = if i == current_descs.len() - 1 { " [VIOLATION]" } else { "" };
                                    eprintln!("  {}. {}{}", parent_descs.len() + i + 1, desc, tag);
                                }
                                eprintln!("===================================");
                                let mut __full_actions: Vec<crucible_test_context::ActionRecord> = parent_descs
                                    .iter()
                                    .map(|d| crucible_test_context::parse_action_desc(d))
                                    .collect();
                                for desc in &current_descs {
                                    __full_actions.push(crucible_test_context::parse_action_desc(desc));
                                }
                                crucible_test_context::write_crash_metadata_with_actions(
                                    &crash_dir, vh, Some(worker_seed), &crash_bytes, Some(__full_actions),
                                );
                            }

                            // Flush discovered variants to shared bitmap
                            {
                                let __total_variants = crucible_test_context::TOTAL_ACTION_VARIANTS
                                    .load(std::sync::atomic::Ordering::Relaxed);
                                for __vi in 0..__total_variants.min(256) {
                                    if crucible_test_context::has_variant_succeeded(__vi) {
                                        discovered_bitmap[__vi].store(1, Ordering::Relaxed);
                                    }
                                }
                            }

                            // Pick a weighted batch of states (read lock — pick_count is atomic)
                            {
                                let p = pool.read().unwrap();
                                __cached_pool_len = p.len();
                                rng_vals.clear();
                                for _ in 0..BATCH_SIZE {
                                    rng_vals.push(rng.next());
                                }
                                let (__wc, __wt) = p.build_weight_distribution();
                                p.pick_weighted_batch_from(&__wc, __wt, &rng_vals, &mut local_batch);
                                // Pick crossover candidates using pre-built distribution (O(log n))
                                __crossover_buf.clear();
                                for _ in 0..16usize {
                                    if let Some(idx) = p.sample_from_distribution(&__wc, __wt, rng.next()) {
                                        if let Some(entry) = p.get(idx) {
                                            if let Some(vi) = entry.action_variant {
                                                __crossover_buf.push((vi as usize, entry.action_field_bytes.clone()));
                                            }
                                        }
                                    }
                                }
                                // Cache weight distribution for splice donor selection
                                __weight_cumulative = __wc;
                                __weight_total = __wt;
                                // Read lock released here — pool is free for other workers
                            }

                            if local_batch.is_empty() {
                                break; // Pool exhausted
                            }

                            // Batch fixture clones under mutex. CRITICAL: ALL Rc operations
                            // (clone + drop) must happen under this mutex because fixtures
                            // contain Rc<Keypair> sharing refcounts across threads.
                            // Using lock() (not try_lock) to guarantee serialization.
                            {
                                let _guard = fixture_clone_lock.lock().unwrap();
                                // 1. Drop old batch + deferred fixtures under mutex (safe Rc ops)
                                fixture_batch.clear();
                                pending_fixture_drops.clear();
                                // 2. Clone new batch (Rc increments — safe under mutex)
                                for (_, _, _, _, _, _, _, fixture_arc) in local_batch.iter() {
                                    if let Some(ref arc) = fixture_arc {
                                        let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                                        fixture_batch.push(wrapper.0.clone());
                                    } else {
                                        fixture_batch.push((*worker_fixture).clone());
                                    }
                                }
                            }
                        }

                        local_iter += 1;

                        // Pop one state + pre-cloned fixture from local batch (no lock needed)
                        let (mut delta_arc, mut parent_depth, mut state_idx, mut parent_action_bytes, parent_variant, parent_field_bytes, mut parent_fingerprint, mut fixture_arc) =
                            local_batch.pop().unwrap();
                        let mut __iter_fixture = fixture_batch.pop().unwrap();

                        // Subsequence splice (5%):
                        let __splice_roll = rng.next() % 100;
                        let mut __splice_chain: Option<Vec<#action_ty>> = None;
                        if __splice_roll < 5 && __cached_pool_len > 10 {
                            // 5%: Donor splice — extract subsequence from an existing chain
                            if let Ok(p) = pool.try_read() {
                                // Use cached weight distribution for weighted donor selection
                                // (consistent with singlecore which uses sample_from_distribution)
                                let __donor_idx = p.sample_from_distribution(&__weight_cumulative, __weight_total, rng.next()).unwrap_or(0);
                                let __donor_seq = p.reconstruct_variant_field_sequence(__donor_idx);
                                if __donor_seq.len() >= 2 {
                                    let __splice_len = (2 + rng.next() as usize % 4).min(__donor_seq.len());
                                    let __splice_start = rng.next() as usize % (__donor_seq.len() - __splice_len + 1);
                                    let mut __spliced_actions: Vec<#action_ty> = Vec::with_capacity(__splice_len);
                                    for (vi, ref fb) in &__donor_seq[__splice_start..__splice_start + __splice_len] {
                                        let action = if !fb.is_empty() {
                                            let mut cursor = 0usize;
                                            match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(*vi, &*fb, &mut cursor) {
                                                Some(a) => a,
                                                None => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng),
                                            }
                                        } else {
                                            <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng)
                                        };
                                        __spliced_actions.push(action);
                                    }
                                    if !__spliced_actions.is_empty() {
                                        if let Some(entry) = p.get(0) {
                                            delta_arc = entry.delta.clone();
                                            parent_depth = 0;
                                            state_idx = 0;
                                            parent_action_bytes = entry.action_bytes.clone();
                                            parent_fingerprint = entry.fingerprint;
                                            fixture_arc = entry.fixture_state.clone();
                                            // Re-clone fixture from initial state under mutex
                                            {
                                                let _guard = fixture_clone_lock.lock().unwrap();
                                                if let Some(ref arc) = fixture_arc {
                                                    let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                                                    __iter_fixture = wrapper.0.clone();
                                                } else {
                                                    __iter_fixture = (*worker_fixture).clone();
                                                }
                                            }
                                        }
                                        __splice_chain = Some(__spliced_actions);
                                    }
                                }
                            }
                        }

                        // 2. Selective restore with dual-SVM support
                        let is_traced_iter = worker_traced_svm.is_some() && (local_iter % trace_interval == 0);
                        let has_tracing = trace_interval == 1 || is_traced_iter;

                        if is_traced_iter {
                            // Swap traced SVM into worker_svm position
                            if let Some(ref mut traced) = worker_traced_svm {
                                std::mem::swap(&mut *worker_svm, &mut **traced);
                            }
                            // Simple restore for traced SVM (infrequent, no delta-to-delta)
                            delta_arc.restore_selective(&*worker_initial, &mut *worker_svm, &traced_divergent);
                            traced_divergent.clear();
                            traced_divergent.extend(delta_arc.keys().copied());
                        } else {
                            // Optimized delta-to-delta restore for fast SVM
                            if let Some(ref prev) = prev_delta_arc {
                                delta_arc.restore_selective_from(&*worker_initial, &mut *worker_svm, &divergent_keys, prev, &prev_exec_dirty);
                            } else {
                                delta_arc.restore_selective(&*worker_initial, &mut *worker_svm, &divergent_keys);
                            }
                            divergent_keys.clear();
                            divergent_keys.extend(delta_arc.keys().copied());
                        }

                        // 3. Generate action chain using adaptive scheduling.
                        #mc_worker_action_chain

                        // 4. Execute chain — use per-iteration fixture clone (correct mutable state).
                        //    Swap SVMs into fixture, run test, swap back.
                        std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                        #extra_swap_in_iter

                        // Set coverage callback only when tracing is active this iteration
                        if has_tracing {
                            // Clear coverage map so hitcount buckets are per-iteration
                            unsafe { std::ptr::write_bytes(worker_cov_ptr, 0, #mod_name::MAP_SIZE); }
                            let callback = #mod_name::FuzzCallback::with_shared_memory(
                                worker_cov_ptr, #mod_name::MAP_SIZE,
                                shared_edge_ptr, shared_branch_ptr,
                            );
                            __iter_fixture.ctx.set_invocation_callback(callback);
                            #mod_name::reset_new_coverage_flag();
                        }

                        crucible_test_context::set_current_iteration(local_iter);
                        crucible_test_context::clear_iteration_state();

                        crucible_test_context::reset_iteration_dispatch_count();
                        let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            #fn_name(&mut __iter_fixture, __action_chain);
                        }));
                        let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();

                        // Truncate chain to actually-executed actions (strip unexecuted bytes)
                        #mc_truncation_code

                        // Flush thread-local bitmap buffers and check for new coverage.
                        // Uses shared bitmaps (atomic fetch_or) as single source of truth
                        // for coverage novelty — same as stateless multicore (SharedBitmapFeedback).
                        // Edge coverage (drives dedup bypass — real code coverage)
                        let __edge_novel_bits: u32 = if has_tracing {
                            #mod_name::flush_local_bitmap_buffers(shared_edge_ptr, shared_branch_ptr);
                            #mod_name::new_coverage_count()
                        } else { 0u32 };
                        // Combined fingerprint + field novelty + patch collection in one pass
                        let (mut __combined_fingerprint, __changed_accounts, __field_novel_bits) = unsafe {
                            crucible_test_context::snapshot::fingerprint_and_collect_changed(
                                &__iter_fixture.ctx.svm,
                                &__iter_fixture.ctx.dirty_tracker,
                                &*worker_initial,
                                shared_field_novelty_ptr,
                                crucible_test_context::snapshot::FIELD_NOVELTY_BITMAP_SIZE,
                            )
                        };
                        let __novel_bits = __edge_novel_bits + __field_novel_bits;
                        let __new_coverage = __edge_novel_bits > 0;
                        let __is_novel = __field_novel_bits > 0;

                        // Count actual SVM executions (includes success-seeking retries)
                        #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, Ordering::Relaxed);
                        iters.fetch_add(__actions_this_iter, Ordering::Relaxed);

                        // Check for violation
                        let violation = crucible_test_context::take_violation();

                        if let Some(ref msg) = violation {
                            // Track violation for record_violation() during flush
                            pending_violations.push(state_idx);

                            // Quick local dedup: skip if we've seen this variant from this state before
                            let __cur_variant = __action_variant_idx as u16;
                            let __local_key = libafl_bolts::hash_std(
                                &[&parent_fingerprint.to_le_bytes()[..], &__cur_variant.to_le_bytes()[..]].concat()
                            );
                            if seen_variant_hashes.insert(__local_key) {
                                // Build crash bytes (strip inherited ghosts from parent)
                                let mut crash_bytes = {
                                    let raw = (*parent_action_bytes).clone();
                                    let stored = if raw.len() >= 4 { u32::from_le_bytes(raw[0..4].try_into().unwrap()) } else { 0 };
                                    if stored != parent_depth {
                                        if let Ok(__pg) = pool.read() { __pg.rebuild_action_bytes_clean(state_idx) } else { raw }
                                    } else { raw }
                                };
                                let __parent_count = if crash_bytes.len() >= 4 {
                                    u32::from_le_bytes(crash_bytes[0..4].try_into().unwrap())
                                } else { 0 };
                                if crash_bytes.len() >= 4 {
                                    let old_count = __parent_count;
                                    crash_bytes[0..4].copy_from_slice(&(old_count + __chain_len as u32).to_le_bytes());
                                    crash_bytes.extend_from_slice(&__single_action_buf);
                                }
                                // Store ALL chain action descs for crash output
                                let history = crucible_test_context::get_action_history();
                                let current_descs: Vec<String> = __chain_descs.iter().enumerate().map(|(i, desc)| {
                                    let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                                    format!("{} -> {}", desc, status)
                                }).collect();
                                pending_crashes.push((__cur_variant, msg.clone(), current_descs, state_idx, crash_bytes));
                            }
                        }

                        // 5. Fingerprint + add to pool (accumulated locally)
                        // Field-novelty gate: only save states with novel per-field buckets or new edges.
                        let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                            let succeeded = crucible_test_context::get_first_action_success().unwrap_or(false);

                            // Record in per-worker action stats
                            action_stats.record(__state_class, __action_variant_idx, succeeded);

                            if __is_novel || __new_coverage {
                                let mut fingerprint = __combined_fingerprint;
                                // Clock-only changes
                                if __iter_fixture.ctx.dirty_tracker.dirty_accounts().is_empty() {
                                    fingerprint = fingerprint ^ parent_fingerprint.wrapping_mul(0x517cc1b727220a95);
                                }
                                if __edge_novel_bits > 0 {
                                    fingerprint = fingerprint
                                        .wrapping_mul(0x9e3779b97f4a7c15)
                                        .wrapping_add(local_iter);
                                }

                                // Skip expensive delta snapshot if pool already has this fingerprint.
                                // coverage_novel states bypass this (always save for coverage).
                                if fingerprint != 0 && (__new_coverage || !fp_bitmap.is_seen(fingerprint)) {
                                    let new_delta = CompactDelta::child_delta(
                                        &delta_arc,
                                        __changed_accounts,
                                        __iter_fixture.ctx.dirty_tracker.dirty_accounts(),
                                        &__iter_fixture.ctx.svm,
                                    );

                                    let mut accumulated_bytes = (*parent_action_bytes).clone();
                                    if accumulated_bytes.len() >= 4 {
                                        // Validate parent action count matches depth to strip inherited ghosts
                                        let stored_count = u32::from_le_bytes(
                                            accumulated_bytes[0..4].try_into().unwrap()
                                        );
                                        if stored_count != parent_depth {
                                            // Parent has ghost actions — rebuild from scratch
                                            match pool.read() {
                                                Ok(__pg) => {
                                                    accumulated_bytes = __pg.rebuild_action_bytes_clean(state_idx);
                                                }
                                                Err(_) => {
                                                    // Lock poisoned — skip save
                                                    continue;
                                                }
                                            }
                                        }
                                        let count = u32::from_le_bytes(
                                            accumulated_bytes[0..4].try_into().unwrap()
                                        );
                                        accumulated_bytes[0..4].copy_from_slice(&(count + __chain_len as u32).to_le_bytes());
                                        accumulated_bytes.extend_from_slice(&__single_action_buf);
                                    }

                                    let __fbc = <#action_ty as crucible_fuzzer::FuzzAction>::field_byte_count(__action_variant_idx);
                                    let __last_action_start = __single_action_buf.len().saturating_sub(2 + __fbc);
                                    let __field_bytes = if __last_action_start + 2 < __single_action_buf.len() {
                                        __single_action_buf[__last_action_start + 2..].to_vec()
                                    } else {
                                        Vec::new()
                                    };

                                    // Store fixture alongside novel state (SVMs swapped out = cheap clone).
                                    // Must use blocking lock to guarantee fixture is always stored.
                                    // Without this, fixture_state=None causes stale template fallback
                                    // on restore, desyncing harness tracking from SVM state.
                                    #extra_restore_swap_back_iter
                                    std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                                    let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> = {
                                        let _guard = fixture_clone_lock.lock().unwrap();
                                        Some(std::sync::Arc::new(__FixtureWrapper(__iter_fixture.clone())))
                                    };
                                    std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                                    #extra_swap_in_iter

                                    let action_desc = {
                                        let history = crucible_test_context::get_action_history();
                                        __chain_descs.iter().enumerate().map(|(i, desc)| {
                                            let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                                            format!("{} -> {}", desc, status)
                                        }).collect::<Vec<_>>().join("\n")
                                    };
                                    let __coverage_positions: Option<Vec<u16>> = if __novel_bits > 0 && has_tracing {
                                        Some(crucible_test_context::snapshot::extract_coverage_positions(&worker_cov_map))
                                    } else { None };
                                    pending_novel.push((
                                        fingerprint, new_delta, parent_depth + __chain_len as u32,
                                        Some(state_idx), accumulated_bytes, action_desc,
                                        Some(__action_variant_idx as u16), __field_bytes,
                                        __fixture_for_storage, __novel_bits, __edge_novel_bits, succeeded, __coverage_positions,
                                    ));
                                }
                            }
                            succeeded
                        } else {
                            action_stats.record(__state_class, __action_variant_idx, false);
                            false
                        };

                        // Record barren pick for exponential weight decay.
                        if !(__is_novel || __new_coverage) && violation.is_none() && __panic_result.is_ok() {
                            pending_barren.push(state_idx);
                        }

                        // 6. Update divergent_keys, prev_delta_arc, and prev_exec_dirty
                        // IMPORTANT: Always track dirty accounts regardless of success/failure.
                        // Failed actions can still create/delete/modify accounts.
                        if is_traced_iter {
                            // Traced SVM: always update divergent tracking
                            traced_divergent.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                        } else {
                            // Fast SVM: update delta optimization state
                            prev_exec_dirty.clear();
                            prev_exec_dirty.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                            divergent_keys.extend(prev_exec_dirty.iter().copied());
                            if __action_succeeded {
                                prev_delta_arc = Some(delta_arc);
                            } else {
                                prev_delta_arc = None;
                            }
                        }

                        // 7. Swap SVMs back out of per-iteration fixture
                        #extra_restore_swap_back_iter
                        std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                        // If traced iteration, swap traced SVM back to its dedicated slot
                        if is_traced_iter {
                            if let Some(ref mut traced) = worker_traced_svm {
                                std::mem::swap(&mut *worker_svm, &mut **traced);
                            }
                        }
                        // Defer fixture drop: Rc::drop must happen under mutex to avoid
                        // racing with Rc::clone on other threads. Cleared at next batch refill.
                        pending_fixture_drops.push(__iter_fixture);

                        // Note: panics from invariant violations are already captured via take_violation().
                        // Do NOT resume_unwind in spawned worker threads — it causes SIGABRT.
                        if __panic_result.is_err() && violation.is_none() {
                            eprintln!("[WORKER] Unexpected panic in worker thread (not a violation)");
                        }
                    }
                    // Worker exiting — drain ALL Rc-bearing locals under mutex for Rc safety.
                    // fixture_batch must also be cleared here (not just pending_fixture_drops),
                    // otherwise its implicit drop triggers Rc::drop without the mutex.
                    {
                        let _guard = fixture_clone_lock.lock().unwrap();
                        pending_fixture_drops.clear();
                        fixture_batch.clear();
                    }
                })
                .expect("failed to spawn worker thread");

            worker_handles.push(handle);
        }

        // Worker 0 (main thread): same pattern — ManuallyDrop, no per-iteration clone
        {
            // Extract raw pointers for worker 0 (main thread)
            let shared_edge_ptr = shared_edge_addr as *mut u8;
            let shared_branch_ptr = shared_branch_addr as *mut u8;
            let shared_field_novelty_ptr = shared_field_novelty_addr as *mut u8;

            let pool = state_pool.clone();
            let iters = shared_iters.clone();
            let crashes = shared_crashes.clone();
            let novel = shared_novel.clone();
            let stop = stop_flag.clone();
            let w0_initial = initial_snapshot.clone();

            // Worker 0 uses raw values (main thread — no Send/Rc concerns)
            let mut w0_fixture = template_fixture;
            let mut w0_svm = __real_svm;
            // Traced SVM for Worker 0 (take from outer scope)
            let mut w0_traced_svm: Option<crucible_test_context::litesvm::LiteSVM> = if trace_interval > 1 {
                __traced_svm.take()
                    .or_else(|| {
                        // Fallback: create a new debuggable SVM from snapshot
                        let mut svm = __create_svm(true);
                        initial_snapshot.restore_full(&mut svm);
                        Some(svm)
                    })
            } else {
                None
            };

            crucible_test_context::set_stateful_chain_mode(true);

            // Per-worker coverage map + virgin map for hitcount novelty detection
            let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
            let worker_cov_ptr = worker_cov_map.as_mut_ptr();
            let mut rng = StdRand::with_seed(seed);
            let mut local_iter: u64 = 0;
            let mut last_print_time = std::time::Instant::now();
            let mut last_print_iters: u64 = 0;
            let mut divergent_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();
            let mut prev_delta_arc: Option<std::sync::Arc<CompactDelta>> = None;
            let mut prev_exec_dirty: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();
            // Dual-SVM: divergent tracking for the traced SVM
            let mut traced_divergent: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();

            let mut __phase_pick_ns: u64 = 0;
            let mut __phase_pick_flush_ns: u64 = 0;
            let mut __phase_pick_batch_ns: u64 = 0;
            let mut __phase_pick_crossover_ns: u64 = 0;
            let mut __phase_pick_splice_ns: u64 = 0;
            let mut __phase_restore_ns: u64 = 0;
            let mut __phase_action_gen_ns: u64 = 0;
            let mut __phase_clone_ns: u64 = 0;
            let mut __phase_svm_exec_ns: u64 = 0;
            let mut __phase_tx_pre_ns: u64 = 0;
            let mut __phase_tx_svm_ns: u64 = 0;
            let mut __phase_tx_post_ns: u64 = 0;
            let mut __phase_tx_blockhash_ns: u64 = 0;
            let mut __phase_tx_sign_ns: u64 = 0;
            let mut __phase_tx_exec_ns: u64 = 0;
            let mut __phase_coverage_ns: u64 = 0;
            let mut __phase_field_novelty_ns: u64 = 0;
            let mut __phase_fingerprint_ns: u64 = 0;
            let mut __phase_save_ns: u64 = 0;
            let mut __phase_crash_ns: u64 = 0;
            let mut __phase_cleanup_ns: u64 = 0;
            let mut __phase_total_ns: u64 = 0;
            let mut __profiled_iters: u64 = 0;
            let __profile_interval: u64 = 64;
            let mut __single_action_buf: Vec<u8> = Vec::with_capacity(64);

            // Per-worker action stats
            let mut action_stats = crucible_test_context::snapshot::ActionStatsMap::new(
                <#action_ty as crucible_fuzzer::FuzzAction>::variant_count(),
            );

            // Batched pool access (same pattern as spawned workers):
            // Pick BATCH_SIZE states under one read lock (pick_count is atomic),
            // process locally, flush results with one write lock per batch.
            const BATCH_SIZE: usize = 512;
            // (delta, depth, state_idx, action_bytes, parent_variant, parent_field_bytes, fingerprint, fixture_state)
            type PickTuple = (std::sync::Arc<CompactDelta>, u32, usize, std::sync::Arc<Vec<u8>>, Option<u16>, std::sync::Arc<Vec<u8>>, u64, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);
            // Reuse rng_vals allocation across batch refills (C4)
            let mut rng_vals: Vec<u64> = Vec::with_capacity(BATCH_SIZE);
            let mut local_batch: Vec<PickTuple> = Vec::with_capacity(BATCH_SIZE);
            // Success crossover: (variant_idx, field_bytes) from random pool states, refreshed each batch
            let mut __crossover_buf: Vec<(usize, std::sync::Arc<Vec<u8>>)> = Vec::with_capacity(16);
            // Pre-cloned fixtures for the current batch
            let mut w0_fixture_batch: Vec<#fixture_name> = Vec::with_capacity(BATCH_SIZE);
            // Deferred fixture drops: serialized with clones under mutex to prevent Rc races
            let mut w0_pending_drops: Vec<#fixture_name> = Vec::with_capacity(BATCH_SIZE + 1);
            // (fingerprint, delta, depth, parent_idx, action_bytes, desc, variant, field_bytes, fixture_state, coverage_novel, edge_novelty, succeeded, coverage_positions)
            let mut pending_novel: Vec<(u64, CompactDelta, u32, Option<usize>, Vec<u8>, String, Option<u16>, Vec<u8>, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>, u32, u32, bool, Option<Vec<u16>>)> = Vec::new();
            let mut pending_crashes: Vec<(u16, String, Vec<String>, usize, Vec<u8>)> = Vec::new();
            // Track pending violations: state indices that need record_violation() in the flush
            let mut pending_violations: Vec<usize> = Vec::new();
            let mut pending_barren: Vec<usize> = Vec::new();
            // Pending state_class selects to flush into registry
            let mut pending_selects: Vec<u16> = Vec::with_capacity(BATCH_SIZE);
            // Thread-local seen variant hashes to skip duplicate crash accumulation
            let mut seen_variant_hashes: crucible_test_context::FastHashSet<u64> = crucible_test_context::FastHashSet::default();
            // Cache pool stats for monitor (updated at batch boundaries, avoids extra read locks)
            let mut cached_pool_len: usize = 1;
            let mut cached_pool_active: usize = 1;
            // Cached weight distribution — rebuilt at batch boundaries, reused for splice
            let mut __weight_cumulative: Vec<f64> = Vec::new();
            let mut __weight_total: f64 = 0.0;

            loop {
                if stop.load(Ordering::Relaxed) || SIGNAL_STOP.load(Ordering::Relaxed) { break; }

                local_iter += 1;

                // Timeout check (rate-limited)
                if let Some(timeout) = timeout_secs {
                    if local_iter % 1000 == 0 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if now - start_time >= timeout {
                            eprintln!("\n[STATEFUL] Timeout reached ({}s). Exiting.", timeout);
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }

                let __do_profile = (local_iter % __profile_interval) == 0;
                let __iter_start = if __do_profile { Some(std::time::Instant::now()) } else { None };

                // 1. Refill batch when empty
                let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
                if local_batch.is_empty() {
                    let __t_flush = if __do_profile { Some(std::time::Instant::now()) } else { None };
                    // Flush pending writes from previous batch
                    // Fix 3: Collect crash outputs inside lock, write to disk outside
                    let mut __crash_outputs: Vec<(String, Vec<String>, Vec<String>, u64, Vec<u8>)> = Vec::new();
                    if !pending_novel.is_empty() || !pending_crashes.is_empty() || !pending_violations.is_empty() || !pending_selects.is_empty() || !pending_barren.is_empty() {
                        if let Ok(mut p) = pool.try_write() {
                            for sc in pending_selects.drain(..) {
                                p.registry_mut().record_select(sc);
                            }
                            p.set_current_iteration(local_iter);
                            p.maybe_advance_phase();
                            for (fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel, edge_novel, succ, cov_pos) in pending_novel.drain(..) {
                                if p.try_add(fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel, edge_novel, succ, cov_pos) {
                                    novel.fetch_add(1, Ordering::Relaxed);
                                    fingerprint_bitmap.mark(fp);
                                    if let Some(ref __cop) = corpus_out_dir {
                                        p.write_corpus_entry(p.len() - 1, __cop);
                                    }
                                }
                            }
                            // Record violations against parent states
                            for vi_idx in pending_violations.drain(..) {
                                p.record_violation(vi_idx);
                            }
                            for bi_idx in pending_barren.drain(..) {
                                p.record_barren_pick(bi_idx);
                            }
                            for (cur_variant, msg, current_descs, parent_idx, crash_bytes) in pending_crashes.drain(..) {
                                // Compute variant-only hash inside the lock
                                let mut __variant_seq = p.reconstruct_variant_sequence(parent_idx);
                                __variant_seq.push(cur_variant);
                                let vh = libafl_bolts::hash_std(
                                    &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                                );
                                if p.is_novel_crash(vh) {
                                    crashes.fetch_add(1, Ordering::Relaxed);
                                    let parent_descs = p.reconstruct_action_descriptions(parent_idx);
                                    __crash_outputs.push((msg, parent_descs, current_descs, vh, crash_bytes));
                                    if stop_on_crash {
                                        eprintln!("[STATEFUL W0] First crash found, signaling stop (--stop-on-crash).");
                                        stop.store(true, Ordering::Relaxed);
                                    }
                                }
                            }
                            cached_pool_len = p.len();
                            cached_pool_active = p.active_count();
                        } else {
                            // Couldn't get write lock — keep pending_novel for retry next batch.
                            // Cap to prevent unbounded growth if write lock is always contended.
                            if pending_novel.len() > 2048 {
                                let dropped = pending_novel.len() - 1024;
                                pending_novel.drain(..dropped);
                                eprintln!("[STATEFUL W0] Warning: dropped {} pending novel states (write lock contention)", dropped);
                            }
                        }
                    }
                    // Crash disk I/O outside write lock (Fix 3)
                    for (msg, parent_descs, current_descs, vh, crash_bytes) in __crash_outputs {
                        let total = parent_descs.len() + current_descs.len();
                        println!("[FUZZ_FINDING] reproduces:true summary:{}", msg);
                        eprintln!("\n[FUZZ_FINDING] {}", msg);
                        eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                        for (i, desc) in parent_descs.iter().enumerate() {
                            eprintln!("  {}. {}", i + 1, desc);
                        }
                        for (i, desc) in current_descs.iter().enumerate() {
                            let tag = if i == current_descs.len() - 1 { " [VIOLATION]" } else { "" };
                            eprintln!("  {}. {}{}", parent_descs.len() + i + 1, desc, tag);
                        }
                        eprintln!("===================================");
                        let mut __full_actions: Vec<crucible_test_context::ActionRecord> = parent_descs
                            .iter()
                            .map(|d| crucible_test_context::parse_action_desc(d))
                            .collect();
                        for desc in &current_descs {
                            __full_actions.push(crucible_test_context::parse_action_desc(desc));
                        }
                        crucible_test_context::write_crash_metadata_with_actions(
                            &crash_dir, vh, Some(seed), &crash_bytes, Some(__full_actions),
                        );
                    }

                    // Flush discovered variants to shared bitmap
                    {
                        let __total_variants = crucible_test_context::TOTAL_ACTION_VARIANTS
                            .load(std::sync::atomic::Ordering::Relaxed);
                        for __vi in 0..__total_variants.min(256) {
                            if crucible_test_context::has_variant_succeeded(__vi) {
                                shared_discovered[__vi].store(1, Ordering::Relaxed);
                            }
                        }
                    }

                    if let Some(__t) = __t_flush { __phase_pick_flush_ns += __t.elapsed().as_nanos() as u64; }

                    // Pick weighted batch (read lock — pick_count is atomic)
                    {
                        let __t_batch = if __do_profile { Some(std::time::Instant::now()) } else { None };
                        let p = pool.read().unwrap();
                        cached_pool_len = p.len();
                        cached_pool_active = p.active_count();
                        rng_vals.clear();
                        for _ in 0..BATCH_SIZE {
                            rng_vals.push(rng.next());
                        }
                        let (__wc, __wt) = p.build_weight_distribution();
                        p.pick_weighted_batch_from(&__wc, __wt, &rng_vals, &mut local_batch);
                        if let Some(__t) = __t_batch { __phase_pick_batch_ns += __t.elapsed().as_nanos() as u64; }
                        // Pick crossover candidates using pre-built distribution (O(log n))
                        let __t_cross = if __do_profile { Some(std::time::Instant::now()) } else { None };
                        __crossover_buf.clear();
                        for _ in 0..16usize {
                            if let Some(idx) = p.sample_from_distribution(&__wc, __wt, rng.next()) {
                                if let Some(entry) = p.get(idx) {
                                    if let Some(vi) = entry.action_variant {
                                        __crossover_buf.push((vi as usize, entry.action_field_bytes.clone()));
                                    }
                                }
                            }
                        }
                        if let Some(__t) = __t_cross { __phase_pick_crossover_ns += __t.elapsed().as_nanos() as u64; }
                        // Cache weight distribution for splice donor selection
                        __weight_cumulative = __wc;
                        __weight_total = __wt;
                        // Read lock released here — pool is free for other workers
                    }

                    if local_batch.is_empty() {
                        eprintln!("[STATEFUL] All active states exhausted. Stopping.");
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }

                    // Batch fixture clones + deferred drops under ONE mutex lock.
                    // Serializes all Rc operations (clone + drop) to prevent data races.
                    {
                        let _guard = fixture_clone_mutex.lock().unwrap();
                        // 1. Drop deferred fixtures from previous batch
                        w0_pending_drops.clear();
                        // 2. Clone new batch
                        w0_fixture_batch.clear();
                        for (_, _, _, _, _, _, _, fixture_arc) in local_batch.iter() {
                            if let Some(ref arc) = fixture_arc {
                                let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                                w0_fixture_batch.push(wrapper.0.clone());
                            } else {
                                w0_fixture_batch.push(w0_fixture.clone());
                            }
                        }
                    }
                }

                // Pop one state + pre-cloned fixture from local batch (no lock needed)
                let (mut delta_arc, mut parent_depth, mut state_idx, mut parent_action_bytes, parent_variant, parent_field_bytes, mut parent_fingerprint, mut fixture_arc) =
                    local_batch.pop().unwrap();
                let mut __iter_fixture = w0_fixture_batch.pop().unwrap();

                // Subsequence splice (5%):
                let __t_splice = if __do_profile { Some(std::time::Instant::now()) } else { None };
                let __splice_roll = rng.next() % 100;
                let mut __splice_chain: Option<Vec<#action_ty>> = None;
                if __splice_roll < 5 && cached_pool_len > 10 {
                    // 5%: Donor splice — extract subsequence from an existing chain
                    if let Ok(p) = pool.try_read() {
                        // Use cached weight distribution for weighted donor selection
                        // (consistent with singlecore which uses sample_from_distribution)
                        let __donor_idx = p.sample_from_distribution(&__weight_cumulative, __weight_total, rng.next()).unwrap_or(0);
                        let __donor_seq = p.reconstruct_variant_field_sequence(__donor_idx);
                        if __donor_seq.len() >= 2 {
                            let __splice_len = (2 + rng.next() as usize % 4).min(__donor_seq.len());
                            let __splice_start = rng.next() as usize % (__donor_seq.len() - __splice_len + 1);
                            let mut __spliced_actions: Vec<#action_ty> = Vec::with_capacity(__splice_len);
                            for (vi, ref fb) in &__donor_seq[__splice_start..__splice_start + __splice_len] {
                                let action = if !fb.is_empty() {
                                    let mut cursor = 0usize;
                                    match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(*vi, &*fb, &mut cursor) {
                                        Some(a) => a,
                                        None => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng),
                                    }
                                } else {
                                    <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(*vi, &mut rng)
                                };
                                __spliced_actions.push(action);
                            }
                            if !__spliced_actions.is_empty() {
                                if let Some(entry) = p.get(0) {
                                    delta_arc = entry.delta.clone();
                                    parent_depth = 0;
                                    state_idx = 0;
                                    parent_action_bytes = entry.action_bytes.clone();
                                    parent_fingerprint = entry.fingerprint;
                                    fixture_arc = entry.fixture_state.clone();
                                    // Re-clone fixture from initial state under mutex
                                    {
                                        let _guard = fixture_clone_mutex.lock().unwrap();
                                        if let Some(ref arc) = fixture_arc {
                                            let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                                            __iter_fixture = wrapper.0.clone();
                                        } else {
                                            __iter_fixture = w0_fixture.clone();
                                        }
                                    }
                                }
                                __splice_chain = Some(__spliced_actions);
                            }
                        }
                    }
                }
                if let Some(__t) = __t_splice { __phase_pick_splice_ns += __t.elapsed().as_nanos() as u64; }
                if let Some(__t) = __t { __phase_pick_ns += __t.elapsed().as_nanos() as u64; }

                // 2. Selective restore with dual-SVM support
                let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
                let is_traced_iter = w0_traced_svm.is_some() && (local_iter % trace_interval == 0);
                let has_tracing = trace_interval == 1 || is_traced_iter;

                if is_traced_iter {
                    // Swap traced SVM into w0_svm position
                    if let Some(ref mut traced) = w0_traced_svm {
                        std::mem::swap(&mut w0_svm, traced);
                    }
                    // Simple restore for traced SVM (infrequent, no delta-to-delta)
                    delta_arc.restore_selective(&*w0_initial, &mut w0_svm, &traced_divergent);
                    traced_divergent.clear();
                    traced_divergent.extend(delta_arc.keys().copied());
                } else {
                    // Optimized delta-to-delta restore for fast SVM
                    if let Some(ref prev) = prev_delta_arc {
                        delta_arc.restore_selective_from(&*w0_initial, &mut w0_svm, &divergent_keys, prev, &prev_exec_dirty);
                    } else {
                        delta_arc.restore_selective(&*w0_initial, &mut w0_svm, &divergent_keys);
                    }
                    divergent_keys.clear();
                    divergent_keys.extend(delta_arc.keys().copied());
                }
                if let Some(__t) = __t { __phase_restore_ns += __t.elapsed().as_nanos() as u64; }

                // 3. Generate action chain using adaptive scheduling.
                #mc_w0_action_chain

                // 4. Execute — use per-iteration fixture clone (correct mutable state).
                //    Swap SVMs into fixture, run test, swap back.
                let __t_clone = if __do_profile { Some(std::time::Instant::now()) } else { None };
                std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                #extra_swap_in_iter

                // Set coverage callback only when tracing is active this iteration
                if has_tracing {
                    // Clear coverage map so hitcount buckets are per-iteration
                    unsafe { std::ptr::write_bytes(worker_cov_ptr, 0, #mod_name::MAP_SIZE); }
                    let callback = #mod_name::FuzzCallback::with_shared_memory(
                        worker_cov_ptr, #mod_name::MAP_SIZE,
                        shared_edge_ptr, shared_branch_ptr,
                    );
                    __iter_fixture.ctx.set_invocation_callback(callback);
                    #mod_name::reset_new_coverage_flag();
                }

                crucible_test_context::set_current_iteration(local_iter);
                crucible_test_context::clear_iteration_state();
                if let Some(__t) = __t_clone { __phase_clone_ns += __t.elapsed().as_nanos() as u64; }

                let __t_exec = if __do_profile { Some(std::time::Instant::now()) } else { None };
                if __do_profile { crucible_test_context::reset_send_batch_timers(); }
                crucible_test_context::reset_iteration_dispatch_count();
                let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #fn_name(&mut __iter_fixture, __action_chain);
                }));
                let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();
                if let Some(__t) = __t_exec {
                    __phase_svm_exec_ns += __t.elapsed().as_nanos() as u64;
                    let (__pre, __svm, __post) = crucible_test_context::get_send_batch_timers();
                    __phase_tx_pre_ns += __pre;
                    __phase_tx_svm_ns += __svm;
                    __phase_tx_post_ns += __post;
                    let (__bh, __sg, __ex) = crucible_test_context::get_send_tx_breakdown();
                    __phase_tx_blockhash_ns += __bh;
                    __phase_tx_sign_ns += __sg;
                    __phase_tx_exec_ns += __ex;
                }

                // Truncate chain to actually-executed actions (strip unexecuted bytes)
                #mc_truncation_code

                // Flush thread-local bitmap buffers and check for new coverage.
                // Uses shared bitmaps (atomic fetch_or) as single source of truth.
                // Edge coverage (drives dedup bypass — real code coverage)
                let __t_cov = if __do_profile { Some(std::time::Instant::now()) } else { None };
                let __edge_novel_bits: u32 = if has_tracing {
                    #mod_name::flush_local_bitmap_buffers(shared_edge_ptr, shared_branch_ptr);
                    #mod_name::new_coverage_count()
                } else { 0u32 };
                if let Some(__t) = __t_cov { __phase_coverage_ns += __t.elapsed().as_nanos() as u64; }

                // Combined fingerprint + field novelty + patch collection in one pass
                let __t_fn = if __do_profile { Some(std::time::Instant::now()) } else { None };
                let (mut __combined_fingerprint, __changed_accounts, __field_novel_bits) = unsafe {
                    crucible_test_context::snapshot::fingerprint_and_collect_changed(
                        &__iter_fixture.ctx.svm,
                        &__iter_fixture.ctx.dirty_tracker,
                        &*w0_initial,
                        shared_field_novelty_ptr,
                        crucible_test_context::snapshot::FIELD_NOVELTY_BITMAP_SIZE,
                    )
                };
                if let Some(__t) = __t_fn { __phase_field_novelty_ns += __t.elapsed().as_nanos() as u64; }
                let __novel_bits = __edge_novel_bits + __field_novel_bits;
                let __new_coverage = __edge_novel_bits > 0;
                let __is_novel = __field_novel_bits > 0;

                // Count actual SVM executions (includes success-seeking retries)
                #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, Ordering::Relaxed);
                iters.fetch_add(__actions_this_iter, Ordering::Relaxed);

                if #mod_name::COVERAGE_ENABLED.load(Ordering::Relaxed) {
                    let exec_count = #mod_name::TOTAL_EXECUTIONS.load(Ordering::Relaxed);
                    #mod_name::maybe_write_coverage(exec_count);
                }

                // Check for violation — accumulate locally (flushed at batch boundary)
                let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
                let violation = crucible_test_context::take_violation();

                if let Some(ref msg) = violation {
                    // Track violation for record_violation() during flush
                    pending_violations.push(state_idx);

                    // Quick local dedup: skip if we've seen this variant from this state before
                    let __cur_variant = __action_variant_idx as u16;
                    let __local_key = libafl_bolts::hash_std(
                        &[&parent_fingerprint.to_le_bytes()[..], &__cur_variant.to_le_bytes()[..]].concat()
                    );
                    if seen_variant_hashes.insert(__local_key) {
                        let mut crash_bytes = {
                            let raw = (*parent_action_bytes).clone();
                            let stored = if raw.len() >= 4 { u32::from_le_bytes(raw[0..4].try_into().unwrap()) } else { 0 };
                            if stored != parent_depth {
                                match state_pool.try_read() {
                                    Ok(__pg) => __pg.rebuild_action_bytes_clean(state_idx),
                                    Err(_) => {
                                        eprintln!("[STATEFUL W0] Warning: crash bytes may have ghost actions (pool lock contended)");
                                        raw
                                    }
                                }
                            } else { raw }
                        };
                        if crash_bytes.len() >= 4 {
                            let old_count = u32::from_le_bytes(
                                crash_bytes[0..4].try_into().unwrap()
                            );
                            crash_bytes[0..4].copy_from_slice(&(old_count + __chain_len as u32).to_le_bytes());
                            crash_bytes.extend_from_slice(&__single_action_buf);
                        }
                        // Store ALL chain action descs for crash output
                        let history = crucible_test_context::get_action_history();
                        let current_descs: Vec<String> = __chain_descs.iter().enumerate().map(|(i, desc)| {
                            let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                            format!("{} -> {}", desc, status)
                        }).collect();
                        pending_crashes.push((__cur_variant, msg.clone(), current_descs, state_idx, crash_bytes));
                    }
                }
                if let Some(__t) = __t { __phase_crash_ns += __t.elapsed().as_nanos() as u64; }

                // 5. Fingerprint + add to pool
                // Field-novelty gate: only save states with novel per-field buckets or new edges.
                let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                    let succeeded = crucible_test_context::get_first_action_success().unwrap_or(false);

                    // Record in per-worker action stats
                    action_stats.record(__state_class, __action_variant_idx, succeeded);

                    if __is_novel || __new_coverage {
                        let __t_fp = if __do_profile { Some(std::time::Instant::now()) } else { None };
                        let mut fingerprint = __combined_fingerprint;
                        // Clock-only changes
                        if __iter_fixture.ctx.dirty_tracker.dirty_accounts().is_empty() {
                            fingerprint = fingerprint ^ parent_fingerprint.wrapping_mul(0x517cc1b727220a95);
                        }
                        if __edge_novel_bits > 0 {
                            fingerprint = fingerprint
                                .wrapping_mul(0x9e3779b97f4a7c15)
                                .wrapping_add(local_iter);
                        }
                        if let Some(__t) = __t_fp { __phase_fingerprint_ns += __t.elapsed().as_nanos() as u64; }

                        // Skip expensive delta snapshot if pool already has this fingerprint.
                        // coverage_novel states bypass this (always save for coverage).
                        if fingerprint != 0 && (__new_coverage || !fingerprint_bitmap.is_seen(fingerprint)) {
                            let __t_save = if __do_profile { Some(std::time::Instant::now()) } else { None };
                            let new_delta = CompactDelta::child_delta(
                                &delta_arc,
                                __changed_accounts,
                                __iter_fixture.ctx.dirty_tracker.dirty_accounts(),
                                &__iter_fixture.ctx.svm,
                            );

                            let mut accumulated_bytes = (*parent_action_bytes).clone();
                            if accumulated_bytes.len() >= 4 {
                                // Validate parent action count matches depth to strip inherited ghosts
                                let stored_count = u32::from_le_bytes(
                                    accumulated_bytes[0..4].try_into().unwrap()
                                );
                                if stored_count != parent_depth {
                                    // Parent has ghost actions — rebuild from scratch
                                    match state_pool.try_read() {
                                        Ok(__pg) => {
                                            accumulated_bytes = __pg.rebuild_action_bytes_clean(state_idx);
                                        }
                                        Err(_) => {
                                            // Can't rebuild — skip save rather than store corrupted bytes
                                            continue;
                                        }
                                    }
                                }
                                let count = u32::from_le_bytes(
                                    accumulated_bytes[0..4].try_into().unwrap()
                                );
                                accumulated_bytes[0..4].copy_from_slice(&(count + __chain_len as u32).to_le_bytes());
                                accumulated_bytes.extend_from_slice(&__single_action_buf);
                            }

                            // Extract field bytes for parent-action replay (skip 2-byte variant header)
                            // Use the LAST action in the chain for crossover source
                            let __fbc = <#action_ty as crucible_fuzzer::FuzzAction>::field_byte_count(__action_variant_idx);
                            let __last_action_start = __single_action_buf.len().saturating_sub(2 + __fbc);
                            let __field_bytes = if __last_action_start + 2 < __single_action_buf.len() {
                                __single_action_buf[__last_action_start + 2..].to_vec()
                            } else {
                                Vec::new()
                            };

                            // Store fixture alongside novel state (SVMs swapped out = cheap clone).
                            // Must use blocking lock to guarantee fixture is always stored.
                            #extra_restore_swap_back_iter
                            std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                            let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> = {
                                let _guard = fixture_clone_mutex.lock().unwrap();
                                Some(std::sync::Arc::new(__FixtureWrapper(__iter_fixture.clone())))
                            };
                            std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                            #extra_swap_in_iter

                            let action_desc = {
                                let history = crucible_test_context::get_action_history();
                                __chain_descs.iter().enumerate().map(|(i, desc)| {
                                    let status = if history.get(i).map(|r| r.success).unwrap_or(false) { "OK" } else { "FAIL" };
                                    format!("{} -> {}", desc, status)
                                }).collect::<Vec<_>>().join("\n")
                            };
                            let __coverage_positions: Option<Vec<u16>> = if __novel_bits > 0 && has_tracing {
                                Some(crucible_test_context::snapshot::extract_coverage_positions(&worker_cov_map))
                            } else { None };
                            pending_novel.push((
                                fingerprint, new_delta, parent_depth + __chain_len as u32,
                                Some(state_idx), accumulated_bytes, action_desc,
                                Some(__action_variant_idx as u16), __field_bytes,
                                __fixture_for_storage, __novel_bits, __edge_novel_bits, succeeded, __coverage_positions,
                            ));
                            if let Some(__t) = __t_save { __phase_save_ns += __t.elapsed().as_nanos() as u64; }
                        }
                    }
                    succeeded
                } else {
                    action_stats.record(__state_class, __action_variant_idx, false);
                    false
                };

                // Record barren pick for exponential weight decay.
                if !(__is_novel || __new_coverage) && violation.is_none() && __panic_result.is_ok() {
                    pending_barren.push(state_idx);
                }

                // 6. Update divergent_keys, prev_delta_arc, and prev_exec_dirty
                // IMPORTANT: Always track dirty accounts regardless of success/failure.
                // Failed actions can still create/delete/modify accounts.
                let __t = if __do_profile { Some(std::time::Instant::now()) } else { None };
                if is_traced_iter {
                    // Traced SVM: always update divergent tracking
                    traced_divergent.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                } else {
                    // Fast SVM: update delta optimization state
                    prev_exec_dirty.clear();
                    prev_exec_dirty.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                    divergent_keys.extend(prev_exec_dirty.iter().copied());
                    if __action_succeeded {
                        prev_delta_arc = Some(delta_arc);
                    } else {
                        prev_delta_arc = None;
                    }
                }

                // 7. Swap SVMs back out of per-iteration fixture
                #extra_restore_swap_back_iter
                std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                // If traced iteration, swap traced SVM back to its dedicated slot
                if is_traced_iter {
                    if let Some(ref mut traced) = w0_traced_svm {
                        std::mem::swap(&mut w0_svm, traced);
                    }
                }
                // Defer fixture drop: Rc::drop must happen under mutex (next batch refill)
                w0_pending_drops.push(__iter_fixture);
                if let Some(__t) = __t { __phase_cleanup_ns += __t.elapsed().as_nanos() as u64; }

                // Note: panics from invariant violations are captured via take_violation().
                // Do NOT resume_unwind in multicore worker 0 — it causes SIGABRT
                // (no catch_unwind above us). Same as spawned workers.
                if __panic_result.is_err() && violation.is_none() {
                    eprintln!("[STATEFUL W0] Unexpected panic (not a violation)");
                }

                // 8. Rate-limited monitor output (worker 0 only)
                if let Some(__t) = __iter_start {
                    __phase_total_ns += __t.elapsed().as_nanos() as u64;
                    __profiled_iters += 1;
                }

                let now = std::time::Instant::now();
                if now.duration_since(last_print_time).as_millis() >= 2000 {
                    let elapsed_secs = now.duration_since(last_print_time).as_secs_f64();
                    let total_iters = iters.load(Ordering::Relaxed);
                    let iters_since = total_iters - last_print_iters;
                    let iter_sec = iters_since as f64 / elapsed_secs;

                    let total_crashes = crashes.load(Ordering::Relaxed);
                    let total_novel = novel.load(Ordering::Relaxed);

                    // Read coverage from shared bitmaps (lock-free) instead of COVERAGE_STATE Mutex
                    let edges = #mod_name::FuzzCallback::count_shared_bits(
                        shared_edge_ptr as *const u8,
                        #mod_name::SHARED_EDGE_BITMAP_SIZE / 2,
                    );
                    let branches = #mod_name::FuzzCallback::count_shared_bits(
                        shared_branch_ptr as *const u8,
                        #mod_name::SHARED_BRANCH_BITMAP_SIZE,
                    );
                    let total_edges: usize = #mod_name::PROGRAM_TOTALS.get()
                        .map(|t| t.values().sum()).unwrap_or(0);
                    let total_branches = total_edges / 2;

                    let edge_pct = if total_edges > 0 {
                        (edges as f64 / total_edges as f64) * 100.0
                    } else { 0.0 };

                    let pool_pct = if pool_capacity > 0 {
                        (cached_pool_len as f64 / pool_capacity as f64) * 100.0
                    } else { 0.0 };

                    let total_actions = crucible_test_context::TOTAL_ACTIONS_DISPATCHED.load(std::sync::atomic::Ordering::Relaxed);
                    let total_ok = crucible_test_context::TOTAL_ACTIONS_SUCCEEDED.load(std::sync::atomic::Ordering::Relaxed);
                    let ok_pct = if total_actions > 0 { (total_ok as f64 / total_actions as f64) * 100.0 } else { 0.0 };

                    // Count discovered variants from shared bitmap
                    let discovered = shared_discovered.iter().filter(|b| b.load(Ordering::Relaxed) != 0).count();
                    let total_variants = crucible_test_context::TOTAL_ACTION_VARIANTS
                        .load(std::sync::atomic::Ordering::Relaxed);

                    let elapsed_total = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                        .saturating_sub(start_time);
                    let mins = elapsed_total / 60;
                    let secs = elapsed_total % 60;
                    let __memory_kib = {
                        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
                        if cfg!(target_os = "macos") { (usage.ru_maxrss / 1024) as u64 } else { usage.ru_maxrss as u64 }
                    };
                    let __show_stats = std::env::var("FUZZ_STATS").is_ok();
                    let __mem_suffix = if __show_stats { format!(", memory_kib: {}", __memory_kib) } else { String::new() };
                    eprintln!(
                        "[FUZZ_PULSE] [{:02}:{:02}] iter: {}, iter/sec: {:.0}, pool: {}/{}k ({:.1}%), \
                         crashes: {}, ok: {}/{} ({:.1}%), discovered: {}/{} actions, edges: {}/{} ({:.1}%), branches: {}/{}, workers: {}{}",
                        mins, secs,
                        total_iters, iter_sec,
                        cached_pool_len, pool_capacity / 1024, pool_pct,
                        total_crashes,
                        total_ok, total_actions, ok_pct,
                        discovered, total_variants,
                        edges, total_edges, edge_pct,
                        branches, total_branches,
                        num_cores,
                        __mem_suffix,
                    );

                    if __profiled_iters > 0 && __show_stats {
                        let total = __phase_total_ns;
                        let n = __profiled_iters;
                        let pct = |ns: u64| -> f64 { if total > 0 { (ns as f64 / total as f64) * 100.0 } else { 0.0 } };
                        let avg = |ns: u64| -> u64 { ns / n / 1000 }; // avg µs per iter
                        let other_ns = total.saturating_sub(
                            __phase_pick_ns + __phase_restore_ns + __phase_action_gen_ns
                            + __phase_clone_ns + __phase_svm_exec_ns + __phase_coverage_ns + __phase_field_novelty_ns
                            + __phase_fingerprint_ns + __phase_save_ns
                            + __phase_crash_ns + __phase_cleanup_ns
                        );
                        let avg_us = total / n / 1000;
                        eprintln!(
                            "[PROFILE] pick: {:.1}% ({}µs) | restore: {:.1}% ({}µs) | gen: {:.1}% ({}µs) | \
                             clone: {:.1}% ({}µs) | exec: {:.1}% ({}µs) | cov: {:.1}% ({}µs) | field: {:.1}% ({}µs) | \
                             fp: {:.1}% ({}µs) | save: {:.1}% ({}µs) | \
                             crash: {:.1}% ({}µs) | cleanup: {:.1}% ({}µs) | other: {:.1}% ({}µs) — avg: {}µs/iter",
                            pct(__phase_pick_ns), avg(__phase_pick_ns),
                            pct(__phase_restore_ns), avg(__phase_restore_ns),
                            pct(__phase_action_gen_ns), avg(__phase_action_gen_ns),
                            pct(__phase_clone_ns), avg(__phase_clone_ns),
                            pct(__phase_svm_exec_ns), avg(__phase_svm_exec_ns),
                            pct(__phase_coverage_ns), avg(__phase_coverage_ns),
                            pct(__phase_field_novelty_ns), avg(__phase_field_novelty_ns),
                            pct(__phase_fingerprint_ns), avg(__phase_fingerprint_ns),
                            pct(__phase_save_ns), avg(__phase_save_ns),
                            pct(__phase_crash_ns), avg(__phase_crash_ns),
                            pct(__phase_cleanup_ns), avg(__phase_cleanup_ns),
                            pct(other_ns), avg(other_ns),
                            avg_us,
                        );
                        // pick breakdown
                        if __phase_pick_ns > 0 {
                            let ppct = |ns: u64| -> f64 { (ns as f64 / __phase_pick_ns as f64) * 100.0 };
                            let pick_other = __phase_pick_ns.saturating_sub(__phase_pick_flush_ns + __phase_pick_batch_ns + __phase_pick_crossover_ns + __phase_pick_splice_ns);
                            eprintln!(
                                "[PICK]    flush: {:.1}% ({}µs) | batch: {:.1}% ({}µs) | crossover: {:.1}% ({}µs) | splice: {:.1}% ({}µs) | other: {:.1}% ({}µs)",
                                ppct(__phase_pick_flush_ns), avg(__phase_pick_flush_ns),
                                ppct(__phase_pick_batch_ns), avg(__phase_pick_batch_ns),
                                ppct(__phase_pick_crossover_ns), avg(__phase_pick_crossover_ns),
                                ppct(__phase_pick_splice_ns), avg(__phase_pick_splice_ns),
                                ppct(pick_other), avg(pick_other),
                            );
                        }
                        __phase_pick_flush_ns = 0;
                        __phase_pick_batch_ns = 0;
                        __phase_pick_crossover_ns = 0;
                        __phase_pick_splice_ns = 0;
                        // exec breakdown: tx_pre (dirty), tx_svm (litesvm), tx_post (outcome), dispatch overhead
                        let tx_total = __phase_tx_pre_ns + __phase_tx_svm_ns + __phase_tx_post_ns;
                        let dispatch_ns = __phase_svm_exec_ns.saturating_sub(tx_total);
                        let epct = |ns: u64| -> f64 { if __phase_svm_exec_ns > 0 { (ns as f64 / __phase_svm_exec_ns as f64) * 100.0 } else { 0.0 } };
                        eprintln!(
                            "[EXEC]    tx_pre: {:.1}% ({}µs) | tx_svm: {:.1}% ({}µs) [blockhash: {}µs, sign: {}µs, exec: {}µs] | tx_post: {:.1}% ({}µs) | dispatch: {:.1}% ({}µs)",
                            epct(__phase_tx_pre_ns), avg(__phase_tx_pre_ns),
                            epct(__phase_tx_svm_ns), avg(__phase_tx_svm_ns),
                            avg(__phase_tx_blockhash_ns), avg(__phase_tx_sign_ns), avg(__phase_tx_exec_ns),
                            epct(__phase_tx_post_ns), avg(__phase_tx_post_ns),
                            epct(dispatch_ns), avg(dispatch_ns),
                        );
                        __phase_pick_ns = 0;
                        __phase_restore_ns = 0;
                        __phase_action_gen_ns = 0;
                        __phase_clone_ns = 0;
                        __phase_svm_exec_ns = 0;
                        __phase_tx_pre_ns = 0;
                        __phase_tx_svm_ns = 0;
                        __phase_tx_post_ns = 0;
                        __phase_tx_blockhash_ns = 0;
                        __phase_tx_sign_ns = 0;
                        __phase_tx_exec_ns = 0;
                        __phase_coverage_ns = 0;
                        __phase_field_novelty_ns = 0;
                        __phase_fingerprint_ns = 0;
                        __phase_save_ns = 0;
                        __phase_crash_ns = 0;
                        __phase_cleanup_ns = 0;
                        __phase_total_ns = 0;
                        __profiled_iters = 0;
                    }

                    if std::env::var("FUZZ_STATS").is_ok() {
                        let __mem_pool = state_pool.read().unwrap();
                        let __mem_stats = __mem_pool.memory_stats();
                        // Current RSS (resident set size) on macOS via task_info
                        let __rss_mb = {
                            #[cfg(target_os = "macos")]
                            {
                                let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
                                let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
                                    / std::mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
                                let kr = unsafe {
                                    libc::task_info(
                                        libc::mach_task_self(),
                                        libc::MACH_TASK_BASIC_INFO,
                                        &mut info as *mut _ as libc::task_info_t,
                                        &mut count,
                                    )
                                };
                                if kr == libc::KERN_SUCCESS {
                                    info.resident_size as f64 / 1_048_576.0
                                } else {
                                    __memory_kib as f64 / 1024.0 // fallback to maxrss
                                }
                            }
                            #[cfg(not(target_os = "macos"))]
                            {
                                // On Linux, read /proc/self/statm
                                if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
                                    let rss_pages = statm.split_whitespace().nth(1)
                                        .and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                                    (rss_pages * 4096) as f64 / 1_048_576.0
                                } else {
                                    __memory_kib as f64 / 1024.0
                                }
                            }
                        };
                        eprintln!(
                            "[MEMORY]  rss: {:.0}MB (peak: {:.0}MB) | {}",
                            __rss_mb,
                            __memory_kib as f64 / 1024.0,
                            __mem_stats.format_breakdown(),
                        );
                    } // FUZZ_STATS

                    last_print_time = now;
                    last_print_iters = total_iters;
                }
            }

            // Worker 0 exiting — clean up all Rc-bearing locals under mutex.
            // Must happen BEFORE scope exit (which implicitly drops w0_fixture),
            // and BEFORE joining workers (which may still be doing Rc ops).
            {
                let _guard = fixture_clone_mutex.lock().unwrap();
                w0_fixture_batch.clear();
                w0_pending_drops.clear();
            }

            // Signal + join workers INSIDE Worker 0's scope, so workers are
            // fully stopped before w0_fixture (last Rc holder) is dropped.
            stop.store(true, Ordering::Relaxed);
            for handle in worker_handles.drain(..) {
                let _ = handle.join();
            }
            // All workers exited. w0_fixture is the last Rc holder. Safe to drop.
        }

        if #mod_name::COVERAGE_ENABLED.load(Ordering::Relaxed) {
            #mod_name::write_lcov_coverage("coverage.lcov");
        }

        if let Some(ref __corpus_out_path) = corpus_out_dir {
            let pool = state_pool.read().unwrap();
            match pool.export_corpus(__corpus_out_path, corpus_in_dir.as_deref()) {
                Ok(n) => eprintln!("[STATEFUL] Saved {} corpus entries to {}", n, __corpus_out_path),
                Err(e) => eprintln!("[STATEFUL] Failed to save corpus: {}", e),
            }
        }

        let total_iters = shared_iters.load(Ordering::Relaxed);
        let total_novel = shared_novel.load(Ordering::Relaxed);
        let total_crashes = shared_crashes.load(Ordering::Relaxed);
        let pool_len = state_pool.read().unwrap().len();
        eprintln!("\n[STATEFUL] Final stats: {} iterations, {} novel states, {} crashes, pool: {}",
            total_iters, total_novel, total_crashes, pool_len);
        std::process::exit(0);
    }
}

// =============================================================================
// Tests — Verify structural properties of generated code.
//
// These tests call the stateful codegen functions with dummy inputs and verify
// that the generated TokenStream contains the expected patterns. They serve as
// regression guards: if the P1 refactoring accidentally changes or drops a
// code pattern, these tests will catch it.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use quote::format_ident;

    /// Helper: convert TokenStream to string for pattern matching.
    fn ts(tokens: proc_macro2::TokenStream) -> String {
        tokens.to_string()
    }

    /// Helper: generate singlecore body with default params.
    fn gen_singlecore() -> String {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture_name = format_ident!("TestFixture");
        let fn_name = format_ident!("invariant_check");
        let fixture_param = format_ident!("fixture");
        let action_ty = quote::quote! { Actions };
        let contexts = vec![format_ident!("ctx")];
        ts(stateful_singlecore_body(
            &mod_name,
            &fixture_name,
            &fn_name,
            &fixture_param,
            "test_feature",
            &action_ty,
            &contexts,
        ))
    }

    /// Helper: generate multicore body with default params.
    fn gen_multicore() -> String {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture_name = format_ident!("TestFixture");
        let fn_name = format_ident!("invariant_check");
        let fixture_param = format_ident!("fixture");
        let action_ty = quote::quote! { Actions };
        let contexts = vec![format_ident!("ctx")];
        ts(stateful_multicore_body(
            &mod_name,
            &fixture_name,
            &fn_name,
            &fixture_param,
            "test_feature",
            &action_ty,
            &contexts,
        ))
    }

    // ── Action generation (must be identical across all 3 bodies) ───────

    #[test]
    fn singlecore_has_adaptive_chain_length() {
        let output = gen_singlecore();
        // Adaptive chain length based on pool fill ratio
        assert!(
            output.contains("pool_fill"),
            "should compute pool fill ratio"
        );
        assert!(
            output.contains("0.05"),
            "should have bootstrap threshold (<5%)"
        );
        assert!(
            output.contains("0.25"),
            "should have early threshold (<25%)"
        );
        assert!(output.contains("0.6"), "should have mid threshold (<60%)");
    }

    #[test]
    fn multicore_has_adaptive_chain_length() {
        let output = gen_multicore();
        assert!(
            output.contains("pool_fill"),
            "should compute pool fill ratio"
        );
        assert!(
            output.contains("0.05"),
            "should have bootstrap threshold (<5%)"
        );
        assert!(
            output.contains("0.25"),
            "should have early threshold (<25%)"
        );
        assert!(output.contains("0.6"), "should have mid threshold (<60%)");
    }

    #[test]
    fn singlecore_has_crossover_replay() {
        let output = gen_singlecore();
        // 35% crossover exact replay
        assert!(
            output.contains("crossover_buf"),
            "should use crossover buffer"
        );
        assert!(
            output.contains("deserialize_fields"),
            "should deserialize crossover fields"
        );
        assert!(
            output.contains("random_variant"),
            "should have random variant fallback"
        );
    }

    #[test]
    fn multicore_has_crossover_replay() {
        let output = gen_multicore();
        assert!(
            output.contains("crossover_buf"),
            "should use crossover buffer"
        );
        assert!(
            output.contains("deserialize_fields"),
            "should deserialize crossover fields"
        );
    }

    #[test]
    fn singlecore_has_guided_variant_selection() {
        let output = gen_singlecore();
        assert!(
            output.contains("action_stats . pick_variant"),
            "should use epsilon-greedy action stats"
        );
    }

    #[test]
    fn multicore_has_guided_variant_selection() {
        let output = gen_multicore();
        assert!(
            output.contains("action_stats . pick_variant"),
            "should use epsilon-greedy action stats"
        );
    }

    // ── Post-execution truncation ───────────────────────────────────────

    #[test]
    fn singlecore_truncates_unexecuted_actions() {
        let output = gen_singlecore();
        assert!(
            output.contains("__actually_executed"),
            "should track actually executed count"
        );
        assert!(
            output.contains("__action_byte_offsets"),
            "should track byte offsets per action"
        );
        assert!(
            output.contains("truncate"),
            "should truncate __single_action_buf"
        );
    }

    #[test]
    fn multicore_truncates_unexecuted_actions() {
        let output = gen_multicore();
        assert!(
            output.contains("__actually_executed"),
            "should track actually executed count"
        );
        assert!(
            output.contains("__action_byte_offsets"),
            "should track byte offsets per action"
        );
        assert!(
            output.contains("truncate"),
            "should truncate __single_action_buf"
        );
    }

    // ── Coverage check (virgin map scan + field novelty) ────────────────

    #[test]
    fn singlecore_has_virgin_map_scan() {
        let output = gen_singlecore();
        assert!(
            output.contains("__virgin_map"),
            "should maintain virgin map"
        );
        assert!(
            output.contains("to_bucket"),
            "should use hitcount bucketing"
        );
        assert!(
            output.contains("__edge_novel_bits"),
            "should track edge novelty bits"
        );
    }

    #[test]
    fn multicore_has_coverage_tracking() {
        let output = gen_multicore();
        // Multicore uses shared bitmap flush instead of virgin map
        assert!(
            output.contains("flush_local_bitmap_buffers"),
            "should flush to shared bitmaps"
        );
        assert!(
            output.contains("new_coverage_count"),
            "should check new coverage count"
        );
    }

    #[test]
    fn singlecore_has_field_novelty() {
        let output = gen_singlecore();
        assert!(
            output.contains("fingerprint_and_collect_changed"),
            "should use combined fingerprint+novelty pass"
        );
        assert!(
            output.contains("__field_novel_bits"),
            "should track field novelty bits"
        );
    }

    #[test]
    fn multicore_has_field_novelty() {
        let output = gen_multicore();
        assert!(
            output.contains("fingerprint_and_collect_changed"),
            "should use combined fingerprint+novelty pass"
        );
    }

    // ── Fingerprint + dedup ─────────────────────────────────────────────

    #[test]
    fn singlecore_has_fingerprint_computation() {
        let output = gen_singlecore();
        assert!(
            output.contains("compute_state_fingerprint_from_snapshot"),
            "should compute fingerprint from SVM state"
        );
        assert!(
            output.contains("dirty_tracker . dirty_accounts () . is_empty"),
            "should detect clock-only changes"
        );
        assert!(
            output.contains("0x517cc1b727220a95"),
            "should XOR with parent fingerprint for clock-only"
        );
    }

    #[test]
    fn multicore_has_fingerprint_computation() {
        let output = gen_multicore();
        assert!(
            output.contains("compute_state_fingerprint_from_snapshot"),
            "should compute fingerprint from SVM state"
        );
        assert!(
            output.contains("0x517cc1b727220a95"),
            "should XOR with parent fingerprint for clock-only"
        );
    }

    #[test]
    fn singlecore_has_edge_novel_dedup_bypass() {
        let output = gen_singlecore();
        // When edge_novel_bits > 0, fingerprint is made unique to bypass dedup
        assert!(
            output.contains("0x9e3779b97f4a7c15"),
            "should use golden ratio constant for dedup bypass"
        );
    }

    #[test]
    fn multicore_has_edge_novel_dedup_bypass() {
        let output = gen_multicore();
        assert!(
            output.contains("0x9e3779b97f4a7c15"),
            "should use golden ratio constant for dedup bypass"
        );
    }

    // ── Delta + pool save ───────────────────────────────────────────────

    #[test]
    fn singlecore_saves_to_pool() {
        let output = gen_singlecore();
        assert!(
            output.contains("child_delta"),
            "should create child delta inheriting parent patches"
        );
        assert!(output.contains("try_add"), "should call pool.try_add()");
        assert!(
            output.contains("accumulated_bytes"),
            "should build accumulated action bytes"
        );
        assert!(
            output.contains("write_corpus_entry"),
            "should write corpus incrementally"
        );
    }

    #[test]
    fn multicore_saves_to_pool() {
        let output = gen_multicore();
        assert!(
            output.contains("child_delta"),
            "should create child delta inheriting parent patches"
        );
        // Multicore uses pending_novel vector, flushed via try_add in batch
        assert!(
            output.contains("pending_novel"),
            "should defer saves to batch"
        );
        assert!(output.contains("try_add"), "should flush via try_add");
        assert!(
            output.contains("write_corpus_entry"),
            "should write corpus incrementally"
        );
    }

    #[test]
    fn singlecore_validates_ghost_actions() {
        let output = gen_singlecore();
        assert!(
            output.contains("rebuild_action_bytes_clean"),
            "should strip ghost actions from inherited parent bytes"
        );
    }

    #[test]
    fn multicore_validates_ghost_actions() {
        let output = gen_multicore();
        assert!(
            output.contains("rebuild_action_bytes_clean"),
            "should strip ghost actions from inherited parent bytes"
        );
    }

    // ── Crash handling ──────────────────────────────────────────────────

    #[test]
    fn singlecore_writes_crash_metadata() {
        let output = gen_singlecore();
        assert!(
            output.contains("take_violation"),
            "should check for violations"
        );
        assert!(
            output.contains("FUZZ_FINDING"),
            "should print finding marker"
        );
        assert!(
            output.contains("write_crash_metadata_with_actions"),
            "should write crash metadata"
        );
        assert!(
            output.contains("record_violation"),
            "should record violation against state"
        );
    }

    #[test]
    fn multicore_writes_crash_metadata() {
        let output = gen_multicore();
        assert!(
            output.contains("take_violation"),
            "should check for violations"
        );
        assert!(
            output.contains("FUZZ_FINDING"),
            "should print finding marker"
        );
        assert!(
            output.contains("write_crash_metadata_with_actions"),
            "should write crash metadata"
        );
        // Multicore uses pending_violations + pending_crashes
        assert!(
            output.contains("pending_violations"),
            "should defer violations to batch"
        );
        assert!(
            output.contains("pending_crashes"),
            "should defer crashes to batch"
        );
    }

    // ── Divergent tracking ──────────────────────────────────────────────

    #[test]
    fn singlecore_tracks_divergent_keys() {
        let output = gen_singlecore();
        assert!(
            output.contains("divergent_keys"),
            "should track divergent accounts"
        );
        assert!(
            output.contains("prev_delta_arc"),
            "should track previous delta for optimization"
        );
        assert!(
            output.contains("prev_exec_dirty"),
            "should track previous execution's dirty accounts"
        );
    }

    #[test]
    fn multicore_tracks_divergent_keys() {
        let output = gen_multicore();
        assert!(
            output.contains("divergent_keys"),
            "should track divergent accounts"
        );
        assert!(
            output.contains("prev_delta_arc"),
            "should track previous delta"
        );
        assert!(
            output.contains("prev_exec_dirty"),
            "should track previous execution's dirty accounts"
        );
    }

    // ── Selective restore (dual-SVM) ────────────────────────────────────

    #[test]
    fn singlecore_has_dual_svm_restore() {
        let output = gen_singlecore();
        assert!(
            output.contains("is_traced_iter"),
            "should detect traced iterations"
        );
        assert!(
            output.contains("restore_selective"),
            "should use selective restore"
        );
        assert!(
            output.contains("restore_selective_from"),
            "should use delta-to-delta restore"
        );
        assert!(
            output.contains("traced_divergent"),
            "should track traced SVM divergent keys"
        );
    }

    #[test]
    fn multicore_has_dual_svm_restore() {
        let output = gen_multicore();
        assert!(
            output.contains("is_traced_iter"),
            "should detect traced iterations"
        );
        assert!(
            output.contains("restore_selective"),
            "should use selective restore"
        );
        assert!(
            output.contains("restore_selective_from"),
            "should use delta-to-delta restore"
        );
    }

    // ── Splice ──────────────────────────────────────────────────────────

    #[test]
    fn singlecore_has_subsequence_splice() {
        let output = gen_singlecore();
        assert!(
            output.contains("splice_chain"),
            "should support splice chains"
        );
        assert!(
            output.contains("splice_roll"),
            "should roll for splice probability"
        );
        assert!(
            output.contains("reconstruct_variant_field_sequence"),
            "should reconstruct donor sequence for splice"
        );
    }

    #[test]
    fn multicore_has_subsequence_splice() {
        let output = gen_multicore();
        assert!(
            output.contains("splice_chain"),
            "should support splice chains"
        );
        assert!(
            output.contains("splice_roll"),
            "should roll for splice probability"
        );
    }

    // ── Corpus seeding ──────────────────────────────────────────────────

    #[test]
    fn singlecore_has_corpus_seeding() {
        let output = gen_singlecore();
        assert!(
            output.contains("corpus_in_dir"),
            "should check for corpus-in"
        );
        assert!(output.contains("seed_files"), "should collect seed files");
        assert!(output.contains("FuzzInput"), "should parse seed inputs");
        assert!(
            output.contains("mark_seed_boundary"),
            "should mark seed boundary"
        );
    }

    #[test]
    fn multicore_has_corpus_seeding() {
        let output = gen_multicore();
        assert!(
            output.contains("corpus_in_dir"),
            "should check for corpus-in"
        );
        assert!(output.contains("seed_files"), "should collect seed files");
        assert!(output.contains("FuzzInput"), "should parse seed inputs");
        assert!(
            output.contains("mark_seed_boundary"),
            "should mark seed boundary"
        );
    }

    // ── Batch picking ───────────────────────────────────────────────────

    #[test]
    fn singlecore_has_batched_picks() {
        let output = gen_singlecore();
        assert!(output.contains("pick_batch"), "should use batched picking");
        assert!(
            output.contains("build_weight_distribution"),
            "should build weight distribution"
        );
        assert!(
            output.contains("pick_weighted_batch"),
            "should use weighted batch picking"
        );
    }

    #[test]
    fn multicore_has_batched_picks() {
        let output = gen_multicore();
        assert!(
            output.contains("local_batch"),
            "should use local batch for workers"
        );
        assert!(
            output.contains("build_weight_distribution"),
            "should build weight distribution"
        );
        assert!(
            output.contains("pick_weighted_batch"),
            "should use weighted batch picking"
        );
    }

    // ── D1: Crash bytes reconstruction (3 copies) ────────────────────────
    // Verifies the crash bytes rebuild pattern is present in all 3 bodies.
    // After extraction to gen_crash_bytes(), the same patterns must appear.

    #[test]
    fn singlecore_crash_bytes_has_reconstruct_and_extend() {
        let output = gen_singlecore();
        assert!(output.contains("crash_bytes"), "should build crash_bytes");
        assert!(
            output.contains("reconstruct_action_sequence"),
            "singlecore should reconstruct full sequence from pool"
        );
        assert!(
            output.contains("rebuild_action_bytes_clean"),
            "should strip ghost actions via rebuild"
        );
        assert!(
            output.contains("extend_from_slice (& __single_action_buf)")
                || output.contains("extend_from_slice"),
            "should extend crash_bytes with current chain"
        );
    }

    #[test]
    fn multicore_worker_crash_bytes_has_clone_and_rebuild() {
        let output = gen_multicore();
        // Worker uses parent_action_bytes clone + try_read fallback
        assert!(output.contains("crash_bytes"), "should build crash_bytes");
        assert!(
            output.contains("rebuild_action_bytes_clean"),
            "should strip ghost actions via rebuild"
        );
        // Worker should have graceful lock handling
        assert!(
            output.contains("pending_crashes"),
            "worker defers crashes to pending list"
        );
    }

    #[test]
    fn multicore_w0_crash_bytes_has_rebuild() {
        let output = gen_multicore();
        // W0 also builds crash_bytes
        // Count occurrences of rebuild_action_bytes_clean — should appear in both worker and W0
        let rebuild_count = output.matches("rebuild_action_bytes_clean").count();
        assert!(
            rebuild_count >= 2,
            "should have rebuild_action_bytes_clean in both worker and W0, found {}",
            rebuild_count
        );
    }

    // ── D2: Accumulated bytes for pool save (3 copies) ─────────────────
    // Verifies the accumulated bytes pattern with ghost-stripping validation.

    #[test]
    fn singlecore_accumulated_bytes_validates_count() {
        let output = gen_singlecore();
        assert!(
            output.contains("accumulated_bytes"),
            "should build accumulated_bytes"
        );
        // Should validate stored count matches parent depth
        assert!(
            output.contains("stored_count") && output.contains("parent_depth"),
            "should validate stored count vs parent depth"
        );
        assert!(
            output.contains("from_le_bytes") && output.contains("accumulated_bytes"),
            "should parse count from accumulated bytes header"
        );
    }

    #[test]
    fn multicore_worker_accumulated_bytes_validates_count() {
        let output = gen_multicore();
        assert!(
            output.contains("accumulated_bytes"),
            "should build accumulated_bytes"
        );
        // Worker path should also validate
        let stored_count_refs = output.matches("stored_count").count();
        assert!(
            stored_count_refs >= 2,
            "should reference stored_count in both crash and save paths, found {}",
            stored_count_refs
        );
    }

    // ── D3: current_descs construction (5 copies) ──────────────────────

    #[test]
    fn singlecore_builds_current_descs_from_chain() {
        let output = gen_singlecore();
        assert!(
            output.contains("current_descs"),
            "should build current_descs"
        );
        assert!(
            output.contains("chain_descs"),
            "should iterate over __chain_descs"
        );
        // Pattern: map chain descs with history status
        assert!(
            output.contains("OK") && output.contains("FAIL"),
            "should annotate with OK/FAIL status"
        );
    }

    #[test]
    fn multicore_builds_current_descs_from_chain() {
        let output = gen_multicore();
        assert!(
            output.contains("current_descs"),
            "should build current_descs"
        );
        assert!(
            output.contains("chain_descs"),
            "should iterate over __chain_descs"
        );
        assert!(
            output.contains("OK") && output.contains("FAIL"),
            "should annotate with OK/FAIL status"
        );
    }

    // ── D4: Field bytes extraction (3 copies) ──────────────────────────

    #[test]
    fn singlecore_extracts_field_bytes() {
        let output = gen_singlecore();
        assert!(
            output.contains("field_byte_count"),
            "should call field_byte_count"
        );
        assert!(
            output.contains("__last_action_start"),
            "should compute last action start offset"
        );
        assert!(
            output.contains("__field_bytes") || output.contains("__fbc"),
            "should extract field bytes for crossover"
        );
    }

    #[test]
    fn multicore_extracts_field_bytes() {
        let output = gen_multicore();
        assert!(
            output.contains("field_byte_count"),
            "should call field_byte_count"
        );
        assert!(
            output.contains("__last_action_start"),
            "should compute last action start offset"
        );
        // Should appear in both worker and W0
        let fbc_count = output.matches("field_byte_count").count();
        assert!(
            fbc_count >= 2,
            "should call field_byte_count in both worker and W0, found {}",
            fbc_count
        );
    }

    // ── D5: Action desc string for pool save (3 copies) ────────────────

    #[test]
    fn singlecore_builds_action_desc_with_status() {
        let output = gen_singlecore();
        // Action desc for pool save joins with \n
        assert!(
            output.contains("action_desc"),
            "should build action_desc for pool save"
        );
        assert!(
            output.contains("get_action_history"),
            "should read action history for status"
        );
    }

    #[test]
    fn multicore_builds_action_desc_with_status() {
        let output = gen_multicore();
        assert!(
            output.contains("action_desc"),
            "should build action_desc for pool save"
        );
        // Should appear in both worker and W0 pool save paths
        let desc_count = output.matches("action_desc").count();
        assert!(
            desc_count >= 2,
            "should build action_desc in both worker and W0, found {}",
            desc_count
        );
    }

    // ── B1: W0 lock safety ─────────────────────────────────────────────
    // After fix, W0 should use try_read() like worker does.

    #[test]
    fn multicore_worker_uses_safe_pool_read_for_crash() {
        let output = gen_multicore();
        // Worker crash path uses try_read or read() gracefully
        // (verifying the pattern exists — after B1 fix, W0 will match)
        assert!(
            output.contains("rebuild_action_bytes_clean"),
            "should have crash byte rebuild in worker path"
        );
    }

    // ── B2: Redundant cast ─────────────────────────────────────────────

    #[test]
    fn multicore_worker_has_stored_count_comparison() {
        let output = gen_multicore();
        // Worker compares stored_count to parent_depth
        assert!(
            output.contains("stored_count"),
            "should have stored_count variable"
        );
        assert!(
            output.contains("parent_depth"),
            "should compare with parent_depth"
        );
    }

    // ── Crash output printing (3 copies) ───────────────────────────────

    #[test]
    fn singlecore_prints_crash_sequence() {
        let output = gen_singlecore();
        assert!(
            output.contains("CRASH SEQUENCE"),
            "should print crash sequence header"
        );
        assert!(output.contains("VIOLATION"), "should mark violation action");
        assert!(
            output.contains("parse_action_desc"),
            "should parse action descs for metadata"
        );
    }

    #[test]
    fn multicore_prints_crash_sequence() {
        let output = gen_multicore();
        assert!(
            output.contains("CRASH SEQUENCE"),
            "should print crash sequence header"
        );
        assert!(output.contains("VIOLATION"), "should mark violation action");
        assert!(
            output.contains("parse_action_desc"),
            "should parse action descs for metadata"
        );
    }

    // ── Variant hash for crash dedup ───────────────────────────────────

    #[test]
    fn singlecore_dedup_crashes_by_variant_hash() {
        let output = gen_singlecore();
        assert!(
            output.contains("is_novel_crash"),
            "should check crash novelty by variant hash"
        );
        assert!(
            output.contains("reconstruct_variant_sequence"),
            "should reconstruct variant sequence for hashing"
        );
    }

    #[test]
    fn multicore_dedup_crashes_by_variant_hash() {
        let output = gen_multicore();
        assert!(
            output.contains("is_novel_crash"),
            "should check crash novelty by variant hash"
        );
        assert!(
            output.contains("reconstruct_variant_sequence"),
            "should reconstruct variant sequence for hashing"
        );
    }

    // ── No burst mode (removed in cleanup) ──────────────────────────────

    #[test]
    fn singlecore_no_burst_mode() {
        let output = gen_singlecore();
        assert!(
            !output.contains("burst_mode"),
            "burst mode should be removed"
        );
    }

    #[test]
    fn multicore_no_burst_mode() {
        let output = gen_multicore();
        assert!(
            !output.contains("burst_mode"),
            "burst mode should be removed"
        );
    }

    // ── Barren pick tracking ────────────────────────────────────────────

    #[test]
    fn singlecore_records_barren_picks() {
        let output = gen_singlecore();
        assert!(
            output.contains("record_barren_pick"),
            "should record barren picks for weight decay"
        );
    }

    #[test]
    fn multicore_records_barren_picks() {
        let output = gen_multicore();
        assert!(
            output.contains("pending_barren") || output.contains("record_barren_pick"),
            "should track barren picks"
        );
    }

    // ── Action stats ────────────────────────────────────────────────────

    #[test]
    fn singlecore_has_action_stats() {
        let output = gen_singlecore();
        assert!(
            output.contains("ActionStatsMap"),
            "should create action stats tracker"
        );
        assert!(
            output.contains("action_stats . record"),
            "should record action outcomes"
        );
    }

    #[test]
    fn multicore_has_action_stats() {
        let output = gen_multicore();
        assert!(
            output.contains("ActionStatsMap"),
            "should create per-worker action stats"
        );
        assert!(
            output.contains("action_stats . record"),
            "should record action outcomes"
        );
    }
}
