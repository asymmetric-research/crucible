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

    let singlecore_body = stateful_singlecore_body(
        mod_name, fixture_name, fn_name, fixture_param_name, feature_name, action_ty,
    );
    let multicore_body = stateful_multicore_body(
        mod_name, fixture_name, fn_name, fixture_param_name, feature_name, action_ty,
    );

    quote! {
        // === STATEFUL FUZZING MODE (ItyFuzz-style) ===
        if std::env::var("FUZZ_STATEFUL").is_ok() {
            use crucible_test_context::snapshot::{
                StatePool, SvmSnapshot, compute_state_fingerprint_from_snapshot,
            };
            use libafl_bolts::rands::{Rand, StdRand};

            eprintln!("[STATEFUL] ItyFuzz-style stateful fuzzing mode");

            // Parse pool capacity from env or default to 100_000
            let pool_capacity: usize = std::env::var("FUZZ_STATE_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000);

            // Parse max depth from env or default to 15
            let max_depth: u32 = std::env::var("FUZZ_MAX_DEPTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(15);

            // Use seed from env var if provided, otherwise use current time
            let seed = std::env::var("FUZZ_SEED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| libafl_bolts::current_nanos().max(1));

            let timeout_secs: Option<u64> = std::env::var("FUZZ_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok());

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
                std::env::var("FUZZ_TRACE_INTERVAL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1)
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

            // Coverage map for FuzzCallback (display only, not driving exploration)
            let mut __stateful_coverage_map = vec![0u8; #mod_name::MAP_SIZE];
            let __stateful_cov_ptr = __stateful_coverage_map.as_mut_ptr();

            // Setup fixture (always with tracing initially for coverage baseline)
            #template_setup_code

            // Take snapshot of initial state
            #[allow(unused_mut)]
            let mut template_fixture = template_fixture;
            template_fixture.ctx.take_snapshot();

            let base_snapshot = template_fixture.ctx.snapshot.as_ref()
                .expect("snapshot must exist after take_snapshot()")
                .clone();

            // SVM swap trick (same as singlecore): move real SVM out of template
            let mut __real_svm = std::mem::replace(
                &mut template_fixture.ctx.svm,
                litesvm::LiteSVM::new(),
            );

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
            let mut __traced_svm: Option<litesvm::LiteSVM> = if trace_interval != 1 {
                // Keep the traced SVM for periodic coverage collection
                Some(__real_svm.clone())
            } else {
                None
            };

            // Create fast (non-debuggable) SVM by restoring snapshot into a fresh SVM.
            // This avoids re-running setup() which would produce different keypairs/addresses.
            let __fast_svm: Option<litesvm::LiteSVM> = if trace_interval != 1 {
                std::env::remove_var("ANCHOR_FUZZ_DEBUGGABLE");
                let mut fast = litesvm::LiteSVM::new();
                initial_snapshot.restore_full(&mut fast);
                // Restore ANCHOR_FUZZ_DEBUGGABLE so traced SVM clones work correctly
                std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");
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

            let num_cores: usize = std::env::var("FUZZ_CORES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);

            if num_cores > 1 {
                #multicore_body
            } else {
                #singlecore_body
            }
        }
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
) -> proc_macro2::TokenStream {
    quote! {
        // === SINGLE-THREADED STATEFUL ===
        let mut state_pool = StatePool::new(pool_capacity, max_depth);
        // Initial pool entry: empty delta (state is identical to initial_snapshot)
        let initial_clock = initial_snapshot.clock().clone();
        state_pool.try_add(0, SvmSnapshot::empty(initial_clock), 0, None, 0u32.to_le_bytes().to_vec(), String::new(), None, Vec::new(), __initial_fixture_state.clone(), false);

        // Action success tracking: learns which actions work from which state classes
        let mut action_stats = crucible_test_context::snapshot::ActionStatsMap::new(
            <#action_ty as crucible_fuzzer::FuzzAction>::variant_count(),
        );

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
        let mut prev_delta_arc: Option<std::sync::Arc<SvmSnapshot>> = None;
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

        eprintln!("[STATEFUL] Pool capacity: {}, max depth: {}, seed: {}", pool_capacity, max_depth, seed);

        // === CORPUS-IN: Seed pool from disk ===
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

            let mut __seeded = 0u64;
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
                    SvmSnapshot::empty(initial_snapshot.clock().clone())
                );

                for __seed_action in &__fuzz_input.actions {
                    if __current_depth >= max_depth { break; }
                    if state_pool.is_full() { break; }

                    // Swap SVM into fixture
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);

                    let callback = #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE);
                    __seed_fixture.ctx.set_invocation_callback(callback);
                    crucible_test_context::clear_action_history();
                    crucible_test_context::clear_violation_tracking();
                    crucible_test_context::reset_iteration_dispatch_count();

                    let __seed_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        #fn_name(&mut __seed_fixture, vec![__seed_action.clone()]);
                    }));

                    // Check success
                    let __seed_ok = __seed_panic.is_ok() && {
                        let h = crucible_test_context::get_action_history();
                        h.first().map(|r| r.success).unwrap_or(false)
                    };

                    if !__seed_ok {
                        // Swap SVM back and stop this sequence
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

                    // Take delta from current SVM state
                    let __new_delta = SvmSnapshot::take_delta(
                        &__seed_fixture.ctx.svm, &__current_delta, &__seed_fixture.ctx.dirty_tracker,
                    );

                    // Fingerprint
                    let __fp = compute_state_fingerprint_from_snapshot(
                        &__seed_fixture.ctx.svm, &__seed_fixture.ctx.dirty_tracker,
                    );

                    __current_depth += 1;
                    let __action_desc = crucible_test_context::format_last_action_oneline();
                    let __variant = __seed_action.variant_index() as u16;
                    let __field_bytes = if __single_bytes.len() > 2 {
                        __single_bytes[2..].to_vec()
                    } else { Vec::new() };

                    // Store fixture state (swap SVM out for cheap clone)
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                    let __fs: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                        Some(std::sync::Arc::new(__FixtureWrapper(__seed_fixture.clone())));
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);

                    if __fp != 0 && state_pool.try_add(
                        __fp, __new_delta.clone(), __current_depth, __parent_idx,
                        __accum.clone(), __action_desc, Some(__variant), __field_bytes,
                        __fs, false,
                    ) {
                        __parent_idx = Some(state_pool.len() - 1);
                        __seeded += 1;
                    }

                    __current_delta = std::sync::Arc::new(__new_delta);
                    __current_action_bytes = __accum;

                    // Swap SVM back for next action (SVM stays modified = correct sequential state)
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                }
            }

            // Reset SVM to initial for the main loop
            initial_snapshot.restore_full(&mut __real_svm);
            eprintln!("[STATEFUL] Seeded {} states from {} corpus files", __seeded, __seed_files.len());
        }

        eprintln!("[STATEFUL] Starting stateful fuzzing loop...\n");

        let __do_profile = std::env::var("FUZZ_PROFILE").is_ok();
        let mut __phase_pick_ns: u64 = 0;
        let mut __phase_restore_ns: u64 = 0;
        let mut __phase_execute_ns: u64 = 0;
        let mut __phase_fingerprint_ns: u64 = 0;
        let mut __phase_save_ns: u64 = 0;
        let mut __phase_crash_ns: u64 = 0;
        let mut __phase_cleanup_ns: u64 = 0;
        let mut __phase_total_ns: u64 = 0;
        let mut __profiled_iters: u64 = 0;

        loop {
            if SIGNAL_STOP.load(std::sync::atomic::Ordering::Relaxed) { break; }
            iteration += 1;

            // Timeout check (rate-limited)
            if let Some(timeout) = timeout_secs {
                if iteration % 300 == 0 {
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
                            match state_pool.export_corpus(__corpus_out_path) {
                                Ok(n) => eprintln!("[STATEFUL] Saved {} corpus entries to {}", n, __corpus_out_path),
                                Err(e) => eprintln!("[STATEFUL] Failed to save corpus: {}", e),
                            }
                        }
                        std::process::exit(0);
                    }
                }
            }

            let __iter_start = std::time::Instant::now();

            // 1. Pick an active state using power-schedule weighting
            let __t = std::time::Instant::now();
            let state_idx = match state_pool.pick_weighted(rng.next()) {
                Some(idx) => idx,
                None => {
                    // All states crashed — nothing left to explore
                    eprintln!("[STATEFUL] All active states exhausted (all led to crashes). Stopping.");
                    break;
                }
            };
            let (parent_depth, parent_action_bytes, parent_fingerprint, parent_variant, parent_field_bytes, __picked_fixture_state) =
                state_pool.get(state_idx)
                    .map(|s| (s.depth, s.action_bytes.clone(), s.fingerprint, s.action_variant, s.action_field_bytes.clone(), s.fixture_state.clone()))
                    .unwrap_or((0, std::sync::Arc::new(0u32.to_le_bytes().to_vec()), 0, None, std::sync::Arc::new(Vec::new()), None));
            if __do_profile { __phase_pick_ns += __t.elapsed().as_nanos() as u64; }

            // 2. Selective restore with dual-SVM support.
            let __t = std::time::Instant::now();

            // Extract delta for picked state
            let delta_arc = state_pool.get(state_idx)
                .map(|entry| entry.delta.clone())
                .unwrap_or_else(|| std::sync::Arc::new(SvmSnapshot::empty(initial_snapshot.clock().clone())));

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
                initial_snapshot.restore_selective(&mut __real_svm, &traced_divergent, &delta_arc);
                traced_divergent.clear();
                traced_divergent.extend(delta_arc.accounts().keys().copied());
            } else {
                // Optimized delta-to-delta restore for fast SVM (or always-traced when trace_interval==1)
                if let Some(ref prev) = prev_delta_arc {
                    initial_snapshot.restore_selective_from(&mut __real_svm, &divergent_keys, prev, &delta_arc, &prev_exec_dirty);
                } else {
                    initial_snapshot.restore_selective(&mut __real_svm, &divergent_keys, &delta_arc);
                }
                divergent_keys.clear();
                divergent_keys.extend(delta_arc.accounts().keys().copied());
            }
            if __do_profile { __phase_restore_ns += __t.elapsed().as_nanos() as u64; }

            // 3. Generate an action using guided selection:
            //    - 10% pure random (epsilon exploration via ActionStatsMap)
            //    - If stats available: weighted by per-state-class success rates
            //    - 15% of guided picks: mutate parent's action (local parameter search)
            //    - 25% of guided picks: same variant as parent, fresh random params
            //    - 60% of guided picks: weighted variant selection from stats
            let __t = std::time::Instant::now();
            let __state_class = crucible_test_context::snapshot::state_class_from_fingerprint(parent_fingerprint);
            let __replay_roll = rng.next() % 100;
            let action = if __replay_roll < 15 && parent_variant.is_some() && !parent_field_bytes.is_empty() {
                // 15%: Mutate parent's action (same variant, perturbed params)
                let vi = parent_variant.unwrap() as usize;
                let mut cursor = 0usize;
                match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(vi, &parent_field_bytes, &mut cursor) {
                    Some(mut a) => {
                        <#action_ty as crucible_fuzzer::FuzzAction>::mutate(&mut a, &mut rng);
                        a
                    }
                    None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                }
            } else if __replay_roll < 40 && parent_variant.is_some() {
                // 25%: Same variant as parent, fresh random params
                <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(
                    parent_variant.unwrap() as usize, &mut rng,
                )
            } else {
                // 60%: Guided variant selection (epsilon-greedy from ActionStatsMap)
                match action_stats.pick_variant(__state_class, rng.next(), rng.next()) {
                    Some(vi) => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(vi, &mut rng),
                    None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                }
            };

            // Serialize the single action for storage
            let single_action_bytes = {
                let mut buf = Vec::new();
                buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                action.serialize_fields(&mut buf);
                buf
            };

            // 5. Execute the single action using the existing invariant test function
            //    Restore fixture from pool state (correct mutable fields for this state),
            //    then swap in the real SVM.
            let mut #fixture_param_name = if let Some(ref arc) = __picked_fixture_state {
                arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed").0.clone()
            } else {
                template_fixture.clone()
            };
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);

            // Set up coverage callback only when tracing is active this iteration
            if has_tracing {
                let callback = #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE);
                #fixture_param_name.ctx.set_invocation_callback(callback);
            }

            crucible_test_context::set_current_iteration(iteration);
            crucible_test_context::clear_action_history();
            crucible_test_context::clear_violation_tracking();

            // Snapshot edge count before execution for coverage-driven pool insertion
            // Only track on iterations where tracing is active
            let __edges_before = if has_tracing {
                #mod_name::TOTAL_EDGES_ATOMIC.load(std::sync::atomic::Ordering::Relaxed)
            } else { 0 };

            // Execute with a single-element action vec (reuses all invariant/dispatch/taint logic)
            crucible_test_context::reset_iteration_dispatch_count();
            let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #fn_name(&mut #fixture_param_name, vec![action.clone()]);
            }));
            let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();
            if __do_profile { __phase_execute_ns += __t.elapsed().as_nanos() as u64; }

            // Check if this action produced new edge coverage
            let __new_coverage = if has_tracing {
                #mod_name::TOTAL_EDGES_ATOMIC.load(std::sync::atomic::Ordering::Relaxed) > __edges_before
            } else { false };

            // Count actual SVM executions (includes success-seeking retries)
            #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                let exec_count = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                #mod_name::maybe_write_coverage(exec_count);
            }

            // Check for violation BEFORE swapping SVM back
            let __t = std::time::Instant::now();
            let violation = crucible_test_context::take_violation();

            if let Some(ref msg) = violation {
                // Reconstruct full action sequence for crash file
                let mut crash_bytes = state_pool.reconstruct_action_sequence(state_idx);
                if crash_bytes.len() >= 4 {
                    let old_count = u32::from_le_bytes(
                        crash_bytes[0..4].try_into().unwrap()
                    );
                    crash_bytes[0..4].copy_from_slice(&(old_count + 1).to_le_bytes());
                    crash_bytes.extend_from_slice(&single_action_bytes);
                }

                // Dedup by action variant sequence (coarse: same action types = same crash class)
                let mut __variant_seq = state_pool.reconstruct_variant_sequence(state_idx);
                __variant_seq.push(action.variant_index() as u16);
                let input_hash = libafl_bolts::hash_std(
                    &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                );
                if state_pool.is_novel_crash(input_hash) {
                    crashes_found += 1;
                    eprintln!("\n[STATEFUL] VIOLATION at iteration {}: {}", iteration, msg);
                    // Print full action chain from root to violation
                    let parent_descs = state_pool.reconstruct_action_descriptions(state_idx);
                    let current_desc = crucible_test_context::format_last_action_oneline();
                    let total = parent_descs.len() + 1;
                    eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                    for (i, desc) in parent_descs.iter().enumerate() {
                        eprintln!("  {}. {}", i + 1, desc);
                    }
                    eprintln!("  {}. {} [VIOLATION]", total, current_desc);
                    eprintln!("===================================");

                    crucible_test_context::write_crash_metadata(
                        &crash_dir, input_hash, Some(seed), &crash_bytes,
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
            if __do_profile { __phase_crash_ns += __t.elapsed().as_nanos() as u64; }

            // 6. Compute fingerprint and potentially add to pool (only if no violation and no panic)
            let __action_variant_idx = action.variant_index();
            let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                let history = crucible_test_context::get_action_history();
                let succeeded = history.first().map(|r| r.success).unwrap_or(false);

                // Record success/failure in action stats for this state class
                action_stats.record(__state_class, __action_variant_idx, succeeded);

                if succeeded {
                    let __t = std::time::Instant::now();
                    let mut fingerprint = compute_state_fingerprint_from_snapshot(
                        &#fixture_param_name.ctx.svm,
                        &#fixture_param_name.ctx.dirty_tracker,
                    );
                    // Coverage-driven: if this action discovered new edges, make fingerprint
                    // unique so the state is always saved (bypasses fingerprint dedup).
                    if __new_coverage {
                        fingerprint = fingerprint
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .wrapping_add(iteration);
                    }
                    if __do_profile { __phase_fingerprint_ns += __t.elapsed().as_nanos() as u64; }

                    if fingerprint != 0 {
                        let __t = std::time::Instant::now();
                        // Create delta: clone parent delta + overlay dirty accounts
                        let new_delta = SvmSnapshot::take_delta(
                            &#fixture_param_name.ctx.svm,
                            &delta_arc,
                            &#fixture_param_name.ctx.dirty_tracker,
                        );

                        // Deep-clone parent action bytes to build accumulated sequence
                        let mut accumulated_bytes = (*parent_action_bytes).clone();
                        if accumulated_bytes.len() >= 4 {
                            let count = u32::from_le_bytes(
                                accumulated_bytes[0..4].try_into().unwrap()
                            );
                            accumulated_bytes[0..4].copy_from_slice(&(count + 1).to_le_bytes());
                            accumulated_bytes.extend_from_slice(&single_action_bytes);
                        }

                        // Extract field bytes for parent-action replay (skip 2-byte variant header)
                        let __field_bytes = if single_action_bytes.len() > 2 {
                            single_action_bytes[2..].to_vec()
                        } else {
                            Vec::new()
                        };

                        let action_desc = crucible_test_context::format_last_action_oneline();

                        // Swap SVM out before storing fixture (makes clone cheap)
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
                        let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                            Some(std::sync::Arc::new(__FixtureWrapper(#fixture_param_name.clone())));
                        // Swap SVM back in for remaining iteration logic (divergent_keys)
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);

                        if state_pool.try_add(
                            fingerprint,
                            new_delta,
                            parent_depth + 1,
                            Some(state_idx),
                            accumulated_bytes,
                            action_desc,
                            Some(__action_variant_idx as u16),
                            __field_bytes,
                            __fixture_for_storage,
                            __new_coverage,
                        ) {
                            novel_states += 1;
                        }
                        if __do_profile { __phase_save_ns += __t.elapsed().as_nanos() as u64; }
                    }
                }
                succeeded
            } else {
                // Record failure in action stats even for violations/panics
                action_stats.record(__state_class, __action_variant_idx, false);
                false
            };

            // 7. Update divergent_keys, prev_delta_arc, and prev_exec_dirty for next iteration
            let __t = std::time::Instant::now();
            if is_traced_iter {
                // Traced SVM: update its own divergent tracking
                if __action_succeeded {
                    traced_divergent.extend(#fixture_param_name.ctx.dirty_tracker.dirty_accounts().iter().copied());
                }
            } else {
                // Fast SVM (or always-traced): update delta optimization state
                prev_exec_dirty.clear();
                if __action_succeeded {
                    prev_exec_dirty.extend(#fixture_param_name.ctx.dirty_tracker.dirty_accounts().iter().copied());
                    divergent_keys.extend(prev_exec_dirty.iter().copied());
                }
                prev_delta_arc = Some(delta_arc);
            }

            // 8. Swap SVM back out of fixture
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
            // If traced iteration, swap traced SVM back to its dedicated slot
            if is_traced_iter {
                if let Some(ref mut traced) = __dual_traced_svm {
                    std::mem::swap(&mut __real_svm, traced);
                }
            }
            // fixture is dropped here
            if __do_profile { __phase_cleanup_ns += __t.elapsed().as_nanos() as u64; }

            // On panic: resume unwinding
            if let Err(__panic_payload) = __panic_result {
                std::panic::resume_unwind(__panic_payload);
            }

            // 9. Rate-limited monitor output
            if __do_profile {
                __phase_total_ns += __iter_start.elapsed().as_nanos() as u64;
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
                eprintln!(
                    "[STATEFUL] [{:02}:{:02}] iter: {}, iter/sec: {:.0}, pool: {}/{} ({:.1}%), active: {}, \
                     novel: {}, crashes: {}, ok: {}/{} ({:.1}%), discovered: {}/{} actions, edges: {}/{} ({:.1}%), branches: {}/{}",
                    mins, secs,
                    iteration, iter_sec,
                    state_pool.len(), pool_capacity, pool_pct,
                    state_pool.active_count(),
                    novel_states, crashes_found,
                    total_ok, total_actions, ok_pct,
                    discovered, total_variants,
                    edges, total_edges, edge_pct,
                    branches, total_branches,
                );

                if __do_profile && __profiled_iters > 0 {
                    let total = __phase_total_ns;
                    let pct = |ns: u64| -> f64 { if total > 0 { (ns as f64 / total as f64) * 100.0 } else { 0.0 } };
                    let other_ns = total.saturating_sub(
                        __phase_pick_ns + __phase_restore_ns + __phase_execute_ns
                        + __phase_fingerprint_ns + __phase_save_ns
                        + __phase_crash_ns + __phase_cleanup_ns
                    );
                    let avg_us = total / __profiled_iters / 1000;
                    eprintln!(
                        "[PROFILE] pick: {:.1}% | restore: {:.1}% | execute: {:.1}% | \
                         fingerprint: {:.1}% | save: {:.1}% | crash: {:.1}% | cleanup: {:.1}% | other: {:.1}% (avg: {}µs/iter)",
                        pct(__phase_pick_ns), pct(__phase_restore_ns), pct(__phase_execute_ns),
                        pct(__phase_fingerprint_ns), pct(__phase_save_ns),
                        pct(__phase_crash_ns), pct(__phase_cleanup_ns), pct(other_ns),
                        avg_us,
                    );
                    __phase_pick_ns = 0;
                    __phase_restore_ns = 0;
                    __phase_execute_ns = 0;
                    __phase_fingerprint_ns = 0;
                    __phase_save_ns = 0;
                    __phase_crash_ns = 0;
                    __phase_cleanup_ns = 0;
                    __phase_total_ns = 0;
                    __profiled_iters = 0;
                }

                last_print_time = now;
                last_print_iter = total_execs_now;
            }
        }

        // Loop exited (all active states exhausted or signal)
        if let Some(ref __corpus_out_path) = corpus_out_dir {
            match state_pool.export_corpus(__corpus_out_path) {
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
) -> proc_macro2::TokenStream {
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
        let shared_edge_addr: usize = _shared_edge_bitmap_owner.as_mut_ptr() as usize;
        let shared_branch_addr: usize = _shared_branch_bitmap_owner.as_mut_ptr() as usize;

        // Unsafe Send wrapper for ALL non-Send data: fixture (Rc<Keypair>) and
        // LiteSVM (Rc<RefCell<LogCollector>> in type params). Each worker gets
        // its own independent clone — all cloning happens sequentially on the
        // main thread before any spawn().
        // Fields: (fixture, fast_svm, Option<traced_svm>)
        struct __SendableWorkerState(#fixture_name, litesvm::LiteSVM, Option<litesvm::LiteSVM>);
        unsafe impl Send for __SendableWorkerState {}

        let state_pool = Arc::new(RwLock::new(StatePool::new(pool_capacity, max_depth)));

        // Add initial state to shared pool (empty delta = identical to initial_snapshot)
        {
            let initial_clock = initial_snapshot.clock().clone();
            let mut pool = state_pool.write().unwrap();
            pool.try_add(0, SvmSnapshot::empty(initial_clock), 0, None, 0u32.to_le_bytes().to_vec(), String::new(), None, Vec::new(), __initial_fixture_state.clone(), false);
        }

        // Shared atomics
        let shared_iters = Arc::new(AtomicU64::new(0));
        let shared_crashes = Arc::new(AtomicU64::new(0));
        let shared_novel = Arc::new(AtomicU64::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));
        // Shared discovered-variants bitmap: each byte is 0/1 for up to 256 variants.
        // Workers atomically set bytes to 1 when they discover a new variant;
        // monitor counts non-zero bytes to display "discovered: X/Y actions".
        let shared_discovered: Arc<Vec<std::sync::atomic::AtomicU8>> = Arc::new(
            (0..256).map(|_| std::sync::atomic::AtomicU8::new(0)).collect()
        );
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

        eprintln!("[STATEFUL] Pool capacity: {}, max depth: {}, seed: {}", pool_capacity, max_depth, seed);

        // === CORPUS-IN: Seed pool from disk (main thread, before workers) ===
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

            let mut __seeded = 0u64;
            let mut pool = state_pool.write().unwrap();
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
                    SvmSnapshot::empty(initial_snapshot.clock().clone())
                );

                for __seed_action in &__fuzz_input.actions {
                    if __current_depth >= max_depth { break; }
                    if pool.is_full() { break; }

                    // Swap SVM into fixture
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);

                    let callback = #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE);
                    __seed_fixture.ctx.set_invocation_callback(callback);
                    crucible_test_context::clear_action_history();
                    crucible_test_context::clear_violation_tracking();
                    crucible_test_context::reset_iteration_dispatch_count();

                    let __seed_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        #fn_name(&mut __seed_fixture, vec![__seed_action.clone()]);
                    }));

                    // Check success
                    let __seed_ok = __seed_panic.is_ok() && {
                        let h = crucible_test_context::get_action_history();
                        h.first().map(|r| r.success).unwrap_or(false)
                    };

                    if !__seed_ok {
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

                    // Take delta from current SVM state
                    let __new_delta = SvmSnapshot::take_delta(
                        &__seed_fixture.ctx.svm, &__current_delta, &__seed_fixture.ctx.dirty_tracker,
                    );

                    // Fingerprint
                    let __fp = compute_state_fingerprint_from_snapshot(
                        &__seed_fixture.ctx.svm, &__seed_fixture.ctx.dirty_tracker,
                    );

                    __current_depth += 1;
                    let __action_desc = crucible_test_context::format_last_action_oneline();
                    let __variant = __seed_action.variant_index() as u16;
                    let __field_bytes = if __single_bytes.len() > 2 {
                        __single_bytes[2..].to_vec()
                    } else { Vec::new() };

                    // Store fixture state (swap SVM out for cheap clone)
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                    let __fs: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                        Some(std::sync::Arc::new(__FixtureWrapper(__seed_fixture.clone())));
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);

                    if __fp != 0 && pool.try_add(
                        __fp, __new_delta.clone(), __current_depth, __parent_idx,
                        __accum.clone(), __action_desc, Some(__variant), __field_bytes,
                        __fs, false,
                    ) {
                        __parent_idx = Some(pool.len() - 1);
                        __seeded += 1;
                    }

                    __current_delta = std::sync::Arc::new(__new_delta);
                    __current_action_bytes = __accum;

                    // Swap SVM back for next action
                    std::mem::swap(&mut __seed_fixture.ctx.svm, &mut __real_svm);
                }
            }
            drop(pool);

            // Reset SVM to initial for workers
            initial_snapshot.restore_full(&mut __real_svm);
            eprintln!("[STATEFUL] Seeded {} states from {} corpus files", __seeded, __seed_files.len());
        }

        eprintln!("[STATEFUL] Starting multi-threaded stateful fuzzing...\n");

        // Clone fixture + SVM on the main thread for each worker.
        // All cloning is sequential here — no Rc races.
        let mut worker_handles = Vec::new();
        for worker_id in 1..num_cores {
            // Clone BEFORE spawning (sequential, safe Rc::clone)
            // Create traced SVM for this worker if dual-SVM mode is active
            let worker_traced = if trace_interval > 1 {
                // ANCHOR_FUZZ_DEBUGGABLE is set, so LiteSVM::new() creates debuggable SVM
                let mut svm = litesvm::LiteSVM::new();
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
            let fixture_clone_lock = fixture_clone_mutex.clone();
            let discovered_bitmap = shared_discovered.clone();
            let worker_seed = seed + worker_id as u64;
            let w_edge_addr = shared_edge_addr;
            let w_branch_addr = shared_branch_addr;

            let handle = std::thread::Builder::new()
                .name(format!("stateful-worker-{}", worker_id))
                .spawn(move || {
                    let shared_edge_ptr = w_edge_addr as *mut u8;
                    let shared_branch_ptr = w_branch_addr as *mut u8;
                    // Force capture of the WHOLE __SendableWorkerState value.
                    // In Rust 2021+, closures use precise field captures: `worker_state.0`
                    // would capture just the EternalFixture field (which is !Send), bypassing
                    // the `unsafe impl Send for __SendableWorkerState` wrapper. By rebinding
                    // the whole struct first, we ensure the closure captures the Send wrapper.
                    let worker_state = worker_state;
                    let mut worker_fixture = std::mem::ManuallyDrop::new(worker_state.0);
                    let mut worker_svm = std::mem::ManuallyDrop::new(worker_state.1);
                    // Traced SVM for periodic coverage (ManuallyDrop for Rc safety)
                    let mut worker_traced_svm = worker_state.2.map(|svm| std::mem::ManuallyDrop::new(svm));

                    // Per-worker coverage map (display only)
                    let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
                    let worker_cov_ptr = worker_cov_map.as_mut_ptr();

                    let mut rng = StdRand::with_seed(worker_seed);
                    let mut local_iter: u64 = 0;
                    let mut divergent_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                        crucible_test_context::FastHashSet::default();
                    let mut prev_delta_arc: Option<std::sync::Arc<SvmSnapshot>> = None;
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
                    type PickTuple = (std::sync::Arc<SvmSnapshot>, u32, usize, std::sync::Arc<Vec<u8>>, Option<u16>, std::sync::Arc<Vec<u8>>, u64, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);
                    // Reuse rng_vals allocation across batch refills (C4)
                    let mut rng_vals: Vec<u64> = Vec::with_capacity(BATCH_SIZE);
                    let mut local_batch: Vec<PickTuple> = Vec::with_capacity(BATCH_SIZE);
                    // Accumulated results to flush after each batch
                    // (fingerprint, delta, depth, parent_idx, action_bytes, desc, variant, field_bytes, fixture_state, coverage_novel)
                    let mut pending_novel: Vec<(u64, SvmSnapshot, u32, Option<usize>, Vec<u8>, String, Option<u16>, Vec<u8>, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>, bool)> = Vec::new();
                    // Crash info: (action_variant, msg, current_action_desc, parent_state_idx, crash_bytes)
                    let mut pending_crashes: Vec<(u16, String, String, usize, Vec<u8>)> = Vec::new();
                    // Track pending violations: state indices that need record_violation() in the flush
                    let mut pending_violations: Vec<usize> = Vec::new();
                    // Thread-local seen variant hashes to skip duplicate crash accumulation
                    let mut seen_variant_hashes: crucible_test_context::FastHashSet<u64> = crucible_test_context::FastHashSet::default();

                    loop {
                        if stop.load(Ordering::Relaxed) || SIGNAL_STOP.load(Ordering::Relaxed) { break; }

                        // Refill batch when empty
                        if local_batch.is_empty() {
                            // Flush pending writes from the previous batch (one write lock)
                            // Fix 3: Collect crash outputs inside lock, write to disk outside
                            let mut __crash_outputs: Vec<(String, Vec<String>, String, u64, Vec<u8>)> = Vec::new();
                            if !pending_novel.is_empty() || !pending_crashes.is_empty() || !pending_violations.is_empty() {
                                if let Ok(mut pool) = pool.try_write() {
                                    for (fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel) in pending_novel.drain(..) {
                                        if pool.try_add(fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel) {
                                            novel.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    // Record violations against parent states
                                    for vi_idx in pending_violations.drain(..) {
                                        pool.record_violation(vi_idx);
                                    }
                                    for (cur_variant, msg, current_desc, parent_idx, crash_bytes) in pending_crashes.drain(..) {
                                        // Compute variant-only hash inside the lock
                                        let mut __variant_seq = pool.reconstruct_variant_sequence(parent_idx);
                                        __variant_seq.push(cur_variant);
                                        let vh = libafl_bolts::hash_std(
                                            &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                                        );
                                        if pool.is_novel_crash(vh) {
                                            crashes.fetch_add(1, Ordering::Relaxed);
                                            let parent_descs = pool.reconstruct_action_descriptions(parent_idx);
                                            __crash_outputs.push((msg, parent_descs, current_desc, vh, crash_bytes));
                                            if stop_on_crash {
                                                stop.store(true, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                } else {
                                    // Couldn't get write lock — discard non-critical pending state additions
                                    // Keep pending_crashes and pending_violations — they'll flush next batch
                                    pending_novel.clear();
                                }
                            }
                            // Crash disk I/O outside write lock (Fix 3)
                            for (msg, parent_descs, current_desc, vh, crash_bytes) in __crash_outputs {
                                eprintln!("\n[STATEFUL W{}] VIOLATION: {}", worker_id, msg);
                                let total = parent_descs.len() + 1;
                                eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                                for (i, desc) in parent_descs.iter().enumerate() {
                                    eprintln!("  {}. {}", i + 1, desc);
                                }
                                eprintln!("  {}. {} [VIOLATION]", total, current_desc);
                                eprintln!("===================================");
                                crucible_test_context::write_crash_metadata(
                                    &crash_dir, vh, Some(worker_seed), &crash_bytes,
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
                                rng_vals.clear();
                                for _ in 0..BATCH_SIZE {
                                    rng_vals.push(rng.next());
                                }
                                p.pick_weighted_batch(&rng_vals, &mut local_batch);
                                // Read lock released here — pool is free for other workers
                            }

                            if local_batch.is_empty() {
                                break; // Pool exhausted
                            }
                        }

                        local_iter += 1;

                        // Pop one state from local batch (no lock needed)
                        let (delta_arc, parent_depth, state_idx, parent_action_bytes, parent_variant, parent_field_bytes, parent_fingerprint, fixture_arc) =
                            local_batch.pop().unwrap();
                        // Fix 1: Per-iteration fixture clone (hold mutex for ~10µs instead of ~5ms for 512 clones)
                        let mut __iter_fixture = {
                            let _guard = fixture_clone_lock.lock().unwrap();
                            if let Some(ref arc) = fixture_arc {
                                let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                                wrapper.0.clone()
                            } else {
                                (*worker_fixture).clone()
                            }
                        };

                        // 2. Selective restore with dual-SVM support
                        let is_traced_iter = worker_traced_svm.is_some() && (local_iter % trace_interval == 0);
                        let has_tracing = trace_interval == 1 || is_traced_iter;

                        if is_traced_iter {
                            // Swap traced SVM into worker_svm position
                            if let Some(ref mut traced) = worker_traced_svm {
                                std::mem::swap(&mut *worker_svm, &mut **traced);
                            }
                            // Simple restore for traced SVM (infrequent, no delta-to-delta)
                            worker_initial.restore_selective(&mut *worker_svm, &traced_divergent, &delta_arc);
                            traced_divergent.clear();
                            traced_divergent.extend(delta_arc.accounts().keys().copied());
                        } else {
                            // Optimized delta-to-delta restore for fast SVM
                            if let Some(ref prev) = prev_delta_arc {
                                worker_initial.restore_selective_from(&mut *worker_svm, &divergent_keys, prev, &delta_arc, &prev_exec_dirty);
                            } else {
                                worker_initial.restore_selective(&mut *worker_svm, &divergent_keys, &delta_arc);
                            }
                            divergent_keys.clear();
                            divergent_keys.extend(delta_arc.accounts().keys().copied());
                        }

                        // 3. Generate action using guided selection (same strategy as singlecore)
                        let __state_class = crucible_test_context::snapshot::state_class_from_fingerprint(parent_fingerprint);
                        let __replay_roll = rng.next() % 100;
                        let action = if __replay_roll < 15 && parent_variant.is_some() && !parent_field_bytes.is_empty() {
                            // 15%: Mutate parent's action
                            let vi = parent_variant.unwrap() as usize;
                            let mut cursor = 0usize;
                            match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(vi, &parent_field_bytes, &mut cursor) {
                                Some(mut a) => {
                                    <#action_ty as crucible_fuzzer::FuzzAction>::mutate(&mut a, &mut rng);
                                    a
                                }
                                None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                            }
                        } else if __replay_roll < 40 && parent_variant.is_some() {
                            // 25%: Same variant as parent, fresh random params
                            <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(
                                parent_variant.unwrap() as usize, &mut rng,
                            )
                        } else {
                            // 60%: Guided variant selection (epsilon-greedy from ActionStatsMap)
                            match action_stats.pick_variant(__state_class, rng.next(), rng.next()) {
                                Some(vi) => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(vi, &mut rng),
                                None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                            }
                        };

                        let single_action_bytes = {
                            let mut buf = Vec::new();
                            buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                            action.serialize_fields(&mut buf);
                            buf
                        };

                        // 4. Execute — use per-iteration fixture clone (correct mutable state).
                        //    Swap SVM into fixture, run test, swap back.
                        std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);

                        // Set coverage callback only when tracing is active this iteration
                        if has_tracing {
                            let callback = #mod_name::FuzzCallback::with_shared_memory(
                                worker_cov_ptr, #mod_name::MAP_SIZE,
                                shared_edge_ptr, shared_branch_ptr,
                            );
                            __iter_fixture.ctx.set_invocation_callback(callback);
                            #mod_name::reset_new_coverage_flag();
                        }

                        crucible_test_context::set_current_iteration(local_iter);
                        crucible_test_context::clear_action_history();
                        crucible_test_context::clear_violation_tracking();

                        crucible_test_context::reset_iteration_dispatch_count();
                        let actions_vec = vec![action.clone()];
                        let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            #fn_name(&mut __iter_fixture, actions_vec);
                        }));
                        let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();

                        // Flush thread-local bitmap buffers and check for new coverage (only on traced iterations)
                        let __new_coverage = if has_tracing {
                            #mod_name::flush_local_bitmap_buffers(shared_edge_ptr, shared_branch_ptr);
                            #mod_name::found_new_coverage()
                        } else { false };

                        // Count actual SVM executions (includes success-seeking retries)
                        #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, Ordering::Relaxed);
                        iters.fetch_add(__actions_this_iter, Ordering::Relaxed);

                        // Check for violation
                        let violation = crucible_test_context::take_violation();

                        if let Some(ref msg) = violation {
                            // Track violation for record_violation() during flush
                            pending_violations.push(state_idx);

                            // Quick local dedup: skip if we've seen this variant from this state before
                            let __cur_variant = action.variant_index() as u16;
                            let __local_key = libafl_bolts::hash_std(
                                &[&parent_fingerprint.to_le_bytes()[..], &__cur_variant.to_le_bytes()[..]].concat()
                            );
                            if seen_variant_hashes.insert(__local_key) {
                                // Build crash bytes locally (deep clone from Arc)
                                let mut crash_bytes = (*parent_action_bytes).clone();
                                if crash_bytes.len() >= 4 {
                                    let old_count = u32::from_le_bytes(
                                        crash_bytes[0..4].try_into().unwrap()
                                    );
                                    crash_bytes[0..4].copy_from_slice(&(old_count + 1).to_le_bytes());
                                    crash_bytes.extend_from_slice(&single_action_bytes);
                                }
                                // Store action variant for coarse dedup (computed inside lock later)
                                let current_desc = crucible_test_context::format_last_action_oneline();
                                pending_crashes.push((__cur_variant, msg.clone(), current_desc, state_idx, crash_bytes));
                            }
                        }

                        // 5. Fingerprint + add to pool (accumulated locally)
                        let __action_variant_idx = action.variant_index();
                        let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                            let history = crucible_test_context::get_action_history();
                            let succeeded = history.first().map(|r| r.success).unwrap_or(false);

                            // Record in per-worker action stats
                            action_stats.record(__state_class, __action_variant_idx, succeeded);

                            if succeeded {
                                let mut fingerprint = compute_state_fingerprint_from_snapshot(
                                    &__iter_fixture.ctx.svm,
                                    &__iter_fixture.ctx.dirty_tracker,
                                );

                                // Coverage-driven: bypass fingerprint dedup for states with new edges
                                if __new_coverage {
                                    fingerprint = fingerprint
                                        .wrapping_mul(0x9e3779b97f4a7c15)
                                        .wrapping_add(local_iter);
                                }

                                if fingerprint != 0 {
                                    let new_delta = SvmSnapshot::take_delta(
                                        &__iter_fixture.ctx.svm,
                                        &delta_arc,
                                        &__iter_fixture.ctx.dirty_tracker,
                                    );

                                    let mut accumulated_bytes = (*parent_action_bytes).clone();
                                    if accumulated_bytes.len() >= 4 {
                                        let count = u32::from_le_bytes(
                                            accumulated_bytes[0..4].try_into().unwrap()
                                        );
                                        accumulated_bytes[0..4].copy_from_slice(&(count + 1).to_le_bytes());
                                        accumulated_bytes.extend_from_slice(&single_action_bytes);
                                    }

                                    let __field_bytes = if single_action_bytes.len() > 2 {
                                        single_action_bytes[2..].to_vec()
                                    } else {
                                        Vec::new()
                                    };

                                    // Store fixture alongside novel state (SVM swapped out = cheap clone).
                                    // Single-threaded within this worker, so Rc::clone is safe.
                                    std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                                    let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                                        Some(std::sync::Arc::new(__FixtureWrapper(__iter_fixture.clone())));
                                    std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);

                                    let action_desc = crucible_test_context::format_last_action_oneline();
                                    pending_novel.push((
                                        fingerprint, new_delta, parent_depth + 1,
                                        Some(state_idx), accumulated_bytes, action_desc,
                                        Some(__action_variant_idx as u16), __field_bytes,
                                        __fixture_for_storage, __new_coverage,
                                    ));
                                }
                            }
                            succeeded
                        } else {
                            action_stats.record(__state_class, __action_variant_idx, false);
                            false
                        };

                        // 6. Update divergent_keys, prev_delta_arc, and prev_exec_dirty
                        if is_traced_iter {
                            // Traced SVM: update its own divergent tracking
                            if __action_succeeded {
                                traced_divergent.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                            }
                        } else {
                            // Fast SVM: update delta optimization state
                            prev_exec_dirty.clear();
                            if __action_succeeded {
                                prev_exec_dirty.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                                divergent_keys.extend(prev_exec_dirty.iter().copied());
                            }
                            prev_delta_arc = Some(delta_arc);
                        }

                        // 7. Swap SVM back out of per-iteration fixture
                        std::mem::swap(&mut __iter_fixture.ctx.svm, &mut *worker_svm);
                        // If traced iteration, swap traced SVM back to its dedicated slot
                        if is_traced_iter {
                            if let Some(ref mut traced) = worker_traced_svm {
                                std::mem::swap(&mut *worker_svm, &mut **traced);
                            }
                        }
                        // __iter_fixture is dropped here (per-iteration clone)

                        if let Err(__panic_payload) = __panic_result {
                            std::panic::resume_unwind(__panic_payload);
                        }
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
            let mut w0_traced_svm: Option<litesvm::LiteSVM> = if trace_interval > 1 {
                __traced_svm.take()
                    .or_else(|| {
                        // Fallback: create a new debuggable SVM from snapshot
                        let mut svm = litesvm::LiteSVM::new();
                        initial_snapshot.restore_full(&mut svm);
                        Some(svm)
                    })
            } else {
                None
            };

            // Per-worker coverage map
            let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
            let worker_cov_ptr = worker_cov_map.as_mut_ptr();

            let mut rng = StdRand::with_seed(seed);
            let mut local_iter: u64 = 0;
            let mut last_print_time = std::time::Instant::now();
            let mut last_print_iters: u64 = 0;
            let mut divergent_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();
            let mut prev_delta_arc: Option<std::sync::Arc<SvmSnapshot>> = None;
            let mut prev_exec_dirty: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();
            // Dual-SVM: divergent tracking for the traced SVM
            let mut traced_divergent: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                crucible_test_context::FastHashSet::default();

            let __do_profile = std::env::var("FUZZ_PROFILE").is_ok();
            let mut __phase_pick_ns: u64 = 0;
            let mut __phase_restore_ns: u64 = 0;
            let mut __phase_execute_ns: u64 = 0;
            let mut __phase_fingerprint_ns: u64 = 0;
            let mut __phase_save_ns: u64 = 0;
            let mut __phase_crash_ns: u64 = 0;
            let mut __phase_cleanup_ns: u64 = 0;
            let mut __phase_total_ns: u64 = 0;
            let mut __profiled_iters: u64 = 0;

            // Per-worker action stats
            let mut action_stats = crucible_test_context::snapshot::ActionStatsMap::new(
                <#action_ty as crucible_fuzzer::FuzzAction>::variant_count(),
            );

            // Batched pool access (same pattern as spawned workers):
            // Pick BATCH_SIZE states under one read lock (pick_count is atomic),
            // process locally, flush results with one write lock per batch.
            const BATCH_SIZE: usize = 64;
            // (delta, depth, state_idx, action_bytes, parent_variant, parent_field_bytes, fingerprint, fixture_state)
            type PickTuple = (std::sync::Arc<SvmSnapshot>, u32, usize, std::sync::Arc<Vec<u8>>, Option<u16>, std::sync::Arc<Vec<u8>>, u64, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);
            // Reuse rng_vals allocation across batch refills (C4)
            let mut rng_vals: Vec<u64> = Vec::with_capacity(BATCH_SIZE);
            let mut local_batch: Vec<PickTuple> = Vec::with_capacity(BATCH_SIZE);
            // (fingerprint, delta, depth, parent_idx, action_bytes, desc, variant, field_bytes, fixture_state, coverage_novel)
            let mut pending_novel: Vec<(u64, SvmSnapshot, u32, Option<usize>, Vec<u8>, String, Option<u16>, Vec<u8>, Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>, bool)> = Vec::new();
            let mut pending_crashes: Vec<(u16, String, String, usize, Vec<u8>)> = Vec::new();
            // Track pending violations: state indices that need record_violation() in the flush
            let mut pending_violations: Vec<usize> = Vec::new();
            // Thread-local seen variant hashes to skip duplicate crash accumulation
            let mut seen_variant_hashes: crucible_test_context::FastHashSet<u64> = crucible_test_context::FastHashSet::default();

            // Cache pool stats for monitor (updated at batch boundaries, avoids extra read locks)
            let mut cached_pool_len: usize = 1;
            let mut cached_pool_active: usize = 1;

            loop {
                if stop.load(Ordering::Relaxed) || SIGNAL_STOP.load(Ordering::Relaxed) { break; }

                local_iter += 1;

                // Timeout check (rate-limited)
                if let Some(timeout) = timeout_secs {
                    if local_iter % 300 == 0 {
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

                let __iter_start = std::time::Instant::now();

                // 1. Refill batch when empty
                let __t = std::time::Instant::now();
                if local_batch.is_empty() {
                    // Flush pending writes from previous batch
                    // Fix 3: Collect crash outputs inside lock, write to disk outside
                    let mut __crash_outputs: Vec<(String, Vec<String>, String, u64, Vec<u8>)> = Vec::new();
                    if !pending_novel.is_empty() || !pending_crashes.is_empty() || !pending_violations.is_empty() {
                        if let Ok(mut p) = pool.try_write() {
                            for (fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel) in pending_novel.drain(..) {
                                if p.try_add(fp, delta, depth, parent, bytes, desc, var, fb, fs, cov_novel) {
                                    novel.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            // Record violations against parent states
                            for vi_idx in pending_violations.drain(..) {
                                p.record_violation(vi_idx);
                            }
                            for (cur_variant, msg, current_desc, parent_idx, crash_bytes) in pending_crashes.drain(..) {
                                // Compute variant-only hash inside the lock
                                let mut __variant_seq = p.reconstruct_variant_sequence(parent_idx);
                                __variant_seq.push(cur_variant);
                                let vh = libafl_bolts::hash_std(
                                    &__variant_seq.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()
                                );
                                if p.is_novel_crash(vh) {
                                    crashes.fetch_add(1, Ordering::Relaxed);
                                    let parent_descs = p.reconstruct_action_descriptions(parent_idx);
                                    __crash_outputs.push((msg, parent_descs, current_desc, vh, crash_bytes));
                                    if stop_on_crash {
                                        stop.store(true, Ordering::Relaxed);
                                    }
                                }
                            }
                            cached_pool_len = p.len();
                            cached_pool_active = p.active_count();
                        } else {
                            // Couldn't get write lock — discard non-critical pending state additions
                            // Keep pending_crashes and pending_violations — they'll flush next batch
                            pending_novel.clear();
                        }
                    }
                    // Crash disk I/O outside write lock (Fix 3)
                    for (msg, parent_descs, current_desc, vh, crash_bytes) in __crash_outputs {
                        eprintln!("\n[STATEFUL W0] VIOLATION: {}", msg);
                        let total = parent_descs.len() + 1;
                        eprintln!("=== CRASH SEQUENCE ({} actions) ===", total);
                        for (i, desc) in parent_descs.iter().enumerate() {
                            eprintln!("  {}. {}", i + 1, desc);
                        }
                        eprintln!("  {}. {} [VIOLATION]", total, current_desc);
                        eprintln!("===================================");
                        crucible_test_context::write_crash_metadata(
                            &crash_dir, vh, Some(seed), &crash_bytes,
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

                    // Pick weighted batch (read lock — pick_count is atomic)
                    {
                        let p = pool.read().unwrap();
                        cached_pool_len = p.len();
                        cached_pool_active = p.active_count();
                        rng_vals.clear();
                        for _ in 0..BATCH_SIZE {
                            rng_vals.push(rng.next());
                        }
                        p.pick_weighted_batch(&rng_vals, &mut local_batch);
                        // Read lock released here — pool is free for other workers
                    }

                    if local_batch.is_empty() {
                        eprintln!("[STATEFUL] All active states exhausted. Stopping.");
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }

                // Pop one state from local batch (no lock needed)
                let (delta_arc, parent_depth, state_idx, parent_action_bytes, parent_variant, parent_field_bytes, parent_fingerprint, fixture_arc) =
                    local_batch.pop().unwrap();
                // Fix 1: Per-iteration fixture clone (hold mutex for ~10µs instead of ~5ms for 64 clones)
                let mut __iter_fixture = {
                    let _guard = fixture_clone_mutex.lock().unwrap();
                    if let Some(ref arc) = fixture_arc {
                        let wrapper = arc.downcast_ref::<__FixtureWrapper>().expect("fixture downcast failed");
                        wrapper.0.clone()
                    } else {
                        w0_fixture.clone()
                    }
                };
                if __do_profile { __phase_pick_ns += __t.elapsed().as_nanos() as u64; }

                // 2. Selective restore with dual-SVM support
                let __t = std::time::Instant::now();
                let is_traced_iter = w0_traced_svm.is_some() && (local_iter % trace_interval == 0);
                let has_tracing = trace_interval == 1 || is_traced_iter;

                if is_traced_iter {
                    // Swap traced SVM into w0_svm position
                    if let Some(ref mut traced) = w0_traced_svm {
                        std::mem::swap(&mut w0_svm, traced);
                    }
                    // Simple restore for traced SVM (infrequent, no delta-to-delta)
                    w0_initial.restore_selective(&mut w0_svm, &traced_divergent, &delta_arc);
                    traced_divergent.clear();
                    traced_divergent.extend(delta_arc.accounts().keys().copied());
                } else {
                    // Optimized delta-to-delta restore for fast SVM
                    if let Some(ref prev) = prev_delta_arc {
                        w0_initial.restore_selective_from(&mut w0_svm, &divergent_keys, prev, &delta_arc, &prev_exec_dirty);
                    } else {
                        w0_initial.restore_selective(&mut w0_svm, &divergent_keys, &delta_arc);
                    }
                    divergent_keys.clear();
                    divergent_keys.extend(delta_arc.accounts().keys().copied());
                }
                if __do_profile { __phase_restore_ns += __t.elapsed().as_nanos() as u64; }

                // 3. Generate action using guided selection
                let __t = std::time::Instant::now();
                let __state_class = crucible_test_context::snapshot::state_class_from_fingerprint(parent_fingerprint);
                let __replay_roll = rng.next() % 100;
                let action = if __replay_roll < 15 && parent_variant.is_some() && !parent_field_bytes.is_empty() {
                    let vi = parent_variant.unwrap() as usize;
                    let mut cursor = 0usize;
                    match <#action_ty as crucible_fuzzer::FuzzAction>::deserialize_fields(vi, &parent_field_bytes, &mut cursor) {
                        Some(mut a) => {
                            <#action_ty as crucible_fuzzer::FuzzAction>::mutate(&mut a, &mut rng);
                            a
                        }
                        None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                    }
                } else if __replay_roll < 40 && parent_variant.is_some() {
                    <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(
                        parent_variant.unwrap() as usize, &mut rng,
                    )
                } else {
                    match action_stats.pick_variant(__state_class, rng.next(), rng.next()) {
                        Some(vi) => <#action_ty as crucible_fuzzer::FuzzAction>::random_variant(vi, &mut rng),
                        None => <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng),
                    }
                };

                let single_action_bytes = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                    action.serialize_fields(&mut buf);
                    buf
                };

                // 4. Execute — use per-iteration fixture clone (correct mutable state).
                //    Swap SVM into fixture, run test, swap back.
                std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);

                // Set coverage callback only when tracing is active this iteration
                if has_tracing {
                    let callback = #mod_name::FuzzCallback::with_shared_memory(
                        worker_cov_ptr, #mod_name::MAP_SIZE,
                        shared_edge_ptr, shared_branch_ptr,
                    );
                    __iter_fixture.ctx.set_invocation_callback(callback);
                    #mod_name::reset_new_coverage_flag();
                }

                crucible_test_context::set_current_iteration(local_iter);
                crucible_test_context::clear_action_history();
                crucible_test_context::clear_violation_tracking();

                crucible_test_context::reset_iteration_dispatch_count();
                let actions_vec = vec![action.clone()];
                let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #fn_name(&mut __iter_fixture, actions_vec);
                }));
                let __actions_this_iter = crucible_test_context::get_iteration_dispatch_count();
                if __do_profile { __phase_execute_ns += __t.elapsed().as_nanos() as u64; }

                // Flush thread-local bitmap buffers and check for new coverage (only on traced iterations)
                let __new_coverage = if has_tracing {
                    #mod_name::flush_local_bitmap_buffers(shared_edge_ptr, shared_branch_ptr);
                    #mod_name::found_new_coverage()
                } else { false };

                // Count actual SVM executions (includes success-seeking retries)
                #mod_name::TOTAL_EXECUTIONS.fetch_add(__actions_this_iter, Ordering::Relaxed);
                iters.fetch_add(__actions_this_iter, Ordering::Relaxed);

                if #mod_name::COVERAGE_ENABLED.load(Ordering::Relaxed) {
                    let exec_count = #mod_name::TOTAL_EXECUTIONS.load(Ordering::Relaxed);
                    #mod_name::maybe_write_coverage(exec_count);
                }

                // Check for violation — accumulate locally (flushed at batch boundary)
                let __t = std::time::Instant::now();
                let violation = crucible_test_context::take_violation();

                if let Some(ref msg) = violation {
                    // Track violation for record_violation() during flush
                    pending_violations.push(state_idx);

                    // Quick local dedup: skip if we've seen this variant from this state before
                    let __cur_variant = action.variant_index() as u16;
                    let __local_key = libafl_bolts::hash_std(
                        &[&parent_fingerprint.to_le_bytes()[..], &__cur_variant.to_le_bytes()[..]].concat()
                    );
                    if seen_variant_hashes.insert(__local_key) {
                        let mut crash_bytes = (*parent_action_bytes).clone();
                        if crash_bytes.len() >= 4 {
                            let old_count = u32::from_le_bytes(
                                crash_bytes[0..4].try_into().unwrap()
                            );
                            crash_bytes[0..4].copy_from_slice(&(old_count + 1).to_le_bytes());
                            crash_bytes.extend_from_slice(&single_action_bytes);
                        }
                        // Store action variant for coarse dedup (computed inside lock later)
                        let current_desc = crucible_test_context::format_last_action_oneline();
                        pending_crashes.push((__cur_variant, msg.clone(), current_desc, state_idx, crash_bytes));
                    }
                }
                if __do_profile { __phase_crash_ns += __t.elapsed().as_nanos() as u64; }

                // 5. Fingerprint + add to pool (accumulated locally)
                let __action_variant_idx = action.variant_index();
                let __action_succeeded = if violation.is_none() && __panic_result.is_ok() {
                    let history = crucible_test_context::get_action_history();
                    let succeeded = history.first().map(|r| r.success).unwrap_or(false);

                    // Record in per-worker action stats
                    action_stats.record(__state_class, __action_variant_idx, succeeded);

                    if succeeded {
                        let __t = std::time::Instant::now();
                        let mut fingerprint = compute_state_fingerprint_from_snapshot(
                            &__iter_fixture.ctx.svm,
                            &__iter_fixture.ctx.dirty_tracker,
                        );
                        // Coverage-driven: bypass fingerprint dedup for states with new edges
                        if __new_coverage {
                            fingerprint = fingerprint
                                .wrapping_mul(0x9e3779b97f4a7c15)
                                .wrapping_add(local_iter);
                        }
                        if __do_profile { __phase_fingerprint_ns += __t.elapsed().as_nanos() as u64; }

                        if fingerprint != 0 {
                            let __t = std::time::Instant::now();
                            let new_delta = SvmSnapshot::take_delta(
                                &__iter_fixture.ctx.svm,
                                &delta_arc,
                                &__iter_fixture.ctx.dirty_tracker,
                            );

                            let mut accumulated_bytes = (*parent_action_bytes).clone();
                            if accumulated_bytes.len() >= 4 {
                                let count = u32::from_le_bytes(
                                    accumulated_bytes[0..4].try_into().unwrap()
                                );
                                accumulated_bytes[0..4].copy_from_slice(&(count + 1).to_le_bytes());
                                accumulated_bytes.extend_from_slice(&single_action_bytes);
                            }

                            let __field_bytes = if single_action_bytes.len() > 2 {
                                single_action_bytes[2..].to_vec()
                            } else {
                                Vec::new()
                            };

                            // Store fixture alongside novel state (SVM swapped out = cheap clone)
                            std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                            let __fixture_for_storage: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> =
                                Some(std::sync::Arc::new(__FixtureWrapper(__iter_fixture.clone())));
                            std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);

                            let action_desc = crucible_test_context::format_last_action_oneline();
                            pending_novel.push((
                                fingerprint, new_delta, parent_depth + 1,
                                Some(state_idx), accumulated_bytes, action_desc,
                                Some(__action_variant_idx as u16), __field_bytes,
                                __fixture_for_storage, __new_coverage,
                            ));
                            if __do_profile { __phase_save_ns += __t.elapsed().as_nanos() as u64; }
                        }
                    }
                    succeeded
                } else {
                    action_stats.record(__state_class, __action_variant_idx, false);
                    false
                };

                // 6. Update divergent_keys, prev_delta_arc, and prev_exec_dirty
                let __t = std::time::Instant::now();
                if is_traced_iter {
                    // Traced SVM: update its own divergent tracking
                    if __action_succeeded {
                        traced_divergent.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                    }
                } else {
                    // Fast SVM: update delta optimization state
                    prev_exec_dirty.clear();
                    if __action_succeeded {
                        prev_exec_dirty.extend(__iter_fixture.ctx.dirty_tracker.dirty_accounts().iter().copied());
                        divergent_keys.extend(prev_exec_dirty.iter().copied());
                    }
                    prev_delta_arc = Some(delta_arc);
                }

                // 7. Swap SVM back out of per-iteration fixture
                std::mem::swap(&mut __iter_fixture.ctx.svm, &mut w0_svm);
                // If traced iteration, swap traced SVM back to its dedicated slot
                if is_traced_iter {
                    if let Some(ref mut traced) = w0_traced_svm {
                        std::mem::swap(&mut w0_svm, traced);
                    }
                }
                // __iter_fixture is dropped here (per-iteration clone)
                if __do_profile { __phase_cleanup_ns += __t.elapsed().as_nanos() as u64; }

                if let Err(__panic_payload) = __panic_result {
                    std::panic::resume_unwind(__panic_payload);
                }

                // 8. Rate-limited monitor output (worker 0 only)
                if __do_profile {
                    __phase_total_ns += __iter_start.elapsed().as_nanos() as u64;
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
                    eprintln!(
                        "[STATEFUL] [{:02}:{:02}] iter: {}, iter/sec: {:.0}, pool: {}/{} ({:.1}%), active: {}, \
                         novel: {}, crashes: {}, ok: {}/{} ({:.1}%), discovered: {}/{} actions, edges: {}/{} ({:.1}%), branches: {}/{}, workers: {}",
                        mins, secs,
                        total_iters, iter_sec,
                        cached_pool_len, pool_capacity, pool_pct,
                        cached_pool_active,
                        total_novel, total_crashes,
                        total_ok, total_actions, ok_pct,
                        discovered, total_variants,
                        edges, total_edges, edge_pct,
                        branches, total_branches,
                        num_cores,
                    );

                    if __do_profile && __profiled_iters > 0 {
                        let total = __phase_total_ns;
                        let pct = |ns: u64| -> f64 { if total > 0 { (ns as f64 / total as f64) * 100.0 } else { 0.0 } };
                        let other_ns = total.saturating_sub(
                            __phase_pick_ns + __phase_restore_ns + __phase_execute_ns
                            + __phase_fingerprint_ns + __phase_save_ns
                            + __phase_crash_ns + __phase_cleanup_ns
                        );
                        let avg_us = total / __profiled_iters / 1000;
                        eprintln!(
                            "[PROFILE] pick: {:.1}% | restore: {:.1}% | execute: {:.1}% | \
                             fingerprint: {:.1}% | save: {:.1}% | crash: {:.1}% | cleanup: {:.1}% | other: {:.1}% (avg: {}µs/iter)",
                            pct(__phase_pick_ns), pct(__phase_restore_ns), pct(__phase_execute_ns),
                            pct(__phase_fingerprint_ns), pct(__phase_save_ns),
                            pct(__phase_crash_ns), pct(__phase_cleanup_ns), pct(other_ns),
                            avg_us,
                        );
                        __phase_pick_ns = 0;
                        __phase_restore_ns = 0;
                        __phase_execute_ns = 0;
                        __phase_fingerprint_ns = 0;
                        __phase_save_ns = 0;
                        __phase_crash_ns = 0;
                        __phase_cleanup_ns = 0;
                        __phase_total_ns = 0;
                        __profiled_iters = 0;
                    }

                    last_print_time = now;
                    last_print_iters = total_iters;
                }
            }
        }

        // Signal workers to stop and wait for them
        stop_flag.store(true, Ordering::Relaxed);
        for handle in worker_handles {
            let _ = handle.join();
        }

        if #mod_name::COVERAGE_ENABLED.load(Ordering::Relaxed) {
            #mod_name::write_lcov_coverage("coverage.lcov");
        }

        if let Some(ref __corpus_out_path) = corpus_out_dir {
            let pool = state_pool.read().unwrap();
            match pool.export_corpus(__corpus_out_path) {
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
