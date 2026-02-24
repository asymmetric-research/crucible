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
                StatePool, SvmSnapshot, compute_state_fingerprint, snapshot_dirty_accounts,
            };
            use libafl_bolts::rands::{Rand, StdRand};

            eprintln!("[STATEFUL] ItyFuzz-style stateful fuzzing mode");

            // Parse pool capacity from env or default to 100_000
            let pool_capacity: usize = std::env::var("FUZZ_STATE_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000);

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
            let initial_snapshot = SvmSnapshot::take_all(&__real_svm);

            // --no-tracing: after capturing initial state with tracing enabled,
            // switch to non-instrumented SVM for maximum throughput.
            if no_tracing {
                std::env::remove_var("ANCHOR_FUZZ_DEBUGGABLE");
                eprintln!("[STATEFUL] Switching to no-tracing mode for higher throughput");
                let mut __new_fixture = #fixture_name::setup();
                __new_fixture.ctx.take_snapshot();
                template_fixture = __new_fixture;
                __real_svm = std::mem::replace(
                    &mut template_fixture.ctx.svm,
                    litesvm::LiteSVM::new(),
                );
            }

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
        let mut state_pool = StatePool::new(pool_capacity);
        state_pool.try_add(0, initial_snapshot, 0, None, Vec::new());

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

        eprintln!("[STATEFUL] Pool capacity: {}, seed: {}", pool_capacity, seed);
        eprintln!("[STATEFUL] Starting stateful fuzzing loop...\n");

        loop {
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
                        std::process::exit(0);
                    }
                }
            }

            // 1. Pick a random state from the pool
            let state_idx = state_pool.pick_random(rng.next()).unwrap_or(0);
            let parent_depth = state_pool.get(state_idx).map(|s| s.depth).unwrap_or(0);

            // 2. Restore SVM to that state
            if let Some(entry) = state_pool.get(state_idx) {
                entry.snapshot.restore_full(&mut __real_svm);
            }

            // 3. Generate a random action
            let action = <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng);

            // Serialize the single action for storage
            let single_action_bytes = {
                let mut buf = Vec::new();
                buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                action.serialize_fields(&mut buf);
                buf
            };

            // 4. Snapshot writable accounts BEFORE executing (for fingerprinting)
            //    We use all tracked accounts from the base snapshot as the pre-state
            let __tracked_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                base_snapshot.accounts().keys().copied().collect();
            let pre_states = snapshot_dirty_accounts(&__real_svm, &__tracked_keys);

            // 5. Execute the single action using the existing invariant test function
            //    Clone template (cheap: empty SVM + Arc programs), swap in real SVM
            let mut #fixture_param_name = template_fixture.clone();
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);

            // Set up coverage callback
            let callback = #mod_name::FuzzCallback::from_raw(__stateful_cov_ptr, #mod_name::MAP_SIZE);
            #fixture_param_name.ctx.set_invocation_callback(callback);

            crucible_test_context::set_current_iteration(iteration);
            crucible_test_context::clear_action_history();
            crucible_test_context::clear_violation_tracking();

            // Execute with a single-element action vec (reuses all invariant/dispatch/taint logic)
            let actions_vec = vec![action.clone()];
            let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #fn_name(&mut #fixture_param_name, actions_vec);
            }));

            #mod_name::TOTAL_EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if #mod_name::COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                let exec_count = #mod_name::TOTAL_EXECUTIONS.load(std::sync::atomic::Ordering::Relaxed);
                #mod_name::maybe_write_coverage(exec_count);
            }

            // Check for violation BEFORE swapping SVM back
            let violation = crucible_test_context::take_violation();

            if let Some(ref msg) = violation {
                // Crash detected! Reconstruct full action sequence from pool
                eprintln!("\n[STATEFUL] VIOLATION at iteration {}: {}", iteration, msg);
                crucible_test_context::print_action_sequence();
                crashes_found += 1;

                // Walk parent chain to build complete action sequence bytes
                let mut crash_bytes = state_pool.reconstruct_action_sequence(state_idx);
                // Append this final action to the sequence
                {
                    // Re-parse the count, increment it, and append the action
                    if crash_bytes.len() >= 4 {
                        let old_count = u32::from_le_bytes(
                            crash_bytes[0..4].try_into().unwrap()
                        );
                        let new_count = old_count + 1;
                        crash_bytes[0..4].copy_from_slice(&new_count.to_le_bytes());
                        crash_bytes.extend_from_slice(&single_action_bytes);
                    }
                }

                // Write crash using content hash for filename
                let input_hash = libafl_bolts::hash_std(&crash_bytes);
                crucible_test_context::write_crash_metadata(
                    &crash_dir, input_hash, Some(seed), &crash_bytes,
                );

                if stop_on_crash {
                    eprintln!("[STATEFUL] First crash found. Exiting (--stop-on-crash).");
                    std::process::exit(0);
                }
            }

            // 6. Compute fingerprint and potentially add to pool (only if no violation and no panic)
            if violation.is_none() && __panic_result.is_ok() {
                // Check if the action actually succeeded (had any effect)
                let history = crucible_test_context::get_action_history();
                let action_succeeded = history.first().map(|r| r.success).unwrap_or(false);

                if action_succeeded {
                    // Fingerprint the dirty accounts
                    let fingerprint = compute_state_fingerprint(
                        &#fixture_param_name.ctx.svm,
                        &#fixture_param_name.ctx.dirty_tracker,
                        &pre_states,
                    );

                    if fingerprint != 0 {
                        // Take a full snapshot for the pool.
                        // IMPORTANT: Use the PARENT state's snapshot as the base,
                        // not the initial base_snapshot. This ensures compound state:
                        // parent's accounts + this action's dirty accounts = correct depth N+1 state.
                        let parent_snap = &state_pool.get(state_idx).unwrap().snapshot;
                        let new_snapshot = SvmSnapshot::take_full(
                            &#fixture_param_name.ctx.svm,
                            parent_snap,
                            &#fixture_param_name.ctx.dirty_tracker,
                        );
                        // parent_snap borrow ends here (take_full returns owned SvmSnapshot)

                        if state_pool.try_add(
                            fingerprint,
                            new_snapshot,
                            parent_depth + 1,
                            Some(state_idx),
                            single_action_bytes,
                        ) {
                            novel_states += 1;
                        }
                    }
                }
            }

            // 7. Swap SVM back out of fixture
            std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);
            // fixture is dropped here

            // On panic: resume unwinding
            if let Err(__panic_payload) = __panic_result {
                std::panic::resume_unwind(__panic_payload);
            }

            // 8. Rate-limited monitor output
            let now = std::time::Instant::now();
            if now.duration_since(last_print_time).as_millis() >= 2000 {
                let elapsed_secs = now.duration_since(last_print_time).as_secs_f64();
                let iters_since = iteration - last_print_iter;
                let exec_sec = iters_since as f64 / elapsed_secs;

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

                eprintln!(
                    "[STATEFUL] iter: {}, exec/sec: {:.0}, pool: {}/{} ({:.1}%), \
                     novel: {}, crashes: {}, edges: {}/{} ({:.1}%), branches: {}/{}",
                    iteration, exec_sec,
                    state_pool.len(), pool_capacity, pool_pct,
                    novel_states, crashes_found,
                    edges, total_edges, edge_pct,
                    branches, total_branches,
                );

                last_print_time = now;
                last_print_iter = iteration;
            }
        }
    }
}

/// Generate the multi-threaded stateful fuzzing body.
///
/// Setup happens ONCE on the main thread. The fixture + SVM are cloned for
/// each worker so all threads share the same keypairs/pubkeys. Workers share
/// a single `Arc<RwLock<StatePool>>`.
///
/// The fixture contains `Rc<Keypair>` which is not `Send`. Since each worker
/// gets its own independent clone (no cross-thread sharing of the same Rc
/// allocation), we use an unsafe `__SendableFixture` wrapper. Workers use
/// `ManuallyDrop` to avoid Rc refcount races during thread exit.
fn stateful_multicore_body(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    fixture_param_name: &syn::Ident,
    _feature_name: &str,
    action_ty: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        // === MULTI-THREADED STATEFUL ===
        use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};

        eprintln!("[STATEFUL] Multi-threaded mode with {} workers", num_cores);

        // Unsafe Send wrapper: each worker gets its own clone of the fixture.
        // The Rc<Keypair> inside is never shared across threads — each clone
        // has independent Rc allocations. This is safe because we clone BEFORE
        // sending to the thread.
        struct __SendableFixture(#fixture_name);
        unsafe impl Send for __SendableFixture {}

        let state_pool = Arc::new(RwLock::new(StatePool::new(pool_capacity)));

        // Add initial state to shared pool
        {
            let mut pool = state_pool.write().unwrap();
            pool.try_add(0, initial_snapshot, 0, None, Vec::new());
        }

        // Shared atomics
        let shared_iters = Arc::new(AtomicU64::new(0));
        let shared_crashes = Arc::new(AtomicU64::new(0));
        let shared_novel = Arc::new(AtomicU64::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = #mod_name::FUZZER_START_TIME.set(start_time);

        let crash_dir = Arc::new(crash_dir);

        eprintln!("[STATEFUL] Pool capacity: {}, seed: {}", pool_capacity, seed);
        eprintln!("[STATEFUL] Starting multi-threaded stateful fuzzing...\n");

        // Clone fixture + SVM on the main thread for each worker.
        // This ensures all workers have the SAME keypairs/pubkeys as the
        // main thread's setup, so shared pool snapshots are compatible.
        let mut worker_handles = Vec::new();
        for worker_id in 1..num_cores {
            let worker_fixture_clone = template_fixture.clone();
            let worker_svm_clone = __real_svm.clone();
            let worker_base_snapshot = base_snapshot.clone();

            let pool = state_pool.clone();
            let iters = shared_iters.clone();
            let crashes = shared_crashes.clone();
            let novel = shared_novel.clone();
            let stop = stop_flag.clone();
            let crash_dir = crash_dir.clone();
            let worker_seed = seed + worker_id as u64;

            // Wrap in __SendableFixture for the move into the thread
            let sendable = __SendableFixture(worker_fixture_clone);

            let handle = std::thread::Builder::new()
                .name(format!("stateful-worker-{}", worker_id))
                .spawn(move || {
                    // Unwrap the sendable fixture. Use ManuallyDrop so Rc refcounts
                    // are never decremented on this thread — the process is about to
                    // exit anyway and the OS reclaims all memory.
                    let mut worker_fixture = std::mem::ManuallyDrop::new(sendable.0);
                    let mut worker_svm = worker_svm_clone;

                    // Per-worker coverage map (display only)
                    let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
                    let worker_cov_ptr = worker_cov_map.as_mut_ptr();

                    let mut rng = StdRand::with_seed(worker_seed);
                    let mut local_iter: u64 = 0;

                    loop {
                        if stop.load(Ordering::Relaxed) { break; }

                        local_iter += 1;

                        // 1. Pick a random state (read lock, brief)
                        let (snap_clone, parent_depth, state_idx) = {
                            let pool = pool.read().unwrap();
                            let idx = pool.pick_random(rng.next()).unwrap_or(0);
                            let entry = pool.get(idx).unwrap();
                            (entry.snapshot.clone(), entry.depth, idx)
                        };

                        // 2. Restore SVM to that state
                        snap_clone.restore_full(&mut worker_svm);

                        // 3. Generate a random action
                        let action = <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng);

                        let single_action_bytes = {
                            let mut buf = Vec::new();
                            buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                            action.serialize_fields(&mut buf);
                            buf
                        };

                        // 4. Snapshot pre-state for fingerprinting
                        let __tracked_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                            worker_base_snapshot.accounts().keys().copied().collect();
                        let pre_states = snapshot_dirty_accounts(&worker_svm, &__tracked_keys);

                        // 5. Execute
                        // Clone the inner fixture (not the ManuallyDrop wrapper) so the
                        // per-iteration clone is a bare value that drops normally at scope end.
                        let mut #fixture_param_name = <#fixture_name as Clone>::clone(&worker_fixture);
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut worker_svm);

                        let callback = #mod_name::FuzzCallback::from_raw(worker_cov_ptr, #mod_name::MAP_SIZE);
                        #fixture_param_name.ctx.set_invocation_callback(callback);

                        crucible_test_context::set_current_iteration(local_iter);
                        crucible_test_context::clear_action_history();
                        crucible_test_context::clear_violation_tracking();

                        let actions_vec = vec![action.clone()];
                        let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            #fn_name(&mut #fixture_param_name, actions_vec);
                        }));

                        #mod_name::TOTAL_EXECUTIONS.fetch_add(1, Ordering::Relaxed);

                        // Check for violation
                        let violation = crucible_test_context::take_violation();

                        if let Some(ref msg) = violation {
                            eprintln!("\n[STATEFUL W{}] VIOLATION at iter {}: {}", worker_id, local_iter, msg);
                            crucible_test_context::print_action_sequence();
                            crashes.fetch_add(1, Ordering::Relaxed);

                            // Reconstruct crash bytes from pool
                            let mut crash_bytes = {
                                let pool = pool.read().unwrap();
                                pool.reconstruct_action_sequence(state_idx)
                            };
                            if crash_bytes.len() >= 4 {
                                let old_count = u32::from_le_bytes(
                                    crash_bytes[0..4].try_into().unwrap()
                                );
                                let new_count = old_count + 1;
                                crash_bytes[0..4].copy_from_slice(&new_count.to_le_bytes());
                                crash_bytes.extend_from_slice(&single_action_bytes);
                            }

                            let input_hash = libafl_bolts::hash_std(&crash_bytes);
                            crucible_test_context::write_crash_metadata(
                                &crash_dir, input_hash, Some(worker_seed), &crash_bytes,
                            );

                            if stop_on_crash {
                                stop.store(true, Ordering::Relaxed);
                            }
                        }

                        // 6. Fingerprint + add to pool
                        if violation.is_none() && __panic_result.is_ok() {
                            let history = crucible_test_context::get_action_history();
                            let action_succeeded = history.first().map(|r| r.success).unwrap_or(false);

                            if action_succeeded {
                                let fingerprint = compute_state_fingerprint(
                                    &#fixture_param_name.ctx.svm,
                                    &#fixture_param_name.ctx.dirty_tracker,
                                    &pre_states,
                                );

                                if fingerprint != 0 {
                                    // Clone parent snapshot for take_full (read lock)
                                    let parent_snap = {
                                        let pool = pool.read().unwrap();
                                        pool.get(state_idx).unwrap().snapshot.clone()
                                    };
                                    let new_snapshot = SvmSnapshot::take_full(
                                        &#fixture_param_name.ctx.svm,
                                        &parent_snap,
                                        &#fixture_param_name.ctx.dirty_tracker,
                                    );

                                    // Write lock to add
                                    let mut pool = pool.write().unwrap();
                                    if pool.try_add(
                                        fingerprint,
                                        new_snapshot,
                                        parent_depth + 1,
                                        Some(state_idx),
                                        single_action_bytes,
                                    ) {
                                        novel.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }

                        // 7. Swap SVM back out
                        std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut worker_svm);

                        iters.fetch_add(1, Ordering::Relaxed);

                        if let Err(__panic_payload) = __panic_result {
                            std::panic::resume_unwind(__panic_payload);
                        }
                    }
                })
                .expect("failed to spawn worker thread");

            worker_handles.push(handle);
        }

        // Worker 0 (main thread): same loop + monitor output
        {
            let pool = state_pool.clone();
            let iters = shared_iters.clone();
            let crashes = shared_crashes.clone();
            let novel = shared_novel.clone();
            let stop = stop_flag.clone();

            // Per-worker coverage map
            let mut worker_cov_map = vec![0u8; #mod_name::MAP_SIZE];
            let worker_cov_ptr = worker_cov_map.as_mut_ptr();

            let mut rng = StdRand::with_seed(seed);
            let mut local_iter: u64 = 0;
            let mut last_print_time = std::time::Instant::now();
            let mut last_print_iters: u64 = 0;

            loop {
                if stop.load(Ordering::Relaxed) { break; }

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

                // 1. Pick a random state (read lock)
                let (snap_clone, parent_depth, state_idx) = {
                    let p = pool.read().unwrap();
                    let idx = p.pick_random(rng.next()).unwrap_or(0);
                    let entry = p.get(idx).unwrap();
                    (entry.snapshot.clone(), entry.depth, idx)
                };

                // 2. Restore SVM
                snap_clone.restore_full(&mut __real_svm);

                // 3. Generate action
                let action = <#action_ty as crucible_fuzzer::FuzzAction>::random(&mut rng);

                let single_action_bytes = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
                    action.serialize_fields(&mut buf);
                    buf
                };

                // 4. Pre-state snapshot
                let __tracked_keys: crucible_test_context::FastHashSet<solana_pubkey::Pubkey> =
                    base_snapshot.accounts().keys().copied().collect();
                let pre_states = snapshot_dirty_accounts(&__real_svm, &__tracked_keys);

                // 5. Execute
                let mut #fixture_param_name = template_fixture.clone();
                std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);

                let callback = #mod_name::FuzzCallback::from_raw(worker_cov_ptr, #mod_name::MAP_SIZE);
                #fixture_param_name.ctx.set_invocation_callback(callback);

                crucible_test_context::set_current_iteration(local_iter);
                crucible_test_context::clear_action_history();
                crucible_test_context::clear_violation_tracking();

                let actions_vec = vec![action.clone()];
                let __panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #fn_name(&mut #fixture_param_name, actions_vec);
                }));

                #mod_name::TOTAL_EXECUTIONS.fetch_add(1, Ordering::Relaxed);

                if #mod_name::COVERAGE_ENABLED.load(Ordering::Relaxed) {
                    let exec_count = #mod_name::TOTAL_EXECUTIONS.load(Ordering::Relaxed);
                    #mod_name::maybe_write_coverage(exec_count);
                }

                // Check for violation
                let violation = crucible_test_context::take_violation();

                if let Some(ref msg) = violation {
                    eprintln!("\n[STATEFUL W0] VIOLATION at iter {}: {}", local_iter, msg);
                    crucible_test_context::print_action_sequence();
                    crashes.fetch_add(1, Ordering::Relaxed);

                    let mut crash_bytes = {
                        let p = pool.read().unwrap();
                        p.reconstruct_action_sequence(state_idx)
                    };
                    if crash_bytes.len() >= 4 {
                        let old_count = u32::from_le_bytes(
                            crash_bytes[0..4].try_into().unwrap()
                        );
                        let new_count = old_count + 1;
                        crash_bytes[0..4].copy_from_slice(&new_count.to_le_bytes());
                        crash_bytes.extend_from_slice(&single_action_bytes);
                    }

                    let input_hash = libafl_bolts::hash_std(&crash_bytes);
                    crucible_test_context::write_crash_metadata(
                        &crash_dir, input_hash, Some(seed), &crash_bytes,
                    );

                    if stop_on_crash {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }

                // 6. Fingerprint + add to pool
                if violation.is_none() && __panic_result.is_ok() {
                    let history = crucible_test_context::get_action_history();
                    let action_succeeded = history.first().map(|r| r.success).unwrap_or(false);

                    if action_succeeded {
                        let fingerprint = compute_state_fingerprint(
                            &#fixture_param_name.ctx.svm,
                            &#fixture_param_name.ctx.dirty_tracker,
                            &pre_states,
                        );

                        if fingerprint != 0 {
                            let parent_snap = {
                                let p = pool.read().unwrap();
                                p.get(state_idx).unwrap().snapshot.clone()
                            };
                            let new_snapshot = SvmSnapshot::take_full(
                                &#fixture_param_name.ctx.svm,
                                &parent_snap,
                                &#fixture_param_name.ctx.dirty_tracker,
                            );

                            let mut p = pool.write().unwrap();
                            if p.try_add(
                                fingerprint,
                                new_snapshot,
                                parent_depth + 1,
                                Some(state_idx),
                                single_action_bytes,
                            ) {
                                novel.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }

                // 7. Swap SVM back out
                std::mem::swap(&mut #fixture_param_name.ctx.svm, &mut __real_svm);

                iters.fetch_add(1, Ordering::Relaxed);

                if let Err(__panic_payload) = __panic_result {
                    std::panic::resume_unwind(__panic_payload);
                }

                // 8. Rate-limited monitor output (worker 0 only)
                let now = std::time::Instant::now();
                if now.duration_since(last_print_time).as_millis() >= 2000 {
                    let elapsed_secs = now.duration_since(last_print_time).as_secs_f64();
                    let total_iters = iters.load(Ordering::Relaxed);
                    let iters_since = total_iters - last_print_iters;
                    let exec_sec = iters_since as f64 / elapsed_secs;

                    let total_crashes = crashes.load(Ordering::Relaxed);
                    let total_novel = novel.load(Ordering::Relaxed);

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

                    let pool_len = {
                        let p = pool.read().unwrap();
                        p.len()
                    };
                    let pool_pct = if pool_capacity > 0 {
                        (pool_len as f64 / pool_capacity as f64) * 100.0
                    } else { 0.0 };

                    eprintln!(
                        "[STATEFUL] iter: {}, exec/sec: {:.0}, pool: {}/{} ({:.1}%), \
                         novel: {}, crashes: {}, edges: {}/{} ({:.1}%), branches: {}/{}, workers: {}",
                        total_iters, exec_sec,
                        pool_len, pool_capacity, pool_pct,
                        total_novel, total_crashes,
                        edges, total_edges, edge_pct,
                        branches, total_branches,
                        num_cores,
                    );

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

        let total_iters = shared_iters.load(Ordering::Relaxed);
        let total_novel = shared_novel.load(Ordering::Relaxed);
        let total_crashes = shared_crashes.load(Ordering::Relaxed);
        let pool_len = state_pool.read().unwrap().len();
        eprintln!("\n[STATEFUL] Final stats: {} iterations, {} novel states, {} crashes, pool: {}",
            total_iters, total_novel, total_crashes, pool_len);
        std::process::exit(0);
    }
}
