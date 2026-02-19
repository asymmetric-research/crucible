//! Coverage tracking for the anchor-fuzz macro.
//!
//! This module contains all coverage-related code that gets generated into the
//! fuzz harness runtime module. The code here is returned as `quote!` blocks
//! that are embedded into the generated harness.

use quote::quote;

/// Constants for coverage map sizes
/// Note: These are only used in generated code, not at macro compile time
#[allow(dead_code)]
pub const MAP_SIZE: usize = 1 << 16;
#[allow(dead_code)]
pub const SHARED_EDGE_BITMAP_SIZE: usize = 1 << 16;   // 64KB = 512K bits for edges
#[allow(dead_code)]
pub const SHARED_BRANCH_BITMAP_SIZE: usize = 1 << 16; // 64KB = 512K bits for branches

/// Generate the coverage state struct and related statics
pub fn coverage_state_code() -> proc_macro2::TokenStream {
    quote! {
        pub const MAP_SIZE: usize = 1 << 16;
        pub const SHARED_EDGE_BITMAP_SIZE: usize = 1 << 16;    // 64KB = 512K bits for edges
        pub const SHARED_BRANCH_BITMAP_SIZE: usize = 1 << 16;  // 64KB = 512K bits for branches

        /// Mix bits thoroughly using xxhash-style finalization
        /// This ensures uniform distribution even for clustered inputs like BPF PCs
        #[inline]
        fn mix_hash(mut h: u64) -> u64 {
            h ^= h >> 33;
            h = h.wrapping_mul(0xff51afd7ed558ccd);
            h ^= h >> 33;
            h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
            h ^= h >> 33;
            h
        }

        /// Convert hitcount to AFL-style bucket (0-8)
        /// Different buckets trigger different bits in shared bitmap for corpus growth
        #[inline]
        fn to_bucket(count: u8) -> u8 {
            match count {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 3,
                4..=7 => 4,
                8..=15 => 5,
                16..=31 => 6,
                32..=127 => 7,
                _ => 8,
            }
        }

        /// Consolidated coverage state - uses Mutex instead of TLS.
        /// Single-threaded fuzzer means no contention, ~20ns lock overhead.
        #[derive(Default)]
        pub struct CoverageState {
            // HOT PATH - use FxHash for speed (10-50x faster than SipHash for integers)
            pub edges: crucible_test_context::FastHashMap<u64, crucible_test_context::FastHashSet<u64>>,
            pub branch_pcs: crucible_test_context::FastHashMap<u64, crucible_test_context::FastHashSet<usize>>,
            // LCOV branch tracking (only when --coverage enabled) - use FastHashMap for performance
            pub branch_outcomes: crucible_test_context::FastHashMap<u64, crucible_test_context::FastHashMap<(usize, bool), u64>>,
            // PC hit tracking for source-level LCOV (only when --coverage enabled)
            pub pc_hits: crucible_test_context::FastHashMap<u64, crucible_test_context::FastHashMap<usize, u64>>,
            pub last_write_iteration: u64,   // Iteration-based throttling (not time-based)
            pub last_coverage_count: usize,  // For smart batching
            // Cached totals for SimpleMonitor (avoid iterating all data)
            pub total_edges: usize,
            pub total_branches: usize,
        }

        pub static COVERAGE_STATE: LazyLock<Mutex<CoverageState>> = LazyLock::new(|| {
            Mutex::new(CoverageState::default())
        });

        // Coverage enabled flag (set by --coverage arg)
        pub static COVERAGE_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        // Multi-core mode: Track whether this iteration discovered new coverage in the shared bitmap.
        // This is set by flush_bitmap_updates when fetch_or returns a value without the bit set.
        // Reset at start of each iteration, checked by SharedBitmapFeedback.
        thread_local! {
            pub static NEW_COVERAGE_THIS_ITERATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }

        pub fn reset_new_coverage_flag() {
            NEW_COVERAGE_THIS_ITERATION.with(|f| f.set(false));
        }

        pub fn found_new_coverage() -> bool {
            NEW_COVERAGE_THIS_ITERATION.with(|f| f.get())
        }

        fn mark_new_coverage() {
            NEW_COVERAGE_THIS_ITERATION.with(|f| f.set(true));
        }

        // Thread-local buffers for bitmap updates to reduce atomic contention in multi-core mode.
        // Updates are accumulated locally and flushed periodically instead of on every transaction.
        thread_local! {
            pub static LOCAL_EDGE_BUFFER: std::cell::RefCell<Vec<(usize, u8)>> = const { std::cell::RefCell::new(Vec::new()) };
            pub static LOCAL_BRANCH_BUFFER: std::cell::RefCell<Vec<(usize, u8)>> = const { std::cell::RefCell::new(Vec::new()) };
        }

        /// Flush thread-local bitmap buffers to shared memory.
        /// Called periodically from the harness (e.g., every 50 iterations) to reduce atomic contention.
        pub fn flush_local_bitmap_buffers(shared_edge_ptr: *mut u8, shared_branch_ptr: *mut u8) {
            LOCAL_EDGE_BUFFER.with(|buf| {
                let mut buffer = buf.borrow_mut();
                if !buffer.is_empty() {
                    FuzzCallback::flush_bitmap_updates(shared_edge_ptr, &buffer, SHARED_EDGE_BITMAP_SIZE);
                    buffer.clear();
                }
            });
            LOCAL_BRANCH_BUFFER.with(|buf| {
                let mut buffer = buf.borrow_mut();
                if !buffer.is_empty() {
                    FuzzCallback::flush_bitmap_updates(shared_branch_ptr, &buffer, SHARED_BRANCH_BITMAP_SIZE);
                    buffer.clear();
                }
            });
        }

        /// Clear thread-local bitmap buffers without flushing (used when resetting for new iteration).
        pub fn clear_local_bitmap_buffers() {
            LOCAL_EDGE_BUFFER.with(|buf| buf.borrow_mut().clear());
            LOCAL_BRANCH_BUFFER.with(|buf| buf.borrow_mut().clear());
        }

        // Force-accept mode for initial corpus loading
        // When true, SharedBitmapFeedback always returns "interesting"
        thread_local! {
            pub static FORCE_INTERESTING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }

        pub fn set_force_interesting(value: bool) {
            FORCE_INTERESTING.with(|f| f.set(value));
        }

        pub fn is_force_interesting() -> bool {
            FORCE_INTERESTING.with(|f| f.get())
        }

        // Runtime stats tracking
        pub static FUZZER_START_TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        pub static TOTAL_EXECUTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        pub static TOTAL_ACTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        // Static storage for total edges per program (for percentage calculation)
        pub static PROGRAM_TOTALS: std::sync::OnceLock<HashMap<u64, usize>> = std::sync::OnceLock::new();
        // Static storage for total instructions per program
        pub static PROGRAM_TOTAL_INSTRUCTIONS: std::sync::OnceLock<HashMap<u64, usize>> = std::sync::OnceLock::new();
        // Static storage for program binaries (for LCOV function extraction)
        pub static PROGRAM_BINARIES: std::sync::OnceLock<HashMap<u64, Vec<u8>>> = std::sync::OnceLock::new();

        pub fn init_program_totals(edge_totals: HashMap<u64, usize>, instruction_totals: HashMap<u64, usize>) {
            let _ = PROGRAM_TOTALS.set(edge_totals);
            let _ = PROGRAM_TOTAL_INSTRUCTIONS.set(instruction_totals);
        }

        pub fn init_program_binaries(binaries: HashMap<u64, Vec<u8>>) {
            let _ = PROGRAM_BINARIES.set(binaries);
        }
    }
}

/// Generate the FuzzCallback struct and implementation
pub fn fuzz_callback_code() -> proc_macro2::TokenStream {
    quote! {
        pub struct FuzzCallback {
            ptr: *mut u8,
            len: usize,
            // Optional shared memory for multi-core edge/branch tracking (set before fork)
            shared_edge_bitmap: Option<*mut u8>,
            shared_branch_bitmap: Option<*mut u8>,
            // Flag to skip global state updates in multi-core mode (reduces lock contention)
            skip_global_state: bool,
        }

        unsafe impl Send for FuzzCallback {}
        unsafe impl Sync for FuzzCallback {}

        impl FuzzCallback {
            pub fn from_raw(ptr: *mut u8, len: usize) -> Self {
                Self {
                    ptr,
                    len,
                    shared_edge_bitmap: None,
                    shared_branch_bitmap: None,
                    skip_global_state: false,
                }
            }

            pub fn with_shared_memory(
                ptr: *mut u8,
                len: usize,
                shared_edge_bitmap: *mut u8,
                shared_branch_bitmap: *mut u8,
            ) -> Self {
                Self {
                    ptr,
                    len,
                    shared_edge_bitmap: Some(shared_edge_bitmap),
                    shared_branch_bitmap: Some(shared_branch_bitmap),
                    // In multi-core mode, skip global state tracking - shared bitmaps are the source of truth
                    skip_global_state: true,
                }
            }

            /// Fast path for small update sets (<=256 unique bytes) - uses stack allocation
            /// This reduces atomic operations from O(edges) to O(unique_bytes), typically 10-100x fewer
            #[inline]
            fn flush_bitmap_updates(bitmap: *mut u8, updates: &[(usize, u8)], bitmap_size: usize) {
                if updates.is_empty() {
                    return;
                }

                // Most transactions touch <256 unique bytes, so stack allocation is efficient
                let mut merged: [u8; 256] = [0u8; 256];
                let mut byte_positions: [usize; 256] = [usize::MAX; 256];
                let mut num_unique = 0usize;

                for &(byte_pos, mask) in updates {
                    if byte_pos >= bitmap_size {
                        continue;
                    }
                    // Linear scan for small N is faster than HashMap overhead
                    let mut found = false;
                    for i in 0..num_unique {
                        if byte_positions[i] == byte_pos {
                            merged[i] |= mask;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        if num_unique < 256 {
                            byte_positions[num_unique] = byte_pos;
                            merged[num_unique] = mask;
                            num_unique += 1;
                        } else {
                            // Overflow - fall back to large implementation
                            return Self::flush_bitmap_updates_large(bitmap, updates, bitmap_size);
                        }
                    }
                }

                // Apply updates with Relaxed ordering (safe for coverage tracking - no happens-before needed)
                unsafe {
                    for i in 0..num_unique {
                        let byte_ptr = bitmap.add(byte_positions[i]) as *const std::sync::atomic::AtomicU8;
                        let prev = (*byte_ptr).fetch_or(merged[i], std::sync::atomic::Ordering::Relaxed);
                        if (prev & merged[i]) != merged[i] {
                            mark_new_coverage();
                        }
                    }
                }
            }

            /// Slow path for large update sets (>256 unique bytes) - uses HashMap
            #[inline]
            fn flush_bitmap_updates_large(bitmap: *mut u8, updates: &[(usize, u8)], bitmap_size: usize) {
                let mut merged: crucible_test_context::FastHashMap<usize, u8> =
                    crucible_test_context::FastHashMap::default();
                merged.reserve(updates.len() / 4);

                for &(byte_pos, mask) in updates {
                    if byte_pos < bitmap_size {
                        *merged.entry(byte_pos).or_insert(0) |= mask;
                    }
                }

                unsafe {
                    for (byte_pos, mask) in merged {
                        let byte_ptr = bitmap.add(byte_pos) as *const std::sync::atomic::AtomicU8;
                        let prev = (*byte_ptr).fetch_or(mask, std::sync::atomic::Ordering::Relaxed);
                        if (prev & mask) != mask {
                            mark_new_coverage();
                        }
                    }
                }
            }

            /// Count set bits in a shared bitmap (for monitor display)
            /// Uses volatile reads to avoid cache-line contention with workers doing atomic writes
            pub fn count_shared_bits(bitmap: *const u8, size: usize) -> usize {
                let mut count = 0usize;
                unsafe {
                    // Process 8 bytes at a time using u64 for better performance
                    let mut i = 0usize;
                    while i + 8 <= size {
                        let val = std::ptr::read_volatile(bitmap.add(i) as *const u64);
                        count += val.count_ones() as usize;
                        i += 8;
                    }
                    // Handle remaining bytes
                    while i < size {
                        let val = std::ptr::read_volatile(bitmap.add(i));
                        count += val.count_ones() as usize;
                        i += 1;
                    }
                }
                count
            }

            /// Process pre-filtered branch edges and PC hits for coverage tracking
            ///
            /// Performance optimizations for multi-core mode:
            /// 1. Skip global COVERAGE_STATE updates (shared bitmaps are source of truth)
            /// 2. Batch atomic bitmap updates to reduce cache-line bouncing
            fn process_trace(
                &self,
                program_id: &crucible_test_context::fuzz_types::Pubkey,
                branch_edges: &[(usize, usize)],
                visited_pcs: &[usize],
            ) {
                if branch_edges.is_empty() && visited_pcs.is_empty() {
                    return;
                }

                // Include program ID to distinguish same-PC edges across programs
                let program_hash = u64::from_le_bytes(
                    program_id.to_bytes()[0..8].try_into().unwrap()
                );

                // Batch updates for shared bitmaps (multi-core mode)
                let mut edge_bitmap_updates: Vec<(usize, u8)> = Vec::new();
                let mut branch_bitmap_updates: Vec<(usize, u8)> = Vec::new();

                // Only allocate local sets if we're updating global state (single-core mode)
                let mut local_branch_pcs: crucible_test_context::FastHashSet<usize> = if self.skip_global_state {
                    crucible_test_context::FastHashSet::default()
                } else {
                    let mut set = crucible_test_context::FastHashSet::default();
                    set.reserve(branch_edges.len());
                    set
                };
                let mut local_edges: crucible_test_context::FastHashSet<u64> = if self.skip_global_state {
                    crucible_test_context::FastHashSet::default()
                } else {
                    let mut set = crucible_test_context::FastHashSet::default();
                    set.reserve(branch_edges.len());
                    set
                };

                // AFL-style edge tracking with prev_location state
                let mut prev_location: usize = 0;

                for &(pc, target_pc) in branch_edges {
                    // Fibonacci hash for better distribution with BPF's small PC range
                    // Combines full (source, target) edge info with golden ratio multiplier
                    let edge_id = ((pc as u64) << 32) | (target_pc as u64);
                    let cur_location = ((edge_id.wrapping_mul(0x9e3779b97f4a7c15)) >> 48) as usize;
                    let edge = (cur_location ^ prev_location) % MAP_SIZE;
                    prev_location = cur_location >> 1;

                    unsafe {
                        // Write to coverage map (must be done inline for AFL compatibility)
                        let buf = std::slice::from_raw_parts_mut(self.ptr, self.len);
                        buf[edge] = buf[edge].wrapping_add(1);
                    }

                    // Multi-core mode: batch updates to shared bitmaps
                    // Edge bitmap is split into two halves:
                    // - First half (bits 0..256K): edge presence (counted for display)
                    // - Second half (bits 256K..512K): hitcount buckets (for corpus growth only)
                    if let Some(edge_bitmap) = self.shared_edge_bitmap {
                        // Half the bitmap size for each purpose
                        let half_bits = (SHARED_EDGE_BITMAP_SIZE * 8) / 2;

                        // Edge presence bit (first half) - for accurate edge count display
                        let bit_idx = (mix_hash(edge_id) as usize) % half_bits;
                        let byte_pos = bit_idx / 8;
                        let bit_pos = bit_idx % 8;
                        edge_bitmap_updates.push((byte_pos, 1u8 << bit_pos));

                        // Hitcount bucket bit (second half) - for corpus growth
                        // Only track buckets > 1 (bucket 1 is already covered by edge discovery)
                        let hitcount = unsafe {
                            let buf = std::slice::from_raw_parts(self.ptr, self.len);
                            buf[edge]
                        };
                        let bucket = to_bucket(hitcount);
                        if bucket > 1 {
                            let combined = edge_id ^ ((bucket as u64) << 56);
                            // Offset into second half of bitmap
                            let bucket_bit_idx = half_bits + ((mix_hash(combined) as usize) % half_bits);
                            let bucket_byte_pos = bucket_bit_idx / 8;
                            let bucket_bit_pos = bucket_bit_idx % 8;
                            edge_bitmap_updates.push((bucket_byte_pos, 1u8 << bucket_bit_pos));
                        }
                    }

                    if let Some(branch_bitmap) = self.shared_branch_bitmap {
                        // Use mix_hash for branch PC too
                        let mixed = mix_hash((program_hash << 32) | (pc as u64));
                        let bit_idx = (mixed as usize) % (SHARED_BRANCH_BITMAP_SIZE * 8);
                        let byte_pos = bit_idx / 8;
                        let bit_pos = bit_idx % 8;
                        branch_bitmap_updates.push((byte_pos, 1u8 << bit_pos));
                    }

                    // Single-core mode: collect for global state
                    if !self.skip_global_state {
                        let unique_edge = ((pc as u64) << 32) | (target_pc as u64);
                        local_edges.insert(unique_edge);
                        local_branch_pcs.insert(pc);
                    }
                }

                // Multi-core mode: accumulate updates in thread-local buffers
                // Buffers are flushed periodically from the harness to reduce atomic contention
                if self.shared_edge_bitmap.is_some() {
                    LOCAL_EDGE_BUFFER.with(|buf| {
                        buf.borrow_mut().extend(edge_bitmap_updates.iter().cloned());
                    });
                }
                if self.shared_branch_bitmap.is_some() {
                    LOCAL_BRANCH_BUFFER.with(|buf| {
                        buf.borrow_mut().extend(branch_bitmap_updates.iter().cloned());
                    });
                }

                // Skip global state updates in multi-core mode (shared bitmaps are source of truth)
                if self.skip_global_state {
                    return;
                }

                // Update global state (single-core mode only)
                let mut state = COVERAGE_STATE.lock().unwrap();

                // Track edges and update cached total
                let edge_set = state.edges.entry(program_hash).or_default();
                let old_edge_count = edge_set.len();
                edge_set.extend(&local_edges);
                state.total_edges += edge_set.len() - old_edge_count;

                // Track branch PCs and update cached total
                let branch_set = state.branch_pcs.entry(program_hash).or_default();
                let old_branch_count = branch_set.len();
                branch_set.extend(&local_branch_pcs);
                state.total_branches += branch_set.len() - old_branch_count;

                // Track branch outcomes and PC hits for LCOV (only when --coverage enabled)
                if COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                    let program_outcomes = state.branch_outcomes.entry(program_hash).or_default();
                    for &(pc, target_pc) in branch_edges {
                        // taken = jump target is not the fall-through (pc + 8)
                        let taken = target_pc != pc + 8;
                        *program_outcomes.entry((pc, taken)).or_insert(0) += 1;
                    }

                    // Track all visited PC addresses for source-level LCOV
                    let program_pc_hits = state.pc_hits.entry(program_hash).or_default();
                    for &pc in visited_pcs {
                        *program_pc_hits.entry(pc).or_insert(0) += 1;
                    }
                }
            }
        }
    }
}

/// Generate the InvocationInspectCallback implementation for FuzzCallback
pub fn invocation_callback_impl_code() -> proc_macro2::TokenStream {
    quote! {
        impl crucible_test_context::InvocationInspectCallback for FuzzCallback {
            fn before_invocation(
                &self,
                _tx: &crucible_test_context::fuzz_types::SanitizedTransaction,
                _program_indices: &[crucible_test_context::fuzz_types::IndexOfAccount],
                _invoke_context: &crucible_test_context::fuzz_types::InvokeContext,
            ) {
                // No-op: coverage tracked in after_invocation
            }

            fn after_invocation(
                &self,
                invoke_context: &crucible_test_context::fuzz_types::InvokeContext,
                register_tracing_enabled: bool,
            ) {
                if register_tracing_enabled {
                    let coverage_enabled = COVERAGE_ENABLED.load(std::sync::atomic::Ordering::Relaxed);

                    invoke_context.iterate_vm_traces(
                        &|instruction_context,
                          executable,
                          register_trace| {
                            if let Ok(program_id) = instruction_context.get_program_key() {
                                use crucible_test_context::fuzz_types::ebpf;

                                let (_vm_addr, program) = executable.get_text_bytes();

                                // Pre-filter: extract only (branch_pc, target_pc) pairs
                                let mut branch_edges: Vec<(usize, usize)> = Vec::with_capacity(register_trace.len() / 8);

                                // Collect all visited PCs for source-level LCOV (only when coverage enabled)
                                let mut visited_pcs: Vec<usize> = if coverage_enabled {
                                    Vec::with_capacity(register_trace.len())
                                } else {
                                    Vec::new()
                                };

                                for i in 0..register_trace.len().saturating_sub(1) {
                                    let pc = register_trace[i][11] as usize;

                                    // Collect all PCs for source-level coverage
                                    if coverage_enabled {
                                        visited_pcs.push(pc);
                                    }

                                    let insn = ebpf::get_insn_unchecked(program, pc);

                                    // Only conditional branches
                                    let is_jmp_class = insn.opc & 7 == ebpf::BPF_JMP;
                                    if !is_jmp_class { continue; }

                                    let opc = insn.opc;
                                    if opc == 0x05 || opc == 0x85 || opc == 0x8d || opc == 0x95 { continue; }

                                    let target_pc = register_trace[i + 1][11] as usize;
                                    branch_edges.push((pc, target_pc));
                                }

                                // Also add the last PC if we have any trace data
                                if coverage_enabled && !register_trace.is_empty() {
                                    let last_pc = register_trace[register_trace.len() - 1][11] as usize;
                                    visited_pcs.push(last_pc);
                                }

                                self.process_trace(program_id, &branch_edges, &visited_pcs);
                            }
                        },
                    );
                }
            }
        }
    }
}

/// Generate the SharedBitmapFeedback struct for multi-core mode
pub fn shared_bitmap_feedback_code() -> proc_macro2::TokenStream {
    quote! {
        /// Custom feedback for multi-core mode that uses the shared bitmap as source of truth.
        ///
        /// Unlike MaxMapFeedback (which has per-worker virgin maps), this feedback checks
        /// whether any NEW bits were set in the shared bitmap during this iteration.
        /// This prevents N× corpus duplication across workers.
        ///
        /// The shared bitmap is updated atomically during harness execution (in FuzzCallback::flush_bitmap_updates).
        /// That function sets NEW_COVERAGE_THIS_ITERATION when it successfully sets a new bit.
        pub struct SharedBitmapFeedback {
            name: std::borrow::Cow<'static, str>,
        }

        impl SharedBitmapFeedback {
            pub fn new() -> Self {
                Self {
                    name: std::borrow::Cow::Borrowed("shared_bitmap"),
                }
            }
        }

        impl<S> libafl::feedbacks::StateInitializer<S> for SharedBitmapFeedback {
            fn init_state(&mut self, _state: &mut S) -> std::result::Result<(), libafl::Error> {
                Ok(())
            }
        }

        impl<EM, I, OT, S> libafl::feedbacks::Feedback<EM, I, OT, S> for SharedBitmapFeedback {
            fn is_interesting(
                &mut self,
                _state: &mut S,
                _manager: &mut EM,
                _input: &I,
                _observers: &OT,
                _exit_kind: &libafl::prelude::ExitKind,
            ) -> std::result::Result<bool, libafl::Error> {
                // During initial corpus loading, force-accept all inputs
                if is_force_interesting() {
                    return Ok(true);
                }
                // Check if any new bits were set in the shared bitmap during this iteration
                Ok(found_new_coverage())
            }
        }

        impl libafl_bolts::Named for SharedBitmapFeedback {
            fn name(&self) -> &std::borrow::Cow<'static, str> {
                &self.name
            }
        }
    }
}

/// Generate the LCOV coverage writing functions
pub fn lcov_coverage_code() -> proc_macro2::TokenStream {
    quote! {
        /// Write LCOV coverage file to disk
        ///
        /// Tries source-level coverage first (using DWARF debug info),
        /// falls back to bytecode-level if no debug info is available.
        pub fn write_lcov_coverage(output_path: &str) {
            use std::fs::File;
            use std::io::{BufWriter, Write};

            let file = match File::create(output_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[LCOV] Failed to create {}: {}", output_path, e);
                    return;
                }
            };
            let mut writer = BufWriter::new(file);

            // Get coverage data from state
            let state = COVERAGE_STATE.lock().unwrap();
            let branch_outcomes = state.branch_outcomes.clone();
            let pc_hits = state.pc_hits.clone();
            drop(state); // Release lock before file I/O

            if branch_outcomes.is_empty() && pc_hits.is_empty() {
                eprintln!("[LCOV] No coverage data to write");
                return;
            }

            let program_binaries = PROGRAM_BINARIES.get();
            let edge_totals = PROGRAM_TOTALS.get();
            let instr_totals = PROGRAM_TOTAL_INSTRUCTIONS.get();

            let mut programs_written = 0usize;

            // Get all program hashes (union of branch_outcomes and pc_hits keys)
            let mut all_programs: std::collections::HashSet<u64> = branch_outcomes.keys().copied().collect();
            all_programs.extend(pc_hits.keys());

            for prog_hash in all_programs {
                let program_name = format!("program_{:016x}", prog_hash);

                let outcomes = branch_outcomes.get(&prog_hash)
                    .cloned()
                    .unwrap_or_default();
                let hits = pc_hits.get(&prog_hash)
                    .cloned()
                    .unwrap_or_default();

                let program_data = program_binaries
                    .and_then(|b| b.get(&prog_hash))
                    .map(|v| v.as_slice());

                let functions = program_data
                    .and_then(|data| crucible_test_context::extract_functions(data))
                    .unwrap_or_default();

                let total_edges = edge_totals.and_then(|t| t.get(&prog_hash).copied()).unwrap_or(0);
                let total_branches = total_edges / 2;
                let total_instructions = instr_totals.and_then(|t| t.get(&prog_hash).copied()).unwrap_or(0);

                if let Err(e) = crucible_test_context::generate_bytecode_lcov(
                    &mut writer,
                    &program_name,
                    &hits,
                    &outcomes,
                    &functions,
                    total_instructions,
                    total_branches,
                ) {
                    eprintln!("[LCOV] Error writing coverage for {}: {}", program_name, e);
                } else {
                    programs_written += 1;
                }
            }

            // Explicitly flush and sync to ensure data is written before process exit
            if let Err(e) = writer.flush() {
                eprintln!("[LCOV] Error flushing buffer: {}", e);
            }
            // Get inner file and sync to disk
            let file = writer.into_inner().expect("Failed to get inner file");
            if let Err(e) = file.sync_all() {
                eprintln!("[LCOV] Error syncing file: {}", e);
            }

            eprintln!("[LCOV] Coverage written to {} ({} programs, {} lines, {} branches)",
                output_path,
                programs_written,
                pc_hits.values().map(|h| h.len()).sum::<usize>(),
                branch_outcomes.values().map(|h| h.len()).sum::<usize>());
        }

        /// Write coverage files every 5000 iterations when new coverage is discovered.
        /// Uses iteration-based throttling (no syscalls) instead of wall-clock time.
        /// Note: Caller should check COVERAGE_ENABLED before calling this function
        pub fn maybe_write_coverage(exec_count: u64) {
            // Iteration-based throttling: only check every 5000 iterations
            if exec_count % 5000 != 0 {
                return;
            }

            // Check if new coverage was discovered (use cached totals)
            let mut state = COVERAGE_STATE.lock().unwrap();
            let current_coverage_count = state.total_edges;
            let has_new_coverage = current_coverage_count > state.last_coverage_count;

            if has_new_coverage {
                // Update coverage count
                state.last_coverage_count = current_coverage_count;
                drop(state); // Release lock before file I/O

                // Write LCOV when new coverage is found
                write_lcov_coverage("coverage.lcov");
            }
        }
    }
}

/// Generate the success pattern TLS and SuccessPatternFeedback for action-level success tracking
pub fn success_pattern_code() -> proc_macro2::TokenStream {
    quote! {
        // Thread-local storage for the success pattern of the last harness iteration.
        // Set by the harness wrapper after executing actions, read by SuccessPatternFeedback.
        thread_local! {
            static LAST_SUCCESS_PATTERN: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) };
        }

        /// Set the success pattern for the current iteration (called from harness wrapper)
        pub fn set_success_pattern(pattern: Vec<bool>) {
            LAST_SUCCESS_PATTERN.with(|p| *p.borrow_mut() = pattern);
        }

        /// Get the success pattern from the current iteration (called by SuccessPatternFeedback)
        pub fn get_success_pattern() -> Vec<bool> {
            LAST_SUCCESS_PATTERN.with(|p| p.borrow().clone())
        }

        /// Feedback that attaches success pattern metadata to corpus entries.
        ///
        /// This feedback never causes corpus admission on its own (is_interesting returns false).
        /// It only appends `SuccessPatternMetadata` to testcases that are admitted by other
        /// feedbacks (e.g., MaxMapFeedback or SharedBitmapFeedback).
        ///
        /// The metadata is later read by `SuccessTrimStage` to strip failed actions.
        pub struct SuccessPatternFeedback {
            name: std::borrow::Cow<'static, str>,
        }

        impl SuccessPatternFeedback {
            pub fn new() -> Self {
                Self {
                    name: std::borrow::Cow::Borrowed("success_pattern"),
                }
            }
        }

        impl<S> libafl::feedbacks::StateInitializer<S> for SuccessPatternFeedback {
            fn init_state(&mut self, _state: &mut S) -> std::result::Result<(), libafl::Error> {
                Ok(())
            }
        }

        impl<EM, I, OT, S> libafl::feedbacks::Feedback<EM, I, OT, S> for SuccessPatternFeedback {
            fn is_interesting(
                &mut self,
                _state: &mut S,
                _manager: &mut EM,
                _input: &I,
                _observers: &OT,
                _exit_kind: &libafl::prelude::ExitKind,
            ) -> std::result::Result<bool, libafl::Error> {
                // Never causes corpus admission on its own
                Ok(false)
            }

            fn append_metadata(
                &mut self,
                _state: &mut S,
                _manager: &mut EM,
                _observers: &OT,
                testcase: &mut libafl::corpus::Testcase<I>,
            ) -> std::result::Result<(), libafl::Error> {
                use libafl::HasMetadata;
                let pattern = get_success_pattern();
                if !pattern.is_empty() {
                    testcase.add_metadata(crucible_fuzzer::SuccessPatternMetadata { pattern });
                }
                Ok(())
            }
        }

        impl libafl_bolts::Named for SuccessPatternFeedback {
            fn name(&self) -> &std::borrow::Cow<'static, str> {
                &self.name
            }
        }
    }
}

/// Generate all coverage-related code for the runtime module
pub fn all_coverage_code() -> proc_macro2::TokenStream {
    let state_code = coverage_state_code();
    let callback_code = fuzz_callback_code();
    let callback_impl = invocation_callback_impl_code();
    let feedback_code = shared_bitmap_feedback_code();
    let lcov_code = lcov_coverage_code();
    let success_pattern = success_pattern_code();

    quote! {
        #state_code
        #callback_code
        #callback_impl
        #feedback_code
        #lcov_code
        #success_pattern
    }
}
