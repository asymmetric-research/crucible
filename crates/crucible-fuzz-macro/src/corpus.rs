//! Corpus management for the anchor-fuzz macro.
//!
//! This module contains code generation for corpus-related operations:
//! - Corpus minimization (cmin mode)
//! - Corpus loading utilities

use quote::quote;

use crate::codegen;

/// Generate the corpus minimization mode code
pub fn cmin_mode(
    mod_name: &syn::Ident,
    fixture_name: &syn::Ident,
    fn_name: &syn::Ident,
    simple_deser_stmts: &[proc_macro2::TokenStream],
    call_args: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    let init_coverage_totals = codegen::init_coverage_totals(mod_name);

    // The simple_deser_stmts may reference either `u` (Unstructured) or `__raw_bytes` (structured)
    // We create both and let the stmts use whichever they need
    let deser_block = quote! {
        let __raw_bytes = input_bytes.clone();
        let mut u = arbitrary::Unstructured::new(&input_bytes);
        #(#simple_deser_stmts)*
    };

    quote! {
        // === CORPUS MINIMIZATION MODE (CMIN) ===
        // Run each input once to collect coverage, then use greedy set-cover
        // to find minimum set of inputs that preserve all coverage
        if cmin_mode {
            let corpus_dir = match &corpus_in_dir {
                Some(dir) => dir.clone(),
                None => {
                    eprintln!("[CMIN] Error: FUZZ_CORPUS_IN required for cmin mode");
                    std::process::exit(1);
                }
            };

            let corpus_out = corpus_out_dir.clone().unwrap_or_else(|| corpus_dir.clone());

            eprintln!("[CMIN] Minimizing corpus from: {}", corpus_dir);
            eprintln!("[CMIN] Output directory: {}", corpus_out);

            // Collect input files (excluding metadata)
            let mut input_files: Vec<_> = match std::fs::read_dir(&corpus_dir) {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let path = e.path();
                        path.is_file() && is_corpus_input(&path)
                    })
                    .map(|e| e.path())
                    .collect(),
                Err(e) => {
                    eprintln!("[CMIN] Failed to read corpus directory: {}", e);
                    std::process::exit(1);
                }
            };

            // Sort by file size (prefer smaller inputs for tie-breaking)
            input_files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(u64::MAX));

            eprintln!("[CMIN] Found {} input files", input_files.len());

            if input_files.is_empty() {
                eprintln!("[CMIN] No input files found in corpus directory");
                std::process::exit(1);
            }

            // Setup tracing for coverage
            std::env::set_var("ANCHOR_FUZZ_DEBUGGABLE", "1");

            // Run setup
            let template_fixture = #fixture_name::setup();

            // Initialize coverage totals
            { #init_coverage_totals }

            // Data structure: for each input, track which edges it covers
            // edges_per_input[i] = set of edge IDs covered by input i
            let mut edges_per_input: Vec<std::collections::HashSet<u64>> = Vec::with_capacity(input_files.len());
            let mut input_paths: Vec<std::path::PathBuf> = Vec::with_capacity(input_files.len());

            // Phase 1: Execute each input and record coverage
            eprintln!("[CMIN] Phase 1: Collecting coverage from {} inputs...", input_files.len());
            let start_time = std::time::Instant::now();

            for (idx, path) in input_files.iter().enumerate() {
                let input_bytes = match std::fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[CMIN] Failed to read {}: {}", path.display(), e);
                        continue;
                    }
                };

                // Reset coverage map for this input
                unsafe {
                    std::ptr::write_bytes(cov_ptr, 0, #mod_name::MAP_SIZE);
                }

                // Create fresh fixture for each input
                // Use set_invocation_callback to avoid double SVM clone (critical for performance)
                let callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                let mut fixture = template_fixture.clone();
                fixture.ctx.set_invocation_callback(callback);

                // Run the test in a closure to handle deserialization failures
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #deser_block
                    #fn_name(#(#call_args),*);
                }));

                // Clear any violation flag
                let _ = crucible_test_context::take_violation();

                // Collect edges hit by this input from the coverage map
                let mut edges: std::collections::HashSet<u64> = std::collections::HashSet::new();
                unsafe {
                    let map = std::slice::from_raw_parts(cov_ptr, #mod_name::MAP_SIZE);
                    for (edge_idx, &count) in map.iter().enumerate() {
                        if count > 0 {
                            edges.insert(edge_idx as u64);
                        }
                    }
                }

                if !edges.is_empty() {
                    edges_per_input.push(edges);
                    input_paths.push(path.clone());
                }

                if (idx + 1) % 50 == 0 {
                    eprintln!("[CMIN] Processed {}/{} inputs...", idx + 1, input_files.len());
                }
            }

            let phase1_time = start_time.elapsed();
            eprintln!("[CMIN] Phase 1 complete: {} inputs with coverage in {:.1}s",
                edges_per_input.len(), phase1_time.as_secs_f64());

            // Collect all unique edges
            let mut all_edges: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for edges in &edges_per_input {
                all_edges.extend(edges);
            }
            eprintln!("[CMIN] Total unique edges: {}", all_edges.len());

            // Phase 2: Greedy set-cover algorithm
            eprintln!("[CMIN] Phase 2: Computing minimum corpus...");

            let mut uncovered: std::collections::HashSet<u64> = all_edges.clone();
            let mut selected: Vec<usize> = Vec::new();
            let mut used: Vec<bool> = vec![false; edges_per_input.len()];

            while !uncovered.is_empty() {
                // Find input that covers the most uncovered edges
                // (ties broken by file size - smaller inputs sorted first)
                let mut best_idx = None;
                let mut best_count = 0usize;

                for (idx, edges) in edges_per_input.iter().enumerate() {
                    if used[idx] { continue; }

                    let new_coverage = edges.iter().filter(|e| uncovered.contains(e)).count();
                    if new_coverage > best_count {
                        best_count = new_coverage;
                        best_idx = Some(idx);
                    }
                }

                match best_idx {
                    Some(idx) => {
                        used[idx] = true;
                        selected.push(idx);
                        for edge in &edges_per_input[idx] {
                            uncovered.remove(edge);
                        }
                    }
                    None => break, // No more inputs can cover remaining edges
                }
            }

            eprintln!("[CMIN] Selected {} inputs (reduced from {})",
                selected.len(), edges_per_input.len());

            // Phase 3: Copy selected inputs to output directory
            if corpus_out != corpus_dir {
                std::fs::create_dir_all(&corpus_out).ok();
            }

            let mut copied = 0usize;
            for idx in &selected {
                let src_path = &input_paths[*idx];
                let filename = src_path.file_name().unwrap_or_default();
                let dst_path = std::path::Path::new(&corpus_out).join(filename);

                if corpus_out == corpus_dir {
                    // In-place: mark as kept (will delete others later)
                    copied += 1;
                } else {
                    // Different directory: copy file
                    if std::fs::copy(src_path, &dst_path).is_ok() {
                        copied += 1;
                    }
                }
            }

            // If in-place minimization, remove non-selected files
            if corpus_out == corpus_dir {
                let selected_set: std::collections::HashSet<_> = selected.iter()
                    .map(|&idx| input_paths[idx].clone())
                    .collect();

                let mut removed = 0usize;
                for path in &input_files {
                    if !selected_set.contains(path) {
                        if std::fs::remove_file(path).is_ok() {
                            removed += 1;
                        }
                    }
                }
                eprintln!("[CMIN] Removed {} redundant inputs", removed);
            }

            let total_time = start_time.elapsed();
            eprintln!("[CMIN] Complete! {} -> {} inputs ({:.1}% reduction) in {:.1}s",
                input_files.len(),
                selected.len(),
                (1.0 - (selected.len() as f64 / input_files.len() as f64)) * 100.0,
                total_time.as_secs_f64());
            eprintln!("[CMIN] Output: {}", corpus_out);

            std::process::exit(0);
        }
    }
}

/// Generate the code for loading inputs from a directory into memory (pre-fork)
/// Returns a Vec<BytesInput> that can be passed to workers
pub fn load_inputs_into_memory() -> proc_macro2::TokenStream {
    quote! {
        /// Load all corpus inputs from a directory into memory
        fn load_inputs_from_dir(corpus_dir: &str) -> Vec<BytesInput> {
            let mut inputs = Vec::new();
            if let Ok(entries) = std::fs::read_dir(corpus_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() && is_corpus_input(&path) {
                        if let Ok(bytes) = std::fs::read(&path) {
                            inputs.push(BytesInput::new(bytes));
                        }
                    }
                }
            }
            inputs
        }
    }
}
