//! Corpus management: cmin mode and corpus loading utilities.

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
        // Stream the corpus once tracking the best input per edge, re-run only
        // those winners, then greedy set-cover drops the redundant ones.
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

            let corpus_path = std::path::Path::new(&corpus_dir);

            let input_count = match crucible_fuzzer::cmin::corpus_dir::count_inputs(corpus_path, is_corpus_input) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[CMIN] Failed to read corpus directory: {}", e);
                    std::process::exit(1);
                }
            };

            eprintln!("[CMIN] Found {} input files", input_count);

            if input_count == 0 {
                eprintln!("[CMIN] No input files found in corpus directory");
                std::process::exit(1);
            }

            std::env::set_var("CRUCIBLE_FUZZ_DEBUGGABLE", "1");

            let template_fixture = #fixture_name::setup();

            { #init_coverage_totals }

            let run_input = |input_bytes: Vec<u8>| -> crucible_test_context::FastHashSet<u64> {
                unsafe {
                    std::ptr::write_bytes(cov_ptr, 0, #mod_name::MAP_SIZE);
                }

                // Use set_invocation_callback to avoid double SVM clone (critical for performance)
                let mut callback = #mod_name::FuzzCallback::from_raw(cov_ptr, #mod_name::MAP_SIZE);
                // Skip global COVERAGE_STATE lock — cmin doesn't use it
                callback.set_skip_global_state(true);
                let mut fixture = template_fixture.clone();
                fixture.ctx.set_invocation_callback(callback);

                // Exact (pc, target_pc) edge tracking, immune to u8 wrapping and AFL map index inflation
                #mod_name::cmin_edge_set_enable();

                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #deser_block
                    #fn_name(#(#call_args),*);
                }));

                let _ = crucible_test_context::take_violation();

                #mod_name::cmin_edge_set_take().unwrap_or_default()
            };

            // Phase 1: stream every input, keeping only the best input per edge
            eprintln!("[CMIN] Phase 1: Collecting coverage from {} inputs...", input_count);
            let start_time = std::time::Instant::now();

            let input_paths = match crucible_fuzzer::cmin::corpus_dir::input_paths(corpus_path, is_corpus_input) {
                Ok(paths) => paths,
                Err(e) => {
                    eprintln!("[CMIN] Failed to read corpus directory: {}", e);
                    std::process::exit(1);
                }
            };

            let mut winners = crucible_fuzzer::cmin::winners::WinnerTable::new();

            for (idx, path) in input_paths.enumerate() {
                let input_bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[CMIN] Failed to read {}: {}", path.display(), e);
                        continue;
                    }
                };

                let size = input_bytes.len() as u64;
                let edges = run_input(input_bytes);
                if let Some(name) = path.file_name() {
                    winners.offer(name, size, edges);
                }

                if (idx + 1) % 50 == 0 {
                    eprintln!("[CMIN] Processed {}/{} inputs...", idx + 1, input_count);
                }
            }

            eprintln!("[CMIN] Phase 1 complete: {} candidate inputs in {:.1}s",
                winners.live_winners(), start_time.elapsed().as_secs_f64());
            eprintln!("[CMIN] Total unique edges: {}", winners.edge_count());

            let candidates = winners.winners();

            // Phase 2: re-run the winners to recover their edge sets
            eprintln!("[CMIN] Phase 2: Re-running {} candidate inputs...", candidates.len());

            let mut edges_per_input: Vec<std::collections::HashSet<u64>> = Vec::with_capacity(candidates.len());
            let mut input_names: Vec<std::ffi::OsString> = Vec::with_capacity(candidates.len());

            for candidate in &candidates {
                let path = corpus_path.join(&candidate.name);
                let input_bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("[CMIN] Failed to read {}: {}", path.display(), e);
                        continue;
                    }
                };

                let edges: std::collections::HashSet<u64> = run_input(input_bytes).into_iter().collect();
                if !edges.is_empty() {
                    edges_per_input.push(edges);
                    input_names.push(candidate.name.clone());
                }
            }

            let mut rerun_edges: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for edges in &edges_per_input {
                rerun_edges.extend(edges);
            }
            // A nondeterministic harness can hit an edge in phase 1 and miss it here, losing it
            let missing = winners.edges().filter(|e| !rerun_edges.contains(e)).count();
            if missing > 0 {
                eprintln!("[CMIN] Warning: {} edges not reproduced on re-run", missing);
            }
            drop(winners);

            // Phase 3: Greedy set-cover over the winners
            eprintln!("[CMIN] Phase 3: Computing minimum corpus...");

            let cmin_result = crucible_fuzzer::cmin::greedy_set_cover(&edges_per_input);
            let selected = cmin_result.selected;

            eprintln!("[CMIN] Selected {} inputs (reduced from {})",
                selected.len(), edges_per_input.len());

            // Phase 4: write the output
            if corpus_out != corpus_dir {
                std::fs::create_dir_all(&corpus_out)
                    .unwrap_or_else(|e| panic!("[CMIN] Failed to create output directory {}: {}", corpus_out, e));

                for idx in &selected {
                    let name = &input_names[*idx];
                    let dst_path = std::path::Path::new(&corpus_out).join(name);
                    let _ = std::fs::copy(corpus_path.join(name), &dst_path);
                }
            } else {
                let keep: std::collections::HashSet<std::ffi::OsString> = selected.iter()
                    .map(|&idx| input_names[idx].clone())
                    .collect();

                match crucible_fuzzer::cmin::corpus_dir::remove_unselected(corpus_path, is_corpus_input, &keep) {
                    Ok(removed) => eprintln!("[CMIN] Removed {} redundant inputs", removed),
                    Err(e) => {
                        eprintln!("[CMIN] Failed to read corpus directory: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            let total_time = start_time.elapsed();
            eprintln!("[CMIN] Complete! {} -> {} inputs ({:.1}% reduction) in {:.1}s",
                input_count,
                selected.len(),
                (1.0 - (selected.len() as f64 / input_count as f64)) * 100.0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use quote::format_ident;

    fn ts(tokens: proc_macro2::TokenStream) -> String {
        tokens.to_string()
    }

    #[test]
    fn cmin_mode_has_greedy_set_cover() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(cmin_mode(&mod_name, &fixture, &fn_name, &[], &[]));
        assert!(
            output.contains("greedy_set_cover"),
            "should use greedy set cover algorithm"
        );
        assert!(output.contains("cmin_mode"), "should check cmin_mode flag");
        assert!(
            output.contains("corpus_in_dir"),
            "should require corpus input dir"
        );
    }

    #[test]
    fn cmin_mode_uses_exact_edge_tracking() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(cmin_mode(&mod_name, &fixture, &fn_name, &[], &[]));
        assert!(
            output.contains("cmin_edge_set_enable"),
            "should enable exact edge tracking"
        );
        assert!(
            output.contains("cmin_edge_set_take"),
            "should take edge set after execution"
        );
    }

    #[test]
    fn cmin_mode_panics_on_bad_output_dir() {
        let mod_name = format_ident!("__fuzz_mod");
        let fixture = format_ident!("TestFixture");
        let fn_name = format_ident!("test_fn");
        let output = ts(cmin_mode(&mod_name, &fixture, &fn_name, &[], &[]));
        assert!(
            output.contains("Failed to create output directory"),
            "should panic with descriptive message on mkdir failure"
        );
    }

    #[test]
    fn load_inputs_into_memory_uses_is_corpus_input() {
        let output = ts(load_inputs_into_memory());
        assert!(
            output.contains("is_corpus_input"),
            "should filter using is_corpus_input"
        );
        assert!(
            output.contains("BytesInput"),
            "should create BytesInput from files"
        );
        assert!(
            output.contains("load_inputs_from_dir"),
            "should define load_inputs_from_dir fn"
        );
    }
}
