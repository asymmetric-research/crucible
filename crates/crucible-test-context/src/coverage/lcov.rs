//! LCOV coverage file generation for BPF programs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::io::Write;
use std::sync::Arc;

use super::dwarf::DwarfSourceMap;
use super::types::FunctionInfo;

/// Extract function information from a BPF program binary
pub fn extract_functions(program_data: &[u8]) -> Option<Vec<FunctionInfo>> {
    use solana_sbpf::elf::Executable;
    use solana_sbpf::program::BuiltinProgram;
    use solana_sbpf::static_analysis::Analysis;
    use solana_sbpf::vm::ContextObject;

    struct DummyContext;
    impl ContextObject for DummyContext {
        fn consume(&mut self, _amount: u64) {}
        fn get_remaining(&self) -> u64 {
            0
        }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader).ok()?;
    let analysis = Analysis::from_executable(&executable).ok()?;

    let functions: Vec<FunctionInfo> = analysis
        .functions
        .iter()
        .map(|(pc, (_key, name))| FunctionInfo {
            name: name.clone(),
            entry_pc: *pc,
        })
        .collect();

    Some(functions)
}

/// Generate LCOV coverage data for a program (bytecode mode)
///
/// Accepts any HashMap-like type (standard HashMap or FastHashMap) via generic hasher parameter.
pub fn generate_bytecode_lcov<W, S1, S2>(
    writer: &mut W,
    program_name: &str,
    pc_hits: &HashMap<usize, u64, S1>,
    branch_outcomes: &HashMap<(usize, bool), u64, S2>,
    functions: &[FunctionInfo],
    total_instructions: usize,
    total_branches: usize,
    symbol_names: Option<&HashMap<usize, String>>,
) -> std::io::Result<()>
where
    W: Write,
    S1: BuildHasher,
    S2: BuildHasher,
{
    writeln!(writer, "TN:fuzzer")?;
    writeln!(writer, "SF:{}.bpf", program_name)?;

    // Function entries (sorted by entry_pc for consistency)
    // Filter out functions with empty names and give unnamed functions a default name
    let mut sorted_functions = functions.to_vec();
    sorted_functions.sort_by_key(|f| f.entry_pc);

    // Resolve a display name for a function entry.
    //
    // The program loaded into the SVM is usually stripped, so `extract_functions`
    // only recovers `fn_<pc>` / `function_<pc>` placeholders. When a symbol-name
    // map from the unstripped `symbols.so` is available, prefer its demangled
    // name so bytecode-level LCOV carries real Rust function names.
    let resolve_name = |func: &FunctionInfo| -> String {
        if let Some(name) = symbol_names.and_then(|m| m.get(&func.entry_pc)) {
            return name.clone();
        }
        if func.name.is_empty() {
            format!("fn_{}", func.entry_pc)
        } else {
            func.name.clone()
        }
    };

    // LCOV expects line numbers starting from 1, so we offset all PCs by 1
    for func in &sorted_functions {
        writeln!(writer, "FN:{},{}", func.entry_pc + 1, resolve_name(func))?;
    }

    // Function hit counts
    let mut functions_hit = 0usize;
    for func in &sorted_functions {
        let hits = pc_hits.get(&func.entry_pc).copied().unwrap_or(0);
        writeln!(writer, "FNDA:{},{}", hits, resolve_name(func))?;
        if hits > 0 {
            functions_hit += 1;
        }
    }
    writeln!(writer, "FNF:{}", sorted_functions.len())?;
    writeln!(writer, "FNH:{}", functions_hit)?;

    // Line (PC) hit data - sorted by PC for consistency
    // Offset by 1 since LCOV expects line numbers starting from 1
    let mut pcs: Vec<_> = pc_hits.keys().copied().collect();
    pcs.sort();
    for pc in &pcs {
        writeln!(writer, "DA:{},{}", pc + 1, pc_hits.get(pc).unwrap_or(&0))?;
    }
    writeln!(writer, "LF:{}", total_instructions)?;
    writeln!(writer, "LH:{}", pc_hits.len())?;

    // Branch data - group by branch PC
    // Offset by 1 since LCOV expects line numbers starting from 1
    let mut branch_pcs: HashSet<usize> = HashSet::new();
    for ((pc, _), _) in branch_outcomes {
        branch_pcs.insert(*pc);
    }
    let mut branch_pcs: Vec<_> = branch_pcs.into_iter().collect();
    branch_pcs.sort();

    let mut branches_hit = 0usize;
    for (block_idx, pc) in branch_pcs.iter().enumerate() {
        let taken = branch_outcomes.get(&(*pc, true)).copied().unwrap_or(0);
        let not_taken = branch_outcomes.get(&(*pc, false)).copied().unwrap_or(0);

        // BRDA: line, block, branch, taken_count (- means not executed)
        let taken_str = if taken > 0 {
            taken.to_string()
        } else {
            "-".to_string()
        };
        let not_taken_str = if not_taken > 0 {
            not_taken.to_string()
        } else {
            "-".to_string()
        };

        writeln!(writer, "BRDA:{},{},0,{}", pc + 1, block_idx, taken_str)?;
        writeln!(writer, "BRDA:{},{},1,{}", pc + 1, block_idx, not_taken_str)?;

        if taken > 0 {
            branches_hit += 1;
        }
        if not_taken > 0 {
            branches_hit += 1;
        }
    }
    writeln!(writer, "BRF:{}", total_branches * 2)?; // Each branch has 2 outcomes
    writeln!(writer, "BRH:{}", branches_hit)?;

    writeln!(writer, "end_of_record")?;
    Ok(())
}

/// Generate source-level LCOV coverage data using DWARF debug info.
///
/// Maps PCs to real source file paths and line numbers. Multiple PCs mapping
/// to the same source line have their hit counts summed. Returns the number
/// of source files written.
///
/// PCs that don't resolve in the DWARF map are silently skipped.
pub fn generate_source_lcov<W, S1, S2>(
    writer: &mut W,
    pc_hits: &HashMap<usize, u64, S1>,
    branch_outcomes: &HashMap<(usize, bool), u64, S2>,
    source_map: &DwarfSourceMap,
    functions: &[FunctionInfo],
) -> std::io::Result<usize>
where
    W: Write,
    S1: BuildHasher,
    S2: BuildHasher,
{
    // Aggregate PC hits by source file and line.
    // Each PC may map to multiple source locations (inline chain),
    // so a single hit contributes to ALL locations in the chain.
    // file -> line -> total_hits
    let mut file_line_hits: HashMap<&str, BTreeMap<u32, u64>> = HashMap::new();

    for (&pc, &hits) in pc_hits {
        if let Some(locations) = source_map.pc_map.get(&pc) {
            for loc in locations {
                *file_line_hits
                    .entry(loc.file.as_str())
                    .or_default()
                    .entry(loc.line)
                    .or_insert(0) += hits;
            }
        }
    }

    // Aggregate branch outcomes by source file and line.
    // Branches are attributed to the innermost (first) location only,
    // since branch semantics belong to the actual branching code.
    let mut file_branches: HashMap<&str, BTreeMap<u32, Vec<(u64, u64)>>> = HashMap::new();

    let mut branch_pcs_set: HashSet<usize> = HashSet::new();
    for &(pc, _) in branch_outcomes.keys() {
        branch_pcs_set.insert(pc);
    }

    for pc in branch_pcs_set {
        if let Some(locations) = source_map.pc_map.get(&pc) {
            if let Some(loc) = locations.first() {
                let taken = branch_outcomes.get(&(pc, true)).copied().unwrap_or(0);
                let not_taken = branch_outcomes.get(&(pc, false)).copied().unwrap_or(0);
                file_branches
                    .entry(loc.file.as_str())
                    .or_default()
                    .entry(loc.line)
                    .or_default()
                    .push((taken, not_taken));
            }
        }
    }

    // Aggregate functions by source file
    // file -> Vec<(line, name, hits)>
    let mut file_functions: HashMap<&str, Vec<(u32, String, u64)>> = HashMap::new();

    for func in functions {
        // Try fn_map first for DWARF-resolved function info
        if let Some((name, loc)) = source_map.fn_map.get(&func.entry_pc) {
            let hits = pc_hits.get(&func.entry_pc).copied().unwrap_or(0);
            file_functions.entry(loc.file.as_str()).or_default().push((
                loc.line,
                name.clone(),
                hits,
            ));
        } else if let Some(locations) = source_map.pc_map.get(&func.entry_pc) {
            // Fallback: use SBF function name with outermost DWARF source location
            if let Some(loc) = locations.last() {
                let name = if func.name.is_empty() {
                    format!("fn_{}", func.entry_pc)
                } else {
                    func.name.clone()
                };
                let hits = pc_hits.get(&func.entry_pc).copied().unwrap_or(0);
                file_functions
                    .entry(loc.file.as_str())
                    .or_default()
                    .push((loc.line, name, hits));
            }
        }
    }

    // Collect all source files and sort for deterministic output.
    // Filter out stdlib, dependency crates, and other non-user source files.
    // User code has paths like "programs/marginfi/src/..." (relative) or
    // absolute paths under the workspace. Non-user code comes from:
    //   - /Users/runner/... (Solana platform-tools stdlib)
    //   - bare "src/..." (dependency crates compiled in the registry)
    let is_user_source = |file: &str| -> bool {
        if file.starts_with('/') {
            // Exclude known non-user paths (stdlib, platform-tools, registry crates)
            if file.contains("/.cargo/registry/")
                || file.contains("/.rustup/toolchains/")
                || file.contains("/platform-tools/")
                || file.contains("/Users/runner/")
                || file.contains("/home/runner/")
            {
                return false;
            }
            // If we can infer workspace root from FUZZ_SYMBOLS, restrict to it
            if let Some(root) = std::env::var("FUZZ_SYMBOLS")
                .ok()
                .and_then(|p| p.find("/target/").map(|idx| p[..idx].to_string()))
            {
                return file.starts_with(&root);
            }
            // No workspace root available (e.g. bundled symbols.so) — keep all
            // absolute paths that weren't excluded above
            return true;
        }
        // Relative paths: "programs/..." is user code.
        // Bare "src/..." is typically a dependency crate (anchor, borsh, serde, etc.)
        if file.starts_with("src/") {
            return false;
        }
        true
    };

    let mut all_files: Vec<&str> = file_line_hits
        .keys()
        .copied()
        .filter(|f| is_user_source(f))
        .collect();
    // Also include files that only have branches or functions
    for file in file_branches.keys() {
        if is_user_source(file) && !all_files.contains(file) {
            all_files.push(file);
        }
    }
    all_files.sort();

    let mut files_written = 0usize;

    for file in &all_files {
        writeln!(writer, "TN:fuzzer")?;
        writeln!(writer, "SF:{}", file)?;

        // Function entries
        let mut funcs = file_functions.get(file).cloned().unwrap_or_default();
        funcs.sort_by_key(|(line, _, _)| *line);
        // Deduplicate functions by name (keep first occurrence)
        let mut seen_names: HashSet<String> = HashSet::new();
        funcs.retain(|(_, name, _)| seen_names.insert(name.clone()));

        for (line, name, _hits) in &funcs {
            writeln!(writer, "FN:{},{}", line, name)?;
        }

        let mut functions_hit = 0usize;
        for (_line, name, hits) in &funcs {
            writeln!(writer, "FNDA:{},{}", hits, name)?;
            if *hits > 0 {
                functions_hit += 1;
            }
        }
        writeln!(writer, "FNF:{}", funcs.len())?;
        writeln!(writer, "FNH:{}", functions_hit)?;

        // Line hit data
        // Use DWARF executable_lines to determine which lines are executable.
        // Only executable lines get DA records — non-executable lines (comments,
        // blank lines, struct field names in patterns, etc.) are left without
        // DA records so genhtml renders them as neutral/white.
        let mut merged_line_hits: BTreeMap<u32, u64> = BTreeMap::new();

        // Start with all executable lines as DA:line,0
        if let Some(exec_lines) = source_map.executable_lines.get(*file) {
            for &line in exec_lines {
                merged_line_hits.insert(line, 0);
            }
        }

        // Overlay actual hit counts
        if let Some(hits) = file_line_hits.get(file) {
            for (&line, &count) in hits {
                merged_line_hits.insert(line, count);
            }
        }

        // Ensure function entry lines have DA records
        for (line, _, _) in &funcs {
            merged_line_hits.entry(*line).or_insert(0);
        }

        // Fill gaps between consecutive DA records.
        // Multi-line expressions (chained calls, function arguments,
        // multi-line let bindings, match arm patterns) often have
        // continuation lines that DWARF doesn't map to any PC. These
        // show as blank in genhtml which is confusing for clearly-code lines.
        //
        // Source-aware rules:
        //   - Blank lines BREAK the gap (they separate logical blocks)
        //   - Comment-only lines (`//`) are SKIPPED (no DA record)
        //   - Code lines get min(hits_a, hits_b) of the surrounding DA records
        //   - Max gap size: 10 lines
        let source_lines: Option<Vec<String>> =
            read_source_file(file).map(|content| content.lines().map(|l| l.to_string()).collect());

        let lines_snapshot: Vec<(u32, u64)> = merged_line_hits
            .iter()
            .map(|(&line, &hits)| (line, hits))
            .collect();
        for window in lines_snapshot.windows(2) {
            let (line_a, hits_a) = window[0];
            let (line_b, hits_b) = window[1];
            let gap = line_b - line_a - 1;
            // Only fill when both endpoints have nonzero hits.
            // Filling with 0 would mark lines as "unreached" when we
            // actually don't know — better to leave them blank/neutral.
            let fill_hits = std::cmp::min(hits_a, hits_b);
            if gap > 0 && gap <= 10 && fill_hits > 0 {
                for line in (line_a + 1)..line_b {
                    if let Some(ref lines) = source_lines {
                        if let Some(src) = lines.get((line - 1) as usize) {
                            let trimmed = src.trim();
                            if trimmed.is_empty() {
                                break; // Blank line = logical separator
                            }
                            if trimmed.starts_with("//") {
                                continue; // Skip comments
                            }
                        }
                    }
                    merged_line_hits.entry(line).or_insert(fill_hits);
                }
            }
        }

        // Backward fill: propagate DA records upward to expression-start lines.
        //
        // After blank-line breaking, an expression-start line (e.g. `check!`,
        // `let x =`, `if condition`) may sit just above a DA record with no
        // preceding DA to anchor a forward fill. Scan backward from each DA
        // record to fill code lines that precede it.
        //
        // Rules:
        //   - Skip blank lines and comments (don't fill them, but keep scanning)
        //   - Stop if the line already has a DA record
        //   - Max backward reach: 10 lines
        let lines_snapshot2: Vec<(u32, u64)> = merged_line_hits
            .iter()
            .map(|(&line, &hits)| (line, hits))
            .collect();
        for &(da_line, da_hits) in &lines_snapshot2 {
            // Only backward-fill from nonzero DA records — filling with 0
            // would falsely mark lines as unreached when we don't know.
            if da_line <= 1 || da_hits == 0 {
                continue;
            }
            let start = if da_line > 10 { da_line - 10 } else { 1 };
            for check_line in (start..da_line).rev() {
                // Stop if this line already has a DA record
                if merged_line_hits.contains_key(&check_line) {
                    break;
                }
                if let Some(ref lines) = source_lines {
                    if let Some(src) = lines.get((check_line - 1) as usize) {
                        let trimmed = src.trim();
                        // Skip blank lines and comments — don't fill but keep scanning
                        if trimmed.is_empty() || trimmed.starts_with("//") {
                            continue;
                        }
                        // It's a code line with no DA — fill it
                        merged_line_hits.insert(check_line, da_hits);
                    } else {
                        break;
                    }
                } else {
                    break; // No source available, can't verify
                }
            }
        }

        let lines_found = merged_line_hits.len();
        let lines_hit = merged_line_hits.values().filter(|&&h| h > 0).count();
        for (&line, &count) in &merged_line_hits {
            writeln!(writer, "DA:{},{}", line, count)?;
        }
        writeln!(writer, "LF:{}", lines_found)?;
        writeln!(writer, "LH:{}", lines_hit)?;

        // Branch data
        let branches = file_branches.get(file);
        let mut total_branch_entries = 0usize;
        let mut branches_hit = 0usize;
        if let Some(branch_lines) = branches {
            for (&line, branch_list) in branch_lines {
                for (block_idx, (taken, not_taken)) in branch_list.iter().enumerate() {
                    let taken_str = if *taken > 0 {
                        taken.to_string()
                    } else {
                        "-".to_string()
                    };
                    let not_taken_str = if *not_taken > 0 {
                        not_taken.to_string()
                    } else {
                        "-".to_string()
                    };

                    writeln!(writer, "BRDA:{},{},0,{}", line, block_idx, taken_str)?;
                    writeln!(writer, "BRDA:{},{},1,{}", line, block_idx, not_taken_str)?;

                    total_branch_entries += 2;
                    if *taken > 0 {
                        branches_hit += 1;
                    }
                    if *not_taken > 0 {
                        branches_hit += 1;
                    }
                }
            }
        }
        writeln!(writer, "BRF:{}", total_branch_entries)?;
        writeln!(writer, "BRH:{}", branches_hit)?;

        writeln!(writer, "end_of_record")?;
        files_written += 1;
    }

    Ok(files_written)
}

/// Try to read a source file, resolving relative paths using FUZZ_SYMBOLS.
///
/// DWARF source paths may be relative to the compilation workspace root.
/// When the fuzzer runs from a different directory, these won't resolve directly.
/// We infer the workspace root from FUZZ_SYMBOLS (e.g., `.../target/sbpf-.../release/prog.so`
/// → strip from `/target/` onward) and prepend it to relative paths.
fn read_source_file(file: &str) -> Option<String> {
    use std::sync::OnceLock;

    // Cache the resolved source root (computed once from FUZZ_SYMBOLS)
    static SOURCE_ROOT: OnceLock<Option<String>> = OnceLock::new();
    let source_root = SOURCE_ROOT.get_or_init(|| {
        std::env::var("FUZZ_SYMBOLS")
            .ok()
            .and_then(|p| p.find("/target/").map(|idx| p[..idx].to_string()))
    });

    // Try the path as-is first (works for absolute paths)
    if let Ok(content) = std::fs::read_to_string(file) {
        return Some(content);
    }

    // Try prepending source root for relative paths
    if let Some(ref root) = source_root {
        if let Ok(content) = std::fs::read_to_string(format!("{}/{}", root, file)) {
            return Some(content);
        }
    }

    None
}
