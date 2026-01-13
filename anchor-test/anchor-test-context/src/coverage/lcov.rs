//! LCOV coverage file generation for BPF programs.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;

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
        fn get_remaining(&self) -> u64 { 0 }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader).ok()?;
    let analysis = Analysis::from_executable(&executable).ok()?;

    let functions: Vec<FunctionInfo> = analysis.functions
        .iter()
        .map(|(pc, (_key, name))| FunctionInfo {
            name: name.clone(),
            entry_pc: *pc,
        })
        .collect();

    Some(functions)
}

/// Generate LCOV coverage data for a program (bytecode mode)
pub fn generate_bytecode_lcov<W: Write>(
    writer: &mut W,
    program_name: &str,
    pc_hits: &HashMap<usize, u64>,
    branch_outcomes: &HashMap<(usize, bool), u64>,
    functions: &[FunctionInfo],
    total_instructions: usize,
    total_branches: usize,
) -> std::io::Result<()> {

    writeln!(writer, "TN:fuzzer")?;
    writeln!(writer, "SF:{}.bpf", program_name)?;

    // Function entries (sorted by entry_pc for consistency)
    // Filter out functions with empty names and give unnamed functions a default name
    let mut sorted_functions = functions.to_vec();
    sorted_functions.sort_by_key(|f| f.entry_pc);

    // LCOV expects line numbers starting from 1, so we offset all PCs by 1
    for func in &sorted_functions {
        // Use function name if available, otherwise use "fn_<entry_pc>"
        let name = if func.name.is_empty() {
            format!("fn_{}", func.entry_pc)
        } else {
            func.name.clone()
        };
        writeln!(writer, "FN:{},{}", func.entry_pc + 1, name)?;
    }

    // Function hit counts
    let mut functions_hit = 0usize;
    for func in &sorted_functions {
        let name = if func.name.is_empty() {
            format!("fn_{}", func.entry_pc)
        } else {
            func.name.clone()
        };
        let hits = pc_hits.get(&func.entry_pc).copied().unwrap_or(0);
        writeln!(writer, "FNDA:{},{}", hits, name)?;
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
        let taken_str = if taken > 0 { taken.to_string() } else { "-".to_string() };
        let not_taken_str = if not_taken > 0 { not_taken.to_string() } else { "-".to_string() };

        writeln!(writer, "BRDA:{},{},0,{}", pc + 1, block_idx, taken_str)?;
        writeln!(writer, "BRDA:{},{},1,{}", pc + 1, block_idx, not_taken_str)?;

        if taken > 0 { branches_hit += 1; }
        if not_taken > 0 { branches_hit += 1; }
    }
    writeln!(writer, "BRF:{}", total_branches * 2)?;  // Each branch has 2 outcomes
    writeln!(writer, "BRH:{}", branches_hit)?;

    writeln!(writer, "end_of_record")?;
    Ok(())
}
