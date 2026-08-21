//! Coverage analysis and visualization for BPF programs.
//!
//! This module provides:
//! - LCOV coverage file generation
//! - Interactive HTML coverage visualization
//! - CFG analysis utilities

pub mod dwarf;
pub mod html;
pub mod lcov;
pub mod types;

// Re-export main types and functions
pub use dwarf::{build_dwarf_source_map, build_symbol_name_map, DwarfSourceMap, SourceLocation};
pub use html::{build_cached_analysis, generate_coverage_html, generate_coverage_html_cached};
pub use lcov::{extract_functions, generate_bytecode_lcov, generate_source_lcov};
pub use types::{
    CachedFunctionInfo, CachedProgramAnalysis, CoverageStats, CoverageWriteStats, FunctionInfo,
    ReachableAnalysis,
};

/// Return whether an SBPF opcode is a conditional 32-bit or 64-bit branch.
///
/// Kept here so static coverage totals and runtime register-trace coverage use
/// exactly the same SBPF 0.21 classification.
#[doc(hidden)]
#[inline]
pub fn is_conditional_branch_opcode(opcode: u8) -> bool {
    use solana_sbpf::ebpf;

    match opcode & ebpf::BPF_CLS_MASK {
        ebpf::BPF_JMP32 => true,
        ebpf::BPF_JMP64 => !matches!(
            opcode,
            ebpf::JA | ebpf::CALL_IMM | ebpf::CALL_REG | ebpf::EXIT
        ),
        _ => false,
    }
}

/// Register-trace PCs are instruction indexes, not byte offsets.
#[doc(hidden)]
#[inline]
pub fn branch_was_taken(branch_pc: usize, next_pc: usize) -> bool {
    next_pc != branch_pc + 1
}

#[cfg(test)]
mod tests {
    use super::{branch_was_taken, is_conditional_branch_opcode};
    use solana_sbpf::ebpf;

    #[test]
    fn recognizes_32_and_64_bit_conditional_branches() {
        assert!(is_conditional_branch_opcode(ebpf::JEQ32_IMM));
        assert!(is_conditional_branch_opcode(ebpf::JNE32_REG));
        assert!(is_conditional_branch_opcode(ebpf::JEQ64_IMM));
        assert!(is_conditional_branch_opcode(ebpf::JNE64_REG));
        assert!(!is_conditional_branch_opcode(ebpf::JA));
        assert!(!is_conditional_branch_opcode(ebpf::CALL_IMM));
        assert!(!is_conditional_branch_opcode(ebpf::CALL_REG));
        assert!(!is_conditional_branch_opcode(ebpf::EXIT));
        assert!(!is_conditional_branch_opcode(ebpf::ADD64_IMM));
    }

    #[test]
    fn classifies_instruction_index_fallthrough() {
        assert!(!branch_was_taken(11, 12));
        assert!(branch_was_taken(11, 19));
    }
}
