//! Shared types for coverage analysis and visualization.

use std::collections::HashSet;

/// Function information extracted from BPF ELF
#[derive(Clone, Debug, Default)]
pub struct FunctionInfo {
    pub name: String,
    pub entry_pc: usize,
}

/// Result of CFG analysis including reachable sets for filtering visited coverage
#[derive(Clone, Default)]
pub struct ReachableAnalysis {
    pub total_instructions: usize,
    pub total_branches: usize,
    pub total_edges: usize,
    /// All instruction PCs reachable from the entry point
    pub reachable_pcs: HashSet<usize>,
    /// All conditional branch PCs reachable from the entry point
    pub reachable_branch_pcs: HashSet<usize>,
    /// All edges (pc<<32|target) reachable from the entry point
    pub reachable_edges: HashSet<u64>,
}

/// Coverage statistics for a function or program
#[derive(Clone, Debug, Default)]
pub struct CoverageStats {
    pub total_instructions: usize,
    pub hit_instructions: usize,
    pub total_branches: usize,
    pub hit_branches: usize,
    pub total_blocks: usize,
    pub hit_blocks: usize,
}

impl CoverageStats {
    /// Calculate instruction coverage percentage
    pub fn instruction_coverage_pct(&self) -> f64 {
        if self.total_instructions == 0 {
            0.0
        } else {
            100.0 * self.hit_instructions as f64 / self.total_instructions as f64
        }
    }

    /// Calculate branch coverage percentage
    pub fn branch_coverage_pct(&self) -> f64 {
        if self.total_branches == 0 {
            0.0
        } else {
            100.0 * self.hit_branches as f64 / self.total_branches as f64
        }
    }

    /// Calculate block coverage percentage
    pub fn block_coverage_pct(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            100.0 * self.hit_blocks as f64 / self.total_blocks as f64
        }
    }
}

/// Runtime statistics for coverage HTML display
#[derive(Clone, Debug, Default)]
pub struct CoverageWriteStats {
    pub run_time_secs: u64,
    pub executions: u64,
    pub edges_hit: usize,
    pub edges_total: usize,
    pub branches_hit: usize,
    pub branches_total: usize,
    pub instructions_hit: usize,
    pub instructions_total: usize,
}

/// Cached per-function data for fast coverage HTML generation
#[derive(Clone, Debug)]
pub struct CachedFunctionInfo {
    pub name: String,
    pub entry_pc: usize,
    pub total_instructions: usize,
    pub total_blocks: usize,
    /// All instruction PCs in this function (for fast hit counting)
    pub instruction_pcs: Vec<usize>,
    /// Block info: (node_id, Vec<instruction_pcs_in_block>)
    pub blocks: Vec<(usize, Vec<usize>)>,
}

/// Cached program analysis for fast coverage generation (computed once at startup)
#[derive(Clone, Debug)]
pub struct CachedProgramAnalysis {
    pub program_name: String,
    /// Pre-computed function list with static stats
    pub functions: Vec<CachedFunctionInfo>,
    /// Pre-computed CFG JSON for each function (func_name -> JSON string)
    pub cfg_json: std::collections::HashMap<String, String>,
}
