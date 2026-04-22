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
pub use dwarf::{build_dwarf_source_map, DwarfSourceMap, SourceLocation};
pub use html::{build_cached_analysis, generate_coverage_html, generate_coverage_html_cached};
pub use lcov::{extract_functions, generate_bytecode_lcov, generate_source_lcov};
pub use types::{
    CachedFunctionInfo, CachedProgramAnalysis, CoverageStats, CoverageWriteStats, FunctionInfo,
    ReachableAnalysis,
};
