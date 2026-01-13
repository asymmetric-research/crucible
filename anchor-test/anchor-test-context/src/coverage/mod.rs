//! Coverage analysis and visualization for BPF programs.
//!
//! This module provides:
//! - LCOV coverage file generation
//! - Interactive HTML coverage visualization
//! - CFG analysis utilities

pub mod types;
pub mod lcov;
pub mod html;

// Re-export main types and functions
pub use types::{FunctionInfo, ReachableAnalysis, CoverageStats, CoverageWriteStats, CachedFunctionInfo, CachedProgramAnalysis};
pub use lcov::{extract_functions, generate_bytecode_lcov};
pub use html::{generate_coverage_html, build_cached_analysis, generate_coverage_html_cached};
