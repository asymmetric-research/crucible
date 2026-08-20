//! DWARF debug info parsing for source-level coverage mapping.
//!
//! Maps SBF program counter (PC) values to real source file paths and line numbers
//! using DWARF debug info from an unstripped ELF binary.

use std::collections::{HashMap, HashSet};

/// Source location for a single PC.
#[derive(Clone, Debug)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
}

/// Optional on-disk root for resolving relative DWARF file paths, read from the
/// explicit `FUZZ_SOURCE_ROOT` env var.
///
/// This is intentionally explicit. It must NOT be inferred from `FUZZ_SYMBOLS`
/// (which the earlier implementation did by splitting at "/target/"): a symbols
/// binary staged under any `.../target/...` path — e.g. a fuzzcorp bundle at
/// `<bundle>/target/deploy/prog.debug.so` — would yield the wrong root and corrupt
/// source-path resolution, producing an LCOV with zero resolvable source files.
fn coverage_source_root() -> Option<String> {
    std::env::var("FUZZ_SOURCE_ROOT").ok()
}

/// Pre-computed PC-to-source mapping, built once from a debug binary.
///
/// All PCs are eagerly resolved at init time to avoid lifetime issues
/// with `addr2line::Context` and to provide O(1) lookup during LCOV generation.
#[derive(Clone, Debug)]
pub struct DwarfSourceMap {
    /// PC (instruction index) -> all source locations (full inline chain).
    /// Multiple locations per PC: innermost (inlined callee) to outermost (call site).
    /// When a PC is hit, ALL locations in the chain should be counted as hit.
    pub pc_map: HashMap<usize, Vec<SourceLocation>>,
    /// Function entry PC -> (name, source location)
    pub fn_map: HashMap<usize, (String, SourceLocation)>,
    /// All executable source lines per file (from DWARF).
    /// Lines in this set had code generated for them by the compiler.
    /// Includes both direct code and inlined call sites.
    pub executable_lines: HashMap<String, HashSet<u32>>,
}

/// Parse DWARF from a debug binary and build a cached PC-to-source map.
///
/// Returns `None` if the binary has no `.debug_info` section.
///
/// The debug binary must be the unstripped ELF (e.g., from
/// `target/sbpf-solana-solana/release/<name>.so`), not the stripped
/// one in `target/deploy/`.
///
/// PC-to-ELF address mapping: PCs from register tracing are instruction
/// indices. Each SBF instruction = 8 bytes. The `.text` section starts
/// at ELF vaddr (typically `0x120`). So: `elf_addr = text_vaddr + (pc * 8)`.
pub fn build_dwarf_source_map(debug_binary: &[u8]) -> Option<DwarfSourceMap> {
    use object::{Object, ObjectSection};

    let object_file = object::File::parse(debug_binary).ok()?;

    // Check for .debug_info section - if missing, no DWARF data
    if object_file.section_by_name(".debug_info").is_none() {
        return None;
    }

    // Find .text section for vaddr and size
    let text_section = object_file.section_by_name(".text")?;
    let text_vaddr = text_section.address();
    let text_size = text_section.size();
    let max_pc = (text_size / 8) as usize;

    // Load DWARF sections from the object file
    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::LittleEndian>, gimli::Error> {
        let data = object_file
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, gimli::LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(&load_section).ok()?;
    let context = addr2line::Context::from_dwarf(dwarf).ok()?;

    // Optional source root for resolving relative DWARF paths to on-disk files.
    // This is a convenience for the local `crucible run --coverage` + genhtml flow,
    // opt-in via the FUZZ_SOURCE_ROOT env var.
    //
    // It is deliberately NOT inferred from the FUZZ_SYMBOLS path. The previous code
    // derived it by splitting FUZZ_SYMBOLS at "/target/", which is a latent trap:
    // whenever the symbols binary is staged under any ".../target/..." path (e.g. a
    // fuzzcorp bundle at `<bundle>/target/deploy/prog.debug.so`), the split yields
    // the bundle root instead of the build workspace and corrupts path resolution —
    // producing an LCOV with zero resolvable source files even though the DWARF is
    // fully intact (which then fails the downstream lcov→fcov conversion). The
    // emitted path must depend only on the DWARF contents, never on where the
    // symbols file happens to sit; consumers remap the build prefix to wherever the
    // sources are actually staged.
    let source_root = coverage_source_root();

    // Resolve a DWARF file path to an absolute path.
    // Tries canonicalize first (works if CWD matches), then prepends source_root.
    let resolve_path = |file: &str| -> String {
        if let Ok(abs) = std::fs::canonicalize(file) {
            return abs.to_string_lossy().into_owned();
        }
        if let Some(ref root) = source_root {
            let full = format!("{}/{}", root, file);
            if let Ok(abs) = std::fs::canonicalize(&full) {
                return abs.to_string_lossy().into_owned();
            }
        }
        file.to_string()
    };

    let mut pc_map: HashMap<usize, Vec<SourceLocation>> = HashMap::new();
    let mut fn_map = HashMap::new();
    let mut executable_lines: HashMap<String, HashSet<u32>> = HashMap::new();

    // Single pass: use find_frames() for every PC to get the full inline chain.
    // This resolves both source locations and function names in one pass.
    // Each frame in the chain represents a level of inlining:
    //   frame[0] = innermost (the inlined callee)
    //   frame[N] = outermost (the actual call site in user code)
    // We record ALL frames' source locations so that inlined call sites get
    // proper hit counts.
    for pc in 0..max_pc {
        let elf_addr = text_vaddr + (pc as u64) * 8;

        let mut frames = match context.find_frames(elf_addr).skip_all_loads() {
            Ok(frames) => frames,
            Err(_) => continue,
        };

        let mut locations = Vec::new();
        let mut first_function_name: Option<String> = None;

        // Collect all frames (innermost to outermost)
        loop {
            match frames.next() {
                Ok(Some(frame)) => {
                    // Record function name from the innermost frame that has one
                    if first_function_name.is_none() {
                        if let Some(ref function) = frame.function {
                            first_function_name = Some(
                                function
                                    .demangle()
                                    .map(|d: std::borrow::Cow<'_, str>| d.into_owned())
                                    .unwrap_or_else(|_| {
                                        function
                                            .raw_name()
                                            .map(|r: std::borrow::Cow<'_, str>| r.into_owned())
                                            .unwrap_or_else(|_| format!("fn_{}", pc))
                                    }),
                            );
                        }
                    }

                    // Record source location from this frame
                    if let Some(loc) = frame.location {
                        if let (Some(file), Some(line)) = (loc.file, loc.line) {
                            let file_path = resolve_path(file);

                            executable_lines
                                .entry(file_path.clone())
                                .or_default()
                                .insert(line);

                            locations.push(SourceLocation {
                                file: file_path,
                                line,
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if !locations.is_empty() {
            // Record function name using the outermost location (call site)
            if let Some(name) = first_function_name {
                let outermost = locations.last().unwrap();
                fn_map
                    .entry(pc)
                    .or_insert_with(|| (name, outermost.clone()));
            }

            pc_map.insert(pc, locations);
        }
    }

    // Phase 2: Scan the DWARF line number table for additional source line mappings.
    //
    // find_frames() returns one location per inline level at each PC, but the
    // DWARF line table often has multiple rows at the SAME address for multi-line
    // expressions (chained method calls like `.foo()\n.bar()`, multi-line let
    // bindings, match arm patterns, etc.). These "continuation lines" get no
    // pc_map entry from find_frames() and would appear as blank in genhtml.
    //
    // find_location_range() iterates the raw line table and yields each entry,
    // including multiple entries at the same address. By adding these to pc_map
    // and executable_lines, continuation lines get proper DA records and inherit
    // hit counts from their shared PC.
    if let Ok(locs) = context.find_location_range(text_vaddr, text_vaddr + text_size) {
        for (addr, _len, loc) in locs {
            if let (Some(file), Some(line)) = (loc.file, loc.line) {
                if addr < text_vaddr || addr >= text_vaddr + text_size {
                    continue;
                }
                let pc = ((addr - text_vaddr) / 8) as usize;

                let file_path = resolve_path(file);

                executable_lines
                    .entry(file_path.clone())
                    .or_default()
                    .insert(line);

                let locations = pc_map.entry(pc).or_default();
                if !locations
                    .iter()
                    .any(|l| l.file == file_path && l.line == line)
                {
                    locations.push(SourceLocation {
                        file: file_path,
                        line,
                    });
                }
            }
        }
    }

    // Also parse symtab for function names not found via DWARF frames
    let symbol_map = object_file.symbol_map();
    for sym in symbol_map.symbols() {
        let addr = sym.address();
        if addr >= text_vaddr && addr < text_vaddr + text_size {
            let pc = ((addr - text_vaddr) / 8) as usize;
            if !fn_map.contains_key(&pc) {
                if let Some(locs) = pc_map.get(&pc) {
                    if let Some(loc) = locs.last() {
                        fn_map.insert(pc, (sym.name().to_string(), loc.clone()));
                    }
                }
            }
        }
    }

    Some(DwarfSourceMap {
        pc_map,
        fn_map,
        executable_lines,
    })
}

/// Build a PC -> demangled-function-name map from an ELF symbol table.
///
/// Unlike [`build_dwarf_source_map`], this does **not** require any `.debug_*`
/// sections — it only reads the symbol table. This is the fallback used when a
/// program is built without DWARF line info (e.g. plain `cargo build-sbf`):
/// the stripped program loaded into the SVM yields only `fn_<pc>` names, but the
/// unstripped `symbols.so` still carries ~hundreds of real (mangled) function
/// symbols. We map each text-section function symbol to its instruction index
/// `pc = (addr - text_vaddr) / 8` and demangle the Rust name, so bytecode-level
/// LCOV can report real function names instead of `fn_<pc>` stubs.
///
/// Returns `None` if the binary has no usable text section or no function
/// symbols within it.
pub fn build_symbol_name_map(binary: &[u8]) -> Option<HashMap<usize, String>> {
    use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

    let object_file = object::File::parse(binary).ok()?;
    let text_section = object_file.section_by_name(".text")?;
    let text_vaddr = text_section.address();
    let text_end = text_vaddr + text_section.size();

    let mut map: HashMap<usize, String> = HashMap::new();
    for sym in object_file.symbols() {
        // Only named function symbols inside .text are useful here.
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let addr = sym.address();
        if addr < text_vaddr || addr >= text_end {
            continue;
        }
        let raw = match sym.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        let pc = ((addr - text_vaddr) / 8) as usize;
        let name = rustc_demangle::demangle(raw).to_string();
        // First symbol at a PC wins (matches DWARF fn_map insertion order).
        map.entry(pc).or_insert(name);
    }

    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::coverage_source_root;

    /// Regression: the coverage source root must come only from the explicit
    /// FUZZ_SOURCE_ROOT env var, never inferred from FUZZ_SYMBOLS. Inferring it by
    /// splitting FUZZ_SYMBOLS at "/target/" corrupted source-path resolution whenever
    /// the symbols binary was staged under a ".../target/..." path (e.g. a bundle),
    /// yielding an LCOV with zero resolvable source files.
    #[test]
    fn source_root_is_explicit_not_inferred_from_symbols() {
        // A FUZZ_SYMBOLS path under ".../target/..." must have no effect.
        std::env::remove_var("FUZZ_SOURCE_ROOT");
        std::env::set_var("FUZZ_SYMBOLS", "/some/bundle/target/deploy/prog.debug.so");
        assert_eq!(coverage_source_root(), None);

        // Only the explicit env var is honored.
        std::env::set_var("FUZZ_SOURCE_ROOT", "/explicit/root");
        assert_eq!(coverage_source_root(), Some("/explicit/root".to_string()));

        std::env::remove_var("FUZZ_SOURCE_ROOT");
        std::env::remove_var("FUZZ_SYMBOLS");
    }
}
