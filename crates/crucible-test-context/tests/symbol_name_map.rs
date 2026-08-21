//! Tests for `build_symbol_name_map` — the symbol-table fallback that gives
//! bytecode-level LCOV real function names when a binary has no DWARF info.

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

/// Build a minimal ELF (no `.debug_*` sections) with two text function symbols
/// and one data symbol, then assert the symbol-name map demangles and filters
/// correctly.
#[test]
fn maps_text_function_symbols_and_demangles() {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let text = obj.section_id(StandardSection::Text);
    // 32 bytes of .text => instruction indices (pc) 0..4 (8 bytes each).
    obj.append_section_data(text, &[0u8; 32], 8);

    let data = obj.section_id(StandardSection::Data);
    obj.append_section_data(data, &[0u8; 16], 8);

    // Text function symbol at offset 0 -> pc 0. Mangled Rust name.
    obj.add_symbol(Symbol {
        name: b"_ZN3foo3barE".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });

    // Text function symbol at offset 16 -> pc 2. Plain (non-mangled) name.
    obj.add_symbol(Symbol {
        name: b"entrypoint".to_vec(),
        value: 16,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });

    // Data symbol -> must be filtered out (not a function).
    obj.add_symbol(Symbol {
        name: b"SOME_GLOBAL".to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(data),
        flags: SymbolFlags::None,
    });

    let bytes = obj.write().expect("write elf");

    let map = crucible_test_context::build_symbol_name_map(&bytes)
        .expect("expected a non-empty symbol-name map");

    // Demangled Rust name at pc 0.
    assert_eq!(map.get(&0).map(String::as_str), Some("foo::bar"));
    // Plain name passes through demangle unchanged at pc 2.
    assert_eq!(map.get(&2).map(String::as_str), Some("entrypoint"));
    // Data symbol excluded; only the two text functions are present.
    assert_eq!(map.len(), 2);
    assert!(!map.values().any(|n| n.contains("SOME_GLOBAL")));
}

/// A binary with no function symbols in `.text` yields `None`.
#[test]
fn returns_none_without_text_function_symbols() {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let data = obj.section_id(StandardSection::Data);
    obj.append_section_data(data, &[0u8; 16], 8);
    obj.add_symbol(Symbol {
        name: b"ONLY_DATA".to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(data),
        flags: SymbolFlags::None,
    });
    let bytes = obj.write().expect("write elf");
    assert!(crucible_test_context::build_symbol_name_map(&bytes).is_none());
}
