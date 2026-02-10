#!/usr/bin/env python3
"""
Generate CFG visualization with coverage overlay from LCOV data.

Usage:
    python cfg_visualize.py coverage.lcov program.so [function_name]

    # Generate DOT for entire program (warning: may be huge)
    python cfg_visualize.py coverage.lcov target/deploy/marginfi.so > cfg.dot

    # Generate DOT for specific function
    python cfg_visualize.py coverage.lcov target/deploy/marginfi.so entrypoint > cfg.dot

    # Convert to PNG/SVG
    dot -Tpng cfg.dot -o cfg.png
    dot -Tsvg cfg.dot -o cfg.svg

    # Or use xdot for interactive viewing
    xdot cfg.dot

Requirements:
    - Graphviz (brew install graphviz)
    - The Rust generate_cfg_dot function must be exposed via a CLI tool

This script parses LCOV and outputs data for the Rust CFG generator.
"""
import sys
import subprocess
import tempfile
import os

def parse_lcov_hits(lcov_path):
    """Parse LCOV file and return dict of PC -> hits."""
    hits = {}
    with open(lcov_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("DA:"):
                parts = line[3:].split(",")
                if len(parts) >= 2:
                    # Line numbers in LCOV are 1-indexed, convert back to PC
                    pc = int(parts[0]) - 1
                    count = int(parts[1])
                    hits[pc] = count
    return hits

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    lcov_path = sys.argv[1]
    program_path = sys.argv[2]
    function_filter = sys.argv[3] if len(sys.argv) > 3 else None

    # Parse coverage data
    hits = parse_lcov_hits(lcov_path)

    print(f"# Parsed {len(hits)} PC hit counts from {lcov_path}", file=sys.stderr)
    print(f"# Program: {program_path}", file=sys.stderr)
    if function_filter:
        print(f"# Function filter: {function_filter}", file=sys.stderr)

    # For now, output a simplified DOT that can be enhanced later
    # This is a placeholder - the full implementation requires calling the Rust function

    # Write hits to temp file for Rust tool to read
    with tempfile.NamedTemporaryFile(mode='w', suffix='.hits', delete=False) as f:
        for pc, count in sorted(hits.items()):
            f.write(f"{pc},{count}\n")
        hits_file = f.name

    print(f"# Coverage data written to {hits_file}", file=sys.stderr)
    print(f"# To generate CFG, run: cargo run --bin cfg_viz -- {program_path} {hits_file}", file=sys.stderr)

    # Generate a simple text summary for now
    print("digraph CFG {")
    print("    // This is a placeholder - full CFG requires the Rust cfg_viz tool")
    print("    // See anchor-test/scripts/cfg_visualize.py for usage")
    print(f"    label=\"Coverage: {len(hits)} PCs hit\";")
    print("    labelloc=t;")
    print("}")

    # Cleanup
    os.unlink(hits_file)

if __name__ == "__main__":
    main()
