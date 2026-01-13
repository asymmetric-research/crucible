#!/usr/bin/env python3
"""
Parse LCOV coverage file and show per-function coverage report.

Usage:
    python coverage_report.py coverage.lcov          # Show named functions only
    python coverage_report.py coverage.lcov --all    # Show all functions
    python coverage_report.py coverage.lcov --cold   # Show only unhit functions
"""
import sys
from collections import defaultdict

def parse_lcov(path):
    """Parse LCOV file and extract function/branch coverage."""
    functions = {}  # name -> {pc, hits, file}
    branches = defaultdict(lambda: {"taken": [], "not_taken": []})
    current_file = None
    fn_lines = {}  # line -> name (for branch attribution)

    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("SF:"):
                current_file = line[3:]
                fn_lines = {}
            elif line.startswith("FN:"):
                parts = line[3:].split(",", 1)
                if len(parts) == 2:
                    line_num, name = int(parts[0]), parts[1]
                    fn_lines[line_num] = name
                    if name not in functions:
                        # -1 to get original PC (we added 1 for LCOV format)
                        functions[name] = {"pc": line_num - 1, "hits": 0, "file": current_file}
            elif line.startswith("FNDA:"):
                parts = line[5:].split(",", 1)
                if len(parts) == 2:
                    hits, name = int(parts[0]), parts[1]
                    if name in functions:
                        functions[name]["hits"] = hits
            elif line.startswith("BRDA:"):
                parts = line[5:].split(",")
                if len(parts) >= 4:
                    line_num = int(parts[0])
                    taken = parts[3]
                    # Find function for this line (last FN before this line)
                    func_name = None
                    for fl, fn in sorted(fn_lines.items(), reverse=True):
                        if fl <= line_num:
                            func_name = fn
                            break
                    if func_name:
                        if taken != "-" and taken != "0":
                            branches[func_name]["taken"].append(line_num - 1)
                        else:
                            branches[func_name]["not_taken"].append(line_num - 1)

    return functions, branches

def format_name(name, max_len=45):
    """Format function name with ANSI colors."""
    if name.startswith("fn_"):
        return f"\033[90m{name[:max_len]}\033[0m"  # dim gray for auto-generated
    return f"\033[1m{name[:max_len]}\033[0m"  # bold for real names

def main():
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print(__doc__)
        sys.exit(0)

    path = sys.argv[1]
    show_all = "--all" in sys.argv
    show_cold = "--cold" in sys.argv

    try:
        functions, branches = parse_lcov(path)
    except FileNotFoundError:
        print(f"Error: File not found: {path}")
        sys.exit(1)

    # Sort by hits (descending), then by name
    sorted_funcs = sorted(functions.items(), key=lambda x: (-x[1]["hits"], x[0]))

    # Filter functions based on flags
    if show_cold:
        display_funcs = [(n, d) for n, d in sorted_funcs if d["hits"] == 0]
        title = "NEVER HIT FUNCTIONS"
    elif show_all:
        display_funcs = sorted_funcs
        title = "ALL FUNCTION COVERAGE"
    else:
        display_funcs = [(n, d) for n, d in sorted_funcs if not n.startswith("fn_")]
        title = "NAMED FUNCTION COVERAGE"

    # Print header
    total_funcs = len(functions)
    print(f"\n\033[1m=== {title} ===\033[0m")
    if not show_all and not show_cold:
        named_count = len([f for f in functions if not f.startswith("fn_")])
        print(f"(showing {named_count} named functions, use --all for all {total_funcs})")
    print()

    if not show_cold:
        print(f"{'Function':<48} {'Hits':>8} {'Branches':>12} {'Missing PCs':<20}")
        print("-" * 95)

        hit_funcs = [f for f in display_funcs if f[1]["hits"] > 0]
        miss_funcs = [f for f in display_funcs if f[1]["hits"] == 0]

        # Show hit functions
        for name, data in hit_funcs[:50]:
            hits = data["hits"]
            br = branches.get(name, {"taken": [], "not_taken": []})
            taken = len(br["taken"])
            total = taken + len(br["not_taken"])
            br_str = f"{taken}/{total}" if total > 0 else "-"
            missing = br["not_taken"][:3]
            miss_str = ",".join(str(pc) for pc in missing) if missing else ""
            if len(br["not_taken"]) > 3:
                miss_str += f"... +{len(br['not_taken'])-3}"
            print(f"{format_name(name, 48):<58} {hits:>8} {br_str:>12} {miss_str:<20}")

        if len(hit_funcs) > 50:
            print(f"  ... and {len(hit_funcs) - 50} more hit functions")

        print("-" * 95)

        # Summary
        total_display = len(display_funcs)
        hit_count = len(hit_funcs)
        print(f"\n\033[1mSummary:\033[0m {hit_count}/{total_display} functions hit ({100*hit_count/total_display:.1f}%)")

        # Branch summary
        total_branches = sum(len(branches[n]["taken"]) + len(branches[n]["not_taken"]) for n in functions)
        hit_branches = sum(len(branches[n]["taken"]) for n in functions)
        if total_branches > 0:
            print(f"         {hit_branches}/{total_branches} branches taken ({100*hit_branches/total_branches:.1f}%)")

        # Show missed functions
        if miss_funcs and not show_all:
            print(f"\n\033[1m=== NEVER HIT ({len(miss_funcs)}) ===\033[0m")
            for name, data in miss_funcs[:25]:
                print(f"  {name} (PC: {data['pc']})")
            if len(miss_funcs) > 25:
                print(f"  ... and {len(miss_funcs) - 25} more")
    else:
        # Cold functions view
        for name, data in display_funcs[:100]:
            br = branches.get(name, {"taken": [], "not_taken": []})
            total_br = len(br["taken"]) + len(br["not_taken"])
            br_str = f"({total_br} branches)" if total_br > 0 else ""
            print(f"  {name:<50} PC: {data['pc']:<8} {br_str}")
        if len(display_funcs) > 100:
            print(f"\n  ... and {len(display_funcs) - 100} more unhit functions")
        print(f"\n\033[1mTotal unhit:\033[0m {len(display_funcs)}/{total_funcs} ({100*len(display_funcs)/total_funcs:.1f}%)")

if __name__ == "__main__":
    main()
