//! Interactive HTML coverage visualization with CFG view.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use super::types::{
    CachedFunctionInfo, CachedProgramAnalysis, CoverageStats, CoverageWriteStats, FunctionInfo,
};

/// Generate an interactive HTML coverage visualization.
///
/// The HTML includes:
/// - Stats header with runtime, executions, coverage %
/// - Function sidebar with search filter and sort buttons
/// - CFG view for selected function with edges/arrows
/// - Color coding: green (covered), yellow (partial), red (uncovered)
/// - Auto-refresh every 5 seconds
pub fn generate_coverage_html<W: Write>(
    writer: &mut W,
    program_name: &str,
    program_data: &[u8],
    pc_hits: &HashMap<usize, u64>,
    stats: Option<&CoverageWriteStats>,
) -> std::io::Result<()> {
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
        fn active_mapping_ptr(
            &mut self,
        ) -> std::ptr::NonNull<solana_sbpf::memory_region::MemoryMapping> {
            unreachable!("static ELF analysis never executes the VM")
        }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    let analysis = Analysis::from_executable(&executable)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)))?;

    // Build function list with coverage stats
    let mut functions: Vec<(FunctionInfo, CoverageStats)> = Vec::new();
    let mut pc_to_node: HashMap<usize, usize> = HashMap::new();

    for (node_idx, cfg_node) in &analysis.cfg_nodes {
        if !cfg_node.instructions.is_empty() {
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            pc_to_node.insert(first_pc, *node_idx);
        }
    }

    // Calculate stats per function
    for (pc, (_key, name)) in &analysis.functions {
        let func = FunctionInfo {
            name: if name.is_empty() {
                format!("fn_{:x}", pc)
            } else {
                name.clone()
            },
            entry_pc: *pc,
        };

        // Calculate coverage for this function by BFS from entry
        let mut stats = CoverageStats::default();
        if let Some(&entry_node) = pc_to_node.get(pc) {
            let mut visited = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(entry_node);
            visited.insert(entry_node);

            while let Some(node_idx) = queue.pop_front() {
                if let Some(cfg_node) = analysis.cfg_nodes.get(&node_idx) {
                    // Track block coverage
                    stats.total_blocks += 1;
                    let mut block_hit = false;

                    for insn_idx in cfg_node.instructions.clone() {
                        let insn = &analysis.instructions[insn_idx];
                        stats.total_instructions += 1;
                        if pc_hits.get(&insn.ptr).copied().unwrap_or(0) > 0 {
                            stats.hit_instructions += 1;
                            block_hit = true;
                        }

                        // Count branches
                        if crate::coverage::is_conditional_branch_opcode(insn.opc) {
                            stats.total_branches += 1;
                            if pc_hits.get(&insn.ptr).copied().unwrap_or(0) > 0 {
                                stats.hit_branches += 1;
                            }
                        }
                    }

                    if block_hit {
                        stats.hit_blocks += 1;
                    }

                    for &dest in &cfg_node.destinations {
                        if visited.insert(dest) {
                            queue.push_back(dest);
                        }
                    }
                }
            }
        }

        functions.push((func, stats));
    }

    // Sort by name
    functions.sort_by(|a, b| a.0.name.cmp(&b.0.name));

    // Calculate overall stats
    let overall_hit: usize = functions.iter().map(|(_, s)| s.hit_instructions).sum();
    let overall_total: usize = functions.iter().map(|(_, s)| s.total_instructions).sum();
    let _overall_pct = if overall_total > 0 {
        100.0 * overall_hit as f64 / overall_total as f64
    } else {
        0.0
    };
    let blocks_hit: usize = functions.iter().map(|(_, s)| s.hit_blocks).sum();
    let blocks_total: usize = functions.iter().map(|(_, s)| s.total_blocks).sum();

    // Generate function list JSON with block counts
    let functions_json: Vec<String> = functions.iter().map(|(f, s)| {
        format!(
            r#"{{"name":"{}","pc":{},"hit":{},"total":{},"pct":{:.1},"blocks_hit":{},"blocks_total":{}}}"#,
            escape_json(&f.name),
            f.entry_pc,
            s.hit_instructions,
            s.total_instructions,
            s.instruction_coverage_pct(),
            s.hit_blocks,
            s.total_blocks
        )
    }).collect();

    // Wrap functions in program object
    let programs_json = format!(
        r#"{{"name":"{}","hit":{},"total":{},"blocks_hit":{},"blocks_total":{},"functions":[{}]}}"#,
        escape_json(program_name),
        overall_hit,
        overall_total,
        blocks_hit,
        blocks_total,
        functions_json.join(",")
    );

    // Generate CFG data per function (as JSON for JS rendering)
    let mut cfg_json_parts: Vec<String> = Vec::new();
    for (func, _) in &functions {
        if let Some(&entry_node) = pc_to_node.get(&func.entry_pc) {
            let cfg_data = generate_function_cfg_json(&analysis, entry_node, pc_hits);
            cfg_json_parts.push(format!(r#""{}": {}"#, escape_json(&func.name), cfg_data));
        }
    }

    // Build stats header HTML
    let stats_html = if let Some(s) = stats {
        let edges_pct = if s.edges_total > 0 {
            100.0 * s.edges_hit as f64 / s.edges_total as f64
        } else {
            0.0
        };
        let branches_pct = if s.branches_total > 0 {
            100.0 * s.branches_hit as f64 / s.branches_total as f64
        } else {
            0.0
        };
        let instr_pct = if s.instructions_total > 0 {
            100.0 * s.instructions_hit as f64 / s.instructions_total as f64
        } else {
            0.0
        };
        format!(
            r#"<div id="stats-header">
            <div class="stat-row"><button id="refresh-btn" onclick="location.reload()">Refresh</button><div class="theme-selector"><button class="theme-btn" data-theme="neon" onclick="setTheme('neon')">Neon</button><button class="theme-btn" data-theme="cyber" onclick="setTheme('cyber')">Cyber</button><button class="theme-btn" data-theme="ocean" onclick="setTheme('ocean')">Ocean</button></div><span class="stat">Runtime: <b>{}s</b></span><span class="stat">Execs: <b>{}</b></span></div>
            <div class="stat-row"><span class="stat">Edges: <b>{}/{}</b> ({:.1}%)</span><span class="stat">Branches: <b>{}/{}</b> ({:.1}%)</span><span class="stat">Blocks: <b>{}/{}</b> ({:.1}%)</span></div>
        </div>"#,
            s.run_time_secs,
            s.executions,
            s.edges_hit,
            s.edges_total,
            edges_pct,
            s.branches_hit,
            s.branches_total,
            branches_pct,
            s.instructions_hit,
            s.instructions_total,
            instr_pct
        )
    } else {
        String::new()
    };

    // Write HTML
    write!(
        writer,
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Coverage - {}</title>
    <style>
        /* Theme: Neon (Solana-inspired - DEFAULT) */
        :root, [data-theme="neon"] {{
            --primary: #9945FF;
            --secondary: #14F195;
            --accent: #00C2FF;
            --hit: #14F195;
            --partial: #00C2FF;
            --miss: #F971FF;
            --bg-dark: #0e0e10;
            --bg-mid: #131315;
            --bg-light: #1a1a2e;
            --border: #2a2a3a;
            --text: #e0e0e0;
            --text-dim: #888899;
            --glow-primary: rgba(153,69,255,0.3);
            --glow-hit: rgba(20,241,149,0.3);
        }}
        /* Theme: Cyber (Asymmetric Research) */
        [data-theme="cyber"] {{
            --primary: #FF6B35;
            --secondary: #4A4A4A;
            --accent: #FF8C42;
            --hit: #2E8B57;
            --partial: #B8860B;
            --miss: #CD5C5C;
            --bg-dark: #0a0a0a;
            --bg-mid: #141414;
            --bg-light: #1e1e1e;
            --border: #333333;
            --text: #e0e0e0;
            --text-dim: #999999;
            --glow-primary: rgba(255,107,53,0.15);
            --glow-hit: rgba(46,139,87,0.2);
        }}
        /* Theme: Ocean (Anchor-inspired) */
        [data-theme="ocean"] {{
            --primary: #0066CC;
            --secondary: #00A3A3;
            --accent: #4ECDC4;
            --hit: #00D9A5;
            --partial: #00A3A3;
            --miss: #FF6B6B;
            --bg-dark: #0B1426;
            --bg-mid: #0F1C30;
            --bg-light: #162A45;
            --border: #1E3A5F;
            --text: #E8F4F8;
            --text-dim: #7BA3C4;
            --glow-primary: rgba(0,102,204,0.3);
            --glow-hit: rgba(0,217,165,0.3);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace; display: flex; flex-direction: column; height: 100vh; background: var(--bg-dark); }}
        #stats-header {{ background: linear-gradient(135deg, color-mix(in srgb, var(--primary) 15%, transparent) 0%, var(--bg-mid) 100%); padding: 14px 24px; border-bottom: 1px solid var(--border); display: flex; gap: 24px; flex-wrap: wrap; backdrop-filter: blur(10px); }}
        .stat-row {{ display: flex; gap: 24px; align-items: center; }}
        .stat {{ color: var(--text-dim); font-size: 13px; }}
        .stat b {{ color: var(--primary); }}
        .theme-selector {{ display: flex; gap: 4px; margin-right: 16px; }}
        .theme-btn {{ padding: 6px 12px; background: var(--bg-dark); border: 1px solid var(--border); color: var(--text-dim); border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }}
        .theme-btn:hover {{ border-color: var(--primary); color: var(--text); }}
        .theme-btn.active {{ background: var(--primary); border-color: var(--primary); color: white; }}
        #refresh-btn {{ padding: 8px 16px; background: var(--primary); color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s; box-shadow: 0 2px 10px var(--glow-primary); }}
        #refresh-btn:hover {{ transform: translateY(-1px); box-shadow: 0 4px 20px var(--glow-primary); }}
        #container {{ display: flex; flex: 1; overflow: hidden; }}
        #sidebar {{ width: 340px; background: var(--bg-mid); color: var(--text); overflow-y: auto; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid var(--border); }}
        #sidebar-header {{ padding: 16px; background: linear-gradient(180deg, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 100%); border-bottom: 1px solid var(--border); }}
        #sidebar-header h2 {{ font-size: 15px; margin-bottom: 12px; color: var(--primary); }}
        #search {{ width: 100%; padding: 10px 14px; border: 1px solid var(--border); background: var(--bg-dark); color: #fff; border-radius: 8px; margin-bottom: 12px; transition: border-color 0.2s; }}
        #search:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--glow-primary); }}
        #sort-controls {{ display: flex; gap: 6px; }}
        .sort-btn {{ padding: 6px 12px; font-size: 11px; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text-dim); border-radius: 6px; cursor: pointer; transition: all 0.2s; }}
        .sort-btn:hover {{ background: var(--bg-light); border-color: var(--primary); color: #fff; }}
        .sort-btn.active {{ background: var(--primary); border-color: transparent; color: #fff; }}
        .func-list {{ list-style: none; flex: 1; overflow-y: auto; }}
        .program-section {{ border-bottom: 1px solid var(--border); }}
        .program-header {{ padding: 12px 16px; background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 100%); cursor: pointer; display: flex; align-items: center; user-select: none; transition: background 0.2s; }}
        .program-header:hover {{ background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 20%, transparent) 0%, var(--bg-light) 100%); }}
        .collapse-icon {{ margin-right: 10px; font-size: 10px; color: var(--primary); transition: transform 0.2s; }}
        .program-header.collapsed .collapse-icon {{ transform: rotate(-90deg); }}
        .program-name {{ flex: 1; font-weight: 600; font-size: 13px; color: #fff; }}
        .program-stats {{ font-size: 11px; color: var(--text-dim); padding-left: 12px; }}
        .program-funcs {{ }}
        .program-funcs.collapsed {{ display: none; }}
        .func-item {{ padding: 10px 16px 10px 32px; cursor: pointer; border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent); display: flex; justify-content: space-between; align-items: center; transition: all 0.15s; }}
        .func-item:hover {{ background: color-mix(in srgb, var(--primary) 10%, transparent); }}
        .func-item.active {{ background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 30%, transparent) 0%, color-mix(in srgb, var(--accent) 10%, transparent) 100%); border-left: 3px solid var(--primary); }}
        .func-name {{ font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }}
        .func-blocks {{ font-size: 10px; color: var(--text-dim); margin-left: 8px; }}
        .func-pct {{ font-size: 11px; margin-left: 8px; padding: 3px 8px; border-radius: 4px; font-weight: 600; }}
        .pct-high {{ background: color-mix(in srgb, var(--hit) 20%, transparent); color: var(--hit); border: 1px solid color-mix(in srgb, var(--hit) 30%, transparent); }}
        .pct-med {{ background: color-mix(in srgb, var(--partial) 20%, transparent); color: var(--partial); border: 1px solid color-mix(in srgb, var(--partial) 30%, transparent); }}
        .pct-low {{ background: color-mix(in srgb, var(--miss) 20%, transparent); color: var(--miss); border: 1px solid color-mix(in srgb, var(--miss) 30%, transparent); }}
        #main {{ flex: 1; background: radial-gradient(ellipse at top left, color-mix(in srgb, var(--primary) 5%, transparent) 0%, var(--bg-dark) 50%); overflow: hidden; padding: 20px; position: relative; }}
        #cfg-viewport {{ width: 100%; height: calc(100% - 40px); overflow: hidden; cursor: grab; position: relative; border-radius: 12px; background: var(--bg-mid); border: 1px solid var(--border); }}
        #cfg-viewport:active {{ cursor: grabbing; }}
        #cfg-container {{ position: absolute; transform-origin: 0 0; transition: none; }}
        .cfg-title {{ color: #fff; font-size: 16px; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }}
        .cfg-title::before {{ content: ''; width: 4px; height: 20px; background: linear-gradient(180deg, var(--primary), var(--hit)); border-radius: 2px; }}
        .zoom-controls {{ position: absolute; bottom: 16px; right: 16px; display: flex; gap: 8px; z-index: 10; }}
        .zoom-btn {{ width: 36px; height: 36px; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text); border-radius: 8px; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }}
        .zoom-btn:hover {{ background: var(--primary); border-color: var(--primary); }}
        .block {{ fill: var(--bg-light); stroke: var(--border); stroke-width: 2; rx: 8; }}
        .block-hit {{ fill: color-mix(in srgb, var(--hit) 15%, transparent); stroke: var(--hit); }}
        .block-partial {{ fill: color-mix(in srgb, var(--partial) 15%, transparent); stroke: var(--partial); }}
        .block-miss {{ fill: color-mix(in srgb, var(--miss) 10%, transparent); stroke: var(--miss); opacity: 0.7; }}
        .block-text {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 10px; fill: var(--text); }}
        .edge {{ stroke: var(--border); stroke-width: 2; fill: none; marker-end: url(#arrow); }}
        .edge-hit {{ stroke: var(--hit); }}
        .edge-miss {{ stroke: var(--miss); stroke-dasharray: 6,4; opacity: 0.6; }}
        .edge-back {{ stroke-dasharray: 4,4; }}
        /* Flash animation for new blocks */
        @keyframes blockFlash {{
            0% {{ filter: brightness(1); }}
            50% {{ filter: brightness(1.5); box-shadow: 0 0 20px var(--hit); }}
            100% {{ filter: brightness(1); }}
        }}
        .func-item.just-updated {{ animation: blockFlash 0.8s ease-out; }}
        .new-badge {{ background: var(--hit); color: var(--bg-dark); font-size: 10px; padding: 2px 6px; border-radius: 10px; margin-left: 8px; font-weight: bold; }}
    </style>
    <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
</head>
<body>
    {}
    <div id="container">
        <div id="sidebar">
            <div id="sidebar-header">
                <h2>{}</h2>
                <input type="text" id="search" placeholder="Filter functions..." oninput="filterFunctions()">
                <div id="sort-controls">
                    <button class="sort-btn active" onclick="sortBy('name')">Name</button>
                    <button class="sort-btn" onclick="sortBy('pct-desc')">Coverage ↓</button>
                    <button class="sort-btn" onclick="sortBy('pct-asc')">Coverage ↑</button>
                </div>
            </div>
            <ul class="func-list" id="func-list"></ul>
        </div>
        <div id="main">
            <div class="cfg-title" id="cfg-title">Select a function</div>
            <div id="cfg-viewport">
                <div id="cfg-container"></div>
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoomIn()">+</button>
                    <button class="zoom-btn" onclick="zoomOut()">-</button>
                    <button class="zoom-btn" onclick="resetView()">⌂</button>
                </div>
            </div>
        </div>
    </div>
    <script>
const programs = [{}];
const cfgData = {{{}}};

// Theme switching
function setTheme(theme) {{
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('coverage-theme', theme);
    document.querySelectorAll('.theme-btn').forEach(btn => {{
        btn.classList.toggle('active', btn.dataset.theme === theme);
    }});
    updateArrowColors();
}}

function updateArrowColors() {{
    const style = getComputedStyle(document.documentElement);
    const hitColor = style.getPropertyValue('--hit').trim();
    const missColor = style.getPropertyValue('--miss').trim();
    const borderColor = style.getPropertyValue('--border').trim();
    // Update arrow markers dynamically
    const arrowHit = document.querySelector('#arrow-hit path');
    const arrowMiss = document.querySelector('#arrow-miss path');
    const arrow = document.querySelector('#arrow path');
    if (arrowHit) arrowHit.setAttribute('fill', hitColor);
    if (arrowMiss) arrowMiss.setAttribute('fill', missColor);
    if (arrow) arrow.setAttribute('fill', borderColor);
}}

// Live update detection
let lastBlockCounts = {{}};

function checkForUpdates() {{
    const prevSnapshot = JSON.parse(localStorage.getItem('coverage-snapshot') || '{{}}');
    programs.forEach(p => p.functions.forEach(f => {{
        const prev = prevSnapshot[f.name];
        if (prev !== undefined && f.blocks_hit > prev) {{
            flashFunction(f.name, f.blocks_hit - prev);
        }}
    }}));
    // Save current snapshot
    const snapshot = {{}};
    programs.forEach(p => p.functions.forEach(f => {{
        snapshot[f.name] = f.blocks_hit;
    }}));
    localStorage.setItem('coverage-snapshot', JSON.stringify(snapshot));
}}

function flashFunction(name, newCount) {{
    const item = document.querySelector(`[data-name="${{name}}"]`);
    if (item) {{
        item.classList.add('just-updated');
        const existing = item.querySelector('.new-badge');
        if (existing) existing.remove();
        const badge = document.createElement('span');
        badge.className = 'new-badge';
        badge.textContent = `+${{newCount}}`;
        item.appendChild(badge);
        setTimeout(() => {{
            item.classList.remove('just-updated');
            badge.remove();
        }}, 2500);
    }}
}}

let currentSort = 'name';

// Viewport pan/zoom state
let viewState = {{ x: 0, y: 0, scale: 1 }};
let isDragging = false;
let dragStart = {{ x: 0, y: 0 }};

function initViewport() {{
    const viewport = document.getElementById('cfg-viewport');
    if (!viewport) return;

    viewport.addEventListener('mousedown', (e) => {{
        if (e.target.closest('.zoom-btn')) return;
        isDragging = true;
        dragStart = {{ x: e.clientX - viewState.x, y: e.clientY - viewState.y }};
        viewport.style.cursor = 'grabbing';
    }});

    viewport.addEventListener('mousemove', (e) => {{
        if (!isDragging) return;
        viewState.x = e.clientX - dragStart.x;
        viewState.y = e.clientY - dragStart.y;
        updateViewTransform();
    }});

    viewport.addEventListener('mouseup', () => {{
        isDragging = false;
        viewport.style.cursor = 'grab';
    }});

    viewport.addEventListener('mouseleave', () => {{
        isDragging = false;
        viewport.style.cursor = 'grab';
    }});

    viewport.addEventListener('wheel', (e) => {{
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        const newScale = Math.max(0.2, Math.min(3, viewState.scale * delta));

        // Zoom towards mouse position
        const rect = viewport.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        viewState.x = mouseX - (mouseX - viewState.x) * (newScale / viewState.scale);
        viewState.y = mouseY - (mouseY - viewState.y) * (newScale / viewState.scale);
        viewState.scale = newScale;
        updateViewTransform();
    }}, {{ passive: false }});
}}

function updateViewTransform() {{
    const container = document.getElementById('cfg-container');
    if (container) {{
        container.style.transform = `translate(${{viewState.x}}px, ${{viewState.y}}px) scale(${{viewState.scale}})`;
    }}
}}

function zoomIn() {{
    viewState.scale = Math.min(3, viewState.scale * 1.2);
    updateViewTransform();
}}

function zoomOut() {{
    viewState.scale = Math.max(0.2, viewState.scale * 0.8);
    updateViewTransform();
}}

function resetView() {{
    viewState = {{ x: 20, y: 20, scale: 1 }};
    updateViewTransform();
}}

function filterFunctions() {{
    const query = document.getElementById('search').value.toLowerCase();
    const items = document.querySelectorAll('.func-item');
    items.forEach(item => {{
        const name = item.dataset.name.toLowerCase();
        item.style.display = name.includes(query) ? '' : 'none';
    }});
    // Show program headers if any child is visible
    document.querySelectorAll('.program-section').forEach(section => {{
        const hasVisible = [...section.querySelectorAll('.func-item')].some(item => item.style.display !== 'none');
        section.style.display = hasVisible ? '' : 'none';
    }});
}}

function sortBy(mode) {{
    currentSort = mode;
    renderPrograms();
    document.querySelectorAll('.sort-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}}

function toggleProgram(idx) {{
    const section = document.querySelector(`[data-program="${{idx}}"]`);
    if (!section) return;
    const header = section.querySelector('.program-header');
    const funcs = section.querySelector('.program-funcs');
    header.classList.toggle('collapsed');
    funcs.classList.toggle('collapsed');
}}

function renderPrograms() {{
    const listEl = document.getElementById('func-list');
    listEl.innerHTML = '';

    programs.forEach((prog, idx) => {{
        const section = document.createElement('div');
        section.className = 'program-section';
        section.dataset.program = idx;

        // Program header
        const header = document.createElement('div');
        header.className = 'program-header';
        header.onclick = () => toggleProgram(idx);
        const blockPct = prog.blocks_total > 0 ? (100 * prog.blocks_hit / prog.blocks_total).toFixed(0) : 0;
        header.innerHTML = `<span class="collapse-icon">▼</span><span class="program-name">${{prog.name}}</span><span class="program-stats">${{prog.blocks_hit}}/${{prog.blocks_total}} blocks (${{blockPct}}%)</span>`;
        section.appendChild(header);

        // Function list
        const funcsDiv = document.createElement('div');
        funcsDiv.className = 'program-funcs';

        // Sort functions
        const sortedFuncs = [...prog.functions].sort((a, b) => {{
            if (currentSort === 'name') return a.name.localeCompare(b.name);
            if (currentSort === 'pct-asc') return a.pct - b.pct;
            if (currentSort === 'pct-desc') return b.pct - a.pct;
            return 0;
        }});

        sortedFuncs.forEach(f => {{
            const li = document.createElement('div');
            li.className = 'func-item';
            li.dataset.name = f.name;
            li.dataset.pct = f.pct;
            li.onclick = (e) => {{ e.stopPropagation(); selectFunction(f.name); }};
            const pctClass = f.pct >= 80 ? 'pct-high' : f.pct >= 40 ? 'pct-med' : 'pct-low';
            const blocksInfo = f.blocks_total ? `${{f.blocks_hit}}/${{f.blocks_total}}` : '';
            li.innerHTML = `<span class="func-name">${{f.name}}</span><span class="func-blocks">${{blocksInfo}}</span><span class="func-pct ${{pctClass}}">${{f.pct.toFixed(0)}}%</span>`;
            funcsDiv.appendChild(li);
        }});

        section.appendChild(funcsDiv);
        listEl.appendChild(section);
    }});
}}

function selectFunction(name) {{
    document.querySelectorAll('.func-item').forEach(el => el.classList.remove('active'));
    document.querySelector(`[data-name="${{name}}"]`)?.classList.add('active');
    document.getElementById('cfg-title').textContent = name;
    renderCFG(name);
    resetView();
}}

function renderCFG(name) {{
    const container = document.getElementById('cfg-container');
    const data = cfgData[name];
    if (!data) {{
        container.innerHTML = '<p style="color:#888">No CFG data available</p>';
        return;
    }}

    const nodes = data.nodes || [];
    const edges = data.edges || [];

    // Create Dagre graph for layout
    const g = new dagre.graphlib.Graph();
    g.setGraph({{ rankdir: 'TB', nodesep: 40, ranksep: 60, marginx: 40, marginy: 40 }});
    g.setDefaultEdgeLabel(() => ({{}}));

    const nodeWidth = 220;
    const nodeHeight = 80;

    // Add nodes to Dagre
    nodes.forEach(node => {{
        g.setNode(node.id.toString(), {{ width: nodeWidth, height: nodeHeight, data: node }});
    }});

    // Add edges to Dagre
    edges.forEach(edge => {{
        g.setEdge(edge.from.toString(), edge.to.toString(), {{ data: edge }});
    }});

    // Compute layout
    dagre.layout(g);

    // Get graph dimensions
    const graphWidth = g.graph().width + 80;
    const graphHeight = g.graph().height + 80;

    let svg = `<svg width="${{graphWidth}}" height="${{graphHeight}}">`;
    svg += `<defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#2a2a3a"/></marker>
        <marker id="arrow-hit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#14F195"/></marker>
        <marker id="arrow-miss" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#F971FF"/></marker>
    </defs>`;

    // Draw edges using Dagre's computed points
    g.edges().forEach(e => {{
        const edgeData = g.edge(e);
        const origEdge = edges.find(ed => ed.from.toString() === e.v && ed.to.toString() === e.w);
        if (!edgeData || !edgeData.points || !origEdge) return;

        const edgeCls = origEdge.hit ? 'edge edge-hit' : 'edge edge-miss';
        const marker = origEdge.hit ? 'url(#arrow-hit)' : 'url(#arrow-miss)';

        // Build path from Dagre's waypoints
        const points = edgeData.points;
        let pathD = `M ${{points[0].x}} ${{points[0].y}}`;
        for (let i = 1; i < points.length; i++) {{
            pathD += ` L ${{points[i].x}} ${{points[i].y}}`;
        }}
        svg += `<path d="${{pathD}}" class="${{edgeCls}}" style="marker-end: ${{marker}}"/>`;
    }});

    // Draw nodes at Dagre-computed positions
    g.nodes().forEach(nodeId => {{
        const pos = g.node(nodeId);
        if (!pos || !pos.data) return;
        const node = pos.data;
        const x = pos.x - nodeWidth / 2;
        const y = pos.y - nodeHeight / 2;
        const hit = node.hit || 0;
        const total = node.total || 0;
        const cls = hit === total ? 'block-hit' : hit > 0 ? 'block-partial' : 'block-miss';

        svg += `<rect x="${{x}}" y="${{y}}" width="${{nodeWidth}}" height="${{nodeHeight}}" class="block ${{cls}}" rx="4"/>`;
        svg += `<text x="${{x + 8}}" y="${{y + 16}}" class="block-text">Block ${{node.id}} (${{hit}}/${{total}})</text>`;

        const lines = (node.insns || []).slice(0, 4);
        lines.forEach((line, li) => {{
            svg += `<text x="${{x + 8}}" y="${{y + 32 + li * 12}}" class="block-text">${{line}}</text>`;
        }});
    }});

    svg += '</svg>';
    container.innerHTML = svg;
}}

// Initial render
// Initialize
const savedTheme = localStorage.getItem('coverage-theme') || 'neon';
setTheme(savedTheme);
initViewport();
renderPrograms();
checkForUpdates();
if (programs.length > 0 && programs[0].functions.length > 0) selectFunction(programs[0].functions[0].name);
    </script>
</body>
</html>
"##,
        program_name,
        stats_html,
        program_name,
        programs_json,
        cfg_json_parts.join(",")
    )?;

    Ok(())
}

/// Generate CFG JSON for a single function
fn generate_function_cfg_json(
    analysis: &solana_sbpf::static_analysis::Analysis,
    entry_node: usize,
    pc_hits: &HashMap<usize, u64>,
) -> String {
    // BFS to get reachable nodes
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    let mut nodes_data: Vec<String> = Vec::new();
    let mut edges_data: Vec<String> = Vec::new();

    queue.push_back(entry_node);
    visited.insert(entry_node);

    while let Some(node_idx) = queue.pop_front() {
        if let Some(cfg_node) = analysis.cfg_nodes.get(&node_idx) {
            if cfg_node.instructions.is_empty() {
                continue;
            }

            let mut hit_count = 0usize;
            let total = cfg_node.instructions.end - cfg_node.instructions.start;
            let mut insn_strs: Vec<String> = Vec::new();

            for insn_idx in cfg_node.instructions.clone() {
                let insn = &analysis.instructions[insn_idx];
                let hits = pc_hits.get(&insn.ptr).copied().unwrap_or(0);
                if hits > 0 {
                    hit_count += 1;
                }

                let opc_name = match insn.opc {
                    0x05 => "ja",
                    0x07 | 0x0f => "add64",
                    0x15 | 0x1d => "jeq",
                    0x18 => "lddw",
                    0x25 | 0x2d => "jgt",
                    0x55 | 0x5d => "jne",
                    0x61 => "ldxw",
                    0x63 => "stxw",
                    0x69 => "ldxh",
                    0x71 => "ldxb",
                    0x79 => "ldxdw",
                    0x7b => "stxdw",
                    0x85 => "call",
                    0x95 => "exit",
                    0xb7 | 0xbf => "mov64",
                    _ => "???",
                };

                let marker = if hits > 0 { "+" } else { " " };
                insn_strs.push(format!("{} {:05x}: {}", marker, insn.ptr, opc_name));
            }

            let insns_json: Vec<String> = insn_strs
                .iter()
                .take(6)
                .map(|s| format!(r#""{}""#, escape_json(s)))
                .collect();

            nodes_data.push(format!(
                r#"{{"id":{},"hit":{},"total":{},"insns":[{}]}}"#,
                node_idx,
                hit_count,
                total,
                insns_json.join(",")
            ));

            // Add edges
            for &dest in &cfg_node.destinations {
                if visited.insert(dest) {
                    queue.push_back(dest);
                }

                // Check if edge was taken (any instruction in destination node was hit)
                let dest_hit = analysis
                    .cfg_nodes
                    .get(&dest)
                    .map(|n| {
                        n.instructions.clone().any(|insn_idx| {
                            pc_hits
                                .get(&analysis.instructions[insn_idx].ptr)
                                .map(|&h| h > 0)
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                edges_data.push(format!(
                    r#"{{"from":{},"to":{},"hit":{}}}"#,
                    node_idx, dest, dest_hit
                ));
            }
        }
    }

    format!(
        r#"{{"nodes":[{}],"edges":[{}]}}"#,
        nodes_data.join(","),
        edges_data.join(",")
    )
}

/// Escape string for JSON
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Build cached program analysis from binary (called once at startup)
pub fn build_cached_analysis(
    program_name: &str,
    program_data: &[u8],
) -> Option<CachedProgramAnalysis> {
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
        fn active_mapping_ptr(
            &mut self,
        ) -> std::ptr::NonNull<solana_sbpf::memory_region::MemoryMapping> {
            unreachable!("static ELF analysis never executes the VM")
        }
    }

    let loader = Arc::new(BuiltinProgram::<DummyContext>::new_mock());
    let executable = Executable::from_elf(program_data, loader).ok()?;
    let analysis = Analysis::from_executable(&executable).ok()?;

    // Build pc_to_node map
    let mut pc_to_node: HashMap<usize, usize> = HashMap::new();
    for (node_idx, cfg_node) in &analysis.cfg_nodes {
        if !cfg_node.instructions.is_empty() {
            let first_pc = analysis.instructions[cfg_node.instructions.start].ptr;
            pc_to_node.insert(first_pc, *node_idx);
        }
    }

    let mut functions: Vec<CachedFunctionInfo> = Vec::new();
    let mut cfg_json: HashMap<String, String> = HashMap::new();

    // Process each function
    for (pc, (_key, name)) in &analysis.functions {
        let func_name = if name.is_empty() {
            format!("fn_{:x}", pc)
        } else {
            name.clone()
        };

        let mut instruction_pcs: Vec<usize> = Vec::new();
        let mut blocks: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut total_instructions = 0usize;

        if let Some(&entry_node) = pc_to_node.get(pc) {
            let mut visited = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(entry_node);
            visited.insert(entry_node);

            // Also build CFG JSON while traversing
            let mut nodes_data: Vec<String> = Vec::new();
            let mut edges_data: Vec<String> = Vec::new();

            while let Some(node_idx) = queue.pop_front() {
                if let Some(cfg_node) = analysis.cfg_nodes.get(&node_idx) {
                    if cfg_node.instructions.is_empty() {
                        continue;
                    }

                    let mut block_pcs: Vec<usize> = Vec::new();
                    let mut insn_strs: Vec<String> = Vec::new();

                    for insn_idx in cfg_node.instructions.clone() {
                        let insn = &analysis.instructions[insn_idx];
                        instruction_pcs.push(insn.ptr);
                        block_pcs.push(insn.ptr);
                        total_instructions += 1;

                        // Build instruction string for CFG display
                        let opc_name = match insn.opc {
                            0x05 => "ja",
                            0x07 | 0x0f => "add64",
                            0x15 | 0x1d => "jeq",
                            0x18 => "lddw",
                            0x25 | 0x2d => "jgt",
                            0x55 | 0x5d => "jne",
                            0x61 => "ldxw",
                            0x63 => "stxw",
                            0x69 => "ldxh",
                            0x71 => "ldxb",
                            0x79 => "ldxdw",
                            0x7b => "stxdw",
                            0x85 => "call",
                            0x95 => "exit",
                            0xb7 | 0xbf => "mov64",
                            _ => "???",
                        };
                        insn_strs.push(format!("  {:05x}: {}", insn.ptr, opc_name));
                    }

                    blocks.push((node_idx, block_pcs));

                    // Build CFG node JSON (without hit counts - those are added at render time)
                    let total = cfg_node.instructions.end - cfg_node.instructions.start;
                    let insns_json: Vec<String> = insn_strs
                        .iter()
                        .take(6)
                        .map(|s| format!(r#""{}""#, escape_json(s)))
                        .collect();
                    nodes_data.push(format!(
                        r#"{{"id":{},"total":{},"insns":[{}]}}"#,
                        node_idx,
                        total,
                        insns_json.join(",")
                    ));

                    // Add edges
                    for &dest in &cfg_node.destinations {
                        if visited.insert(dest) {
                            queue.push_back(dest);
                        }
                        edges_data.push(format!(r#"{{"from":{},"to":{}}}"#, node_idx, dest));
                    }
                }
            }

            // Store CFG JSON for this function
            cfg_json.insert(
                func_name.clone(),
                format!(
                    r#"{{"nodes":[{}],"edges":[{}]}}"#,
                    nodes_data.join(","),
                    edges_data.join(",")
                ),
            );
        }

        functions.push(CachedFunctionInfo {
            name: func_name,
            entry_pc: *pc,
            total_instructions,
            total_blocks: blocks.len(),
            instruction_pcs,
            blocks,
        });
    }

    // Sort by name
    functions.sort_by(|a, b| a.name.cmp(&b.name));

    Some(CachedProgramAnalysis {
        program_name: program_name.to_string(),
        functions,
        cfg_json,
    })
}

/// Generate HTML coverage visualization using cached analysis (fast path)
pub fn generate_coverage_html_cached<W: Write>(
    writer: &mut W,
    cached: &CachedProgramAnalysis,
    pc_hits: &HashMap<usize, u64>,
    stats: Option<&CoverageWriteStats>,
) -> std::io::Result<()> {
    // Compute hit counts from cached data
    let mut functions_with_stats: Vec<(&CachedFunctionInfo, CoverageStats)> = Vec::new();

    for func in &cached.functions {
        let hit_instructions = func
            .instruction_pcs
            .iter()
            .filter(|pc| pc_hits.get(pc).map(|&h| h > 0).unwrap_or(false))
            .count();

        let hit_blocks = func
            .blocks
            .iter()
            .filter(|(_, block_pcs)| {
                block_pcs
                    .iter()
                    .any(|pc| pc_hits.get(pc).map(|&h| h > 0).unwrap_or(false))
            })
            .count();

        functions_with_stats.push((
            func,
            CoverageStats {
                total_instructions: func.total_instructions,
                hit_instructions,
                total_branches: 0, // Not tracked in cached version
                hit_branches: 0,
                total_blocks: func.total_blocks,
                hit_blocks,
            },
        ));
    }

    // Calculate overall stats
    let overall_hit: usize = functions_with_stats
        .iter()
        .map(|(_, s)| s.hit_instructions)
        .sum();
    let overall_total: usize = functions_with_stats
        .iter()
        .map(|(_, s)| s.total_instructions)
        .sum();
    let _overall_pct = if overall_total > 0 {
        100.0 * overall_hit as f64 / overall_total as f64
    } else {
        0.0
    };
    let blocks_hit: usize = functions_with_stats.iter().map(|(_, s)| s.hit_blocks).sum();
    let blocks_total: usize = functions_with_stats
        .iter()
        .map(|(_, s)| s.total_blocks)
        .sum();

    // Generate function list JSON with block counts
    let functions_json: Vec<String> = functions_with_stats.iter().map(|(f, s)| {
        format!(
            r#"{{"name":"{}","pc":{},"hit":{},"total":{},"pct":{:.1},"blocks_hit":{},"blocks_total":{}}}"#,
            escape_json(&f.name),
            f.entry_pc,
            s.hit_instructions,
            s.total_instructions,
            s.instruction_coverage_pct(),
            s.hit_blocks,
            s.total_blocks
        )
    }).collect();

    // Wrap functions in program object
    let programs_json = format!(
        r#"{{"name":"{}","hit":{},"total":{},"blocks_hit":{},"blocks_total":{},"functions":[{}]}}"#,
        escape_json(&cached.program_name),
        overall_hit,
        overall_total,
        blocks_hit,
        blocks_total,
        functions_json.join(",")
    );

    // Generate CFG data with hit counts computed from pc_hits
    let mut cfg_json_parts: Vec<String> = Vec::new();
    for (func, _) in &functions_with_stats {
        if let Some(cached_cfg) = cached.cfg_json.get(&func.name) {
            // Parse cached CFG and add hit counts
            let cfg_with_hits = add_hit_counts_to_cfg(cached_cfg, &func.blocks, pc_hits);
            cfg_json_parts.push(format!(
                r#""{}": {}"#,
                escape_json(&func.name),
                cfg_with_hits
            ));
        }
    }

    // Build stats header HTML
    let stats_html = if let Some(s) = stats {
        let edges_pct = if s.edges_total > 0 {
            100.0 * s.edges_hit as f64 / s.edges_total as f64
        } else {
            0.0
        };
        let branches_pct = if s.branches_total > 0 {
            100.0 * s.branches_hit as f64 / s.branches_total as f64
        } else {
            0.0
        };
        let instr_pct = if s.instructions_total > 0 {
            100.0 * s.instructions_hit as f64 / s.instructions_total as f64
        } else {
            0.0
        };
        format!(
            r#"<div id="stats-header">
            <div class="stat-row"><button id="refresh-btn" onclick="location.reload()">Refresh</button><div class="theme-selector"><button class="theme-btn" data-theme="neon" onclick="setTheme('neon')">Neon</button><button class="theme-btn" data-theme="cyber" onclick="setTheme('cyber')">Cyber</button><button class="theme-btn" data-theme="ocean" onclick="setTheme('ocean')">Ocean</button></div><span class="stat">Runtime: <b>{}s</b></span><span class="stat">Execs: <b>{}</b></span></div>
            <div class="stat-row"><span class="stat">Edges: <b>{}/{}</b> ({:.1}%)</span><span class="stat">Branches: <b>{}/{}</b> ({:.1}%)</span><span class="stat">Blocks: <b>{}/{}</b> ({:.1}%)</span></div>
        </div>"#,
            s.run_time_secs,
            s.executions,
            s.edges_hit,
            s.edges_total,
            edges_pct,
            s.branches_hit,
            s.branches_total,
            branches_pct,
            s.instructions_hit,
            s.instructions_total,
            instr_pct
        )
    } else {
        String::new()
    };

    // Write HTML (same template as non-cached version but with block counts in function list)
    write!(
        writer,
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Coverage - {}</title>
    <style>
        /* Theme: Neon (Solana-inspired - DEFAULT) */
        :root, [data-theme="neon"] {{
            --primary: #9945FF;
            --secondary: #14F195;
            --accent: #00C2FF;
            --hit: #14F195;
            --partial: #00C2FF;
            --miss: #F971FF;
            --bg-dark: #0e0e10;
            --bg-mid: #131315;
            --bg-light: #1a1a2e;
            --border: #2a2a3a;
            --text: #e0e0e0;
            --text-dim: #888899;
            --glow-primary: rgba(153,69,255,0.3);
            --glow-hit: rgba(20,241,149,0.3);
        }}
        /* Theme: Cyber (Asymmetric Research) */
        [data-theme="cyber"] {{
            --primary: #FF6B35;
            --secondary: #4A4A4A;
            --accent: #FF8C42;
            --hit: #2E8B57;
            --partial: #B8860B;
            --miss: #CD5C5C;
            --bg-dark: #0a0a0a;
            --bg-mid: #141414;
            --bg-light: #1e1e1e;
            --border: #333333;
            --text: #e0e0e0;
            --text-dim: #999999;
            --glow-primary: rgba(255,107,53,0.15);
            --glow-hit: rgba(46,139,87,0.2);
        }}
        /* Theme: Ocean (Anchor-inspired) */
        [data-theme="ocean"] {{
            --primary: #0066CC;
            --secondary: #00A3A3;
            --accent: #4ECDC4;
            --hit: #00D9A5;
            --partial: #00A3A3;
            --miss: #FF6B6B;
            --bg-dark: #0B1426;
            --bg-mid: #0F1C30;
            --bg-light: #162A45;
            --border: #1E3A5F;
            --text: #E8F4F8;
            --text-dim: #7BA3C4;
            --glow-primary: rgba(0,102,204,0.3);
            --glow-hit: rgba(0,217,165,0.3);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace; display: flex; flex-direction: column; height: 100vh; background: var(--bg-dark); }}
        #stats-header {{ background: linear-gradient(135deg, color-mix(in srgb, var(--primary) 15%, transparent) 0%, var(--bg-mid) 100%); padding: 14px 24px; border-bottom: 1px solid var(--border); display: flex; gap: 24px; flex-wrap: wrap; backdrop-filter: blur(10px); }}
        .stat-row {{ display: flex; gap: 24px; align-items: center; }}
        .stat {{ color: var(--text-dim); font-size: 13px; }}
        .stat b {{ color: var(--primary); }}
        .theme-selector {{ display: flex; gap: 4px; margin-right: 16px; }}
        .theme-btn {{ padding: 6px 12px; background: var(--bg-dark); border: 1px solid var(--border); color: var(--text-dim); border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }}
        .theme-btn:hover {{ border-color: var(--primary); color: var(--text); }}
        .theme-btn.active {{ background: var(--primary); border-color: var(--primary); color: white; }}
        #refresh-btn {{ padding: 8px 16px; background: var(--primary); color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s; box-shadow: 0 2px 10px var(--glow-primary); }}
        #refresh-btn:hover {{ transform: translateY(-1px); box-shadow: 0 4px 20px var(--glow-primary); }}
        #container {{ display: flex; flex: 1; overflow: hidden; }}
        #sidebar {{ width: 340px; background: var(--bg-mid); color: var(--text); overflow-y: auto; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid var(--border); }}
        #sidebar-header {{ padding: 16px; background: linear-gradient(180deg, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 100%); border-bottom: 1px solid var(--border); }}
        #sidebar-header h2 {{ font-size: 15px; margin-bottom: 12px; color: var(--primary); }}
        #search {{ width: 100%; padding: 10px 14px; border: 1px solid var(--border); background: var(--bg-dark); color: #fff; border-radius: 8px; margin-bottom: 12px; transition: border-color 0.2s; }}
        #search:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--glow-primary); }}
        #sort-controls {{ display: flex; gap: 6px; }}
        .sort-btn {{ padding: 6px 12px; font-size: 11px; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text-dim); border-radius: 6px; cursor: pointer; transition: all 0.2s; }}
        .sort-btn:hover {{ background: var(--bg-light); border-color: var(--primary); color: #fff; }}
        .sort-btn.active {{ background: var(--primary); border-color: transparent; color: #fff; }}
        .func-list {{ list-style: none; flex: 1; overflow-y: auto; }}
        .program-section {{ border-bottom: 1px solid var(--border); }}
        .program-header {{ padding: 12px 16px; background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 100%); cursor: pointer; display: flex; align-items: center; user-select: none; transition: background 0.2s; }}
        .program-header:hover {{ background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 20%, transparent) 0%, var(--bg-light) 100%); }}
        .collapse-icon {{ margin-right: 10px; font-size: 10px; color: var(--primary); transition: transform 0.2s; }}
        .program-header.collapsed .collapse-icon {{ transform: rotate(-90deg); }}
        .program-name {{ flex: 1; font-weight: 600; font-size: 13px; color: #fff; }}
        .program-stats {{ font-size: 11px; color: var(--text-dim); padding-left: 12px; }}
        .program-funcs {{ }}
        .program-funcs.collapsed {{ display: none; }}
        .func-item {{ padding: 10px 16px 10px 32px; cursor: pointer; border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent); display: flex; justify-content: space-between; align-items: center; transition: all 0.15s; }}
        .func-item:hover {{ background: color-mix(in srgb, var(--primary) 10%, transparent); }}
        .func-item.active {{ background: linear-gradient(90deg, color-mix(in srgb, var(--primary) 30%, transparent) 0%, color-mix(in srgb, var(--accent) 10%, transparent) 100%); border-left: 3px solid var(--primary); }}
        .func-name {{ font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }}
        .func-blocks {{ font-size: 10px; color: var(--text-dim); margin-left: 8px; }}
        .func-pct {{ font-size: 11px; margin-left: 8px; padding: 3px 8px; border-radius: 4px; font-weight: 600; }}
        .pct-high {{ background: color-mix(in srgb, var(--hit) 20%, transparent); color: var(--hit); border: 1px solid color-mix(in srgb, var(--hit) 30%, transparent); }}
        .pct-med {{ background: color-mix(in srgb, var(--partial) 20%, transparent); color: var(--partial); border: 1px solid color-mix(in srgb, var(--partial) 30%, transparent); }}
        .pct-low {{ background: color-mix(in srgb, var(--miss) 20%, transparent); color: var(--miss); border: 1px solid color-mix(in srgb, var(--miss) 30%, transparent); }}
        #main {{ flex: 1; background: radial-gradient(ellipse at top left, color-mix(in srgb, var(--primary) 5%, transparent) 0%, var(--bg-dark) 50%); overflow: hidden; padding: 20px; position: relative; }}
        #cfg-viewport {{ width: 100%; height: calc(100% - 40px); overflow: hidden; cursor: grab; position: relative; border-radius: 12px; background: var(--bg-mid); border: 1px solid var(--border); }}
        #cfg-viewport:active {{ cursor: grabbing; }}
        #cfg-container {{ position: absolute; transform-origin: 0 0; transition: none; }}
        .cfg-title {{ color: #fff; font-size: 16px; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }}
        .cfg-title::before {{ content: ''; width: 4px; height: 20px; background: linear-gradient(180deg, var(--primary), var(--hit)); border-radius: 2px; }}
        .zoom-controls {{ position: absolute; bottom: 16px; right: 16px; display: flex; gap: 8px; z-index: 10; }}
        .zoom-btn {{ width: 36px; height: 36px; border: 1px solid var(--border); background: var(--bg-dark); color: var(--text); border-radius: 8px; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }}
        .zoom-btn:hover {{ background: var(--primary); border-color: var(--primary); }}
        .block {{ fill: var(--bg-light); stroke: var(--border); stroke-width: 2; rx: 8; }}
        .block-hit {{ fill: color-mix(in srgb, var(--hit) 15%, transparent); stroke: var(--hit); }}
        .block-partial {{ fill: color-mix(in srgb, var(--partial) 15%, transparent); stroke: var(--partial); }}
        .block-miss {{ fill: color-mix(in srgb, var(--miss) 10%, transparent); stroke: var(--miss); opacity: 0.7; }}
        .block-text {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 10px; fill: var(--text); }}
        .edge {{ stroke: var(--border); stroke-width: 2; fill: none; marker-end: url(#arrow); }}
        .edge-hit {{ stroke: var(--hit); }}
        .edge-miss {{ stroke: var(--miss); stroke-dasharray: 6,4; opacity: 0.6; }}
        .edge-back {{ stroke-dasharray: 4,4; }}
        /* Flash animation for new blocks */
        @keyframes blockFlash {{
            0% {{ filter: brightness(1); }}
            50% {{ filter: brightness(1.5); box-shadow: 0 0 20px var(--hit); }}
            100% {{ filter: brightness(1); }}
        }}
        .func-item.just-updated {{ animation: blockFlash 0.8s ease-out; }}
        .new-badge {{ background: var(--hit); color: var(--bg-dark); font-size: 10px; padding: 2px 6px; border-radius: 10px; margin-left: 8px; font-weight: bold; }}
    </style>
    <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
</head>
<body>
    {}
    <div id="container">
        <div id="sidebar">
            <div id="sidebar-header">
                <h2>{}</h2>
                <input type="text" id="search" placeholder="Filter functions..." oninput="filterFunctions()">
                <div id="sort-controls">
                    <button class="sort-btn active" onclick="sortBy('name')">Name</button>
                    <button class="sort-btn" onclick="sortBy('pct-desc')">Coverage ↓</button>
                    <button class="sort-btn" onclick="sortBy('pct-asc')">Coverage ↑</button>
                </div>
            </div>
            <ul class="func-list" id="func-list"></ul>
        </div>
        <div id="main">
            <div class="cfg-title" id="cfg-title">Select a function</div>
            <div id="cfg-viewport">
                <div id="cfg-container"></div>
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoomIn()">+</button>
                    <button class="zoom-btn" onclick="zoomOut()">-</button>
                    <button class="zoom-btn" onclick="resetView()">⌂</button>
                </div>
            </div>
        </div>
    </div>
    <script>
const programs = [{}];
const cfgData = {{{}}};

// Theme switching
function setTheme(theme) {{
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('coverage-theme', theme);
    document.querySelectorAll('.theme-btn').forEach(btn => {{
        btn.classList.toggle('active', btn.dataset.theme === theme);
    }});
    updateArrowColors();
}}

function updateArrowColors() {{
    const style = getComputedStyle(document.documentElement);
    const hitColor = style.getPropertyValue('--hit').trim();
    const missColor = style.getPropertyValue('--miss').trim();
    const borderColor = style.getPropertyValue('--border').trim();
    // Update arrow markers dynamically
    const arrowHit = document.querySelector('#arrow-hit path');
    const arrowMiss = document.querySelector('#arrow-miss path');
    const arrow = document.querySelector('#arrow path');
    if (arrowHit) arrowHit.setAttribute('fill', hitColor);
    if (arrowMiss) arrowMiss.setAttribute('fill', missColor);
    if (arrow) arrow.setAttribute('fill', borderColor);
}}

// Live update detection
let lastBlockCounts = {{}};

function checkForUpdates() {{
    const prevSnapshot = JSON.parse(localStorage.getItem('coverage-snapshot') || '{{}}');
    programs.forEach(p => p.functions.forEach(f => {{
        const prev = prevSnapshot[f.name];
        if (prev !== undefined && f.blocks_hit > prev) {{
            flashFunction(f.name, f.blocks_hit - prev);
        }}
    }}));
    // Save current snapshot
    const snapshot = {{}};
    programs.forEach(p => p.functions.forEach(f => {{
        snapshot[f.name] = f.blocks_hit;
    }}));
    localStorage.setItem('coverage-snapshot', JSON.stringify(snapshot));
}}

function flashFunction(name, newCount) {{
    const item = document.querySelector(`[data-name="${{name}}"]`);
    if (item) {{
        item.classList.add('just-updated');
        const existing = item.querySelector('.new-badge');
        if (existing) existing.remove();
        const badge = document.createElement('span');
        badge.className = 'new-badge';
        badge.textContent = `+${{newCount}}`;
        item.appendChild(badge);
        setTimeout(() => {{
            item.classList.remove('just-updated');
            badge.remove();
        }}, 2500);
    }}
}}

let currentSort = 'name';

// Viewport pan/zoom state
let viewState = {{ x: 0, y: 0, scale: 1 }};
let isDragging = false;
let dragStart = {{ x: 0, y: 0 }};

function initViewport() {{
    const viewport = document.getElementById('cfg-viewport');
    if (!viewport) return;

    viewport.addEventListener('mousedown', (e) => {{
        if (e.target.closest('.zoom-btn')) return;
        isDragging = true;
        dragStart = {{ x: e.clientX - viewState.x, y: e.clientY - viewState.y }};
        viewport.style.cursor = 'grabbing';
    }});

    viewport.addEventListener('mousemove', (e) => {{
        if (!isDragging) return;
        viewState.x = e.clientX - dragStart.x;
        viewState.y = e.clientY - dragStart.y;
        updateViewTransform();
    }});

    viewport.addEventListener('mouseup', () => {{
        isDragging = false;
        viewport.style.cursor = 'grab';
    }});

    viewport.addEventListener('mouseleave', () => {{
        isDragging = false;
        viewport.style.cursor = 'grab';
    }});

    viewport.addEventListener('wheel', (e) => {{
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        const newScale = Math.max(0.2, Math.min(3, viewState.scale * delta));

        // Zoom towards mouse position
        const rect = viewport.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        viewState.x = mouseX - (mouseX - viewState.x) * (newScale / viewState.scale);
        viewState.y = mouseY - (mouseY - viewState.y) * (newScale / viewState.scale);
        viewState.scale = newScale;
        updateViewTransform();
    }}, {{ passive: false }});
}}

function updateViewTransform() {{
    const container = document.getElementById('cfg-container');
    if (container) {{
        container.style.transform = `translate(${{viewState.x}}px, ${{viewState.y}}px) scale(${{viewState.scale}})`;
    }}
}}

function zoomIn() {{
    viewState.scale = Math.min(3, viewState.scale * 1.2);
    updateViewTransform();
}}

function zoomOut() {{
    viewState.scale = Math.max(0.2, viewState.scale * 0.8);
    updateViewTransform();
}}

function resetView() {{
    viewState = {{ x: 20, y: 20, scale: 1 }};
    updateViewTransform();
}}

function filterFunctions() {{
    const query = document.getElementById('search').value.toLowerCase();
    const items = document.querySelectorAll('.func-item');
    items.forEach(item => {{
        const name = item.dataset.name.toLowerCase();
        item.style.display = name.includes(query) ? '' : 'none';
    }});
    // Show program headers if any child is visible
    document.querySelectorAll('.program-section').forEach(section => {{
        const hasVisible = [...section.querySelectorAll('.func-item')].some(item => item.style.display !== 'none');
        section.style.display = hasVisible ? '' : 'none';
    }});
}}

function sortBy(mode) {{
    currentSort = mode;
    renderPrograms();
    document.querySelectorAll('.sort-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}}

function toggleProgram(idx) {{
    const section = document.querySelector(`[data-program="${{idx}}"]`);
    if (!section) return;
    const header = section.querySelector('.program-header');
    const funcs = section.querySelector('.program-funcs');
    header.classList.toggle('collapsed');
    funcs.classList.toggle('collapsed');
}}

function renderPrograms() {{
    const listEl = document.getElementById('func-list');
    listEl.innerHTML = '';

    programs.forEach((prog, idx) => {{
        const section = document.createElement('div');
        section.className = 'program-section';
        section.dataset.program = idx;

        // Program header
        const header = document.createElement('div');
        header.className = 'program-header';
        header.onclick = () => toggleProgram(idx);
        const blockPct = prog.blocks_total > 0 ? (100 * prog.blocks_hit / prog.blocks_total).toFixed(0) : 0;
        header.innerHTML = `<span class="collapse-icon">▼</span><span class="program-name">${{prog.name}}</span><span class="program-stats">${{prog.blocks_hit}}/${{prog.blocks_total}} blocks (${{blockPct}}%)</span>`;
        section.appendChild(header);

        // Function list
        const funcsDiv = document.createElement('div');
        funcsDiv.className = 'program-funcs';

        // Sort functions
        const sortedFuncs = [...prog.functions].sort((a, b) => {{
            if (currentSort === 'name') return a.name.localeCompare(b.name);
            if (currentSort === 'pct-asc') return a.pct - b.pct;
            if (currentSort === 'pct-desc') return b.pct - a.pct;
            return 0;
        }});

        sortedFuncs.forEach(f => {{
            const li = document.createElement('div');
            li.className = 'func-item';
            li.dataset.name = f.name;
            li.dataset.pct = f.pct;
            li.onclick = (e) => {{ e.stopPropagation(); selectFunction(f.name); }};
            const pctClass = f.pct >= 80 ? 'pct-high' : f.pct >= 40 ? 'pct-med' : 'pct-low';
            const blocksInfo = f.blocks_total ? `${{f.blocks_hit}}/${{f.blocks_total}}` : '';
            li.innerHTML = `<span class="func-name">${{f.name}}</span><span class="func-blocks">${{blocksInfo}}</span><span class="func-pct ${{pctClass}}">${{f.pct.toFixed(0)}}%</span>`;
            funcsDiv.appendChild(li);
        }});

        section.appendChild(funcsDiv);
        listEl.appendChild(section);
    }});
}}

function selectFunction(name) {{
    document.querySelectorAll('.func-item').forEach(el => el.classList.remove('active'));
    document.querySelector(`[data-name="${{name}}"]`)?.classList.add('active');
    document.getElementById('cfg-title').textContent = name;
    renderCFG(name);
    resetView();
}}

function renderCFG(name) {{
    const container = document.getElementById('cfg-container');
    const data = cfgData[name];
    if (!data) {{
        container.innerHTML = '<p style="color:#888">No CFG data available</p>';
        return;
    }}

    const nodes = data.nodes || [];
    const edges = data.edges || [];

    // Create Dagre graph for layout
    const g = new dagre.graphlib.Graph();
    g.setGraph({{ rankdir: 'TB', nodesep: 40, ranksep: 60, marginx: 40, marginy: 40 }});
    g.setDefaultEdgeLabel(() => ({{}}));

    const nodeWidth = 220;
    const nodeHeight = 80;

    // Add nodes to Dagre
    nodes.forEach(node => {{
        g.setNode(node.id.toString(), {{ width: nodeWidth, height: nodeHeight, data: node }});
    }});

    // Add edges to Dagre
    edges.forEach(edge => {{
        g.setEdge(edge.from.toString(), edge.to.toString(), {{ data: edge }});
    }});

    // Compute layout
    dagre.layout(g);

    // Get graph dimensions
    const graphWidth = g.graph().width + 80;
    const graphHeight = g.graph().height + 80;

    let svg = `<svg width="${{graphWidth}}" height="${{graphHeight}}">`;
    svg += `<defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#2a2a3a"/></marker>
        <marker id="arrow-hit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#14F195"/></marker>
        <marker id="arrow-miss" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#F971FF"/></marker>
    </defs>`;

    // Draw edges using Dagre's computed points
    g.edges().forEach(e => {{
        const edgeData = g.edge(e);
        const origEdge = edges.find(ed => ed.from.toString() === e.v && ed.to.toString() === e.w);
        if (!edgeData || !edgeData.points || !origEdge) return;

        const edgeCls = origEdge.hit ? 'edge edge-hit' : 'edge edge-miss';
        const marker = origEdge.hit ? 'url(#arrow-hit)' : 'url(#arrow-miss)';

        // Build path from Dagre's waypoints
        const points = edgeData.points;
        let pathD = `M ${{points[0].x}} ${{points[0].y}}`;
        for (let i = 1; i < points.length; i++) {{
            pathD += ` L ${{points[i].x}} ${{points[i].y}}`;
        }}
        svg += `<path d="${{pathD}}" class="${{edgeCls}}" style="marker-end: ${{marker}}"/>`;
    }});

    // Draw nodes at Dagre-computed positions
    g.nodes().forEach(nodeId => {{
        const pos = g.node(nodeId);
        if (!pos || !pos.data) return;
        const node = pos.data;
        const x = pos.x - nodeWidth / 2;
        const y = pos.y - nodeHeight / 2;
        const hit = node.hit || 0;
        const total = node.total || 0;
        const cls = hit === total ? 'block-hit' : hit > 0 ? 'block-partial' : 'block-miss';

        svg += `<rect x="${{x}}" y="${{y}}" width="${{nodeWidth}}" height="${{nodeHeight}}" class="block ${{cls}}" rx="4"/>`;
        svg += `<text x="${{x + 8}}" y="${{y + 16}}" class="block-text">Block ${{node.id}} (${{hit}}/${{total}})</text>`;

        const lines = (node.insns || []).slice(0, 4);
        lines.forEach((line, li) => {{
            svg += `<text x="${{x + 8}}" y="${{y + 32 + li * 12}}" class="block-text">${{line}}</text>`;
        }});
    }});

    svg += '</svg>';
    container.innerHTML = svg;
}}

// Initialize
const savedTheme = localStorage.getItem('coverage-theme') || 'neon';
setTheme(savedTheme);
initViewport();
renderPrograms();
checkForUpdates();
if (programs.length > 0 && programs[0].functions.length > 0) selectFunction(programs[0].functions[0].name);
    </script>
</body>
</html>
"##,
        cached.program_name,
        stats_html,
        cached.program_name,
        programs_json,
        cfg_json_parts.join(",")
    )?;

    Ok(())
}

/// Add hit counts to cached CFG JSON based on current pc_hits
fn add_hit_counts_to_cfg(
    cached_cfg: &str,
    blocks: &[(usize, Vec<usize>)],
    pc_hits: &HashMap<usize, u64>,
) -> String {
    // Create a map of node_id -> hit count
    let mut node_hits: HashMap<usize, usize> = HashMap::new();
    for (node_id, block_pcs) in blocks {
        let hit_count = block_pcs
            .iter()
            .filter(|pc| pc_hits.get(pc).map(|&h| h > 0).unwrap_or(false))
            .count();
        node_hits.insert(*node_id, hit_count);
    }

    // Parse and rebuild CFG JSON with hit counts
    // Simple string manipulation since we know the format
    let mut result = cached_cfg.to_string();

    // Add hit counts to nodes: {"id":N,"total":M,"insns":[...]} -> {"id":N,"hit":H,"total":M,"insns":[...]}
    for (node_id, hit_count) in &node_hits {
        let search = format!(r#""id":{},"total":"#, node_id);
        let replace = format!(r#""id":{},"hit":{},"total":"#, node_id, hit_count);
        result = result.replace(&search, &replace);
    }

    // Add hit status to edges based on destination node hits
    // {"from":N,"to":M} -> {"from":N,"to":M,"hit":true/false}
    for (node_id, hit_count) in &node_hits {
        let search = format!(r#""to":{}}}"#, node_id);
        let replace = format!(r#""to":{},"hit":{}}}"#, node_id, *hit_count > 0);
        result = result.replace(&search, &replace);
    }

    result
}
