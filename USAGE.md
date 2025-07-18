# Writing the USAGE guide as plain text file for the user to download

usage_text = """# DeFi Smart Contract Audit Agent – Final Prompt and Usage Guide

## Overview
This agent is a fully automated DeFi smart contract auditing assistant designed to run in a local CLI environment. It performs end-to-end security analysis of Solidity contracts—static analysis, gas optimization checks, dynamic testing/fuzzing with Foundry, and PoC exploit generation—to produce a comprehensive Immunefi-style Markdown report.

All steps execute locally, with automated tool setup, structured logging, and clear, child-proof instructions. No web UI—everything happens in your terminal.

---

## Phase 1: Scope Initialization

1. Specify Target
   - Option A: GitHub Repository
     python audit_agent.py -g https://github.com/username/repo.git
   - Option B: Local Folder
     python audit_agent.py -c ./contracts_folder
   - If neither -g nor -c is provided, the agent will ask:
     Where is your code? Enter GitHub URL or local path:

2. Confirm Scope & Objectives
   - Agent prompts:
     Which contracts or subfolders are in-scope?
   - Reply with comma-separated names or leave blank to include all.
   - Agent asks:
     Any focus areas (e.g. price or oracle manipulation)?
   - Reply in plain text.

3. Workspace Setup
   - Automatically creates ./audit_workspace and clones or copies the code there.
   - No manual cd is ever required.

---

## Phase 2: Tools Setup & Installation

1. Slither (Static Analysis)
   - Checks slither --version. If missing:
     pip install slither-analyzer

2. Foundry (Dynamic Testing & Fuzzing)
   - Checks forge --version. If missing:
     curl -L https://foundry.paradigm.xyz | bash
     foundryup
   - Important: Ensure there is a foundry.toml file in audit_workspace/ to signal Foundry usage.

3. Solidity Compiler
   - Checks solc --version. If missing or mismatched, installs via solc-select or downloads the correct binary.

4. Gas Analyzer (Python Module)
   - Installs Python libraries:
     pip install rich requests

5. Hardhat (Contingency Only)
   - Only used if Foundry is unavailable and you manually add a hardhat.config.js in audit_workspace/.
   - Requires a valid Hardhat project to compile and test.

6. Verification & Logging
   - Each installation step prints success or clear error messages.

---

## Phase 3: Static Analysis with Slither

1. Runs:
   slither . --json slither-output.json
2. Parses output for High/Medium severity issues.
3. Filters known false positives.
4. Prioritizes DeFi-specific risks (reentrancy, access control, overflow).
5. Saves JSON results for subsequent phases.

---

## Phase 4: Gas Optimization Analysis

1. Scans contracts for patterns like:
   - State variable packing opportunities
   - Expensive loops
   - Unnecessary storage writes
2. Estimates potential gas savings.
3. Writes findings to gas-optimizations.json.
4. Includes a Gas Optimizations section in the final report.

---

## Phase 5: Dynamic Testing & Fuzzing

1. Foundry (Preferred)
   - Requires foundry.toml in the workspace.
   - Compile:
     forge build
   - Run Tests:
     forge test
   - Automated Fuzzing:
     forge test --fuzz
   - Captures reverts and crashes.

2. Hardhat (Contingency Only)
   - Only if Foundry is unavailable and you have manually added hardhat.config.js.
   - Compile:
     npx hardhat compile
   - Run Tests:
     npx hardhat test

3. Custom Vulnerability Tests
   - Reentrancy: auto-generates a malicious test contract.
   - Access Control: unauthorized call tests expecting revert.
   - Overflow: fuzz tests with max uint values.

---

## Phase 6: Exploit Generation (Proof-of-Concept)

For each confirmed issue, the agent:
1. Creates a minimal Solidity PoC contract illustrating the exploit.
2. Deploys locally via Anvil (Foundry) or Hardhat node (if enabled).
3. Executes exploit transactions to prove impact.
4. Captures logs and pre/post state snapshots.

---

## Phase 7: Report Generation

1. Aggregates all findings into an Immunefi-style Markdown report (audit_report.md), including:
   - Title & overview
   - Scope & tool versions
   - Summary of findings (by severity)
   - Detailed issue sections with descriptions, reproductions, PoC snippets, and recommendations
   - Gas optimization suggestions

2. Saves the report to the root of the repository:
   audit_report.md
3. Prints:
   Report generated: ./audit_workspace/audit_report.md

---

## Usage Examples

- Audit a GitHub repo:
  python audit_agent.py -g https://github.com/username/repo.git

- Audit a local folder & output custom file:
  python audit_agent.py -c ./contracts -o my_audit.md

- Interactive mode:
  python audit_agent.py

---

End of Guide

Tip: Keep this USAGE.md in sync whenever you update audit_agent.py—it’s your single source of truth for using the audit agent.
"""

