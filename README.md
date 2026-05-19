# Sherlock

Build a chain analysis engine that applies chain-analysis heuristics to a dataset of Bitcoin transactions from real block data, a web visualizer to surface and display the results, and Markdown reports documenting your findings.

---

## Assumptions / scope

- parse raw block files (`blk*.dat`, `rev*.dat`, `xor.dat`) to extract transactions and their prevout data.
- need to validate signatures or execute scripts.
- need to connect to a node or external API.

---

## Deliverables

You must ship **all** of the following:

1. **CLI chain analyzer** — applies heuristics to every transaction in a block and produces machine-readable JSON output.
2. **Markdown reports** — human-readable reports summarizing the analysis for each block file. Must be committed to `out/`.
3. **Web visualizer** — interactive UI for exploring chain analysis results.

---
