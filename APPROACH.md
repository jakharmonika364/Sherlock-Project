# Sherlock: Bitcoin Chain Analysis Engine

## Architecture Overview

Sherlock is built in Go using only the standard library for maximum efficiency and minimal dependencies. The engine is divided into three main layers:

1. **Parser Layer**: Handles the low-level binary parsing of `blk*.dat` and `rev*.dat` files. It includes a custom Bitcion VarInt (CompactSize) reader, a SegWit-aware transaction parser, and an XOR decoding engine.
2. **Analysis Layer**: Implements 9 distinct heuristics to fingerprint transactions. These heuristics run in parallel for each transaction to classify its intent (e.g., CoinJoin, Consolidation).
3. **Report Layer**: Aggregates block and transaction data into deterministic JSON and Markdown reports. It also includes an embedded web server for interactive visualization.

## Heuristics Implemented

- **cioh**: Common Input Ownership Heuristic. Triggers when a transaction has more than one input, suggesting all inputs belong to the same entity.
- **change_detection**: Uses a multi-step confidence-based approach. It first looks for script type matches between inputs and outputs (high confidence), then checks for round value payments (medium confidence), and finally falls back to output ordering (low confidence).
- **address_reuse**: Detects if an output script matches any of the input prevout scripts.
- **coinjoin**: Flags transactions with many equal-valued outputs, typically used for privacy.
- **consolidation**: Identifies transactions that combine many inputs into a single output.
- **self_transfer**: Detects if all outputs match the dominant input script type, suggesting the user is moving funds between their own addresses.
- **peeling_chain**: Identifies a "peeling" pattern where a large output is repeatedly split into a smaller payment and another large change output.
- **op_return**: Analyzes OP_RETURN outputs to identify known protocols like Omni, OpenTimestamps, and Runes.
- **round_number_payment**: Flags payments that are multiples of round numbers in satoshis (e.g., 0.01 BTC).

## Trade-offs and Design Decisions

- **In-Memory vs. Streaming**: Due to the challenge requirements, Sherlock loads larger chunks into memory for XOR decoding. While this increases peak memory usage, it significantly simplifies the cyclical XOR implementation.
- **Deterministic Reporting**: All statistics (mean, median, etc.) are computed with fixed precision to ensure reports are identical across different runs.
- **Graceful Desync Handling**: Bitcoin block and undo files can sometimes desync. Sherlock implements a robust magic-scanning loop to find block boundaries and gracefully fall back to zero-values if undo data is malformed.

## References

- **BIP34**: Block Height in Coinbase.
- **BIP141**: Segregated Witness (SegWit) structure.
- **Meiklejohn et al. 2013**: "A Fistful of Bitcoins: Characterizing Payments on the Bitcoin Network".
- **Harrshita et al. 2024**: "Heuristics for Privacy in the Bitcoin Network".
