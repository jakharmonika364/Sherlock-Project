package analysis

import (
	"github.com/harrshita123/sherlock/internal/bitcoin"
)

func ClassifyTransaction(tx *bitcoin.Transaction, hr HeuristicsResult) string {
	if tx.IsCoinbase() {
		return "unknown"
	}
	if hr.CoinJoin.Detected {
		return "coinjoin"
	}
	if hr.Consolidation.Detected {
		return "consolidation"
	}
	if hr.SelfTransfer.Detected {
		return "self_transfer"
	}
	if len(tx.Outputs) >= 5 {
		return "batch_payment"
	}
	if len(tx.Outputs) <= 3 {
		return "simple_payment"
	}
	return "unknown"
}
