package analysis

import (
	"math"
	"sort"

	"github.com/harrshita123/sherlock/internal/bitcoin"
)

type FeeRateStats struct {
	MinSatVb    float64 `json:"min_sat_vb"`
	MaxSatVb    float64 `json:"max_sat_vb"`
	MedianSatVb float64 `json:"median_sat_vb"`
	MeanSatVb   float64 `json:"mean_sat_vb"`
}

type AnalysisSummary struct {
	TotalTransactionsAnalyzed int            `json:"total_transactions_analyzed"`
	HeuristicsApplied         []string       `json:"heuristics_applied"`
	FlaggedTransactions       int            `json:"flagged_transactions"`
	ScriptTypeDistribution    map[string]int `json:"script_type_distribution"`
	FeeRateStats              FeeRateStats   `json:"fee_rate_stats"`
}

func ComputeStats(txData []TxAnalysis) AnalysisSummary {
	summary := AnalysisSummary{
		TotalTransactionsAnalyzed: len(txData),
		HeuristicsApplied: []string{
			"cioh", "change_detection", "address_reuse", "coinjoin",
			"consolidation", "self_transfer", "peeling_chain", "op_return",
			"round_number_payment",
		},
		ScriptTypeDistribution: make(map[string]int),
	}

	// Initialize distribution map with all keys
	types := []string{"p2wpkh", "p2tr", "p2sh", "p2pkh", "p2wsh", "op_return", "unknown"}
	for _, t := range types {
		summary.ScriptTypeDistribution[t] = 0
	}

	var feeRates []float64
	var totalFeeRate float64
	flaggedCount := 0

	for _, d := range txData {
		// Flagged check
		isFlagged := d.Heuristics.CIOH.Detected ||
			d.Heuristics.ChangeDetection.Detected ||
			d.Heuristics.AddressReuse.Detected ||
			d.Heuristics.CoinJoin.Detected ||
			d.Heuristics.Consolidation.Detected ||
			d.Heuristics.SelfTransfer.Detected ||
			d.Heuristics.PeelingChain.Detected ||
			d.Heuristics.OpReturn.Detected ||
			d.Heuristics.RoundNumberPayment.Detected
		if isFlagged {
			flaggedCount++
		}

		// Script distribution
		for _, out := range d.Transaction.Outputs {
			summary.ScriptTypeDistribution[out.ScriptType]++
		}

		// Fee rate
		rate, ok := GetFeeRate(d.Transaction)
		if ok {
			feeRates = append(feeRates, rate)
			totalFeeRate += rate
		}
	}

	summary.FlaggedTransactions = flaggedCount

	if len(feeRates) > 0 {
		sort.Float64s(feeRates)
		summary.FeeRateStats.MinSatVb = feeRates[0]
		summary.FeeRateStats.MaxSatVb = feeRates[len(feeRates)-1]
		summary.FeeRateStats.MeanSatVb = math.Round((totalFeeRate/float64(len(feeRates)))*10) / 10

		mid := len(feeRates) / 2
		if len(feeRates)%2 == 0 {
			summary.FeeRateStats.MedianSatVb = math.Round(((feeRates[mid-1]+feeRates[mid])/2)*100) / 100
		} else {
			summary.FeeRateStats.MedianSatVb = feeRates[mid]
		}
	}

	return summary
}

type TxAnalysis struct {
	Transaction    *bitcoin.Transaction
	Heuristics     HeuristicsResult
	Classification string
	FeeRate        float64
}

type FullReport struct {
	Ok              bool            `json:"ok"`
	Mode            string          `json:"mode"`
	File            string          `json:"file"`
	BlockCount      int             `json:"block_count"`
	AnalysisSummary AnalysisSummary `json:"analysis_summary"`
	Blocks          []BlockReport   `json:"blocks"`
}

type BlockReport struct {
	BlockHash       string          `json:"block_hash"`
	BlockHeight     int32           `json:"block_height"`
	BlockTimestamp  uint32          `json:"block_timestamp"`
	TxCount         int             `json:"tx_count"`
	AnalysisSummary AnalysisSummary `json:"analysis_summary"`
	Transactions    []TxReport      `json:"transactions"`
}

type TxReport struct {
	Txid           string           `json:"txid"`
	Heuristics     HeuristicsResult `json:"heuristics"`
	Classification string           `json:"classification"`
	ScriptTypes    []string         `json:"script_types"`
	FeeRate        float64          `json:"fee_rate"`
	Timestamp      uint32           `json:"timestamp"`
	InputCount     int              `json:"input_count"`
	OutputCount    int              `json:"output_count"`
}

func GetFeeRate(tx *bitcoin.Transaction) (float64, bool) {
	if tx.IsCoinbase() {
		return 0, false
	}
	allInputsKnown := true
	var totalInputVal int64
	for _, in := range tx.Inputs {
		if in.PrevOutput == nil {
			allInputsKnown = false
			break
		}
		totalInputVal += in.PrevOutput.Value
	}

	if allInputsKnown {
		var totalOutputVal int64
		for _, out := range tx.Outputs {
			totalOutputVal += out.Value
		}
		fee := totalInputVal - totalOutputVal
		if fee >= 0 {
			rate := float64(fee) / float64(tx.VSize)
			return math.Round(rate*100) / 100, true
		}
	}
	return 0, false
}
