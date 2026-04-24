package analysis

import (
	"github.com/harrshita123/sherlock/internal/bitcoin"
)

type HeuristicsResult struct {
	CIOH               CIOHResult               `json:"cioh"`
	ChangeDetection    ChangeDetectionResult    `json:"change_detection"`
	AddressReuse       AddressReuseResult       `json:"address_reuse"`
	CoinJoin           CoinJoinResult           `json:"coinjoin"`
	Consolidation      ConsolidationResult      `json:"consolidation"`
	SelfTransfer       SelfTransferResult       `json:"self_transfer"`
	PeelingChain       PeelingChainResult       `json:"peeling_chain"`
	OpReturn           OpReturnResult           `json:"op_return"`
	RoundNumberPayment RoundNumberPaymentResult `json:"round_number_payment"`
}

type CIOHResult struct {
	Detected bool `json:"detected"`
}

type ChangeDetectionResult struct {
	Detected          bool   `json:"detected"`
	LikelyChangeIndex int    `json:"likely_change_index"`
	Method            string `json:"method"`
	Confidence        string `json:"confidence"`
}

type AddressReuseResult struct {
	Detected   bool `json:"detected"`
	ReuseCount int  `json:"reuse_count"`
}

type CoinJoinResult struct {
	Detected         bool   `json:"detected"`
	EqualOutputCount int    `json:"equal_output_count"`
	EqualOutputValue uint64 `json:"equal_output_value"`
}

type ConsolidationResult struct {
	Detected   bool `json:"detected"`
	InputCount int  `json:"input_count"`
}

type SelfTransferResult struct {
	Detected bool `json:"detected"`
}

type PeelingChainResult struct {
	Detected         bool `json:"detected"`
	LargeOutputIndex int  `json:"large_output_index"`
	SmallOutputIndex int  `json:"small_output_index"`
}

type OpReturnResult struct {
	Detected      bool     `json:"detected"`
	OpReturnCount int      `json:"op_return_count"`
	Protocols     []string `json:"protocols"`
}

type RoundNumberPaymentResult struct {
	Detected           bool  `json:"detected"`
	RoundOutputIndices []int `json:"round_output_indices"`
}

func RunHeuristics(tx *bitcoin.Transaction) HeuristicsResult {
	res := HeuristicsResult{
		ChangeDetection:    ChangeDetectionResult{Detected: false, LikelyChangeIndex: -1},
		PeelingChain:       PeelingChainResult{Detected: false, LargeOutputIndex: -1, SmallOutputIndex: -1},
		RoundNumberPayment: RoundNumberPaymentResult{Detected: false, RoundOutputIndices: []int{}},
		OpReturn:           OpReturnResult{Detected: false, Protocols: []string{}},
	}

	isCoinbase := tx.IsCoinbase()

	// 1. CIOH
	if !isCoinbase && len(tx.Inputs) > 1 {
		res.CIOH.Detected = true
	}

	// 2. Change Detection
	if !isCoinbase {
		res.ChangeDetection = runChangeDetection(tx)
	}

	// 3. Address Reuse
	res.AddressReuse = runAddressReuse(tx)

	// 4. CoinJoin
	res.CoinJoin = runCoinJoin(tx)

	// 5. Consolidation
	if !isCoinbase && len(tx.Inputs) >= 3 && len(tx.Outputs) <= 2 {
		res.Consolidation.Detected = true
		res.Consolidation.InputCount = len(tx.Inputs)
	}

	// 6. Self Transfer
	if !isCoinbase && (len(tx.Outputs) == 1 || len(tx.Outputs) == 2) {
		res.SelfTransfer = runSelfTransfer(tx)
	}

	// 7. Peeling Chain
	if !isCoinbase && len(tx.Inputs) == 1 && len(tx.Outputs) == 2 {
		res.PeelingChain = runPeelingChain(tx)
	}

	// 8. OP_RETURN
	res.OpReturn = runOpReturn(tx)

	// 9. Round Number Payment
	res.RoundNumberPayment = runRoundNumberPayment(tx)

	return res
}

func runChangeDetection(tx *bitcoin.Transaction) ChangeDetectionResult {
	// Priority: script_type_match > round_value_analysis > output_ordering

	// script_type_match
	typeCount := make(map[string]int)
	inputDataAvailable := true
	for _, in := range tx.Inputs {
		if in.PrevOutput == nil {
			inputDataAvailable = false
			break
		}
		typeCount[in.PrevOutput.ScriptType]++
	}

	if inputDataAvailable && len(tx.Inputs) > 0 {
		dominantType := ""
		maxCount := 0
		for t, c := range typeCount {
			if c > maxCount {
				maxCount = c
				dominantType = t
			}
		}

		matchIndex := -1
		matchCount := 0
		otherCount := 0
		for i, out := range tx.Outputs {
			if out.ScriptType == dominantType {
				matchIndex = i
				matchCount++
			} else if out.ScriptType != "op_return" {
				otherCount++
			}
		}
		if matchCount == 1 && otherCount >= 1 {
			return ChangeDetectionResult{Detected: true, LikelyChangeIndex: matchIndex, Method: "script_type_match", Confidence: "high"}
		}
	}

	// round_value_analysis
	if len(tx.Outputs) == 2 {
		r0 := tx.Outputs[0].Value > 0 && tx.Outputs[0].Value%1_000_000 == 0
		r1 := tx.Outputs[1].Value > 0 && tx.Outputs[1].Value%1_000_000 == 0
		if r0 && !r1 {
			return ChangeDetectionResult{Detected: true, LikelyChangeIndex: 1, Method: "round_value_analysis", Confidence: "medium"}
		}
		if r1 && !r0 {
			return ChangeDetectionResult{Detected: true, LikelyChangeIndex: 0, Method: "round_value_analysis", Confidence: "medium"}
		}
	}

	// output_ordering
	if len(tx.Outputs) == 2 {
		return ChangeDetectionResult{Detected: true, LikelyChangeIndex: 1, Method: "output_ordering", Confidence: "low"}
	}

	return ChangeDetectionResult{Detected: false, LikelyChangeIndex: -1}
}

func runAddressReuse(tx *bitcoin.Transaction) AddressReuseResult {
	inputScripts := make(map[string]bool)
	for _, in := range tx.Inputs {
		if in.PrevOutput != nil {
			inputScripts[string(in.PrevOutput.ScriptPubKey)] = true
		}
	}

	reuseCount := 0
	for _, out := range tx.Outputs {
		if inputScripts[string(out.ScriptPubKey)] {
			reuseCount++
		}
	}

	return AddressReuseResult{Detected: reuseCount > 0, ReuseCount: reuseCount}
}

func runCoinJoin(tx *bitcoin.Transaction) CoinJoinResult {
	if len(tx.Inputs) < 3 || len(tx.Outputs) < 3 {
		return CoinJoinResult{Detected: false}
	}

	valCount := make(map[int64]int)
	for _, out := range tx.Outputs {
		if out.Value > 546 {
			valCount[out.Value]++
		}
	}

	maxCount := 0
	var maxVal int64
	for val, count := range valCount {
		if count >= 2 {
			if count > maxCount {
				maxCount = count
				maxVal = val
			}
		}
	}

	if maxCount >= 2 {
		return CoinJoinResult{Detected: true, EqualOutputCount: maxCount, EqualOutputValue: uint64(maxVal)}
	}

	return CoinJoinResult{Detected: false}
}

func runSelfTransfer(tx *bitcoin.Transaction) SelfTransferResult {
	typeCount := make(map[string]int)
	inputDataAvailable := true
	for _, in := range tx.Inputs {
		if in.PrevOutput == nil {
			inputDataAvailable = false
			break
		}
		typeCount[in.PrevOutput.ScriptType]++
	}

	if !inputDataAvailable || len(tx.Inputs) == 0 {
		return SelfTransferResult{Detected: false}
	}

	dominantType := ""
	maxCount := 0
	for t, c := range typeCount {
		if c > maxCount {
			maxCount = c
			dominantType = t
		}
	}

	for _, out := range tx.Outputs {
		if out.ScriptType != "op_return" && out.ScriptType != dominantType {
			return SelfTransferResult{Detected: false}
		}
	}

	return SelfTransferResult{Detected: true}
}

func runPeelingChain(tx *bitcoin.Transaction) PeelingChainResult {
	if len(tx.Inputs) != 1 || len(tx.Outputs) != 2 {
		return PeelingChainResult{Detected: false, LargeOutputIndex: -1, SmallOutputIndex: -1}
	}

	v0 := tx.Outputs[0].Value
	v1 := tx.Outputs[1].Value
	if v0 <= 0 || v1 <= 0 {
		return PeelingChainResult{Detected: false, LargeOutputIndex: -1, SmallOutputIndex: -1}
	}

	total := float64(v0 + v1)
	minV := float64(v0)
	maxV := float64(v1)
	smallIdx := 0
	largeIdx := 1
	if v1 < v0 {
		minV = float64(v1)
		maxV = float64(v0)
		smallIdx = 1
		largeIdx = 0
	}

	if minV < 0.2*total && maxV > 100_000 {
		return PeelingChainResult{Detected: true, LargeOutputIndex: largeIdx, SmallOutputIndex: smallIdx}
	}

	return PeelingChainResult{Detected: false, LargeOutputIndex: -1, SmallOutputIndex: -1}
}

func runOpReturn(tx *bitcoin.Transaction) OpReturnResult {
	count := 0
	protocols := make(map[string]bool)
	for _, out := range tx.Outputs {
		if bitcoin.IsOpReturn(out.ScriptPubKey) {
			count++
			proto := bitcoin.GetOpReturnProtocol(out.ScriptPubKey)
			protocols[proto] = true
		}
	}

	if count > 0 {
		res := OpReturnResult{Detected: true, OpReturnCount: count, Protocols: []string{}}
		for p := range protocols {
			res.Protocols = append(res.Protocols, p)
		}
		return res
	}

	return OpReturnResult{Detected: false, Protocols: []string{}}
}

func runRoundNumberPayment(tx *bitcoin.Transaction) RoundNumberPaymentResult {
	indices := []int{}
	rounds := []int64{100_000_000, 10_000_000, 1_000_000, 100_000, 10_000, 1_000}
	for i, out := range tx.Outputs {
		if bitcoin.IsOpReturn(out.ScriptPubKey) {
			continue
		}
		if out.Value <= 0 {
			continue
		}
		isRound := false
		for _, r := range rounds {
			if out.Value%r == 0 {
				isRound = true
				break
			}
		}
		if isRound {
			indices = append(indices, i)
		}
	}

	if len(indices) > 0 {
		return RoundNumberPaymentResult{Detected: true, RoundOutputIndices: indices}
	}
	return RoundNumberPaymentResult{Detected: false, RoundOutputIndices: []int{}}
}
