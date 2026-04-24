package analysis

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/harrshita123/sherlock/internal/bitcoin"
)

func RunAnalysis(blkPath, revPath, xorPath string) (FullReport, string, error) {
	stem := strings.TrimSuffix(filepath.Base(blkPath), ".gz")
	stem = strings.TrimSuffix(stem, ".dat")

	xorKey, err := os.ReadFile(xorPath)
	if err != nil {
		return FullReport{}, "", err
	}

	blkData, err := os.ReadFile(blkPath)
	if err != nil {
		return FullReport{}, "", err
	}
	bitcoin.ApplyXor(blkData, xorKey)

	var revData []byte
	if revPath != "" {
		revData, err = os.ReadFile(revPath)
		if err == nil {
			bitcoin.ApplyXor(revData, xorKey)
		}
	}

	blocks, err := bitcoin.ReadBlocks(blkData, revData)
	if err != nil {
		return FullReport{}, "", err
	}

	fullReport := FullReport{
		Ok:         true,
		Mode:       "chain_analysis",
		File:       filepath.Base(blkPath),
		BlockCount: len(blocks),
	}

	var allTxData []TxAnalysis

	for _, b := range blocks {
		br := BlockReport{
			BlockHash:      b.Hash,
			BlockHeight:    b.Height,
			BlockTimestamp: b.Header.Timestamp,
			TxCount:        len(b.Transactions),
		}

		var blockTxData []TxAnalysis
		for _, tx := range b.Transactions {
			hr := RunHeuristics(tx)
			cls := ClassifyTransaction(tx, hr)

			var scripts []string
			for _, out := range tx.Outputs {
				scripts = append(scripts, out.ScriptType)
			}

			rate, _ := GetFeeRate(tx)

			txReport := TxReport{
				Txid:           tx.TXID,
				Heuristics:     hr,
				Classification: cls,
				ScriptTypes:    scripts,
				FeeRate:        rate,
				Timestamp:      b.Header.Timestamp,
				InputCount:     len(tx.Inputs),
				OutputCount:    len(tx.Outputs),
			}
			br.Transactions = append(br.Transactions, txReport)

			d := TxAnalysis{
				Transaction:    tx,
				Heuristics:     hr,
				Classification: cls,
				FeeRate:        rate,
			}
			blockTxData = append(blockTxData, d)
			allTxData = append(allTxData, d)
		}
		br.AnalysisSummary = ComputeStats(blockTxData)
		fullReport.Blocks = append(fullReport.Blocks, br)
	}

	fullReport.AnalysisSummary = ComputeStats(allTxData)

	return fullReport, stem, nil
}
