package report

import (
	"encoding/json"
	"os"

	"github.com/harrshita123/sherlock/internal/analysis"
)

func WriteJSON(path string, report analysis.FullReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
