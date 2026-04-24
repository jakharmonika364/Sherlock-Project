package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/harrshita123/sherlock/internal/analysis"
	"github.com/harrshita123/sherlock/internal/report"
	"github.com/harrshita123/sherlock/internal/web"
)

func main() {
	blockMode := flag.Bool("block", false, "Run CLI analysis mode")
	webMode := flag.Bool("web", false, "Run web server mode")
	port := flag.Int("port", 3000, "Web server port")
	flag.Parse()

	if *webMode {
		web.StartServer(*port)
		return
	}

	if *blockMode {
		args := flag.Args()
		if len(args) < 3 {
			fatal("INVALID_ARGUMENTS", "Usage: --block <blk.dat> <rev.dat> <xor.dat>")
		}
		runCLI(args[0], args[1], args[2])
		return
	}

	flag.Usage()
}

func runCLI(blkPath, revPath, xorPath string) {
	fullReport, stem, err := analysis.RunAnalysis(blkPath, revPath, xorPath)
	if err != nil {
		fatal("ANALYSIS_FAILED", err.Error())
	}

	os.MkdirAll("out", 0755)

	jsonPath := filepath.Join("out", stem+".json")
	if err := report.WriteJSON(jsonPath, fullReport); err != nil {
		fatal("JSON_WRITE_FAILED", err.Error())
	}

	mdPath := filepath.Join("out", stem+".md")
	if err := report.WriteMarkdown(mdPath, fullReport); err != nil {
		fatal("MD_WRITE_FAILED", err.Error())
	}

	os.Exit(0)
}

func fatal(code, msg string) {
	fmt.Fprintf(os.Stderr, `{"ok":false,"error":{"code":"%s","message":"%s"}}`+"\n", code, msg)
	os.Exit(1)
}
