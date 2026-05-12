package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/harrshita123/sherlock/internal/analysis"
	"github.com/harrshita123/sherlock/internal/report"
)

//go:embed static/index.html
var staticFiles embed.FS

type ErrorResponse struct {
	OK    bool `json:"ok"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func sendError(w http.ResponseWriter, code string, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var resp ErrorResponse
	resp.OK = false
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}

func StartServer(port int) {
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	http.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		files, _ := os.ReadDir("out")
		var stems []string
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".json") {
				stems = append(stems, strings.TrimSuffix(f.Name(), ".json"))
			}
		}
		json.NewEncoder(w).Encode(map[string][]string{"files": stems})
	})

	http.HandleFunc("/api/analysis/", func(w http.ResponseWriter, r *http.Request) {
		stem := strings.TrimPrefix(r.URL.Path, "/api/analysis/")
		path := filepath.Join("out", stem+".json")
		f, err := os.Open(path)
		if err != nil {
			sendError(w, "NOT_FOUND", "File not found", 404)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, f)
	})
	
	http.HandleFunc("/api/analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendError(w, "METHOD_NOT_ALLOWED", "Method not allowed", 405)
			return
		}
		
		err := r.ParseMultipartForm(500 << 20) // 500MB
		if err != nil {
			sendError(w, "BAD_REQUEST", "Failed to parse form: "+err.Error(), 400)
			return
		}
		
		saveFile := func(key string) (string, error) {
			file, header, err := r.FormFile(key)
			if err != nil {
				if key == "rev" { return "", nil } // rev is optional
				return "", err
			}
			defer file.Close()
			
			os.MkdirAll("fixtures", 0755)
			path := filepath.Join("fixtures", header.Filename)
			dst, err := os.Create(path)
			if err != nil { return "", err }
			defer dst.Close()
			
			io.Copy(dst, file)
			return path, nil
		}
		
		blkPath, err := saveFile("blk")
		if err != nil {
			sendError(w, "MISSING_FILE", "Block data file (blk) is required: "+err.Error(), 400)
			return
		}
		revPath, _ := saveFile("rev")
		xorPath, err := saveFile("xor")
		if err != nil {
			sendError(w, "MISSING_FILE", "XOR key file (xor) is required: "+err.Error(), 400)
			return
		}

		// Structured Validation
		if revPath != "" {
			blkStem := strings.TrimSuffix(filepath.Base(blkPath), filepath.Ext(blkPath))
			revStem := strings.TrimSuffix(filepath.Base(revPath), filepath.Ext(revPath))
			blkNoExt := strings.TrimSuffix(blkStem, ".dat")
			revNoExt := strings.TrimSuffix(revStem, ".dat")
			
			// Simple check: "blk001" and "rev001" stems should match the numeric part
			blkNum := strings.TrimPrefix(blkNoExt, "blk")
			revNum := strings.TrimPrefix(revNoExt, "rev")
			if blkNum != revNum {
				sendError(w, "FILE_MISMATCH", fmt.Sprintf("File mismatch: block file '%s' and undo file '%s' do not belong to the same sequence.", filepath.Base(blkPath), filepath.Base(revPath)), 400)
				return
			}
		}

		xorStat, err := os.Stat(xorPath)
		if err == nil && xorStat.Size() != 32 && xorStat.Size() != 0 {
			// standard leveldb xor is 32 bytes
			// if it's way off, it's probably the wrong file
			if xorStat.Size() > 1024 {
				sendError(w, "INVALID_XOR_KEY", "The XOR key file is too large. Did you upload the correct xor.dat file?", 400)
				return
			}
		}
		
		fullReport, stem, err := analysis.RunAnalysis(blkPath, revPath, xorPath)
		if err != nil {
			// Check if it's a magic byte error from the parser
			if strings.Contains(err.Error(), "invalid magic") {
				sendError(w, "INVALID_DAT_FILE", "The file content does not match Bitcoin block format. Check if the XOR key is correct.", 400)
			} else {
				sendError(w, "ANALYSIS_FAILED", "Analysis engine error: "+err.Error(), 500)
			}
			return
		}
		
		os.MkdirAll("out", 0755)
		report.WriteJSON(filepath.Join("out", stem+".json"), fullReport)
		report.WriteMarkdown(filepath.Join("out", stem+".md"), fullReport)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := staticFiles.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	fmt.Printf("http://%s\n", addr)

	srv := &http.Server{Addr: addr}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	fmt.Println("\nShutting down server...")
}
