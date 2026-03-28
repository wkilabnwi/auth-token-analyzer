package models

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type Finding struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Key      string `json:"key"`
	Payload  string `json:"payload"`
}

var FindingChan = make(chan Finding, 500)

var (
	seenMu sync.Mutex
	seen   = make(map[[32]byte]struct{})
)

func isDuplicate(f Finding) bool {
	h := sha256.Sum256([]byte(f.Type + "|" + f.Key + "|" + f.Payload))
	seenMu.Lock()
	defer seenMu.Unlock()
	if _, ok := seen[h]; ok {
		return true
	}
	seen[h] = struct{}{}
	return false
}

func StartWriter(filename string) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Printf("[!] Writer Error: %v\n", err)
			for range FindingChan {
			}
			return
		}
		defer file.Close()

		var findings []Finding
		for f := range FindingChan {
			if !isDuplicate(f) {
				findings = append(findings, f)
			}
		}

		enc := json.NewEncoder(file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Printf("[!] JSON encode error: %v\n", err)
		}
	}()
	return done
}
