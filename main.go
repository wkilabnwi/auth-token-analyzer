package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/wkilabnwi/auth-token-analyzer/engine"
	"github.com/wkilabnwi/auth-token-analyzer/models"
)

func main() {
	url := flag.String("url", "", "Base URL")
	wordlist := flag.String("w", "", "Path to wordlist.txt")
	threads := flag.Int("t", 5, "Threads")
	user := flag.String("u", "", "Username")
	pass := flag.String("p", "", "Password")
	output := flag.String("o", "findings.json", "Output file")
	userSel := flag.String("user-sel", "", "CSS selector for username field (optional)")
	passSel := flag.String("pass-sel", "", "CSS selector for password field (optional)")
	submitSel := flag.String("submit-sel", "", "CSS selector for submit button (optional)")
	flag.Parse()

	if *url == "" {
		log.Fatal("Usage: go run main.go -url http://site.com -u admin -p pass123")
	}

	// Starting async writer
	writerDone := models.StartWriter(*output)

	pw, err := playwright.Run()
	if err != nil {
		log.Fatalf("could not start playwright: %v", err)
	}
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)})
	if err != nil {
		log.Fatalf("[!] Failed to launch browser: %v", err)
	}

	// 1. Perform Login First if credentials provided
	var storageStateFile string
	if *user != "" && *pass != "" {
		loginCtx, err := browser.NewContext()
		if err != nil {
			log.Fatalf("[!] Failed to create login context: %v", err)
		}
		if !engine.Login(loginCtx, *url+"/login", *user, *pass, *userSel, *passSel, *submitSel) {
			log.Fatal("[!] Aborting — login failed")
		}
		tmpFile, err := os.CreateTemp("", "auth-state-*.json")
		if err != nil {
			log.Fatalf("[!] Failed to create temp state file: %v", err)
		}
		storageStateFile = tmpFile.Name()
		tmpFile.Close()
		if _, err := loginCtx.StorageState(storageStateFile); err != nil {
			log.Fatalf("[!] Failed to capture storage state: %v", err)
		}
		loginCtx.Close()
		defer os.Remove(storageStateFile)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	// 2. Start Worker Pool — each worker gets its own browser context so
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := playwright.BrowserNewContextOptions{}
			if storageStateFile != "" {
				opts.StorageStatePath = &storageStateFile
			}
			workerCtx, err := browser.NewContext(opts)
			if err != nil {
				log.Printf("[!] Worker failed to create context: %v", err)
				return
			}
			defer workerCtx.Close()
			for target := range jobs {
				engine.ScanURL(workerCtx, target)
			}
		}()
	}

	// 3. Feed URLs
	jobs <- *url
	if *wordlist != "" {
		file, err := os.Open(*wordlist)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				jobs <- *url + "/" + scanner.Text()
				time.Sleep(200 * time.Millisecond) // polite delay
			}
			file.Close()
		}
	}
	close(jobs)

	wg.Wait()
	close(models.FindingChan)
	<-writerDone

	fmt.Println("[+] Audit complete. Check", *output)
}
