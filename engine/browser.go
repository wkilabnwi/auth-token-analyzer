package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/wkilabnwi/auth-token-analyzer/models"
	"github.com/wkilabnwi/auth-token-analyzer/parser"
)

const scanTimeout = 30 * time.Second

func ScanURL(ctx playwright.BrowserContext, targetURL string) {

	page, err := ctx.NewPage()
	if err != nil {
		return
	}
	defer page.Close()

	// Capture JS Hooks
	page.OnConsole(func(msg playwright.ConsoleMessage) {
		text := msg.Text()
		if !strings.HasPrefix(text, "SINK_DETECTED:") {
			return
		}
		parts := strings.SplitN(text, ":", 4)
		if len(parts) < 4 {
			return
		}
		storageType, key, value := parts[1], parts[2], parts[3]
		if !parser.IsSensitive(value) {
			return
		}
		fmt.Printf("[!] STORAGE HOOK (%s) key=%s: %s\n", storageType, key, targetURL)
		models.FindingChan <- models.Finding{
			Type:     "STORAGE_HOOK",
			Location: targetURL,
			Key:      storageType + ":" + key,
			Payload:  value,
		}
	})

	page.AddInitScript(playwright.Script{
		Content: playwright.String(`
			['localStorage', 'sessionStorage'].forEach(function(type) {
				var originalSet = window[type].setItem.bind(window[type]);
				window[type].setItem = function(key, value) {
					console.log("SINK_DETECTED:" + type + ":" + key + ":" + value);
					return originalSet(key, value);
				};
			});
			var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
			                 Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
			if (cookieDesc && cookieDesc.configurable) {
				Object.defineProperty(document, 'cookie', {
					set: function(val) {
						console.log("SINK_DETECTED:cookie:document.cookie:" + val);
						cookieDesc.set.call(document, val);
					}
				});
			}
		`),
	})

	// Scan Responses
	page.OnResponse(func(res playwright.Response) {
		url := res.URL()
		headers := res.Headers()

		skipHeaders := map[string]bool{
			"content-security-policy": true,
			"cache-control":           true,
			"etag":                    true,
			"last-modified":           true,
			"content-encoding":        true,
			"transfer-encoding":       true,
			"vary":                    true,
		}
		for k, v := range headers {
			if skipHeaders[strings.ToLower(k)] {
				continue
			}
			if parser.IsSensitive(v) {
				fmt.Printf("[!] HEADER LEAK (%s): %s\n", k, url)
				models.FindingChan <- models.Finding{Type: "HEADER", Location: url, Key: k, Payload: v}
			}
		}

		ct := headers["content-type"]
		isJS := strings.Contains(ct, "javascript")
		isJSON := strings.Contains(ct, "json")
		isHTML := strings.Contains(ct, "html")

		if !isJS && !isJSON && !isHTML {
			return
		}

		body, err := res.Body()
		if err != nil || len(body) == 0 {
			return
		}
		bodyStr := string(body)

		if isJS || isJSON {
			// Full secret extraction forstructured content
			secrets := parser.ExtractSecrets(bodyStr)
			for patternName, matches := range secrets {
				for _, match := range matches {
					fmt.Printf("[!] SOURCE LEAK (%s): %s\n", patternName, url)
					models.FindingChan <- models.Finding{
						Type:     "SOURCE",
						Location: url,
						Key:      patternName,
						Payload:  match,
					}
				}
			}
		} else if isHTML {
			// For HTML, only scan inline <script> block contents to avoid
			for _, block := range extractScriptBlocks(bodyStr) {
				secrets := parser.ExtractSecrets(block)
				for patternName, matches := range secrets {
					for _, match := range matches {
						fmt.Printf("[!] INLINE SCRIPT LEAK (%s): %s\n", patternName, url)
						models.FindingChan <- models.Finding{
							Type:     "INLINE_SCRIPT",
							Location: url,
							Key:      patternName,
							Payload:  match,
						}
					}
				}
			}
		}
	})

	// Navigate with timeout
	_, err = page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(float64(scanTimeout.Milliseconds())),
	})
	if err != nil {
		fmt.Printf("[!] Timeout or navigation error for %s: %v\n", targetURL, err)
	}
}

// extractScriptBlocks pulls content between <script> and </script> tags.
func extractScriptBlocks(html string) []string {
	var blocks []string
	lower := strings.ToLower(html)
	searchFrom := 0
	for {
		start := strings.Index(lower[searchFrom:], "<script")
		if start == -1 {
			break
		}
		start += searchFrom
		closeTag := strings.Index(lower[start:], ">")
		if closeTag == -1 {
			break
		}
		contentStart := start + closeTag + 1
		end := strings.Index(lower[contentStart:], "</script>")
		if end == -1 {
			break
		}
		block := html[contentStart : contentStart+end]
		if strings.TrimSpace(block) != "" {
			blocks = append(blocks, block)
		}
		searchFrom = contentStart + end + len("</script>")
	}
	return blocks
}
