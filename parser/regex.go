package parser

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// RegexMap stores patterns for various sensitive data types
var RegexMap = map[string]*regexp.Regexp{
	"JWT_TOKEN":       regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"GOOGLE_API_KEY":  regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"AWS_ACCESS_KEY":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"RSA_PRIVATE_KEY": regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	"GENERIC_BEARER":  regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+[A-Za-z0-9-._~+/]+=*`),
	"SLACK_TOKEN":     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
}

var EntropyTarget = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)

func IsSensitive(value string) bool {
	return len(ExtractSecrets(value)) > 0
}

func ExtractSecrets(value string) map[string][]string {
	found := make(map[string][]string)

	for name, re := range RegexMap {
		matches := re.FindAllString(value, -1)
		if len(matches) == 0 {
			continue
		}
		if name == "JWT_TOKEN" {
			for _, m := range matches {
				decoded := DecodeJWT(m)
				if !strings.Contains(decoded, "Error") && !strings.Contains(decoded, "Invalid") {
					found[name] = append(found[name], m)
				}
			}
			continue
		}
		found[name] = append(found[name], matches...)
	}

	potentialSecrets := EntropyTarget.FindAllString(value, -1)
	for _, s := range potentialSecrets {
		if len(s) >= 32 && CalculateEntropy(s) > 4.5 {
			found["HIGH_ENTROPY"] = append(found["HIGH_ENTROPY"], s)
		}
	}

	return found
}

func DecodeJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "Invalid Token"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "Decode Error"
	}
	if !json.Valid(payload) {
		return "Invalid JSON payload"
	}
	return string(payload)
}

func CalculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	charCounts := make(map[rune]float64)
	for _, char := range s {
		charCounts[char]++
	}
	var entropy float64
	lenStr := float64(len(s))
	for _, count := range charCounts {
		p := count / lenStr
		entropy -= p * math.Log2(p)
	}
	return entropy
}
