package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/tidwall/pretty"
)

var version = "dev"

func main() {
	jsonOut := flag.Bool("json", false, "output raw JSON (no colors, for piping)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "jut - JWT decoder for your terminal\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  jut                  decode JWT from clipboard\n")
		fmt.Fprintf(os.Stderr, "  jut <token>          decode a JWT\n")
		fmt.Fprintf(os.Stderr, "  echo <token> | jut   read from stdin\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("jut %s\n", version)
		os.Exit(0)
	}

	token := getToken(flag.Args())
	parts := strings.Split(token, ".")
	if len(parts) < 2 || len(parts) > 3 {
		fatal("invalid JWT: expected 2 or 3 dot-separated segments, got %d", len(parts))
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		fatal("failed to decode header: %v", err)
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		fatal("failed to decode payload: %v", err)
	}

	if *jsonOut {
		printJSON(header, payload)
	} else {
		printPretty(header, payload)
	}
}

func getToken(args []string) string {
	if len(args) > 0 {
		return strings.TrimSpace(args[0])
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal("failed to read stdin: %v", err)
		}
		return strings.TrimSpace(string(b))
	}

	// No args, no pipe — try clipboard
	text, err := clipboard.ReadAll()
	if err != nil {
		fatal("failed to read clipboard: %v", err)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		fatal("clipboard is empty")
	}
	return text
}

func decodeSegment(seg string) ([]byte, error) {
	// JWT uses base64url encoding without padding
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}

	// Re-marshal to get consistently formatted JSON
	var obj map[string]interface{}
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	return json.Marshal(obj)
}

func printJSON(header, payload []byte) {
	out := map[string]json.RawMessage{
		"header":  header,
		"payload": payload,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

func printPretty(header, payload []byte) {
	// Colors
	dim := "\033[2m"
	bold := "\033[1m"
	reset := "\033[0m"
	cyan := "\033[36m"
	green := "\033[32m"

	fmt.Printf("\n%s%s── HEADER ──%s\n", bold, cyan, reset)
	fmt.Println(string(pretty.Color(pretty.Pretty(header), nil)))

	fmt.Printf("%s%s── PAYLOAD ─%s\n", bold, green, reset)
	fmt.Println(string(pretty.Color(pretty.Pretty(payload), nil)))

	// Parse payload for timestamp info
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return
	}

	timestamps := extractTimestamps(claims)
	if len(timestamps) > 0 {
		fmt.Printf("%s%s── DATES ───%s\n", bold, dim, reset)
		for _, ts := range timestamps {
			fmt.Printf("  %s%-4s%s %s%s%s", dim, ts.name+":", reset, "", ts.formatted, reset)
			if ts.relative != "" {
				fmt.Printf("  %s(%s)%s", dim, ts.relative, reset)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	// Expiry check
	if exp, ok := claims["exp"]; ok {
		if expF, ok := exp.(float64); ok {
			expTime := time.Unix(int64(expF), 0)
			now := time.Now()
			if now.After(expTime) {
				red := "\033[31m"
				ago := humanDuration(now.Sub(expTime))
				fmt.Printf("  %s%s✗ EXPIRED%s %s(%s ago)%s\n\n", bold, red, reset, dim, ago, reset)
			} else {
				remaining := humanDuration(expTime.Sub(now))
				fmt.Printf("  %s%s✓ VALID%s %s(expires in %s)%s\n\n", bold, green, reset, dim, remaining, reset)
			}
		}
	}
}

type tsInfo struct {
	name      string
	formatted string
	relative  string
}

func extractTimestamps(claims map[string]interface{}) []tsInfo {
	known := []struct {
		key  string
		name string
	}{
		{"iat", "iat"},
		{"nbf", "nbf"},
		{"exp", "exp"},
	}

	var results []tsInfo
	for _, k := range known {
		val, ok := claims[k.key]
		if !ok {
			continue
		}
		f, ok := val.(float64)
		if !ok {
			continue
		}
		t := time.Unix(int64(f), 0)
		rel := humanDuration(time.Since(t))
		if time.Now().Before(t) {
			rel = "in " + rel
		} else {
			rel = rel + " ago"
		}
		results = append(results, tsInfo{
			name:      k.name,
			formatted: t.Format("2006-01-02 15:04:05 MST"),
			relative:  rel,
		})
	}
	return results
}

func humanDuration(d time.Duration) string {
	d = d.Abs()
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(math.Mod(d.Minutes(), 60))
		if m > 0 {
			return fmt.Sprintf("%dh %dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	days := int(d.Hours() / 24)
	if days < 30 {
		return fmt.Sprintf("%dd", days)
	}
	if days < 365 {
		return fmt.Sprintf("%dmo", days/30)
	}
	return fmt.Sprintf("%dy", days/365)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "jut: "+format+"\n", args...)
	os.Exit(1)
}
