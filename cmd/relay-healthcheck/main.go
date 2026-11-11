package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := strings.TrimSpace(os.Getenv("RELAYD_ADMIN_ADDR"))
	if addr == "" {
		addr = "127.0.0.1:9080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	// /readyz (not /healthz) so the container is actually marked unhealthy
	// when the relay has no connected carriers or fair-use isn't ready — see
	// internal/relay/metrics.go healthz/readyz doc comments.
	url := "http://" + addr + "/readyz"
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck // healthcheck exits immediately after reading status.
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "health status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
