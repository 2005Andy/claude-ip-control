package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const DefaultCheckURL = "https://api.ipify.org?format=json"

type response struct {
	IP string `json:"ip"`
}

func Check(ctx context.Context, expectedIP, checkURL string) (string, error) {
	expectedIP = strings.TrimSpace(expectedIP)
	if expectedIP == "" {
		return "", nil
	}
	if net.ParseIP(expectedIP) == nil {
		return "", fmt.Errorf("expected egress IP %q is invalid", expectedIP)
	}
	if strings.TrimSpace(checkURL) == "" {
		checkURL = DefaultCheckURL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return "", fmt.Errorf("create egress check request: %w", err)
	}
	request.Header.Set("Accept", "application/json,text/plain")
	client := &http.Client{Timeout: 15 * time.Second}
	responseBody, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("check egress IP via %s: %w", checkURL, err)
	}
	defer responseBody.Body.Close()
	if responseBody.StatusCode < 200 || responseBody.StatusCode >= 300 {
		return "", fmt.Errorf("egress check via %s returned HTTP %s", checkURL, responseBody.Status)
	}
	body, err := io.ReadAll(io.LimitReader(responseBody.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read egress check response: %w", err)
	}
	actualIP := parseIPResponse(body)
	if actualIP == "" || net.ParseIP(actualIP) == nil {
		return "", fmt.Errorf("egress check via %s returned an invalid IP: %q", checkURL, strings.TrimSpace(string(body)))
	}
	if actualIP != expectedIP {
		return actualIP, fmt.Errorf("egress IP mismatch: expected %s, observed %s", expectedIP, actualIP)
	}
	return actualIP, nil
}

func parseIPResponse(body []byte) string {
	var parsed response
	if json.Unmarshal(body, &parsed) == nil && strings.TrimSpace(parsed.IP) != "" {
		return strings.TrimSpace(parsed.IP)
	}
	return strings.TrimSpace(string(body))
}
