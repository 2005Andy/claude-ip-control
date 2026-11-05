package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseIPResponse(t *testing.T) {
	if got := parseIPResponse([]byte(`{"ip":"198.51.100.7"}`)); got != "198.51.100.7" {
		t.Fatalf("got %q", got)
	}
	if got := parseIPResponse([]byte("198.51.100.7\n")); got != "198.51.100.7" {
		t.Fatalf("got %q", got)
	}
	trace := "fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nts=1\nloc=US\n"
	if got := parseIPResponse([]byte(trace)); got != "198.51.100.7" {
		t.Fatalf("trace: got %q", got)
	}
}

func TestObserveUsesGivenClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ip=2001:db8::1\nloc=US\n"))
	}))
	defer server.Close()
	got, err := Observe(context.Background(), server.Client(), server.URL)
	if err != nil || got != "2001:db8::1" {
		t.Fatalf("got %q, %v", got, err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>blocked</html>"))
	}))
	defer bad.Close()
	if _, err := Observe(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Fatal("expected error for body without IP")
	}
}
