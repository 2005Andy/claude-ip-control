package egress

import "testing"

func TestParseIPResponse(t *testing.T) {
	if got := parseIPResponse([]byte(`{"ip":"142.249.129.109"}`)); got != "142.249.129.109" {
		t.Fatalf("got %q", got)
	}
	if got := parseIPResponse([]byte("142.249.129.109\n")); got != "142.249.129.109" {
		t.Fatalf("got %q", got)
	}
}
