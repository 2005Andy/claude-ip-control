package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mihomo is the subset of the mihomo external-controller API the guard uses.
type Mihomo interface {
	Mode(ctx context.Context) (string, error)
	SetMode(ctx context.Context, mode string) error
	Group(ctx context.Context, name string) (Group, error)
	Select(ctx context.Context, group, proxy string) error
	Rules(ctx context.Context) ([]Rule, error)
	Connections(ctx context.Context) ([]Connection, error)
	CloseConnection(ctx context.Context, id string) error
}

type Group struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

type Connection struct {
	ID       string   `json:"id"`
	Chains   []string `json:"chains"`
	Rule     string   `json:"rule"`
	Metadata struct {
		Host          string `json:"host"`
		SniffHost     string `json:"sniffHost"`
		DestinationIP string `json:"destinationIP"`
		Type          string `json:"type"`
	} `json:"metadata"`
}

// ErrNotFound is returned when the controller answers 404 (e.g. missing group).
var ErrNotFound = fmt.Errorf("not found")

type mihomoClient struct {
	base   string
	secret string
	http   *http.Client
}

func NewMihomoClient(cfg MihomoConfig) Mihomo {
	transport := &http.Transport{Proxy: nil}
	base := strings.TrimRight(cfg.URL, "/")
	if cfg.Socket != "" {
		socket := cfg.Socket
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		base = "http://mihomo"
	}
	return &mihomoClient{base: base, secret: cfg.Secret, http: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

func (m *mihomoClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if m.secret != "" {
		req.Header.Set("Authorization", "Bearer "+m.secret)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("mihomo %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mihomo %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("mihomo %s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

func (m *mihomoClient) Mode(ctx context.Context) (string, error) {
	var out struct {
		Mode string `json:"mode"`
	}
	if err := m.do(ctx, http.MethodGet, "/configs", nil, &out); err != nil {
		return "", err
	}
	return strings.ToLower(out.Mode), nil
}

func (m *mihomoClient) SetMode(ctx context.Context, mode string) error {
	return m.do(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil)
}

func (m *mihomoClient) Group(ctx context.Context, name string) (Group, error) {
	var g Group
	err := m.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name), nil, &g)
	return g, err
}

func (m *mihomoClient) Select(ctx context.Context, group, proxy string) error {
	return m.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": proxy}, nil)
}

func (m *mihomoClient) Rules(ctx context.Context) ([]Rule, error) {
	var out struct {
		Rules []Rule `json:"rules"`
	}
	err := m.do(ctx, http.MethodGet, "/rules", nil, &out)
	return out.Rules, err
}

func (m *mihomoClient) Connections(ctx context.Context) ([]Connection, error) {
	var out struct {
		Connections []Connection `json:"connections"`
	}
	err := m.do(ctx, http.MethodGet, "/connections", nil, &out)
	return out.Connections, err
}

func (m *mihomoClient) CloseConnection(ctx context.Context, id string) error {
	err := m.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
	if err == ErrNotFound {
		return nil
	}
	return err
}
