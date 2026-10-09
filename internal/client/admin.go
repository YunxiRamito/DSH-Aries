// Package client contains the Aries server-management API client used by
// serverctl. It deliberately exposes only the admin API, not device APIs.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultTimeout  = 10 * time.Second
	maxResponseBody = 4 << 20
)

// Client is an authenticated client for the versioned server-management API.
type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

// InputError describes invalid client options such as an endpoint or timeout.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// New creates a client after validating the endpoint and securely reading the
// token file. The token is kept in memory and is never included in errors.
func New(endpoint, tokenFile string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		return nil, &InputError{Message: "timeout must be greater than zero"}
	}
	base, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	token, err := ReadToken(tokenFile)
	if err != nil {
		return nil, err
	}
	return newClient(base, token, timeout), nil
}

// NewWithToken creates a client with an already loaded token. It is useful for
// embedding and tests; command-line users should use New and a token file.
func NewWithToken(endpoint, token string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		return nil, &InputError{Message: "timeout must be greater than zero"}
	}
	if strings.TrimSpace(token) == "" {
		return nil, &InputError{Message: "admin token is empty"}
	}
	base, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return newClient(base, token, timeout), nil
}

func newClient(base *url.URL, token string, timeout time.Duration) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		// Never send loopback HTTP requests (and their bearer token) through an
		// environment-configured proxy.
		if req.URL.Scheme == "http" && isLoopbackHost(req.URL.Hostname()) {
			return nil, nil
		}
		return http.ProxyFromEnvironment(req)
	}
	return &Client{
		baseURL: base,
		token:   token,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Admin credentials are scoped to the configured endpoint. Do not
				// forward a request to a redirect target.
				return http.ErrUseLastResponse
			},
		},
	}
}

func parseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return nil, &InputError{Message: "endpoint must be an absolute http or https URL, for example https://server.example:8788"}
	}
	if u.Opaque != "" {
		return nil, &InputError{Message: "endpoint must be a hierarchical URL with a host"}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, &InputError{Message: "endpoint must not include credentials, a query string, or a fragment"}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, &InputError{Message: "endpoint must be the server origin without an API path"}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, &InputError{Message: "plain HTTP is allowed only for loopback development endpoints; use HTTPS for remote administration"}
		}
	default:
		return nil, &InputError{Message: "endpoint scheme must be http or https"}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Get performs an authenticated JSON GET on a path below /api/v1/admin. The
// path is fixed by the caller; arbitrary absolute URLs are rejected.
func (c *Client) Get(ctx context.Context, path string) (json.RawMessage, error) {
	return c.request(ctx, http.MethodGet, path, nil, "")
}

// Put performs an authenticated JSON PUT. idempotencyKey should be a unique
// random value for a durable configuration update.
func (c *Client) Put(ctx context.Context, path string, body json.RawMessage, idempotencyKey string) (json.RawMessage, error) {
	return c.request(ctx, http.MethodPut, path, body, idempotencyKey)
}

func (c *Client) Post(ctx context.Context, path string, body json.RawMessage, idempotencyKey string) (json.RawMessage, error) {
	return c.request(ctx, http.MethodPost, path, body, idempotencyKey)
}

func (c *Client) request(ctx context.Context, method, path string, body json.RawMessage, idempotencyKey string) (json.RawMessage, error) {
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/api/v1/admin/") || strings.Contains(parsed.Path, "..") || parsed.Fragment != "" {
		return nil, errors.New("invalid server-management API path")
	}
	u := *c.baseURL
	u.Path = parsed.Path
	u.RawQuery = parsed.RawQuery
	var payload io.Reader
	if body != nil {
		if !json.Valid(body) {
			return nil, errors.New("request body is not valid JSON")
		}
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), payload)
	if err != nil {
		return nil, fmt.Errorf("create API request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, describeTransportError(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, fmt.Errorf("read server response: %w", err)
	}
	if len(b) > maxResponseBody {
		return nil, errors.New("server response exceeded the 4 MiB safety limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp.StatusCode, b, c.token)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, fmt.Errorf("server returned an empty response (HTTP %d)", resp.StatusCode)
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("server returned invalid JSON (HTTP %d)", resp.StatusCode)
	}
	return json.RawMessage(b), nil
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// APIError is a structured HTTP rejection returned by the server.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("server rejected request (HTTP %d, %s): %s", e.Status, e.Code, e.Message)
	if e.RequestID != "" {
		message += " [request " + e.RequestID + "]"
	}
	return message
}

// ConnectionError identifies endpoint, network, and timeout failures for
// stable CLI exit-code mapping.
type ConnectionError struct{ Message string }

func (e *ConnectionError) Error() string { return e.Message }

func parseAPIError(status int, body []byte, token string) error {
	var envelope errorEnvelope
	if json.Unmarshal(body, &envelope) == nil && envelope.Error.Code != "" {
		message := strings.TrimSpace(envelope.Error.Message)
		if message == "" {
			message = "request failed"
		}
		message = safeErrorText(message, 512)
		code := safeErrorText(envelope.Error.Code, 96)
		requestID := safeErrorText(envelope.Error.RequestID, 128)
		if token != "" {
			message = strings.ReplaceAll(message, token, "[redacted]")
			code = strings.ReplaceAll(code, token, "[redacted]")
			requestID = strings.ReplaceAll(requestID, token, "[redacted]")
		}
		return &APIError{Status: status, Code: code, Message: message, RequestID: requestID}
	}
	return fmt.Errorf("server rejected request (HTTP %d)", status)
}

func safeErrorText(value string, limit int) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, value)
	clean = strings.Join(strings.Fields(clean), " ")
	runes := []rune(clean)
	if len(runes) > limit {
		clean = string(runes[:limit]) + "…"
	}
	return clean
}

func describeTransportError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &ConnectionError{Message: "request timed out; check the endpoint, network, and --timeout value"}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if errors.Is(urlErr.Err, context.DeadlineExceeded) {
			return &ConnectionError{Message: "request timed out; check the endpoint, network, and --timeout value"}
		}
		var opErr *net.OpError
		if errors.As(urlErr.Err, &opErr) && opErr.Op == "dial" {
			return &ConnectionError{Message: "could not connect to the server; check the endpoint, listener, and firewall"}
		}
		return &ConnectionError{Message: fmt.Sprintf("could not reach the server: %v", urlErr.Err)}
	}
	return &ConnectionError{Message: fmt.Sprintf("API request failed: %v", err)}
}
