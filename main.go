package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	success    = "SUCCESS"
	recordType = "A"
)

var client http.Client

// flags
var (
	level slog.Level

	endpoint = flag.String(
		"endpoint",
		"https://api-ipv4.porkbun.com/api/json/v3",
		"Porkbun API endpoint",
	)
	apiKey = flag.String(
		"apikey",
		"",
		"Porkbun API key (example: pk1_deadbeef)",
	)
	secKey = flag.String(
		"secretapikey",
		"",
		"Porkbun secret API key (example: sk1_deadbeef)",
	)
	domain = flag.String(
		"domain",
		"",
		"The top-level domain (example: google.com)",
	)
	subdomain = flag.String(
		"subdomain",
		"",
		"The sub domain (example: www, leave empty for root)",
	)
	ip = flag.String(
		"ip",
		"",
		"The IPv4 ip for the A record (leave empty to use your current IP via Porkbun API)",
	)
	unifiAPIKey = flag.String(
		"unifi-apikey",
		"",
		"When set and ip is unset, get the IP from unifi API instead of Porkbun API",
	)
	ttl = flag.Duration(
		"ttl",
		10*time.Minute, // NOTE: this is the current minimal TTL allowed by Porkbun
		"The TTL for the record",
	)
	timeout = flag.Duration(
		"timeout",
		5*time.Second,
		"Timeout for each http requests",
	)
)

type request struct {
	// Required for all requests
	APIKey string `json:"apikey"`
	SecKey string `json:"secretapikey"`

	Subdomain string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	Content   string `json:"content,omitempty"`
	TTL       string `json:"ttl,omitempty"`
}

func main() {
	flag.TextVar(&level, "log-level", &level, "minimal log level to keep")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     &level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if req, ok := a.Value.Any().(request); ok {
				req.SecKey = "*REDACTED*"

				var sb strings.Builder
				if err := json.NewEncoder(&sb).Encode(req); err == nil {
					a.Value = slog.StringValue(sb.String())
				}
			}
			return a
		},
	})))

	ctx := context.Background()
	content := getIP(ctx)
	slog.DebugContext(ctx, "auth successful", "ip", content)
	if *ip != "" {
		content = *ip
	} else if *unifiAPIKey != "" {
		content = getIPFromUnifi(ctx, *unifiAPIKey)
	}
	id, prevContent := getID(ctx)
	if prevContent == content {
		slog.InfoContext(ctx, "same ip, skipping...")
		return
	}
	if id != "" {
		update(ctx, id, content)
	} else {
		create(ctx, content)
	}
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func getBuf() *bytes.Buffer {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func returnBuf(buf **bytes.Buffer) {
	bufPool.Put(*buf)
	*buf = nil
}

func fatal(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
	os.Exit(-1)
}

func decodeBody(resp *http.Response, data any) (string, error) {
	buf := getBuf()
	defer returnBuf(&buf)
	reader := io.TeeReader(resp.Body, buf)
	defer func() {
		io.Copy(io.Discard, reader)
		resp.Body.Close()
	}()

	err := json.NewDecoder(reader).Decode(data)
	return buf.String(), err
}

func getIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,
	}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request",
			"err", err,
			"request", req,
		)
		return ""
	}

	url := *endpoint + "/ping"
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request",
			"err", err,
			"url", url,
			"request", req,
		)
		return ""
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed",
			"err", err,
			"url", url,
			"request", req,
		)
		return ""
	}
	var data struct {
		Status string `json:"status"`
		IP     string `json:"yourIp"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return ""
	}
	slog.DebugContext(ctx, "auth", "url", url, "response", body, "decoded", data)
	if data.Status != success {
		fatal(
			ctx,
			"Ping failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return ""
	}
	return data.IP
}

func getID(ctx context.Context) (id, ip string) {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := request{
		APIKey: *apiKey,
		SecKey: *secKey,
	}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request",
			"err", err,
			"request", req,
		)
		return "", ""
	}

	url := fmt.Sprintf("%s/dns/retrieveByNameType/%s/%s/", *endpoint, *domain, recordType)
	if *subdomain != "" {
		url += *subdomain
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request",
			"err", err,
			"url", url,
			"request", req,
		)
		return "", ""
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed",
			"err", err,
			"url", url,
			"request", req,
		)
		return "", ""
	}
	var data struct {
		Status string `json:"status"`

		Records []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"records"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return "", ""
	}
	if data.Status != success {
		fatal(
			ctx,
			"Ping failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return "", ""
	}
	slog.DebugContext(ctx, "existing records", "url", url, "response", body, "decoded", data)
	switch len(data.Records) {
	default:
		fatal(
			ctx,
			"Multiple A record found",
			"records", data.Records,
		)
		return "", ""
	case 0:
		return "", ""
	case 1:
		return data.Records[0].ID, data.Records[0].Content
	}
}

func updateOrCreateRequest(content string) request {
	return request{
		APIKey: *apiKey,
		SecKey: *secKey,

		Subdomain: *subdomain,
		Type:      recordType,
		Content:   content,
		TTL:       strconv.FormatInt(int64(ttl.Seconds()), 10),
	}
}

func update(ctx context.Context, id string, content string) {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := updateOrCreateRequest(content)
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request",
			"err", err,
			"request", req,
		)
		return
	}

	url := fmt.Sprintf("%s/dns/edit/%s/%s", *endpoint, *domain, id)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}
	var data struct {
		Status string `json:"status"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return
	}
	if data.Status != success {
		fatal(
			ctx,
			"Ping failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return
	}
	slog.DebugContext(ctx, "updated record", "url", url, "response", body, "decoded", data)
}

func create(ctx context.Context, content string) {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	buf := getBuf()
	defer returnBuf(&buf)

	req := updateOrCreateRequest(content)
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		fatal(
			ctx,
			"Failed to json encode request",
			"err", err,
			"request", req,
		)
		return
	}

	url := fmt.Sprintf("%s/dns/create/%s", *endpoint, *domain)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		fatal(
			ctx,
			"Failed to generate http request",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}

	resp, err := client.Do(r)
	if err != nil {
		fatal(
			ctx,
			"http request failed",
			"err", err,
			"url", url,
			"body", buf.String(),
		)
		return
	}
	var data struct {
		Status string `json:"status"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode response body",
			"err", err,
			"url", url,
			"code", resp.StatusCode,
			"body", body,
		)
		return
	}
	if data.Status != success {
		fatal(
			ctx,
			"Ping failed",
			"url", url,
			"code", resp.StatusCode,
			"status", data.Status,
			"body", body,
		)
		return
	}
	slog.DebugContext(ctx, "created record", "url", url, "response", body, "decoded", data)
}

var zeroV4 [4]byte

func isPublicV4IP(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}
	if ip.As4() == zeroV4 {
		return false
	}
	return true
}

func getIPFromUnifi(ctx context.Context, apikey string) string {
	const endpoint = "https://api.ui.com/v1/hosts"

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		fatal(ctx, "failed to create unifi api request", "err", err)
		return ""
	}
	r.Header.Set("X-API-Key", apikey)
	r.Header.Set("Accept", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		fatal(ctx, "unifi api http request failed", "err", err)
		return ""
	}
	var data struct {
		Data []struct {
			ReportedState struct {
				IP netip.Addr `json:"ip"`
			} `json:"reportedState"`
		} `json:"data"`
	}
	body, err := decodeBody(resp, &data)
	if err != nil {
		fatal(
			ctx,
			"Failed to decode unifi response body",
			"err", err,
			"code", resp.StatusCode,
			"body", body,
		)
		return ""
	}
	if len(data.Data) == 0 {
		fatal(ctx, "No data in unifi api response", "body", body)
		return ""
	}
	if len(data.Data) > 1 {
		slog.WarnContext(
			ctx,
			"More than one data in unifi api response",
			"data", data,
		)
	}
	// Find the first public v4 address
	for i := range data.Data {
		ip := data.Data[i].ReportedState.IP.Unmap()
		if !isPublicV4IP(ip) {
			continue
		}
		slog.DebugContext(
			ctx,
			"Found public v4 ip from unifi response",
			"i", i,
			"ip", ip,
			"body", body,
		)
		return netip.AddrFrom4(ip.As4()).String()
	}
	fatal(
		ctx,
		"No public v4 ip from unifi response found",
		"data", data,
	)
	return ""
}
