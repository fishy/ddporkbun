package main

import (
	"bufio"
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
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yhsif.com/ctxslog"
	"go.yhsif.com/flagutils"
)

const (
	success      = "SUCCESS"
	v4RecordType = "A"
	v6RecordType = "AAAA"
)

var client http.Client

// flags
var (
	level slog.Level

	v4 = flagutils.OneOf{Bool: true}
	v6 = flagutils.OneOf{Bool: false}

	v4Endpoint = flag.String(
		"endpoint",
		"https://api-ipv4.porkbun.com/api/json/v3",
		"Porkbun IPv4 API endpoint",
	)
	v6Endpoint = flag.String(
		"v6-endpoint",
		"https://api.porkbun.com/api/json/v3",
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
		"The ip to set (leave empty to figure out your current IP via APIs)",
	)
	v6LocalIP = flag.Bool(
		"local-ipv6",
		true,
		"When set with ipv6 set and ip is unset, get the first public IPv6 from local network interfaces instead of using APIs (NOTE: requires `ip addr` command to be available",
	)
	unifiAPIKey = flag.String(
		"unifi-apikey",
		"",
		"When set with ipv4 set and ip is unset, get the IP from unifi API instead of Porkbun API",
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

func redactSecKey(groups []string, a slog.Attr) slog.Attr {
	if req, ok := a.Value.Any().(request); ok {
		req.SecKey = "*REDACTED*"

		var sb strings.Builder
		if err := json.NewEncoder(&sb).Encode(req); err == nil {
			a.Value = slog.StringValue(sb.String())
		}
	}
	return a
}

func main() {
	flag.Var(&v4, "ipv4", "Set ipv4 ip (A record), unsets ipv6")
	flag.Var(&v6, "ipv6", "Set ipv6 ip (AAAA record), unsets ipv4")
	flagutils.GroupOneOf(&v4, &v6)
	flag.TextVar(&level, "log-level", &level, "minimal log level to keep")
	flag.Parse()

	slog.SetDefault(ctxslog.New(
		ctxslog.WithText,
		ctxslog.WithAddSource(true),
		ctxslog.WithLevel(&level),
		ctxslog.WithReplaceAttr(ctxslog.ChainReplaceAttr(
			redactSecKey,
		)),
	))

	ctx := context.Background()
	switch {
	default:
		ctx = ctxslog.Attach(ctx, slog.Bool("ipv4", true))
	case v6.Bool:
		ctx = ctxslog.Attach(ctx, slog.Bool("ipv6", true))
	}
	content := getIP(ctx)
	slog.DebugContext(ctx, "auth successful", "ip", content)
	if *ip != "" {
		content = *ip
	} else {
		switch {
		default:
			if *unifiAPIKey != "" {
				content = getIPFromUnifi(ctx, *unifiAPIKey)
			}

		case v6.Bool:
			if *v6LocalIP {
				content = getFirstPublicIPv6(ctx)
			}
		}
	}
	doubleCheckIP(ctx, content)
	id, prevContent := getID(ctx)
	if prevContent == content {
		slog.InfoContext(ctx, "same ip, skipping...", "ip", content)
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

func getPorkbunEndpoint() string {
	switch {
	default:
		return *v4Endpoint

	case v6.Bool:
		return *v6Endpoint
	}
}

func getRecordType() string {
	switch {
	default:
		return v4RecordType

	case v6.Bool:
		return v6RecordType
	}
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

	url := getPorkbunEndpoint() + "/ping"
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

	url := fmt.Sprintf("%s/dns/retrieveByNameType/%s/%s/", getPorkbunEndpoint(), *domain, getRecordType())
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
			"Failed to get existing records",
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
		Type:      getRecordType(),
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

	url := fmt.Sprintf("%s/dns/edit/%s/%s", getPorkbunEndpoint(), *domain, id)
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
			"Failed to update existing record",
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

	url := fmt.Sprintf("%s/dns/create/%s", getPorkbunEndpoint(), *domain)
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
			"Failed to create record",
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

func isPublicIPv4(ctx context.Context, ip netip.Addr) bool {
	ctx = ctxslog.Attach(ctx, "ip", ip)
	if !ip.Is4() {
		slog.DebugContext(ctx, "Skipping non-4")
		return false
	}
	if ip.As4() == zeroV4 {
		slog.DebugContext(ctx, "Skipping zero")
		return false
	}
	return isPublicIP(ctx, ip)
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
		if ip := data.Data[i].ReportedState.IP.Unmap(); isPublicIPv4(ctx, ip) {
			return netip.AddrFrom4(ip.As4()).String()
		}
	}
	fatal(
		ctx,
		"No public v4 ip from unifi response found",
		"data", data,
	)
	return ""
}

// With IPv6 SLAAC privacy, we could have multiple public IPv6 addresses, with
// one of them being "permenant" and others being "temporary" or "deprecated".
// But in Go there's no way to tell them apart
// (https://github.com/golang/go/issues/42694), so instead we just parse the
// output of `ip addr` with regular expression instead (https://xkcd.com/208/).
//
// Example line:
//
//	inet6 1234:1234::1234/64 scope global temporary dynamic
var ipv6RE = regexp.MustCompile(`inet6 ([0-9a-f:]*)/[0-9]* scope (.*)`)

func getFirstPublicIPv6(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "ip", "addr")
	output, err := cmd.Output()
	if err != nil {
		fatal(ctx, "Failed to run `ip addr`", "err", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		groups := ipv6RE.FindStringSubmatch(line)
		if len(groups) == 0 {
			slog.DebugContext(ctx, "Skipping line", "line", line)
			continue
		}
		ipStr := groups[1]
		scopes := strings.Fields(groups[2])
		slog.DebugContext(ctx, "Matched line", "ip", ipStr, "scopes", scopes, "line", line)
		if !slices.Contains(scopes, "global") || slices.Contains(scopes, "temporary") || slices.Contains(scopes, "deprecated") {
			// We only want global ipv6 without temporary or deprecated scopes
			slog.DebugContext(ctx, "Skipping by scopes", "scopes", scopes)
			continue
		}
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			slog.WarnContext(ctx, "Failed to parse IP", "err", err, "ip", ipStr)
			continue
		}
		if isPublicIPv6(ctx, ip) {
			return ip.String()
		}
	}
	fatal(ctx, "No public ipv6 found from `ip addr`")
	return ""
}

func isPublicIP(ctx context.Context, ip netip.Addr) bool {
	if !ip.IsValid() {
		slog.WarnContext(ctx, "Skipping invalid")
		return false
	}
	if ip.IsLoopback() {
		slog.DebugContext(ctx, "Skipping loopback")
		return false
	}
	if ip.IsPrivate() {
		slog.DebugContext(ctx, "Skipping private")
		return false
	}
	if ip.IsUnspecified() {
		slog.DebugContext(ctx, "Skipping unspecifid")
		return false
	}
	if ip.IsLinkLocalMulticast() {
		slog.DebugContext(ctx, "Skipping link local multicast")
		return false
	}
	if ip.IsLinkLocalUnicast() {
		slog.DebugContext(ctx, "Skipping link local unicast")
		return false
	}
	slog.DebugContext(ctx, "Found public ip")
	return true
}

var zeroV6 [16]byte

func isPublicIPv6(ctx context.Context, ip netip.Addr) bool {
	ctx = ctxslog.Attach(ctx, slog.Any("ip", ip))
	if !ip.Is6() {
		slog.DebugContext(ctx, "Skipping non-6")
		return false
	}
	if ip.Is4In6() {
		slog.DebugContext(ctx, "Skipping 4-in-6")
		return false
	}
	if ip.As16() == zeroV6 {
		slog.DebugContext(ctx, "Skipping zero")
		return false
	}
	return isPublicIP(ctx, ip)
}

func doubleCheckIP(ctx context.Context, ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		fatal(ctx, "Failed to parse contet as ip", "err", err, "content", ip)
	}
	switch {
	default:
		if !addr.Is4() {
			fatal(ctx, "Trying to set non-v4 ip", "ip", ip, "recordType", getRecordType())
		}

	case v6.Bool:
		if !addr.Is6() {
			fatal(ctx, "Trying to set non-v6 ip", "ip", ip, "recordType", getRecordType())
		}
	}
}
