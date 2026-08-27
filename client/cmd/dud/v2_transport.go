// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	v2DNSResponseLimit = 65535
	v2DefaultBodyLimit = 1024 * 1024
	// The single ECHConfig version this client implements, matching the one
	// crypto/tls accepts (draft-ietf-tls-esni-13).
	v2ECHConfigVersion = 0xfe0d
)

// Phase deadlines. A bounded control message is governed by one whole-request
// timeout, but a 100 MB transfer is not: it is bounded per phase instead, so a
// legitimately long body cannot be killed by a control-plane budget while a
// genuinely stalled one still dies.
const (
	v2ConnectTimeout        = 10 * time.Second
	v2TLSHandshakeTimeout   = 10 * time.Second
	v2ResponseHeaderTimeout = 15 * time.Second
	v2StreamIdleTimeout     = 60 * time.Second
)

type v2Request struct {
	Method  string
	Origin  string
	Path    string
	Headers http.Header
	// Body is the bounded request form: the whole body is already in memory
	// and its size is known by construction.
	Body []byte
	// BodyStream is the streaming request form. ContentLength must state the
	// exact number of bytes the reader will produce; a stream of unknown
	// length is not accepted, so no request is ever chunked.
	BodyStream    io.Reader
	ContentLength int64
	// StreamResponse hands the response body back unread instead of buffering
	// it. MaxResponseBytes does not apply to a streamed response.
	StreamResponse   bool
	MaxResponseBytes int64
}

type v2Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
	// Stream is set only when the request asked for a streamed response. The
	// caller owns it and must close it, which also releases the request.
	Stream io.ReadCloser
	// TLS describes the connection the response arrived on. It is nil for
	// transports that do not model one.
	TLS *v2ConnectionInfo
}

// v2ConnectionInfo is the subset of tls.ConnectionState the client reports.
// It is a plain struct rather than the crypto/tls type so an injected test
// transport can describe a connection it never made.
type v2ConnectionInfo struct {
	Version            uint16
	CipherSuite        uint16
	NegotiatedProtocol string
	ServerName         string
	ECHAccepted        bool
	// ECHPublicName is the public name of the ECHConfig the handshake used,
	// taken from the validated ECHConfigList rather than parsed from a trace.
	ECHPublicName string
}

type v2Transport interface {
	Do(context.Context, v2Request) (*v2Response, error)
}

// v2ResolutionRetirer is optional. Test transports do not need to model DNS or
// connection pools. The operation layer calls it only before
// rebuilding an idempotent request with fresh authorization nonces.
type v2ResolutionRetirer interface {
	retireV2Resolution(origin string)
}

type v2TransportOptions struct {
	DOHURL       string
	ECHMode      string
	CABundle     string
	ConnectTo    string
	DOHBootstrap []netip.Addr
	Timeout      time.Duration
	// Configuration layers behind the target origin and the ECH mode. They
	// never affect a decision; they only let a resolution failure name the
	// setting to correct. Either may be empty.
	OriginSource  string
	ECHModeSource string
}

type productionV2Transport struct {
	options v2TransportOptions
	// doh and newTargetClient are the two network boundaries. Production wires
	// them to the pure-Go clients below; the tests replace them to model DNS and
	// target responses without touching a network.
	doh             *http.Client
	newTargetClient func(origin string, resolution *v2Resolution) (*http.Client, error)
	mu              sync.Mutex
	cache           map[string]v2CachedResolution
	targets         map[string]v2CachedTarget
}

type v2CachedResolution struct {
	resolution v2Resolution
	expiresAt  time.Time
}

type v2CachedTarget struct {
	client    *http.Client
	expiresAt time.Time
}

type v2Resolution struct {
	Addresses []netip.Addr
	ECHConfig []byte
	TTL       time.Duration
}

func newProductionV2Transport(options v2TransportOptions) (*productionV2Transport, error) {
	if options.ConnectTo != "" {
		return nil, errors.New("DUD_CONNECT_TO is forbidden by the native transport; use the injected test transport")
	}
	if options.ECHMode != "hard" && options.ECHMode != "off" {
		return nil, errors.New("DUD_ECH_MODE must be either 'hard' or 'off'")
	}
	doh, err := canonicalV2DOHURL(options.DOHURL)
	if err != nil {
		return nil, fmt.Errorf("invalid v2 DoH endpoint: %w", err)
	}
	options.DOHURL = doh
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	for _, address := range options.DOHBootstrap {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("invalid pinned DoH bootstrap address %q", address)
		}
	}
	dohClient, err := newV2DOHClient(options)
	if err != nil {
		return nil, err
	}
	transport := &productionV2Transport{
		options: options,
		doh:     dohClient,
		cache:   map[string]v2CachedResolution{},
		targets: map[string]v2CachedTarget{},
	}
	transport.newTargetClient = transport.newV2TargetClient
	return transport, nil
}

func newV2DOHClient(options v2TransportOptions) (*http.Client, error) {
	parsed, err := url.Parse(options.DOHURL)
	if err != nil {
		return nil, err
	}
	config, err := newV2TLSConfig(options.CABundle, parsed.Hostname(), nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       config,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   v2TLSHandshakeTimeout,
		ResponseHeaderTimeout: v2ResponseHeaderTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   2,
	}
	if len(options.DOHBootstrap) != 0 {
		addresses := append([]netip.Addr(nil), options.DOHBootstrap...)
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		var next atomic.Uint32
		dialer := &net.Dialer{Timeout: v2ConnectTimeout}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			address := addresses[int(next.Add(1)-1)%len(addresses)]
			return dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		}
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: options.Timeout}, nil
}

func newV2TLSConfig(caBundle, serverName string, echConfig []byte) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: serverName, EncryptedClientHelloConfigList: append([]byte(nil), echConfig...)}
	if caBundle == "" {
		return config, nil
	}
	bytes, err := os.ReadFile(caBundle)
	if err != nil {
		return nil, fmt.Errorf("read v2 CA bundle: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(bytes) {
		return nil, errors.New("v2 CA bundle contains no certificates")
	}
	config.RootCAs = pool
	return config, nil
}

func canonicalV2DOHURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("DoH URL must not contain userinfo, query, or fragment")
	}
	originInput := parsed.Scheme + "://" + parsed.Host
	origin, err := canonicalV2Origin(originInput)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = "/dns-query"
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(strings.ToLower(path), "%2f") {
		return "", errors.New("DoH URL path is not canonical")
	}
	return origin + path, nil
}

func (transport *productionV2Transport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	origin, err := validateV2Request(request)
	if err != nil {
		return nil, err
	}

	// Resolution is a control-plane step even for a streamed transfer, so it
	// keeps the whole-operation timeout regardless of what follows.
	resolveCtx, cancelResolve := context.WithTimeout(ctx, transport.options.Timeout)
	defer cancelResolve()
	resolution, err := transport.resolveTarget(resolveCtx, origin)
	if err != nil {
		return nil, err
	}
	if transport.options.ECHMode == "hard" && len(resolution.ECHConfig) == 0 {
		return nil, fmt.Errorf(
			"ECH hard mode requires a valid ECHConfigList from HTTPS DNS, and %s supplied none%s",
			v2OriginHost(origin),
			transport.provenance(),
		)
	}

	streaming := request.BodyStream != nil || request.StreamResponse
	var callCtx context.Context
	var cancel context.CancelFunc
	if streaming {
		callCtx, cancel = context.WithCancel(ctx)
	} else {
		callCtx, cancel = context.WithTimeout(ctx, transport.options.Timeout)
	}
	response, err := transport.doTarget(callCtx, cancel, request, origin, resolution)
	// A streamed response owns its cancel function until it is closed.
	if err != nil || response.Stream == nil {
		cancel()
	}
	return response, err
}

func validateV2Request(request v2Request) (string, error) {
	if request.Method == "" || request.Method != strings.ToUpper(request.Method) ||
		strings.ContainsAny(request.Method, " \t\r\n") {
		return "", errors.New("v2 request method must be a non-empty uppercase HTTP token")
	}
	origin, err := canonicalV2Origin(request.Origin)
	if err != nil {
		return "", err
	}
	if request.Origin != origin {
		return "", fmt.Errorf("v2 request origin must already be canonical: use %s", origin)
	}
	if request.Path == "" || request.Path[0] != '/' {
		return "", errors.New("v2 request path must start with '/'")
	}
	if parsed, err := url.ParseRequestURI(request.Path); err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return "", errors.New("v2 request path must be an origin-relative URI without a fragment")
	} else if parsed.RawQuery != "" {
		return "", errors.New("v2 request path must not contain a query")
	}
	if request.BodyStream != nil {
		if request.Body != nil {
			return "", errors.New("v2 request carries both a bounded and a streaming body")
		}
		if request.ContentLength < 0 {
			return "", errors.New("v2 streaming request requires a non-negative ContentLength")
		}
	} else if request.ContentLength != 0 {
		return "", errors.New("v2 request ContentLength applies only to a streaming body")
	}
	return origin, nil
}

func (transport *productionV2Transport) targetClient(origin string, resolution *v2Resolution) (*http.Client, error) {
	transport.mu.Lock()
	cached, found := transport.targets[origin]
	transport.mu.Unlock()
	if found && time.Now().Before(cached.expiresAt) {
		return cached.client, nil
	}
	if found {
		transport.retireTargetClient(origin)
	}
	client, err := transport.newTargetClient(origin, resolution)
	if err != nil {
		return nil, err
	}
	if resolution.TTL > 0 {
		transport.mu.Lock()
		if transport.targets == nil {
			transport.targets = map[string]v2CachedTarget{}
		}
		transport.targets[origin] = v2CachedTarget{client: client, expiresAt: time.Now().Add(resolution.TTL)}
		transport.mu.Unlock()
	}
	return client, nil
}

func (transport *productionV2Transport) doTarget(
	ctx context.Context,
	cancel context.CancelFunc,
	request v2Request,
	origin string,
	resolution *v2Resolution,
) (*v2Response, error) {
	// Headers are checked before anything is constructed, so a rejected header
	// cannot leave a client, a guard, or a partly consumed body behind.
	for name, values := range request.Headers {
		if strings.EqualFold(name, "Host") {
			return nil, errors.New("v2 requests cannot override the Host header")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("invalid newline in v2 header %q", name)
			}
		}
	}
	client, err := transport.targetClient(origin, resolution)
	if err != nil {
		return nil, err
	}

	var guard *v2ProgressGuard
	body := io.Reader(bytes.NewReader(request.Body))
	if request.BodyStream != nil {
		guard = newV2ProgressGuard(v2StreamIdleTimeout, cancel)
		body = &v2ProgressReader{reader: request.BodyStream, guard: guard}
	} else if request.StreamResponse {
		guard = newV2ProgressGuard(v2StreamIdleTimeout, cancel)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, origin+request.Path, body)
	if err != nil {
		if guard != nil {
			guard.stop()
		}
		return nil, err
	}
	if request.BodyStream != nil {
		httpRequest.ContentLength = request.ContentLength
		if request.ContentLength == 0 {
			httpRequest.Body = http.NoBody
		}
	}
	for name, values := range request.Headers {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}

	response, err := client.Do(httpRequest)
	if err != nil {
		if guard != nil {
			guard.stop()
			transport.retireTargetClient(origin)
		}
		return nil, fmt.Errorf("v2 request failed: %w", err)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		if guard != nil {
			guard.stop()
		}
		return nil, fmt.Errorf("v2 transport rejected HTTP redirect status %d", response.StatusCode)
	}

	result := &v2Response{
		StatusCode:  response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		TLS:         v2ConnectionInfoFrom(response.TLS, resolution.ECHConfig),
	}
	if request.StreamResponse {
		result.Stream = &v2StreamBody{
			reader: response.Body,
			guard:  guard,
			cancel: cancel,
			onFailure: func() {
				transport.retireTargetClient(origin)
			},
		}
		return result, nil
	}

	defer response.Body.Close()
	if guard != nil {
		defer guard.stop()
	}
	limit := request.MaxResponseBytes
	if limit == 0 {
		limit = v2DefaultBodyLimit
	}
	result.Body, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		if guard != nil {
			transport.retireTargetClient(origin)
		}
		return nil, err
	}
	if int64(len(result.Body)) > limit {
		return nil, errors.New("v2 response exceeds the configured limit")
	}
	return result, nil
}

func v2ConnectionInfoFrom(state *tls.ConnectionState, echConfig []byte) *v2ConnectionInfo {
	if state == nil {
		return nil
	}
	info := &v2ConnectionInfo{
		Version:            state.Version,
		CipherSuite:        state.CipherSuite,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
		ECHAccepted:        state.ECHAccepted,
	}
	if state.ECHAccepted {
		info.ECHPublicName = v2ECHPublicName(echConfig)
	}
	return info
}

// v2ProgressGuard turns a whole-request timeout into an idle-progress
// deadline: a transfer may run for as long as it keeps moving bytes, and only
// a stall longer than the idle window cancels it.
type v2ProgressGuard struct {
	idle  time.Duration
	mu    sync.Mutex
	timer *time.Timer
	done  bool
}

func newV2ProgressGuard(idle time.Duration, cancel context.CancelFunc) *v2ProgressGuard {
	return &v2ProgressGuard{idle: idle, timer: time.AfterFunc(idle, cancel)}
}

func (guard *v2ProgressGuard) progressed() {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if !guard.done {
		guard.timer.Reset(guard.idle)
	}
}

func (guard *v2ProgressGuard) stop() {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.done = true
	guard.timer.Stop()
}

type v2ProgressReader struct {
	reader io.Reader
	guard  *v2ProgressGuard
}

func (reader *v2ProgressReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		reader.guard.progressed()
	}
	return count, err
}

// v2StreamBody hands the response body to the caller while keeping the
// request alive. Closing it releases the request context; a read that fails
// short of EOF also retires the pooled connection that produced it.
type v2StreamBody struct {
	reader    io.ReadCloser
	guard     *v2ProgressGuard
	cancel    context.CancelFunc
	onFailure func()
	failed    sync.Once
	closed    sync.Once
}

func (body *v2StreamBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	if count > 0 {
		body.guard.progressed()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		body.failed.Do(body.onFailure)
	}
	return count, err
}

func (body *v2StreamBody) Close() error {
	err := body.reader.Close()
	body.closed.Do(func() {
		body.guard.stop()
		body.cancel()
	})
	return err
}

func (transport *productionV2Transport) newV2TargetClient(origin string, resolution *v2Resolution) (*http.Client, error) {
	parsed, _ := url.Parse(origin)
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	addresses := append([]netip.Addr(nil), resolution.Addresses...)
	var next atomic.Uint32
	dialer := &net.Dialer{Timeout: v2ConnectTimeout}
	tlsConfig, err := newV2TLSConfig(transport.options.CABundle, parsed.Hostname(), resolution.ECHConfig)
	if err != nil {
		return nil, err
	}
	clientTransport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if len(addresses) == 0 {
				return nil, errors.New("validated target address set is empty")
			}
			address := addresses[int(next.Add(1)-1)%len(addresses)]
			return dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		},
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   v2TLSHandshakeTimeout,
		ResponseHeaderTimeout: v2ResponseHeaderTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
	return &http.Client{Transport: clientTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// v2OriginHost returns the hostname of an already-canonical origin.
func v2OriginHost(origin string) string {
	parsed, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	return parsed.Hostname()
}

func (transport *productionV2Transport) provenance() string {
	return v2NetworkProvenance(transport.options.OriginSource, transport.options.ECHModeSource)
}

func (transport *productionV2Transport) resolveTarget(ctx context.Context, origin string) (*v2Resolution, error) {
	transport.mu.Lock()
	cached, found := transport.cache[origin]
	transport.mu.Unlock()
	if found && time.Now().Before(cached.expiresAt) {
		return cloneV2Resolution(cached.resolution), nil
	}
	if found {
		transport.retireTargetClient(origin)
	}
	host := v2OriginHost(origin)
	httpsRecord, err := transport.resolveHTTPS(ctx, host, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}
	addressHost := host
	var echConfig []byte
	var ttl time.Duration
	if httpsRecord != nil {
		addressHost = httpsRecord.target
		echConfig = httpsRecord.ech
		ttl = httpsRecord.ttl
	}
	if transport.options.ECHMode == "hard" {
		if len(echConfig) == 0 {
			return nil, fmt.Errorf(
				"ECH hard mode requires an HTTPS DNS record with ECH, and %s published none%s",
				host,
				transport.provenance(),
			)
		}
		if err := validateECHConfigList(echConfig); err != nil {
			return nil, fmt.Errorf("invalid ECHConfigList: %w", err)
		}
	}
	addresses, addressTTL, err := transport.resolveAddresses(ctx, addressHost, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if reason := forbiddenV2Address(address); reason != "" {
			return nil, fmt.Errorf("v2 target resolution returned forbidden address %s (%s)", address, reason)
		}
	}
	if ttl == 0 || addressTTL < ttl {
		ttl = addressTTL
	}
	resolution := v2Resolution{Addresses: addresses, ECHConfig: echConfig, TTL: ttl}
	if ttl > 0 {
		transport.mu.Lock()
		if transport.cache == nil {
			transport.cache = map[string]v2CachedResolution{}
		}
		transport.cache[origin] = v2CachedResolution{resolution: *cloneV2Resolution(resolution), expiresAt: time.Now().Add(ttl)}
		transport.mu.Unlock()
	}
	return cloneV2Resolution(resolution), nil
}

func (transport *productionV2Transport) retireTargetClient(origin string) {
	transport.mu.Lock()
	cached, found := transport.targets[origin]
	if found {
		delete(transport.targets, origin)
	}
	transport.mu.Unlock()
	if found && cached.client != nil {
		cached.client.CloseIdleConnections()
	}
}

// retireV2Resolution discards both the validated address/ECH cache and its
// dependent HTTP/2 pool. A retry must re-run the complete DoH validation
// rather than reusing a connection which may have caused an ambiguous result.
func (transport *productionV2Transport) retireV2Resolution(origin string) {
	transport.mu.Lock()
	delete(transport.cache, origin)
	transport.mu.Unlock()
	transport.retireTargetClient(origin)
}

func cloneV2Resolution(value v2Resolution) *v2Resolution {
	return &v2Resolution{Addresses: append([]netip.Addr(nil), value.Addresses...), ECHConfig: append([]byte(nil), value.ECHConfig...), TTL: value.TTL}
}

type v2HTTPSRecord struct {
	priority uint16
	target   string
	ech      []byte
	ttl      time.Duration
}

func (transport *productionV2Transport) resolveHTTPS(ctx context.Context, host string, depth int, seen map[string]bool) (*v2HTTPSRecord, error) {
	if depth >= 8 || seen[host] {
		return nil, errors.New("HTTPS DNS alias chain is cyclic or exceeds 8 records")
	}
	seen[host] = true
	response, err := transport.dohQuery(ctx, host, dnsmessage.TypeHTTPS)
	if err != nil {
		return nil, err
	}
	var services []v2HTTPSRecord
	var aliases []string
	for _, answer := range response.answers {
		if answer.Header.Class != dnsmessage.ClassINET ||
			trimDNSName(answer.Header.Name.String()) != host {
			return nil, errors.New("HTTPS DNS response contains an answer for an unexpected name")
		}
		switch resource := answer.Body.(type) {
		case *dnsmessage.CNAMEResource:
			aliases = append(aliases, trimDNSName(resource.CNAME.String()))
			continue
		case *dnsmessage.HTTPSResource:
			if resource.Priority == 0 {
				aliases = append(aliases, trimDNSName(resource.Target.String()))
				continue
			}
			target := trimDNSName(resource.Target.String())
			if target == "" {
				target = host
			}
			ech, _ := resource.GetParam(dnsmessage.SVCParamECH)
			services = append(services, v2HTTPSRecord{
				priority: resource.Priority,
				target:   target,
				ech:      append([]byte(nil), ech...),
				ttl:      time.Duration(answer.Header.TTL) * time.Second,
			})
		default:
			return nil, errors.New("HTTPS DNS response contains an unexpected answer type")
		}
	}
	if len(services) == 0 {
		if len(aliases) == 0 {
			return nil, nil
		}
		sort.Strings(aliases)
		if aliases[0] == "" {
			return nil, errors.New("HTTPS DNS alias target is empty")
		}
		for _, alias := range aliases[1:] {
			if alias != aliases[0] {
				return nil, errors.New("HTTPS DNS response contains ambiguous aliases")
			}
		}
		return transport.resolveHTTPS(ctx, aliases[0], depth+1, seen)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].priority < services[j].priority })
	selected := services[0]
	for _, service := range services[1:] {
		if service.priority != selected.priority {
			break
		}
		if service.target != selected.target || !bytes.Equal(service.ech, selected.ech) {
			return nil, errors.New("HTTPS DNS response contains ambiguous service records")
		}
		if service.ttl < selected.ttl {
			selected.ttl = service.ttl
		}
	}
	return &selected, nil
}

func (transport *productionV2Transport) resolveAddresses(ctx context.Context, host string, depth int, seen map[string]bool) ([]netip.Addr, time.Duration, error) {
	if depth >= 8 || seen[host] {
		return nil, 0, errors.New("address DNS alias chain is cyclic or exceeds 8 records")
	}
	seen[host] = true
	var addresses []netip.Addr
	var aliases []string
	var ttl time.Duration
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		response, err := transport.dohQuery(ctx, host, qtype)
		if err != nil {
			return nil, 0, err
		}
		cnameTargets := map[string]string{}
		for _, answer := range response.answers {
			if answer.Header.Class != dnsmessage.ClassINET {
				return nil, 0, errors.New("address DNS response contains a non-IN answer")
			}
			if resource, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
				owner := trimDNSName(answer.Header.Name.String())
				target := trimDNSName(resource.CNAME.String())
				if prior, exists := cnameTargets[owner]; exists && prior != target {
					return nil, 0, errors.New("DNS response contains ambiguous CNAME targets")
				}
				cnameTargets[owner] = target
			}
		}
		allowedNames := map[string]bool{host: true}
		current := host
		for hops := 0; hops < 8; hops++ {
			target, exists := cnameTargets[current]
			if !exists {
				break
			}
			if target == "" || allowedNames[target] {
				return nil, 0, errors.New("DNS response contains an invalid CNAME chain")
			}
			allowedNames[target] = true
			aliases = append(aliases, target)
			current = target
		}
		for _, answer := range response.answers {
			if !allowedNames[trimDNSName(answer.Header.Name.String())] {
				return nil, 0, errors.New("address DNS response contains an answer for an unexpected name")
			}
			switch resource := answer.Body.(type) {
			case *dnsmessage.AResource:
				if qtype != dnsmessage.TypeA {
					return nil, 0, errors.New("address DNS response contains an unexpected A answer")
				}
				addresses = append(addresses, netip.AddrFrom4(resource.A))
			case *dnsmessage.AAAAResource:
				if qtype != dnsmessage.TypeAAAA {
					return nil, 0, errors.New("address DNS response contains an unexpected AAAA answer")
				}
				addresses = append(addresses, netip.AddrFrom16(resource.AAAA))
			case *dnsmessage.CNAMEResource:
				// Already validated above.
			default:
				return nil, 0, errors.New("address DNS response contains an unexpected answer type")
			}
			candidate := time.Duration(answer.Header.TTL) * time.Second
			if ttl == 0 || candidate < ttl {
				ttl = candidate
			}
		}
	}
	if len(addresses) == 0 && len(aliases) != 0 {
		sort.Strings(aliases)
		for _, alias := range aliases[1:] {
			if alias != aliases[0] {
				return nil, 0, errors.New("DNS response contains ambiguous CNAME targets")
			}
		}
		return transport.resolveAddresses(ctx, aliases[0], depth+1, seen)
	}
	if len(addresses) == 0 {
		return nil, 0, fmt.Errorf("DoH returned no A or AAAA addresses for %s", host)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	addresses = compactAddresses(addresses)
	return addresses, ttl, nil
}

type v2DNSResponse struct {
	answers []dnsmessage.Resource
}

func (transport *productionV2Transport) dohQuery(ctx context.Context, host string, qtype dnsmessage.Type) (*v2DNSResponse, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid DNS query name %q: %w", host, err)
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	wire, err := builder.Finish()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, transport.options.DOHURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := transport.doh.Do(request)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH query returned HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, v2DNSResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) > v2DNSResponseLimit {
		return nil, errors.New("DoH response exceeds the configured limit")
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(body)
	if err != nil {
		return nil, fmt.Errorf("parse DoH response: %w", err)
	}
	if header.ID != id || !header.Response || header.Truncated || header.RCode != dnsmessage.RCodeSuccess {
		return nil, errors.New("DoH response header does not match the bounded query")
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0] != question {
		return nil, errors.New("DoH response question does not match the query")
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, fmt.Errorf("parse DoH answers: %w", err)
	}
	return &v2DNSResponse{answers: answers}, nil
}

func validateECHConfigList(value []byte) error {
	if len(value) < 6 {
		return errors.New("ECHConfigList is too short")
	}
	if int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
		return errors.New("ECHConfigList outer length is inconsistent")
	}
	remaining := value[2:]
	configs := 0
	supported := 0
	for len(remaining) != 0 {
		if len(remaining) < 4 {
			return errors.New("ECHConfig header is truncated")
		}
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length == 0 || len(remaining) < 4+length {
			return errors.New("ECHConfig body length is inconsistent")
		}
		if binary.BigEndian.Uint16(remaining[:2]) == v2ECHConfigVersion {
			supported++
		}
		remaining = remaining[4+length:]
		configs++
	}
	if configs == 0 {
		return errors.New("ECHConfigList contains no configurations")
	}
	// A list carrying only versions this client cannot use is invalid, not
	// merely unsupported: hard mode must fail here rather than at the
	// handshake, where the failure looks like a network fault.
	if supported == 0 {
		return errors.New("ECHConfigList contains no supported ECH version")
	}
	return nil
}

// v2ECHPublicName returns the public_name of the first supported ECHConfig in
// a list crypto/tls has already accepted. The public name is what appears in
// the outer ClientHello SNI, so reporting it needs no packet capture and no
// trace parsing: it is a property of the configuration the handshake used.
func v2ECHPublicName(configList []byte) string {
	if len(configList) < 2 || int(binary.BigEndian.Uint16(configList[:2])) != len(configList)-2 {
		return ""
	}
	remaining := configList[2:]
	for len(remaining) >= 4 {
		version := binary.BigEndian.Uint16(remaining[:2])
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length == 0 || len(remaining) < 4+length {
			return ""
		}
		contents := remaining[4 : 4+length]
		remaining = remaining[4+length:]
		if version != v2ECHConfigVersion {
			continue
		}
		// HpkeKeyConfig: config_id(1) kem_id(2) public_key<2> cipher_suites<2>.
		cursor := 3
		for _, width := range []int{2, 2} {
			if len(contents) < cursor+width {
				return ""
			}
			cursor += width + int(binary.BigEndian.Uint16(contents[cursor:cursor+width]))
		}
		// maximum_name_length(1) then public_name<1>.
		if len(contents) < cursor+2 {
			return ""
		}
		cursor++
		size := int(contents[cursor])
		cursor++
		if len(contents) < cursor+size {
			return ""
		}
		return string(contents[cursor : cursor+size])
	}
	return ""
}

func forbiddenV2Address(address netip.Addr) string {
	classified := address.Unmap()
	if classified.IsUnspecified() {
		return "unspecified"
	}
	if classified.IsLoopback() {
		return "loopback"
	}
	if classified.IsPrivate() {
		return "private"
	}
	if classified.IsLinkLocalUnicast() || classified.IsLinkLocalMulticast() {
		return "link-local"
	}
	if classified.IsMulticast() {
		return "multicast"
	}
	if !classified.IsGlobalUnicast() {
		return "non-global"
	}
	for _, prefix := range forbiddenV2Prefixes {
		if prefix.Contains(classified) {
			return "reserved"
		}
	}
	return ""
}

var forbiddenV2Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func compactAddresses(addresses []netip.Addr) []netip.Addr {
	if len(addresses) < 2 {
		return addresses
	}
	result := addresses[:1]
	for _, address := range addresses[1:] {
		if address != result[len(result)-1] {
			result = append(result, address)
		}
	}
	return result
}

func trimDNSName(name string) string {
	if name == "." {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
