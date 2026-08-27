// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestV2TransportHardModeUsesValidatedDoHAddressesAndECH(t *testing.T) {
	mock := &v2NetworkMock{
		address: netip.MustParseAddr("93.184.216.34"),
		ech:     testECHConfigList(),
		status:  204,
	}
	transport := testProductionV2Transport(t, "hard", mock)
	response, err := transport.Do(context.Background(), v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 204 {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if len(mock.targets) != 1 {
		t.Fatalf("target clients built = %d, want 1", len(mock.targets))
	}
	built := mock.targets[0]
	if built.origin != "https://dud.example.com" {
		t.Fatalf("target origin = %q", built.origin)
	}
	if len(built.resolution.Addresses) != 1 ||
		built.resolution.Addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("target addresses = %v, want only the validated answer", built.resolution.Addresses)
	}
	if !bytes.Equal(built.resolution.ECHConfig, mock.ech) {
		t.Fatalf("target ECHConfigList = %x, want the one from HTTPS DNS", built.resolution.ECHConfig)
	}

	// The client the transport would really have built must pin TLS 1.3, carry
	// the ECHConfigList, and refuse to consult the system resolver.
	client, err := transport.newV2TargetClient(built.origin, &built.resolution)
	if err != nil {
		t.Fatal(err)
	}
	assertV2TargetClientIsSealed(t, client, built.resolution.ECHConfig)
}

func TestV2TransportHardModeRejectsMissingECHBeforeTargetRequest(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), status: 200}
	transport := testProductionV2Transport(t, "hard", mock)
	_, err := transport.Do(context.Background(), v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	})
	if err == nil || !strings.Contains(err.Error(), "ECH") {
		t.Fatalf("missing ECH error = %v", err)
	}
	if len(mock.targets) != 0 {
		t.Fatal("a target client was built before ECH validation")
	}
}

func TestV2TransportCachesValidatedResolutionUntilTTL(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), ech: testECHConfigList(), status: 200}
	transport := testProductionV2Transport(t, "hard", mock)
	request := v2Request{Method: "GET", Origin: "https://dud.example.com", Path: "/v2/capabilities"}
	if _, err := transport.Do(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Do(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if mock.dohQueries != 3 {
		t.Fatalf("DoH queries = %d, want 3 (HTTPS, A, AAAA once)", mock.dohQueries)
	}
}

func TestV2TransportOffPreservesOtherControls(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), status: 200}
	transport := testProductionV2Transport(t, "off", mock)
	if _, err := transport.Do(context.Background(), v2Request{
		Method: "HEAD",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	}); err != nil {
		t.Fatal(err)
	}
	if len(mock.targets) != 1 {
		t.Fatalf("target clients built = %d, want 1", len(mock.targets))
	}
	built := mock.targets[0]
	if len(built.resolution.ECHConfig) != 0 {
		t.Fatalf("off mode still supplied an ECHConfigList: %x", built.resolution.ECHConfig)
	}
	// Every other control survives: still only validated addresses, still TLS 1.3.
	if len(built.resolution.Addresses) != 1 {
		t.Fatalf("off mode changed the validated address set: %v", built.resolution.Addresses)
	}
	client, err := transport.newV2TargetClient(built.origin, &built.resolution)
	if err != nil {
		t.Fatal(err)
	}
	assertV2TargetClientIsSealed(t, client, nil)
}

func TestV2TransportRejectsForbiddenOrMixedResolution(t *testing.T) {
	for _, address := range []string{
		"0.1.2.3",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"192.0.2.1",
		"::ffff:127.0.0.1",
		"64:ff9b::7f00:1",
		"2001:db8::1",
	} {
		t.Run(address, func(t *testing.T) {
			mock := &v2NetworkMock{address: netip.MustParseAddr(address), ech: testECHConfigList(), status: 200}
			transport := testProductionV2Transport(t, "hard", mock)
			_, err := transport.Do(context.Background(), v2Request{
				Method: "GET",
				Origin: "https://dud.example.com",
				Path:   "/v2/capabilities",
			})
			if err == nil || !strings.Contains(err.Error(), "forbidden address") {
				t.Fatalf("address %s error = %v", address, err)
			}
			if len(mock.targets) != 0 {
				t.Fatal("target client built for a forbidden address")
			}
		})
	}
}

func TestV2TransportRejectsConnectToAndRedirects(t *testing.T) {
	if _, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:    "https://dns.google/dns-query",
		ECHMode:   "hard",
		ConnectTo: "dud.example.com:443:127.0.0.1:8443",
	}); err == nil {
		t.Fatal("DUD_CONNECT_TO accepted for production v2")
	}
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), ech: testECHConfigList(), status: 302}
	transport := testProductionV2Transport(t, "hard", mock)
	_, err := transport.Do(context.Background(), v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestV2TransportRejectsQueryComponents(t *testing.T) {
	transport := testProductionV2Transport(t, "off", &v2NetworkMock{})
	_, err := transport.Do(context.Background(), v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities?debug=1",
	})
	if err == nil || !strings.Contains(err.Error(), "must not contain a query") {
		t.Fatalf("query rejection error = %v", err)
	}
}

func TestV2TransportPinnedDoHBootstrapNeverFallsBack(t *testing.T) {
	// A real listener stands in for the pinned resolver address. Handing the
	// dialer a name that could only resolve through the system resolver and
	// still landing on the listener proves the pin wins.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:       fmt.Sprintf("https://dns.google:%d/dns-query", port),
		ECHMode:      "hard",
		DOHBootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	dohTransport := transport.doh.Transport.(*http.Transport)
	if dohTransport.DialContext == nil {
		t.Fatal("a pinned DoH bootstrap still dials through the system resolver")
	}
	connection, err := dohTransport.DialContext(
		context.Background(), "tcp", "name.that.must.never.resolve.invalid:443")
	if err != nil {
		t.Fatalf("dial did not reach the pinned address: %v", err)
	}
	defer connection.Close()
	if got := connection.RemoteAddr().String(); got != listener.Addr().String() {
		t.Fatalf("dialled %s, want the pinned %s", got, listener.Addr())
	}

	// Without a pin the resolver hostname is left to the system
	// bootstrap; nothing else may be.
	unpinned, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:  "https://dns.google/dns-query",
		ECHMode: "hard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if unpinned.doh.Transport.(*http.Transport).DialContext != nil {
		t.Fatal("an unpinned DoH client installed an unexpected dialer")
	}
}

// The host in this failure is often one the reader never typed: a dead drop
// command with no DUD_BASE_URL falls back to the compiled default, and a peer
// command reads an origin pinned in the profile. Naming the host alone would
// still leave them hunting for which setting produced it.
func TestV2TransportHardModeECHFailureNamesTheHostAndItsSource(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), status: 200}
	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:        "https://dns.google/dns-query",
		ECHMode:       "hard",
		OriginSource:  v2NetworkSourceDefault,
		ECHModeSource: v2NetworkSourceEnvironment,
	})
	if err != nil {
		t.Fatal(err)
	}
	mock.install(transport)
	_, err = transport.Do(context.Background(), v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	})
	if err == nil {
		t.Fatal("hard mode accepted a target that published no ECH")
	}
	for _, want := range []string{
		"dud.example.com",
		"target from the compiled default",
		"ECH mode from DUD_ECH_MODE",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestV2CodeHasOneProductionNetworkBoundary(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	dir := filepath.Dir(source)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "v2_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if name == "v2_transport.go" {
			continue
		}
		for _, forbidden := range []string{
			"exec.Command",
			"http.Client",
			"http.Get(",
			"http.NewRequest",
			"net.Dial",
			"tls.Dial",
			"runSecureCurl",
		} {
			// Git peer sync invokes only the configured local Git binary. Keep
			// every network-specific primitive forbidden in that file while
			// allowing its isolated parser and quarantine subprocesses.
			if name == "v2_git.go" && forbidden == "exec.Command" {
				continue
			}
			if strings.Contains(text, forbidden) {
				t.Errorf("%s bypasses the mandatory v2 transport helper with %q", name, forbidden)
			}
		}
	}
}

// v2TransportUsesNoSubprocess guards the property this package traded curl for:
// the v2 transport reaches the network only through the Go standard library.
func TestV2TransportUsesNoSubprocess(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "v2_transport.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"exec.Command", "os/exec", "curl"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("v2_transport.go reintroduced an external process with %q", forbidden)
		}
	}
}

func assertV2TargetClientIsSealed(t *testing.T, client *http.Client, ech []byte) {
	t.Helper()
	clientTransport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("target client does not use *http.Transport")
	}
	if clientTransport.Proxy != nil {
		t.Fatal("the target client would follow a proxy from the environment")
	}
	if clientTransport.DialContext == nil {
		t.Fatal("the target client dials through Go's default resolver")
	}
	config := clientTransport.TLSClientConfig
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %d..%d", config.MinVersion, config.MaxVersion)
	}
	if config.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled")
	}
	if !bytes.Equal(config.EncryptedClientHelloConfigList, ech) {
		t.Fatalf("ECHConfigList = %x, want %x", config.EncryptedClientHelloConfigList, ech)
	}
	if client.CheckRedirect == nil {
		t.Fatal("the target client would follow redirects")
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

func testProductionV2Transport(t *testing.T, mode string, mock *v2NetworkMock) *productionV2Transport {
	t.Helper()
	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:  "https://dns.google/dns-query",
		ECHMode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	mock.install(transport)
	return transport
}

// ---------------------------------------------------------------------------
// A network mock that replaces the transport's two boundaries: the DoH client
// and the per-origin target client. Nothing here touches a socket.
// ---------------------------------------------------------------------------

type v2TargetBuild struct {
	origin     string
	resolution v2Resolution
}

type v2NetworkMock struct {
	address netip.Addr
	ech     []byte
	status  int
	// targetResponse overrides the canned answer, so a test can model a
	// streamed body or a body that fails part way through.
	targetResponse func(*http.Request) (*http.Response, error)

	dohQueries int
	targets    []v2TargetBuild
	requests   []*http.Request
}

func (mock *v2NetworkMock) install(transport *productionV2Transport) {
	transport.doh = &http.Client{Transport: roundTripperFunc(mock.roundTripDOH)}
	transport.newTargetClient = func(origin string, resolution *v2Resolution) (*http.Client, error) {
		mock.targets = append(mock.targets, v2TargetBuild{origin: origin, resolution: *resolution})
		return &http.Client{
			Transport:     roundTripperFunc(mock.roundTripTarget),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}, nil
	}
}

func (mock *v2NetworkMock) roundTripDOH(request *http.Request) (*http.Response, error) {
	mock.dohQueries++
	query, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	return dnsHTTPResponse(mock.dnsResponse(query)), nil
}

func (mock *v2NetworkMock) roundTripTarget(request *http.Request) (*http.Response, error) {
	mock.requests = append(mock.requests, request)
	if mock.targetResponse != nil {
		return mock.targetResponse(request)
	}
	status := mock.status
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{v2CBORContentType}},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func dnsHTTPResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func (mock *v2NetworkMock) dnsResponse(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		panic(err)
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		panic("invalid test DNS query")
	}
	question := questions[0]
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionAvailable: true,
	})
	if err := builder.StartQuestions(); err != nil {
		panic(err)
	}
	if err := builder.Question(question); err != nil {
		panic(err)
	}
	if err := builder.StartAnswers(); err != nil {
		panic(err)
	}
	resourceHeader := dnsmessage.ResourceHeader{
		Name:  question.Name,
		Class: dnsmessage.ClassINET,
		TTL:   300,
	}
	switch question.Type {
	case dnsmessage.TypeA:
		if mock.address.Is4() {
			resourceHeader.Type = dnsmessage.TypeA
			if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: mock.address.As4()}); err != nil {
				panic(err)
			}
		}
	case dnsmessage.TypeAAAA:
		if mock.address.Is6() {
			resourceHeader.Type = dnsmessage.TypeAAAA
			if err := builder.AAAAResource(resourceHeader, dnsmessage.AAAAResource{AAAA: mock.address.As16()}); err != nil {
				panic(err)
			}
		}
	case dnsmessage.TypeHTTPS:
		resourceHeader.Type = dnsmessage.TypeHTTPS
		record := dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
			Priority: 1,
			Target:   dnsmessage.MustNewName("."),
		}}
		if len(mock.ech) != 0 {
			record.SetParam(dnsmessage.SVCParamECH, mock.ech)
		}
		if err := builder.HTTPSResource(resourceHeader, record); err != nil {
			panic(err)
		}
	}
	response, err := builder.Finish()
	if err != nil {
		panic(err)
	}
	return response
}

func testECHConfigList() []byte {
	// Outer length 6, one config with version 0xfe0d and a two-byte body.
	return []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x02, 0x00, 0x00}
}
