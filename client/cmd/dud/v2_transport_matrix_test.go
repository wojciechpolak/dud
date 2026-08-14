// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------------------
// A scriptable DoH mock. Each query type answers from a per-test recipe, so a
// scenario can describe exactly the DNS a hostile or broken resolver returns.
// ---------------------------------------------------------------------------

type v2DNSAnswer struct {
	name     string
	ttl      uint32
	addr     netip.Addr
	cname    string
	priority uint16
	target   string
	ech      []byte
	// resourceType overrides the answer type; zero means "derive from fields".
	resourceType dnsmessage.Type
}

type v2DNSScript struct {
	// answers maps "<host>|<qtype>" to the answers that query returns.
	answers map[string][]v2DNSAnswer
	// rcode, truncated, mismatchID and mismatchQuestion inject header faults.
	rcode            dnsmessage.RCode
	truncated        bool
	mismatchID       bool
	mismatchQuestion bool
	rawBody          []byte
	queries          []string
	dohQueries       int
	targets          []v2TargetBuild
	status           int
}

func (script *v2DNSScript) key(host string, qtype dnsmessage.Type) string {
	return fmt.Sprintf("%s|%d", host, qtype)
}

func (script *v2DNSScript) set(host string, qtype dnsmessage.Type, answers ...v2DNSAnswer) *v2DNSScript {
	if script.answers == nil {
		script.answers = map[string][]v2DNSAnswer{}
	}
	script.answers[script.key(host, qtype)] = answers
	return script
}

// install replaces the transport's two network boundaries: DoH answers come
// from the script, and the target client records what it was asked to dial.
func (script *v2DNSScript) install(transport *productionV2Transport) {
	transport.doh = &http.Client{Transport: roundTripperFunc(script.roundTripDOH)}
	transport.newTargetClient = func(origin string, resolution *v2Resolution) (*http.Client, error) {
		script.targets = append(script.targets, v2TargetBuild{origin: origin, resolution: *resolution})
		return &http.Client{
			Transport:     roundTripperFunc(script.roundTripTarget),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}, nil
	}
}

func (script *v2DNSScript) roundTripDOH(request *http.Request) (*http.Response, error) {
	script.dohQueries++
	query, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	body, _, err := script.respond(query)
	if err != nil {
		return nil, err
	}
	return dnsHTTPResponse(body), nil
}

func (script *v2DNSScript) roundTripTarget(*http.Request) (*http.Response, error) {
	status := script.status
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{v2CBORContentType}},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

func (script *v2DNSScript) respond(query []byte) ([]byte, []byte, error) {
	if script.rawBody != nil {
		return script.rawBody, nil, nil
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, nil, errors.New("invalid test DNS query")
	}
	question := questions[0]
	host := trimDNSName(question.Name.String())
	script.queries = append(script.queries, script.key(host, question.Type))

	responseHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionAvailable: true,
		Truncated:          script.truncated,
		RCode:              script.rcode,
	}
	if script.mismatchID {
		responseHeader.ID = header.ID ^ 0xffff
	}
	builder := dnsmessage.NewBuilder(nil, responseHeader)
	if err := builder.StartQuestions(); err != nil {
		return nil, nil, err
	}
	echoed := question
	if script.mismatchQuestion {
		echoed.Type = dnsmessage.TypeTXT
	}
	if err := builder.Question(echoed); err != nil {
		return nil, nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, nil, err
	}
	for _, answer := range script.answers[script.key(host, question.Type)] {
		name := answer.name
		if name == "" {
			name = host
		}
		ttl := answer.ttl
		if ttl == 0 {
			ttl = 300
		}
		resourceHeader := dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name + "."),
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		}
		switch {
		case answer.resourceType == dnsmessage.TypeTXT:
			resourceHeader.Type = dnsmessage.TypeTXT
			if err := builder.TXTResource(resourceHeader, dnsmessage.TXTResource{TXT: []string{"x"}}); err != nil {
				return nil, nil, err
			}
		case answer.cname != "":
			resourceHeader.Type = dnsmessage.TypeCNAME
			if err := builder.CNAMEResource(resourceHeader, dnsmessage.CNAMEResource{
				CNAME: dnsmessage.MustNewName(answer.cname + "."),
			}); err != nil {
				return nil, nil, err
			}
		case question.Type == dnsmessage.TypeHTTPS:
			resourceHeader.Type = dnsmessage.TypeHTTPS
			target := answer.target
			if target == "" {
				target = "."
			} else {
				target += "."
			}
			record := dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
				Priority: answer.priority,
				Target:   dnsmessage.MustNewName(target),
			}}
			if len(answer.ech) != 0 {
				record.SetParam(dnsmessage.SVCParamECH, answer.ech)
			}
			if err := builder.HTTPSResource(resourceHeader, record); err != nil {
				return nil, nil, err
			}
		case answer.addr.Is4():
			resourceHeader.Type = dnsmessage.TypeA
			if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: answer.addr.As4()}); err != nil {
				return nil, nil, err
			}
		case answer.addr.Is6():
			resourceHeader.Type = dnsmessage.TypeAAAA
			if err := builder.AAAAResource(resourceHeader, dnsmessage.AAAAResource{AAAA: answer.addr.As16()}); err != nil {
				return nil, nil, err
			}
		}
	}
	body, err := builder.Finish()
	if err != nil {
		return nil, nil, err
	}
	return body, nil, nil
}

func scriptedV2Transport(t *testing.T, mode string, script *v2DNSScript) *productionV2Transport {
	t.Helper()
	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:  "https://dns.google/dns-query",
		ECHMode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	script.install(transport)
	return transport
}

func capabilitiesRequest() v2Request {
	return v2Request{
		Method: "GET",
		Origin: "https://dud.example.com",
		Path:   "/v2/capabilities",
	}
}

// A well-formed HTTPS record carrying ECH, plus one public address.
func healthyV2Script() *v2DNSScript {
	script := &v2DNSScript{}
	script.set("dud.example.com", dnsmessage.TypeHTTPS,
		v2DNSAnswer{priority: 1, ech: testECHConfigList()})
	script.set("dud.example.com", dnsmessage.TypeA,
		v2DNSAnswer{addr: netip.MustParseAddr("93.184.216.34")})
	script.set("dud.example.com", dnsmessage.TypeAAAA)
	return script
}

// ---------------------------------------------------------------------------
// Malformed DNS
// ---------------------------------------------------------------------------

func TestV2TransportRejectsMalformedDNS(t *testing.T) {
	for name, mutate := range map[string]func(*v2DNSScript){
		"truncated body":       func(s *v2DNSScript) { s.rawBody = []byte{0x00, 0x01} },
		"empty body":           func(s *v2DNSScript) { s.rawBody = []byte{} },
		"transaction ID":       func(s *v2DNSScript) { s.mismatchID = true },
		"question mismatch":    func(s *v2DNSScript) { s.mismatchQuestion = true },
		"truncation flag":      func(s *v2DNSScript) { s.truncated = true },
		"server failure rcode": func(s *v2DNSScript) { s.rcode = dnsmessage.RCodeServerFailure },
		"answer for another name": func(s *v2DNSScript) {
			s.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{name: "attacker.example", priority: 1, ech: testECHConfigList()})
		},
		"unexpected answer type": func(s *v2DNSScript) {
			s.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{resourceType: dnsmessage.TypeTXT})
		},
	} {
		t.Run(name, func(t *testing.T) {
			script := healthyV2Script()
			mutate(script)
			transport := scriptedV2Transport(t, "hard", script)
			if _, err := transport.Do(context.Background(), capabilitiesRequest()); err == nil {
				t.Fatal("malformed DNS was accepted")
			}
			if len(script.targets) != 0 {
				t.Fatalf("target client built after malformed DNS: %v", script.targets)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Alias chains and ambiguity
// ---------------------------------------------------------------------------

func TestV2TransportRejectsAliasLoopsAndAmbiguity(t *testing.T) {
	for name, build := range map[string]func() *v2DNSScript{
		"HTTPS alias points at itself": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 0, target: "dud.example.com"})
			return script
		},
		"HTTPS alias cycles through a second name": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 0, target: "alias.example"})
			script.set("alias.example", dnsmessage.TypeHTTPS,
				v2DNSAnswer{name: "alias.example", priority: 0, target: "dud.example.com"})
			return script
		},
		"HTTPS aliases disagree": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 0, target: "one.example"},
				v2DNSAnswer{priority: 0, target: "two.example"})
			return script
		},
		"service records at one priority disagree on ECH": func() *v2DNSScript {
			script := healthyV2Script()
			other := append([]byte(nil), testECHConfigList()...)
			other[len(other)-1] ^= 0x01
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 1, ech: testECHConfigList()},
				v2DNSAnswer{priority: 1, ech: other})
			return script
		},
		"service records at one priority disagree on target": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 1, target: "one.example", ech: testECHConfigList()},
				v2DNSAnswer{priority: 1, target: "two.example", ech: testECHConfigList()})
			return script
		},
		"address alias cycles": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeA,
				v2DNSAnswer{cname: "dud.example.com"})
			return script
		},
	} {
		t.Run(name, func(t *testing.T) {
			transport := scriptedV2Transport(t, "hard", build())
			_, err := transport.Do(context.Background(), capabilitiesRequest())
			if err == nil {
				t.Fatal("an ambiguous or cyclic DNS answer was accepted")
			}
			if !strings.Contains(err.Error(), "cyclic") &&
				!strings.Contains(err.Error(), "ambiguous") &&
				!strings.Contains(err.Error(), "exceeds") &&
				!strings.Contains(err.Error(), "invalid CNAME chain") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ECH
// ---------------------------------------------------------------------------

func TestV2TransportRejectsMalformedECHConfigInHardMode(t *testing.T) {
	for name, config := range map[string][]byte{
		"too short":            {0x00, 0x01},
		"inconsistent length":  {0x00, 0xff, 0xfe, 0x0d, 0x00, 0x02, 0x00, 0x00},
		"unsupported version":  {0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00},
		"empty configuration":  {0x00, 0x00},
		"body length overruns": {0x00, 0x06, 0xfe, 0x0d, 0x00, 0xff, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeHTTPS,
				v2DNSAnswer{priority: 1, ech: config})
			transport := scriptedV2Transport(t, "hard", script)
			if _, err := transport.Do(context.Background(), capabilitiesRequest()); err == nil {
				t.Fatal("a malformed ECHConfigList was accepted in hard mode")
			}
			if len(script.targets) != 0 {
				t.Fatal("target client built with an invalid ECH configuration")
			}
		})
	}
}

func TestV2TransportOffModeToleratesMissingECH(t *testing.T) {
	// `off` is the documented escape hatch: it must still resolve through DoH
	// and still pin the address, it simply stops requiring ECH.
	script := healthyV2Script()
	script.set("dud.example.com", dnsmessage.TypeHTTPS)
	transport := scriptedV2Transport(t, "off", script)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(script.targets) != 1 {
		t.Fatalf("target clients built = %d, want 1", len(script.targets))
	}
	built := script.targets[0]
	if len(built.resolution.ECHConfig) != 0 {
		t.Fatalf("off mode passed an ECH configuration: %x", built.resolution.ECHConfig)
	}
	if len(built.resolution.Addresses) != 1 ||
		built.resolution.Addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("off mode stopped pinning the validated address: %v", built.resolution.Addresses)
	}
}

func TestV2DoctorWarnsOnlyWhenECHIsOff(t *testing.T) {
	for mode, expectWarning := range map[string]bool{"off": true, "hard": false} {
		t.Run(mode, func(t *testing.T) {
			setTestV2Homes(t)
			clearV2NetworkEnvironment(t)
			if _, _, err := initializeV2Config(
				"desktop",
				"https://dud.example.com",
				"https://dns.google/dns-query",
				mode,
			); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			a := newApp(strings.NewReader(""), &stdout, &stderr)
			a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
				return &stubV2Transport{}, nil
			}
			if code := a.main([]string{"doctor"}); code != 0 {
				t.Fatalf("doctor code = %d (%s)", code, stderr.String())
			}
			warned := strings.Contains(stderr.String(), "ECH off mode")
			if warned != expectWarning {
				t.Fatalf("ECH %s warning = %v, want %v (stderr: %q)",
					mode, warned, expectWarning, stderr.String())
			}
			if expectWarning && !strings.Contains(stderr.String(), "SNI") {
				t.Fatalf("the off-mode warning does not say what leaks: %q", stderr.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address policy
// ---------------------------------------------------------------------------

func TestV2TransportRejectsMixedPublicAndPrivateAnswers(t *testing.T) {
	// A resolver that returns one routable address and one loopback address is
	// the classic rebinding setup: taking the "good" one is not safe, because
	// the connection pool would round-robin onto the other.
	for name, build := range map[string]func() *v2DNSScript{
		"public A with private AAAA": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeAAAA,
				v2DNSAnswer{addr: netip.MustParseAddr("::1")})
			return script
		},
		"two A records, one private": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeA,
				v2DNSAnswer{addr: netip.MustParseAddr("93.184.216.34")},
				v2DNSAnswer{addr: netip.MustParseAddr("169.254.169.254")})
			return script
		},
		"public A with mapped loopback AAAA": func() *v2DNSScript {
			script := healthyV2Script()
			script.set("dud.example.com", dnsmessage.TypeAAAA,
				v2DNSAnswer{addr: netip.MustParseAddr("::ffff:127.0.0.1")})
			return script
		},
	} {
		t.Run(name, func(t *testing.T) {
			script := build()
			transport := scriptedV2Transport(t, "hard", script)
			_, err := transport.Do(context.Background(), capabilitiesRequest())
			if err == nil || !strings.Contains(err.Error(), "forbidden address") {
				t.Fatalf("mixed answer error = %v", err)
			}
			if len(script.targets) != 0 {
				t.Fatal("target client built with a forbidden address in the set")
			}
		})
	}
}

func TestV2TransportRejectsRebindingAfterTheCacheExpires(t *testing.T) {
	// The first answer is routable and short-lived. Once it expires the
	// resolver flips to loopback; the cached pool must not survive to serve it.
	script := healthyV2Script()
	script.set("dud.example.com", dnsmessage.TypeHTTPS,
		v2DNSAnswer{priority: 1, ttl: 1, ech: testECHConfigList()})
	script.set("dud.example.com", dnsmessage.TypeA,
		v2DNSAnswer{ttl: 1, addr: netip.MustParseAddr("93.184.216.34")})
	transport := scriptedV2Transport(t, "hard", script)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(transport.cache) != 1 {
		t.Fatalf("validated resolution was not cached: %d entries", len(transport.cache))
	}

	script.set("dud.example.com", dnsmessage.TypeA,
		v2DNSAnswer{ttl: 1, addr: netip.MustParseAddr("127.0.0.1")})
	// Expire the entry rather than sleeping on a wall clock.
	for origin, entry := range transport.cache {
		entry.expiresAt = time.Now().Add(-time.Second)
		transport.cache[origin] = entry
	}
	script.targets = nil
	_, err := transport.Do(context.Background(), capabilitiesRequest())
	if err == nil || !strings.Contains(err.Error(), "forbidden address") {
		t.Fatalf("rebinding error = %v", err)
	}
	if len(script.targets) != 0 {
		t.Fatal("a rebound address was contacted")
	}
}

func TestV2TransportRetryReresolvesAfterRetirement(t *testing.T) {
	script := healthyV2Script()
	transport := scriptedV2Transport(t, "hard", script)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	first := len(script.queries)
	if first != 3 {
		t.Fatalf("first resolution used %d DoH queries, want 3", first)
	}
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(script.queries) != first {
		t.Fatalf("a cached resolution issued %d more queries", len(script.queries)-first)
	}

	// Retiring the resolution is what a retry does after an ambiguous failure:
	// the next request must repeat the full DoH validation and drop the pool.
	transport.retireV2Resolution("https://dud.example.com")
	if len(transport.cache) != 0 || len(transport.targets) != 0 {
		t.Fatal("retirement left the resolution or connection pool in place")
	}
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(script.queries) != first*2 {
		t.Fatalf("retry issued %d queries, want %d", len(script.queries), first*2)
	}
}

// ---------------------------------------------------------------------------
// Transport isolation
// ---------------------------------------------------------------------------

func TestV2ResolutionUsesOneDoHTransportForEveryRecordType(t *testing.T) {
	script := healthyV2Script()
	transport := scriptedV2Transport(t, "hard", script)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(script.queries) != 3 || script.dohQueries != 3 {
		t.Fatalf("resolution issued %d queries over %d exchanges, want 3 and 3",
			len(script.queries), script.dohQueries)
	}
	// HTTPS, A and AAAA share one client, so the profile cannot drift between
	// record types. Assert the profile that single client actually carries.
	production, err := newProductionV2Transport(v2TransportOptions{
		DOHURL: "https://dns.google/dns-query", ECHMode: "hard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if production.doh == nil {
		t.Fatal("the DoH client was not created once up front")
	}
	dohTransport, ok := production.doh.Transport.(*http.Transport)
	if !ok {
		t.Fatal("DoH client does not use *http.Transport")
	}
	config := dohTransport.TLSClientConfig
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("DoH TLS versions = %d..%d, want exactly TLS 1.3",
			config.MinVersion, config.MaxVersion)
	}
	if config.InsecureSkipVerify {
		t.Fatal("the DoH client skips certificate verification")
	}
	if config.ServerName != "dns.google" {
		t.Fatalf("DoH server name = %q; hostname verification would not apply", config.ServerName)
	}
	if err := production.doh.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("DoH CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	if production.doh.Timeout == 0 {
		t.Fatal("the DoH client has no overall timeout")
	}
}

func TestV2TransportIgnoresProxyEnvironmentOnBothClients(t *testing.T) {
	// Go's default transport honours HTTPS_PROXY; a proxy would see the target
	// hostname in CONNECT and could observe or redirect the DoH lookup.
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:8080")
	t.Setenv("ALL_PROXY", "socks5://proxy.invalid:1080")
	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:  "https://dns.google/dns-query",
		ECHMode: "hard",
	})
	if err != nil {
		t.Fatal(err)
	}
	dohTransport, ok := transport.doh.Transport.(*http.Transport)
	if !ok {
		t.Fatal("DoH client does not use *http.Transport")
	}
	if dohTransport.Proxy != nil {
		t.Fatal("the DoH client would follow a proxy from the environment")
	}
	client, err := transport.newV2TargetClient("https://dud.example.com", &v2Resolution{
		Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		ECHConfig: testECHConfigList(),
		TTL:       time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetTransport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("target client does not use *http.Transport")
	}
	if targetTransport.Proxy != nil {
		t.Fatal("the target client would follow a proxy from the environment")
	}
}

func TestV2TargetDialingNeverConsultsTheSystemResolver(t *testing.T) {
	// A real listener stands in for the validated address. The dialer is then
	// handed a hostname that could only resolve through the system resolver;
	// landing on the listener proves the hostname was ignored.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	transport, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:  "https://dns.google/dns-query",
		ECHMode: "hard",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := transport.newV2TargetClient(
		fmt.Sprintf("https://dud.example.com:%d", port),
		&v2Resolution{
			Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			ECHConfig: testECHConfigList(),
			TTL:       time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := client.Transport.(*http.Transport)
	if clientTransport.DialContext == nil {
		t.Fatal("target client dials through Go's default resolver")
	}
	connection, err := clientTransport.DialContext(
		context.Background(), "tcp", "name.that.must.never.resolve.invalid:443")
	if err != nil {
		t.Fatalf("dial did not reach the validated address: %v", err)
	}
	defer connection.Close()
	if got := connection.RemoteAddr().String(); got != listener.Addr().String() {
		t.Fatalf("dialled %s, want the validated %s", got, listener.Addr())
	}

	// With no validated address the dialer must refuse rather than fall back.
	empty, err := transport.newV2TargetClient(
		"https://dud.example.com", &v2Resolution{TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Transport.(*http.Transport).DialContext(
		context.Background(), "tcp", "dud.example.com:443",
	); err == nil {
		t.Fatal("an empty validated address set still dialled")
	}
}

func TestV2TLSConfigurationPinsTLS13AndVerifies(t *testing.T) {
	config, err := newV2TLSConfig("", "dud.example.com", testECHConfigList())
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %d..%d", config.MinVersion, config.MaxVersion)
	}
	if config.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled")
	}
	if config.ServerName != "dud.example.com" {
		t.Fatalf("server name = %q; hostname verification would not apply", config.ServerName)
	}
	if len(config.EncryptedClientHelloConfigList) == 0 {
		t.Fatal("ECH configuration was dropped")
	}
	// A CA bundle that contains no certificates must fail closed rather than
	// silently falling back to the system pool.
	if _, err := newV2TLSConfig("/nonexistent/ca.pem", "dud.example.com", nil); err == nil {
		t.Fatal("a missing CA bundle was accepted")
	}
}

func TestV2TransportNeverDelegatesResolutionOrFollowsRedirects(t *testing.T) {
	script := healthyV2Script()
	transport := scriptedV2Transport(t, "hard", script)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err != nil {
		t.Fatal(err)
	}
	if len(script.targets) != 1 {
		t.Fatalf("target clients built = %d, want 1", len(script.targets))
	}
	built := script.targets[0]
	client, err := transport.newV2TargetClient(built.origin, &built.resolution)
	if err != nil {
		t.Fatal(err)
	}
	assertV2TargetClientIsSealed(t, client, built.resolution.ECHConfig)

	// A redirect status is rejected outright rather than followed.
	script.status = 302
	transport.retireTargetClient(built.origin)
	if _, err := transport.Do(context.Background(), capabilitiesRequest()); err == nil ||
		!strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestV2TransportRejectsUnusableConfiguration(t *testing.T) {
	for name, options := range map[string]v2TransportOptions{
		"connect-to injection": {
			DOHURL: "https://dns.google/dns-query", ECHMode: "hard",
			ConnectTo: "dud.example.com:443:127.0.0.1:8443",
		},
		"unknown ECH mode":     {DOHURL: "https://dns.google/dns-query", ECHMode: "soft"},
		"empty ECH mode":       {DOHURL: "https://dns.google/dns-query"},
		"plaintext DoH":        {DOHURL: "http://dns.google/dns-query", ECHMode: "hard"},
		"DoH with a query":     {DOHURL: "https://dns.google/dns-query?ct", ECHMode: "hard"},
		"DoH with credentials": {DOHURL: "https://user:pass@dns.google/dns-query", ECHMode: "hard"},
		"unspecified bootstrap": {
			DOHURL: "https://dns.google/dns-query", ECHMode: "hard",
			DOHBootstrap: []netip.Addr{netip.MustParseAddr("0.0.0.0")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newProductionV2Transport(options); err == nil {
				t.Fatal("an unusable transport configuration was accepted")
			}
		})
	}
}
