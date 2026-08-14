// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Streaming is the form a 100 MB transfer needs; the bounded form stays for
// control messages. Both have to survive the same DoH resolution, address
// classification, and ECH validation the transport already enforces.

func streamingNetworkMock(status int, body func() io.ReadCloser) *v2NetworkMock {
	mock := &v2NetworkMock{
		address: netip.MustParseAddr("93.184.216.34"),
		ech:     testECHConfigList(),
	}
	mock.targetResponse = func(request *http.Request) (*http.Response, error) {
		if request.Body != nil {
			if _, err := io.Copy(io.Discard, request.Body); err != nil {
				return nil, err
			}
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
			Body:       body(),
		}, nil
	}
	return mock
}

func TestV2TransportStreamsARequestBodyWithAnExactLength(t *testing.T) {
	payload := bytes.Repeat([]byte("payload"), 4096)
	var received []byte
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), ech: testECHConfigList()}
	mock.targetResponse = func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		received = body
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	}
	transport := testProductionV2Transport(t, "hard", mock)

	response, err := transport.Do(context.Background(), v2Request{
		Method:        "POST",
		Origin:        "https://dud.example.com",
		Path:          "/v1/files",
		BodyStream:    bytes.NewReader(payload),
		ContentLength: int64(len(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(response.Body) != `{"ok":true}` {
		t.Fatalf("response = %d %q", response.StatusCode, response.Body)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("received %d bytes, sent %d", len(received), len(payload))
	}
	sent := mock.requests[0]
	if sent.ContentLength != int64(len(payload)) {
		t.Fatalf("ContentLength = %d, want %d", sent.ContentLength, len(payload))
	}
	if len(sent.TransferEncoding) != 0 {
		t.Fatalf("a streaming request was chunked: %v", sent.TransferEncoding)
	}
	// The resolution and its ECH validation still apply to a streamed request.
	if len(mock.targets) != 1 || !bytes.Equal(mock.targets[0].resolution.ECHConfig, mock.ech) {
		t.Fatalf("streaming skipped ECH validation: %#v", mock.targets)
	}
	if len(mock.targets[0].resolution.Addresses) != 1 ||
		mock.targets[0].resolution.Addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("streaming skipped address classification: %v", mock.targets[0].resolution.Addresses)
	}
}

func TestV2TransportHandsBackAStreamedResponseUnread(t *testing.T) {
	payload := bytes.Repeat([]byte("ciphertext"), 8192)
	mock := streamingNetworkMock(200, func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(payload))
	})
	transport := testProductionV2Transport(t, "hard", mock)

	response, err := transport.Do(context.Background(), v2Request{
		Method:         "GET",
		Origin:         "https://dud.example.com",
		Path:           "/v1/files/abcd",
		StreamResponse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Stream == nil {
		t.Fatal("StreamResponse returned a buffered body")
	}
	if response.Body != nil {
		t.Fatalf("a streamed response also buffered %d bytes", len(response.Body))
	}
	body, err := io.ReadAll(response.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("drained %d bytes, want %d", len(body), len(payload))
	}
}

// A streamed response must not be silently truncated by the bounded limit,
// which exists to protect control messages.
func TestV2TransportDoesNotApplyTheBoundedLimitToAStream(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), v2DefaultBodyLimit+4096)
	mock := streamingNetworkMock(200, func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(payload))
	})
	transport := testProductionV2Transport(t, "hard", mock)

	response, err := transport.Do(context.Background(), v2Request{
		Method:         "GET",
		Origin:         "https://dud.example.com",
		Path:           "/v1/files/abcd",
		StreamResponse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Stream.Close()
	count, err := io.Copy(io.Discard, response.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if count != int64(len(payload)) {
		t.Fatalf("streamed %d bytes, want %d", count, len(payload))
	}
}

func TestV2TransportKeepsTheBoundedLimitForControlMessages(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), ech: testECHConfigList()}
	mock.targetResponse = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 2048))),
		}, nil
	}
	transport := testProductionV2Transport(t, "hard", mock)

	_, err := transport.Do(context.Background(), v2Request{
		Method:           "GET",
		Origin:           "https://dud.example.com",
		Path:             "/v2/capabilities",
		MaxResponseBytes: 1024,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds the configured limit") {
		t.Fatalf("bounded limit error = %v", err)
	}
}

// A stream that dies part way through leaves an ambiguous connection behind.
// The next request must build a fresh client rather than reuse it.
type failingBody struct {
	remaining int
}

func (body *failingBody) Read(buffer []byte) (int, error) {
	if body.remaining <= 0 {
		return 0, errors.New("connection reset by peer")
	}
	count := min(len(buffer), body.remaining)
	body.remaining -= count
	return count, nil
}

func (body *failingBody) Close() error { return nil }

func TestV2TransportRetiresTheTargetClientAfterAFailedStream(t *testing.T) {
	mock := streamingNetworkMock(200, func() io.ReadCloser {
		return &failingBody{remaining: 16}
	})
	transport := testProductionV2Transport(t, "hard", mock)
	request := v2Request{
		Method:         "GET",
		Origin:         "https://dud.example.com",
		Path:           "/v1/files/abcd",
		StreamResponse: true,
	}

	response, err := transport.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Stream); err == nil {
		t.Fatal("the failing stream reported success")
	}
	response.Stream.Close()

	next, err := transport.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, next.Stream)
	next.Stream.Close()
	if len(mock.targets) != 2 {
		t.Fatalf("target clients built = %d, want a fresh one after the failed stream", len(mock.targets))
	}
	// The validated resolution itself is still cached: only the pooled
	// connection was suspect.
	if mock.dohQueries != 3 {
		t.Fatalf("DoH queries = %d, want 3 (HTTPS, A, AAAA once)", mock.dohQueries)
	}
}

func TestV2TransportRejectsContradictoryBodyForms(t *testing.T) {
	mock := &v2NetworkMock{address: netip.MustParseAddr("93.184.216.34"), ech: testECHConfigList()}
	transport := testProductionV2Transport(t, "hard", mock)
	tests := []struct {
		name    string
		request v2Request
		want    string
	}{
		{
			name: "both body forms",
			request: v2Request{
				Method: "POST", Origin: "https://dud.example.com", Path: "/v1/files",
				Body: []byte("x"), BodyStream: strings.NewReader("y"), ContentLength: 1,
			},
			want: "both a bounded and a streaming body",
		},
		{
			name: "negative length",
			request: v2Request{
				Method: "POST", Origin: "https://dud.example.com", Path: "/v1/files",
				BodyStream: strings.NewReader("y"), ContentLength: -1,
			},
			want: "non-negative ContentLength",
		},
		{
			name: "length without a stream",
			request: v2Request{
				Method: "POST", Origin: "https://dud.example.com", Path: "/v1/files",
				Body: []byte("x"), ContentLength: 1,
			},
			want: "applies only to a streaming body",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := transport.Do(context.Background(), test.request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if mock.dohQueries != 0 {
				t.Fatal("an invalid request still reached the resolver")
			}
		})
	}
}

// The idle-progress guard replaces the whole-request timeout for streams: it
// must not fire while bytes keep moving.
func TestV2ProgressGuardOnlyFiresWhenAStreamStalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fired := make(chan struct{})
	// Cancel before announcing, so a reader that observes the announcement is
	// guaranteed to see the cancellation the guard is being tested for.
	guard := newV2ProgressGuard(20*time.Millisecond, func() {
		cancel()
		close(fired)
	})

	deadline := time.Now().Add(120 * time.Millisecond)
	for time.Now().Before(deadline) {
		guard.progressed()
		time.Sleep(5 * time.Millisecond)
		select {
		case <-fired:
			t.Fatal("the guard fired while the stream was still moving")
		default:
		}
	}

	select {
	case <-fired:
		t.Fatal("the guard fired before the stall")
	default:
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("the guard never fired after the stream stalled")
	}
	if ctx.Err() == nil {
		t.Fatal("a stalled stream was not cancelled")
	}

	// A stopped guard must not cancel a request that already completed.
	guard.stop()
}
