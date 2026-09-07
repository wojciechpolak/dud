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

type v2TestProgressTicker struct {
	channel chan time.Time
}

func (ticker *v2TestProgressTicker) Chan() <-chan time.Time { return ticker.channel }
func (ticker *v2TestProgressTicker) Stop()                  {}

func newV2TestProgressReporter(output io.Writer, peer string, terminal, jsonOutput bool, flags v2ProgressFlags, now *time.Time) *v2ProgressReporter {
	return newV2ProgressReporter(v2ProgressReporterConfig{
		out: output, peer: peer, json: jsonOutput, flags: flags,
		terminal: func(io.Writer) bool { return terminal },
		now:      func() time.Time { return *now },
		newTicker: func(time.Duration) v2ProgressTicker {
			return &v2TestProgressTicker{channel: make(chan time.Time)}
		},
	})
}

func TestV2ProgressSelectionHonorsTerminalJSONAndFlags(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name     string
		terminal bool
		json     bool
		flags    v2ProgressFlags
		enabled  bool
	}{
		{name: "terminal default", terminal: true, enabled: true},
		{name: "redirected default"},
		{name: "JSON default", terminal: true, json: true},
		{name: "forced redirected", json: true, flags: v2ProgressFlags{force: true}, enabled: true},
		{name: "disabled terminal", terminal: true, flags: v2ProgressFlags{disabled: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reporter := newV2TestProgressReporter(io.Discard, "peer", test.terminal, test.json, test.flags, &now)
			if reporter.enabled != test.enabled {
				t.Fatalf("enabled = %v, want %v", reporter.enabled, test.enabled)
			}
			reporter.Stop()
		})
	}
}

func TestV2ProgressUsesModeSpecificUpdateIntervals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		terminal bool
		want     time.Duration
	}{
		{terminal: true, want: v2ProgressTerminalInterval},
		{terminal: false, want: v2ProgressNonterminalInterval},
	} {
		var got time.Duration
		reporter := newV2ProgressReporter(v2ProgressReporterConfig{
			out: io.Discard, peer: "peer", flags: v2ProgressFlags{force: true},
			terminal: func(io.Writer) bool { return test.terminal },
			now:      func() time.Time { return now },
			newTicker: func(interval time.Duration) v2ProgressTicker {
				got = interval
				return &v2TestProgressTicker{channel: make(chan time.Time)}
			},
		})
		reporter.Stop()
		if got != test.want {
			t.Fatalf("terminal %v interval = %s, want %s", test.terminal, got, test.want)
		}
	}
}

func TestV2ProgressFlagsRejectOnlyConflictingChoices(t *testing.T) {
	checks := []struct {
		name  string
		parse func([]string) error
		args  []string
	}{
		{name: "send", args: []string{"peer", "-m", "hello"}, parse: func(args []string) error { _, err := parseV2PeerSendOptions(args); return err }},
		{name: "receive", args: []string{"peer"}, parse: func(args []string) error { _, err := parseV2PeerReceiveOptions(args); return err }},
		{name: "Git push", args: []string{"peer", "--current"}, parse: func(args []string) error { _, err := parseV2GitPushOptions(args); return err }},
		{name: "Git fetch", args: []string{"peer"}, parse: func(args []string) error { _, err := parseV2GitFetchOptions(args); return err }},
	}
	for _, check := range checks {
		if err := check.parse(append(append([]string(nil), check.args...), "--progress")); err != nil {
			t.Fatalf("%s rejected --progress: %v", check.name, err)
		}
		if err := check.parse(append(append([]string(nil), check.args...), "--no-progress")); err != nil {
			t.Fatalf("%s rejected --no-progress: %v", check.name, err)
		}
		conflicting := append(append([]string(nil), check.args...), "--progress", "--no-progress")
		if err := check.parse(conflicting); err == nil {
			t.Fatalf("%s accepted conflicting progress flags", check.name)
		}
	}
	if _, err := parseV2SyncOptions([]string{"peer", "--progress", "--no-progress"}); err == nil {
		t.Fatal("sync accepted conflicting progress flags")
	}
	if opts, err := parseV2SyncOptions([]string{"peer", "--progress", "--json"}); err != nil || !opts.progress.force || !opts.json {
		t.Fatalf("sync progress options = %#v, %v", opts, err)
	}
}

func TestV2ForcedProgressUsesSafeNewlineDelimitedUpdates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var output bytes.Buffer
	reporter := newV2TestProgressReporter(&output, "peer\x1b[2J", false, false, v2ProgressFlags{force: true}, &now)
	reporter.Phase("uploading", 1_000)
	now = now.Add(2 * time.Second)
	reporter.Set(500, 1_000)
	reporter.render()
	reporter.Complete()

	text := output.String()
	if strings.ContainsAny(text, "\r\x1b") {
		t.Fatalf("redirected progress contains terminal controls: %q", text)
	}
	if !strings.Contains(text, `"peer\x1b[2J"`) || !strings.Contains(text, " 500 B/1000 B ( 50.00%)") ||
		!strings.Contains(text, "250 B/s") || !strings.Contains(text, "ETA       2s") || !strings.Contains(text, ": complete") {
		t.Fatalf("progress output = %q", text)
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if line == "" {
			t.Fatal("progress emitted an empty update")
		}
	}
}

func TestV2TerminalProgressDelaysAndClearsItsLine(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var output bytes.Buffer
	reporter := newV2TestProgressReporter(&output, "peer", true, false, v2ProgressFlags{}, &now)
	reporter.Phase("downloading", 100)
	now = now.Add(200 * time.Millisecond)
	reporter.render()
	if output.Len() != 0 {
		t.Fatalf("progress appeared before delay: %q", output.String())
	}
	now = now.Add(50 * time.Millisecond)
	reporter.Set(25, 100)
	reporter.render()
	if !strings.Contains(output.String(), "\rpeer: downloading  25 B/100 B ( 25.00%)") {
		t.Fatalf("terminal progress = %q", output.String())
	}
	reporter.Clear()
	if !strings.HasSuffix(output.String(), "\r") {
		t.Fatalf("clear did not return to the start of the line: %q", output.String())
	}
	clearedSize := output.Len()
	now = now.Add(time.Second)
	reporter.Set(50, 100)
	reporter.render()
	if output.Len() != clearedSize {
		t.Fatalf("progress redrew over foreground output: %q", output.String())
	}
	reporter.Stop()
}

func TestV2KnownTotalProgressKeepsStableColumns(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reporter := newV2TestProgressReporter(io.Discard, "peer", true, false, v2ProgressFlags{}, &now)
	reporter.Phase("uploading", 1_000)
	now = now.Add(2 * time.Second)

	var widths []int
	for _, current := range []int64{5, 50, 500} {
		reporter.Set(current, 1_000)
		reporter.mu.Lock()
		line := reporter.lineLocked(now)
		reporter.mu.Unlock()
		widths = append(widths, len(line))
	}
	reporter.Stop()

	if widths[0] != widths[1] || widths[1] != widths[2] {
		t.Fatalf("progress widths = %v, want stable columns", widths)
	}
}

func TestV2KnownTotalProgressUsesOneUnitAndTwoDecimalPlaces(t *testing.T) {
	got := formatV2ProgressTransfer(12*1024*1024+512*1024, 50*1024*1024)
	if got != "12.50 MiB/50.00 MiB" {
		t.Fatalf("formatted transfer = %q", got)
	}
}

func TestV2ProgressResumeDoesNotCountReusableBytesInRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var output bytes.Buffer
	reporter := newV2TestProgressReporter(&output, "peer", false, false, v2ProgressFlags{force: true}, &now)
	reporter.PhaseResumed("uploading", 600, 1_000)
	now = now.Add(2 * time.Second)
	reporter.Set(800, 1_000)
	reporter.render()
	reporter.Stop()
	if !strings.Contains(output.String(), "100 B/s") {
		t.Fatalf("reused bytes inflated transfer rate: %q", output.String())
	}
}

type v2FailingProgressWriter struct{}

func (v2FailingProgressWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestV2ProgressOutputFailureDisablesReporter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reporter := newV2TestProgressReporter(v2FailingProgressWriter{}, "peer", false, false, v2ProgressFlags{force: true}, &now)
	reporter.Phase("connecting", 0)
	if !reporter.failed {
		t.Fatal("reporter stayed active after its writer failed")
	}
	reporter.Set(10, 20)
	reporter.Stop()
}

func TestV2TransportObservesBufferedRequestAndResponseReads(t *testing.T) {
	origin := "https://dud.example.com"
	var uploaded, downloaded []int64
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.ContentLength != 6 {
			t.Fatalf("ContentLength = %d, want 6", request.ContentLength)
		}
		buffer := make([]byte, 2)
		for {
			_, err := request.Body.Read(buffer)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
		}
		return &http.Response{
			StatusCode: 200, Header: http.Header{"Content-Type": {v2CBORContentType}, "Content-Length": {"5"}},
			ContentLength: 5, Body: io.NopCloser(&v2StepReader{data: []byte("reply"), step: 2}),
		}, nil
	})}
	transport := &productionV2Transport{targets: map[string]v2CachedTarget{
		origin: {client: client, expiresAt: time.Now().Add(time.Hour)},
	}}
	response, err := transport.doTarget(context.Background(), func() {}, v2Request{
		Method: "POST", Origin: origin, Path: "/v2/test", Body: []byte("abcdef"), MaxResponseBytes: 5,
		ObserveUpload:   func(value, _ int64) { uploaded = append(uploaded, value) },
		ObserveDownload: func(value, _ int64) { downloaded = append(downloaded, value) },
	}, origin, &v2Resolution{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != "reply" || uploaded[len(uploaded)-1] != 6 || downloaded[len(downloaded)-1] != 5 {
		t.Fatalf("body = %q, uploaded = %v, downloaded = %v", response.Body, uploaded, downloaded)
	}
}

func TestV2TransportObservesStreamedResponsePartialReads(t *testing.T) {
	origin := "https://dud.example.com"
	var downloaded []int64
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200, Header: http.Header{"Content-Length": {"6"}}, ContentLength: 6,
			Body: io.NopCloser(&v2StepReader{data: []byte("abcdef"), step: 2}),
		}, nil
	})}
	transport := &productionV2Transport{targets: map[string]v2CachedTarget{
		origin: {client: client, expiresAt: time.Now().Add(time.Hour)},
	}}
	response, err := transport.doTarget(context.Background(), func() {}, v2Request{
		Method: "GET", Origin: origin, Path: "/v2/test", StreamResponse: true,
		ObserveDownload: func(value, _ int64) { downloaded = append(downloaded, value) },
	}, origin, &v2Resolution{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 3)
	if count, err := response.Stream.Read(buffer); err != nil || count != 2 {
		t.Fatalf("partial read = %d, %v", count, err)
	}
	if downloaded[len(downloaded)-1] != 2 {
		t.Fatalf("download observations = %v", downloaded)
	}
	if _, err := io.Copy(io.Discard, response.Stream); err != nil {
		t.Fatal(err)
	}
	if err := response.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if downloaded[len(downloaded)-1] != 6 {
		t.Fatalf("final download observations = %v", downloaded)
	}
}

func TestV2TransportObservesStreamedRequestReadsAndKeepsLength(t *testing.T) {
	origin := "https://dud.example.com"
	var uploaded []int64
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.ContentLength != 6 {
			t.Fatalf("ContentLength = %d, want 6", request.ContentLength)
		}
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 204, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	transport := &productionV2Transport{targets: map[string]v2CachedTarget{
		origin: {client: client, expiresAt: time.Now().Add(time.Hour)},
	}}
	_, err := transport.doTarget(context.Background(), func() {}, v2Request{
		Method: "PUT", Origin: origin, Path: "/v2/test",
		BodyStream: &v2StepReader{data: []byte("abcdef"), step: 2}, ContentLength: 6,
		ObserveUpload: func(value, _ int64) { uploaded = append(uploaded, value) },
	}, origin, &v2Resolution{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if uploaded[len(uploaded)-1] != 6 || len(uploaded) < 4 {
		t.Fatalf("upload observations = %v", uploaded)
	}
}

func TestV2TransportCountsOnlyBytesReadBeforeResponseLimit(t *testing.T) {
	origin := "https://dud.example.com"
	var downloaded []int64
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 400, Header: http.Header{"Content-Length": {"8"}}, ContentLength: 8,
			Body: io.NopCloser(&v2StepReader{data: []byte("12345678"), step: 2}),
		}, nil
	})}
	transport := &productionV2Transport{targets: map[string]v2CachedTarget{
		origin: {client: client, expiresAt: time.Now().Add(time.Hour)},
	}}
	_, err := transport.doTarget(context.Background(), func() {}, v2Request{
		Method: "GET", Origin: origin, Path: "/v2/test", MaxResponseBytes: 5,
		ObserveDownload: func(value, _ int64) { downloaded = append(downloaded, value) },
	}, origin, &v2Resolution{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err == nil || !strings.Contains(err.Error(), "configured limit") {
		t.Fatalf("response limit error = %v", err)
	}
	if downloaded[len(downloaded)-1] != 6 {
		t.Fatalf("observed bytes = %v, want reads through limit+1", downloaded)
	}
}

func TestV2ObservedReaderReportsBytesReturnedWithAnError(t *testing.T) {
	var observations []int64
	reader := &v2ObservedReader{
		reader: v2ReadOnceWithError{data: []byte("part"), err: context.Canceled}, total: 10,
		observe: func(value, _ int64) { observations = append(observations, value) },
	}
	buffer := make([]byte, 10)
	count, err := reader.Read(buffer)
	if count != 4 || !errors.Is(err, context.Canceled) {
		t.Fatalf("read = %d, %v", count, err)
	}
	if len(observations) != 1 || observations[0] != 4 {
		t.Fatalf("observations = %v", observations)
	}
}

type v2StepReader struct {
	data []byte
	step int
	read int
}

type v2ReadOnceWithError struct {
	data []byte
	err  error
}

func (reader v2ReadOnceWithError) Read(buffer []byte) (int, error) {
	return copy(buffer, reader.data), reader.err
}

func (reader *v2StepReader) Read(buffer []byte) (int, error) {
	if reader.read == len(reader.data) {
		return 0, io.EOF
	}
	count := reader.step
	if count > len(buffer) {
		count = len(buffer)
	}
	if remaining := len(reader.data) - reader.read; count > remaining {
		count = remaining
	}
	copy(buffer, reader.data[reader.read:reader.read+count])
	reader.read += count
	return count, nil
}
