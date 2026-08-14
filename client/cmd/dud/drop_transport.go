// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Dead drop requests run on the same in-process transport as peer transfers:
// DoH resolution, address classification, exactly TLS 1.3, and ECH `hard` all
// happen in Go. The commands reach it through the same injected seam the peer
// commands use, so a test can supply a transport that talks to a local server
// instead of resolving a public name.

// dropStatusError reports an HTTP status of 400 or more from a dead drop
// route. It carries exit code 22, which scripts wrapping the CLI branch on.
type dropStatusError struct {
	StatusCode int
	URL        string
}

func (e *dropStatusError) Error() string {
	return fmt.Sprintf("The requested URL returned error: %d", e.StatusCode)
}

func (e *dropStatusError) ExitCode() int { return 22 }

// splitDropURL separates a dead drop URL into the canonical origin the
// transport binds to and the origin-relative path it requests. `upload`,
// `download`, and `flush` append their own route to a base URL, while `test`
// accepts a complete URL, so both forms arrive here.
func splitDropURL(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("URL query and fragment are not permitted")
	}
	if parsed.User != nil {
		return "", "", errors.New("URL userinfo is not permitted")
	}
	origin, err := canonicalV2Origin(parsed.Scheme + "://" + parsed.Host)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	path := parsed.EscapedPath()
	// A base URL written with a trailing slash would otherwise produce a
	// scheme-relative "//v1/files" once a route is appended to it.
	path = "/" + strings.TrimLeft(path, "/")
	return origin, path, nil
}

// dropOriginSource names the layer that chose a dead drop target. Every drop
// command resolves its own --url before calling here, so the effective origin
// is compared with the configured base URL rather than threaded back through
// five option parsers. A --url that merely restates the configured base URL is
// reported as the configuration, which is where a reader would look anyway.
func (a *app) dropOriginSource(origin string) string {
	if configured, _, err := splitDropURL(a.cfg.BaseURL); err != nil || origin != configured {
		return v2NetworkSourceCLI
	}
	return dropEnvironmentSource("DUD_BASE_URL")
}

// Dead drop commands read their network settings only from DUD_* and the
// compiled defaults: no profile or configuration file feeds this path.
func dropEnvironmentSource(name string) string {
	if os.Getenv(name) != "" {
		return v2NetworkSourceEnvironment
	}
	return v2NetworkSourceDefault
}

func (a *app) dropTransport(origin string) (v2Transport, error) {
	if err := a.validateECHMode(); err != nil {
		return nil, err
	}
	return a.newV2Transport(v2TransportOptions{
		DOHURL:        a.cfg.DOHURL,
		ECHMode:       a.cfg.ECHMode,
		CABundle:      a.cfg.CABundle,
		ConnectTo:     a.cfg.ConnectTo,
		OriginSource:  a.dropOriginSource(origin),
		ECHModeSource: dropEnvironmentSource("DUD_ECH_MODE"),
	})
}

// dropRequest performs one dead drop request. The caller supplies everything
// except the origin and path, which are derived from the target URL so that a
// base URL and a complete URL behave identically.
func (a *app) dropRequest(ctx context.Context, targetURL string, request v2Request) (*v2Response, error) {
	origin, path, err := splitDropURL(targetURL)
	if err != nil {
		return nil, fatalError(err.Error())
	}
	transport, err := a.dropTransport(origin)
	if err != nil {
		return nil, err
	}
	request.Origin = origin
	request.Path = path
	response, err := transport.Do(ctx, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		if response.Stream != nil {
			response.Stream.Close()
		}
		return nil, &dropStatusError{StatusCode: response.StatusCode, URL: targetURL}
	}
	return response, nil
}
