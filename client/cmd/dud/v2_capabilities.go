// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const v2CBORContentType = "application/dud+cbor; version=2"

type v2Capabilities struct {
	Protocols   []uint64
	Features    []uint64
	Limits      map[uint64]uint64
	Enforcement map[uint64]uint64
}

// v2ServerContract is the validated capability document retained with a paired
// relationship. It keeps normal delivery and Git operations independent of
// capability discovery while retaining the limits they were checked against.
type v2ServerContract struct {
	Protocols      []uint64          `json:"protocols"`
	Features       []uint64          `json:"features"`
	Limits         map[uint64]uint64 `json:"limits"`
	Enforcement    map[uint64]uint64 `json:"enforcement"`
	DocumentDigest string            `json:"document_digest"`
}

var v2FeatureNames = map[uint64]string{
	1:  "objects",
	2:  "scoped-auth",
	3:  "pairing",
	4:  "delivery-slots",
	5:  "git-full",
	6:  "git-incremental",
	7:  "chunked-upload",
	8:  "strict-consume",
	9:  "atomic-delivery",
	10: "batched-inbox",
	11: "inline-control",
}

// v2LocalPeerFeatures names the registered feature IDs this device implements
// as a peer, advertised to the other side on every acknowledgement. It is not
// the server feature list: a server feature says what the relay will carry,
// while this says what the peer at the far end can actually process. Only
// features with peer-visible behaviour belong here, so 6 (git-incremental) is
// absent until that release implements it.
var v2LocalPeerFeatures = []uint64{5}

func v2LocalPeerFeatureList() []any {
	features := make([]any, 0, len(v2LocalPeerFeatures))
	for _, id := range v2LocalPeerFeatures {
		features = append(features, id)
	}
	return features
}

// v2LimitNames spells the registered limit IDs of protocol-v2.md §"Limit IDs".
// Reporting a bare numeric key would make the operator look the table up.
var v2LimitNames = map[uint64]string{
	1: "maximum object bytes",
	2: "maximum descriptor bytes",
	3: "maximum TTL seconds",
	4: "pending deliveries per slot",
	5: "objects per capability per slot epoch",
	6: "concurrent uploads per capability",
	7: "requests per capability per minute",
	8: "staged bytes per capability",
	9: "pairing envelope bytes",
}

// v2LimitName falls back to the numeric ID, because an unregistered limit is an
// optional registry entry a newer server may legitimately advertise.
// v2FeatureName spells a registered feature ID, because a bare number sends the
// reader to the registry table in protocol-v2.md.
func v2FeatureName(id uint64) string {
	if name, ok := v2FeatureNames[id]; ok {
		return name
	}
	return "unknown:" + strconv.FormatUint(id, 10)
}

func v2LimitName(id uint64) string {
	if name, ok := v2LimitNames[id]; ok {
		return name
	}
	return "limit " + strconv.FormatUint(id, 10)
}

func decodeV2Capabilities(body []byte) (*v2Capabilities, error) {
	if len(body) == 0 || len(body) > v2MaxDescriptorBytes {
		return nil, errors.New("capability discovery response has an invalid size")
	}
	var raw map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode capability discovery response: %w", err)
	}
	if len(raw) != 4 {
		return nil, errors.New("capability discovery response must contain exactly four core fields")
	}
	for _, key := range []int{1, 2, 3, 4} {
		if _, ok := raw[key]; !ok {
			return nil, fmt.Errorf("capability discovery response is missing core field %d", key)
		}
	}
	for key := range raw {
		if key < 1 || key > 4 {
			return nil, fmt.Errorf("capability discovery response contains unknown core field %d", key)
		}
	}
	canonical, err := v2EncMode.Marshal(raw)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("capability discovery response is not deterministic CBOR")
	}
	result := &v2Capabilities{}
	if err := v2DecMode.Unmarshal(raw[1], &result.Protocols); err != nil {
		return nil, errors.New("capability protocols field is invalid")
	}
	if err := v2DecMode.Unmarshal(raw[2], &result.Features); err != nil {
		return nil, errors.New("capability features field is invalid")
	}
	if err := v2DecMode.Unmarshal(raw[3], &result.Limits); err != nil {
		return nil, errors.New("capability limits field is invalid")
	}
	if err := v2DecMode.Unmarshal(raw[4], &result.Enforcement); err != nil {
		return nil, errors.New("capability enforcement field is invalid")
	}
	if !strictlyIncreasingV2(result.Protocols) || !strictlyIncreasingV2(result.Features) {
		return nil, errors.New("capability protocol and feature registries must be sorted and unique")
	}
	if !containsV2Uint(result.Protocols, 2) {
		return nil, errors.New("server does not advertise protocol v2")
	}
	for id := uint64(1); id <= 9; id++ {
		if result.Limits[id] == 0 {
			return nil, fmt.Errorf("capability response omits required limit %d", id)
		}
	}
	for _, id := range []uint64{1, 2} {
		if _, ok := result.Enforcement[id]; !ok {
			return nil, fmt.Errorf("capability response omits required enforcement field %d", id)
		}
	}
	if quota := result.Enforcement[1]; quota != 1 && quota != 2 {
		return nil, errors.New("capability response has an invalid quota enforcement class")
	}
	if consume := result.Enforcement[2]; consume > 2 {
		return nil, errors.New("capability response has an invalid consume enforcement class")
	}
	return result, nil
}

func strictlyIncreasingV2(values []uint64) bool {
	if len(values) == 0 {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index] <= values[index-1] {
			return false
		}
	}
	return true
}

func containsV2Uint(values []uint64, value uint64) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= value })
	return index < len(values) && values[index] == value
}

func v2CapabilityDocumentBytes(capabilities *v2Capabilities) ([]byte, error) {
	if capabilities == nil {
		return nil, errors.New("server capability document is missing")
	}
	return v2EncMode.Marshal(map[int]any{
		1: capabilities.Protocols,
		2: capabilities.Features,
		3: capabilities.Limits,
		4: capabilities.Enforcement,
	})
}

func newV2ServerContract(capabilities *v2Capabilities) (v2ServerContract, error) {
	body, err := v2CapabilityDocumentBytes(capabilities)
	if err != nil {
		return v2ServerContract{}, err
	}
	validated, err := decodeV2Capabilities(body)
	if err != nil {
		return v2ServerContract{}, err
	}
	digest := sha256.Sum256(body)
	return v2ServerContract{
		Protocols:      append([]uint64(nil), validated.Protocols...),
		Features:       append([]uint64(nil), validated.Features...),
		Limits:         maps.Clone(validated.Limits),
		Enforcement:    maps.Clone(validated.Enforcement),
		DocumentDigest: hex.EncodeToString(digest[:]),
	}, nil
}

func (contract v2ServerContract) capabilities() (*v2Capabilities, error) {
	capabilities := &v2Capabilities{
		Protocols:   append([]uint64(nil), contract.Protocols...),
		Features:    append([]uint64(nil), contract.Features...),
		Limits:      maps.Clone(contract.Limits),
		Enforcement: maps.Clone(contract.Enforcement),
	}
	body, err := v2CapabilityDocumentBytes(capabilities)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	if contract.DocumentDigest == "" || contract.DocumentDigest != hex.EncodeToString(digest[:]) {
		return nil, errors.New("stored server capability document digest is invalid")
	}
	return decodeV2Capabilities(body)
}

func requireV2CapabilityFeatures(capabilities *v2Capabilities, features ...uint64) error {
	for _, feature := range features {
		if !containsV2Uint(capabilities.Features, feature) {
			name := v2FeatureNames[feature]
			if name == "" {
				name = strconv.FormatUint(feature, 10)
			}
			return fmt.Errorf("server does not support required v2 feature %q", name)
		}
	}
	return nil
}

func requireV2Features(ctx context.Context, transport v2Transport, origin string, features ...uint64) (*v2Capabilities, error) {
	response, err := transport.Do(ctx, v2Request{
		Method: "GET",
		Origin: origin,
		Path:   "/v2/capabilities",
		Headers: http.Header{
			"Accept": []string{v2CBORContentType},
		},
		MaxResponseBytes: v2MaxDescriptorBytes,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, errors.New(
			"server does not offer protocol v2; use an explicit dead-drop command such as 'dud upload --file PATH' and share its object ID",
		)
	}
	if response.StatusCode != http.StatusOK ||
		response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf(
			"v2 capability discovery returned HTTP %d and Content-Type %q",
			response.StatusCode,
			response.ContentType,
		)
	}
	capabilities, err := decodeV2Capabilities(response.Body)
	if err != nil {
		return nil, err
	}
	if err := requireV2CapabilityFeatures(capabilities, features...); err != nil {
		return nil, err
	}
	return capabilities, nil
}

func v2BootstrapAddresses(cfg *v2LocalConfig) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(cfg.DOHBootstrap))
	for _, raw := range cfg.DOHBootstrap {
		address, _ := netip.ParseAddr(raw)
		addresses = append(addresses, address)
	}
	return addresses
}

// fetchV2Capabilities takes the resolved settings rather than their values so
// that a transport failure can name the layer that chose the target.
func (a *app) fetchV2Capabilities(ctx context.Context, settings v2NetworkSettings, bootstrap []netip.Addr) (*v2Capabilities, int, error) {
	baseURL, dohURL, echMode := settings.values()
	transport, err := a.newV2Transport(v2TransportOptions{
		DOHURL:        dohURL,
		ECHMode:       echMode,
		CABundle:      a.cfg.CABundle,
		ConnectTo:     a.cfg.ConnectTo,
		DOHBootstrap:  bootstrap,
		Timeout:       30 * time.Second,
		OriginSource:  settings.BaseURL.Source,
		ECHModeSource: settings.ECHMode.Source,
	})
	if err != nil {
		return nil, 0, err
	}
	response, err := transport.Do(ctx, v2Request{
		Method: "GET",
		Origin: baseURL,
		Path:   "/v2/capabilities",
		Headers: http.Header{
			"Accept": []string{v2CBORContentType},
		},
		MaxResponseBytes: v2MaxDescriptorBytes,
	})
	if err != nil {
		return nil, 0, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, fmt.Errorf("capability discovery returned HTTP %d", response.StatusCode)
	}
	if response.ContentType != v2CBORContentType {
		return nil, response.StatusCode, fmt.Errorf(
			"capability discovery returned unexpected Content-Type %q",
			response.ContentType,
		)
	}
	capabilities, err := decodeV2Capabilities(response.Body)
	if err != nil {
		return nil, response.StatusCode, err
	}
	return capabilities, response.StatusCode, nil
}

func (a *app) cmdCapabilities(args []string) error {
	jsonOutput := false
	overrides := v2NetworkOverrides{}
	for len(args) != 0 {
		matched, rest, err := parseV2NetworkOption(args, &overrides)
		if err != nil {
			return err
		}
		if matched {
			args = rest
			continue
		}
		matched, rest, err = parseJSONOption(args, &jsonOutput)
		if err != nil {
			return err
		}
		if !matched {
			return fatalError("Unknown capabilities option: " + args[0])
		}
		args = rest
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		return err
	}
	settings, err := resolveV2Network(cfg, nil, overrides)
	if err != nil {
		return err
	}
	baseURL, dohURL, echMode := settings.values()
	if echMode == "off" && !jsonOutput {
		fmt.Fprintln(a.errOut, "WARNING: v2 ECH off mode exposes the target hostname in TLS SNI.")
	}
	capabilities, status, err := a.fetchV2Capabilities(
		context.Background(),
		settings,
		v2BootstrapAddresses(cfg),
	)
	if err != nil {
		return err
	}
	report := renderV2Capabilities(capabilities)
	report["base_url"] = baseURL
	report["doh_url"] = dohURL
	report["ech_mode"] = echMode
	report["network_sources"] = settings.sources()
	report["transport_status"] = status
	if jsonOutput {
		return writeJSON(a.out, report)
	}
	out := &textReport{}
	origin := out.section("")
	origin.addNote("Server", baseURL, settings.BaseURL.Source)
	origin.addNote("DoH", dohURL, settings.DOHURL.Source)
	origin.addNote("ECH", echMode, settings.ECHMode.Source)
	origin.addf("Transport", "ok (HTTP %d)", status)

	server := out.section("Server capabilities")
	server.add("protocols", joinValues(capabilities.Protocols))
	features, _ := report["features"].([]string)
	server.add("features", joinValues(features))
	server.addf("quota enforcement", "%v", report["quota_enforcement"])
	server.addf("consume enforcement", "%v", report["consume_enforcement"])
	server.addf("enrollment", "%v", report["enrollment_enforcement"])

	limits := out.section("Limits")
	ids := make([]uint64, 0, len(capabilities.Limits))
	for id := range capabilities.Limits {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	for _, id := range ids {
		limits.addf(v2LimitName(id), "%d", capabilities.Limits[id])
	}
	return out.write(a.out)
}

func renderV2Capabilities(capabilities *v2Capabilities) map[string]any {
	features := make([]string, len(capabilities.Features))
	for index, id := range capabilities.Features {
		features[index] = v2FeatureName(id)
	}
	quota := map[uint64]string{1: "best-effort", 2: "atomic"}[capabilities.Enforcement[1]]
	consume := map[uint64]string{0: "none", 1: "delete-after-read", 2: "strict-atomic"}[capabilities.Enforcement[2]]
	// Enforcement 3 is additive, so a server that omits it is read as open,
	// which is what it is.
	enrollment := "open"
	if capabilities.Enforcement[3] == 1 {
		enrollment = "secret-required"
	}
	return map[string]any{
		"protocols":              capabilities.Protocols,
		"features":               features,
		"limits":                 capabilities.Limits,
		"quota_enforcement":      quota,
		"consume_enforcement":    consume,
		"enrollment_enforcement": enrollment,
	}
}
