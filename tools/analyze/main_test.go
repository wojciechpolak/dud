// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"testing"

	"golang.org/x/tools/go/analysis"
)

// A malformed analyzer set fails inside multichecker.Main at run time, where
// the failure looks like a broken tool rather than a bad list. Validate
// catches it here instead.
func TestAnalyzersAreValid(t *testing.T) {
	list := analyzers()
	if len(list) == 0 {
		t.Fatal("no analyzers registered")
	}
	if err := analysis.Validate(list); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// multichecker keys its -NAME flags by analyzer name, so a duplicate silently
// makes one of the pair unselectable.
func TestAnalyzerNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, a := range analyzers() {
		if seen[a.Name] {
			t.Errorf("duplicate analyzer %q", a.Name)
		}
		seen[a.Name] = true
	}
}
