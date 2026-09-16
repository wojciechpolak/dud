// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// analyze runs the golang.org/x/tools analyzers that "go vet" does not enable
// by default. They live in one multichecker binary, so this repository gains no
// dependency beyond golang.org/x/tools, which the tools module already pins for
// goimports and deadcode.
package main

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/multichecker"
	"golang.org/x/tools/go/analysis/passes/atomicalign"
	"golang.org/x/tools/go/analysis/passes/deepequalerrors"
	"golang.org/x/tools/go/analysis/passes/defers"
	"golang.org/x/tools/go/analysis/passes/httpresponse"
	"golang.org/x/tools/go/analysis/passes/lostcancel"
	"golang.org/x/tools/go/analysis/passes/nilness"
	"golang.org/x/tools/go/analysis/passes/reflectvaluecompare"
	"golang.org/x/tools/go/analysis/passes/sigchanyzer"
	"golang.org/x/tools/go/analysis/passes/sortslice"
	"golang.org/x/tools/go/analysis/passes/testinggoroutine"
	"golang.org/x/tools/go/analysis/passes/unusedwrite"
	"golang.org/x/tools/go/analysis/passes/waitgroup"
)

// analyzers lists the passes to run. httpresponse catches a response body used
// or deferred before the error return is checked, which leaks a connection.
// lostcancel catches a context cancel function that nothing calls. nilness
// catches impossible nil comparisons and guaranteed nil dereferences.
// unusedwrite catches writes to struct fields that nothing reads.
func analyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		atomicalign.Analyzer,
		deepequalerrors.Analyzer,
		defers.Analyzer,
		httpresponse.Analyzer,
		lostcancel.Analyzer,
		nilness.Analyzer,
		reflectvaluecompare.Analyzer,
		sigchanyzer.Analyzer,
		sortslice.Analyzer,
		testinggoroutine.Analyzer,
		unusedwrite.Analyzer,
		waitgroup.Analyzer,
	}
}

func main() {
	multichecker.Main(analyzers()...)
}
