// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// textNoteWidth is the fixed column at which prose notes wrap. Nothing here
// probes the terminal size: a report has to be byte-identical whether it is
// read on a TTY, piped into a pager, or captured in a CI log, so the width is
// a constant rather than a property of the process that happens to run it.
const textNoteWidth = 78

func safeTerminalText(value string) string {
	if strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0 {
		return strconv.QuoteToASCII(value)
	}
	return value
}

// textRow is one aligned label/value pair. Note carries the provenance or
// qualifier rendered in a trailing parenthesised column, and Items carries
// bullet lines rendered underneath the row.
type textRow struct {
	Label string
	Value string
	Note  string
	Items []string
}

// textSection is a titled block of aligned rows. Sections nest, so a report can
// place a delivery block underneath the origin it belongs to without either one
// knowing how deep it sits.
type textSection struct {
	title    string
	rows     []textRow
	notes    []string
	children []*textSection
}

// textReport renders the sectioned, column-aligned text output shared by every
// reporting command. Text and JSON stay two renderings of the same values, so a
// field added to one belongs in the other.
type textReport struct {
	sections []*textSection
}

// section starts a new top-level block. An empty title produces a flush-left
// header block, which is how a report opens before its first named section.
func (r *textReport) section(title string) *textSection {
	created := &textSection{title: title}
	r.sections = append(r.sections, created)
	return created
}

func (s *textSection) add(label, value string) {
	s.rows = append(s.rows, textRow{Label: label, Value: value})
}

func (s *textSection) addf(label, format string, args ...any) {
	s.add(label, fmt.Sprintf(format, args...))
}

// addNote records a value together with the layer or qualifier it came from.
// The note renders in its own column so provenance lines up down the section.
func (s *textSection) addNote(label, value, note string) {
	s.rows = append(s.rows, textRow{Label: label, Value: value, Note: note})
}

// addList records a value followed by bullet lines. Callers pass the summary as
// the value so the row still reads correctly when the list is empty.
func (s *textSection) addList(label, value string, items []string) {
	s.rows = append(s.rows, textRow{Label: label, Value: value, Items: items})
}

func (s *textSection) addRows(rows []textRow) {
	s.rows = append(s.rows, rows...)
}

// note attaches a wrapped prose paragraph after the rows of this section.
func (s *textSection) note(text string) {
	s.notes = append(s.notes, text)
}

func (s *textSection) notef(format string, args ...any) {
	s.note(fmt.Sprintf(format, args...))
}

// child nests a titled block inside this section, indented one level further.
func (s *textSection) child(title string) *textSection {
	created := &textSection{title: title}
	s.children = append(s.children, created)
	return created
}

func (s *textSection) empty() bool {
	return len(s.rows) == 0 && len(s.notes) == 0 && len(s.children) == 0
}

// write renders the report. A titled section is preceded by one blank line, an
// untitled one is not, and the report never ends with trailing blank lines.
func (r *textReport) write(out io.Writer) error {
	var buffer strings.Builder
	written := false
	for _, section := range r.sections {
		// A section a command declared but never filled contributes nothing;
		// emitting a bare heading would only add noise.
		if section.empty() {
			continue
		}
		if written && section.title != "" {
			buffer.WriteString("\n")
		}
		section.render(&buffer, 0)
		written = true
	}
	_, err := io.WriteString(out, buffer.String())
	return err
}

func (r *textReport) String() string {
	var buffer strings.Builder
	_ = r.write(&buffer)
	return buffer.String()
}

// render emits one section at the given depth. Rows sit one level deeper than
// their title; an untitled section keeps its rows at the current depth so a
// header block starts flush left.
func (s *textSection) render(buffer *strings.Builder, depth int) {
	rowDepth := depth
	if s.title != "" {
		buffer.WriteString(strings.Repeat("  ", depth))
		buffer.WriteString(s.title)
		buffer.WriteString("\n")
		rowDepth++
	}
	indent := strings.Repeat("  ", rowDepth)
	labelWidth := 0
	valueWidth := 0
	noted := false
	for _, row := range s.rows {
		labelWidth = max(labelWidth, len(row.Label))
		if row.Note != "" {
			noted = true
			valueWidth = max(valueWidth, len(row.Value))
		}
	}
	for _, row := range s.rows {
		buffer.WriteString(indent)
		if row.Value == "" && row.Note == "" && len(row.Items) == 0 {
			// A bare label is a standalone line, not a padded column.
			buffer.WriteString(row.Label)
			buffer.WriteString("\n")
			continue
		}
		buffer.WriteString(padRight(row.Label, labelWidth))
		buffer.WriteString("  ")
		if noted && row.Note != "" {
			buffer.WriteString(padRight(row.Value, valueWidth))
			buffer.WriteString("  (")
			buffer.WriteString(row.Note)
			buffer.WriteString(")")
		} else {
			buffer.WriteString(row.Value)
		}
		buffer.WriteString("\n")
		for _, item := range row.Items {
			buffer.WriteString(indent)
			buffer.WriteString(strings.Repeat(" ", labelWidth+2))
			buffer.WriteString("- ")
			buffer.WriteString(item)
			buffer.WriteString("\n")
		}
	}
	for _, note := range s.notes {
		for _, line := range wrapText(note, textNoteWidth-len(indent)) {
			buffer.WriteString(indent)
			buffer.WriteString(line)
			buffer.WriteString("\n")
		}
	}
	for _, child := range s.children {
		if child.empty() {
			continue
		}
		buffer.WriteString("\n")
		child.render(buffer, rowDepth)
	}
}

func padRight(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}

// wrapText breaks a paragraph on spaces at the given width. A word longer than
// the width keeps its own line rather than being split, because the long words
// here are URLs and hostnames that must stay selectable in one piece.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	if width < 16 {
		width = 16
	}
	lines := []string{}
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
			continue
		}
		current += " " + word
	}
	return append(lines, current)
}

// fprintWrapped writes a prose line at the same fixed width the report notes
// use, so a headline sentence that outgrows one line breaks where a note would
// break rather than wherever the terminal happens to end.
func fprintWrapped(out io.Writer, format string, args ...any) error {
	for _, line := range wrapText(fmt.Sprintf(format, args...), textNoteWidth) {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

// markJSONOption records that --json was seen. Every command routes through it
// so a repeat is reported the same way everywhere, whatever option-parsing
// shape the command itself uses.
func markJSONOption(jsonOutput *bool) error {
	if *jsonOutput {
		return errors.New("--json may be specified only once")
	}
	*jsonOutput = true
	return nil
}

// markVerboseOption records that -v or --verbose was seen. The commands whose
// status footer is otherwise reported only when it matters all route through
// it, so a repeat is refused the same way --json is.
func markVerboseOption(verbose *bool) error {
	if *verbose {
		return errors.New("--verbose may be specified only once")
	}
	*verbose = true
	return nil
}

// parseJSONOption consumes a leading --json from args. It has the same shape as
// parseV2NetworkOption so both compose in one option loop.
func parseJSONOption(args []string, jsonOutput *bool) (bool, []string, error) {
	if len(args) == 0 || args[0] != "--json" {
		return false, args, nil
	}
	if err := markJSONOption(jsonOutput); err != nil {
		return false, nil, err
	}
	return true, args[1:], nil
}

// onlyJSONOption parses the arguments of a command whose sole option is --json.
func onlyJSONOption(args []string) (bool, error) {
	jsonOutput := false
	for len(args) != 0 {
		matched, rest, err := parseJSONOption(args, &jsonOutput)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, fatalError("Unknown option: " + args[0])
		}
		args = rest
	}
	return jsonOutput, nil
}

// joinValues renders a list for text output. Go's default %v spelling for a
// slice ("[a b c]") leaks a language detail into operator-facing output.
func joinValues[T any](values []T) string {
	if len(values) == 0 {
		return "none"
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = fmt.Sprint(value)
	}
	return strings.Join(parts, ", ")
}

// sortedKeys returns map keys in a stable order so text output does not depend
// on Go's randomized map iteration.
func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
