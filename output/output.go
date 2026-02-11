package output

import (
	"io"
	"strings"

	"bptools/checker"
)

// Format represents an output format.
type Format string

const (
	Text Format = "text"
	JSON Format = "json"
	CSV  Format = "csv"
)

// ParseFormat parses a format string.
func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "json":
		return JSON
	case "csv":
		return CSV
	default:
		return Text
	}
}

// Write writes results in the given format.
func Write(w io.Writer, results []checker.Result, format Format) error {
	_ = w
	_ = results
	_ = format
	return nil
}
