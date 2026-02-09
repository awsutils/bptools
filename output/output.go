package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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
	switch format {
	case JSON:
		return writeJSON(w, results)
	case CSV:
		return writeCSV(w, results)
	default:
		return writeText(w, results)
	}
}

func writeJSON(w io.Writer, results []checker.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeCSV(w io.Writer, results []checker.Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"check_id", "resource_id", "status", "message"})
	for _, r := range results {
		_ = cw.Write([]string{r.CheckID, r.ResourceID, string(r.Status), r.Message})
	}
	cw.Flush()
	return cw.Error()
}

func writeText(w io.Writer, results []checker.Result) error {
	for _, r := range results {
		_, err := fmt.Fprintf(w, "[%s] %s: %s - %s\n", r.Status, r.CheckID, r.ResourceID, r.Message)
		if err != nil {
			return err
		}
	}
	return nil
}
