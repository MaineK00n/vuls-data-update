package json

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"
)

// A JSONReader is a utility object to read JSON files and unmarshal it to Go structs.
type JSONReader struct {
	paths map[string]struct{}
}

// NewJSONReader returns the pointer to JSONReader.
func NewJSONReader() *JSONReader {
	return &JSONReader{paths: make(map[string]struct{})}
}

// Read reads JSON file specified by path and umarhsal it to v.
// 2nd argument v MUST be of non-nil pointer type.
func (j *JSONReader) Read(path, prefix string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(v); err != nil {
		return errors.Wrapf(err, "decode %s", path)
	}

	rel, err := filepath.Rel(prefix, path)
	if err != nil {
		return errors.Wrapf(err, "relative filepath. prefix: %q, path: %q", prefix, path)
	}
	j.paths[filepath.Join(filepath.Base(prefix), rel)] = struct{}{}

	return nil
}

// Paths returns a path slice accumulated by Read() calls.
// Returned pathes is the string after the basename of prefixes.
// Resulting slices has no duplication even if multiple Read() calls with the same path.
func (j JSONReader) Paths() []string {
	return slices.Collect(maps.Keys(j.paths))
}
