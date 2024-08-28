package json

import (
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"slices"

	"github.com/pkg/errors"
)

// A JSONReader is a utility object to read JSON files and unmarshal it to Go structs.
type JSONReader struct {
	memo map[string]reflect.Value
}

// NewJSONReader returns the pointer to JSONReader with empty memo.
func NewJSONReader() *JSONReader {
	return &JSONReader{memo: map[string]reflect.Value{}}
}

// Read reads JSON file specified by path and umarhsal it to v.
// It internally uses memoization, it assigns the previous result to v after 2nd call with the identical path.
// 2nd argument v MUST be of non-nil pointer type.
func (j *JSONReader) Read(path string, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.Errorf("invalid value v (2nd arg). expected: non-nil pointer, actual kind: %v, type: %v, isNil: %v", rv.Kind(), rv.Type(), rv.Kind() == reflect.Pointer && rv.IsNil())
	}
	// the value that the pointer point to
	ev := rv.Elem()

	if value, found := j.memo[path]; found {
		ev.Set(value)
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(v); err != nil {
		return errors.Wrapf(err, "decode %s", path)
	}
	j.memo[path] = ev

	return nil
}

// Paths returns a path slice accumulated by Read() calls.
// Resulting slices has no duplication even if multiple Read() calls with the same path.
func (j JSONReader) Paths() []string {
	return slices.Collect(maps.Keys(j.memo))
}
