package util

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls-data-update")
	return dir
}

func Unique[T comparable](s []T) []T {
	m := make(map[T]struct{})
	for _, v := range s {
		m[v] = struct{}{}
	}
	return slices.Collect(maps.Keys(m))
}

type IndexChunk struct {
	From, To int
}

func ChunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}

type writeOption struct {
	allowInvalidUTF8 bool
}

type WriteOption interface {
	apply(*writeOption)
}

type allowInvalidUTF8Option bool

func (o allowInvalidUTF8Option) apply(opts *writeOption) {
	opts.allowInvalidUTF8 = bool(o)
}

func WithAllowInvalidUTF8(allow bool) WriteOption {
	return allowInvalidUTF8Option(allow)
}

func Write(path string, content any, opts ...WriteOption) error {
	options := &writeOption{
		allowInvalidUTF8: false,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()

	if err := json.MarshalWrite(f, content, jsontext.WithIndent("\t"), json.Deterministic(true), jsontext.AllowInvalidUTF8(options.allowInvalidUTF8)); err != nil {
		return errors.Wrap(err, "encode json")
	}

	return nil
}

func RemoveAll(root string) error {
	ds, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		return errors.Wrapf(err, "glob %s", filepath.Join(root, "*"))
	}
	for _, d := range ds {
		if strings.HasSuffix(d, ".git") {
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			return errors.Wrapf(err, "remove %s", d)
		}
	}
	return nil
}

// Split divides the input string by delimiters in order from the front.
// The return value has n+1 elements exactly, where n is len(delimiters).
func Split(str string, delimiters ...string) ([]string, error) {
	splitted := make([]string, 0, len(delimiters)+1)
	for _, delimiter := range delimiters {
		lhs, rhs, ok := strings.Cut(str, delimiter)
		if !ok {
			return nil, errors.Errorf("delimiter: %q not found in %q", delimiter, str)
		}
		str = rhs
		splitted = append(splitted, lhs)
	}

	splitted = append(splitted, str)
	return splitted, nil
}
