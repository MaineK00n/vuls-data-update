package util

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
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
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
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

func Write(path string, content any, doSort bool) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()

	if doSort {
		switch v := content.(type) {
		case types.Data:
			(&v).Sort()
		case types.CPEDictionary:
			(&v).Sort()
		case types.CWEDictionary:
			(&v).Sort()
		case types.CAPECDictionary:
			(&v).Sort()
		case types.AttackDictionary:
			(&v).Sort()
		case types.WindowsKBDictionary:
			(&v).Sort()
		case types.EOLDictionary:
			(&v).Sort()
		default:
		}
	}

	e := json.NewEncoder(f)
	e.SetEscapeHTML(false)
	e.SetIndent("", "\t")
	if err := e.Encode(content); err != nil {
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
