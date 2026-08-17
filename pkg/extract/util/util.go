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

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cpe"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
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

func Write(path string, content any, doSort bool) error {
	// Sort (and validate the type) before touching the filesystem so an
	// unsupported doSort type returns an error without leaving an empty file
	// behind. Sorting mutates content's shared slice/map backing storage, so
	// doing it here is equivalent to doing it just before encoding.
	if doSort {
		switch v := content.(type) {
		case dataTypes.Data:
			(&v).Sort()
		case cpeTypes.CPE:
			(&v).Sort()
		case cweTypes.CWE:
			(&v).Sort()
		case capecTypes.CAPEC:
			(&v).Sort()
		case attackTypes.Attack:
			(&v).Sort()
		case microsoftkbTypes.KB:
			(&v).Sort()
		case eolTypes.EOL:
			(&v).Sort()
		case map[string]eolTypes.EOL:
			// map values are not addressable, so sort a copy and write it back.
			for k, e := range v {
				e.Sort()
				v[k] = e
			}
		case datasourceTypes.DataSource:
			(&v).Sort()
		default:
			return errors.Errorf("doSort requested but content type %T has no sort handler; add a case to the util.Write type switch", content)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	defer f.Close()

	if err := json.MarshalWrite(f, content, jsontext.WithIndent("\t"), json.Deterministic(true)); err != nil {
		return errors.Wrap(err, "encode json")
	}

	return nil
}

type removeOption struct {
	keeps []string
}

type RemoveOption interface {
	apply(*removeOption)
}

type keepOption []string

func (o keepOption) apply(opts *removeOption) {
	opts.keeps = o
}

// WithKeep sets which entries directly under root RemoveAll leaves alone. It
// states the whole set rather than adding to the default, so that every set is
// reachable -- including the empty one, which is how a tree is emptied
// completely:
//
//	RemoveAll(dir)                            // .git
//	RemoveAll(dir, WithKeep(".git", "raw"))   // .git and raw
//	RemoveAll(dir, WithKeep("raw"))           // raw ALONE -- .git is deleted
//	RemoveAll(dir, WithKeep())                // nothing; empties dir
//
// Note the third line. .git carries the history the tree is distributed as, so
// a call meaning to widen the default has to name it: WithKeep(".git", ...).
// Passing the option repeatedly replaces rather than accumulates, the last one
// winning, as with every other option here.
//
// It exists for trees that are only partly extract-generated -- where some of
// the tree is produced by another step and cannot be rebuilt by an extract.
// Naming what to keep, rather than narrowing the call to the subdirectory the
// extract does own, is what keeps the rest of the tree swept: a file an older
// version of an extractor wrote and the current one does not is still removed.
//
// Names are matched against the entry's own name, so WithKeep("raw") keeps
// "raw" and not "rawdata".
func WithKeep(names ...string) RemoveOption {
	return keepOption(names)
}

// RemoveAll empties root, keeping whatever WithKeep names -- .git when the
// option is not given.
//
// That default is .git because it carries the history the tree is distributed
// as, which no extract writes and every extract would otherwise destroy.
func RemoveAll(root string, opts ...RemoveOption) error {
	options := &removeOption{
		keeps: []string{".git"},
	}

	for _, o := range opts {
		o.apply(options)
	}

	ds, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		return errors.Wrapf(err, "glob %s", filepath.Join(root, "*"))
	}
	for _, d := range ds {
		if slices.Contains(options.keeps, filepath.Base(d)) {
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
