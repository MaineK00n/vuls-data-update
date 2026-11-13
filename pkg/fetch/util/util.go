package util

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io/fs"
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

type removeOption struct {
	keeps []string
}

type RemoveOption interface {
	apply(*removeOption)
}

// KeepOption is what WithKeep returns. It configures RemoveAll and
// EnsureWritten alike, so that a fetcher names what it keeps once and the two
// agree on it.
type KeepOption interface {
	RemoveOption
	EnsureOption
}

type keepOption []string

func (o keepOption) apply(opts *removeOption) {
	opts.keeps = o
}

func (o keepOption) applyEnsure(opts *ensureOption) {
	opts.keeps = o
}

// WithKeep sets which entries directly under root RemoveAll leaves alone, and
// so which ones EnsureWritten leaves out of what a fetch wrote. It states the
// whole set rather than adding to the default, so that every set is reachable
// -- including the empty one, which is how a tree is emptied completely:
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
// It exists for sources whose tree is only partly fetch-generated -- where some
// of it is produced by another step and cannot be rebuilt by a fetch. Naming
// what to keep, rather than narrowing the call to the subdirectory the fetch
// does own, is what keeps the rest of the tree swept: a file an older version
// of a fetcher wrote and the current one does not is still removed.
//
// Names are matched against the entry's own name, so WithKeep("raw") keeps
// "raw" and not "rawdata".
func WithKeep(names ...string) KeepOption {
	return keepOption(names)
}

// RemoveAll empties root, keeping whatever WithKeep names -- .git when the
// option is not given.
//
// That default is .git because it carries the history the tree is distributed
// as, which no fetch writes and every fetch would otherwise destroy.
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

type ensureOption struct {
	keeps    []string
	requires []string
}

type EnsureOption interface {
	applyEnsure(*ensureOption)
}

type requireOption []string

func (o requireOption) applyEnsure(opts *ensureOption) {
	opts.requires = o
}

// WithRequire names paths, relative to root, under each of which EnsureWritten
// requires a file. A fetcher whose data falls into fixed sections names them,
// so that a section it stops writing fails the fetch: one section going
// missing still leaves the rest of the tree, which is all the default check
// asks for. A path that names a file requires that file. Like WithKeep, the
// option states the whole set, and passing it again replaces it.
func WithRequire(paths ...string) EnsureOption {
	return requireOption(paths)
}

// EnsureWritten returns an error unless the fetch that just ran wrote into
// root: unless root holds a file outside what WithKeep names (.git when the
// option is not given) and, with WithRequire, a file under each path that
// names.
//
// It is the end of a fetch as RemoveAll is the start. RemoveAll empties root
// but for what it keeps, so whatever else is there afterwards is what the
// fetch wrote; pass both the same WithKeep, or what was kept passes for output.
//
// A fetch that decodes nothing -- because upstream changed the structure the
// fetcher decodes, say -- otherwise succeeds and leaves root, or a section of
// it, empty, and committing that deletes every file of it from the repository
// the tree is distributed as. Only the absence is checked: what each file
// holds, and whether as many were written as last time, is not.
func EnsureWritten(root string, opts ...EnsureOption) error {
	options := &ensureOption{
		keeps: []string{".git"},
	}

	for _, o := range opts {
		o.applyEnsure(options)
	}

	switch ok, err := holdsFile(root, options.keeps); {
	case err != nil:
		return errors.Wrapf(err, "check %s", root)
	case !ok:
		return errors.Errorf("no file written under %s", root)
	}

	missing := make([]string, 0, len(options.requires))
	for _, p := range options.requires {
		if !filepath.IsLocal(p) {
			return errors.Errorf("unexpected required path. expected: a path under %q, actual: %q", root, p)
		}

		switch ok, err := holdsFile(filepath.Join(root, p), nil); {
		case err != nil:
			return errors.Wrapf(err, "check %s", filepath.Join(root, p))
		case !ok:
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return errors.Errorf("no file written under %q in %s", missing, root)
	}

	return nil
}

// holdsFile reports whether path is a regular file, or a directory with one
// anywhere beneath it, leaving out the entries directly under path that skips
// names. A path that does not exist holds nothing, and neither does a tree of
// empty directories: a fetcher that unpacks an archive or clones a repository
// can leave those behind without writing anything.
func holdsFile(path string, skips []string) (bool, error) {
	root := filepath.Clean(path)

	found := false
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}

		if filepath.Dir(p) == root && slices.Contains(skips, d.Name()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.Type().IsRegular() {
			found = true
			return fs.SkipAll
		}

		return nil
	}); err != nil {
		return false, errors.Wrapf(err, "walk %s", root)
	}

	return found, nil
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
