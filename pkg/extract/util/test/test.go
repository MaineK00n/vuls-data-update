package test

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
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

// Diff compares the tree an extractor wrote under gotAbsPath against the golden
// tree at expectedAbsPath, and reports the differences as an error. Which files
// exist is part of the comparison: comparing only the files the extractor wrote
// passes a run that wrote none of them.
func Diff(expectedAbsPath, gotAbsPath string) error {
	var diffs []string

	names := []string{"datasource.json", "README.md", "data", "cpe", "cwe", "capec", "attack", "microsoftkb", "eol"}

	unknown, err := unknownTopLevel(names, expectedAbsPath, gotAbsPath)
	if err != nil {
		return errors.Wrap(err, "list top level")
	}
	for _, n := range unknown {
		diffs = append(diffs, fmt.Sprintf("top level entry the comparison does not know: %q", n))
	}

	for _, name := range names {
		gotExists, err := exists(filepath.Join(gotAbsPath, name))
		if err != nil {
			return errors.Wrapf(err, "check %s", filepath.Join(gotAbsPath, name))
		}
		wantExists, err := exists(filepath.Join(expectedAbsPath, name))
		if err != nil {
			return errors.Wrapf(err, "check %s", filepath.Join(expectedAbsPath, name))
		}
		if !gotExists && !wantExists {
			continue
		}

		want, err := paths(filepath.Join(expectedAbsPath, name))
		if err != nil {
			return errors.Wrapf(err, "list %s", filepath.Join(expectedAbsPath, name))
		}
		got, err := paths(filepath.Join(gotAbsPath, name))
		if err != nil {
			return errors.Wrapf(err, "list %s", filepath.Join(gotAbsPath, name))
		}
		if diff := cmp.Diff(want, escapeNames(got)); diff != "" {
			diffs = append(diffs, fmt.Sprintf("%s (-expected +got):\n%s", name, diff))
			continue
		}

		// Both sides hold the same files, or the comparison above would have
		// moved on to the next name, so walking the output alone reaches every
		// pair. Without that, a file golden does not describe would be looked
		// up and the walk would fail on its absence rather than report it.
		gotRoot := filepath.Join(gotAbsPath, name)
		if err := filepath.WalkDir(gotRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			// Relative to the category's own root: the output root is a temp
			// directory the test does not choose, and a component of it can be
			// named after a category.
			rel, err := filepath.Rel(gotRoot, path)
			if err != nil {
				return errors.Wrapf(err, "rel %s", path)
			}

			ef, err := os.Open(filepath.Join(expectedAbsPath, name, escapeName(rel)))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(expectedAbsPath, name, escapeName(rel)))
			}
			defer ef.Close()

			gf, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer gf.Close()

			var diff string
			switch name {
			case "datasource.json":
				var want, got datasourceTypes.DataSource
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				want.Sort()

				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				got.Sort()

				diff = cmp.Diff(want, got)
			case "README.md":
				want, err := io.ReadAll(ef)
				if err != nil {
					return errors.Wrapf(err, "read %s", ef.Name())
				}
				got, err := io.ReadAll(gf)
				if err != nil {
					return errors.Wrapf(err, "read %s", gf.Name())
				}
				diff = cmp.Diff(string(want), string(got))
			case "data":
				var want, got dataTypes.Data
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				want.Sort()

				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				got.Sort()

				diff = cmp.Diff(want, got)
			case "cpe":
				var want, got cpeTypes.CPE
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			case "cwe":
				var want, got cweTypes.CWE
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			case "capec":
				var want, got capecTypes.CAPEC
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			case "attack":
				var want, got attackTypes.Attack
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			case "microsoftkb":
				var want, got microsoftkbTypes.KB
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			case "eol":
				var want, got map[string]eolTypes.EOL
				if err := json.UnmarshalRead(ef, &want); err != nil {
					return errors.Wrapf(err, "decode %s", ef.Name())
				}
				if err := json.UnmarshalRead(gf, &got); err != nil {
					return errors.Wrapf(err, "decode %s", gf.Name())
				}
				diff = cmp.Diff(want, got)
			default:
				return errors.Errorf("unsupported type: %q", name)
			}
			if diff != "" {
				diffs = append(diffs, fmt.Sprintf("%s (-expected +got):\n%s", filepath.Join(name, rel), diff))
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", gotRoot)
		}
	}

	if len(diffs) > 0 {
		return errors.New(strings.Join(diffs, "\n"))
	}

	return nil
}

// paths lists the files under root as slash-separated paths relative to it, so
// that a golden tree and an output tree can be compared by which files they
// hold. A root that does not exist reads as empty.
func paths(root string) ([]string, error) {
	var ps []string
	switch ok, err := exists(root); {
	case err != nil:
		return nil, errors.Wrapf(err, "check %s", root)
	case !ok:
		return ps, nil
	}

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.Wrapf(err, "rel %s", path)
		}
		ps = append(ps, filepath.ToSlash(rel))

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	slices.Sort(ps)

	return ps, nil
}

// escapeName returns rel with its base name URL-escaped, which is how golden
// stores it. Only the base name is escaped: directory components are stored raw
// on both sides.
func escapeName(rel string) string {
	dir, file := filepath.Split(rel)

	return filepath.Join(dir, url.QueryEscape(file))
}

// escapeNames re-keys a list of slash-separated paths the same way, for
// comparing an output tree against the golden tree that describes it.
func escapeNames(ps []string) []string {
	// nil rather than an empty slice, so that a category directory holding
	// nothing compares equal to one that is not there at all, as paths reports
	// both as nil.
	var escaped []string
	for _, p := range ps {
		escaped = append(escaped, filepath.ToSlash(escapeName(filepath.FromSlash(p))))
	}
	slices.Sort(escaped)

	return escaped
}

// unknownTopLevel lists what sits at the top of either tree that is not one of
// names, sorted and without repeats. The comparison below knows only those
// names, so anything else would go unlooked at on both sides at once.
//
// A directory holding no files is not one of them: git cannot carry an empty
// directory, so golden has no way to describe one the extractor creates.
func unknownTopLevel(names []string, expectedAbsPath, gotAbsPath string) ([]string, error) {
	seen := make(map[string]struct{})

	for _, root := range []string{expectedAbsPath, gotAbsPath} {
		switch ok, err := exists(root); {
		case err != nil:
			return nil, errors.Wrapf(err, "check %s", root)
		case !ok:
			continue
		}

		des, err := os.ReadDir(root)
		if err != nil {
			return nil, errors.Wrapf(err, "read dir %s", root)
		}

		for _, de := range des {
			if slices.Contains(names, de.Name()) {
				continue
			}

			ps, err := paths(filepath.Join(root, de.Name()))
			if err != nil {
				return nil, errors.Wrapf(err, "list %s", filepath.Join(root, de.Name()))
			}
			if len(ps) == 0 {
				continue
			}

			seen[de.Name()] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(seen)), nil
}

// exists reports whether path is there. Only its absence is an answer: any
// other stat failure is an error, so that a directory that cannot be read is
// not mistaken for one that holds nothing.
func exists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, errors.Wrapf(err, "stat %s", path)
	}

	return true, nil
}

// QueryUnescapeFileTree copies the file tree at fixturePath into dir by
// query-unescaping file names, and returns the copy's path,
// <dir>/(basename of fixturePath). Callers pass t.TempDir() as dir.
func QueryUnescapeFileTree(dir, fixturePath string) (string, error) {
	rawPath := filepath.Join(dir, filepath.Base(fixturePath))
	if err := os.MkdirAll(rawPath, fs.ModePerm); err != nil {
		return "", errors.Wrapf(err, "mkdir %s", rawPath)
	}

	if err := filepath.WalkDir(fixturePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(fixturePath, path)
		if err != nil {
			return errors.Wrapf(err, "rel %s", path)
		}
		unescaped, err := url.QueryUnescape(rel)
		if err != nil {
			return errors.Wrapf(err, "query unescape %s", rel)
		}
		// A name that unescapes to something reaching outside the destination
		// would be materialized outside the temp directory, where the test
		// would neither find it nor clean it up.
		if !filepath.IsLocal(unescaped) {
			return errors.Errorf("unexpected fixture name. expected: %q to unescape to a path under the fixture root, actual: %q", rel, unescaped)
		}

		targetDir := filepath.Join(rawPath, filepath.Dir(unescaped))
		if err := os.MkdirAll(targetDir, fs.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", targetDir)
		}
		if err := os.Link(path, filepath.Join(rawPath, unescaped)); err != nil {
			return errors.Wrapf(err, "link %s", filepath.Join(rawPath, unescaped))
		}

		return nil
	}); err != nil {
		return "", errors.Wrapf(err, "walk %s", fixturePath)
	}

	return rawPath, nil
}
