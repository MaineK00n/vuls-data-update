package test_test

import (
	"io/fs"
	"slices"

	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/pkg/errors"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

type file struct {
	path    string
	content string
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name string
		// gotParent places the output tree under an extra path component, for
		// the case where that component is named after one of the categories.
		gotParent string
		golden    []file
		got       []file
		// gotEmptyDirs are directories created in the output holding no files,
		// which git cannot carry on the golden side.
		gotEmptyDirs []string
		// wantErr lists substrings the reported error must contain. Empty means
		// the trees must compare equal.
		wantErr []string
	}{
		{
			name:   "equal trees",
			golden: []file{{path: "README.md", content: "# title\n"}, {path: "data/2024/CVE-2024-0001.json", content: "{}"}},
			got:    []file{{path: "README.md", content: "# title\n"}, {path: "data/2024/CVE-2024-0001.json", content: "{}"}},
		},
		{
			name:    "file the extractor did not write",
			golden:  []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}, {path: "data/2024/CVE-2024-0002.json", content: "{}"}},
			got:     []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}},
			wantErr: []string{"data", "CVE-2024-0002.json"},
		},
		{
			name:    "file golden does not describe",
			golden:  []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}},
			got:     []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}, {path: "data/2024/CVE-2024-0002.json", content: "{}"}},
			wantErr: []string{"data", "CVE-2024-0002.json"},
		},
		{
			// The regression this guards: Diff used to skip a name the output
			// lacked entirely, so an extractor that wrote no data/ at all had
			// the whole category pass unchecked.
			name:    "output holds no data at all",
			golden:  []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}},
			got:     []file{{path: "README.md", content: "# title\n"}},
			wantErr: []string{"data", "CVE-2024-0001.json"},
		},
		{
			name:    "content differs",
			golden:  []file{{path: "README.md", content: "# title\n"}},
			got:     []file{{path: "README.md", content: "# other\n"}},
			wantErr: []string{"README.md", "(-expected +got)"},
		},
		{
			name:   "golden name is URL-escaped",
			golden: []file{{path: "data/oval%3Acom.redhat.rhba%3Aste%3A20070331002.json", content: "{}"}},
			got:    []file{{path: "data/oval:com.redhat.rhba:ste:20070331002.json", content: "{}"}},
		},
		{
			// The output root is a temp directory the test does not choose, and
			// a component of it can be named after a category. The path of a
			// file inside the category must be taken relative to the category's
			// own root, not from the first place its name turns up.
			name:      "output path contains a component named after the category",
			gotParent: "data",
			golden:    []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}},
			got:       []file{{path: "data/2024/CVE-2024-0001.json", content: "{}"}},
		},
		{
			// An extractor that creates its output directory and then has
			// nothing to write for a case leaves the category there but empty.
			// Golden cannot say that, so the two must compare equal.
			name:         "category directory exists but holds nothing",
			gotEmptyDirs: []string{"data"},
		},
		{
			name: "nothing on either side",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()

			goldenDir := filepath.Join(root, "golden")
			if err := write(goldenDir, tt.golden); err != nil {
				t.Fatal("unexpected error:", err)
			}

			gotDir := filepath.Join(root, tt.gotParent, "got")
			if err := write(gotDir, tt.got); err != nil {
				t.Fatal("unexpected error:", err)
			}
			for _, d := range tt.gotEmptyDirs {
				if err := os.MkdirAll(filepath.Join(gotDir, d), os.ModePerm); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			err := utiltest.Diff(goldenDir, gotDir)
			switch {
			case err != nil && len(tt.wantErr) == 0:
				t.Error("unexpected error:", err)
			case err == nil && len(tt.wantErr) > 0:
				t.Errorf("expected error has not occurred, want it to contain %q", tt.wantErr)
			case err != nil:
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Diff() error does not contain %q, error:\n%s", want, err)
					}
				}
			}
		})
	}
}

// write materializes files under root, creating root itself even when there is
// nothing to put in it.
func write(root string, files []file) error {
	if err := os.MkdirAll(root, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", root)
	}

	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Dir(p))
		}
		if err := os.WriteFile(p, []byte(f.content), 0600); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}
	}

	return nil
}

func TestQueryUnescapeFileTree(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []file
		want     []string
		hasError bool
	}{
		{
			name:     "escaped names are decoded",
			fixtures: []file{{path: "definitions/oval%3Aorg.almalinux.alsa%3Adef%3A20227071.json", content: "{}"}},
			want:     []string{"definitions/oval:org.almalinux.alsa:def:20227071.json"},
		},
		{
			name:     "names needing no decoding are copied as they are",
			fixtures: []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
			want:     []string{"2024/CVE-2024-0001.json"},
		},
		{
			// A lone % is not an escape sequence, and a fixture named that way
			// is a mistake worth reporting rather than copying through.
			name:     "name is not a valid escape sequence",
			fixtures: []file{{path: "100%.json", content: "{}"}},
			hasError: true,
		},
		{
			// Materializing this one would put it outside the directory the
			// test asked for, where the test would neither find it nor clean
			// it up.
			name:     "name unescapes to a path outside the destination",
			fixtures: []file{{path: "%2e%2e%2foutside.json", content: "{}"}},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := filepath.Join(t.TempDir(), "fixtures")
			if err := write(fixtureDir, tt.fixtures); err != nil {
				t.Fatal("unexpected error:", err)
			}

			p, err := utiltest.QueryUnescapeFileTree(t.TempDir(), fixtureDir)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if filepath.Base(p) != filepath.Base(fixtureDir) {
					t.Errorf("QueryUnescapeFileTree() = %q, want it to end in %q", p, filepath.Base(fixtureDir))
				}

				var got []string
				if err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					rel, err := filepath.Rel(p, path)
					if err != nil {
						return err
					}
					got = append(got, filepath.ToSlash(rel))
					return nil
				}); err != nil {
					t.Fatal("walk error:", err)
				}
				slices.Sort(got)

				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("QueryUnescapeFileTree(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
