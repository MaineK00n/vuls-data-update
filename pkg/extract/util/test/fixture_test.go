package test_test

import (
	"io/fs"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

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
