package csaf_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

func TestFetch(t *testing.T) {
	type args struct {
		args []string
	}
	tests := []struct {
		name string
		args args
		// seed is a fixture directory laid into the output directory before the
		// fetch, standing in for the advisories a previous run left there.
		seed     string
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
		},
		{
			// The title on disk names the CSAF, so no CVRF is served here: the
			// fetch has to resolve the advisory without asking for one.
			name: "stored-title",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
			seed: "seed",
		},
		{
			name: "invalid-csaf",
			args: args{
				args: []string{"FG-IR-25-771"},
			},
		},
		{
			// No CSAF answers to any name the title yields -- the advisory
			// carries none, or its CSAF has been renamed. Neither is an error;
			// the advisory is skipped and the caller keeps what it holds.
			name: "not-found",
			args: args{
				args: []string{"FG-IR-24-437"},
			},
		},
		{
			// The name carrying the ID leaves no room for another advisory to
			// own it, so a file answering to it that tracks a different one means
			// upstream contradicts itself.
			name: "id-mismatch",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
			hasError: true,
		},
		{
			// Titles repeat, so the name without the ID is shared ground: the
			// advisory that holds it answers for everyone whose title slugs to
			// it. That is this advisory missing its CSAF, not a run to fail.
			name: "title-collision",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtures := filepath.Join("testdata", "fixtures", tt.name)

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name, contentType := func() (string, string) {
					if rest, ok := strings.CutPrefix(r.URL.Path, "/psirt/cvrf/"); ok {
						return rest, "application/xml"
					}
					return path.Base(r.URL.Path), "application/json"
				}()

				bs, err := os.ReadFile(filepath.Join(fixtures, name))
				if err != nil {
					http.NotFound(w, r)
					return
				}

				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write(bs)
			}))
			defer ts.Close()

			dir := t.TempDir()
			if tt.seed != "" {
				if err := os.CopyFS(dir, os.DirFS(filepath.Join(fixtures, tt.seed))); err != nil {
					t.Fatal("seed error:", err)
				}
			}

			err := csaf.Fetch(tt.args.args,
				csaf.WithCSAFURL(fmt.Sprintf("%s/fortiguard/psirt/%%s", ts.URL)),
				csaf.WithCVRFURL(fmt.Sprintf("%s/psirt/cvrf/%%s", ts.URL)),
				csaf.WithDir(dir), csaf.WithRetry(0), csaf.WithConcurrency(2))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case tt.hasError:
			default:
				golden := filepath.Join("testdata", "golden", tt.name)

				want, got := files(t, golden), files(t, dir)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch() files. (-expected +got):\n%s", diff)
				}

				for _, name := range got {
					if !slices.Contains(want, name) {
						continue
					}

					expected, err := os.ReadFile(filepath.Join(golden, name))
					if err != nil {
						t.Error("read error:", err)
						continue
					}

					actual, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil {
						t.Error("read error:", err)
						continue
					}

					if diff := cmp.Diff(expected, actual); diff != "" {
						t.Errorf("Fetch() %s. (-expected +got):\n%s", name, diff)
					}
				}
			}
		})
	}
}

// files lists the paths under root, relative to it and sorted. A root that does
// not exist holds none, which is how a case that expects no output says so.
func files(t *testing.T, root string) []string {
	t.Helper()

	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal("stat error:", err)
	}

	var paths []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, rel)

		return nil
	}); err != nil {
		t.Fatal("walk error:", err)
	}

	slices.Sort(paths)

	return paths
}
