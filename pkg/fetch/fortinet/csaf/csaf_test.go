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
			// The fetch sweeps the output directory before it writes, so an
			// advisory that resolves to nothing leaves nothing behind -- not even
			// what was there before. Putting the rest back is the caller's job.
			name: "sweep",
			args: args{
				args: []string{"FG-IR-24-437"},
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
			// Fortinet encodes its titles twice in XML, so one level of entities
			// outlives the parse. The name is built from the title itself, not
			// from what the leftover "&amp;" would spell.
			name: "encoded-title",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
		},
		{
			// A CSAF is named after its title, so a title holding nothing
			// alphanumeric names nothing there is to fetch.
			name: "unnameable-title",
			args: args{
				args: []string{"FG-IR-25-756"},
			},
			hasError: true,
		},
		{
			// Fortinet answers an ID it has no advisory for with a CVRF skeleton
			// carrying an empty title, not a 404. That is the caller naming an
			// advisory that does not exist, so say so.
			name: "unknown-id",
			args: args{
				args: []string{"FG-IR-99-999"},
			},
			hasError: true,
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
			// The one advisory whose CSAF answers to the title-only name.
			name: "title-only-listed",
			args: args{
				args: []string{"FG-IR-21-173"},
			},
		},
		{
			// Every other advisory leaves that name alone. It is keyed on the
			// title alone and titles repeat, so a file answering to it belongs to
			// whichever advisory holds it -- here, another one entirely.
			name: "title-only-unlisted",
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
