package packagemanifest_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	pm "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/packagemanifest"
)

type tableNoSource struct {
	Title   string              `json:"title"`
	ID      string              `json:"id"`
	Headers []string            `json:"headers"`
	Rows    []map[string]string `json:"rows"`
}

// loadHTMLFromFile reads a plain HTML fixture file.
func loadHTMLFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readTableNoSource(path string) (tableNoSource, error) {
	var tns tableNoSource
	b, err := os.ReadFile(path)
	if err != nil {
		return tns, err
	}
	// unmarshal into full struct then strip Source implicitly by using tableNoSource
	var full struct {
		Title   string              `json:"title"`
		ID      string              `json:"id"`
		Headers []string            `json:"headers"`
		Rows    []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal(b, &full); err != nil {
		return tns, err
	}
	return tableNoSource{Title: full.Title, ID: full.ID, Headers: full.Headers, Rows: full.Rows}, nil
}

func TestFetch(t *testing.T) {
	majors := []int{8, 9, 10}

	// Load HTML from plain .html fixtures
	htmlByMajor := map[int]string{}
	for _, m := range majors {
		p := filepath.Join("testdata", "fixtures", fmt.Sprintf("rhel-%d.html", m))
		html, err := loadHTMLFromFile(p)
		if err != nil {
			// Provide guidance if file missing
			files, _ := os.ReadDir(filepath.Join("testdata", "fixtures"))
			var list []string
			for _, f := range files {
				list = append(list, f.Name())
			}
			t.Fatalf("load fixture %s: %v (fixtures: %v)", p, err, list)
		}
		htmlByMajor[m] = html
	}

	// HTTP test server serving the HTML by simple path pattern /rhel-<major>.html
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, m := range majors {
			if r.URL.Path == fmt.Sprintf("/rhel-%d.html", m) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w, htmlByMajor[m])
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Temporary output directory
	dir := t.TempDir()

	// Run Fetch against our server with overridden base and directory
	if err := pm.Fetch(
		pm.WithMajors(majors...),
		pm.WithBase(ts.URL+"/rhel-%d.html"),
		pm.WithDir(dir),
		pm.WithRetry(0),
	); err != nil {
		// Provide directory listing for debugging
		entries, _ := os.ReadDir(dir)
		var list []string
		for _, e := range entries {
			list = append(list, e.Name())
		}
		t.Fatalf("Fetch error: %v (out root entries: %v)", err, list)
	}

	// Compare produced JSON with golden (ignoring Source field)
	for _, m := range majors {
		goldenDir := filepath.Join("testdata", "golden", fmt.Sprintf("%d", m))
		outDir := filepath.Join(dir, fmt.Sprintf("%d", m))

		// Gather golden files
		entries, err := os.ReadDir(goldenDir)
		if err != nil {
			t.Fatalf("read golden dir %s: %v", goldenDir, err)
		}

		seen := map[string]struct{}{}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			goldPath := filepath.Join(goldenDir, e.Name())
			gotPath := filepath.Join(outDir, e.Name())
			gold, err := readTableNoSource(goldPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldPath, err)
			}
			got, err := readTableNoSource(gotPath)
			if err != nil {
				// Provide context listing files when missing
				files, _ := os.ReadDir(outDir)
				var list []string
				for _, f := range files {
					list = append(list, f.Name())
				}
				t.Fatalf("read output %s: %v (have: %v)", gotPath, err, list)
			}
			if diff := cmp.Diff(gold, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("major %d file %s mismatch (-want +got):\n%s", m, e.Name(), diff)
			}
			seen[e.Name()] = struct{}{}
		}

		// Ensure no unexpected extra files
		if err := filepath.WalkDir(outDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			_, name := filepath.Split(path)
			if filepath.Ext(name) == ".json" {
				if _, ok := seen[name]; !ok {
					return fmt.Errorf("unexpected extra file %s", name)
				}
			}
			return nil
		}); err != nil {
			t.Errorf("major %d: %v", m, err)
		}
	}
}
