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

// Updated struct matching new schema (ignoring Source for comparison).
// Use concrete row structs for packages/modules to reflect nested arrays correctly.
type packageRow struct {
	Package                       string `json:"package"`
	License                       string `json:"license,omitempty"`
	ApplicationCompatibilityLevel string `json:"application_compatibility_level,omitempty"`
	RHEL9MinorReleaseVersion      string `json:"rhel_9_minor_release_version,omitempty"`
	RHEL10MinorReleaseVersion     string `json:"rhel_10_minor_release_version,omitempty"`
}

type moduleRow struct {
	Module                        string   `json:"module"`
	Stream                        string   `json:"stream"`
	ApplicationCompatibilityLevel string   `json:"application_compatibility_level,omitempty"`
	Packages                      []string `json:"packages"`
}

type manifestTable struct {
	Title      string              `json:"title"`
	Section    string              `json:"section"`
	ID         string              `json:"id"`
	Repository string              `json:"repository"`
	Type       string              `json:"type"`
	Headers    []string            `json:"headers,omitempty"`
	Rows       []map[string]string `json:"rows,omitempty"`
	Packages   []packageRow        `json:"packages,omitempty"`
	Modules    []moduleRow         `json:"modules,omitempty"`
	Source     string              `json:"source"`
}

// loadHTMLFromFile reads a plain HTML fixture file.
func loadHTMLFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readManifestTable(path string) (manifestTable, error) {
	var mt manifestTable
	b, err := os.ReadFile(path)
	if err != nil {
		return mt, err
	}
	if err := json.Unmarshal(b, &mt); err != nil {
		return mt, err
	}
	return mt, nil
}

func TestFetch(t *testing.T) {
	majors := []int{8, 9, 10}

	// Load HTML fixtures (.html)
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

			gold, err := readManifestTable(goldPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldPath, err)
			}
			got, err := readManifestTable(gotPath)
			if err != nil {
				// Provide context listing files when missing
				files, _ := os.ReadDir(outDir)
				var list []string
				for _, f := range files {
					list = append(list, f.Name())
				}
				t.Fatalf("read output %s: %v (have: %v)", gotPath, err, list)
			}

			// Convert specialized tables to generic comparable shape if needed
			// (Packages/Modules already map[string]string slices; keep as-is)
			if diff := cmp.Diff(gold, got, cmpopts.IgnoreFields(manifestTable{}, "Source"), cmpopts.EquateEmpty()); diff != "" {
				// Table mismatch
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
			// Non-fatal to collect all diffs
			t.Errorf("major %d: %v", m, err)
		}
	}
}
