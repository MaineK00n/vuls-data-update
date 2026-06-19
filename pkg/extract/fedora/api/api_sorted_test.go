package api_test

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fedora/api"
)

// TestExtractArchitecturesSorted guards the determinism fix: a binary package
// that spans multiple architectures must be serialized with a sorted
// Architectures slice, stably across runs. The golden Diff helper normalizes
// both sides with Sort() before comparing, so it cannot catch an ordering
// regression -- this inspects the raw serialized output instead.
func TestExtractArchitecturesSorted(t *testing.T) {
	// Reuse a real fixture for all the non-build fields, and swap in one build
	// whose single package "zzz-multiarch" exists under several architectures.
	base, err := os.ReadFile(filepath.Join("testdata", "fixtures", "F40", "2025", "FEDORA-2025-fd490bcdcd.json"))
	if err != nil {
		t.Fatal(err)
	}
	var adv map[string]any
	if err := json.Unmarshal(base, &adv); err != nil {
		t.Fatal(err)
	}
	pkg := func(arch string) any {
		return []any{map[string]any{"name": "zzz-multiarch", "version": "1.0", "release": "1.fc40", "arch": arch}}
	}
	adv["builds"] = []any{map[string]any{
		"type": "rpm",
		"nvr":  "zzz-multiarch-1.0-1.fc40",
		"package": map[string]any{
			"x86_64": pkg("x86_64"), "src": pkg("src"), "s390x": pkg("s390x"),
			"ppc64le": pkg("ppc64le"), "i686": pkg("i686"), "aarch64": pkg("aarch64"),
		},
	}}

	in := t.TempDir()
	if err := os.MkdirAll(filepath.Join(in, "F40", "2025"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(adv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "F40", "2025", "FEDORA-2025-fd490bcdcd.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}

	want := []string{"aarch64", "i686", "ppc64le", "s390x", "src", "x86_64"}
	// A single map-iteration order could coincidentally come out sorted, so
	// repeat to make a missing Sort fail reliably.
	for i := 0; i < 8; i++ {
		out := t.TempDir()
		if err := api.Extract(in, api.WithDir(out)); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(out, "data", "F40", "2025", "FEDORA-2025-fd490bcdcd.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		got := findArchitectures(doc, "zzz-multiarch")
		if got == nil {
			t.Fatalf("run %d: package zzz-multiarch not found in output", i)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: Architectures not sorted: got %v, want %v", i, got, want)
		}
	}
}

// findArchitectures walks decoded JSON for a binary package with the given name
// and returns its architectures slice (nil if not found).
func findArchitectures(v any, name string) []string {
	switch t := v.(type) {
	case map[string]any:
		if t["name"] == name {
			if as, ok := t["architectures"].([]any); ok {
				out := make([]string, 0, len(as))
				for _, a := range as {
					out = append(out, a.(string))
				}
				return out
			}
		}
		for _, e := range t {
			if r := findArchitectures(e, name); r != nil {
				return r
			}
		}
	case []any:
		for _, e := range t {
			if r := findArchitectures(e, name); r != nil {
				return r
			}
		}
	}
	return nil
}
