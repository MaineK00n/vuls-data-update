package test_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

type file struct {
	path    string
	content string
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name string
		// noGolden leaves the golden directory uncreated, for the case whose
		// expected output is nothing at all.
		noGolden bool
		golden   []file
		got      []file
		opts     []utiltest.Option
		// wantErr lists substrings the reported error must contain. Empty means
		// the trees must compare equal.
		wantErr []string
	}{
		{
			name:   "equal trees",
			golden: []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
			got:    []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
		},
		{
			name:    "file the writer did not write",
			golden:  []file{{path: "2024/CVE-2024-0001.json", content: "{}"}, {path: "2024/CVE-2024-0002.json", content: "{}"}},
			got:     []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
			wantErr: []string{"2024/CVE-2024-0002.json"},
		},
		{
			name:    "file golden does not describe",
			golden:  []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
			got:     []file{{path: "2024/CVE-2024-0001.json", content: "{}"}, {path: "2024/CVE-2024-0002.json", content: "{}"}},
			wantErr: []string{"2024/CVE-2024-0002.json"},
		},
		{
			name:    "content differs",
			golden:  []file{{path: "2024/CVE-2024-0001.json", content: `{"id": "CVE-2024-0001"}`}},
			got:     []file{{path: "2024/CVE-2024-0001.json", content: `{"id": "CVE-2024-9999"}`}},
			wantErr: []string{"(-expected +got)", "CVE-2024-9999"},
		},
		{
			// Golden carries the escaped name, the fetcher writes the raw one.
			name:   "golden name is URL-escaped",
			golden: []file{{path: "states/oval%3Acom.redhat.rhba%3Aste%3A20070331002.json", content: "{}"}},
			got:    []file{{path: "states/oval:com.redhat.rhba:ste:20070331002.json", content: "{}"}},
		},
		{
			name:     "no golden directory and nothing written",
			noGolden: true,
		},
		{
			name:     "no golden directory but something written",
			noGolden: true,
			got:      []file{{path: "2024/CVE-2024-0001.json", content: "{}"}},
			wantErr:  []string{"2024/CVE-2024-0001.json"},
		},
		{
			name:   "test server URL replaced before comparing",
			golden: []file{{path: "2024/CVE-2024-0001.json", content: `{"url": "https://example.com/a"}`}},
			got:    []file{{path: "2024/CVE-2024-0001.json", content: `{"url": "http://127.0.0.1:34567/a"}`}},
			opts:   []utiltest.Option{utiltest.WithReplace("http://127.0.0.1:34567", "https://example.com")},
		},
		{
			name:    "replacement does not hide a real difference",
			golden:  []file{{path: "2024/CVE-2024-0001.json", content: `{"url": "https://example.com/a"}`}},
			got:     []file{{path: "2024/CVE-2024-0001.json", content: `{"url": "http://127.0.0.1:34567/b"}`}},
			opts:    []utiltest.Option{utiltest.WithReplace("http://127.0.0.1:34567", "https://example.com")},
			wantErr: []string{"(-expected +got)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()

			goldenDir := filepath.Join(root, "golden")
			if !tt.noGolden {
				if err := write(goldenDir, tt.golden); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			gotDir := filepath.Join(root, "got")
			if err := write(gotDir, tt.got); err != nil {
				t.Fatal("unexpected error:", err)
			}

			err := utiltest.Diff(goldenDir, gotDir, tt.opts...)
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
