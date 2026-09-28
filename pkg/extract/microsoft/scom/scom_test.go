package scom_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/scom"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixture is the article and its includes as fetched.
//
// An update rollup is one KB and three builds -- the management server, the
// agent and gateway and the SCX agent each advance on their own numbers -- so
// the component is the chain and a KB takes its place in each of them. The
// components do not advance in step: Operations Manager 2025's agent skipped a
// rollup its management server took, which is why KB5068304 is superseded by
// two KBs rather than one.
//
// Which product version a table is for is in neither the table nor the file it
// sits in. The article is INCLUDE directives, and the file each pulls in is
// named for the version, so the path is what says it -- and the article itself,
// along with the note one of its includes brings in, holds no tables at all.
//
// The KB is a bare number linked to the support site, so it is read from the
// link. The SCX agent's tables put a version linked to a GitHub release in the
// same column, and the general availability rows leave it empty or write a
// dash; none of the three is a KB.
func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures/happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := scom.Extract(tt.args, scom.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}

// The product a table is for is in the path of the file it was included from,
// and in nothing else.
func TestVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "an included table file", raw: "SystemCenterDocs/includes/release-build-versions-2025.json", want: "System Center 2025 - Operations Manager", ok: true},
		{name: "another", raw: "SystemCenterDocs/includes/release-build-versions-2016.json", want: "System Center 2016 - Operations Manager", ok: true},
		{name: "the article that includes them", raw: "SystemCenterDocs/scom/release-build-versions.json", ok: false},
		{name: "a note one of them brings in", raw: "SystemCenterDocs/includes/discontinue-spf-2025.json", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := scom.Version(tt.raw)
			if ok != tt.ok {
				t.Fatalf("version() ok = %v, want %v", ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("version(). (-expected +got):\n%s", diff)
			}
		})
	}
}

// Every row of the article is a month with no day.
func TestReleaseDate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want time.Time
		ok   bool
	}{
		{name: "a month", s: "November 2025", want: time.Date(2025, time.November, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "another", s: "September 2016", want: time.Date(2016, time.September, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a month that is not one", s: "Smarch 2016", ok: false},
		{name: "nothing", s: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := scom.ReleaseDate(tt.s)
			if ok != tt.ok {
				t.Fatalf("releaseDate() ok = %v, want %v", ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("releaseDate(). (-expected +got):\n%s", diff)
			}
		})
	}
}
