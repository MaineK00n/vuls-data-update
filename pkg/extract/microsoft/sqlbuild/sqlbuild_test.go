package sqlbuild_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/sqlbuild"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixture is the article as fetched, chosen for what decides a chain.
//
// SQL Server 2019 runs the two lines a modern version runs, and runs them
// through the same months: KB5102335 at 15.0.4480.2 and KB5102336 at
// 15.0.2180.2 shipped on one day and replace their own predecessors and not
// each other.
//
// SQL Server 2016 is where the service pack has to be read twice over. Its
// Azure Connect Pack line runs 13.0.7000.253 through 13.0.7085.1, and Microsoft
// stopped filling the Service pack column in partway along it, so the last of
// the four names no service pack anywhere and takes SP3 from the build below it.
// Without that the article's one chain of four is two, of three and one.
//
// Its SP1 baseline at 13.0.4001.0 is what both SP1 lines are built on, and is
// superseded by the SP1 CU and the SP1 GDR alike. Its RTM GDR pair is the shape
// the build order has to be trusted through: 13.0.4202.2 is filed under RTM
// while its build number says SP1, so it comes after 13.0.1745.2 by build and
// thirteen months before it by date.
//
// SQL Server 2008 is why the service pack is in the key at all. Its RTM CU9 at
// 10.00.1835.0 shipped in March 2010, eleven months after its SP1 CU2 at
// 10.00.2710.0, so ordering the version's cumulative updates as one line by
// build number has the older one replacing the newer.
//
// SQL Server 2005 carries the QFE line, which GDR ran beside rather than after.
//
// Three rows name a release date Microsoft wrote by hand -- "Friday, June 27,
// 2014", "March 21,2016", "July 16 2018" -- and two name no kind of update at
// all, which leaves them recorded and unchained rather than guessed at.
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
			err := sqlbuild.Extract(tt.args, sqlbuild.WithDir(dir))
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

// The line an update belongs to is the whole of what keeps SQL Server's parallel
// servicing apart, and it is read from a label Microsoft writes many ways. The
// order the cases are asked in decides most of these: "CU25 + GDR" names both a
// cumulative update and a GDR, and is a cumulative update.
func TestLine(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  string
	}{
		{name: "a cumulative update", label: "CU26", want: "cu"},
		{name: "a cumulative update carrying a security fix is still one", label: "CU25 + GDR", want: "cu"},
		{name: "a cumulative update named in full", label: "SQL Server 2014 SP3 CU4 + GDR", want: "cu"},
		{name: "a general distribution release", label: "GDR", want: "gdr"},
		{name: "one named as a security update", label: "GDR Security Update", want: "gdr"},
		{name: "one named after its bulletin", label: "MS15-058: GDR Security Update", want: "gdr"},
		{name: "one whose bulletin has no colon", label: "MS16-136 GDR Security Update", want: "gdr"},
		{name: "the hotfix line GDR ran beside", label: "MS12-070: QFE Security update", want: "qfe"},
		{name: "the feature pack serviced on its own", label: "Azure Connect Pack + GDR", want: "azure-connect-pack"},
		{name: "which Microsoft has also written in lower case", label: "Azure Connect pack", want: "azure-connect-pack"},
		{name: "a product release", label: "RTM", want: "baseline"},
		{name: "a service pack release", label: "RTW/PCU1", want: "baseline"},
		{name: "the same, spaced", label: "RTW / PCU 1", want: "baseline"},
		{name: "general availability", label: "RTM/GA", want: "baseline"},
		{name: "a row naming no kind at all", label: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, sqlbuild.Line(tt.label)); diff != "" {
				t.Errorf("line(). (-expected +got):\n%s", diff)
			}
		})
	}
}

// The service pack is read from the column that names it, and from the label
// where Microsoft has stopped filling that column in.
func TestServicePack(t *testing.T) {
	tests := []struct {
		name   string
		column string
		label  string
		want   string
	}{
		{name: "the column names it", column: "SP3", label: "GDR", want: "SP3"},
		{name: "the column names the product release", column: "RTM", label: "CU9", want: "RTM"},
		{name: "the column is empty and the label names it", column: "None", label: "SP3 + GDR", want: "SP3"},
		{name: "the label names it in full", column: "None", label: "SQL Server 2014 SP3 CU4 + GDR", want: "SP3"},
		{name: "neither names one", column: "None", label: "Azure Connect Pack + GDR", want: ""},
		{name: "a version that has no service packs", column: "None", label: "CU32 + GDR", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, sqlbuild.ServicePack(tt.column, tt.label)); diff != "" {
				t.Errorf("servicePack(). (-expected +got):\n%s", diff)
			}
		})
	}
}

// The release date is prose in a hand-authored article, and Microsoft has
// written it four ways across 586 rows.
func TestReleaseDate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want time.Time
		ok   bool
	}{
		{name: "as written almost everywhere", s: "July 16, 2026", want: time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "with the day zero-padded", s: "October 09, 2012", want: time.Date(2012, time.October, 9, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "with no comma", s: "July 16 2018", want: time.Date(2018, time.July, 16, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "with no space after the comma", s: "March 21,2016", want: time.Date(2016, time.March, 21, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "opening with the day of the week", s: "Friday, June 27, 2014", want: time.Date(2014, time.June, 27, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "not a date", s: "n/a", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sqlbuild.ReleaseDate(tt.s)
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
