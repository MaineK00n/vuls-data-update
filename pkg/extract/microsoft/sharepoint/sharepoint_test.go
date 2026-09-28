package sharepoint_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/sharepoint"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixture is the page as fetched, chosen for what decides a chain.
//
// A row is two updates wherever it names two packages, and the two are not one
// line: KB5002894 and KB5002896 shipped on the same day in the same row, one
// for SharePoint Server 2019 and one for its language pack, and neither
// replaces the other. On 2013 the pair is SharePoint Foundation beside
// SharePoint Server, a different product again.
//
// SharePoint Foundation 2010 is where that matters most. Its row for June 2015
// reads "No update for June." beside SharePoint Server 2010's KB3054880, so the
// Foundation chain runs straight from April 2015 to April 2021 while the Server
// chain takes the June release in between. Reading the row as one update would
// hand Foundation a KB it never shipped.
//
// The 2016 rows write the version once per package and the others once for the
// row, so the version has to be taken per package where there is one and shared
// where there is not.
//
// Dates come three ways -- "August 11, 2026", "April 2023" and "Service Pack 2
// July 2013" -- and most of the page has no day at all, which is why the
// version orders these and the date does not. Several 2010 KBs are written as
// text with no link, and those records carry no URL rather than a made-up one.
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
			err := sharepoint.Extract(tt.args, sharepoint.WithDir(dir))
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

// Most of the page is dated by month alone, so a month has to read as a date at
// all, and two rows put a service pack in front of one.
func TestReleaseDate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want time.Time
		ok   bool
	}{
		{name: "a full date", s: "August 11, 2026", want: time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a single-digit day", s: "June 9, 2026", want: time.Date(2026, time.June, 9, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a month with no day, which is most of the page", s: "April 2023", want: time.Date(2023, time.April, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a month behind a service pack", s: "Service Pack 2 July 2013", want: time.Date(2013, time.July, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "not a date", s: "No update for June.", ok: false},
		{name: "nothing", s: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sharepoint.ReleaseDate(tt.s)
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
