package sfb_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/sfb"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixture is the page as fetched, chosen for what decides a chain.
//
// There is no build number to order these by -- the Subscription Edition's
// table has one and no other table does -- so the date is the order, and the
// date is a month. Lync Server 2013 runs the full shape: September 2014 to
// February 2021 to May 2021 to April 2022 to July 2022, each month superseding
// the one before it.
//
// KB4470124, KB5065372 and KB2493736 are on two rows of different months each,
// which is Microsoft revising one article in place for every hotfix of a
// cumulative update line -- fifteen rows of it on the real page. "KB4470124 is
// installed" does not say which of them a host has, so it is recorded and left
// unchained rather than given a place it does not have.
//
// KB5016714 is on two rows of one month, which is the opposite case: one July
// 2022 update listed under both products it was released for. It is chained in
// both.
//
// One row names two KBs in one cell, KB5000675 and KB5000688, with only the
// first linked. They are siblings of one release, so both supersede the
// February 2021 update before them and both are superseded by the May 2021 one
// after.
//
// A tools table sits among the update histories and names no KB column at all;
// ten of the page's sixteen tables are like it.
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
			err := sfb.Extract(tt.args, sfb.WithDir(dir))
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

// The date is the whole order here, so every shape the page writes one in has to
// read. Almost all of them are a month with no day.
func TestReleaseDate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want time.Time
		ok   bool
	}{
		{name: "a month, which is all but four rows", s: "August 2025", want: time.Date(2025, time.August, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a month with a day", s: "May 11, 2021", want: time.Date(2021, time.May, 11, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "a month Microsoft abbreviated", s: "Sept 2014", want: time.Date(2014, time.September, 1, 0, 0, 0, 0, time.UTC), ok: true},
		{name: "not a date", s: "n/a", ok: false},
		{name: "a month that is not one", s: "Smarch 2014", ok: false},
		{name: "nothing", s: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sfb.ReleaseDate(tt.s)
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
