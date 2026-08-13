package exchange_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/exchange"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixture is the page as fetched, chosen for what decides a chain.
//
// Exchange services every supported cumulative update level side by side, and
// the build number says which: KB5121574 at 15.2.1748.49 and KB5121575 at
// 15.2.1544.44 shipped on one day for Exchange Server 2019, the first for hosts
// on CU15 and the second for hosts on CU14, and neither reaches the other's.
// Ordering the version's updates as one line by build number would have the
// CU14 update replaced by a CU15 one that will never be offered to it.
//
// KB5000871 is on four rows across three product versions, which is what the
// March 2021 update was: every supported cumulative update level got its own
// patched build of the one fix. It takes its place in each of those lanes.
//
// Exchange Server SE and Exchange Server 2019 are both 15.2, so the table is
// part of the key -- KB5121573 at 15.2.2562.46 has nothing to do with Exchange
// 2019's chains.
//
// Rows that ship as downloads carry no KB: a cumulative update, and Exchange
// Server SE's own release, link to the Download Center instead. Exchange Server
// 2003 is listed with a column set of its own. None of them is an update this
// can chain, and none is reported as a failure to read one.
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
			err := exchange.Extract(tt.args, exchange.WithDir(dir))
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
