package servicing_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/servicing"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixtures are articles as fetched, chosen for what decides a chain.
//
// dotnetframework/windows-11/22h2 carries no build numbers, so its six are
// ordered by the date in the title -- which four of them file under a folder
// month that is not their release month, the shape the path must not be trusted
// for. Two of the six share a release date, from the months this line ran as a
// 22H2 and a 23H2 package before merging back: they take the month before them
// each, and neither supersedes the other.
//
// 25h2 and 26h1 are filed with no month at all, which is what the series has to
// read the path carefully enough to see. They are lines of their own, and the
// May 2026 article of each shares its date with the other's without joining it.
//
// os/windows-10 holds the two titles that are punctuated like no others, "KB
// 3216755" spaced and "March 18 2021" without its comma, both of which read as
// no update at all if taken literally.
//
// os/windows-11 carries build numbers, and holds three lines at once. 26200 and
// 26100 run together; 28000 is a version of its own and links to neither. The
// cumulative update of the second Tuesday and the out-of-band and Preview that
// follow it are separate lines too, in the same builds -- the July 28th Preview
// at .8973 supersedes the July 18th Out-of-band at .8894 and not the 14th's
// cumulative update, which the next month's will.
//
// os/windows-server is there for the build number that is not unique: Windows
// Server 2025 is 26100 as Windows 11 24H2 is, with its own KB at a revision
// Windows 11 also ships. It belongs to neither of the other chains.
//
// The last two name no KB. A series listing carries its hub page and its end of
// servicing statement alongside the updates, and neither is one.
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
			err := servicing.Extract(tt.args, servicing.WithDir(dir))
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
