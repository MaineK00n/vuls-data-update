package servicing_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/servicing"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixtures are articles as fetched, chosen for what decides a chain.
//
// dotnetframework/windows-11/22h2 carries no build numbers, so its six are
// ordered by the date in the title -- which four of them file under a folder
// month that is not their release month, the shape the path must not be trusted
// for.
//
// Two of the six share a release date, from the months this directory held two
// lines: a 22H2 and a 23H2 package, run side by side before merging back. They
// do not supersede each other, and the August article before them is taken up
// by the 22H2 of September alone, which is the edge msuc records -- the title's
// products decide which of a shared date links, because the directory has said
// they are one line and is wrong.
//
// 25h2 and 26h1 are filed with no month at all, which is what the series has to
// read the path carefully enough to see. They are lines of their own, and the
// May 2026 article of each shares its date with the other's without joining it.
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
// os/windows-10 holds the two titles that are punctuated like no others, "KB
// 3216755" spaced and "March 18 2021" without its comma, both of which read as
// no update at all if taken literally.
//
// os/windows-7 holds the one "(Monthly rollup)" Microsoft has spelled in lower
// case, against the November rollup that supersedes it.
//
// os/windows holds the two Microsoft filed away from their build lines, which
// run in full under os/windows-10. Nothing about either article is wrong, so
// they are read correctly and chain to nothing -- the failure no other warning
// can see, and the reason there is one that can.
//
// Two articles name no KB. A series listing carries its hub page and its end of
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

// The products a title names are only ever consulted to tell two articles of
// one date and one directory apart, and two count as one line on any overlap at
// all. So a release read out of a title that does not name one can only join
// lines that should be apart, and would do it silently -- there is no output to
// notice it in. These are the shapes that decide it.
func TestProducts(t *testing.T) {
	tests := []struct {
		name  string
		title string
		want  []string
	}{
		{
			name:  "one release",
			title: "October 14, 2025-KB5066128 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 25H2",
			want:  []string{"25h2"},
		},
		{
			name:  "two releases, the shape a shared date has to be told apart by",
			title: "November 14, 2023-KB5032007 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 22H2 and Windows 11, version 23H2",
			want:  []string{"22h2", "23h2"},
		},
		{
			name:  "a build number is not a release",
			title: "April 14, 2026-KB5084165 Cumulative Update for .NET Framework 3.5 for Windows 11, version 26H1 (build 28000) and later",
			want:  []string{"26h1"},
		},
		{
			name:  "nor is a build number with a revision",
			title: "April 14, 2026-KB5084165 Cumulative Update for .NET Framework 3.5 for Windows 11, version 26H1 (build 28000.2525) and later",
			want:  []string{"26h1"},
		},
		{
			name:  "a year-shaped release still is",
			title: "July 14, 2026-KB5101005 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows Server 2022",
			want:  []string{"2022"},
		},
		{
			name:  "the version list is not the product list",
			title: "July 14, 2026-Security and Quality Rollup for .NET Framework 3.5, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 for Windows Server 2012 R2 (KB5102205)",
			want:  []string{"2012"},
		},
		{
			name:  "an OS title names none, and leaves the product to the directory",
			title: "October 11, 2016 — KB3185330 (Monthly rollup)",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, servicing.Products(tt.title)); diff != "" {
				t.Errorf("products(). (-expected +got):\n%s", diff)
			}
		})
	}
}
