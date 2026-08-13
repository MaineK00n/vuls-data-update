package releaseinfo_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/releaseinfo"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

// The fixtures are the tables as fetched, chosen for what decides a chain.
//
// Windows 10 1507 is one month written out in full: A on the 5th, B on the
// 11th, OOB on the 14th, C on the 18th, D on the 27th, then the B of September.
// Microsoft's revisions run straight through the six, .16413 to .16487, so
// ordering by revision alone threads them into one line and has the September
// security update replacing an August preview that nothing ever took up. Split
// by the letter it is two: .16430 to .16487, and .16413 to .16433 to .16445 to
// .16463.
//
// 1709 is January 2018, where the security update shipped on the 3rd rather
// than on a second Tuesday, and two out-of-band releases and a preview followed
// it at revisions above it. Asking the calendar which line the 3rd belongs to
// puts the month's security update among the optional ones and leaves the
// December one superseded by a preview; asking Microsoft puts it where it
// belongs.
//
// Windows 11 24H2 and Windows Server 2025 are both 26100, and neither their
// release histories nor their hotpatch calendars have anything to do with each
// other. KB5121003 is 26100.9168 on one page while KB5120233 is 26100.33296 on
// the other, so a chain keyed on the build alone would have each superseding the
// other's updates.
//
// The Server hotpatch calendar shares KB5094125 with its release history, being
// the June baseline and the June cumulative update at once. It takes its place
// in both chains, which is what a baseline is: it supersedes May's hotpatch and
// May's cumulative update, and neither of those touches the other.
//
// Server 2025 also runs an optional line through the same builds, and it is not
// the hotpatch one. KB5091157 is .32698, between April's baseline at .32690 and
// May's hotpatch at .32772, so a chain that took "not the second Tuesday" for
// one line would splice an out-of-band cumulative update into the middle of a
// hotpatch quarter. Its predecessor is January's out-of-band release, 462
// revisions below it.
//
// The Server 2025 RTM row names no KB, being the release rather than an update
// to it. Rows like that are not the hotpatch calendars' alone.
//
// KB5101684 and KB5121767 are the pair whose KB numbers run backwards against
// their builds -- the July 28th preview at .8973 supersedes the July 18th
// out-of-band at .8894 -- so a chain that fell back on the number would invert
// them.
//
// One hotpatch row names no KB, being a month the calendar has reached and
// Microsoft has not shipped; one carries a cell more than its header names; one
// carries an asterisk after its cadence letter. None of the three is an update
// that can be dropped for being oddly written.
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
			err := releaseinfo.Extract(tt.args, releaseinfo.WithDir(dir))
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

// The release name is what a KB record says it is for, and the label it is read
// off is written two ways: Windows Server names its product in full, Windows 10
// and 11 say only the version and leave the product to the page. A hotpatch
// calendar names neither, being filed under the year.
func TestRelease(t *testing.T) {
	tests := []struct {
		name  string
		page  string
		label string
		want  string
	}{
		{
			name:  "a Windows 10 label leaves the product to the page",
			page:  "windows-10",
			label: "Version 22H2 (OS build 19045)",
			want:  "Windows 10 Version 22H2",
		},
		{
			name:  "as does a Windows 11 one",
			page:  "windows-11",
			label: "Version 24H2 (OS build 26100)",
			want:  "Windows 11 Version 24H2",
		},
		{
			name:  "the first release of all carries a parenthesis of its own",
			page:  "windows-10",
			label: "Version 1507 (RTM) (OS build 10240)",
			want:  "Windows 10 Version 1507 (RTM)",
		},
		{
			name:  "a Windows Server label names its product in full",
			page:  "windows-server",
			label: "Windows Server 2016 (OS build 14393)",
			want:  "Windows Server 2016",
		},
		{
			name:  "a hotpatch calendar names no release",
			page:  "windows-server",
			label: "Calendar year 2026",
			want:  "Calendar year 2026",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, releaseinfo.Release(tt.page, tt.label)); diff != "" {
				t.Errorf("release(). (-expected +got):\n%s", diff)
			}
		})
	}
}
