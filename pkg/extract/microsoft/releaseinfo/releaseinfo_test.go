package releaseinfo_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/releaseinfo"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	fetchReleaseinfo "github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/releaseinfo"
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
// the June baseline and the June cumulative update at once. It is chained as the
// cumulative update: it supersedes May's cumulative update and not May's
// hotpatch, which nothing supersedes.
//
// April's baseline does not supersede May's hotpatch, nor January's February's
// on Windows 11, nor August 2024's September's on Windows Server 2022. A
// hotpatch installs on top of its baseline rather than in place of it, and the
// next baseline restarts the series rather than continuing it, so the
// quarter's hotpatch line runs from its first hotpatch to its last and touches
// no baseline.
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
// KB3185611 and KB3193821 are both 10240.17113, a week apart under one B, so
// the revision cannot order them and the release date does. The KB numbers run
// the same way here, as they do in all five pairs of this kind on the pages, so
// the fixture cannot tell the date from the number falling back behind it.
// KB5061977 is on the Windows 11 and the Windows Server page alike, and its
// record carries both pages as its raws.
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
		{
			// A hotpatch calendar is named after the release history covering
			// its build. Without one, that history is gone from the page, and
			// its KBs would be written unnamed and off their monthly chain.
			name:     "hotpatch calendar without its release history",
			args:     "./testdata/fixtures/hotpatch-without-history",
			hasError: true,
		},
		{
			// A history's label is the only thing naming its release. One that
			// names another build than its rows would name every KB after the
			// wrong release.
			name:     "release history labelled with another build",
			args:     "./testdata/fixtures/label-mismatch",
			hasError: true,
		},
		{
			// A hotpatch calendar whose Type column is renamed reads as a
			// history, which would chain its hotpatches across the baselines
			// between them. Its "Calendar year" label names no build, and that stops it.
			name:     "hotpatch calendar without its Type column",
			args:     "./testdata/fixtures/type-renamed",
			hasError: true,
		},
		{
			// A hotpatch links from those of the month before, so a calendar
			// row whose date cannot be read cannot be placed.
			name:     "hotpatch calendar row without its date",
			args:     "./testdata/fixtures/hotpatch-without-date",
			hasError: true,
		},
		{
			// A baseline dropped for its build would chain the hotpatches
			// either side of it into one quarter.
			name:     "hotpatch calendar row without its build",
			args:     "./testdata/fixtures/hotpatch-without-build",
			hasError: true,
		},
		{
			// July's KB listed again at a build past August's would have it and
			// August's superseding each other.
			name:     "KB listed twice on one line",
			args:     "./testdata/fixtures/duplicate-kb",
			hasError: true,
		},
		{
			// Every table of one page skipped, here for a renamed KB column,
			// reads as no updates from it while the other pages read fine. That
			// is not a dataset to replace the last one with.
			name:     "no update read",
			args:     "./testdata/fixtures/no-update",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// A run that fails leaves the last good output where it was.
			sentinel := filepath.Join(dir, "sentinel")
			if err := os.WriteFile(sentinel, nil, 0666); err != nil {
				t.Fatalf("write %s: %v", sentinel, err)
			}
			err := releaseinfo.Extract(tt.args, releaseinfo.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				if _, err := os.Stat(sentinel); err != nil {
					t.Errorf("unexpected output cleared on error: %v", err)
				}
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
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

// The pages give every pair of updates sharing a revision a later date to the
// higher KB number, so the fixtures cannot tell the date deciding from the
// number falling back behind it. These pairs run the number against the date.
func TestChain(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, time.January, d, 0, 0, 0, 0, time.UTC) }

	tests := []struct {
		name string
		us   []releaseinfo.Update
		want map[string][]string
	}{
		{
			name: "the later date supersedes at a shared revision, whatever the KB numbers say",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000001", 100, day(8)),
				releaseinfo.NewUpdate("5000002", 100, day(1)),
			},
			want: map[string][]string{"5000001": {"5000002"}},
		},
		{
			name: "the KB number decides only where the date ties as well",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000002", 100, day(1)),
				releaseinfo.NewUpdate("5000001", 100, day(1)),
			},
			want: map[string][]string{"5000002": {"5000001"}},
		},
		{
			name: "a KB listed again at the next build does not supersede itself",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000003", 102, day(15)),
				releaseinfo.NewUpdate("5000001", 101, day(8)),
				releaseinfo.NewUpdate("5000001", 100, day(1)),
			},
			want: map[string][]string{"5000003": {"5000001"}},
		},
		{
			name: "an out-of-band hotpatch takes its month's monthly edge and is superseded by nothing, and a baseline restarts the line",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000001", 100, time.Date(2026, time.January, 13, 0, 0, 0, 0, time.UTC)).WithType("B", true, true),
				releaseinfo.NewUpdate("5000002", 200, time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
				releaseinfo.NewUpdate("5000003", 300, time.Date(2026, time.March, 10, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
				releaseinfo.NewUpdate("5000004", 310, time.Date(2026, time.March, 13, 0, 0, 0, 0, time.UTC)).WithType("OOB", true, false),
				releaseinfo.NewUpdate("5000005", 400, time.Date(2026, time.April, 14, 0, 0, 0, 0, time.UTC)).WithType("B", true, true),
				releaseinfo.NewUpdate("5000006", 500, time.Date(2026, time.May, 12, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
			},
			want: map[string][]string{"5000003": {"5000002"}, "5000004": {"5000002"}},
		},
		{
			name: "an out-of-band hotpatch in its baseline's month supersedes nothing, nor is chained into",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000001", 100, time.Date(2026, time.January, 13, 0, 0, 0, 0, time.UTC)).WithType("B", true, true),
				releaseinfo.NewUpdate("5000002", 110, time.Date(2026, time.January, 17, 0, 0, 0, 0, time.UTC)).WithType("OOB", true, false),
				releaseinfo.NewUpdate("5000003", 200, time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
			},
			want: map[string][]string{},
		},
		{
			name: "two monthly hotpatches of one month are both superseded and neither supersedes the other",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("5000001", 100, time.Date(2026, time.January, 13, 0, 0, 0, 0, time.UTC)).WithType("B", true, true),
				releaseinfo.NewUpdate("5000002", 200, time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
				releaseinfo.NewUpdate("5000003", 300, time.Date(2026, time.March, 10, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
				releaseinfo.NewUpdate("5000004", 305, time.Date(2026, time.March, 12, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
				releaseinfo.NewUpdate("5000005", 310, time.Date(2026, time.March, 13, 0, 0, 0, 0, time.UTC)).WithType("OOB", true, false),
				releaseinfo.NewUpdate("5000006", 400, time.Date(2026, time.April, 14, 0, 0, 0, 0, time.UTC)).WithType("B", true, false),
			},
			want: map[string][]string{"5000003": {"5000002"}, "5000004": {"5000002"}, "5000005": {"5000002"}, "5000006": {"5000004", "5000003"}},
		},
		{
			// KB4073290 is for x64-based systems and KB4073291 for x86-based ones.
			name: "updates shipped side by side for different architectures share their place",
			us: []releaseinfo.Update{
				releaseinfo.NewUpdate("4051963", 100, day(1)).WithType("D", false, false),
				releaseinfo.NewUpdate("4073290", 101, day(17)).WithType("OOB", false, false),
				releaseinfo.NewUpdate("4073291", 102, day(18)).WithType("OOB", false, false),
				releaseinfo.NewUpdate("4058258", 103, day(31)).WithType("D", false, false),
			},
			want: map[string][]string{"4073290": {"4051963"}, "4073291": {"4051963"}, "4058258": {"4073290", "4073291"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kbs, err := releaseinfo.Chain(tt.us)
			if err != nil {
				t.Fatalf("chain(). unexpected error: %v", err)
			}
			got := make(map[string][]string)
			for _, kb := range kbs {
				for _, s := range kb.Supersedes {
					got[kb.KBID] = append(got[kb.KBID], s.KBID)
				}
				for _, s := range kb.SupersededBy {
					if s.KBID == kb.KBID {
						t.Errorf("chain(). KB%s is superseded by itself", kb.KBID)
					}
				}
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("chain(). (-expected +got):\n%s", diff)
			}
		})
	}
}

// A hotpatch calendar's Type is read as a baseline unless it says Hotpatch:
// taking a baseline for a hotpatch would join the quarters either side of it.
func TestIsBaseline(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		want bool
	}{
		{
			name: "a baseline",
			typ:  "Baseline (Restart)",
			want: true,
		},
		{
			name: "a hotpatch",
			typ:  "Hotpatch",
			want: false,
		},
		{
			name: "a Type this does not know is read as a baseline",
			typ:  "Hotpatch (Restart)",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := fetchReleaseinfo.Table{Header: []string{"Type", "KB article"}}
			row := []fetchReleaseinfo.Cell{{Text: tt.typ}, {Text: "KB5000001"}}
			if got := releaseinfo.IsBaseline(table, row, "raw/windows-server.json", "5000001"); got != tt.want {
				t.Errorf("isBaseline(). expected: %v, actual: %v", tt.want, got)
			}
		})
	}
}

// A KB on two pages takes its link from whichever page has one.
func TestChainURL(t *testing.T) {
	day := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	kbs, err := releaseinfo.Chain([]releaseinfo.Update{
		releaseinfo.NewUpdate("5000001", 100, day),
		releaseinfo.NewUpdate("5000001", 100, day).WithPage("windows-server", "https://support.microsoft.com/help/5000001"),
	})
	if err != nil {
		t.Fatalf("chain(). unexpected error: %v", err)
	}
	if len(kbs) != 1 || kbs[0].URL != "https://support.microsoft.com/help/5000001" {
		t.Errorf("chain(). expected: one KB linked to %q, actual: %+v", "https://support.microsoft.com/help/5000001", kbs)
	}
}

// Updates of one parallel group with another between them cannot share a place.
func TestChainParallelApart(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2018, time.January, d, 0, 0, 0, 0, time.UTC) }
	if _, err := releaseinfo.Chain([]releaseinfo.Update{
		releaseinfo.NewUpdate("4073290", 101, day(17)).WithType("OOB", false, false),
		releaseinfo.NewUpdate("5000001", 102, day(17)).WithType("OOB", false, false),
		releaseinfo.NewUpdate("4073291", 103, day(18)).WithType("OOB", false, false),
	}); err == nil {
		t.Error("chain(). expected error has not occurred")
	}
}
