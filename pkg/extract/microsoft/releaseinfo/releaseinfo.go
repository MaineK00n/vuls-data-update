// Package releaseinfo extracts supersedence from Microsoft's Windows
// release-information tables.
//
// The tables carry no supersedence of their own. What they carry is a release's
// whole update history in one place, and in columns rather than in prose: the OS
// build, the availability date, the release-cadence letter and the KB. The order
// of that history is the supersedence, and reading it out is this package's job.
//
// The order is the build number, within one release line. Revision order is
// supersedence -- a cumulative update at .8973 contains .8894 -- and the date is
// only a tiebreaker, for the two occasions Microsoft has shipped one build twice.
//
// Three things decide which line an update belongs to, and all three are needed:
//
//   - The page. A build number is not unique across products: 26100 is Windows
//     Server 2025 on one page and Windows 11 24H2 on another, each shipping its
//     own KBs at revisions the other also ships. Keyed on the build alone the
//     two interleave into one chain and each claims to supersede the other's
//     updates.
//
//   - The build's major part, which is the release: an update to 22621 has
//     nothing to do with one to 26100.
//
//   - The cadence letter. A build line runs two lines at once and only one of
//     them carries it. B is the second Tuesday, and is what the following month
//     builds on; C and D are the optional previews of the weeks after it, and
//     OOB is out-of-band. Those carry the same fixes to the same build without
//     the next month's update ever taking them up, and Microsoft's revision
//     numbers interleave the two, so ordering by revision alone threads them
//     into one chain.
//
// The servicing source splits that last one by asking whether the release date
// falls on a second Tuesday, which is a reading of the calendar rather than of
// what Microsoft said. Over the 1,944 rows these three pages carry, the letter
// and the calendar disagree 18 times: twelve B releases did not ship on a second
// Tuesday, and three D and three OOB releases did. Reading the letter puts all
// eighteen on the line Microsoft filed them under.
//
// A and E appear seven times between them, first-week and fifth-week releases
// from 2015 and 2016, and none of the seven is a second Tuesday. They are
// optional releases and are treated as such, which is also what an unrecognised
// letter is treated as: a new letter is far likelier to be another optional
// cadence than a second security line, and mistaking one for B would put a
// stranger into the chain the rest of the estate is measured against, where
// mistaking B for one leaves an update chained to nothing.
//
// Hotpatch updates are a line of their own and are never mixed with the
// cumulative ones. A hotpatch quarter opens with a Baseline (Restart) and runs
// two hotpatch months on top of it before the next baseline rebases it, so the
// hotpatch of one month does not supersede the cumulative update of that month
// and is not superseded by the next one. The baseline is the join: Microsoft
// ships it as that month's ordinary cumulative update too, so its KB appears in
// both tables -- 22 of the 54 hotpatch KBs on the Windows Server page -- and it
// takes its place in both chains, which is what a baseline is.
//
// Rows naming no KB are the months a calendar has reached but Microsoft has not
// shipped yet, and are skipped.
package releaseinfo

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	microsoftkbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb"
	microsoftkbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
	microsoftkbSupersedesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersedes"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/releaseinfo"
)

// The column names the tables are read by. They are read by name and not by
// position because the two shapes share most of them in a different order, and
// because Microsoft has already changed the set once: "Update type" was added
// after these pages had run for years without it.
const (
	columnKB           = "KB article"
	columnBuild        = "Build"
	columnDate         = "Availability date"
	columnUpdateType   = "Update type"
	columnHotpatchType = "Type"
)

var (
	// kbPattern allows the space Microsoft leaves after KB elsewhere in this
	// estate, though these tables have not used one.
	kbPattern = regexp.MustCompile(`KB ?(\d{6,})`)

	buildPattern = regexp.MustCompile(`^(\d+)\.(\d+)$`)

	// updateTypePattern reads the cadence letter out of "2026-08 B", "2021-03
	// OOB" and "2024.08 B *" alike: the month is one token however Microsoft
	// punctuates it, the letter is the next, and the footnote marker appended to
	// one row of one hotpatch calendar is not the letter.
	updateTypePattern = regexp.MustCompile(`^\S+ ([A-Z]+)`)

	// buildSuffixPattern is what every release-history label ends with, and the
	// only part of one that is not the release name: "Version 22H2 (OS build
	// 19045)", "Windows Server 2016 (OS build 14393)".
	buildSuffixPattern = regexp.MustCompile(`\s*\(OS build (\d+)\)$`)
)

// The lines a build runs at once. Kept as strings because they are a grouping
// key and appear in warnings, where "hotpatch" says what "2" does not.
const (
	kindMonthly  = "monthly"
	kindOptional = "optional"
	kindHotpatch = "hotpatch"
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

// update is one row of a release history or a hotpatch calendar, read for what
// decides its place in a chain.
type update struct {
	kbID string
	url  string

	// page is the file the row was read from -- windows-10, windows-11,
	// windows-server -- which is the product, and which two releases sharing a
	// build number are told apart by.
	page string

	// release is the label the table was filed under, e.g. "Windows 10 Version
	// 22H2". It names the line for a reader; the chain is keyed on the build.
	release string

	major    int
	revision int

	date   time.Time
	letter string

	hotpatch bool

	// raw is the path this was read from, recorded on the KB so a record can be
	// traced back to the page it came from.
	raw string
}

// kind is the line within a release that an update belongs to.
func (u update) kind() string {
	switch {
	case u.hotpatch:
		return kindHotpatch
	case u.letter == "B":
		return kindMonthly
	default:
		return kindOptional
	}
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "releaseinfo"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Release Information")

	us, err := read(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}

	// A release whose updates all landed on one line is a line that was not
	// split. Every release Microsoft has run for a full month has both -- a
	// second-Tuesday cumulative update and something optional after it -- so one
	// with only monthly rows means the letters stopped being read, and one with
	// no monthly rows means they stopped being read the other way. Neither shows
	// in the output: the KBs are all there, chained into one long line that
	// looks exactly like a right one.
	//
	// A release of fewer than three updates is not counted. 26H1 opened with
	// two and was neither wrong nor finished.
	kinds := make(map[string]map[string]int)
	for _, u := range us {
		if u.hotpatch {
			continue
		}
		if kinds[u.release] == nil {
			kinds[u.release] = make(map[string]int)
		}
		kinds[u.release][u.kind()]++
	}
	for _, release := range slices.Sorted(maps.Keys(kinds)) {
		total := kinds[release][kindMonthly] + kinds[release][kindOptional]
		if total < 3 || len(kinds[release]) > 1 {
			continue
		}
		slog.Warn("a release ran every update on one line", slog.String("release", release), slog.String("line", slices.Collect(maps.Keys(kinds[release]))[0]), slog.Int("count", total))
	}

	kbs := chain(us)

	for _, kb := range kbs {
		if err := util.Write(filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftReleaseInfo,
		Name: new("Microsoft Windows Release Information"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{URL: u}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// read walks the raw tree and returns the rows that are updates.
func read(args string) ([]update, error) {
	root := filepath.Join(args, "raw")

	var us []update
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".json" {
			return nil
		}

		f, err := os.Open(p)
		if err != nil {
			return errors.Wrapf(err, "open %s", p)
		}
		defer f.Close()

		var page releaseinfo.Page
		if err := json.UnmarshalRead(f, &page); err != nil {
			return errors.Wrapf(err, "decode %s", p)
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}
		rel = filepath.ToSlash(rel)

		us = append(us, parsePage(page, strings.TrimSuffix(rel, ".json"), rel)...)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return us, nil
}

// parsePage reads one page's tables for the rows that are updates.
func parsePage(page releaseinfo.Page, name, raw string) []update {
	var us []update

	// The release name of a hotpatch calendar is not in its label -- Microsoft
	// files those under "Calendar year 2026", which says the year and not the
	// product, and a page runs two of them at once. It is taken from the release
	// history covering the same build, which is on the same page and says it in
	// full. The histories are read first for that reason.
	releases := make(map[int]string)
	for _, t := range page.Tables {
		if !slices.Contains(t.Header, columnKB) || slices.Contains(t.Header, columnHotpatchType) {
			continue
		}
		if m := buildSuffixPattern.FindStringSubmatch(t.Label); m != nil {
			major, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			releases[major] = release(name, t.Label)
		}
	}

	for _, t := range page.Tables {
		if !slices.Contains(t.Header, columnKB) {
			// A lifecycle table. It states support dates rather than a history,
			// and names only the latest update of each release, which the
			// history it sits above already carries.
			slog.Debug("not an update table", slog.String("path", raw), slog.String("label", t.Label))
			continue
		}

		hotpatch := slices.Contains(t.Header, columnHotpatchType)

		// The columns an update is read out of. A table missing one of them
		// cannot be read at all, and saying which is missing is the difference
		// between a page to go and look at and a source that quietly halved.
		var missing []string
		for _, c := range []string{columnBuild, columnDate, columnUpdateType} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			slog.Warn("update table is missing columns", slog.String("path", raw), slog.String("label", t.Label), slog.String("missing", strings.Join(missing, ", ")), slog.String("header", strings.Join(t.Header, ", ")))
			continue
		}

		for _, row := range t.Rows {
			u, ok := parseRow(t, row, name, raw)
			if !ok {
				continue
			}
			u.hotpatch = hotpatch
			if hotpatch {
				u.release = releases[u.major]
			}
			us = append(us, u)
		}
	}

	return us
}

// parseRow reads one row, reporting false for the ones that are not updates.
func parseRow(t releaseinfo.Table, row []releaseinfo.Cell, name, raw string) (update, bool) {
	cell := func(column string) releaseinfo.Cell {
		i := slices.Index(t.Header, column)
		// A row is free to hold a cell more than its header names -- one
		// hotpatch row does -- so its length is checked rather than assumed.
		if i < 0 || i >= len(row) {
			return releaseinfo.Cell{}
		}
		return row[i]
	}

	m := kbPattern.FindStringSubmatch(cell(columnKB).Text)
	if m == nil {
		// A month the calendar has reached and Microsoft has not shipped yet.
		slog.Debug("row names no KB", slog.String("path", raw), slog.String("label", t.Label))
		return update{}, false
	}

	bm := buildPattern.FindStringSubmatch(cell(columnBuild).Text)
	if bm == nil {
		// The build is the whole order. A row without one cannot be placed, and
		// every one of the 1,944 rows that names a KB has had it.
		slog.Warn("unexpected build", slog.String("path", raw), slog.String("label", t.Label), slog.String("kb", m[1]), slog.String("build", cell(columnBuild).Text))
		return update{}, false
	}
	major, err := strconv.Atoi(bm[1])
	if err != nil {
		slog.Warn("unexpected build", slog.String("path", raw), slog.String("kb", m[1]), slog.String("build", cell(columnBuild).Text))
		return update{}, false
	}
	revision, err := strconv.Atoi(bm[2])
	if err != nil {
		slog.Warn("unexpected build", slog.String("path", raw), slog.String("kb", m[1]), slog.String("build", cell(columnBuild).Text))
		return update{}, false
	}

	// The date is a tiebreaker between two updates of one build, not the order,
	// so an unreadable one costs the tie and not the row.
	var date time.Time
	if d := cell(columnDate).Text; d != "" {
		date, err = time.Parse(time.DateOnly, d)
		if err != nil {
			slog.Warn("unexpected availability date", slog.String("path", raw), slog.String("kb", m[1]), slog.String("date", d))
			date = time.Time{}
		}
	}

	// An unreadable cadence leaves the update on the optional line, where it
	// chains among updates that supersede nothing the estate is measured
	// against. Putting it on the monthly line instead would let it claim to
	// replace the cumulative updates.
	var letter string
	if lm := updateTypePattern.FindStringSubmatch(cell(columnUpdateType).Text); lm != nil {
		letter = lm[1]
	} else {
		slog.Warn("unexpected update type", slog.String("path", raw), slog.String("kb", m[1]), slog.String("update_type", cell(columnUpdateType).Text))
	}
	switch letter {
	case "A", "B", "C", "D", "E", "OOB":
	default:
		slog.Warn("unrecognised release cadence, update is left on the optional line", slog.String("path", raw), slog.String("kb", m[1]), slog.String("update_type", cell(columnUpdateType).Text))
	}

	return update{
		kbID:     m[1],
		url:      cell(columnKB).Href,
		page:     name,
		release:  release(name, t.Label),
		major:    major,
		revision: revision,
		date:     date,
		letter:   letter,
		raw:      raw,
	}, true
}

// release names the line a table covers, as a reader would say it.
//
// The Windows Server labels name their product in full; the Windows 10 and 11
// ones say "Version 22H2" and leave the product to the page, so the page
// supplies it. A label that is neither -- a hotpatch calendar's "Calendar year
// 2026" -- is left alone here and replaced by the release history's, which
// covers the same build.
func release(page, label string) string {
	name := buildSuffixPattern.ReplaceAllString(label, "")

	after, ok := strings.CutPrefix(name, "Version ")
	if !ok {
		return name
	}

	switch page {
	case "windows-10":
		return fmt.Sprintf("Windows 10 Version %s", after)
	case "windows-11":
		return fmt.Sprintf("Windows 11 Version %s", after)
	default:
		return name
	}
}

// chain turns the rows into KB records, chained into supersedence.
//
// An update ships to more than one release at a time -- KB5121003 is 26200.9168
// on one line and 26100.9168 on another -- so it takes its place in each of
// their chains and ends up with the edges of both.
func chain(us []update) []microsoftkbTypes.KB {
	type buildLine struct {
		page  string
		major int
		kind  string
	}

	byLine := make(map[buildLine][]update)
	for _, u := range us {
		bl := buildLine{page: u.page, major: u.major, kind: u.kind()}
		byLine[bl] = append(byLine[bl], u)
	}

	type link struct{ older, newer string }
	var links []link
	for _, group := range byLine {
		// Two updates do share a revision, where Microsoft has shipped a build
		// twice off the same cadence. The release date decides those, and the KB
		// number only where even that ties -- ordering by the number alone would
		// be right by the accident that Microsoft allocates them in order, and
		// wrong the first time it does not.
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(cmp.Compare(x.revision, y.revision), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})
		for i := 1; i < len(group); i++ {
			links = append(links, link{older: group[i-1].kbID, newer: group[i].kbID})
		}
	}

	kbs := make(map[string]*microsoftkbTypes.KB, len(us))
	for _, u := range us {
		kb, ok := kbs[u.kbID]
		if !ok {
			kb = &microsoftkbTypes.KB{
				KBID: u.kbID,
				URL:  u.url,
				DataSource: sourceTypes.Source{
					ID: sourceTypes.MicrosoftReleaseInfo,
				},
			}
			kbs[u.kbID] = kb
		}
		if u.release != "" && !slices.Contains(kb.Products, u.release) {
			kb.Products = append(kb.Products, u.release)
		}
		if !slices.Contains(kb.DataSource.Raws, u.raw) {
			kb.DataSource.Raws = append(kb.DataSource.Raws, u.raw)
		}
	}

	for _, l := range links {
		if l.older == l.newer {
			continue
		}
		if kb, ok := kbs[l.older]; ok {
			s := microsoftkbSupersededByTypes.SupersededBy{KBID: l.newer}
			if !slices.Contains(kb.SupersededBy, s) {
				kb.SupersededBy = append(kb.SupersededBy, s)
			}
		}
		if kb, ok := kbs[l.newer]; ok {
			s := microsoftkbSupersedesTypes.Supersedes{KBID: l.older}
			if !slices.Contains(kb.Supersedes, s) {
				kb.Supersedes = append(kb.Supersedes, s)
			}
		}
	}

	out := make([]microsoftkbTypes.KB, 0, len(kbs))
	for _, kb := range kbs {
		out = append(out, *kb)
	}
	return out
}
