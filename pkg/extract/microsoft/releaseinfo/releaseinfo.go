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
// and is not superseded by the next one. The baseline belongs to the cumulative
// line: Microsoft ships it as that month's ordinary cumulative update, so its
// KB appears in both tables -- 22 of the 54 hotpatch KBs on the Windows Server
// page -- and it is chained there, from the cumulative update before it to the
// one after.
//
// Supersedence here is replacement, as it is in the Update Catalog: an update
// supersedes another when installing it leaves the other unneeded. It is not
// containment. A hotpatch carries its baseline's fixes, but it does not replace
// the baseline -- it installs only on top of it, and the baseline stays -- so
// no edge runs from a baseline into a hotpatch. Nor does one run from a
// hotpatch into the next baseline: the baseline does not continue the hotpatch
// series but restarts it, and Microsoft records no such edge, cvrf naming a
// hotpatch only for the predecessor of a hotpatch of the same quarter. The
// hotpatch line runs from one hotpatch to the next within a quarter and stops at
// each baseline, as the servicing extractor chains the same series. An
// out-of-band hotpatch takes the edge its month's monthly one would and is
// superseded by nothing, again as servicing has it: cvrf names the hotpatch
// before the month's monthly one as its predecessor, and none for the hotpatch
// after it.
// Reading it as containment would not even be safe: a hotpatch is not the
// security content of its month's cumulative update, the November 2022 one
// having shipped without the fix for CVE-2022-37966 because that fix could not
// be hotpatched.
//
// A table has no column for the architecture, so two updates Microsoft shipped
// side by side for different ones are ordered by their builds and the later
// made to replace the earlier, which it cannot. parallelUpdates names them. An
// update shipped for fewer architectures than the one before it still replaces
// it on those it ships for, and the next update for all of them reaches the
// earlier one through it, so that edge is kept.
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
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/extract/util/filepath"
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
	// OOB", "2024.08 B *" and "2024.08 B*" alike: the month is one token however
	// Microsoft punctuates it, the letter is the next, and the footnote marker
	// appended to one row of one hotpatch calendar, with or without a space, is
	// not the letter.
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

	// baseline marks the Baseline (Restart) rows of a hotpatch calendar, the
	// ones a hotpatch installs on top of rather than in place of, and where
	// the hotpatch line stops.
	baseline bool

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

	slog.Info("Extract Microsoft Release Information")

	// The raw tree is read and chained before the output is cleared, so a run
	// that cannot do either leaves the last good output where it was.
	us, err := read(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}

	// Each page read has to hold updates (see read). A raw tree holding no page
	// at all would still read as none, and writing that out would replace the
	// dataset with an empty one, with the run green.
	if len(us) == 0 {
		return errors.Errorf("no update in %s", filepath.Join(args, "raw"))
	}

	kbs, err := chain(us)
	if err != nil {
		return errors.Wrap(err, "chain")
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
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

	for _, kb := range kbs {
		p, err := utilfilepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, kb, true); err != nil {
			return errors.Wrapf(err, "write %s", p)
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

		pus, err := parsePage(page, strings.TrimSuffix(rel, ".json"), rel)
		if err != nil {
			return errors.Wrapf(err, "parse %s", p)
		}
		// Each page has carried releases since its first. One read for none is
		// every one of its tables skipped -- a column renamed, a header
		// restyled -- and the other pages reading fine would not show it: the
		// output would just lose that page's KBs.
		if len(pus) == 0 {
			return errors.Errorf("no update in %s", p)
		}
		us = append(us, pus...)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return us, nil
}

// parsePage reads one page's tables for the rows that are updates.
func parsePage(page releaseinfo.Page, name, raw string) ([]update, error) {
	var us []update

	// The release name of a hotpatch calendar is not in its label -- Microsoft
	// files those under "Calendar year 2026", which says the year and not the
	// product, and a page runs two of them at once. It is taken from the release
	// history covering the same build, which is on the same page and says it in
	// full. The histories are read first for that reason.
	//
	// The label is the only thing tying a history to its release, and nothing
	// downstream would notice it pointing at the wrong one: a <strong> picked up
	// from the prose, a label naming another build, or a calendar whose Type
	// column was renamed and so reads as a history would each name KBs after the
	// wrong release -- the last also chaining its hotpatches across the
	// baselines between them. So a history's label has to name its build, and its rows have to be of
	// that build.
	releases := make(map[int]string)
	// majors is the build each release history covers, by its index in Tables.
	majors := make(map[int]int)
	for i, t := range page.Tables {
		if !slices.Contains(t.Header, columnKB) || slices.Contains(t.Header, columnHotpatchType) {
			continue
		}
		m := buildSuffixPattern.FindStringSubmatch(t.Label)
		if m == nil {
			return nil, errors.Errorf("unexpected release history label. expected: %q, actual: %q", "<release> (OS build <major>)", t.Label)
		}
		major, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, errors.Wrapf(err, "parse build in %q", t.Label)
		}
		if _, ok := releases[major]; ok {
			return nil, errors.Errorf("two release histories for build %d. label: %q", major, t.Label)
		}
		releases[major] = release(name, t.Label)
		majors[i] = major
	}

	for i, t := range page.Tables {
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
		missing := make([]string, 0, 3)
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
			u, ok, err := parseRow(t, row, name, raw)
			if err != nil {
				return nil, errors.Wrapf(err, "parse row. label: %q", t.Label)
			}
			if !ok {
				continue
			}
			u.hotpatch = hotpatch
			if !hotpatch && u.major != majors[i] {
				return nil, errors.Errorf("unexpected build in release history. expected: %d.<revision>, actual: %d.%d, label: %q, kb: %s", majors[i], u.major, u.revision, t.Label, u.kbID)
			}
			if hotpatch {
				u.baseline = isBaseline(t, row, raw, u.kbID)

				// On a hotpatch line the month places an update, not only a
				// tie: a hotpatch links from those of the month before.
				if u.date.IsZero() {
					return nil, errors.Errorf("unexpected availability date in hotpatch calendar. expected: %q, actual: none readable, label: %q, kb: %s", time.DateOnly, t.Label, u.kbID)
				}

				// A calendar runs monthly hotpatches, and out-of-band ones
				// between them. Anything else is chained as out-of-band, where
				// it supersedes and is superseded by the least.
				switch u.letter {
				case "B", "OOB":
				default:
					slog.Warn("unexpected update type in hotpatch calendar, update is chained as out-of-band", slog.String("path", raw), slog.String("kb", u.kbID), slog.String("letter", u.letter))
				}

				// Every hotpatch calendar covers a release whose history is on
				// the same page. One without is that history lost or relabelled,
				// which costs its KBs their monthly chain as well as the name.
				r, ok := releases[u.major]
				if !ok {
					return nil, errors.Errorf("no release history for hotpatch build %d. label: %q, kb: %s", u.major, t.Label, u.kbID)
				}
				u.release = r
			}
			us = append(us, u)
		}
	}

	return us, nil
}

// parseRow reads one row, reporting false for the ones that are not updates.
func parseRow(t releaseinfo.Table, row []releaseinfo.Cell, name, raw string) (update, bool, error) {
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
		return update{}, false, nil
	}

	// The build is the whole order. A row without one cannot be placed, and
	// every one of the 1,944 rows that names a KB has had it. A release history
	// loses the one KB to it. A hotpatch calendar would lose more: a baseline
	// dropped there would chain the hotpatches either side of it into one
	// quarter, so it fails instead.
	unreadable := func() (update, bool, error) {
		if slices.Contains(t.Header, columnHotpatchType) {
			return update{}, false, errors.Errorf("unexpected build in hotpatch calendar. expected: %q, actual: %q, kb: %s", "<major>.<revision>", cell(columnBuild).Text, m[1])
		}
		slog.Warn("unexpected build", slog.String("path", raw), slog.String("label", t.Label), slog.String("kb", m[1]), slog.String("build", cell(columnBuild).Text))
		return update{}, false, nil
	}
	bm := buildPattern.FindStringSubmatch(cell(columnBuild).Text)
	if bm == nil {
		return unreadable()
	}
	major, err := strconv.Atoi(bm[1])
	if err != nil {
		return unreadable()
	}
	revision, err := strconv.Atoi(bm[2])
	if err != nil {
		return unreadable()
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
	}, true, nil
}

// isBaseline reads a hotpatch calendar row's Type.
//
// A Type this does not recognise is read as a baseline. Mistaking a hotpatch
// for one costs the edges either side of it; mistaking a baseline for a
// hotpatch would join the quarters either side of it into one, chaining the
// last hotpatch before it to the first after.
func isBaseline(t releaseinfo.Table, row []releaseinfo.Cell, raw, kbID string) bool {
	var typ string
	if i := slices.Index(t.Header, columnHotpatchType); i >= 0 && i < len(row) {
		typ = row[i].Text
	}

	switch {
	case strings.HasPrefix(typ, "Baseline"):
		return true
	case typ == "Hotpatch":
		return false
	default:
		slog.Warn("unexpected hotpatch type, update is read as a baseline", slog.String("path", raw), slog.String("kb", kbID), slog.String("type", typ))
		return true
	}
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
func chain(us []update) ([]microsoftkbTypes.KB, error) {
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
		// A KB occupies one place on a line. Listed twice with another update
		// between -- re-released at a later build -- it would supersede and be
		// superseded by that update at once, and which place is the real one is
		// not something the table says.
		at := make(map[string]int)
		for i, u := range group {
			if j, ok := at[u.kbID]; ok && j != i-1 {
				return nil, errors.Errorf("KB%s is listed twice on one line with another update between. page: %s, build: %d, line: %s, revisions: %d.%d, %d.%d", u.kbID, u.page, u.major, u.kind(), u.major, group[j].revision, u.major, u.revision)
			}
			at[u.kbID] = i
		}

		if group[0].hotpatch {
			links = append(links, chainHotpatch(group)...)
			continue
		}

		// Updates shipped side by side for different architectures share one
		// place on the line: each replaces the update before them, and the one
		// after replaces each.
		var places [][]update
		placed := make(map[string]int)
		for _, u := range group {
			g, ok := parallelUpdates[u.kbID]
			if ok {
				if i, seen := placed[g]; seen {
					// One parallel to it sits further back, with another update
					// between: chained as served, the two would replace each
					// other's neighbours as well as the one between.
					if i != len(places)-1 {
						return nil, errors.Errorf("unexpected parallel updates. expected: KB%s next to the other updates of %q on one line, actual: another update between. page: %s, build: %d, line: %s", u.kbID, g, u.page, u.major, u.kind())
					}
					places[i] = append(places[i], u)
					continue
				}
				placed[g] = len(places)
			}
			places = append(places, []update{u})
		}
		for i := 1; i < len(places); i++ {
			for _, older := range places[i-1] {
				for _, newer := range places[i] {
					links = append(links, link{older: older.kbID, newer: newer.kbID})
				}
			}
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
		// A KB on two pages may be linked from only one of them.
		if kb.URL == "" {
			kb.URL = u.url
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
	return out, nil
}

// link is one supersedence edge, from the update replaced to the one replacing
// it.
type link struct{ older, newer string }

// chainHotpatch links one hotpatch calendar's line, sorted by revision.
//
// A hotpatch does not replace the baseline it installs on top of, and the next
// baseline restarts the series rather than continuing it, so a hotpatch links
// from the monthly hotpatches of the latest earlier month since the baseline,
// as servicing has it. An out-of-band one takes the edge its month's monthly
// hotpatch would and is superseded by nothing: the monthly hotpatch after it
// links to the monthly ones before it.
//
// Unlike servicing, no gap of more than a quarter is looked for: a calendar
// names each baseline in a row of its own, and a Type it does not know is read
// as one.
func chainHotpatch(group []update) []link {
	month := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC) }

	var links []link
	var monthly []update
	for _, u := range group {
		switch {
		case u.baseline:
			monthly = nil
		default:
			// Every monthly hotpatch of the latest earlier month, so that two
			// of one month are both superseded and neither supersedes the other.
			var latest time.Time
			for i := len(monthly) - 1; i >= 0; i-- {
				m := month(monthly[i].date)
				if !m.Before(month(u.date)) {
					continue
				}
				if latest.IsZero() {
					latest = m
				}
				if !m.Equal(latest) {
					break
				}
				links = append(links, link{older: monthly[i].kbID, newer: u.kbID})
			}
			if u.letter == "B" {
				monthly = append(monthly, u)
			}
		}
	}
	return links
}

// parallelUpdates groups updates Microsoft shipped side by side for different
// architectures with none in common, which therefore do not replace one another
// however their builds run. Each is keyed by KB ID, and the KBs of one group
// share a value. Over the edges on the pages as served on 2026-10-27, checked
// against the architectures the Update Catalog lists, this pair is the only one
// sharing no architecture. KB5014697 (x64) and KB5016138 (ARM64), Windows 11
// 21H2 in June 2022, are a split too, but filed under B and OOB they sit on
// different lines, each between updates for both, and are left there.
var parallelUpdates = map[string]string{
	// Windows 10 Version 1709, January 2018: KB4073290 (16299.194, January
	// 17th) is for x64-based systems and KB4073291 (16299.201, January 18th)
	// for x86-based ones, as the Update Catalog lists them; KB4058258
	// (16299.214) after them is for both.
	"4073290": "2018-01 1709",
	"4073291": "2018-01 1709",
}
