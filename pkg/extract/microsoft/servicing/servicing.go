// Package servicing extracts supersedence from Microsoft's servicing articles.
//
// The articles carry no supersedence of their own -- each states a title and
// its own address, nothing more. What they do carry is a series: every article
// of one lists all of them, expired members included, which is the whole reason
// this source exists. The order of that series is the supersedence, and reading
// it out is this package's job.
//
// The order comes from two things, both in the title. Where Microsoft gives OS
// build numbers, they decide it outright: a cumulative update at 26100.8973
// contains 26100.8894, so revision order within a build is supersedence with
// nothing inferred. Where it does not -- .NET Framework and the pre-Windows-10
// rollups -- the release date decides it, within one series and one track.
//
// Neither the directory an article sits in nor the series as a whole can be
// used for this:
//
//   - os/windows-11 holds six versions at once, 21H2 through 26H1. An update to
//     22621 has nothing to do with one to 26100, and only the build number says
//     so.
//   - The directory is not the release date. It disagrees with the date in the
//     title on 35 of 263 sampled articles -- .../2022/12/january-26-2023-... --
//     so it is the title that is read, never the path. The two dates the title
//     and the slug carry agree on every one of those 263.
//   - A legacy series runs two tracks side by side, a Monthly Rollup and a
//     Security-only update. They supersede along their own lines and are kept
//     apart.
//
// Articles naming no KB are not updates and are skipped: the six "Windows 11,
// version NNHN update history" hub pages and "End of servicing statement" in a
// 271-article sample, which are exactly the seven carrying no date either.
package servicing

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/servicing"
)

var (
	kbPattern = regexp.MustCompile(`KB(\d{6,})`)

	// datePattern is the release date every article that names a KB opens with,
	// in any of the separators Microsoft has used between it and the KB.
	datePattern = regexp.MustCompile(`^([A-Z][a-z]+ \d{1,2}, \d{4})`)

	// buildsPattern is the parenthetical Microsoft puts OS builds in, singular
	// for one and plural for the several an update ships to at once:
	// "(OS Build 28000.2525)", "(OS Builds 26200.8973 and 26100.8973)".
	buildsPattern = regexp.MustCompile(`OS Builds? ([^)]+)`)
	buildPattern  = regexp.MustCompile(`(\d+)\.(\d+)`)
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

// build is one OS build an update ships to, split so that updates to the same
// line can be ordered without the ones to every other line coming with them.
type build struct {
	major    int
	revision int
}

// article is one servicing article, read for what decides its place in a chain.
type article struct {
	kbID string
	url  string
	date time.Time

	// line is the series the article was stored under, e.g. os/windows-11 or
	// dotnetframework/windows-11/22h2.
	line string

	// track keeps a Monthly Rollup from superseding a Security-only update.
	track string

	builds []build

	// raw is the path this was read from, recorded on the KB so a record can be
	// traced back to the page it came from.
	raw string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "servicing"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Servicing")

	as, err := read(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}

	// An unrecognised track is recorded and left unchained, which does not show
	// in the output -- the KB is there, only its edges are missing. A product
	// family arriving as a kind this has not seen would otherwise extract clean
	// with no supersedence at all, so it is reported per series with a page to
	// go and look at. Articles carrying build numbers are chained by those and
	// never consult the track, so they are not counted.
	unchained := make(map[string]int)
	example := make(map[string]string)
	for _, a := range as {
		if a.track != trackUnknown || len(a.builds) > 0 {
			continue
		}
		unchained[a.line]++
		if _, ok := example[a.line]; !ok {
			example[a.line] = a.raw
		}
	}
	for _, series := range slices.Sorted(maps.Keys(unchained)) {
		slog.Warn("articles of an unrecognised kind are left unchained", slog.String("series", series), slog.Int("count", unchained[series]), slog.String("example", example[series]))
	}

	for _, kb := range chain(as) {
		if err := util.Write(filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftServicing,
		Name: new("Microsoft Servicing Articles"),
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

// read walks the raw tree and returns the articles that are updates.
func read(args string) ([]article, error) {
	root := filepath.Join(args, "raw")

	var as []article
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

		var a servicing.Article
		if err := json.UnmarshalRead(f, &a); err != nil {
			return errors.Wrapf(err, "decode %s", p)
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}

		parsed, ok := parse(a, filepath.ToSlash(rel))
		if !ok {
			// A hub page or a servicing statement rather than an update. There
			// is no KB to record and no place in any chain.
			slog.Debug("not an update", slog.String("path", filepath.ToSlash(rel)), slog.String("title", a.Title))
			return nil
		}

		as = append(as, parsed)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return as, nil
}

// parse reads an article for what decides its place in a chain, reporting false
// for the pages that are not updates.
func parse(a servicing.Article, rel string) (article, bool) {
	m := kbPattern.FindStringSubmatch(a.Title)
	if m == nil {
		return article{}, false
	}

	dm := datePattern.FindStringSubmatch(a.Title)
	if dm == nil {
		// Every article naming a KB carries a date -- 264 of 264 sampled -- so
		// one without is a title shape this has not seen rather than an update
		// that has no date. Ordering it by guesswork would put an edge where
		// there may be none.
		slog.Warn("no date in title", slog.String("path", rel), slog.String("title", a.Title))
		return article{}, false
	}
	date, err := time.Parse("January 2, 2006", dm[1])
	if err != nil {
		slog.Warn("unexpected date", slog.String("path", rel), slog.String("date", dm[1]))
		return article{}, false
	}

	// The series is where the article sits, minus the year, month and slug.
	segs := strings.Split(rel, "/")
	if len(segs) < 4 {
		slog.Warn("unexpected path", slog.String("path", rel))
		return article{}, false
	}

	var builds []build
	if bm := buildsPattern.FindStringSubmatch(a.Title); bm != nil {
		for _, b := range buildPattern.FindAllStringSubmatch(bm[1], -1) {
			major, err := strconv.Atoi(b[1])
			if err != nil {
				continue
			}
			revision, err := strconv.Atoi(b[2])
			if err != nil {
				continue
			}
			builds = append(builds, build{major: major, revision: revision})
		}
	}

	return article{
		kbID:   m[1],
		url:    a.URL,
		date:   date,
		line:   strings.Join(segs[:len(segs)-3], "/"),
		track:  track(a.Title),
		builds: builds,
		raw:    rel,
	}, true
}

// track tells apart the lines a legacy series runs at once. os/server-2008
// alone carries 64 Monthly Rollups, 64 Security-only updates and 14 Previews of
// Monthly Rollup, interleaved by date.
//
// Only the rollup line is cumulative, and it is the only one chained. Taking
// each track's consecutive pairs and asking whether any of msuc, wsusscn2 or
// cvrf records supersedence between them:
//
//	rollup          64 pairs, 63 confirmed   98%
//	security-only   64 pairs,  2 confirmed    3%
//
// A Security-only update carries one month's fixes and nothing before it, so
// ordering them by date and joining them would assert 62 replacements that no
// source records and that do not happen. They are recorded as KBs and left
// unchained.
//
// It is superseded across tracks instead, by the rollup of its own month, which
// carries the same fixes and the months before them. No source records that --
// 0 of 64 same-month pairs -- but msuc synthesises the same edge for the same
// reason, that "Microsoft does NOT consistently record cross-track supersession"
// while "the broader-track update is functionally a superset of the narrower".
//
// A Preview is a line of its own, not part of the rollup one. Chained to each
// other they confirm 13 of 13, and each is superseded by the rollup of the
// month it previews, 14 of 14. Ordering them into the rollup line by date
// instead loses the first of those and asserts what the second denies -- that a
// preview supersedes the rollup before it, which no source records at all,
// 0 of 14.
func track(title string) string {
	switch {
	case strings.Contains(title, "Security-only"), strings.Contains(title, "Security Only"):
		return trackSecurityOnly
	case strings.Contains(title, "Preview"):
		return trackPreview
	case strings.Contains(title, "Monthly Rollup"), strings.Contains(title, "Cumulative Update"):
		return trackRollup
	default:
		return trackUnknown
	}
}

const (
	trackRollup       = "rollup"
	trackSecurityOnly = "security-only"
	trackPreview      = "preview"
	trackUnknown      = ""
)

// chain turns the articles into KB records, chained into supersedence.
//
// An update ships to more than one build at a time -- "(OS Builds 26200.8973
// and 26100.8973)" is one KB on two lines -- so it takes its place in each of
// their chains and ends up with the edges of both.
func chain(as []article) []microsoftkbTypes.KB {
	type link struct{ older, newer string }
	var links []link

	// By build where Microsoft gives one, within one series. Revision order is
	// supersedence: a cumulative update at .8973 contains .8894.
	//
	// A build number is not unique across series -- Windows 11 24H2 and Windows
	// Server 2025 are both 26100, shipping their own KBs at the same revisions --
	// so the series has to be part of the key or the two interleave into one
	// chain and each claims to supersede the other's updates.
	//
	// The track is not, and must not be: a build-numbered article is cumulative
	// whatever its title says, so the Preview at .8973 does supersede the
	// Out-of-band at .8894. That is one line, and splitting it by track breaks it.
	type buildLine struct {
		series string
		major  int
	}
	byBuild := make(map[buildLine][]article)
	for _, a := range as {
		for _, b := range a.builds {
			byBuild[buildLine{series: a.line, major: b.major}] = append(byBuild[buildLine{series: a.line, major: b.major}], a)
		}
	}
	for bl, group := range byBuild {
		revision := func(a article) int {
			for _, b := range a.builds {
				if b.major == bl.major {
					return b.revision
				}
			}
			return 0
		}
		slices.SortFunc(group, func(x, y article) int {
			return cmp.Or(cmp.Compare(revision(x), revision(y)), cmp.Compare(x.kbID, y.kbID))
		})
		for i := 1; i < len(group); i++ {
			links = append(links, link{older: group[i-1].kbID, newer: group[i].kbID})
		}
	}

	// By date for the series Microsoft numbers no builds in, within one track.
	type line struct{ series, track string }
	byLine := make(map[line][]article)
	for _, a := range as {
		if len(a.builds) > 0 || a.track == trackSecurityOnly || a.track == trackUnknown {
			continue
		}
		l := line{series: a.line, track: a.track}
		byLine[l] = append(byLine[l], a)
	}
	for _, group := range byLine {
		slices.SortFunc(group, func(x, y article) int {
			return cmp.Or(x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})
		for i := 1; i < len(group); i++ {
			links = append(links, link{older: group[i-1].kbID, newer: group[i].kbID})
		}
	}

	// Across tracks, within one month: the rollup carries what the Security-only
	// update of that month carries, so it supersedes it. This is the edge msuc
	// synthesises rather than reads, for the same reason.
	type month struct {
		series string
		year   int
		month  int
	}
	byMonth := make(map[month][]article)
	for _, a := range as {
		if len(a.builds) > 0 {
			continue
		}
		byMonth[month{series: a.line, year: a.date.Year(), month: int(a.date.Month())}] = append(byMonth[month{series: a.line, year: a.date.Year(), month: int(a.date.Month())}], a)
	}
	for m, group := range byMonth {
		for _, older := range group {
			switch older.track {
			case trackSecurityOnly:
				// The rollup of the same month carries the same fixes.
				for _, newer := range group {
					if newer.track == trackRollup {
						links = append(links, link{older: older.kbID, newer: newer.kbID})
					}
				}
			case trackPreview:
				// A preview is of the month that follows it, and that month's
				// rollup is what ships it for real.
				next := m
				if next.month++; next.month > 12 {
					next.year, next.month = next.year+1, 1
				}
				for _, newer := range byMonth[next] {
					if newer.track == trackRollup {
						links = append(links, link{older: older.kbID, newer: newer.kbID})
					}
				}
			}
		}
	}

	kbs := make(map[string]*microsoftkbTypes.KB, len(as))
	for _, a := range as {
		kb, ok := kbs[a.kbID]
		if !ok {
			kb = &microsoftkbTypes.KB{
				KBID: a.kbID,
				URL:  a.url,
				DataSource: sourceTypes.Source{
					ID: sourceTypes.MicrosoftServicing,
				},
			}
			kbs[a.kbID] = kb
		}
		if !slices.Contains(kb.Products, a.line) {
			kb.Products = append(kb.Products, a.line)
		}
		if !slices.Contains(kb.DataSource.Raws, a.raw) {
			kb.DataSource.Raws = append(kb.DataSource.Raws, a.raw)
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
