// Package servicing extracts supersedence from Microsoft's servicing articles.
//
// The articles carry no supersedence of their own -- each states a title and
// its own address, nothing more. What they do carry is a series: every article
// of one lists all of them, expired members included, which is the whole reason
// this source exists. The order of that series is the supersedence, and reading
// it out is this package's job.
//
// The order comes from two things, both in the title. Where Microsoft gives OS
// build numbers, revision order within one build and one release cadence is
// supersedence. Where it does not -- .NET Framework and the pre-Windows-10
// rollups -- the release date decides it, within one series and one track.
//
// Neither the directory an article sits in nor the series as a whole can be
// used for this:
//
//   - os/windows-11 holds six versions at once, 21H2 through 26H1. An update to
//     22621 has nothing to do with one to 26100, and only the build number says
//     so.
//   - The directory is not the release date. It disagrees with the date in the
//     title on 272 of the 2,535 articles filed under one -- and the shape is
//     always .../2022/12/january-26-2023-..., the month the work was done
//     against the month it shipped -- so it is the title that is read, never
//     the path.
//   - A legacy series runs two tracks side by side, a Monthly Rollup and a
//     Security-only update. They supersede along their own lines and are kept
//     apart.
//
// What the directory does say is which product line an article belongs to, and
// there it is better than the title. Microsoft renames products under a stable
// path -- "Microsoft server operating system version 21H2" became "Windows
// Server 2022" in the titles of dotnetframework/microsoft-server/2022 -- and
// widens and narrows the list of products a .NET article names while the line
// runs on. Reading the line out of the title instead loses those, so the path
// is what is read and the title is what is measured against.
//
// Articles naming no KB are not updates and are skipped: the "Windows 10 update
// history" and "Windows 11, version NNHN update history" hub pages, "End of
// servicing statement" and the support-lifecycle notices, 30 in 2,580.
//
// The rules are checked by taking the pairs each would produce and asking
// whether msuc, wsusscn2 or cvrf records supersedence between them, counting
// only the pairs whose two KBs both appear in that union -- roughly half of the
// .NET ones do not, and a pair with an unknown end can neither confirm nor
// deny. An edge is confirmed if the union records it or reaches it, since the
// union holds direct edges where a chain holds a transitive reduction. Over the
// whole 2,580-article tree that comes to 1,853 of 2,118.
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
	// kbPattern allows the space Microsoft has left after KB once, in
	// "January 26, 2017-KB 3216755 (OS Build 14393.726)". Without it that
	// article reads as naming no KB and is dropped as though it were a hub page.
	kbPattern = regexp.MustCompile(`KB ?(\d{6,})`)

	// datePattern is the release date every article that names a KB opens with,
	// in any of the separators Microsoft has used between it and the KB. The
	// comma is optional for the same reason: "March 18 2021-KB5001633" is
	// missing it, alone in 2,549 articles.
	datePattern = regexp.MustCompile(`^([A-Z][a-z]+ \d{1,2},? \d{4})`)

	// yearPattern and monthPattern recognise the yyyy/mm directories Microsoft
	// files most, but not all, articles beneath.
	yearPattern  = regexp.MustCompile(`^(19|20)\d{2}$`)
	monthPattern = regexp.MustCompile(`^(0[1-9]|1[0-2])$`)

	// buildsPattern is the parenthetical Microsoft puts OS builds in, singular
	// for one and plural for the several an update ships to at once:
	// "(OS Build 28000.2525)", "(OS Builds 26200.8973 and 26100.8973)".
	buildsPattern = regexp.MustCompile(`OS Builds? ([^)]+)`)
	buildPattern  = regexp.MustCompile(`(\d+)\.(\d+)`)

	// productsPattern is what a .NET title names after its version list, the
	// products the update is for: "for .NET Framework 3.5 and 4.8.1 for Windows
	// 11, version 22H2 and Windows 11, version 23H2". versionPattern picks the
	// releases out of that -- 22H2, 24H2, 1809, 2019 -- which is the part that
	// tells two of one directory apart. The OS series name none: their titles
	// carry the kind and leave the product to the directory.
	//
	// buildSuffixPattern is cut out first. "for Windows 11, version 26H1 (build
	// 28000) and later" names one release and would otherwise yield two, the
	// second being the first four digits of a build number. Since two products
	// count as one line on any overlap at all, a spurious release can only ever
	// join lines that should be apart, and would do it silently.
	productsPattern    = regexp.MustCompile(`\.NET Framework .*? for (.*)`)
	buildSuffixPattern = regexp.MustCompile(`(?i)\(build [^)]*\)`)
	versionPattern     = regexp.MustCompile(`(?i)\b\d{2}h\d\b|\b\d{4}\b`)
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

	// products are the OS releases the title names, which tell two lines apart
	// where one directory holds both. Empty where the title names none.
	products []string

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
	for _, line := range slices.Sorted(maps.Keys(unchained)) {
		slog.Warn("articles of an unrecognised kind are left unchained", slog.String("series", line), slog.Int("count", unchained[line]), slog.String("example", example[line]))
	}

	// Two articles of one date in one track are releases beside each other, and
	// chain as such rather than into one another. That they exist at all is
	// worth saying: a date-ordered series is meant to be one line, so a date it
	// ships twice on is usually a directory holding two -- dotnetframework's
	// windows-11/22h2 ran a 22H2 and a 23H2 package side by side for two months
	// before merging them back. The edges are not wrong, but the series is a
	// coarser thing than it looks and the page is worth reading.
	together := coreleased(as)
	for _, line := range slices.Sorted(maps.Keys(together)) {
		for _, d := range together[line] {
			slog.Warn("a series released more than one article of a track on one date", slog.String("series", line), slog.String("date", d.date), slog.Int("count", d.count), slog.String("example", d.example))
		}
	}

	kbs := chain(as)

	// A series of several articles that comes out with no supersedence at all is
	// the failure this cannot otherwise see. The warnings above catch an article
	// whose kind is unrecognised and a path that names no product, but an
	// article can be read perfectly and still chain to nothing -- by being filed
	// away from the rest of its line, where there is nothing to chain it to.
	// os/windows holds two, KB5070882 at 14393.8524 and KB5070883 at 17763.7922,
	// while os/windows-10 runs 191 articles of one build and 164 of the other.
	// Nothing about either article is wrong, so nothing else reports them.
	//
	// A series of one is not counted: it has no second article to link to and
	// says nothing by having no edges.
	linked := make(map[string]bool, len(kbs))
	for _, kb := range kbs {
		if len(kb.Supersedes) > 0 || len(kb.SupersededBy) > 0 {
			linked[kb.KBID] = true
		}
	}
	held := make(map[string]map[string]struct{})
	for _, a := range as {
		if held[a.line] == nil {
			held[a.line] = make(map[string]struct{})
		}
		held[a.line][a.kbID] = struct{}{}
	}
	for _, line := range slices.Sorted(maps.Keys(held)) {
		if len(held[line]) < 2 {
			continue
		}
		if slices.ContainsFunc(slices.Collect(maps.Keys(held[line])), func(k string) bool { return linked[k] }) {
			continue
		}
		slog.Warn("a series of several articles came out with no supersedence at all", slog.String("series", line), slog.Int("count", len(held[line])))
	}

	for _, kb := range kbs {
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
		// Every article naming a KB carries a date -- 2,550 of 2,550 -- so one
		// without is a title shape this has not seen rather than an update that
		// has no date. Ordering it by guesswork would put an edge where there
		// may be none.
		slog.Warn("no date in title", slog.String("path", rel), slog.String("title", a.Title))
		return article{}, false
	}
	date, err := time.Parse("January 2, 2006", dm[1])
	if err != nil {
		date, err = time.Parse("January 2 2006", dm[1])
	}
	if err != nil {
		slog.Warn("unexpected date", slog.String("path", rel), slog.String("date", dm[1]))
		return article{}, false
	}

	line := series(rel)
	if !strings.Contains(line, "/") {
		// Every series but one names its product in the path. The exception is
		// the thirteen under dotnetframework/2026/07/, where Microsoft has
		// dropped the product segment from the newer .NET URLs and the title
		// alone says which line the article belongs to. They are recorded and
		// left to chain among themselves, which -- sharing one release date --
		// comes to nothing rather than to guesswork.
		slog.Warn("no product in path, article is left to a series of its own", slog.String("path", rel), slog.String("title", a.Title))
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
		kbID:     m[1],
		url:      a.URL,
		date:     date,
		line:     line,
		track:    track(a.Title),
		products: products(a.Title),
		builds:   builds,
		raw:      rel,
	}, true
}

// products are the OS releases a title names, lowercased. Nothing is returned
// for the titles that name none.
func products(title string) []string {
	m := productsPattern.FindStringSubmatch(title)
	if m == nil {
		return nil
	}
	return versionPattern.FindAllString(strings.ToLower(buildSuffixPattern.ReplaceAllString(m[1], " ")), -1)
}

// sameLine reports whether two articles of one date and one directory belong to
// the same product line, which is what their titles have to settle: the
// directory has already said they are together and it is wrong.
//
// A title naming no product answers yes, which is what every OS series does and
// is the behaviour there was before there was anything to compare.
func sameLine(x, y article) bool {
	if len(x.products) == 0 || len(y.products) == 0 {
		return true
	}
	for _, p := range x.products {
		if slices.Contains(y.products, p) {
			return true
		}
	}
	return false
}

// series is the product line an article was filed under: its directory, minus
// the yyyy/mm Microsoft files most but not all articles beneath.
//
// The month cannot be taken off by counting segments. Three shapes exist --
// dotnetframework/windows-10/1809/2026/07/<slug>, dotnetframework/2026/07/<slug>
// with no product, and dotnetframework/windows-11/25h2/<slug> with no month --
// and dropping a fixed three from the end reads the product of the third as a
// date and loses it. Fifteen articles under windows-11/25h2, 26h1 and 3-5 were
// collapsed onto one another that way.
func series(rel string) string {
	segs := strings.Split(rel, "/")
	if len(segs) < 2 {
		return rel
	}
	segs = segs[:len(segs)-1]
	if len(segs) >= 2 && yearPattern.MatchString(segs[len(segs)-2]) && monthPattern.MatchString(segs[len(segs)-1]) {
		segs = segs[:len(segs)-2]
	}
	return strings.Join(segs, "/")
}

// track tells apart the lines a legacy series runs at once. The four of them --
// server-2008, server-2012, windows-7 and windows-8-1 -- carry a Monthly
// Rollup, a Security-only update and a Preview of Monthly Rollup, interleaved
// by date.
//
// Only the rollup line is cumulative, and it is the only one chained. Taking
// each track's pairs across all four series and asking whether msuc, wsusscn2
// or cvrf records supersedence between them:
//
//	rollup          386 pairs, 384 confirmed   99%
//	security-only   165 pairs,   6 confirmed    4%
//
// A Security-only update carries one month's fixes and nothing before it, so
// ordering them by date and joining them would assert 159 replacements that no
// source records and that do not happen. They are recorded as KBs and left
// unchained. os/windows-8-1 is the plainest case: 65 pairs, none recorded.
//
// It is superseded across tracks instead, by the rollup of its own month, which
// carries the same fixes and the months before them. Almost no source records
// that -- 5 of 187 same-month pairs -- but msuc synthesises the same edge for
// the same reason, that "Microsoft does NOT consistently record cross-track
// supersession" while "the broader-track update is functionally a superset of
// the narrower".
//
// A Preview is a line of its own, not part of the rollup one. Chained to each
// other they confirm 116 of 116, and each is superseded by the rollup of the
// month it previews, 136 of 137. Ordering them into the rollup line by date
// instead loses the first of those and asserts what the second denies -- that a
// preview supersedes the rollup of its own month, which no source records at
// all, 0 of 130.
//
// The names are matched as Microsoft writes them, case and all, with the one
// casing slip it has made -- "(Monthly rollup)", once in 2,549 articles --
// spelled out rather than folded away. Folding the case would also take in the
// three .NET articles titled "Cumulative update", and those do not belong to
// the line they sit in: msuc has KB4483452 superseding both KB4480056 of
// January 8th and KB4481031 of January 22nd, which makes the second a release
// beside the first rather than after it. Chaining them would assert an edge
// that the record contradicts.
//
// "Security and Quality Rollup" is the .NET legacy line's own name for its
// cumulative track. It has no pairs to check -- Microsoft files seven articles
// under it, all of one date, and none of the predecessors msuc names for them
// are in this source -- so it is recorded on the evidence of what it is, and
// produces nothing until a second date arrives.
func track(title string) string {
	switch {
	case strings.Contains(title, "Security-only"), strings.Contains(title, "Security Only"):
		return trackSecurityOnly
	case strings.Contains(title, "Preview"):
		return trackPreview
	case strings.Contains(title, "Monthly Rollup"), strings.Contains(title, "Monthly rollup"),
		strings.Contains(title, "Cumulative Update"), strings.Contains(title, "Security and Quality Rollup"):
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

// isPatchTuesday reports whether t is the second Tuesday of its month, the day
// Microsoft ships the cumulative update the build line is carried by. A Tuesday
// falling on the 8th through the 14th is the second one of its month.
func isPatchTuesday(t time.Time) bool {
	return t.Weekday() == time.Tuesday && t.Day() >= 8 && t.Day() <= 14
}

// sameDay is one date a series shipped more than one article of a track on.
type sameDay struct {
	date    string
	count   int
	example string
}

// coreleased finds the dates a date-ordered series shipped more than one
// article of one track on, by series and in date order. Articles carrying build
// numbers are ordered by those and share a date freely, so they are not counted.
func coreleased(as []article) map[string][]sameDay {
	type key struct {
		line, track string
		date        time.Time
	}
	days := make(map[key][]article)
	for _, a := range as {
		if len(a.builds) > 0 || a.track == trackUnknown {
			continue
		}
		k := key{line: a.line, track: a.track, date: a.date}
		days[k] = append(days[k], a)
	}

	out := make(map[string][]sameDay)
	for k, group := range days {
		if len(group) < 2 {
			continue
		}
		out[k.line] = append(out[k.line], sameDay{
			date:    k.date.Format(time.DateOnly),
			count:   len(group),
			example: slices.MinFunc(group, func(x, y article) int { return cmp.Compare(x.raw, y.raw) }).raw,
		})
	}
	for line := range out {
		slices.SortFunc(out[line], func(x, y sameDay) int { return cmp.Compare(x.date, y.date) })
	}
	return out
}

// dates splits a date-sorted group into the runs that share one date.
func dates(group []article) [][]article {
	var out [][]article
	for i := 0; i < len(group); {
		j := i + 1
		for j < len(group) && group[j].date.Equal(group[i].date) {
			j++
		}
		out = append(out, group[i:j])
		i = j
	}
	return out
}

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
	// chain and each claims to supersede the other's updates. Keyed this way
	// os/windows-server confirms 156 of 156.
	//
	// A build line runs two releases a month and only one of them is the line.
	// The cumulative update of the second Tuesday is what the next month's
	// builds on; the optional releases of the weeks after it, and the
	// out-of-band ones, carry the same fixes to the same build without the
	// following month ever taking them up. Microsoft's revision numbers
	// interleave the two, so ordering by revision alone threads them into one
	// chain -- msuc has KB4022727 of June 13th superseded by KB4025338 of July
	// 11th, and KB4032695 of June 27th, whose revision falls between them,
	// superseded by neither of them but by the next month's optional release.
	// Splitting the two takes the build chains from 771 of 1,198 confirmed to
	// 1,122 of 1,183.
	type buildLine struct {
		series  string
		major   int
		monthly bool
	}
	byBuild := make(map[buildLine][]article)
	for _, a := range as {
		for _, b := range a.builds {
			bl := buildLine{series: a.line, major: b.major, monthly: isPatchTuesday(a.date)}
			byBuild[bl] = append(byBuild[bl], a)
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
		// Two articles do share a revision, where Microsoft has shipped a build
		// twice off the same cadence: KB4075199 of January 18th and KB4077735 of
		// the 31st are both 10240.17741. The release date decides those, and the
		// KB number only where even that ties -- ordering by the number alone
		// would be right on both pairs this fires on by the accident that
		// Microsoft allocates them in order, and wrong the first time it does
		// not.
		slices.SortFunc(group, func(x, y article) int {
			return cmp.Or(cmp.Compare(revision(x), revision(y)), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
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
		// It is the date that links, not the article. Two of one date are
		// releases beside each other -- so ordering them by KB number and
		// joining them asserts a replacement between updates that shipped the
		// same morning, which of 2,149 such pairs msuc, wsusscn2 and cvrf record
		// five of. Each date links to the one before it instead.
		//
		// Which of them link is then a question, because a date that ships twice
		// is a directory holding two lines rather than one line shipping twice.
		// dotnetframework/windows-11/22h2 ran a 22H2 and a 23H2 package side by
		// side through September and October 2023 before merging them back, and
		// joining every article of one date to every article of the next crosses
		// them: msuc records KB5028948 superseded by the 22H2 of September and
		// not the 23H2, and the two Octobers by neither. So where a date holds
		// more than one, the products their titles name decide.
		//
		// Where a date holds one, it links whatever it is called. The directory
		// is the line and the title drifts along it -- "Microsoft server
		// operating system version 21H2" became "Windows Server 2022" between
		// two consecutive articles of one chain, an edge msuc records and
		// comparing products would refuse.
		days := dates(group)
		for i := 1; i < len(days); i++ {
			prev, cur := days[i-1], days[i]
			for _, older := range prev {
				for _, newer := range cur {
					if len(prev) > 1 || len(cur) > 1 {
						if !sameLine(older, newer) {
							continue
						}
					}
					links = append(links, link{older: older.kbID, newer: newer.kbID})
				}
			}
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
