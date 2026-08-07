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

// track separates the lines a legacy series runs at once. A Security-only
// update and a Monthly Rollup ship the same month and supersede along their own
// lines, so an edge between them would say one contains the other.
//
// A Preview is not a track of its own: it is the next rollup released early,
// and the rollup that follows supersedes it.
func track(title string) string {
	if strings.Contains(title, "Security-only") || strings.Contains(title, "Security Only") {
		return "security-only"
	}
	return "rollup"
}

// chain turns the articles into KB records, chained into supersedence.
//
// An update ships to more than one build at a time -- "(OS Builds 26200.8973
// and 26100.8973)" is one KB on two lines -- so it takes its place in each of
// their chains and ends up with the edges of both.
func chain(as []article) []microsoftkbTypes.KB {
	type link struct{ older, newer string }
	var links []link

	// By build where Microsoft gives one. Revision order is supersedence: a
	// cumulative update at .8973 contains .8894.
	byBuild := make(map[int][]article)
	for _, a := range as {
		for _, b := range a.builds {
			byBuild[b.major] = append(byBuild[b.major], a)
		}
	}
	for major, group := range byBuild {
		revision := func(a article) int {
			for _, b := range a.builds {
				if b.major == major {
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
		if len(a.builds) > 0 {
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
	slices.SortFunc(out, microsoftkbTypes.Compare)

	return out
}
