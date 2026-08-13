// Package scom extracts supersedence from Microsoft's System Center Operations
// Manager build versions.
//
// The article carries no supersedence. What it carries is every update rollup
// each component has shipped, and the build number is the order within a
// component: the management server, the agent and gateway and the SCX agent
// advance on their own numbers under the one rollup, so an update rollup is
// three builds and one KB.
//
// The KB is written as a bare number linked to the support site --
// "[5068304](https://support.microsoft.com/kb/5068304)" -- so it is read from
// the link rather than from the text. The same column on the SCX agent's tables
// holds a version linked to a GitHub release, "[v1.6.9-0](https://github.com/...)",
// which is not a KB at all and is what makes the link the thing to read.
//
// Which product version a table belongs to is in neither the table nor the file
// it is in. The article is four INCLUDE directives, one per version, and the
// file each pulls in is named for it, so the path is what says it.
//
// The general availability rows carry no KB, being the product rather than an
// update to it, and are skipped.
package scom

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/scom"
)

// The columns a row is read out of, by name.
const (
	columnBuild       = "Build Number"
	columnKB          = "KB"
	columnDate        = "Release Date"
	columnDescription = "Description"
)

var (
	// kbPattern reads the KB out of the link on the number, that being where
	// this article puts it. A link anywhere else -- GitHub, on the SCX agent's
	// tables -- names no KB and does not match.
	kbPattern = regexp.MustCompile(`support\.microsoft\.com/(?:[a-z-]+/)?(?:kb|help)/(\d{6,})`)

	buildPattern = regexp.MustCompile(`^\d+(?:\.\d+){2,3}$`)

	// versionPattern is the product version, which is in the name of the file a
	// table was included from and nowhere else.
	versionPattern = regexp.MustCompile(`release-build-versions-(\d{4})\.json$`)

	// datePattern is the release date, a month with no day in every row.
	datePattern = regexp.MustCompile(`^([A-Za-z]+) (\d{4})$`)
)

var months = map[string]time.Month{
	"january": time.January, "february": time.February, "march": time.March,
	"april": time.April, "may": time.May, "june": time.June,
	"july": time.July, "august": time.August, "september": time.September,
	"october": time.October, "november": time.November, "december": time.December,
}

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

// update is one build, read for what decides its place in a chain.
type update struct {
	kbID string
	url  string

	// version is the product, taken from the path of the file the table was
	// included from, e.g. "System Center 2022 - Operations Manager".
	version string

	// component is the heading the table sits under -- the management server,
	// the agent and gateway, or the SCX agent -- which advance on their own
	// build numbers and so are chained apart.
	component string

	build    []int
	buildStr string

	// description is the rollup as written, e.g. "Update Rollup 1". Nothing is
	// parsed out of it: the build number is the order and says the same thing
	// without being prose.
	description string

	date time.Time

	raw string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "scom"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft System Center Operations Manager Build Versions")

	us, err := read(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}

	kbs := chain(us)

	for _, kb := range kbs {
		if err := util.Write(filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftSCOM,
		Name: new("Microsoft System Center Operations Manager Build Versions"),
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

// read walks the raw tree and returns the builds that name a KB.
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

		var a scom.Article
		if err := json.UnmarshalRead(f, &a); err != nil {
			return errors.Wrapf(err, "decode %s", p)
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}

		us = append(us, parseArticle(a, filepath.ToSlash(rel))...)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return us, nil
}

// parseArticle reads one file's build tables.
func parseArticle(a scom.Article, raw string) []update {
	version, ok := version(raw)
	if !ok {
		// The article itself, which holds the INCLUDE directives and no tables,
		// and the note one of them pulls in beside them.
		slog.Debug("not a build table file", slog.String("path", raw))
		return nil
	}

	var us []update
	for _, t := range a.Tables {
		var missing []string
		for _, c := range []string{columnBuild, columnKB, columnDate} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			slog.Warn("build table is missing columns", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("missing", strings.Join(missing, ", ")), slog.String("header", strings.Join(t.Header, ", ")))
			continue
		}

		for _, row := range t.Rows {
			u, ok := parseRow(t, row, version, raw)
			if !ok {
				continue
			}
			us = append(us, u)
		}
	}

	return us
}

// version is the product a file's tables are for, which is in the file's name.
func version(raw string) (string, bool) {
	m := versionPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return fmt.Sprintf("System Center %s - Operations Manager", m[1]), true
}

// parseRow reads one row, reporting false for the ones that are not updates.
func parseRow(t scom.Table, row []scom.Cell, version, raw string) (update, bool) {
	cell := func(column string) scom.Cell {
		i := slices.Index(t.Header, column)
		if i < 0 || i >= len(row) {
			return scom.Cell{}
		}
		return row[i]
	}

	kb := cell(columnKB)

	m := kbPattern.FindStringSubmatch(kb.Href)
	if m == nil {
		// A general availability row, which is the product rather than an
		// update to it and carries no KB -- Microsoft writes the cell empty or
		// as a dash -- or an SCX agent row, whose KB column holds a version
		// linked to a GitHub release instead.
		slog.Debug("build names no KB", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("build", cell(columnBuild).Text), slog.String("kb", kb.Text))
		return update{}, false
	}

	bs := cell(columnBuild).Text
	if !buildPattern.MatchString(bs) {
		// The build is the whole order within a component. A row without one
		// cannot be placed.
		slog.Warn("unexpected build", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("kb", m[1]), slog.String("build", bs))
		return update{}, false
	}
	build := make([]int, 0, 4)
	for _, p := range strings.Split(bs, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			slog.Warn("unexpected build", slog.String("path", raw), slog.String("kb", m[1]), slog.String("build", bs))
			return update{}, false
		}
		build = append(build, n)
	}

	// The date is a tiebreaker between two builds of one component, not the
	// order, so an unreadable one costs the tie and not the row.
	var date time.Time
	if d := cell(columnDate).Text; d != "" {
		var ok bool
		date, ok = releaseDate(d)
		if !ok {
			slog.Warn("unexpected release date", slog.String("path", raw), slog.String("kb", m[1]), slog.String("date", d))
		}
	}

	return update{
		kbID:        m[1],
		url:         kb.Href,
		version:     version,
		component:   t.Heading,
		build:       build,
		buildStr:    bs,
		description: cell(columnDescription).Text,
		date:        date,
		raw:         raw,
	}, true
}

// releaseDate reads the month a row was released. Every row of the article is a
// month with no day, so a month is taken as its first.
func releaseDate(s string) (time.Time, bool) {
	m := datePattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return time.Time{}, false
	}

	month, ok := months[strings.ToLower(m[1])]
	if !ok {
		return time.Time{}, false
	}

	year, err := strconv.Atoi(m[2])
	if err != nil {
		return time.Time{}, false
	}

	return time.Date(year, month, 1, 0, 0, 0, 0, time.UTC), true
}

// chain turns the builds into KB records, chained into supersedence.
func chain(us []update) []microsoftkbTypes.KB {
	type line struct {
		version   string
		component string
	}

	lines := make(map[line][]update)
	for _, u := range us {
		lines[line{version: u.version, component: u.component}] = append(lines[line{version: u.version, component: u.component}], u)
	}

	type link struct{ older, newer string }
	var links []link
	for l, group := range lines {
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(slices.Compare(x.build, y.build), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})

		for i := 1; i < len(group); i++ {
			older, newer := group[i-1], group[i]

			if !older.date.IsZero() && !newer.date.IsZero() && newer.date.Before(older.date) {
				slog.Warn("a component's builds and release dates disagree",
					slog.String("version", l.version), slog.String("component", l.component),
					slog.String("older", fmt.Sprintf("KB%s %s %s", older.kbID, older.buildStr, older.date.Format("January 2006"))),
					slog.String("newer", fmt.Sprintf("KB%s %s %s", newer.kbID, newer.buildStr, newer.date.Format("January 2006"))))
			}

			links = append(links, link{older: older.kbID, newer: newer.kbID})
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
					ID: sourceTypes.MicrosoftSCOM,
				},
			}
			kbs[u.kbID] = kb
		}
		if !slices.Contains(kb.Products, u.version) {
			kb.Products = append(kb.Products, u.version)
		}
		if !slices.Contains(kb.DataSource.Raws, u.raw) {
			kb.DataSource.Raws = append(kb.DataSource.Raws, u.raw)
		}
	}

	for _, l := range links {
		// One update rollup is one KB across three components, so a component
		// can name an edge another has already named. It is one edge either way.
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
