// Package exchange extracts supersedence from Microsoft's Exchange Server build
// numbers and release dates.
//
// The page carries no supersedence. What it carries is every build Exchange has
// shipped, and the build number is the order -- but not in one line. Exchange
// services every cumulative update level that is still supported, side by side,
// and the build number says which:
//
//	Exchange Server 2019 CU15 Aug26SU   15.2.1748.49
//	Exchange Server 2019 CU15 Jul26SU   15.2.1748.48
//	Exchange Server 2019 CU14 Aug26SU   15.2.1544.44
//
// The third component is the cumulative update and the fourth is the security
// update within it. A host on CU14 is not served by CU15's update and never
// will be, so the lane is the chain: keyed on the table and the first three
// components, ordered by the fourth. Thirty-seven of them run across the page,
// and over their 121 edges the build order and the release dates never disagree.
//
// One KB is on many lanes. KB5000871, the March 2021 update, appears on
// twenty-five rows -- every supported cumulative update level of Exchange 2013,
// 2016 and 2019 got its own patched build of the one fix -- so it takes its
// place in each of their chains and ends up with the edges of all of them.
//
// The table has to be part of the key rather than the build alone. Exchange
// Server SE and Exchange Server 2019 are both 15.2, and only the table Microsoft
// filed a row under says which product it is.
//
// Rows naming no KB are the cumulative updates themselves, which ship as
// downloads rather than as KB articles, and every build of Exchange 2010 and
// earlier. They are skipped: a chain of KBs has no place for them.
package exchange

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/exchange"
)

// The columns a row is read out of, by name. The build is taken from the short
// format; the long one is the same number with its parts zero-padded.
const (
	columnProduct = "Product name"
	columnDate    = "Release date"
	columnBuild   = "Build number (short format)"
)

var (
	// kbPattern reads the KB out of the link on a product's name, that being
	// where this page puts it.
	kbPattern = regexp.MustCompile(`support\.microsoft\.com/(?:[a-z-]+/)?(?:help|kb)/(\d{6,})`)

	// buildPattern is an Exchange build number. Four components on every row
	// that names a KB; the older tables, which name none, use fewer.
	buildPattern = regexp.MustCompile(`^\d+(?:\.\d+){3}$`)
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

// update is one build, read for what decides its place in a chain.
type update struct {
	kbID string
	url  string

	// version is the heading the table sits under, e.g. "Exchange Server 2019".
	// Exchange Server SE shares 15.2 with it, so the build number alone would
	// not tell the two apart.
	version string

	// name is the product name as written, e.g. "Exchange Server 2019 CU15
	// Aug26SU". Nothing is parsed out of it -- the build number says everything
	// the name does, and says it the same way every time.
	name string

	build    []int
	buildStr string

	date time.Time

	raw string
}

// lane is the cumulative update level an update patches: everything of the
// build but its last component, which is the update's place within the lane.
func (u update) lane() string {
	parts := make([]string, 0, len(u.build)-1)
	for _, p := range u.build[:len(u.build)-1] {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ".")
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "exchange"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Exchange Build Numbers and Release Dates")

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
		ID:   sourceTypes.MicrosoftExchange,
		Name: new("Microsoft Exchange Build Numbers and Release Dates"),
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

		var page exchange.Page
		if err := json.UnmarshalRead(f, &page); err != nil {
			return errors.Wrapf(err, "decode %s", p)
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return errors.Wrapf(err, "rel %s", p)
		}

		us = append(us, parsePage(page, filepath.ToSlash(rel))...)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return us, nil
}

// parsePage reads a page's build histories.
func parsePage(page exchange.Page, raw string) []update {
	var us []update

	for _, t := range page.Tables {
		var missing []string
		for _, c := range []string{columnProduct, columnDate, columnBuild} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			// Exchange Server 2003 and earlier are listed with a single "Build
			// number" column and name no KB, so there is nothing here to lose.
			slog.Debug("not a build history this can read", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("missing", strings.Join(missing, ", ")))
			continue
		}

		for _, row := range t.Rows {
			u, ok := parseRow(t, row, raw)
			if !ok {
				continue
			}
			us = append(us, u)
		}
	}

	return us
}

// parseRow reads one row, reporting false for the ones that are not updates.
func parseRow(t exchange.Table, row []exchange.Cell, raw string) (update, bool) {
	cell := func(column string) exchange.Cell {
		i := slices.Index(t.Header, column)
		if i < 0 || i >= len(row) {
			return exchange.Cell{}
		}
		return row[i]
	}

	product := cell(columnProduct)

	m := kbPattern.FindStringSubmatch(product.Href)
	if m == nil {
		// A cumulative update, a service pack or a build of Exchange 2010 and
		// earlier. Those ship as downloads rather than as KB articles, so the
		// name links to the Download Center or to nothing at all.
		slog.Debug("build names no KB", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("product", product.Text))
		return update{}, false
	}

	bs := cell(columnBuild).Text
	if !buildPattern.MatchString(bs) {
		// The build is the whole order, and its last component is the update's
		// place in its lane. A row without one cannot be placed at all.
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

	// The date is a tiebreaker between two builds of one lane, not the order,
	// so an unreadable one costs the tie and not the row.
	var date time.Time
	if d := cell(columnDate).Text; d != "" {
		var err error
		date, err = time.Parse("January 2, 2006", d)
		if err != nil {
			slog.Warn("unexpected release date", slog.String("path", raw), slog.String("kb", m[1]), slog.String("date", d))
			date = time.Time{}
		}
	}

	return update{
		kbID:     m[1],
		url:      product.Href,
		version:  t.Heading,
		name:     product.Text,
		build:    build,
		buildStr: bs,
		date:     date,
		raw:      raw,
	}, true
}

// chain turns the builds into KB records, chained into supersedence.
func chain(us []update) []microsoftkbTypes.KB {
	type buildLane struct {
		version string
		lane    string
	}

	lanes := make(map[buildLane][]update)
	for _, u := range us {
		lanes[buildLane{version: u.version, lane: u.lane()}] = append(lanes[buildLane{version: u.version, lane: u.lane()}], u)
	}

	type link struct{ older, newer string }
	var links []link
	for bl, group := range lanes {
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(slices.Compare(x.build, y.build), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})

		for i := 1; i < len(group); i++ {
			older, newer := group[i-1], group[i]

			// The build is the order and the date is not, but where the two
			// disagree the row is worth reading. Over the whole page they never
			// have.
			if !older.date.IsZero() && !newer.date.IsZero() && newer.date.Before(older.date) {
				slog.Warn("a lane's builds and release dates disagree",
					slog.String("version", bl.version), slog.String("lane", bl.lane),
					slog.String("older", fmt.Sprintf("KB%s %s %s", older.kbID, older.buildStr, older.date.Format(time.DateOnly))),
					slog.String("newer", fmt.Sprintf("KB%s %s %s", newer.kbID, newer.buildStr, newer.date.Format(time.DateOnly))))
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
					ID: sourceTypes.MicrosoftExchange,
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
		// A KB is on many lanes and the lanes are patched in step, so one of
		// them can name the next KB that another has already named. It is one
		// edge either way.
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
