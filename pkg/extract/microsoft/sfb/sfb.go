// Package sfb extracts supersedence from Microsoft's Skype for Business Server
// update history.
//
// The page carries no supersedence and no build numbers to derive one from --
// the Subscription Edition's table has a Build number column and no other table
// does. What every row has is a release date, so the date is the order, within
// the product a table is filed under. Six products run across the page, from
// Lync Server 2010 to the Subscription Edition.
//
// The date is a month. 100 of the page's 104 rows are dated "August 2025" with
// no day in them, so two updates of one month cannot be told apart and are not
// ordered against each other: a month links to the month before it, all of one
// to all of the other, which is what the servicing source does with the dates it
// cannot split either. Four rows do carry a day, and one of those writes its
// month as "Sept".
//
// Four KBs are not updates but articles. Microsoft revises one KB in place for
// every hotfix of a cumulative update line -- KB4470124 is fifteen rows of
// Skype for Business Server 2019, from Cumulative Update 5 in 2020 to Cumulative
// Update 8 Hotfix 2 in 2025, and KB3061064 is twelve of Server 2015 -- so
// "KB4470124 is installed" does not say which of the fifteen a host has. A KB
// like that cannot be placed in a chain at all: an edge into it would claim a
// patch level it does not name. They are recorded for their products and left
// unchained, and reported so that a fifth is noticed.
//
// A KB on several rows of one month is a different thing and is chained
// normally: KB5016714 is one July 2022 update listed under the three products
// it was released for.
package sfb

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/sfb"
)

// The columns a row is read out of, by name. A table without a KB number column
// lists tools, virtual machines or documentation rather than updates.
const (
	columnPackage = "Package name"
	columnKB      = "KB number"
	columnDate    = "Release date"
)

var (
	// kbPattern allows the space this page writes after KB, as every one of its
	// 104 rows does.
	kbPattern = regexp.MustCompile(`KB ?(\d{6,})`)

	// datePattern is the release date. The day is optional because four rows in
	// 104 have one, and the month is matched loosely because one of those four
	// writes September as "Sept".
	datePattern = regexp.MustCompile(`^([A-Za-z]+)\.? (?:(\d{1,2}), )?(\d{4})$`)
)

// months are the names this page writes, in the two lengths it writes them.
var months = map[string]time.Month{
	"jan": time.January, "feb": time.February, "mar": time.March,
	"apr": time.April, "may": time.May, "jun": time.June,
	"jul": time.July, "aug": time.August, "sep": time.September,
	"oct": time.October, "nov": time.November, "dec": time.December,
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

// update is one row of an update history.
type update struct {
	kbID string
	url  string

	// product is the heading the table sits under, e.g. "Lync Server 2013
	// update history". It is the only place a row's product is named.
	product string

	// name is the package as written, e.g. "Skype for Business Server 2019
	// Cumulative Update 8, Hotfix 2". Nothing is parsed out of it: Microsoft
	// writes cumulative updates, hotfixes and security updates into the one
	// column in prose, and the date says what the order is without it.
	name string

	date time.Time

	raw string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "sfb"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Skype for Business Server Updates")

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
		ID:   sourceTypes.MicrosoftSfB,
		Name: new("Microsoft Skype for Business Server Updates"),
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

		var page sfb.Page
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

// parsePage reads a page's update histories.
func parsePage(page sfb.Page, raw string) []update {
	var us []update

	for _, t := range page.Tables {
		if !slices.Contains(t.Header, columnKB) {
			// Tools, pre-configured virtual machines, developer kits and
			// documentation. Ten of the page's sixteen tables are these, and
			// none of them ships a KB.
			slog.Debug("not an update history", slog.String("path", raw), slog.String("heading", t.Heading))
			continue
		}

		var missing []string
		for _, c := range []string{columnPackage, columnDate} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			slog.Warn("update history is missing columns", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("missing", strings.Join(missing, ", ")), slog.String("header", strings.Join(t.Header, ", ")))
			continue
		}

		for _, row := range t.Rows {
			us = append(us, parseRow(t, row, raw)...)
		}
	}

	return us
}

// parseRow reads one row into the updates it names, which is usually one.
//
// Two rows name two KBs, comma-separated on one and merely spaced on the other:
// a release that shipped an update for the server and another for a component
// beside it. Both are updates of that product and that month, so both are read.
func parseRow(t sfb.Table, row []sfb.Cell, raw string) []update {
	cell := func(column string) sfb.Cell {
		i := slices.Index(t.Header, column)
		if i < 0 || i >= len(row) {
			return sfb.Cell{}
		}
		return row[i]
	}

	kb := cell(columnKB)

	ms := kbPattern.FindAllStringSubmatch(kb.Text, -1)
	if ms == nil {
		slog.Debug("row names no KB", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("package", cell(columnPackage).Text))
		return nil
	}

	// The date is the whole order here, there being no build number to fall
	// back on, so a row without a readable one cannot be placed at all.
	date, ok := releaseDate(cell(columnDate).Text)
	if !ok {
		slog.Warn("unexpected release date", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("kb", ms[0][1]), slog.String("date", cell(columnDate).Text))
		return nil
	}

	out := make([]update, 0, len(ms))
	for i, m := range ms {
		// The cell links its first KB and leaves the rest as text, so a second
		// KB is recorded without a URL rather than given the first's.
		var href string
		if i == 0 {
			href = kb.Href
		}

		out = append(out, update{
			kbID:    m[1],
			url:     href,
			product: t.Heading,
			name:    cell(columnPackage).Text,
			date:    date,
			raw:     raw,
		})
	}

	return out
}

// releaseDate reads the month a row was released, and the day where Microsoft
// gave one.
//
// A month with no day is taken as its first, which orders it against the months
// around it and against nothing within its own -- and within its own is exactly
// where this source cannot tell two updates apart, so the chain does not try.
func releaseDate(s string) (time.Time, bool) {
	m := datePattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return time.Time{}, false
	}

	name := strings.ToLower(m[1])
	if len(name) < 3 {
		return time.Time{}, false
	}
	month, ok := months[name[:3]]
	if !ok {
		return time.Time{}, false
	}

	year, err := strconv.Atoi(m[3])
	if err != nil {
		return time.Time{}, false
	}

	day := 1
	if m[2] != "" {
		day, err = strconv.Atoi(m[2])
		if err != nil {
			return time.Time{}, false
		}
	}

	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC), true
}

// chain turns the rows into KB records, chained into supersedence.
func chain(us []update) []microsoftkbTypes.KB {
	// A KB written across more than one month is an article Microsoft revises
	// in place rather than an update, and has no one place in a chain. It is
	// recorded and left out of the ordering.
	months := make(map[string]map[time.Time]struct{})
	for _, u := range us {
		if months[u.kbID] == nil {
			months[u.kbID] = make(map[time.Time]struct{})
		}
		months[u.kbID][time.Date(u.date.Year(), u.date.Month(), 1, 0, 0, 0, 0, time.UTC)] = struct{}{}
	}
	revised := make(map[string]struct{})
	for kbID, ms := range months {
		if len(ms) > 1 {
			revised[kbID] = struct{}{}
		}
	}
	for _, kbID := range slices.Sorted(maps.Keys(revised)) {
		var names []string
		for _, u := range us {
			if u.kbID == kbID {
				names = append(names, fmt.Sprintf("%s (%s)", u.name, u.date.Format("January 2006")))
			}
		}
		slog.Warn("a KB is revised in place across releases and is left unchained", slog.String("kb", kbID), slog.Int("releases", len(names)), slog.String("example", names[0]))
	}

	products := make(map[string][]update)
	for _, u := range us {
		if _, ok := revised[u.kbID]; ok {
			continue
		}
		products[u.product] = append(products[u.product], u)
	}

	type link struct{ older, newer string }
	var links []link
	for _, group := range products {
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})

		// It is the date that links, not the row. Two updates of one month are
		// releases beside each other -- the page gives no day to tell them
		// apart by -- so each month links to the month before it rather than
		// its rows being threaded into a line.
		for i := 0; i < len(group); {
			j := i + 1
			for j < len(group) && group[j].date.Equal(group[i].date) {
				j++
			}
			if i > 0 {
				k := i - 1
				for k > 0 && group[k-1].date.Equal(group[i-1].date) {
					k--
				}
				for _, older := range group[k:i] {
					for _, newer := range group[i:j] {
						links = append(links, link{older: older.kbID, newer: newer.kbID})
					}
				}
			}
			i = j
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
					ID: sourceTypes.MicrosoftSfB,
				},
			}
			kbs[u.kbID] = kb
		}
		if kb.URL == "" {
			kb.URL = u.url
		}
		if !slices.Contains(kb.Products, u.product) {
			kb.Products = append(kb.Products, u.product)
		}
		if !slices.Contains(kb.DataSource.Raws, u.raw) {
			kb.DataSource.Raws = append(kb.DataSource.Raws, u.raw)
		}
	}

	for _, l := range links {
		// One KB is listed under several products of one month, so two of them
		// can name each other from opposite sides. It is no edge at all.
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
