// Package sharepoint extracts supersedence from Microsoft's SharePoint Server
// update history.
//
// The page carries no supersedence. What it carries is every public update a
// package has shipped, and the version number is the order: a cumulative update
// contains the one below it. Reading the packages apart is this package's job.
//
// A row is not one update. It describes two at once, naming the packages one
// per line and their KBs one per line beside them, matched by position:
//
//	SharePoint Server 2019                     KB 5002894
//	SharePoint Server 2019 MUI/language patch   KB 5002896
//
// and the two are separate chains. On the Subscription Edition, 2019 and 2016
// the second is the language pack of the first; on 2013 and 2010 it is
// SharePoint Foundation beside SharePoint Server, a different product
// altogether. Either way they ship their own KBs at their own versions and
// neither replaces the other, so the package name is what a chain is keyed on.
// Ten of them run across the page, from SharePoint Foundation 2010 to the
// Subscription Edition's language pack.
//
// The version orders them and the release date does not, because most of the
// page has no day in it: 411 of the 769 rows are dated by month alone, "April
// 2026", against 45 written out in full. The two never disagree -- over all 759
// edges there is not one pair whose versions and dates run opposite ways, and no
// two updates of a package share a version -- so the date is kept as a
// tiebreaker it has never had to break.
package sharepoint

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/sharepoint"
)

// The columns a row is read out of, by name.
const (
	columnPackage = "Package Name"
	columnKB      = "KB Number"
	columnVersion = "Version"
	columnDate    = "Release Date"
)

var (
	// kbPattern allows the space Microsoft writes on this page and nowhere else
	// in the estate: every one of the 769 is written "KB 5002893".
	kbPattern = regexp.MustCompile(`KB ?(\d{6,})`)

	versionPattern = regexp.MustCompile(`^\d+(?:\.\d+){2,3}$`)

	// datePattern is the release date, with the day Microsoft writes on the
	// newer rows and without it on the older ones. A row dated by month alone
	// is taken as its first, which orders it against the months around it and
	// against nothing within its own -- which is all the date is ever asked to
	// do here.
	//
	// It is searched rather than anchored because two rows open with the
	// service pack instead: "Service Pack 2 July 2013".
	datePattern = regexp.MustCompile(`([A-Z][a-z]+) (?:(\d{1,2}), )?(\d{4})`)

	// noUpdatePattern is how Microsoft writes a month one package of a row
	// shipped nothing in, rather than leaving the cell blank.
	noUpdatePattern = regexp.MustCompile(`(?i)^No update for\b`)
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

// update is one package's release, read for what decides its place in a chain.
type update struct {
	kbID string
	url  string

	// pkg is the package the update is for, e.g. "SharePoint Server 2019" or
	// "SharePoint Foundation 2013". It is the chain.
	pkg string

	version    []int
	versionStr string

	date time.Time

	raw string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "sharepoint"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft SharePoint Update History")

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
		ID:   sourceTypes.MicrosoftSharePoint,
		Name: new("Microsoft SharePoint Update History"),
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

// read walks the raw tree and returns the releases it holds.
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

		var page sharepoint.Page
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
func parsePage(page sharepoint.Page, raw string) []update {
	var us []update

	for _, t := range page.Tables {
		var missing []string
		for _, c := range []string{columnPackage, columnKB, columnVersion, columnDate} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			slog.Debug("not an update history", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("missing", strings.Join(missing, ", ")))
			continue
		}

		for _, row := range t.Rows {
			us = append(us, parseRow(t, row, raw)...)
		}
	}

	return us
}

// parseRow reads one row into the releases it describes, one per package named.
func parseRow(t sharepoint.Table, row []sharepoint.Cell, raw string) []update {
	cell := func(column string) sharepoint.Cell {
		i := slices.Index(t.Header, column)
		if i < 0 || i >= len(row) {
			return sharepoint.Cell{}
		}
		return row[i]
	}

	pkgs, kbs, versions := cell(columnPackage).Lines, cell(columnKB).Lines, cell(columnVersion).Lines

	// The packages and their KBs are matched by position, so a row naming more
	// of one than the other cannot be matched at all: pairing what there is
	// would attach a KB to whichever package happened to line up with it. Every
	// one of the 769 releases on the page pairs one to one.
	if len(pkgs) != len(kbs) {
		slog.Warn("row names a different number of packages and KBs", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("packages", strings.Join(texts(pkgs), " / ")), slog.String("kbs", strings.Join(texts(kbs), " / ")))
		return nil
	}

	// The date is one for the whole row -- the packages of a row ship together
	// -- so it is read once.
	var date time.Time
	if lines := cell(columnDate).Lines; len(lines) > 0 {
		var ok bool
		date, ok = releaseDate(lines[0].Text)
		if !ok {
			slog.Warn("unexpected release date", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("date", lines[0].Text))
		}
	}

	out := make([]update, 0, len(pkgs))
	for i, pkg := range pkgs {
		m := kbPattern.FindStringSubmatch(kbs[i].Text)
		if m == nil {
			// A month one package of a row shipped nothing in, which Microsoft
			// writes out rather than leaving blank: SharePoint Foundation 2010
			// says "No update for June." beside SharePoint Server 2010's KB
			// three times in 2015. It is a release that did not happen, not a
			// release this failed to read, so it is not reported as one.
			if noUpdatePattern.MatchString(kbs[i].Text) {
				slog.Debug("package shipped no update", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("package", pkg.Text), slog.String("kb", kbs[i].Text))
				continue
			}
			slog.Warn("package names no KB", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("package", pkg.Text), slog.String("kb", kbs[i].Text))
			continue
		}

		// The version is written once where the packages share it and once each
		// where they do not, which is how Microsoft has written both.
		var vs string
		switch {
		case i < len(versions):
			vs = versions[i].Text
		case len(versions) > 0:
			vs = versions[0].Text
		}
		if !versionPattern.MatchString(vs) {
			// The version is the whole order. A release without one cannot be
			// placed, and every one of the 769 has had it.
			slog.Warn("unexpected version", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("kb", m[1]), slog.String("version", vs))
			continue
		}
		version := make([]int, 0, 4)
		bad := false
		for _, p := range strings.Split(vs, ".") {
			n, err := strconv.Atoi(p)
			if err != nil {
				bad = true
				break
			}
			version = append(version, n)
		}
		if bad {
			slog.Warn("unexpected version", slog.String("path", raw), slog.String("kb", m[1]), slog.String("version", vs))
			continue
		}

		out = append(out, update{
			kbID:       m[1],
			url:        kbs[i].Href,
			pkg:        pkg.Text,
			version:    version,
			versionStr: vs,
			date:       date,
			raw:        raw,
		})
	}

	return out
}

// releaseDate reads the date a row was released.
//
// Most of the page is dated by month alone, and a month is taken as its first
// day: the date only ever orders a release against other months, the version
// having already ordered it within its own.
func releaseDate(s string) (time.Time, bool) {
	m := datePattern.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}

	day := m[2]
	if day == "" {
		day = "1"
	}

	t, err := time.Parse("January 2 2006", fmt.Sprintf("%s %s %s", m[1], day, m[3]))
	if err != nil {
		return time.Time{}, false
	}

	return t, true
}

func texts(lines []sharepoint.Line) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.Text)
	}
	return out
}

// chain turns the releases into KB records, chained into supersedence.
func chain(us []update) []microsoftkbTypes.KB {
	packages := make(map[string][]update)
	for _, u := range us {
		packages[u.pkg] = append(packages[u.pkg], u)
	}

	type link struct{ older, newer string }
	var links []link
	for _, group := range packages {
		// No two releases of a package share a version, so the date and the KB
		// number are tiebreakers that have never had to break one. They are
		// there because the first time Microsoft ships one twice, the order
		// should not fall to whichever the walk reached first.
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(slices.Compare(x.version, y.version), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})

		for i := 1; i < len(group); i++ {
			older, newer := group[i-1], group[i]

			// The version is the order and the date is not, but where the two
			// disagree the row is worth reading. Over the whole page they never
			// have.
			if !older.date.IsZero() && !newer.date.IsZero() && newer.date.Before(older.date) {
				slog.Warn("a package's versions and release dates disagree",
					slog.String("package", older.pkg),
					slog.String("older", fmt.Sprintf("KB%s %s %s", older.kbID, older.versionStr, older.date.Format(time.DateOnly))),
					slog.String("newer", fmt.Sprintf("KB%s %s %s", newer.kbID, newer.versionStr, newer.date.Format(time.DateOnly))))
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
					ID: sourceTypes.MicrosoftSharePoint,
				},
			}
			kbs[u.kbID] = kb
		}
		if kb.URL == "" {
			kb.URL = u.url
		}
		if !slices.Contains(kb.Products, u.pkg) {
			kb.Products = append(kb.Products, u.pkg)
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
