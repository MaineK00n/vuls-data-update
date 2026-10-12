// Package sqlbuild extracts supersedence from Microsoft's SQL Server
// build-versions article.
//
// The article carries no supersedence. What it carries is every build a product
// version has shipped, and the build number is the order: a build contains the
// one below it on the same line. Reading the lines apart is this package's job,
// and SQL Server runs several at once.
//
// A product version services two or three lines in parallel, and they do not
// supersede each other:
//
//   - CU, the cumulative updates. Each contains every fix before it.
//   - GDR, the general distribution releases, which carry security fixes and
//     nothing else. A host on GDR is not on CU and a CU does not reach it.
//   - QFE, the older name for the hotfix line GDR ran beside, on SQL Server 2005
//     through 2012.
//   - Azure Connect Pack, an optional feature pack for SQL Server 2016 SP3 and
//     2017 that is serviced on its own.
//
// The line is read from the Update column, which names it: "CU26", "CU25 + GDR",
// "GDR Security Update", "MS15-058: QFE Security Update", "Azure Connect Pack +
// GDR". A "CUn + GDR" is on the CU line -- it is that CU with a security fix on
// top -- and only the rows naming no CU are on the GDR one.
//
// The service pack is the other divider, and it is needed. Microsoft services
// the RTM line and the SP1 line side by side for as long as both are supported,
// so a build number that is higher is not always a build that came later: SQL
// Server 2008's RTM CU9 at 10.00.1835.0 shipped in March 2010, eleven months
// after SP1 CU2 at 10.00.2710.0. Ordering a version's CUs as one line by build
// number puts 41 such pairs the wrong way round; keying the service pack in as
// well leaves 7, and every one of those is a row Microsoft filed under a service
// pack its build number does not belong to.
//
// The service pack is not simply the Service pack column. Microsoft stopped
// filling it in around 2023 and moved the fact into the Update column -- SQL
// Server 2016's SP3 GDRs read "SP3 | GDR" up to February 2023 and "None | SP3 +
// GDR" after it -- so the column is read first and the label second. Thirteen
// rows state it in neither, all of them Azure Connect Pack releases, and they
// take the service pack of the build below them on their own line, which is what
// splitting them off it would otherwise cost: two chains where the article has
// one.
//
// RTM and RTW/PCU rows are the baselines a service pack opens with, and they
// belong to every line that runs on it: SQL Server 2016's SP1 baseline at
// 13.0.4001.0 is what both the SP1 CUs and the SP1 GDRs are built on. A baseline
// joins only the lines that exist -- a version that shipped no QFE gets no QFE
// chain from having a baseline.
//
// Rows naming no KB are the product releases themselves, marked "NA" or left
// empty, and are skipped. So are SQL Server 2000 and earlier, whose tables have
// no Knowledge Base column at all.
package sqlbuild

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/sqlbuild"
)

// The columns a row is read out of, by name. A table without the Knowledge Base
// column is not a build history -- SQL Server 2000 and earlier are listed with
// their KBs written into prose, and 7.0 and 6.5 with no KBs at all.
const (
	columnBuild       = "Build number or version"
	columnServicePack = "Service pack"
	columnUpdate      = "Update"
	columnKB          = "Knowledge Base number"
	columnDate        = "Release date"
)

// The lines a product version services in parallel.
const (
	lineCU       = "cu"
	lineGDR      = "gdr"
	lineQFE      = "qfe"
	lineACP      = "azure-connect-pack"
	lineBaseline = "baseline"
	lineUnknown  = ""
)

var (
	kbPattern = regexp.MustCompile(`KB ?(\d{6,})`)

	// buildPattern is a SQL Server build number. Three components as well as
	// four: SQL Server 2005 and 2000 are written 9.00.5324.
	buildPattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+){1,2}$`)

	// servicePackPattern is how a service pack is written wherever it appears --
	// on its own in the Service pack column, and inside a label in the Update
	// one, as "SP3 + GDR" and "SQL Server 2014 SP3 CU4 + GDR".
	servicePackPattern = regexp.MustCompile(`(?i)\bSP(\d)\b`)

	// cuPattern is a cumulative update's name. The space is allowed because
	// Microsoft has written both "CU26" and, elsewhere in this estate, "CU 26".
	cuPattern = regexp.MustCompile(`(?i)\bCU ?\d+`)

	// baselinePattern is what a service pack's own release is called. Microsoft
	// spells the PCU form five ways -- RTW/PCU1, RTW / PCU 1, RTW/PCU4 -- so the
	// separator is not matched, only the two names.
	baselinePattern = regexp.MustCompile(`(?i)\bRT[MW]\b|\bPCU\b|\bGA\b`)

	// weekdayPattern is the day of the week one row opens its release date with.
	weekdayPattern = regexp.MustCompile(`(?i)^(Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day,?\s*`)
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

// update is one row of a build history, read for what decides its place in a
// chain.
type update struct {
	kbID string
	url  string

	// version is the heading the table sits under, e.g. "SQL Server 2008 R2".
	// It is the only place the article writes the product version out; the
	// build number says 10.50, which is the same fact in a spelling nothing
	// else uses.
	version string

	// servicePack divides the lines a version runs in parallel. Empty for the
	// versions that have no service packs at all, which is every one since SQL
	// Server 2016.
	servicePack string

	line string

	build    []int
	buildStr string

	date  time.Time
	label string

	raw string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "sqlbuild"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft SQL Server Build Versions")

	us, err := read(args)
	if err != nil {
		return errors.Wrapf(err, "read %s", args)
	}

	inherit(us)

	kbs := chain(us)

	for _, kb := range kbs {
		if err := util.Write(filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)), kb, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "microsoftkb", fmt.Sprintf("%sxxx", kb.KBID[:len(kb.KBID)-3]), fmt.Sprintf("%s.json", kb.KBID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftSQLBuild,
		Name: new("Microsoft SQL Server Build Versions"),
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

		var a sqlbuild.Article
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

// parseArticle reads an article's build histories.
func parseArticle(a sqlbuild.Article, raw string) []update {
	var us []update

	for _, t := range a.Tables {
		if !slices.Contains(t.Header, columnKB) {
			// A summary of the latest update per version, or SQL Server 2000
			// and earlier, whose KBs are written into prose rather than given a
			// column. The summary repeats rows the histories already carry;
			// 2000 and earlier are two KBs in a shape of their own.
			slog.Debug("not a build history", slog.String("path", raw), slog.String("heading", t.Heading))
			continue
		}

		var missing []string
		for _, c := range []string{columnBuild, columnServicePack, columnUpdate, columnDate} {
			if !slices.Contains(t.Header, c) {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			slog.Warn("build history is missing columns", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("missing", strings.Join(missing, ", ")), slog.String("header", strings.Join(t.Header, ", ")))
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
func parseRow(t sqlbuild.Table, row []sqlbuild.Cell, raw string) (update, bool) {
	cell := func(column string) sqlbuild.Cell {
		i := slices.Index(t.Header, column)
		if i < 0 || i >= len(row) {
			return sqlbuild.Cell{}
		}
		return row[i]
	}

	m := kbPattern.FindStringSubmatch(cell(columnKB).Text)
	if m == nil {
		// The product release itself, written "NA" or left empty. It ships no
		// KB and takes no place in a chain of them.
		slog.Debug("row names no KB", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("build", cell(columnBuild).Text))
		return update{}, false
	}

	bs := cell(columnBuild).Text
	if !buildPattern.MatchString(bs) {
		// The build is the whole order. A row without one cannot be placed.
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

	// The date is a tiebreaker between two rows of one build, not the order, so
	// an unreadable one costs the tie and not the row.
	var date time.Time
	if d := cell(columnDate).Text; d != "" {
		var ok bool
		date, ok = releaseDate(d)
		if !ok {
			slog.Warn("unexpected release date", slog.String("path", raw), slog.String("kb", m[1]), slog.String("date", d))
		}
	}

	label := cell(columnUpdate).Text
	line := line(label)
	if line == lineUnknown {
		// Two rows name no kind of update at all. They are recorded and left to
		// a line of their own, where they chain to nothing: guessing one would
		// put an edge into a line the estate is measured against.
		slog.Warn("unrecognised kind of update, row is left unchained", slog.String("path", raw), slog.String("heading", t.Heading), slog.String("kb", m[1]), slog.String("build", bs))
	}

	return update{
		kbID:        m[1],
		url:         absolute(cell(columnKB).Href),
		version:     t.Heading,
		servicePack: servicePack(cell(columnServicePack).Text, label),
		line:        line,
		build:       build,
		buildStr:    bs,
		date:        date,
		label:       label,
		raw:         raw,
	}, true
}

// line is which of a version's parallel lines an update belongs to.
//
// The order the cases are asked in is the whole of it. "CU25 + GDR" is a
// cumulative update carrying a security fix and belongs to the CU line, so a
// label naming a CU is answered before one naming GDR is ever considered; and
// "Azure Connect Pack + GDR" is neither, so it is answered before both.
func line(label string) string {
	switch {
	case strings.Contains(strings.ToLower(label), "azure connect"):
		return lineACP
	case cuPattern.MatchString(label):
		return lineCU
	case strings.Contains(strings.ToUpper(label), "QFE"):
		return lineQFE
	case strings.Contains(strings.ToUpper(label), "GDR"):
		return lineGDR
	case baselinePattern.MatchString(label):
		return lineBaseline
	default:
		return lineUnknown
	}
}

// servicePack reads the service pack an update was built on, from the column
// that names it or, where Microsoft has stopped filling that in, from the label.
func servicePack(column, label string) string {
	if m := servicePackPattern.FindStringSubmatch(column); m != nil {
		return "SP" + m[1]
	}
	if strings.EqualFold(strings.TrimSpace(column), "RTM") {
		return "RTM"
	}
	if m := servicePackPattern.FindStringSubmatch(label); m != nil {
		return "SP" + m[1]
	}
	return ""
}

// releaseDate reads the date a row was released, in the four shapes Microsoft
// has written across 586 of them.
//
// The article is hand-authored and the date is prose, so the comma is optional
// ("July 16 2018"), the space after it is optional ("March 21,2016"), and one
// row opens with the day of the week ("Friday, June 27, 2014"). Four rows in all,
// and none of them is a date that cannot be read -- only one written by hand.
func releaseDate(s string) (time.Time, bool) {
	s = weekdayPattern.ReplaceAllString(strings.TrimSpace(s), "")
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, ",", ", ")), " ")

	for _, layout := range []string{"January 2, 2006", "January 2 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}

	return time.Time{}, false
}

// absolute keeps a link only where it addresses the KB.
//
// Some Knowledge Base cells link to a sibling article in the docs repository
// instead -- "[KB5093421](sqlserver-2025/cumulativeupdate6.md)" -- which is a
// path in a repository and not an address for anything. Turning one into a
// learn.microsoft.com URL means knowing how that docset is mounted, which the
// path does not say, and building an address the article never gave.
func absolute(href string) string {
	if href == "" {
		return ""
	}
	u, err := url.Parse(href)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return ""
	}
	return href
}

// inherit fills in the service pack of the rows that name none, from the build
// below them on their own line.
//
// Thirteen rows name none, every one an Azure Connect Pack release from 2023 on,
// by which time Microsoft had stopped filling the column in and the label had
// never carried it. Left empty they are a second Azure Connect Pack line beside
// the first, and the article's one chain of sixteen becomes two of thirteen and
// three.
//
// A version whose rows all name none is not this case and is left alone: SQL
// Server 2017 and later have no service packs to name, and there is nothing
// below them to inherit.
func inherit(us []update) {
	type key struct{ version, line string }
	byLine := make(map[key][]int)
	for i, u := range us {
		byLine[key{version: u.version, line: u.line}] = append(byLine[key{version: u.version, line: u.line}], i)
	}

	for _, is := range byLine {
		slices.SortFunc(is, func(x, y int) int { return slices.Compare(us[x].build, us[y].build) })

		var last string
		for _, i := range is {
			switch {
			case us[i].servicePack != "":
				last = us[i].servicePack
			case last != "":
				us[i].servicePack = last
			}
		}
	}
}

// chain turns the rows into KB records, chained into supersedence.
func chain(us []update) []microsoftkbTypes.KB {
	type buildLine struct {
		version     string
		line        string
		servicePack string
	}

	// Which lines a version actually runs, so that a baseline joins the ones
	// there are rather than conjuring the ones there are not.
	served := make(map[buildLine]struct{})
	for _, u := range us {
		if u.line == lineBaseline || u.line == lineUnknown {
			continue
		}
		served[buildLine{version: u.version, line: u.line, servicePack: u.servicePack}] = struct{}{}
	}

	lines := make(map[buildLine][]update)
	for _, u := range us {
		switch u.line {
		case lineBaseline:
			// A service pack's own release is what every line running on it is
			// built from, so it takes its place in each.
			for _, l := range []string{lineCU, lineGDR, lineQFE} {
				bl := buildLine{version: u.version, line: l, servicePack: u.servicePack}
				if _, ok := served[bl]; !ok {
					continue
				}
				lines[bl] = append(lines[bl], u)
			}
		case lineUnknown:
			// Recorded, and left where nothing chains to it.
		default:
			lines[buildLine{version: u.version, line: u.line, servicePack: u.servicePack}] = append(lines[buildLine{version: u.version, line: u.line, servicePack: u.servicePack}], u)
		}
	}

	type link struct{ older, newer string }
	var links []link
	for bl, group := range lines {
		// Two rows do share a build, where Microsoft has listed one build under
		// two labels. The release date decides those, and the KB number only
		// where even that ties.
		slices.SortFunc(group, func(x, y update) int {
			return cmp.Or(slices.Compare(x.build, y.build), x.date.Compare(y.date), cmp.Compare(x.kbID, y.kbID))
		})

		for i := 1; i < len(group); i++ {
			older, newer := group[i-1], group[i]

			// The build is the order and the date is not, but where the two
			// disagree the row is worth reading: seven pairs do, and every one
			// is filed under a service pack its build number does not belong
			// to -- SQL Server 2016's 13.0.4202.2 is listed under RTM while its
			// build says SP1. The edge is kept, the build being the surer of
			// the two, and the pair is named so it can be looked at.
			if !older.date.IsZero() && !newer.date.IsZero() && newer.date.Before(older.date) {
				slog.Warn("a line's builds and release dates disagree",
					slog.String("version", bl.version), slog.String("line", bl.line), slog.String("service_pack", bl.servicePack),
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
					ID: sourceTypes.MicrosoftSQLBuild,
				},
			}
			kbs[u.kbID] = kb
		}
		if kb.URL == "" {
			kb.URL = u.url
		}
		if !slices.Contains(kb.Products, u.version) {
			kb.Products = append(kb.Products, u.version)
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
