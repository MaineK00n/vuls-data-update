package securityreleases

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	securityreleases "github.com/MaineK00n/vuls-data-update/pkg/fetch/apple/security-releases"
)

// vulnerabilityIDPattern matches CVE IDs and their pre-2005 candidate form
// (CAN-), which shares the number space with CVE.
var vulnerabilityIDPattern = regexp.MustCompile(`(CVE|CAN)-[0-9]{4}-[0-9]{4,}`)

// trailingDatePattern matches the release date at the end of a list-format
// row text, e.g. "- Mac OS X v10.4 - v10.4.5 - 03 Apr 2006".
var trailingDatePattern = regexp.MustCompile(`[0-9]{1,2} [A-Z][a-z]{2,8} [0-9]{4}$`)

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

// release is a row of a security releases list page, joined to advisories by
// the article ID the row links to.
type release struct {
	row  securityreleases.Release
	path string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "apple", "security-releases"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Apple Security Releases")

	releases, err := readLists(args)
	if err != nil {
		return errors.Wrap(err, "read lists")
	}

	// the same page may be linked under different article IDs across lists;
	// accumulate by root ID and merge before writing
	datas := make(map[dataTypes.RootID]dataTypes.Data)
	if err := filepath.WalkDir(filepath.Join(args, "advisories"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(p) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched securityreleases.Advisory
		if err := r.Read(p, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", p)
		}

		rs := releases[strings.TrimSuffix(filepath.Base(p), ".json")]
		raws := r.Paths()
		for _, r := range rs {
			if !slices.Contains(raws, r.path) {
				raws = append(raws, r.path)
			}
		}

		extracted, err := extract(fetched, rs, raws)
		if err != nil {
			return errors.Wrapf(err, "extract %s", p)
		}

		if base, ok := datas[extracted.ID]; ok {
			base.Merge(extracted)
			datas[extracted.ID] = base
			return nil
		}
		datas[extracted.ID] = extracted

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", filepath.Join(args, "advisories"))
	}

	for _, id := range slices.Sorted(maps.Keys(datas)) {
		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", id)), datas[id], true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", id)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.AppleSecurityReleases,
		Name: new("Apple Security Releases"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// readLists reads the security releases list pages and indexes their rows by
// the article ID each row links to, which is also the file name the fetch
// stage stores the linked advisory under.
func readLists(args string) (map[string][]release, error) {
	releases := make(map[string][]release)
	if err := filepath.WalkDir(filepath.Join(args, "lists"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(p) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched securityreleases.List
		if err := r.Read(p, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", p)
		}
		if len(r.Paths()) != 1 {
			return errors.Errorf("unexpected number of read paths. expected: %d, actual: %d", 1, len(r.Paths()))
		}

		for _, row := range fetched.Releases {
			if row.URL == "" {
				continue
			}
			u, err := url.Parse(row.URL)
			if err != nil {
				return errors.Wrapf(err, "parse %s", row.URL)
			}
			releases[path.Base(u.Path)] = append(releases[path.Base(u.Path)], release{row: row, path: r.Paths()[0]})
		}

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", filepath.Join(args, "lists"))
	}
	return releases, nil
}

func extract(fetched securityreleases.Advisory, releases []release, raws []string) (dataTypes.Data, error) {
	// the root ID is the canonical article ID: the last segment of the
	// redirect-resolved URL. legacy kb/HTxxxx and kb/TAxxxxx links redirect
	// to the current en-us/<id> form, and lists may still link the legacy ID,
	// so the file name (linked ID) is not stable enough to be the root
	u, err := url.Parse(fetched.URL)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "parse %s", fetched.URL)
	}
	rootID := path.Base(u.Path)

	title := fetched.Title
	if title == "" && len(releases) > 0 {
		// pages are sometimes served with an empty <h1>; fall back to the
		// release name the list rows carry
		title = releases[0].row.Name
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(rootID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:         advisoryContentTypes.AdvisoryID(rootID),
				Title:      title,
				References: []referenceTypes.Reference{{Source: "support.apple.com", URL: fetched.URL}},
				Published:  published(fetched, releases),
			},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			var cves []string
			for _, s := range fetched.Sections {
				for _, e := range s.Entries {
					// vulnerability references live in IDs; the pre-2005
					// inline archive pages carry them in prose, which the
					// fetch stage stores in Others
					for _, t := range slices.Concat(e.IDs, e.Others) {
						for _, m := range vulnerabilityIDPattern.FindAllString(t, -1) {
							// CAN- is the pre-2005 candidate form of the same
							// CVE number
							cves = append(cves, strings.Replace(m, "CAN-", "CVE-", 1))
						}
					}
				}
			}
			slices.Sort(cves)
			cves = slices.Compact(cves)

			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(cves))
			for _, c := range cves {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: vulnerabilityContentTypes.VulnerabilityID(c),
						References: []referenceTypes.Reference{{
							Source: "support.apple.com",
							URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", c),
						}},
					},
				})
			}
			return vs
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.AppleSecurityReleases,
			Raws: raws,
		},
	}, nil
}

// published returns the release date, preferring the "Released ..." note on
// the advisory page and falling back to the release date column of the list
// rows. either may be missing: old list-format rows keep the date inside the
// unparsed row text, and pointer pages have no note.
func published(fetched securityreleases.Advisory, releases []release) *time.Time {
	for _, s := range fetched.Sections {
		for _, e := range s.Entries {
			for _, n := range e.Notes {
				if v, ok := strings.CutPrefix(n, "Released "); ok {
					if t := utiltime.Parse([]string{"January 2, 2006"}, v); t != nil {
						return t
					}
				}
			}
		}
	}
	for _, r := range releases {
		if t := parseDate(r.row.ReleaseDate); t != nil {
			return t
		}
		// list-format rows keep the date at the end of the unparsed row text
		if t := parseDate(trailingDatePattern.FindString(r.row.Text)); t != nil {
			return t
		}
	}
	return nil
}

// parseDate parses the release date column formats: "27 Jul 2026",
// "26 Sept 2013" (a 4-letter abbreviation Go's "Jan" layout does not accept)
// and the occasional full month name.
func parseDate(v string) *time.Time {
	if t := utiltime.Parse([]string{"2 Jan 2006", "2 January 2006"}, v); t != nil {
		return t
	}
	return utiltime.Parse([]string{"2 Jan 2006"}, strings.ReplaceAll(v, "Sept ", "Sep "))
}
