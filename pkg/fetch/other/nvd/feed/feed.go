package feed

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	cveURLFormat     = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	oldestYear       = 2002
	cpeMatchURL      = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
	cpeDictionaryURL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
)

type options struct {
	feedURL *FeedURL
	dir     string
	retry   int
}

type FeedURL struct {
	CVE           []string
	CPEMatch      string
	CPEDictionary string
}

type Option interface {
	apply(*options)
}

type feedURLOption struct {
	URL *FeedURL
}

func (u feedURLOption) apply(opts *options) {
	opts.feedURL = u.URL
}

func WithFeedURL(url *FeedURL) Option {
	return feedURLOption{URL: url}
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	u := FeedURL{
		CVE: []string{
			fmt.Sprintf(cveURLFormat, "modified"),
			fmt.Sprintf(cveURLFormat, "recent"),
		},
		CPEMatch:      cpeMatchURL,
		CPEDictionary: cpeDictionaryURL,
	}

	for y := oldestYear; y <= time.Now().Year(); y++ {
		u.CVE = append(u.CVE, fmt.Sprintf(cveURLFormat, strconv.Itoa(y)))
	}

	options := &options{
		feedURL: &u,
		dir:     filepath.Join(util.SourceDir(), "nvd"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	cpeDict, err := options.fetchCPEDictinoary()
	if err != nil {
		return errors.Wrap(err, "fetch cpe dictionary")
	}

	if err := util.Write(filepath.Join(options.dir, "cpe-dictionary.json.gz"), cpeDict); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "cpe-dictionary.gz"))
	}

	cpeMatch, err := options.fetchCPEMatch()
	if err != nil {
		return errors.Wrap(err, "fetch cpe match")
	}

	slices.SortFunc(options.feedURL.CVE, func(a, b string) bool {
		a = strings.TrimSuffix(strings.TrimPrefix(path.Base(a), "nvdcve-1.1-"), ".json.gz")
		b = strings.TrimSuffix(strings.TrimPrefix(path.Base(b), "nvdcve-1.1-"), ".json.gz")

		_, erra := strconv.Atoi(a)
		_, errb := strconv.Atoi(b)
		if erra == nil && errb == nil && erra != nil && errb != nil {
			return a < b
		}
		return a > b
	})
	cves := map[string]map[string]CVEItem{}
	for _, u := range options.feedURL.CVE {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		feedname := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "nvdcve-1.1-"), ".json.gz")

		log.Printf("[INFO] Fetch NVD CVE Feed %s", feedname)
		if err := options.fetchCVEFeed(u, cves, cpeMatch); err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed", feedname)
		}

		if feedname == "modified" || feedname == "recent" {
			continue
		}

		bar := pb.StartNew(len(cves[feedname]))
		for _, cve := range cves[feedname] {
			y := strings.Split(cve.Cve.CVEDataMeta.ID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}

			if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json.gz", cve.Cve.CVEDataMeta.ID)), cve); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, cve.Cve.CVEDataMeta.ID))
			}

			bar.Increment()
		}
		delete(cves, feedname)
		bar.Finish()
	}

	return nil
}

func (opts options) fetchCPEDictinoary() ([]CPEDictItem, error) {
	var cpes []CPEDictItem

	log.Printf(`[INFO] Fetch NVD CPE Dictinoary`)
	bs, err := util.FetchURL(opts.feedURL.CPEDictionary, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe dictionary feed")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open cpe dictionary as gzip")
	}
	defer r.Close()

	parseDateFn := func(layout string, v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	d := xml.NewDecoder(r)
	for {
		t, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.Wrap(err, "return next XML token")
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local != "cpe-item" {
				break
			}
			var item cpeDictItem
			if err := d.DecodeElement(&item, &se); err != nil {
				return nil, errors.Wrap(err, "decode element")
			}

			c := CPEDictItem{
				Name:            item.Name,
				DeprecationDate: parseDateFn("2006-01-02T15:04:05.000Z", item.DeprecationDate),
				Title:           item.Title,
				References:      item.References,
				Cpe23Item: CPEDictCpe23Item{
					Name: item.Cpe23Item.Name,
				},
			}

			if item.Deprecated != "" {
				b, err := strconv.ParseBool(item.Deprecated)
				if err != nil {
					log.Printf(`[WARN] unexpected Deprecated Value in %s. accepts: ["true", "false"], received: "%s"`, item.Cpe23Item.Name, item.Deprecated)
				} else {
					c.Deprecated = b
				}
			}
			if item.Cpe23Item.Deprecation != nil {
				c.Cpe23Item.Deprecation = &CPEDictDeprecation{
					Date: parseDateFn("2006-01-02T15:04:05.000-07:00", item.Cpe23Item.Deprecation.Date),
					DeprecatedBy: CPEDictDeprectedBy{
						Name: item.Cpe23Item.Deprecation.DeprecatedBy.Name,
						Type: item.Cpe23Item.Deprecation.DeprecatedBy.Type,
					},
				}
			}
			cpes = append(cpes, c)
		default:
		}
	}
	return cpes, nil
}

func (opts options) fetchCPEMatch() (map[string][]cpeMatchItem, error) {
	cpes := map[string][]cpeMatchItem{}

	log.Printf(`[INFO] Fetch NVD CPE Match`)
	bs, err := util.FetchURL(opts.feedURL.CPEMatch, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe match feed")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open cpe match as gzip")
	}
	defer r.Close()

	d := json.NewDecoder(r)
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: {"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "string: matches"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ["`)
	}
	for d.More() {
		var e cpeMatchItem
		if err := d.Decode(&e); err != nil {
			return nil, errors.Wrap(err, "decode element")
		}
		cpes[e.Cpe23URI] = append(cpes[e.Cpe23URI], e)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ]"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: }"`)
	}

	return cpes, nil
}

func (opts options) fetchCVEFeed(feedURL string, cves map[string]map[string]CVEItem, cpeMatch map[string][]cpeMatchItem) error {
	parseDateFn := func(v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse("2006-01-02T15:04Z", v); err == nil {
			t = t.UTC()
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	compare := func(v1, v2 *string) bool {
		var s1, s2 string
		if v1 != nil {
			s1 = *v1
		}
		if v2 != nil {
			s2 = *v2
		}
		return s1 == s2
	}

	bs, err := util.FetchURL(feedURL, opts.retry)
	if err != nil {
		return errors.Wrap(err, "fetch nvd cve feed")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return errors.Wrap(err, "open cve as gzip")
	}
	defer r.Close()

	var feed doc
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for _, e := range feed.CVEItems {
		item := CVEItem{
			Cve:              e.Cve,
			Impact:           e.Impact,
			Configurations:   e.Configurations,
			LastModifiedDate: parseDateFn(e.LastModifiedDate),
			PublishedDate:    parseDateFn(e.PublishedDate),
		}

		y := strings.Split(e.Cve.CVEDataMeta.ID, "-")[1]
		if c, ok := cves[y][e.Cve.CVEDataMeta.ID]; ok {
			if c.LastModifiedDate.After(*item.LastModifiedDate) {
				continue
			}
		}
		for i, n := range item.Configurations.Nodes {
			for j, m := range n.CpeMatch {
				cpes, ok := cpeMatch[m.Cpe23URI]
				if !ok {
					continue
				}
				for _, cpe := range cpes {
					if compare(m.VersionEndExcluding, cpe.VersionEndExcluding) && compare(m.VersionEndIncluding, cpe.VersionEndIncluding) && compare(m.VersionStartExcluding, cpe.VersionStartExcluding) && compare(m.VersionStartIncluding, cpe.VersionStartIncluding) {
						for _, name := range cpe.CpeName {
							n.CpeMatch[j].CPEName = append(n.CpeMatch[j].CPEName, name.Cpe23URI)
						}
					}
				}
			}
			e.Configurations.Nodes[i].CpeMatch = n.CpeMatch

			for j, child := range n.Children {
				for k, m := range child.CpeMatch {
					cpes, ok := cpeMatch[m.Cpe23URI]
					if !ok {
						continue
					}
					for _, cpe := range cpes {
						if compare(m.VersionEndExcluding, cpe.VersionEndExcluding) && compare(m.VersionEndIncluding, cpe.VersionEndIncluding) && compare(m.VersionStartExcluding, cpe.VersionStartExcluding) && compare(m.VersionStartIncluding, cpe.VersionStartIncluding) {
							for _, name := range cpe.CpeName {
								child.CpeMatch[k].CPEName = append(child.CpeMatch[k].CPEName, name.Cpe23URI)
							}
						}
					}
				}
				n.Children[j].CpeMatch = child.CpeMatch
			}
			e.Configurations.Nodes[i].Children = n.Children
		}
		if _, ok := cves[y]; !ok {
			cves[y] = map[string]CVEItem{}
		}
		cves[y][e.Cve.CVEDataMeta.ID] = item
	}

	return nil
}
