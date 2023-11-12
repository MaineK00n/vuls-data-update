package cve

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURLFormat = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	oldestYear    = 2002
)

type options struct {
	baseURLs []string
	dir      string
	retry    int
}

type Option interface {
	apply(*options)
}

type baseURLsOption []string

func (u baseURLsOption) apply(opts *options) {
	opts.baseURLs = u
}

func WithBaseURLs(urls []string) Option {
	return baseURLsOption(urls)
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
	us := []string{
		fmt.Sprintf(baseURLFormat, "modified"),
		fmt.Sprintf(baseURLFormat, "recent"),
	}

	for y := oldestYear; y <= time.Now().Year(); y++ {
		us = append(us, fmt.Sprintf(baseURLFormat, strconv.Itoa(y)))
	}

	options := &options{
		baseURLs: us,
		dir:      filepath.Join(util.CacheDir(), "nvd", "feed", "cve"),
		retry:    3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slices.SortFunc(options.baseURLs, func(a, b string) int {
		return cmp.Compare(strings.TrimSuffix(strings.TrimPrefix(path.Base(b), "nvdcve-1.1-"), ".json.gz"), strings.TrimSuffix(strings.TrimPrefix(path.Base(a), "nvdcve-1.1-"), ".json.gz"))
	})

	cves := map[string]map[string]CVEItem{}
	for _, u := range options.baseURLs {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		feedname := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "nvdcve-1.1-"), ".json.gz")

		log.Printf("[INFO] Fetch NVD CVE Feed %s", feedname)
		if err := options.fetch(u, cves); err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed", feedname)
		}

		if feedname == "modified" || feedname == "recent" {
			continue
		}

		bar := pb.StartNew(len(cves[feedname]))
		for _, cve := range cves[feedname] {
			splitted, err := util.Split(cve.Cve.CVEDataMeta.ID, "-", "-")
			if err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Cve.CVEDataMeta.ID)
				continue
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Cve.CVEDataMeta.ID)
				continue
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.Cve.CVEDataMeta.ID)), cve); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], cve.Cve.CVEDataMeta.ID))
			}

			bar.Increment()
		}
		delete(cves, feedname)
		bar.Finish()
	}

	return nil
}

func (opts options) fetch(feedURL string, cves map[string]map[string]CVEItem) error {
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(feedURL)
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
			LastModifiedDate: e.LastModifiedDate,
			PublishedDate:    e.PublishedDate,
		}

		y := strings.Split(e.Cve.CVEDataMeta.ID, "-")[1]
		if c, ok := cves[y][e.Cve.CVEDataMeta.ID]; ok {
			a, _ := time.Parse("2006-01-02T15:04Z", c.LastModifiedDate)
			b, _ := time.Parse("2006-01-02T15:04Z", item.LastModifiedDate)
			if a.After(b) {
				continue
			}
		}
		if _, ok := cves[y]; !ok {
			cves[y] = map[string]CVEItem{}
		}
		cves[y][e.Cve.CVEDataMeta.ID] = item
	}

	return nil
}
