package v2

import (
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURLFormat = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%s.json.gz"
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
		dir:      filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cve", "v2"),
		retry:    3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slices.SortFunc(options.baseURLs, func(a, b string) int {
		return cmp.Compare(strings.TrimSuffix(strings.TrimPrefix(path.Base(b), "nvdcve-2.0-"), ".json.gz"), strings.TrimSuffix(strings.TrimPrefix(path.Base(a), "nvdcve-2.0-"), ".json.gz"))
	})

	cves := make(map[string]map[string]CVE)
	for _, u := range options.baseURLs {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		feedname := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "nvdcve-2.0-"), ".json.gz")

		log.Printf("[INFO] Fetch NVD CVE Feed 2.0 %s", feedname)
		if err := options.fetch(u, cves); err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed 2.0", feedname)
		}

		if feedname == "modified" || feedname == "recent" {
			continue
		}

		bar := progressbar.Default(int64(len(cves[feedname])))
		for _, cve := range cves[feedname] {
			splitted, err := util.Split(cve.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.ID)), cve); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], cve.ID))
			}

			_ = bar.Add(1)
		}
		delete(cves, feedname)
		_ = bar.Close()
	}

	return nil
}

func (opts options) fetch(feedURL string, cves map[string]map[string]CVE) error {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(feedURL)
	if err != nil {
		return errors.Wrap(err, "fetch nvd cve feed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "open cve as gzip")
	}
	defer r.Close()

	var feed api20
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for _, v := range feed.Vulnerabilities {
		y := strings.Split(v.CVE.ID, "-")[1]
		if base, ok := cves[y][v.CVE.ID]; ok {
			a, _ := time.Parse("2006-01-02T15:04:05.000", base.LastModified)
			b, _ := time.Parse("2006-01-02T15:04:05.000", v.CVE.LastModified)
			if a.After(b) {
				continue
			}
		}
		if _, ok := cves[y]; !ok {
			cves[y] = make(map[string]CVE)
		}
		cves[y][v.CVE.ID] = v.CVE
	}

	return nil
}
