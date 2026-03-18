package v1

import (
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

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
	var us []string
	for y := oldestYear; y <= time.Now().Year(); y++ {
		us = append(us, fmt.Sprintf(baseURLFormat, strconv.Itoa(y)))
	}
	// Process recent and modified last so they overwrite year-feed data
	// with the latest version.
	us = append(us, fmt.Sprintf(baseURLFormat, "recent"), fmt.Sprintf(baseURLFormat, "modified"))

	options := &options{
		baseURLs: us,
		dir:      filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cve", "v1"),
		retry:    3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for _, u := range options.baseURLs {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		feedname := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "nvdcve-1.1-"), ".json.gz")

		log.Printf("[INFO] Fetch NVD CVE Feed 1.1 %s", feedname)
		cves, err := options.fetch(u)
		if err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed 1.1", feedname)
		}

		bar := progressbar.Default(int64(len(cves)))
		for _, cve := range cves {
			splitted, err := util.Split(cve.Cve.CVEDataMeta.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Cve.CVEDataMeta.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.Cve.CVEDataMeta.ID)
			}

			p := filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.Cve.CVEDataMeta.ID))
			if isNewer(p, cve.LastModifiedDate) {
				_ = bar.Add(1)
				continue
			}

			if err := util.Write(p, cve); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}

			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func (opts options) fetch(feedURL string) ([]CVEItem, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(feedURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch nvd cve feed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "open cve as gzip")
	}
	defer r.Close()

	var feed doc
	if err := json.UnmarshalRead(r, &feed); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	cves := make([]CVEItem, 0, len(feed.CVEItems))
	for _, e := range feed.CVEItems {
		cves = append(cves, CVEItem{
			Cve:              e.Cve,
			Impact:           e.Impact,
			Configurations:   e.Configurations,
			LastModifiedDate: e.LastModifiedDate,
			PublishedDate:    e.PublishedDate,
		})
	}

	return cves, nil
}

// isNewer reports whether the file at path already contains a CVE record
// whose lastModifiedDate timestamp is newer than incoming.
func isNewer(path, incoming string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var existing struct {
		LastModifiedDate string `json:"lastModifiedDate"`
	}
	if err := json.Unmarshal(b, &existing); err != nil {
		return false
	}
	existingTime, _ := time.Parse("2006-01-02T15:04Z", existing.LastModifiedDate)
	incomingTime, _ := time.Parse("2006-01-02T15:04Z", incoming)
	return existingTime.After(incomingTime)
}
