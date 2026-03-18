package v2

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
	var us []string
	for y := oldestYear; y <= time.Now().Year(); y++ {
		us = append(us, fmt.Sprintf(baseURLFormat, strconv.Itoa(y)))
	}
	// Process recent and modified last so they overwrite year-feed data
	// with the latest version.
	us = append(us, fmt.Sprintf(baseURLFormat, "recent"), fmt.Sprintf(baseURLFormat, "modified"))

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

	for _, u := range options.baseURLs {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		feedname := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "nvdcve-2.0-"), ".json.gz")

		log.Printf("[INFO] Fetch NVD CVE Feed 2.0 %s", feedname)
		cves, err := options.fetch(u)
		if err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed 2.0", feedname)
		}

		bar := progressbar.Default(int64(len(cves)))
		for _, cve := range cves {
			splitted, err := util.Split(cve.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cve.ID)
			}

			p := filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", cve.ID))
			newer, err := isNewer(p, cve.LastModified)
			if err != nil {
				return errors.Wrapf(err, "check lastModified %s", cve.ID)
			}
			if newer {
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

func (opts options) fetch(feedURL string) ([]CVE, error) {
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

	var feed api20
	if err := json.UnmarshalRead(r, &feed); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	cves := make([]CVE, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cves = append(cves, v.CVE)
	}

	return cves, nil
}

// isNewer reports whether the file at the given path already contains a CVE record
// whose lastModified timestamp is newer than incoming.
func isNewer(filePath, incoming string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, errors.Wrapf(err, "open %s", filePath)
	}
	defer f.Close()

	var existing struct {
		LastModified string `json:"lastModified"`
	}
	if err := json.UnmarshalRead(f, &existing); err != nil {
		return false, errors.Wrapf(err, "unmarshal %s", filePath)
	}
	existingTime, err := time.Parse("2006-01-02T15:04:05.000", existing.LastModified)
	if err != nil {
		return false, errors.Wrapf(err, "parse existing lastModified %q", existing.LastModified)
	}
	incomingTime, err := time.Parse("2006-01-02T15:04:05.000", incoming)
	if err != nil {
		return false, errors.Wrapf(err, "parse incoming lastModified %q", incoming)
	}
	return existingTime.After(incomingTime), nil
}
