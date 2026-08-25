package v1

import (
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
	feeds []string
	dir   string
	retry int

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
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

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	feeds := []string{"modified", "recent"}
	for y := oldestYear; y <= time.Now().Year(); y++ {
		feeds = append(feeds, strconv.Itoa(y))
	}

	options := &options{
		feeds: feeds,
		dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cve", "v1"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for _, feed := range options.feeds {
		slog.Info("Fetch NVD CVE Feed 1.1", slog.String("feed", feed))
		cves, err := options.fetch(fmt.Sprintf(baseURLFormat, feed))
		if err != nil {
			return errors.Wrapf(err, "fetch nvd cve %s feed 1.1", feed)
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
			newer, err := isNewer(p, cve.LastModifiedDate)
			if err != nil {
				return errors.Wrapf(err, "check lastModifiedDate %s", cve.Cve.CVEDataMeta.ID)
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

func (opts options) fetch(feedURL string) ([]CVEItem, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientHTTPClient(opts.httpClient)).Get(feedURL)
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

// isNewer reports whether the file at filePath already contains a CVE record
// whose lastModifiedDate timestamp is newer than incoming.
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
		LastModifiedDate string `json:"lastModifiedDate"`
	}
	if err := json.UnmarshalRead(f, &existing); err != nil {
		return false, errors.Wrapf(err, "unmarshal %s", filePath)
	}
	existingTime, err := time.Parse("2006-01-02T15:04Z", existing.LastModifiedDate)
	if err != nil {
		return false, errors.Wrapf(err, "parse existing lastModifiedDate %q", existing.LastModifiedDate)
	}
	incomingTime, err := time.Parse("2006-01-02T15:04Z", incoming)
	if err != nil {
		return false, errors.Wrapf(err, "parse incoming lastModifiedDate %q", incoming)
	}
	return existingTime.After(incomingTime), nil
}
