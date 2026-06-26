package json

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURLFormat = "https://security.paloaltonetworks.com/json/%s"

// knownMissing lists advisory IDs that are advertised by the list endpoint
// (/json/?page=) but whose per-advisory /json/<id> endpoint returns HTTP 404 — a
// known upstream regression (the human-readable HTML pages still return 200, so
// the advisories themselves exist). A 404 is tolerated only for these IDs; any
// other 404 fails the fetch so a new regression surfaces loudly instead of being
// silently skipped. Once upstream restores these endpoints this list should be
// emptied / removed — see MaineK00n/vuls-data-update#864 and vuls-data-db
// docs/paloalto-missing-json-csaf-ids.md.
var knownMissing = map[string]struct{}{
	"CVE-2022-42889":   {},
	"PAN-SA-2014-0001": {},
	"PAN-SA-2014-0002": {},
	"PAN-SA-2014-0004": {},
	"PAN-SA-2014-0006": {},
	"PAN-SA-2015-0003": {},
	"PAN-SA-2015-0005": {},
	"PAN-SA-2015-0006": {},
	"PAN-SA-2016-0006": {},
	"PAN-SA-2016-0007": {},
	"PAN-SA-2016-0008": {},
	"PAN-SA-2016-0010": {},
	"PAN-SA-2016-0011": {},
	"PAN-SA-2016-0013": {},
	"PAN-SA-2016-0014": {},
	"PAN-SA-2016-0015": {},
	"PAN-SA-2016-0016": {},
	"PAN-SA-2016-0017": {},
	"PAN-SA-2016-0018": {},
	"PAN-SA-2016-0019": {},
	"PAN-SA-2016-0020": {},
	"PAN-SA-2016-0022": {},
	"PAN-SA-2016-0023": {},
	"PAN-SA-2016-0024": {},
	"PAN-SA-2016-0025": {},
	"PAN-SA-2016-0026": {},
	"PAN-SA-2016-0028": {},
	"PAN-SA-2016-0029": {},
	"PAN-SA-2016-0030": {},
	"PAN-SA-2016-0031": {},
	"PAN-SA-2016-0032": {},
	"PAN-SA-2016-0033": {},
	"PAN-SA-2018-0001": {},
	"PAN-SA-2018-0011": {},
	"PAN-SA-2018-0015": {},
	"PAN-SA-2019-0004": {},
	"PAN-SA-2019-0011": {},
	"PAN-SA-2019-0012": {},
	"PAN-SA-2019-0013": {},
	"PAN-SA-2022-0006": {},
	"PAN-SA-2022-0007": {},
}

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(ids []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURLFormat,
		dir:         filepath.Join(util.CacheDir(), "fetch", "paloalto", "json"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Palo Alto Networks Security Advisories (JSON)")

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		us = append(us, fmt.Sprintf(options.dataURL, id))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	if err := client.PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			id := path.Base(resp.Request.URL.Path)
			// A handful of advisories listed by /json/?page= return 404 on the
			// per-advisory endpoint (a known upstream regression). Skip those, but only
			// for the known IDs (knownMissing) so a 404 on any other advisory still fails
			// loudly as a new regression. The vuls-data-db pipeline restores the
			// last-known-good copy of the skipped IDs from history.
			if resp.StatusCode == http.StatusNotFound {
				if _, ok := knownMissing[id]; !ok {
					return errors.Errorf("unexpected 404 for advisory %q (not a known upstream regression)", id)
				}
				slog.Warn("skip advisory: known upstream 404 regression", "id", id)
				return nil
			}
			return errors.Errorf("error response with status code %d for advisory %q", resp.StatusCode, id)
		}

		var v CVE
		if err := json.UnmarshalRead(resp.Body, &v); err != nil {
			return errors.Wrap(err, "decode json")
		}

		switch {
		case strings.HasPrefix(v.CVEMetadata.CVEID, "PAN-SA-"):
			splitted, err := util.Split(strings.TrimPrefix(v.CVEMetadata.CVEID, "PAN-SA-"), "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
			}
			if _, err := time.Parse("2006", splitted[0]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)))
			}
		case strings.HasPrefix(v.CVEMetadata.CVEID, "CVE-"):
			splitted, err := util.Split(strings.TrimPrefix(v.CVEMetadata.CVEID, "CVE-"), "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
			}
			if _, err := time.Parse("2006", splitted[0]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)))
			}
		default:
			return errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"PAN-SA-", "CVE-"}, v.CVEMetadata.CVEID)
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
