package json

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURLFormat = "https://security.paloaltonetworks.com/json/%s"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(ids []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURLFormat,
		dir:         filepath.Join(util.CacheDir(), "fetch", "paloalto", "json"),
		retry:       3,
		concurrency: 5,
		wait:        1,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Palo Alto Networks Security Advisories (JSON)")

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		us = append(us, fmt.Sprintf(options.dataURL, id))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	if err := client.PipelineGet(us, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var v CVE
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
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
