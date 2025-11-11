package csaf

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

const dataURLFormat = "https://security.paloaltonetworks.com/csaf/%s"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "paloalto", "csaf"),
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

	log.Printf("[INFO] Fetch Palo Alto Networks Security Advisories (CSAF)")

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		us = append(us, fmt.Sprintf(options.dataURL, id))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	if err := client.PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var csaf CSAF
			if err := json.NewDecoder(resp.Body).Decode(&csaf); err != nil {
				return errors.Wrap(err, "decode json")
			}

			switch {
			case strings.HasPrefix(csaf.Document.Tracking.ID, "PAN-SA-"):
				splitted, err := util.Split(strings.TrimPrefix(csaf.Document.Tracking.ID, "PAN-SA-"), "-")
				if err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", csaf.Document.Tracking.ID)
				}
				if _, err := time.Parse("2006", splitted[0]); err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", csaf.Document.Tracking.ID)
				}

				if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)), csaf); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)))
				}
			case strings.HasPrefix(csaf.Document.Tracking.ID, "CVE-"):
				splitted, err := util.Split(strings.TrimPrefix(csaf.Document.Tracking.ID, "CVE-"), "-")
				if err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", csaf.Document.Tracking.ID)
				}
				if _, err := time.Parse("2006", splitted[0]); err != nil {
					return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", csaf.Document.Tracking.ID)
				}

				if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)), csaf); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)))
				}
			default:
				return errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"PAN-SA-", "CVE-"}, csaf.Document.Tracking.ID)
			}

			return nil
		case http.StatusNotFound:
			// ignore the error because there is no way to check in advance that there is no CSAF
			// e.g. https://security.paloaltonetworks.com/csaf/CVE-2016-2219
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		default:
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
