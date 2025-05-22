package echo

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

const dataURL = "https://advisory.echohq.com/data.json"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(dataURL string) Option {
	return dataURLOption(dataURL)
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
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "echo"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Echo")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var as advisories
	if err := json.NewDecoder(resp.Body).Decode(&as); err != nil {
		return errors.Wrap(err, "decode json")
	}

	m := make(map[string]Vulnerability)
	for pkg, vm := range as {
		for id, a := range vm {
			base, ok := m[id]
			if !ok {
				base = Vulnerability{ID: id}
			}
			base.Packages = append(base.Packages, Package{
				Name:         pkg,
				Severity:     a.Severity,
				FixedVersion: a.FixedVersion,
			})
			m[id] = base
		}
	}

	for _, v := range m {
		switch {
		case strings.HasPrefix(v.ID, "CVE-"):
			splitted, err := util.Split(v.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", v.ID)))
			}
		default:
			splitted, err := util.Split(v.ID, "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "TEMP-<ID>", v.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", v.ID)))
			}
		}
	}

	return nil
}
