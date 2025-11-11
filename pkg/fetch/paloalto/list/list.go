package list

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
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://security.paloaltonetworks.com/json/?page=%d&limit=100&sort=doc"

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

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "paloalto", "list"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Palo Alto Networks Security Advisories (list)")

	var advs []Advisory
	for i := 1; ; i++ {
		as, err := func() ([]Advisory, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(fmt.Sprintf(options.dataURL, i))
			if err != nil {
				return nil, errors.Wrap(err, "fetch advisory")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var as []Advisory
			if err := json.NewDecoder(resp.Body).Decode(&as); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}

			return as, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		if len(as) == 0 {
			break
		}

		advs = append(advs, as...)
	}

	bar := progressbar.Default(int64(len(advs)))
	for _, a := range advs {
		switch {
		case strings.HasPrefix(a.ID, "PAN-SA-"):
			splitted, err := util.Split(strings.TrimPrefix(a.ID, "PAN-SA-"), "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", a.ID)
			}
			if _, err := time.Parse("2006", splitted[0]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "PAN-SA-yyyy-\\d{4,}", a.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", a.ID)))
			}
		case strings.HasPrefix(a.ID, "CVE-"):
			splitted, err := util.Split(strings.TrimPrefix(a.ID, "CVE-"), "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.ID)
			}
			if _, err := time.Parse("2006", splitted[0]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.ID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", a.ID)))
			}
		default:
			return errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"PAN-SA-", "CVE-"}, a.ID)
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
