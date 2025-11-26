package errata

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://errata.build.resf.org/api/v2/advisories?page=%d&limit=1"

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

var errNoMoreAdvisory = errors.New("no more advisory")

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "rocky", "errata"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Rocky Linux Errata")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))
	bar := progressbar.Default(-1, "Paging Rocky Linux Errata")
	for i := 0; ; i++ {
		if err := func() error {
			resp, err := client.Get(fmt.Sprintf(options.dataURL, i))
			if err != nil {
				return errors.Wrap(err, "fetch advisory")
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				var a advisories
				if err := json.UnmarshalRead(resp.Body, &a); err != nil {
					return errors.Wrap(err, "decode json")
				}

				if len(a.Advisories) == 0 {
					return errNoMoreAdvisory
				}

				for _, a := range a.Advisories {
					splitted, err := util.Split(a.Name, "-", ":")
					if err != nil {
						return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
					}
					if _, err := time.Parse("2006", splitted[1]); err != nil {
						return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
					}

					if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)), a); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)))
					}
				}

				return nil
			case http.StatusInternalServerError:
				// https://github.com/resf/distro-tools/issues/62
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil
			default:
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}
		}(); err != nil {
			if errors.Is(err, errNoMoreAdvisory) {
				break
			}
			return errors.Wrap(err, "fetch")
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	switch resp.StatusCode {
	case http.StatusInternalServerError:
		return false, nil
	default:
		return retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err)
	}
}
