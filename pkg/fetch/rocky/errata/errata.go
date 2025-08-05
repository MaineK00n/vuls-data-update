package errata

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://errata.build.resf.org/api/v2/advisories?page=%d&limit=100"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "rocky"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Rocky Linux")

	var advs []Advisory
	for i := 0; ; i++ {
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

			var a advisories
			if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}

			return a.Advisories, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		if len(as) == 0 {
			break
		}

		advs = append(advs, as...)
	}

	bar := pb.StartNew(len(advs))
	for _, a := range advs {
		splitted, err := util.Split(a.Name, "-", ":")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
			continue
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.Name)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
