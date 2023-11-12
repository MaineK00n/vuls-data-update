package errata

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://errata.build.resf.org/api/v2/advisories?filters.type=TYPE_SECURITY&page=%d&limit=100"

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
		dir:     filepath.Join(util.CacheDir(), "rocky"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Rocky Linux")

	var as []Advisory
	for i := 0; ; i++ {
		bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(fmt.Sprintf(options.dataURL, i))
		if err != nil {
			return errors.Wrap(err, "fetch advisory")
		}

		var a advisories
		if err := json.Unmarshal(bs, &a); err != nil {
			return errors.Wrap(err, "unmarshal json")
		}

		if len(a.Advisories) == 0 {
			break
		}

		as = append(as, a.Advisories...)
	}

	bar := pb.StartNew(len(as))
	for _, a := range as {
		splitted, err := util.Split(a.Name, "-", ":")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
			continue
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", a.Name)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.Name)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.Name)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
