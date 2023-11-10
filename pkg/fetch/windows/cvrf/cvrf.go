package cvrf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"path"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"

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
		dir:     filepath.Join(util.CacheDir(), "windows", "cvrf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows CVRF")
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch updates")
	}

	var us updates
	if err := json.NewDecoder(bytes.NewReader(bs)).Decode(&us); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var cs []CVRF
	for _, u := range us.Value {
		log.Printf("[INFO] Fetch Windows CVRF %s", path.Base(u.CvrfURL))
		bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u.CvrfURL)
		if err != nil {
			return errors.Wrap(err, "fetch cvrf")
		}

		var c CVRF
		if err := xml.NewDecoder(bytes.NewReader(bs)).Decode(&c); err != nil {
			return errors.Wrap(err, "decode xml")
		}
		cs = append(cs, c)
	}

	bar := pb.StartNew(len(cs))
	for _, c := range cs {
		splitted, err := util.Split(c.DocumentTracking.Identification.ID, "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "yyyy-.+", c.DocumentTracking.Identification.ID)
			continue
		}
		if _, err := time.Parse("2006", splitted[0]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "yyyy-.+", c.DocumentTracking.Identification.ID)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", c.DocumentTracking.Identification.ID)), c); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], fmt.Sprintf("%s.json", c.DocumentTracking.Identification.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}
