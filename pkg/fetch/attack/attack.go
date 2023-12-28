package attack

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	enterpriseURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	icsURL        = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
	mobileURL     = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
)

type options struct {
	dataURL *DataURL
	dir     string
	retry   int
}

type DataURL struct {
	Enterprise string
	ICS        string
	Mobile     string
}

type Option interface {
	apply(*options)
}

type dataURLOption struct {
	URL *DataURL
}

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = u.URL
}

func WithDataURL(url *DataURL) Option {
	return dataURLOption{URL: url}
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
		dataURL: &DataURL{
			Enterprise: enterpriseURL,
			ICS:        icsURL,
			Mobile:     mobileURL,
		},
		dir:   filepath.Join(util.CacheDir(), "fetch", "attack"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch MITRE ATT&CK Enterprise")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL.Enterprise)
	if err != nil {
		return errors.Wrap(err, "fetch attack enterprise")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var enterprise enterprise
	if err := json.NewDecoder(resp.Body).Decode(&enterprise); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := pb.StartNew(len(enterprise.Objects))
	for _, o := range enterprise.Objects {
		if err := util.Write(filepath.Join(options.dir, "enterprise", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "enterprise", o.Type, fmt.Sprintf("%s.json", o.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch MITRE ATT&CK ICS")
	resp, err = utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL.ICS)
	if err != nil {
		return errors.Wrap(err, "fetch attack ics")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var ics ics
	if err := json.NewDecoder(resp.Body).Decode(&ics); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar = pb.StartNew(len(ics.Objects))
	for _, o := range enterprise.Objects {
		if err := util.Write(filepath.Join(options.dir, "ics", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "ics", o.Type, fmt.Sprintf("%s.json", o.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch MITRE ATT&CK Mobile")
	resp, err = utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL.Mobile)
	if err != nil {
		return errors.Wrap(err, "fetch attack mobile")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var mobile mobile
	if err := json.NewDecoder(resp.Body).Decode(&mobile); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar = pb.StartNew(len(mobile.Objects))
	for _, o := range enterprise.Objects {
		if err := util.Write(filepath.Join(options.dir, "mobile", o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "mobile", o.Type, fmt.Sprintf("%s.json", o.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}
