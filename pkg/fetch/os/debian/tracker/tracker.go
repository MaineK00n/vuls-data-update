package tracker

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/codename"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const advisoryURL = "https://security-tracker.debian.org/tracker/data/json"

type options struct {
	advisoryURL    string
	dir            string
	retry          int
	compressFormat string
}

type Option interface {
	apply(*options)
}

type advisoryURLOption string

func (a advisoryURLOption) apply(opts *options) {
	opts.advisoryURL = string(a)
}

func WithAdvisoryURL(advisoryURL string) Option {
	return advisoryURLOption(advisoryURL)
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		advisoryURL:    advisoryURL,
		dir:            filepath.Join(util.SourceDir(), "debian", "tracker"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Debian Security Tracker")
	bs, err := util.FetchURL(options.advisoryURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var as advisories
	if err := json.Unmarshal(bs, &as); err != nil {
		return errors.Wrap(err, "unmarshal advisory")
	}

	m := map[string]map[string]Advisory{}
	for pkg, cves := range as {
		for id, cve := range cves {
			for code, release := range cve.Release {
				if _, ok := m[code]; !ok {
					m[code] = map[string]Advisory{}
				}
				adv, ok := m[code][id]
				if !ok {
					adv = Advisory{
						ID:          id,
						Description: cve.Description,
						Scope:       cve.Scope,
					}
					if cve.DebianBug != nil {
						adv.DebianBug = cve.DebianBug
					}
				}
				p := Package{
					Name:         pkg,
					Status:       release.Status,
					NoDSA:        release.NoDSA,
					NoDSAReason:  release.NoDSAReason,
					Urgency:      release.Urgency,
					FixedVersion: release.FixedVersion,
				}
				for repo, v := range release.Repositories {
					p.Repository = append(p.Repository, Repository{
						Name:    repo,
						Version: v,
					})
				}
				adv.Packages = append(adv.Packages, p)
				m[code][id] = adv
			}
		}
	}

	for code, advs := range m {
		v, ok := codename.CodeToVer[code]
		if !ok {
			return errors.Errorf("unexpected codename. accepts %q, received %q", maps.Keys(codename.CodeToVer), code)
		}

		log.Printf("[INFO] Fetched Debian %s Advisory", v)
		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}

		as := maps.Values(advs)
		bar := pb.StartNew(len(as))
		for _, a := range as {
			var y string
			if strings.HasPrefix(a.ID, "CVE-") {
				y = strings.Split(a.ID, "-")[1]
				if _, err := strconv.Atoi(y); err != nil {
					continue
				}
			} else {
				y = strings.Split(a.ID, "-")[0]
			}

			bs, err := json.Marshal(a)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(dir, y, fmt.Sprintf("%s.json", a.ID)), options.compressFormat), bs, options.compressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, y, a.ID))
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
