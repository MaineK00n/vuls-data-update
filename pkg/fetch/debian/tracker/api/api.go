package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const advisoryURL = "https://security-tracker.debian.org/tracker/data/json"

type options struct {
	advisoryURL string
	dir         string
	retry       int
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

func Fetch(opts ...Option) error {
	options := &options{
		advisoryURL: advisoryURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "debian", "tracker", "api"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Debian Security Tracker API")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.advisoryURL)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var as advisories
	if err := json.NewDecoder(resp.Body).Decode(&as); err != nil {
		return errors.Wrap(err, "decode json")
	}

	m := make(map[string]map[string]Advisory)
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
		log.Printf("[INFO] Fetched Debian %s Advisory", code)

		bar := pb.StartNew(len(advs))
		for _, a := range advs {
			d := "TEMP"
			if strings.HasPrefix(a.ID, "CVE-") {
				splitted, err := util.Split(a.ID, "-", "-")
				if err != nil {
					log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.ID)
					continue
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.ID)
					continue
				}
				d = splitted[1]
			}

			if err := util.Write(filepath.Join(options.dir, code, d, fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, d, fmt.Sprintf("%s.json", a.ID)))
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
