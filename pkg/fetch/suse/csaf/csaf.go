package csaf

import (
	"archive/tar"
	"compress/bzip2"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/csaf.tar.bz2"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
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
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "suse", "csaf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch SUSE CSAF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch suse csaf")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	tr := tar.NewReader(bzip2.NewReader(resp.Body))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var adv CSAF
		if err := json.UnmarshalRead(tr, &adv, jsontext.AllowInvalidUTF8(true)); err != nil {
			return errors.Wrap(err, "decode json")
		}

		var splitted []string
		switch prefix, _, _ := strings.Cut(adv.Document.Tracking.ID, "-"); prefix {
		case "SUSE", "openSUSE":
			// e.g. SUSE-SU-2015:0011-2, openSUSE-SU-2016:1623-1, SUSE-EL-9-Client-Tools-2023-2185, SUSE-SU-403
			splitted, err = util.Split(adv.Document.Tracking.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(SUSE|openSUSE)-(SU|RU|FU|OU|EL)-.*", adv.Document.Tracking.ID)
			}
		case "ESBA", "ESEA", "ESSA", "RHBA", "RHEA", "RHSA":
			// SUSE Liberty Linux advisories have no vendor prefix.
			// e.g. ESBA-2024:0591, ESEA-2023:0047, ESSA-2022:0008, RHBA-2019:1992, RHEA-2019:3072, RHSA-2019:2079
			splitted, err = util.Split(adv.Document.Tracking.ID, "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(ESBA|ESEA|ESSA|RHBA|RHEA|RHSA)-.*", adv.Document.Tracking.ID)
			}
		default:
			return errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"SUSE", "openSUSE", "ESBA", "ESEA", "ESSA", "RHBA", "RHEA", "RHSA"}, prefix)
		}

		y := "others"
		if lhs, _, ok := strings.Cut(splitted[len(splitted)-1], ":"); ok {
			if _, err := time.Parse("2006", lhs); err == nil {
				y = lhs
			}
		}

		if err := util.Write(filepath.Join(slices.Concat([]string{options.dir}, splitted[:len(splitted)-1], []string{y, fmt.Sprintf("%s.json", adv.Document.Tracking.ID)})...), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(slices.Concat([]string{options.dir}, splitted[:len(splitted)-1], []string{y, fmt.Sprintf("%s.json", adv.Document.Tracking.ID)})...))
		}
	}

	return nil
}
