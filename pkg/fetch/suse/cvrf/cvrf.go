package cvrf

import (
	"archive/tar"
	"compress/bzip2"
	"encoding/xml"
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

const baseURL = "https://ftp.suse.com/pub/projects/security/cvrf1.2.tar.bz2"

type options struct {
	baseURL string
	dir     string
	retry   int

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch SUSE CVRF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch suse cvrf")
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

		if filepath.Ext(hdr.Name) != ".xml" {
			continue
		}

		var adv CVRF
		if err := xml.NewDecoder(tr).Decode(&adv); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		id := adv.DocumentTracking.Identification.ID
		if adv.DocumentType == "SUSE Image" {
			id = adv.DocumentTitle
		}

		var splitted []string
		switch prefix, _, _ := strings.Cut(id, "-"); prefix {
		case "SUSE", "openSUSE":
			// e.g. SUSE-SU-2015:0011-2, openSUSE-SU-2015:0225-1, SUSE-IU-2021:2-1, SUSE-SU-403
			splitted, err = util.Split(id, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(SUSE|openSUSE)-(SU|RU|FU|OU|IU|EL)-.*", id)
			}
		case "ESBA", "ESEA", "ESSA", "RHBA", "RHEA", "RHSA":
			// SUSE Liberty Linux advisories have no vendor prefix.
			// e.g. ESBA-2024:0591, ESEA-2023:0047, ESSA-2022:0008, RHBA-2019:1992, RHEA-2019:3072, RHSA-2019:2079
			splitted, err = util.Split(id, "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(ESBA|ESEA|ESSA|RHBA|RHEA|RHSA)-.*", id)
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

		if err := util.Write(filepath.Join(slices.Concat([]string{options.dir}, splitted[:len(splitted)-1], []string{y, fmt.Sprintf("%s.json", id)})...), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(slices.Concat([]string{options.dir}, splitted[:len(splitted)-1], []string{y, fmt.Sprintf("%s.json", id)})...))
		}
	}

	return nil
}
