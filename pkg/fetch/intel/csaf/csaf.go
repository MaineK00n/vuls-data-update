package csaf

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/intel/security-center/archive/refs/heads/main.tar.gz"

// advisoryDir is the directory in the repository archive holding the CSAF documents.
const advisoryDir = "advisories"

// advisoryIDPattern matches the Intel advisory IDs, e.g. INTEL-SA-00606, INTEL-TA-01108.
// It is validated before being used as a path element.
var advisoryIDPattern = regexp.MustCompile(`^INTEL-[A-Z]{2}-[0-9]+$`)

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "intel", "csaf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Intel Security Center CSAF")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (o options) fetch() error {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(o.retry)).Get(o.dataURL)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", o.dataURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	var n int
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// The archive root is named after the repository and the branch, e.g. "security-center-main/".
		_, p, found := strings.Cut(hdr.Name, "/")
		if !found {
			continue
		}
		if path.Dir(p) != advisoryDir || !strings.EqualFold(path.Ext(p), ".json") {
			continue
		}

		var advisory CSAF
		if err := json.UnmarshalRead(tr, &advisory); err != nil {
			return errors.Wrapf(err, "decode %s", hdr.Name)
		}

		if !advisoryIDPattern.MatchString(advisory.Document.Tracking.ID) {
			return errors.Errorf("unexpected advisory ID format. expected: %q, actual: %q", advisoryIDPattern.String(), advisory.Document.Tracking.ID)
		}

		t, err := time.Parse(time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "unexpected initial_release_date format. expected: %q, actual: %q", time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(o.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)), advisory); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)))
		}

		n++
	}

	// The advisories are the whole data set, so an empty result means the archive layout changed upstream.
	if n == 0 {
		return errors.Errorf("no advisory found in %s of %s", advisoryDir, o.dataURL)
	}

	return nil
}
