package cvrf

import (
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	// baseURL is the MSRC CVRF v3.0 endpoint root. The index lives at
	// baseURL + "updates" and each month's document at baseURL + "cvrf/<YYYY-Mon>".
	// Every document URL is built from this root (see cvrfDocumentURL) rather than
	// from the index's advertised CvrfUrl, so the same construction is exercised
	// on index-listed months too: if MSRC ever changed the path scheme, those
	// fetches would 404 and fail loudly instead of silently mis-supplementing.
	baseURL = "https://api.msrc.microsoft.com/cvrf/v3.0/"

	// defaultSupplementMonths is how many recent months to recover by fetching
	// the per-month CVRF document URL directly when MSRC drops them from the
	// index. See supplement().
	defaultSupplementMonths = 3
)

// errNotFound is returned by fetchCVRF when the per-month CVRF document
// responds with 404. A supplemented month is allowed to be absent (not yet
// published, or genuinely gone); an index-listed month is not.
var errNotFound = errors.New("cvrf document not found")

// timeNow is the clock used to decide which recent months to supplement. It is
// a package variable so tests can pin it deterministically (see export_test.go).
var timeNow = time.Now

type options struct {
	baseURL          string
	dir              string
	retry            int
	supplementMonths int

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

type supplementMonthsOption int

func (m supplementMonthsOption) apply(opts *options) {
	opts.supplementMonths = int(m)
}

// WithSupplementMonths sets how many recent months to recover by fetching the
// per-month CVRF document URL directly when they are missing from the index.
// Set to 0 to disable supplementation.
func WithSupplementMonths(months int) Option {
	return supplementMonthsOption(months)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:          baseURL,
		dir:              filepath.Join(util.CacheDir(), "fetch", "microsoft", "cvrf"),
		retry:            3,
		supplementMonths: defaultSupplementMonths,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	updatesURL, err := url.JoinPath(options.baseURL, "updates")
	if err != nil {
		return errors.Wrapf(err, "join updates url from %s", options.baseURL)
	}

	slog.Info("Fetch Windows CVRF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(updatesURL)
	if err != nil {
		return errors.Wrap(err, "fetch updates")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var us updates
	if err := json.UnmarshalRead(resp.Body, &us); err != nil {
		return errors.Wrap(err, "decode json")
	}

	seen := make(map[string]struct{}, len(us.Value))
	for _, u := range us.Value {
		seen[u.ID] = struct{}{}

		// Build the document URL from baseURL + ID rather than trusting the
		// index's advertised CvrfUrl, so index-listed months exercise the same
		// URL construction that supplement relies on for absent months.
		cvrfURL, err := cvrfDocumentURL(options.baseURL, u.ID)
		if err != nil {
			return errors.Wrapf(err, "get cvrf document url for %s", u.ID)
		}

		slog.Info("Fetch Windows CVRF", slog.String("file", u.ID))
		c, err := fetchCVRF(options, cvrfURL)
		if err != nil {
			return errors.Wrapf(err, "fetch %s", cvrfURL)
		}

		if err := writeCVRF(options.dir, c); err != nil {
			return errors.Wrapf(err, "write %s", u.ID)
		}
	}

	if err := supplement(options, seen); err != nil {
		return errors.Wrap(err, "supplement recent months")
	}

	return nil
}

func fetchCVRF(options *options, cvrfURL string) (*CVRF, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient)).Get(cvrfURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cvrf")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errNotFound
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var c CVRF
	if err := xml.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}

	return &c, nil
}

func writeCVRF(dir string, c *CVRF) error {
	bar := progressbar.Default(int64(len(c.Vulnerability)))
	for _, v := range c.Vulnerability {
		vc := CVRF{
			DocumentTitle:     c.DocumentTitle,
			DocumentType:      c.DocumentType,
			DocumentPublisher: c.DocumentPublisher,
			DocumentTracking: DocumentTracking{
				Identification: Identification{
					ID:    v.CVE,
					Alias: v.CVE,
				},
				Status:             c.DocumentTracking.Status,
				Version:            c.DocumentTracking.Version,
				RevisionHistory:    c.DocumentTracking.RevisionHistory,
				InitialReleaseDate: c.DocumentTracking.InitialReleaseDate,
				CurrentReleaseDate: c.DocumentTracking.CurrentReleaseDate,
			},
			DocumentNotes: c.DocumentNotes,
			ProductTree:   filterProductTree(c.ProductTree, v.ProductStatuses.Status.ProductID),
			Vulnerability: []Vulnerability{v},
		}

		d := "others"
		if strings.HasPrefix(vc.DocumentTracking.Identification.ID, "CVE-") {
			splitted, err := util.Split(vc.DocumentTracking.Identification.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vc.DocumentTracking.Identification.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vc.DocumentTracking.Identification.ID)
			}

			d = splitted[1]
		}

		if err := util.Write(filepath.Join(dir, c.DocumentTracking.Identification.ID, d, fmt.Sprintf("%s.json", vc.DocumentTracking.Identification.ID)), vc); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(dir, c.DocumentTracking.Identification.ID, d, fmt.Sprintf("%s.json", vc.DocumentTracking.Identification.ID)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}

// supplement recovers the most recent options.supplementMonths months that are
// absent from the index by fetching their per-month CVRF document URL directly.
// MSRC occasionally drops a recently published month from the index while its
// document URL still resolves; without this, the raw dataset (and everything
// extracted from it) would lose that month until MSRC restores the index entry.
// A month that is missing from both the index and the direct URL (404) is
// skipped: it is either not yet published or genuinely retired.
func supplement(options *options, seen map[string]struct{}) error {
	if options.supplementMonths <= 0 {
		return nil
	}

	// Anchor to the first of the month so AddDate never overflows a short month.
	now := timeNow()
	ref := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for n := range options.supplementMonths {
		ym := ref.AddDate(0, -n, 0).Format("2006-Jan")
		if _, ok := seen[ym]; ok {
			continue
		}

		cvrfURL, err := cvrfDocumentURL(options.baseURL, ym)
		if err != nil {
			return errors.Wrapf(err, "get cvrf document url for %s", ym)
		}

		slog.Info("Supplement Windows CVRF missing from index", slog.String("month", ym))
		c, err := fetchCVRF(options, cvrfURL)
		if err != nil {
			if errors.Is(err, errNotFound) {
				slog.Warn("Skip supplement month absent from both index and direct url", slog.String("month", ym))
				continue
			}
			return errors.Wrapf(err, "fetch %s", cvrfURL)
		}

		if err := writeCVRF(options.dir, c); err != nil {
			return errors.Wrapf(err, "write %s", ym)
		}
	}

	return nil
}

// cvrfDocumentURL builds the per-month CVRF document URL (baseURL + "cvrf/<id>").
func cvrfDocumentURL(baseURL, id string) (string, error) {
	u, err := url.JoinPath(baseURL, "cvrf", id)
	if err != nil {
		return "", errors.Wrapf(err, "join cvrf document url from %s for %s", baseURL, id)
	}
	return u, nil
}

func filterProductTree(ptree ProductTree, productIDs []string) ProductTree {
	pt := ProductTree{Branch: filterBranch(ptree.Branch, productIDs)}
	for _, p := range ptree.FullProductName {
		if slices.Contains(productIDs, p.ProductID) {
			pt.FullProductName = append(pt.FullProductName, p)
		}
	}
	return pt
}

func filterBranch(branch Branch, productIDs []string) Branch {
	root := Branch{
		Type: branch.Type,
		Name: branch.Name,
	}
	for _, p := range branch.FullProductName {
		if slices.Contains(productIDs, p.ProductID) {
			root.FullProductName = append(root.FullProductName, p)
		}
	}
	for _, b := range branch.Branch {
		if filtered := filterBranch(b, productIDs); len(filtered.FullProductName) > 0 || len(filtered.Branch) > 0 {
			root.Branch = append(root.Branch, filtered)
		}
	}

	return root
}
