package cvrf

import (
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "microsoft", "cvrf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows CVRF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
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

	for _, u := range us.Value {
		log.Printf("[INFO] Fetch Windows CVRF %s", path.Base(u.CvrfURL))
		c, err := func() (*CVRF, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u.CvrfURL)
			if err != nil {
				return nil, errors.Wrap(err, "fetch cvrf")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var c CVRF
			if err := xml.NewDecoder(resp.Body).Decode(&c); err != nil {
				return nil, errors.Wrap(err, "decode xml")
			}

			return &c, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

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

			if err := util.Write(filepath.Join(options.dir, c.DocumentTracking.Identification.ID, d, fmt.Sprintf("%s.json", vc.DocumentTracking.Identification.ID)), vc); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, c.DocumentTracking.Identification.ID, d, fmt.Sprintf("%s.json", vc.DocumentTracking.Identification.ID)))
			}

			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func filterProductTree(ptree ProductTree, productIDs []string) ProductTree {
	pt := ProductTree{Branch: filterBranch(ptree.Branch, productIDs)}
	for _, p := range ptree.FullProductName {
		if slices.Contains(productIDs, p.ProductID) {
			ptree.FullProductName = append(ptree.FullProductName, p)
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
		if filtered := filterBranch(b, productIDs); len(filtered.FullProductName) > 0 {
			root.Branch = append(root.Branch, filtered)
		}
	}

	return root
}
