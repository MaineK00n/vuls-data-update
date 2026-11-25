package nistnvd

import (
	"archive/zip"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://api.vulncheck.com/v3/backup/nist-nvd"

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

func Fetch(apiToken string, opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "vulncheck", "nist-nvd"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch VulnCheck NVD++ (nist-nvd)")

	if err := os.MkdirAll(options.dir, 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}
	if err := os.WriteFile(filepath.Join(options.dir, "README.md"), []byte(`## Repository of VulnCheck NVD++ (nist-nvd) data accumulation

All the data in this repository are fetched from VulnCheck by its API.

- https://docs.vulncheck.com/
- https://docs.vulncheck.com/api
- https://docs.vulncheck.com/community/nist-nvd/attribution

**CAUTION**

When you use the data in this repository, you *MUST* comply with the terms and conditions of VulnCheck NVD++: https://docs.vulncheck.com/community/nist-nvd/attribution
Notably, you must show "prominent attribution" to show the data is from VulnCheck NVD++ to users.
`), 0666); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "README.md"))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient))
	u, err := fetchBackupURL(client, options.baseURL, apiToken)
	if err != nil {
		return errors.Wrap(err, "fetch backup url")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrap(err, "fetch vulncheck nvd++")
	}
	defer resp.Body.Close()

	// The backup runs to gigabytes, so it goes to disk rather than to memory.
	tempDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", tempDir)
	}
	defer os.RemoveAll(tempDir)

	zipPath := filepath.Join(tempDir, "nist-nvd.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return errors.Wrapf(err, "create %s", zipPath)
	}
	defer f.Close()

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return errors.Wrapf(err, "write %s", zipPath)
	}

	r, err := zip.NewReader(f, n)
	if err != nil {
		return errors.Wrap(err, "create zip reader")
	}

	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}

		if !strings.HasPrefix(zf.FileInfo().Name(), "nvdcve-1.1-") || !strings.HasSuffix(zf.FileInfo().Name(), ".json") {
			continue
		}

		if err := func() error {
			f, err := zf.Open()
			if err != nil {
				return errors.Wrapf(err, "open %s", zf.Name)
			}
			defer f.Close()

			for v, err := range cveItems(f) {
				if err != nil {
					return errors.Wrap(err, "decode json")
				}

				splitted, err := util.Split(v.Cve.CVEDataMeta.ID, "-", "-")
				if err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Cve.CVEDataMeta.ID)
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Cve.CVEDataMeta.ID)
				}

				p, err := utilfilepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.Cve.CVEDataMeta.ID))
				if err != nil {
					return errors.Wrap(err, "join")
				}

				if err := util.Write(p, v); err != nil {
					return errors.Wrapf(err, "write %s", p)
				}
			}
			return nil
		}(); err != nil {
			return errors.Wrapf(err, "read %s", zf.Name)
		}
	}

	// The README is written whatever the fetch got, so it says nothing about
	// whether the fetch got anything.
	if err := util.EnsureWritten(options.dir, util.WithIgnore(".git", "README.md")); err != nil {
		return errors.Wrapf(err, "ensure written %s", options.dir)
	}

	return nil
}

// cveItems yields the CVE_Items of the NVD 1.1 feed in r one at a time, and
// skips the other members of the feed. A yearly feed, with its CPE names
// expanded, decodes to gigabytes, so decoding a whole one at once can take
// more memory than the runner has.
func cveItems(r io.Reader) iter.Seq2[CVEItem, error] {
	return func(yield func(CVEItem, error) bool) {
		d := jsontext.NewDecoder(r)

		if err := readDelim(d, '{'); err != nil {
			yield(CVEItem{}, err)
			return
		}
		for d.PeekKind() != '}' {
			name, err := d.ReadToken()
			if err != nil {
				yield(CVEItem{}, errors.Wrap(err, "read member name"))
				return
			}

			// A feed that decoded into a struct took a null CVE_Items as
			// none, so it is still none.
			if name.String() != "CVE_Items" || d.PeekKind() == 'n' {
				if err := d.SkipValue(); err != nil {
					yield(CVEItem{}, errors.Wrapf(err, "skip %s", name.String()))
					return
				}
				continue
			}

			if err := readDelim(d, '['); err != nil {
				yield(CVEItem{}, errors.Wrap(err, "read CVE_Items"))
				return
			}
			for d.PeekKind() != ']' {
				var item CVEItem
				if err := json.UnmarshalDecode(d, &item); err != nil {
					yield(CVEItem{}, errors.Wrap(err, "decode CVE item"))
					return
				}
				if !yield(item, nil) {
					return
				}
			}
			if err := readDelim(d, ']'); err != nil {
				yield(CVEItem{}, errors.Wrap(err, "read CVE_Items"))
				return
			}
		}
		if err := readDelim(d, '}'); err != nil {
			yield(CVEItem{}, err)
			return
		}

		switch _, err := d.ReadToken(); {
		case errors.Is(err, io.EOF):
		case err != nil:
			yield(CVEItem{}, errors.Wrap(err, "read after the feed"))
		default:
			yield(CVEItem{}, errors.New("unexpected data after the feed"))
		}
	}
}

// readDelim reads the next token of d and fails unless it is want.
func readDelim(d *jsontext.Decoder, want jsontext.Kind) error {
	tok, err := d.ReadToken()
	if err != nil {
		return errors.Wrapf(err, "read %q", want)
	}
	if tok.Kind() != want {
		return errors.Errorf("unexpected JSON token. expected: %q, actual: %q", want, tok.Kind())
	}
	return nil
}

func fetchBackupURL(client *utilhttp.Client, baseURL, apiToken string) (string, error) {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))

	resp, err := client.Get(baseURL, utilhttp.WithRequestHeader(header))
	if err != nil {
		return "", errors.Wrap(err, "fetch vulncheck nist-nvd backup")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r backupResponse
	if err := json.UnmarshalRead(resp.Body, &r); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	if len(r.Data) != 1 {
		return "", errors.Errorf("expected data length is 1. actual response: %+v", r)
	}

	return r.Data[0].URL, nil
}
