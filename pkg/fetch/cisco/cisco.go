package cisco

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	// https://developer.cisco.com/docs/psirt/authentication/#accessing-the-api
	accesstokenURL = "https://id.cisco.com/oauth2/default/v1/token"

	// https://developer.cisco.com/docs/psirt/obtain-all-advisories/
	apiURL = "https://apix.cisco.com/security/advisories/v2/all"
)

type options struct {
	accesstokenURL string
	apiURL         string
	dir            string
	retry          int
	concurrency    int
	wait           int
}

type Option interface {
	apply(*options)
}

type accesstokenURLOption string

func (u accesstokenURLOption) apply(opts *options) {
	opts.accesstokenURL = string(u)
}

func WithAccessTokenURL(url string) Option {
	return accesstokenURLOption(url)
}

type apiURLOption string

func (u apiURLOption) apply(opts *options) {
	opts.apiURL = string(u)
}

func WithAPIURL(url string) Option {
	return apiURLOption(url)
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

type concurrencyOption int

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(id, secret string, opts ...Option) error {
	options := &options{
		accesstokenURL: accesstokenURL,
		apiURL:         apiURL,
		dir:            filepath.Join(util.CacheDir(), "fetch", "cisco"),
		retry:          3,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Cisco. dir: %s", options.dir)
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	token, err := fetchAccessToken(client, options.accesstokenURL, id, secret)
	if err != nil {
		return errors.Wrap(err, "fetch cisco access token")
	}

	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	req, err := utilhttp.NewRequest(http.MethodGet, options.apiURL, utilhttp.WithRequestHeader(header))
	if err != nil {
		return errors.Wrap(err, "new request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "fetch cisco api")
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

	bar := pb.StartNew(len(as.Advisories))
	for _, a := range as.Advisories {
		t, err := time.Parse("2006-01-02T15:04:05", a.FirstPublished)
		if err != nil {
			return errors.Errorf("unexpected published format. expected: %q, actual: %q", time.RFC3339, a.FirstPublished)
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "base.json"), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "base.json"))
		}

		if a.CvrfURL != "NA" {
			cvrf, err := func() (any, error) {
				resp, err := client.Get(a.CvrfURL)
				if err != nil {
					return nil, errors.Wrapf(err, "get %s", a.CvrfURL)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					_, _ = io.Copy(io.Discard, resp.Body)
					return nil, errors.Errorf("error request response with status code %d", resp.StatusCode)
				}

				var cvrf any
				if err := xml.NewDecoder(resp.Body).Decode(&cvrf); err != nil {
					return nil, errors.Wrap(err, "decode xml")
				}

				return cvrf, nil
			}()
			if err != nil {
				return errors.Wrapf(err, "fetch %s", a.CvrfURL)
			}

			if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "cvrf.json"), cvrf); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "cvrf.json"))
			}
		}

		if a.CsafURL != "NA" {
			csaf, err := func() (any, error) {
				resp, err := client.Get(a.CsafURL)
				if err != nil {
					return nil, errors.Wrapf(err, "get %s", a.CsafURL)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					_, _ = io.Copy(io.Discard, resp.Body)
					return nil, errors.Errorf("error request response with status code %d", resp.StatusCode)
				}

				var csaf any
				if err := json.NewDecoder(resp.Body).Decode(&csaf); err != nil {
					return nil, errors.Wrap(err, "decode json")
				}

				return csaf, nil
			}()
			if err != nil {
				return errors.Wrapf(err, "fetch %s", a.CsafURL)
			}

			if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "csaf.json"), csaf); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), a.AdvisoryID, "csaf.json"))
			}
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func fetchAccessToken(client *utilhttp.Client, baseURL, clientID, clientSecret string) (string, error) {
	header := make(http.Header)
	header.Set("Content-Type", "application/x-www-form-urlencoded")

	req, err := utilhttp.NewRequest(http.MethodPost, baseURL, utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody([]byte(fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", clientID, clientSecret))))
	if err != nil {
		return "", errors.Wrap(err, "new request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "fetch cisco access token")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var r accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	return r.AccessToken, nil
}
