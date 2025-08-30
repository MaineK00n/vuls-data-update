package emb3d

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://github.com/mitre/emb3d/raw/refs/heads/main/_data/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "emb3d"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch MITRE EMB3D")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	if err := options.fetchThreats(client); err != nil {
		return errors.Wrap(err, "fetch threats")
	}

	if err := options.fetchMitigations(client); err != nil {
		return errors.Wrap(err, "fetch mitigations")
	}

	if err := options.fetchProperties(client); err != nil {
		return errors.Wrap(err, "fetch properties")
	}

	return nil
}

func (opts options) fetchThreats(client *utilhttp.Client) error {
	u, err := url.JoinPath(opts.baseURL, "threats.json")
	if err != nil {
		return errors.Wrap(err, "join url path")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ts threats
	if err := json.NewDecoder(resp.Body).Decode(&ts); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for _, t := range ts.Threats {
		if err := util.Write(filepath.Join(opts.dir, "threats", fmt.Sprintf("%s.json", t.ID)), t); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "threats", fmt.Sprintf("%s.json", t.ID)))
		}
	}

	return nil
}

func (opts options) fetchMitigations(client *utilhttp.Client) error {
	u, err := url.JoinPath(opts.baseURL, "mitigations_threat_mappings.json")
	if err != nil {
		return errors.Wrap(err, "join url path")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ms mitigations
	if err := json.NewDecoder(resp.Body).Decode(&ms); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for _, m := range ms.Mitigations {
		if err := util.Write(filepath.Join(opts.dir, "mitigations", fmt.Sprintf("%s.json", m.ID)), m); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "mitigations", fmt.Sprintf("%s.json", m.ID)))
		}
	}

	return nil
}

func (opts options) fetchProperties(client *utilhttp.Client) error {
	u, err := url.JoinPath(opts.baseURL, "properties_threat_mappings.json")
	if err != nil {
		return errors.Wrap(err, "join url path")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ps properties
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for _, p := range ps.Properties {
		if err := util.Write(filepath.Join(opts.dir, "properties", fmt.Sprintf("%s.json", p.ID)), p); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "properties", fmt.Sprintf("%s.json", p.ID)))
		}
	}

	return nil
}
