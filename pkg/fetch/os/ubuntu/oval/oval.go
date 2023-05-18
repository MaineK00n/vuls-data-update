package oval

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	mainURLFormat = "https://security-metadata.canonical.com/oval/oci.com.ubuntu.%s.cve.oval.xml.bz2"
	subURLFormat  = "https://people.canonical.com/~ubuntu-security/oval/oci.com.ubuntu.%s.cve.oval.xml.bz2"
)

type options struct {
	urls  map[string]string
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type urlOption map[string]string

func (u urlOption) apply(opts *options) {
	opts.urls = u
}

func WithURLs(urls map[string]string) Option {
	return urlOption(urls)
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
		urls: map[string]string{
			fmt.Sprintf("%s%s%s", "trusty", string(os.PathSeparator), "main"):         fmt.Sprintf(mainURLFormat, "trusty"),
			fmt.Sprintf("%s%s%s", "trusty", string(os.PathSeparator), "esm"):          fmt.Sprintf(mainURLFormat, "trusty_esm"),
			fmt.Sprintf("%s%s%s", "xenial", string(os.PathSeparator), "main"):         fmt.Sprintf(mainURLFormat, "xenial"),
			fmt.Sprintf("%s%s%s", "xenial", string(os.PathSeparator), "esm-apps"):     fmt.Sprintf(mainURLFormat, "esm-apps_xenial"),
			fmt.Sprintf("%s%s%s", "xenial", string(os.PathSeparator), "esm-infra"):    fmt.Sprintf(mainURLFormat, "esm-infra_xenial"),
			fmt.Sprintf("%s%s%s", "xenial", string(os.PathSeparator), "fips"):         fmt.Sprintf(mainURLFormat, "fips_xenial"),
			fmt.Sprintf("%s%s%s", "xenial", string(os.PathSeparator), "fips-updates"): fmt.Sprintf(mainURLFormat, "fips-updates_xenial"),
			fmt.Sprintf("%s%s%s", "bionic", string(os.PathSeparator), "main"):         fmt.Sprintf(mainURLFormat, "bionic"),
			fmt.Sprintf("%s%s%s", "bionic", string(os.PathSeparator), "esm-apps"):     fmt.Sprintf(mainURLFormat, "esm-apps_bionic"),
			fmt.Sprintf("%s%s%s", "bionic", string(os.PathSeparator), "fips"):         fmt.Sprintf(mainURLFormat, "fips_bionic"),
			fmt.Sprintf("%s%s%s", "bionic", string(os.PathSeparator), "fips-updates"): fmt.Sprintf(mainURLFormat, "fips-updates_bionic"),
			fmt.Sprintf("%s%s%s", "eoan", string(os.PathSeparator), "main"):           fmt.Sprintf(subURLFormat, "eoan"),
			fmt.Sprintf("%s%s%s", "focal", string(os.PathSeparator), "main"):          fmt.Sprintf(mainURLFormat, "focal"),
			fmt.Sprintf("%s%s%s", "focal", string(os.PathSeparator), "esm-apps"):      fmt.Sprintf(mainURLFormat, "esm-apps_focal"),
			fmt.Sprintf("%s%s%s", "focal", string(os.PathSeparator), "fips"):          fmt.Sprintf(mainURLFormat, "fips_focal"),
			fmt.Sprintf("%s%s%s", "focal", string(os.PathSeparator), "fips-updates"):  fmt.Sprintf(mainURLFormat, "fips-updates_focal"),
			fmt.Sprintf("%s%s%s", "groovy", string(os.PathSeparator), "main"):         fmt.Sprintf(subURLFormat, "groovy"),
			fmt.Sprintf("%s%s%s", "hirsute", string(os.PathSeparator), "main"):        fmt.Sprintf(mainURLFormat, "hirsute"),
			fmt.Sprintf("%s%s%s", "impish", string(os.PathSeparator), "main"):         fmt.Sprintf(mainURLFormat, "impish"),
			fmt.Sprintf("%s%s%s", "jammy", string(os.PathSeparator), "main"):          fmt.Sprintf(mainURLFormat, "jammy"),
			fmt.Sprintf("%s%s%s", "jammy", string(os.PathSeparator), "esm-apps"):      fmt.Sprintf(mainURLFormat, "esm-apps_jammy"),
			fmt.Sprintf("%s%s%s", "kinetic", string(os.PathSeparator), "main"):        fmt.Sprintf(mainURLFormat, "kinetic"),
			fmt.Sprintf("%s%s%s", "lunar", string(os.PathSeparator), "main"):          fmt.Sprintf(mainURLFormat, "lunar"),
		},
		dir:   filepath.Join(util.SourceDir(), "ubuntu", "oval"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Ubuntu OVAL")
	for code, url := range options.urls {
		log.Printf("[INFO] Fetch Ubuntu %s", code)
		bs, err := util.FetchURL(url, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch oval")
		}

		var root root
		if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		dir := filepath.Join(options.dir, code)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}

		bar := pb.StartNew(len(root.Definitions.Definition) + 4)
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)))
			}
			bar.Increment()
		}

		if err := util.Write(filepath.Join(dir, "tests", "tests.json.gz"), root.Tests); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "tests.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "objects", "objects.json.gz"), root.Objects); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "objects.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "states", "states.json.gz"), root.States); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "states.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "variables", "variables.json.gz"), root.Variables); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "variables", "variables.json.gz"))
		}
		bar.Increment()

		bar.Finish()
	}

	return nil
}
