package oval

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/microsoft/AzureLinuxVulnerabilityData/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "azure", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Azure Linux OVAL")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch")
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

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || filepath.Ext(hdr.Name) != ".xml" {
			continue
		}

		var root root
		if err := xml.NewDecoder(tr).Decode(&root); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		var t, v string
		switch {
		case strings.HasPrefix(filepath.Base(hdr.Name), "azurelinux-"):
			t = "azurelinux"
			v = strings.TrimPrefix(strings.TrimSuffix(filepath.Base(hdr.Name), "-oval.xml"), "azurelinux-")
		case strings.HasPrefix(filepath.Base(hdr.Name), "cbl-mariner-"):
			t = "cbl-mariner"
			v = strings.TrimPrefix(strings.TrimSuffix(filepath.Base(hdr.Name), "-oval.xml"), "cbl-mariner-")
		default:
			return errors.Errorf("unexpected oval file name. expected: %q, actual: %q", []string{"azurelinux-<version>-oval.xml", "cbl-mariner-<version>-oval.xml"}, filepath.Base(hdr.Name))
		}

		log.Printf("[INFO] Fetch %s %s OVAL", t, v)

		log.Printf("[INFO] Fetch %s %s Definitions", t, v)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, t, v, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t, v, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch %s %s Tests", t, v)
		bar = pb.StartNew(len(root.Tests.RpminfoTest))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, t, v, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t, v, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch %s %s Objects", t, v)
		bar = pb.StartNew(len(root.Objects.RpminfoObject))
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, t, v, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t, v, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch %s %s States", t, v)
		bar = pb.StartNew(len(root.States.RpminfoState))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, t, v, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t, v, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}
