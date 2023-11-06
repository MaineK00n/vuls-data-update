package v5

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "mitre", "v5"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE CVE V5 List")
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}

	var vs []Vulnerability

	gr, err := gzip.NewReader(bytes.NewReader(bs))
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

		if !strings.HasPrefix(filepath.Base(hdr.Name), "CVE-") || filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var c cve
		if err := json.NewDecoder(tr).Decode(&c); err != nil {
			return errors.Wrap(err, "decode json")
		}

		vs = append(vs, convert(c))
	}

	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		y := strings.Split(v.CveMetadata.CveID, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CveMetadata.CveID)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CveMetadata.CveID)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func convert(cve cve) Vulnerability {
	v := Vulnerability{
		DataType:    cve.DataType,
		DataVersion: cve.DataVersion,
		CveMetadata: CveMetadata(cve.CveMetadata),
		Containers: Containers{Cna: Cna{
			DateAssigned:     cve.Containers.Cna.DateAssigned,
			DatePublic:       cve.Containers.Cna.DatePublic,
			ProviderMetadata: cve.Containers.Cna.ProviderMetadata,
			ReplacedBy:       cve.Containers.Cna.ReplacedBy,
			Source:           cve.Containers.Cna.Source,
			Tags:             cve.Containers.Cna.Tags,
			Title:            cve.Containers.Cna.Title,
			XGenerator:       cve.Containers.Cna.XGenerator,
			XLegacyV4Record:  cve.Containers.Cna.XLegacyV4Record,
			XRedHatCweChain:  cve.Containers.Cna.XRedhatCweChain,
		}},
	}

	for _, a := range cve.Containers.Cna.Affected {
		affected := Affected{
			CollectionURL:   a.CollectionURL,
			Cpes:            append(a.Cpes, a.Cpe...),
			DefaultStatus:   a.DefaultStatus,
			Modules:         a.Modules,
			Platforms:       a.Platforms,
			Product:         a.Product,
			ProgramFiles:    a.ProgramFiles,
			ProgramRoutines: a.ProgramRoutines,
			Repo:            a.Repo,
			Vendor:          a.Vendor,
			Versions:        a.Versions,
			XRedhatStatus:   a.XRedhatStatus,
		}
		if affected.CollectionURL == nil {
			affected.CollectionURL = a.CollectionURL2
		}
		v.Containers.Cna.Affected = append(v.Containers.Cna.Affected, affected)
	}

	for _, c := range cve.Containers.Cna.Configurations {
		v.Containers.Cna.Configurations = append(v.Containers.Cna.Configurations, Configuration(c))
	}

	for _, c := range cve.Containers.Cna.Credits {
		v.Containers.Cna.Credits = append(v.Containers.Cna.Credits, Credit(c))
	}

	for _, d := range cve.Containers.Cna.Descriptions {
		v.Containers.Cna.Descriptions = append(v.Containers.Cna.Descriptions, Description(d))
	}

	for _, e := range cve.Containers.Cna.Exploits {
		v.Containers.Cna.Exploits = append(v.Containers.Cna.Exploits, Exploit(e))
	}

	for _, i := range cve.Containers.Cna.Impacts {
		v.Containers.Cna.Impacts = append(v.Containers.Cna.Impacts, Impact(i))
	}

	for _, m := range cve.Containers.Cna.Metrics {
		v.Containers.Cna.Metrics = append(v.Containers.Cna.Metrics, Metric(m))
	}

	for _, p := range cve.Containers.Cna.ProblemTypes {
		ds := make([]ProblemTypeDescription, 0, len(p.Descriptions))
		for _, d := range p.Descriptions {
			cweid := d.CweID
			if d.CWEID != nil {
				cweid = d.CWEID
			}
			if d.Cweid != nil {
				cweid = d.Cweid
			}
			ds = append(ds, ProblemTypeDescription{
				CWEID:       cweid,
				Description: d.Description,
				Lang:        d.Lang,
				Reference:   d.Reference,
				Type:        d.Type,
			})
		}
		v.Containers.Cna.ProblemTypes = append(v.Containers.Cna.ProblemTypes, ProblemType{Descriptions: ds})
	}

	for _, r := range cve.Containers.Cna.References {
		v.Containers.Cna.References = append(v.Containers.Cna.References, Reference(r))
	}

	for _, r := range cve.Containers.Cna.RejectedReasons {
		v.Containers.Cna.RejectedReasons = append(v.Containers.Cna.RejectedReasons, RejectedReason(r))
	}

	for _, s := range cve.Containers.Cna.Solutions {
		v.Containers.Cna.Solutions = append(v.Containers.Cna.Solutions, Solution(s))
	}

	for _, t := range cve.Containers.Cna.TaxonomyMappings {
		v.Containers.Cna.TaxonomyMappings = append(v.Containers.Cna.TaxonomyMappings, TaxonomyMapping(t))
	}

	for _, t := range cve.Containers.Cna.Timeline {
		v.Containers.Cna.Timeline = append(v.Containers.Cna.Timeline, Timeline(t))
	}

	for _, w := range cve.Containers.Cna.Workarounds {
		v.Containers.Cna.Workarounds = append(v.Containers.Cna.Workarounds, Workaround(w))
	}

	for k, e := range cve.Containers.Cna.XConverterErrors {
		v.Containers.Cna.XConverterErrors[k] = e
	}

	if v.Containers.Cna.XRedHatCweChain == nil {
		v.Containers.Cna.XRedHatCweChain = cve.Containers.Cna.XRedHatCweChain
	}

	return v
}
