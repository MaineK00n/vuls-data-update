package oval

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
)

var (
	ovalURLs = map[string]OvalURL{
		"4": {
			URLs: []string{"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL4.xml.bz2"},
		},
		"5": {
			URLs: []string{
				"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL5.xml.bz2",
				"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL5-ELS.xml.bz2",
			},
		},
		"6": {
			Indexof: "https://www.redhat.com/security/data/oval/v2/RHEL6/",
		},
		"7": {
			Indexof: "https://www.redhat.com/security/data/oval/v2/RHEL7/",
		},
		"8": {
			Indexof: "https://www.redhat.com/security/data/oval/v2/RHEL8/",
		},
		"9": {
			Indexof: "https://www.redhat.com/security/data/oval/v2/RHEL9/",
		},
	}
	repositoryToCPEURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"
)

type OvalURL struct {
	Indexof string
	URLs    []string
}

type options struct {
	ovalURLs           map[string]OvalURL
	repositoryToCPEURL string
	dir                string
	retry              int
	compressFormat     string
}

type Option interface {
	apply(*options)
}

type ovalURLsOption map[string]OvalURL

func (u ovalURLsOption) apply(opts *options) {
	opts.ovalURLs = u
}

func WithOvalURLs(u map[string]OvalURL) Option {
	return ovalURLsOption(u)
}

type repositoryToCPEURLOption string

func (u repositoryToCPEURLOption) apply(opts *options) {
	opts.repositoryToCPEURL = string(u)
}

func WithRepositoryToCPEURLs(u string) Option {
	return repositoryToCPEURLOption(u)
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		ovalURLs:           ovalURLs,
		repositoryToCPEURL: repositoryToCPEURL,
		dir:                filepath.Join(util.SourceDir(), "redhat", "oval"),
		retry:              3,
		compressFormat:     "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch RedHat OVAL")
	log.Println("[INFO] Fetch Redhat Repository to CPE")
	var repo2cpe repositoryToCPE
	bs, err := util.FetchURL(options.repositoryToCPEURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch repository to cpe")
	}
	if err := json.Unmarshal(bs, &repo2cpe); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}
	cpe2repo := map[string][]string{}
	for repo, cpes := range repo2cpe.Data {
		for _, cpe := range cpes.Cpes {
			cpe2repo[cpe] = append(cpe2repo[cpe], repo)
		}
	}

	for v, ovalURL := range options.ovalURLs {
		log.Printf("[INFO] Fetch RedHat %s OVAL", v)
		if ovalURL.Indexof != "" {
			urls, err := options.walkIndexOf(ovalURL.Indexof)
			if err != nil {
				return errors.Wrap(err, "walk index of")
			}
			ovalURL.URLs = urls
		}

		for _, u := range ovalURL.URLs {
			ovalName := path.Base(u)
			switch {
			case strings.HasPrefix(ovalName, "com.redhat.rhsa-RHEL"):
				ovalName = strings.TrimSuffix(strings.TrimPrefix(ovalName, "com.redhat.rhsa-RHEL"), ".xml.bz2")
			case strings.HasPrefix(ovalName, "rhel-"):
				ovalName = strings.TrimSuffix(strings.TrimPrefix(ovalName, "rhel-"), ".oval.xml.bz2")
			}

			log.Printf(`[INFO] Fetch %s`, ovalName)
			defs, err := options.fetchOVAL(u, cpe2repo)
			if err != nil {
				return errors.Wrapf(err, "fetch redhat %s", v)
			}

			dir := filepath.Join(options.dir, v, ovalName)
			if err := os.RemoveAll(dir); err != nil {
				return errors.Wrapf(err, "remove %s", dir)
			}
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", dir)
			}

			bar := pb.StartNew(len(defs))
			for _, def := range defs {
				bs, err := json.Marshal(def)
				if err != nil {
					return errors.Wrap(err, "marshal json")
				}

				if err := util.Write(util.BuildFilePath(filepath.Join(dir, fmt.Sprintf("%s.json", def.DefinitionID)), options.compressFormat), bs, options.compressFormat); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(dir, def.DefinitionID))
				}

				bar.Increment()
			}
			bar.Finish()
		}
	}

	return nil
}

func (opts options) walkIndexOf(indexOfURL string) ([]string, error) {
	bs, err := util.FetchURL(indexOfURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var files []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "rhel-") {
			return
		}
		files = append(files, txt)
	})

	urls := make([]string, 0, len(files))
	for _, f := range files {
		u, err := url.JoinPath(indexOfURL, f)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		urls = append(urls, u)
	}
	return urls, nil
}

func (opts options) fetchOVAL(url string, cpe2repo map[string][]string) ([]Definition, error) {
	bs, err := util.FetchURL(url, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch oval")
	}

	var root root
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
		return nil, errors.Wrap(err, "decode oval")
	}

	tests, err := parseTests(root)
	if err != nil {
		return nil, errors.Wrap(err, "parse rpminfo_test")
	}

	return parseDefinitions(root.Definitions.Definitions, tests, cpe2repo), nil
}

func parseTests(root root) (map[string]Package, error) {
	objs := parseObjects(root.Objects)
	states := parseStates(root.States)
	tests := map[string]Package{}
	for _, test := range root.Tests.RpminfoTests {
		t, err := followTestRefs(test, objs, states)
		if err != nil {
			return nil, errors.Wrap(err, "follow test refs")
		}
		if t != nil {
			tests[test.ID] = *t
		}
	}
	return tests, nil
}

func parseObjects(ovalObjs objects) map[string]string {
	objs := map[string]string{}
	for _, obj := range ovalObjs.RpminfoObject {
		objs[obj.ID] = obj.Name
	}
	return objs
}

func parseStates(objStates states) map[string]rpminfoState {
	states := map[string]rpminfoState{}
	for _, state := range objStates.RpminfoState {
		states[state.ID] = state
	}
	return states
}

func followTestRefs(test rpminfoTest, objects map[string]string, states map[string]rpminfoState) (*Package, error) {
	var p Package

	if test.Object.ObjectRef == "" {
		return nil, errors.Errorf(`ObjectRef is empty. rpminfo_test id="%s"`, test.ID)
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return nil, errors.Errorf(`rpminfo_object not found. rpminfo_test id="%s", rpminfo_object id="%s"`, test.ID, test.Object.ObjectRef)
	}
	p.Name = pkgName

	if test.State.StateRef == "" {
		return &p, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return nil, errors.Errorf(`rpminfo_state not found. rpminfo_test id="%s", rpminfo_state id="%s"`, test.ID, test.State.StateRef)
	}

	if state.SignatureKeyid.Text != "" {
		return nil, nil
	}

	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		// state.Arch.Text: aarch64|ppc64le|s390x|x86_64
		p.Arch = state.Arch.Text
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		p.FixedVersion = state.Evr.Text
	}

	return &p, nil
}

func parseDefinitions(ovalDefs []definition, tests map[string]Package, cpe2repo map[string][]string) []Definition {
	defs := []Definition{}

	parseDateFn := func(layouts []string, v string) *time.Time {
		if v == "" {
			return nil
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, v); err == nil {
				return &t
			}
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	for _, d := range ovalDefs {
		def := Definition{
			DefinitionID: d.ID,
			Class:        d.Class,
			Title:        d.Title,
			Description:  d.Description,
			Affected: Affected{
				Family:    d.Affected.Family,
				Platforms: d.Affected.Platform,
			},
			Advisory: Advisory{
				Severity: d.Advisory.Severity,
				Issued:   parseDateFn([]string{"2006-01-02"}, d.Advisory.Issued.Date),
				Updated:  parseDateFn([]string{"2006-01-02"}, d.Advisory.Updated.Date),
			},
		}

		for _, r := range d.References {
			def.References = append(def.References, Reference{
				ID:     r.RefID,
				Source: r.Source,
				URL:    r.RefURL,
			})
		}

		for _, cve := range d.Advisory.Cves {
			def.Advisory.CVEs = append(def.Advisory.CVEs, CVE{
				CVEID:  cve.CveID,
				CVSS2:  cve.Cvss2,
				CVSS3:  cve.Cvss3,
				CWE:    cve.Cwe,
				Impact: cve.Impact,
				Href:   cve.Href,
				Public: parseDateFn([]string{"20060102", "20060102:1504"}, cve.Public),
			})
		}

		for _, b := range d.Advisory.Bugzillas {
			def.Advisory.Bugzillas = append(def.Advisory.Bugzillas, Bugzilla(b))
		}

		for _, cpe := range d.Advisory.AffectedCPEList {
			def.Advisory.CPEs = append(def.Advisory.CPEs, CPE{
				CPE:        cpe,
				Repository: cpe2repo[cpe],
			})
		}

		component2state := map[string]string{}
		if d.Advisory.Affected.State != "" {
			def.Advisory.Affected = &Resolution{
				State:     d.Advisory.Affected.State,
				Component: d.Advisory.Affected.Component,
			}
			for _, c := range d.Advisory.Affected.Component {
				component2state[c] = d.Advisory.Affected.State
			}
		}
		def.Packages = collectPkgs(d.Criteria, tests, strings.HasPrefix(d.ID, "oval:com.redhat.unaffected:def:"), component2state)

		defs = append(defs, def)
	}
	return defs
}

func collectPkgs(cri criteria, tests map[string]Package, isUnaffected bool, componenct2state map[string]string) []Package {
	label, pkgs := walkCriterion(cri, tests)
	for i, pkg := range pkgs {
		if isUnaffected {
			pkg.Status = "Not affected"
		}
		if state, ok := componenct2state[pkg.Name]; ok {
			pkg.Status = state
		}
		if pkg.Status == "" && pkg.FixedVersion != "" {
			pkg.Status = "Fixed"
		}
		pkg.ModularityLabel = label
		pkgs[i] = pkg
	}
	return pkgs
}

func walkCriterion(cri criteria, tests map[string]Package) (string, []Package) {
	var label string
	packages := []Package{}

	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Module ") && strings.HasSuffix(c.Comment, " is enabled") {
			label = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Module "), " is enabled")
			continue
		}

		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		for _, arch := range strings.Split(t.Arch, "|") {
			packages = append(packages, Package{
				Name:         t.Name,
				FixedVersion: t.FixedVersion,
				Arch:         arch,
			})
		}
	}

	for _, c := range cri.Criterias {
		l, pkgs := walkCriterion(c, tests)
		if l != "" {
			label = l
		}
		if len(pkgs) != 0 {
			packages = append(packages, pkgs...)
		}
	}
	return label, util.Unique(packages)
}
