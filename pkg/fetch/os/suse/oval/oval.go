package oval

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/oval/"

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
		dir:     filepath.Join(util.SourceDir(), "suse", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch SUSE OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		var osname, version string
		if strings.HasPrefix(ovalname, "suse.linux.enterprise.desktop") {
			osname = "suse.linux.enterprise.desktop"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "suse.linux.enterprise.desktop.")
		} else if strings.HasPrefix(ovalname, "suse.linux.enterprise.server") {
			osname = "suse.linux.enterprise.server"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "suse.linux.enterprise.server.")
		} else if strings.HasPrefix(ovalname, "opensuse.tumbleweed") {
			osname = "opensuse"
			version = "tumbleweed"
		} else if strings.HasPrefix(ovalname, "opensuse.leap") {
			osname = "opensuse.leap"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "opensuse.leap.")
		} else if strings.HasPrefix(ovalname, "opensuse") {
			osname = "opensuse"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "opensuse.")
		} else {
			return errors.Wrapf(err, `unexpected ovalname. accepts: "<osname>.<version>.xml.gz", received: "%s"`, ovalname)
		}

		log.Printf("[INFO] Fetch %s", fmt.Sprintf("%s %s", osname, version))
		defs, err := options.fetchOVAL(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch %s", fmt.Sprintf("%s %s", osname, version))
		}

		dir := filepath.Join(options.dir, osname, version)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}

		bar := pb.StartNew(len(defs))
		for _, def := range defs {
			if err := func() error {
				f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.json", def.DefinitionID)))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, fmt.Sprintf("%s.json", def.DefinitionID)))
				}
				defer f.Close()

				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(def); err != nil {
					return errors.Wrap(err, "encode data")
				}
				return nil
			}(); err != nil {
				return err
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := util.FetchURL(opts.baseURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var ovals []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".xml.gz") {
			return
		}
		if !(strings.HasPrefix(txt, "opensuse") ||
			strings.HasPrefix(txt, "opensuse.leap") ||
			strings.HasPrefix(txt, "opensuse.tumbleweed") ||
			strings.HasPrefix(txt, "suse.linux.enterprise.desktop") ||
			strings.HasPrefix(txt, "suse.linux.enterprise.server")) || strings.HasPrefix(txt, "opensuse.leap.micro") {
			return
		}
		if strings.Contains(txt, "-patch") || strings.Contains(txt, "-affected") || strings.Contains(txt, "-sp") {
			return
		}
		ovals = append(ovals, txt)
	})
	return ovals, nil
}

func (opts options) fetchOVAL(ovalname string) ([]Definition, error) {
	u, err := url.JoinPath(opts.baseURL, ovalname)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	bs, err := util.FetchURL(u, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch oval")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open oval as gzip")
	}

	var root root
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, errors.Wrap(err, "decode oval")
	}

	tests, err := parseTests(root)
	if err != nil {
		return nil, errors.Wrap(err, "parse rpminfo_test")
	}

	return parseDefinitions(ovalname, root.Definitions.Definitions, tests), nil
}

func parseTests(root root) (map[string]Package, error) {
	objs := parseObjects(root.Objects)
	states := parseStates(root.States)
	tests := map[string]Package{}
	for _, test := range root.Tests.RpminfoTest {
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

	state, ok := states[test.State.StateRef]
	if !ok {
		return nil, errors.Errorf(`rpminfo_state not found. rpminfo_test id="%s", rpminfo_state id="%s"`, test.ID, test.State.StateRef)
	}

	if state.SignatureKeyid.Text != "" {
		return nil, nil
	}

	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		// state.Arch.Text: (aarch64|ppc64le|s390x|x86_64)
		p.Arch = strings.Trim(state.Arch.Text, "()")
	}

	switch test.Check {
	case "at least one", "all":
		if state.Evr.Datatype == "evr_string" {
			switch state.Evr.Operation {
			case "less than":
				p.FixedVersion = state.Evr.Text
			case "equals":
				if p.Name == "kernel-default" {
					p.KernelDefaultVersion = state.Evr.Text
				} else {
					log.Printf(`[WARN] unexpected package name. expected: "kernel-default", actual: "%s"`, p.Name)
				}
			case "greater than or equal":
			default:
				log.Printf(`[WARN] unexpected operation. expected: ["less than", "equals", "greater than or equal"], actual: "%s"`, state.Evr.Operation)
			}
		}
	case "none satisfy":
		if state.Evr.Datatype == "evr_string" {
			switch state.Evr.Operation {
			case "less than", "equals":
			case "greater than or equal":
				p.FixedVersion = state.Evr.Text
			default:
				log.Printf(`[WARN] unexpected operation. expected: ["less than", "equals", "greater than or equal"], actual: "%s"`, state.Evr.Operation)
			}
		}
	default:
		log.Printf(`[WARN] unexpected rpminfo_test.check. accepts ["at least one", "all", "none satisfy"], received "%s"`, test.Check)
	}

	return &p, nil
}

func parseDefinitions(xmlname string, ovalDefs []definition, tests map[string]Package) []Definition {
	defs := []Definition{}

	parseDateFn := func(v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return &t
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
				CPEs:     d.Advisory.AffectedCPEList,
				Issued:   parseDateFn(d.Advisory.Issued.Date),
				Updated:  parseDateFn(d.Advisory.Updated.Date),
			},
			Packages: collectPkgs(xmlname, d.Criteria, tests),
		}

		for _, cve := range d.Advisory.Cves {
			def.Advisory.CVEs = append(def.Advisory.CVEs, CVE{
				CVEID:  cve.CveID,
				CVSS3:  cve.Cvss3,
				Impact: cve.Impact,
				Href:   cve.Href,
			})
		}
		if len(def.Advisory.CVEs) == 0 && strings.Contains(xmlname, "opensuse.1") || strings.Contains(xmlname, "suse.linux.enterprise.desktop.10") || strings.Contains(xmlname, "suse.linux.enterprise.server.9") || strings.Contains(xmlname, "suse.linux.enterprise.server.10") {
			t := strings.TrimSpace(d.Title)
			if strings.HasPrefix(t, "CVE-") {
				def.Advisory.CVEs = append(def.Advisory.CVEs, CVE{
					CVEID: t,
					Href:  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", d.Title),
				})
			}
		}
		if len(def.Advisory.CVEs) == 0 {
			log.Printf(`[WARN] no cves. DefinitionID: %s`, d.ID)
		}

		for _, r := range d.References {
			def.References = append(def.References, Reference{
				ID:     r.RefID,
				Source: r.Source,
				URL:    r.RefURL,
			})
		}

		for _, b := range d.Advisory.Bugzillas {
			def.Advisory.Bugzillas = append(def.Advisory.Bugzillas, Bugzilla(b))
		}

		defs = append(defs, def)
	}
	return defs
}

func collectPkgs(xmlname string, cri criteria, tests map[string]Package) []Package {
	if strings.HasPrefix(xmlname, "opensuse.12") {
		v := fmt.Sprintf("openSUSE %s", strings.TrimSuffix(strings.TrimPrefix(xmlname, "opensuse."), ".xml.gz"))
		_, pkgs := walkCriterion(cri, tests)
		for i := range pkgs {
			pkgs[i].Platform = v
		}
		return pkgs
	}
	return walkCriteria(cri, tests)
}

func walkCriteria(cri criteria, tests map[string]Package) []Package {
	pkgs := []Package{}
	if cri.Operator == "AND" {
		vs, ps := walkCriterion(cri, tests)
		for _, v := range vs {
			for _, p := range ps {
				p.Platform = v
				pkgs = append(pkgs, p)
			}
		}
		return pkgs
	}
	for _, criteria := range cri.Criterias {
		if ps := walkCriteria(criteria, tests); len(ps) > 0 {
			pkgs = append(pkgs, ps...)
		}
	}
	return pkgs
}

func walkCriterion(cri criteria, tests map[string]Package) ([]string, []Package) {
	var (
		vers []string
		pkgs []Package
	)
	for _, c := range cri.Criterions {
		if isOSComment(c.Comment) {
			vers = append(vers, strings.TrimSuffix(c.Comment, " is installed"))
			continue
		}

		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		status := "released"
		if strings.HasSuffix(c.Comment, "is not affected") {
			status = "not-affected"
		}

		for _, arch := range strings.Split(t.Arch, "|") {
			pkgs = append(pkgs, Package{
				Name:                 t.Name,
				Status:               status,
				FixedVersion:         t.FixedVersion,
				KernelDefaultVersion: t.KernelDefaultVersion,
				Arch:                 arch,
			})
		}
	}
	var kernelDefaultVersion string
	for _, p := range pkgs {
		if p.Name == "kernel-default" && p.KernelDefaultVersion != "" && p.FixedVersion == "" {
			kernelDefaultVersion = p.KernelDefaultVersion
			break
		}
	}
	if kernelDefaultVersion != "" {
		var livepatchPkgs []Package
		for _, p := range pkgs {
			if p.Name == "kernel-default" && p.KernelDefaultVersion != "" && p.FixedVersion == "" {
				continue
			}
			livepatchPkgs = append(livepatchPkgs, Package{
				Name:                 p.Name,
				Status:               p.Status,
				FixedVersion:         p.FixedVersion,
				KernelDefaultVersion: kernelDefaultVersion,
				Arch:                 p.Arch,
			})
		}
		pkgs = livepatchPkgs
	}

	for _, c := range cri.Criterias {
		vs, ps := walkCriterion(c, tests)
		vers = append(vers, vs...)
		pkgs = append(pkgs, ps...)
	}

	return vers, pkgs
}

func isOSComment(comment string) bool {
	if !strings.HasSuffix(comment, "is installed") {
		return false
	}
	if strings.HasPrefix(comment, "suse1") || // os: suse102 is installed, pkg: suseRegister less than
		comment == "core9 is installed" ||
		(strings.HasPrefix(comment, "sles10") && !strings.Contains(comment, "-docker-image-")) || // os: sles10-sp1 is installed, pkg: sles12-docker-image-1.1.4-20171002 is installed
		strings.HasPrefix(comment, "sled10") || // os: sled10-sp1 is installed
		strings.HasPrefix(comment, "openSUSE") || strings.HasPrefix(comment, "SUSE Linux Enterprise") || strings.HasPrefix(comment, "SUSE Manager") {
		return true
	}
	return false
}
