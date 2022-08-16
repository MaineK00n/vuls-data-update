package oval

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var (
	urlFormat  = "https://ftp.suse.com/pub/projects/security/oval/%s.%s.xml"
	osVersions = map[string][]string{
		"opensuse":                      {"10.2", "10.3", "11.0", "11.1", "11.2", "11.3", "11.4", "12.1", "12.2", "12.3", "13.1", "13.2", "tumbleweed"},
		"opensuse.leap":                 {"42.1", "42.2", "42.3", "15.0", "15.1", "15.2", "15.3"},
		"suse.linux.enterprise.desktop": {"10", "11", "12", "15"},
		"suse.linux.enterprise.server":  {"9", "10", "11", "12", "15"},
	}
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
		urls:  map[string]string{},
		dir:   filepath.Join(util.CacheDir(), "source", "suse", "oval"),
		retry: 3,
	}

	for osname, versions := range osVersions {
		for _, v := range versions {
			options.urls[fmt.Sprintf("%s %s", osname, v)] = fmt.Sprintf(urlFormat, osname, v)
		}
	}

	for _, o := range opts {
		o.apply(options)
	}

	for name, url := range options.urls {
		osname, version, found := strings.Cut(name, " ")
		if !found {
			return errors.Errorf(`unexpected name. accepts: "<osname> <version>", received: "%s"`, name)
		}
		versions, ok := osVersions[osname]
		if !ok {
			return errors.Errorf(`unexpected osname. accepts: "%s", received: "%s"`, maps.Keys(osVersions), osname)
		}
		if !slices.Contains(versions, version) {
			return errors.Errorf(`unexpected version. accepts: "%s", received: "%s"`, versions, version)
		}

		log.Printf("[INFO] Fetch %s", name)
		advs, err := options.fetchOVAL(url)
		if err != nil {
			return errors.Wrapf(err, "fetch %s", name)
		}

		dir := filepath.Join(options.dir, osname, version)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}

		bar := pb.StartNew(len(advs))
		for _, adv := range advs {
			if err := func() error {
				y := strings.Split(adv.ID, "-")[1]

				if err := os.MkdirAll(filepath.Join(dir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(dir, y))
				}

				f, err := os.Create(filepath.Join(dir, y, fmt.Sprintf("%s.json", adv.ID)))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, y, fmt.Sprintf("%s.json", adv.ID)))
				}
				defer f.Close()

				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(adv); err != nil {
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

func (opts options) fetchOVAL(url string) ([]Advisory, error) {
	bs, err := util.FetchURL(url, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch oval")
	}

	var root root
	if err := xml.Unmarshal(bs, &root); err != nil {
		return nil, errors.Wrap(err, "unmarshal oval")
	}

	tests, err := parseTests(root)
	if err != nil {
		return nil, errors.Wrap(err, "parse rpminfo_test")
	}

	return parseDefinitions(path.Base(url), root.Definitions.Definitions, tests), nil
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

func parseDefinitions(xmlname string, ovalDefs []definition, tests map[string]Package) []Advisory {
	advs := []Advisory{}
	for _, d := range ovalDefs {
		switch d.Class {
		case "vulnerability":
			cves := d.Advisory.Cves
			if len(cves) == 0 && strings.Contains(xmlname, "opensuse.1") || strings.Contains(xmlname, "suse.linux.enterprise.desktop.10") || strings.Contains(xmlname, "suse.linux.enterprise.server.9") || strings.Contains(xmlname, "suse.linux.enterprise.server.10") {
				t := strings.TrimSpace(d.Title)
				if strings.HasPrefix(t, "CVE-") {
					cves = append(cves, cve{
						CveID: t,
						Href:  fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", d.Title),
					})
				}
			}
			if len(cves) == 0 {
				log.Printf(`[WARN] no cves. DefinitionID: %s`, d.ID)
				continue
			}

			var rs []Reference
			for _, r := range d.References {
				rs = append(rs, Reference{
					ID:     r.RefID,
					Source: r.Source,
					URL:    r.RefURL,
				})
			}

			for _, b := range d.Advisory.Bugzillas {
				rs = append(rs, Reference{
					ID:     b.Title,
					Source: "BUG",
					URL:    b.URL,
				})
			}

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

			issued := parseDateFn(d.Advisory.Issued.Date)
			updated := parseDateFn(d.Advisory.Updated.Date)

			pkgs := collectPkgs(xmlname, d.Criteria, tests)

			for _, cve := range cves {
				advs = append(advs, Advisory{
					ID:           cve.CveID,
					DefinitionID: d.ID,
					Title:        d.Title,
					Description:  d.Description,
					CVSS3:        cve.Cvss3,
					Severity:     d.Advisory.Severity,
					Impact:       cve.Impact,
					Affected: Affected{
						Family:    d.Affected.Family,
						Platforms: d.Affected.Platform,
						CPEs:      d.Advisory.AffectedCPEList,
					},
					Packages:   pkgs,
					References: rs,
					Issued:     issued,
					Updated:    updated,
				})
			}
		default:
			log.Printf("[WARN] unknown class: %s", d.Class)
		}
	}
	return advs
}

func collectPkgs(xmlname string, cri criteria, tests map[string]Package) []Package {
	if strings.HasPrefix(xmlname, "opensuse.12") {
		v := fmt.Sprintf("openSUSE %s", strings.TrimSuffix(strings.TrimPrefix(xmlname, "opensuse."), ".xml"))
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

func getOSVersion(platform string) (string, error) {
	if strings.HasPrefix(platform, "suse") {
		s := strings.TrimPrefix(platform, "suse")
		if len(s) < 3 {
			return "", errors.Errorf(`unexpected version string. expected: "suse\d{3}(-.+)?", actual: "%s"`, platform)
		}
		lhs, _, _ := strings.Cut(s, "-")
		v := fmt.Sprintf("%s.%s", lhs[:2], lhs[2:])
		if _, err := version.NewVersion(v); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		return v, nil
	}

	if strings.HasPrefix(platform, "sled") {
		s := strings.TrimPrefix(platform, "sled")
		major, rhs, found := strings.Cut(s, "-")
		if _, err := version.NewVersion(major); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		if !found {
			return major, nil
		}
		for _, s := range strings.Split(rhs, "-") {
			if strings.HasPrefix(s, "sp") {
				sp, err := strconv.Atoi(strings.TrimPrefix(s, "sp"))
				if err != nil {
					return "", errors.Wrap(err, "parse sp version")
				}
				v := major
				if sp != 0 {
					v = fmt.Sprintf("%s.%d", major, sp)
				}
				if _, err := version.NewVersion(v); err != nil {
					return "", errors.Wrap(err, "parse version")
				}
				return v, nil
			}
		}
		return major, nil
	}

	if strings.HasPrefix(platform, "sles") {
		s := strings.TrimPrefix(platform, "sles")
		major, rhs, found := strings.Cut(s, "-")
		if _, err := version.NewVersion(major); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		if !found {
			return major, nil
		}
		for _, s := range strings.Split(rhs, "-") {
			if strings.HasPrefix(s, "sp") {
				sp, err := strconv.Atoi(strings.TrimPrefix(s, "sp"))
				if err != nil {
					return "", errors.Wrap(err, "parse sp version")
				}
				v := major
				if sp != 0 {
					v = fmt.Sprintf("%s.%d", major, sp)
				}
				if _, err := version.NewVersion(v); err != nil {
					return "", errors.Wrap(err, "parse version")
				}
				return v, nil
			}
		}
		return major, nil
	}

	if strings.HasPrefix(platform, "core9") {
		return "9", nil
	}

	if strings.HasPrefix(platform, "openSUSE") {
		if strings.HasPrefix(platform, "openSUSE Leap") {
			// e.g. openSUSE Leap 15.0
			ss := strings.Fields(platform)
			if len(ss) < 3 {
				return "", errors.Errorf(`unexpected version string. expected: "openSUSE Leap <Version>", actual: "%s"`, platform)
			}
			if _, err := version.NewVersion(ss[2]); err != nil {
				return "", errors.Wrap(err, "parse version")
			}
			return ss[2], nil
		}
		// e.g. openSUSE 13.2, openSUSE Tumbleweed
		ss := strings.Fields(platform)
		if len(ss) < 2 {
			return "", errors.Errorf(`unexpected version string. expected: "openSUSE <Version>", actual: "%s"`, platform)
		}
		if ss[1] == "Tumbleweed" {
			return "tumbleweed", nil
		}
		if _, err := version.NewVersion(ss[1]); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		return ss[1], nil
	}

	if strings.HasPrefix(platform, "SUSE Linux Enterprise") {
		// e.g. SUSE Linux Enterprise Storage 7, SUSE Linux Enterprise Micro 5.1
		if strings.HasPrefix(platform, "SUSE Linux Enterprise Storage") || strings.HasPrefix(platform, "SUSE Linux Enterprise Micro") {
			return "", nil
		}

		ss := strings.Fields(strings.ReplaceAll(platform, "-", " "))
		var sp int
		for i := len(ss) - 1; i > 0; i-- {
			if strings.HasPrefix(ss[i], "SP") {
				var err error
				sp, err = strconv.Atoi(strings.TrimPrefix(ss[i], "SP"))
				if err != nil {
					return "", errors.Wrap(err, "parse sp version")
				}
			}
			if major, err := strconv.Atoi(ss[i]); err == nil {
				v := fmt.Sprintf("%d", major)
				if sp != 0 {
					v = fmt.Sprintf("%d.%d", major, sp)
				}
				if _, err := version.NewVersion(v); err != nil {
					return "", errors.Wrap(err, "parse version")
				}
				return v, nil
			}
		}
		return "", errors.Errorf(`unexpected version string. expected: "SUSE Linux Enterprise .+ <Major Version>.*( SP\d.*)?", actual: "%s"`, platform)
	}

	if strings.HasPrefix(platform, "SUSE Manager") {
		// e.g. SUSE Manager Proxy 4.0, SUSE Manager Server 4.0
		return "", nil
	}

	return "", errors.Errorf(`not support platform. platform: "%s"`, platform)
}
