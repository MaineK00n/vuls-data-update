package vex

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/vex"
)

type options struct {
	dir string
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

type extractor struct {
	vexDir string
	r      *utiljson.JSONReader
}

func Extract(vexDir, repository2cpeDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "vex"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract RedHat VEX")

	br := utiljson.NewJSONReader()
	var r2c repository2cpe.RepositoryToCPE
	if err := br.Read(filepath.Join(repository2cpeDir, "repository-to-cpe.json"), repository2cpeDir, &r2c); err != nil {
		return errors.Wrapf(err, "read %s", filepath.Join(repository2cpeDir, "repository-to-cpe.json"))
	}
	cpe2repository := make(map[string][]string)
	for repo, d := range r2c.Data {
		for _, cpe := range d.Cpes {
			cpe2repository[cpe] = append(cpe2repository[cpe], repo)
		}
	}

	if err := filepath.WalkDir(vexDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		e := extractor{
			vexDir: vexDir,
			r:      br.Copy(),
		}

		var vuln vex.VEX
		if err := e.r.Read(path, e.vexDir, &vuln); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		extracted, err := e.extract(vuln, cpe2repository)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		ss, err := util.Split(string(extracted.ID), "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-<year>-<ID>", extracted.ID)
		}

		if err := util.Write(filepath.Join(options.dir, "data", ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", vexDir)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RedHatVEX,
		Name: func() *string { t := "RedHat Enterprise Linux CSAF VEX"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			var rs []repositoryTypes.Repository
			r1, _ := utilgit.GetDataSourceRepository(vexDir)
			if r1 != nil {
				rs = append(rs, *r1)
			}
			r2, _ := utilgit.GetDataSourceRepository(repository2cpeDir)
			if r2 != nil {
				rs = append(rs, *r2)
			}
			return rs
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

func (e extractor) extract(vuln vex.VEX, c2r map[string][]string) (dataTypes.Data, error) {
	pm, err := walkProductTree(vuln.Document.Tracking.ID, vuln.ProductTree, c2r)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk product_tree")
	}

	assm, vc, err := walkVulnerabilities(vuln.Vulnerabilities, slices.Collect(maps.Keys(pm)))
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk vulnerabilities")
	}

	as, vs, ds, err := buildDataComponents(vuln.Document, vc, pm, assm)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "build data components")
	}

	return dataTypes.Data{
		ID:              dataTypes.RootID(vuln.Document.Tracking.ID),
		Advisories:      as,
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.RedHatVEX,
			Raws: e.r.Paths(),
		},
	}, nil
}

type product struct {
	major           string
	name            string
	version         string
	arch            string
	modularitylabel string
	cpe             string
	repositories    []string
}

type ass struct {
	advisory advisory
	severity severity
	status   status
}

type advisory struct {
	id   string
	date string
}

type severity struct {
	cvss2  string
	cvss3  string
	impact string
}
type status struct {
	product_status  string
	affected_status string
}

func walkProductTree(cveid string, pt vex.ProductTree, c2r map[string][]string) (map[vex.ProductID][]product, error) {
	var f func(m map[vex.ProductID]vex.FullProductName, branch vex.Branch) error
	f = func(m map[vex.ProductID]vex.FullProductName, branch vex.Branch) error {
		for _, b := range branch.Branches {
			if err := f(m, b); err != nil {
				return errors.Wrap(err, "walk product_tree")
			}
		}
		switch branch.Category {
		case "vendor", "product_family", "architecture":
			return nil
		case "product_name", "product_version":
			if branch.Product == nil {
				return errors.New("branch product is nil")
			}
			m[branch.Product.ProductID] = *branch.Product
			return nil
		default:
			return errors.Errorf("unexpected branch category. expected: %q, actual: %q", []string{"vendor", "product_family", "product_name", "product_version", "architecture"}, branch.Category)
		}
	}

	fpnm := make(map[vex.ProductID]vex.FullProductName)
	for _, b := range pt.Branches {
		if err := f(fpnm, b); err != nil {
			return nil, errors.Wrap(err, "walk product_tree")
		}
	}

	rm := make(map[vex.ProductID][]vex.ProductID)
	for _, r := range pt.Relationships {
		rm[r.FullProductName.ProductID] = append(rm[r.FullProductName.ProductID], r.ProductReference, r.RelatesToProductReference)
	}

	var f2 func(tree map[vex.ProductID][]vex.ProductID, node vex.ProductID) []vex.ProductID
	f2 = func(tree map[vex.ProductID][]vex.ProductID, node vex.ProductID) []vex.ProductID {
		if _, ok := tree[node]; !ok {
			return []vex.ProductID{node}
		}

		var leaves []vex.ProductID
		for _, n := range tree[node] {
			leaves = append(leaves, f2(tree, n)...)
		}
		return leaves
	}

	pm := make(map[vex.ProductID][]product)
	for root := range func() map[vex.ProductID]struct{} {
		rs := make(map[vex.ProductID]struct{}, len(rm))
		for id := range rm {
			rs[id] = struct{}{}
		}
		for _, r := range pt.Relationships {
			delete(rs, r.RelatesToProductReference)
		}
		return rs
	}() {
		p, err := func() (*product, error) {
			var p product
			for _, id := range f2(rm, root) {
				fpn, ok := fpnm[id]
				if !ok {
					return nil, errors.Errorf("%q makes up %q cannot be found within branches", id, root)
				}

				if fpn.ProductIdentificationHelper == nil {
					continue
				}

				if fpn.ProductIdentificationHelper.Hashes != nil || fpn.ProductIdentificationHelper.ModuleNumbers != nil || fpn.ProductIdentificationHelper.SBOMURLs != nil || fpn.ProductIdentificationHelper.SerialNumbers != nil || fpn.ProductIdentificationHelper.SKUs != nil || fpn.ProductIdentificationHelper.XGenericURIs != nil {
					return nil, errors.New("unexpected product identification helper method")
				}

				if fpn.ProductIdentificationHelper.CPE != "" {
					p.cpe = fpn.ProductIdentificationHelper.CPE
					p.repositories = c2r[fpn.ProductIdentificationHelper.CPE]
				}

				if fpn.ProductIdentificationHelper.PURL != "" {
					switch {
					case strings.HasPrefix(fpn.ProductIdentificationHelper.PURL, "pkg:rpm/"):
						instance, err := packageurl.FromString(fpn.ProductIdentificationHelper.PURL)
						if err != nil {
							return nil, errors.Wrapf(err, "parse %q", fpn.ProductIdentificationHelper.PURL)
						}
						m := instance.Qualifiers.Map()

						switch rpmmod := m["rpmmod"]; rpmmod {
						case "":
							switch instance.Version {
							case "":
								p.name = instance.Name

								// source rpm: 'arch=src'
								// binary rpm: ''
								p.arch = m["arch"]

								// Red Hat VEX data bug: https://issues.redhat.com/browse/SECDATA-1097?focusedId=28048367&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-28048367
								if p.arch == "" && strings.HasSuffix(string(id), ".src") {
									p.arch = "src"
								}
							default:
								p.name = instance.Name
								p.version = func() string {
									if n, ok := m["epoch"]; ok {
										return fmt.Sprintf("%s:%s", n, instance.Version)
									}
									return fmt.Sprintf("0:%s", instance.Version)
								}()

								// source rpm: 'arch=src'
								// binary rpm: 'arch=<arch>'
								switch m["arch"] {
								case "":
									// Red Hat VEX data bug: https://issues.redhat.com/browse/SECDATA-1097?focusedId=28054960&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-28054960
									if slices.Contains([]string{"CVE-2025-26699", "CVE-2025-30472", "CVE-2025-47287", "CVE-2025-48432"}, cveid) {
										return nil, nil
									}
									return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", "pkg:rpm/redhat/<name>@<version>?arch=<arch>(&epoch=<epoch>)", fpn.ProductIdentificationHelper.PURL)
								default:
									p.arch = m["arch"]
								}
							}
						default:
							// Red Hat VEX data bug: https://issues.redhat.com/browse/SECDATA-1097?focusedId=28062364&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-28062364

							switch instance.Version {
							case "":
								ss := strings.Split(rpmmod, ":")
								if len(ss) < 2 {
									return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", "pkg:rpm/redhat/<name>?arch=<arch>(&epoch=<epoch>)&rpmmod=<<module>:<stream>>", fpn.ProductIdentificationHelper.PURL)
								}
								p.modularitylabel = fmt.Sprintf("%s:%s", ss[0], ss[1])
								p.name = instance.Name

								// source rpm: 'arch=src'
								// binary rpm: ''
								p.arch = m["arch"]
							default:
								ss := strings.Split(rpmmod, ":")
								if len(ss) < 4 {
									return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", "pkg:rpm/redhat/<name>@<version>?arch=<arch>(&epoch=<epoch>)&rpmmod=<<module>:<stream>:<version>:<context>(:<arch>)>", fpn.ProductIdentificationHelper.PURL)
								}
								p.modularitylabel = fmt.Sprintf("%s:%s", ss[0], ss[1])
								p.name = instance.Name
								p.version = func() string {
									if n, ok := m["epoch"]; ok {
										return fmt.Sprintf("%s:%s", n, instance.Version)
									}
									return fmt.Sprintf("0:%s", instance.Version)
								}()

								// source rpm: 'arch=src'
								// binary rpm: 'arch=<arch>'
								switch m["arch"] {
								case "":
									return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", "pkg:rpm/redhat/<name>@<version>?arch=<arch>(&epoch=<epoch>)&rpmmod=<<module>:<stream>:<version>:<context>(:<arch>)>", fpn.ProductIdentificationHelper.PURL)
								default:
									p.arch = m["arch"]
								}
							}
						}
					default:
						for _, s := range []string{"pkg:oci/", "pkg:maven/", "pkg:generic/", "pkg:koji/", "pkg:npm/"} {
							if strings.HasPrefix(fpn.ProductIdentificationHelper.PURL, s) {
								return nil, nil
							}
						}
						return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", []string{"pkg:rpm/...", "pkg:oci/...", "pkg:maven/...", "pkg:generic/...", "pkg:koji/...", "pkg:npm/..."}, fpn.ProductIdentificationHelper.PURL)
					}
				}
			}
			return &p, nil
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "combine %q", root)
		}
		if p == nil {
			pm[root] = nil
			continue
		}

		majors, err := func() ([]string, error) {
			var vs []string
			for _, r := range p.repositories {
				switch {
				case strings.Contains(r, "rhel-4-"):
					if !slices.Contains(vs, "4") {
						vs = append(vs, "4")
					}
				case strings.Contains(r, "rhel-5-"),
					strings.Contains(r, "rhel-server-5-"):
					if !slices.Contains(vs, "5") {
						vs = append(vs, "5")
					}
				case strings.Contains(r, "rhel-6-"),
					strings.Contains(r, "rhel-server-6-"),
					strings.Contains(r, "rhel-hpc-node-6-"),
					strings.Contains(r, "rhel-server-ost-6-"),
					strings.Contains(r, "rhel-server-dts2-6-"), strings.Contains(r, "rhel-workstation-dts2-6-"),
					strings.Contains(r, "rhel-server-ose-infra-6-"), strings.Contains(r, "rhel-server-ose-jbosseap-6-"), strings.Contains(r, "rhel-server-ose-node-6-"), strings.Contains(r, "rhel-server-ose-rhc-6-"),
					strings.Contains(r, "rhel-server-ose-1.2-infra-6-"), strings.Contains(r, "rhel-server-ose-1.2-jbosseap-6-"), strings.Contains(r, "rhel-server-ose-1.2-node-6-"), strings.Contains(r, "rhel-server-ose-1.2-rhc-6-"),
					strings.Contains(r, "rhel-server-rhscl-6-"), strings.Contains(r, "rhel-workstation-rhscl-6-"),
					strings.Contains(r, "rhel-x86_64-6-"):
					if !slices.Contains(vs, "6") {
						vs = append(vs, "6")
					}
				case strings.Contains(r, "rhel-7-"),
					strings.Contains(r, "rhel-x86_64-server-7-"),
					strings.Contains(r, "rhel-server-rhscl-7-"), strings.Contains(r, "rhel-workstation-rhscl-7-"):
					if !slices.Contains(vs, "7") {
						vs = append(vs, "7")
					}
				case strings.Contains(r, "rhel-8-"):
					if !slices.Contains(vs, "8") {
						vs = append(vs, "8")
					}
				case strings.Contains(r, "rhel-9-"):
					if !slices.Contains(vs, "9") {
						vs = append(vs, "9")
					}
				case strings.Contains(r, "rhel-10-"):
					if !slices.Contains(vs, "10") {
						vs = append(vs, "10")
					}
				default:
				}
			}

			switch len(vs) {
			case 0:
				switch {
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:2.1"):
					return []string{"2.1"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:3"),
					strings.HasPrefix(p.cpe, "cpe:/o:redhat:rhel_els:3"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_extras:3"),
					strings.HasSuffix(p.cpe, "::el3"):
					return []string{"3"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:4"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_extras:4"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_extras_sap:4"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_cluster:4"),
					strings.HasSuffix(p.cpe, ":el4"), strings.HasSuffix(p.cpe, "::el4"):
					return []string{"4"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:5"),
					strings.HasPrefix(p.cpe, "cpe:/o:redhat:rhel_eus:5"),
					strings.HasPrefix(p.cpe, "cpe:/o:redhat:rhel_mission_critical:5"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_cluster_storage:5"),
					strings.HasSuffix(p.cpe, "::el5"):
					return []string{"5"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:6"),
					strings.HasPrefix(p.cpe, "cpe:/o:redhat:rhel_eus:6"),
					strings.HasSuffix(p.cpe, "::el6"):
					return []string{"6"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:7"),
					strings.HasPrefix(p.cpe, "cpe:/a:redhat:rhel_atomic:7"),
					strings.HasSuffix(p.cpe, "::el7"):
					return []string{"7"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:8"),
					strings.HasSuffix(p.cpe, "::el8"):
					return []string{"8"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:9"),
					strings.HasSuffix(p.cpe, "::el9"):
					return []string{"9"}, nil
				case strings.HasPrefix(p.cpe, "cpe:/o:redhat:enterprise_linux:10"),
					strings.HasSuffix(p.cpe, "::el10"):
					return []string{"10"}, nil
				default:
					switch {
					case strings.HasPrefix(string(root), "3AS-"), strings.HasPrefix(string(root), "3ES-"), strings.HasPrefix(string(root), "3WS-"):
						return []string{"3"}, nil
					case strings.HasPrefix(string(root), "4AS-"), strings.HasPrefix(string(root), "4ES-"), strings.HasPrefix(string(root), "4WS-"):
						return []string{"4"}, nil
					case strings.HasPrefix(string(root), "5Server-"):
						return []string{"5"}, nil
					default:
						if p.version != "" {
							if p.modularitylabel != "" {
								if _, rhs, ok := strings.Cut(p.version, ".module+el"); ok {
									var sb strings.Builder
									for _, r := range rhs {
										if !unicode.IsDigit(r) {
											break
										}
										if _, err := sb.WriteRune(r); err != nil {
											return nil, errors.Wrapf(err, "write rune %q", r)
										}
									}
									if sb.Len() < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.module+el<major>.*", p.version)
									}
									return []string{sb.String()}, nil
								}
							} else {
								if _, rhs, ok := strings.Cut(p.version, ".el"); ok {
									var sb strings.Builder
									for _, r := range rhs {
										if !unicode.IsDigit(r) {
											break
										}
										if _, err := sb.WriteRune(r); err != nil {
											return nil, errors.Wrapf(err, "write rune %q", r)
										}
									}
									if sb.Len() < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.el<major>.*", p.version)
									}
									return []string{sb.String()}, nil
								}
								if _, rhs, ok := strings.Cut(p.version, ".RHEL"); ok {
									var sb strings.Builder
									for _, r := range rhs {
										if !unicode.IsDigit(r) {
											break
										}
										if _, err := sb.WriteRune(r); err != nil {
											return nil, errors.Wrapf(err, "write rune %q", r)
										}
									}
									if sb.Len() < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.RHEL<major>.*", p.version)
									}
									return []string{sb.String()}, nil
								}
							}
						}
						return []string{}, nil
					}
				}
			default:
				return vs, nil
			}
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "%q detect major versions", root)
		}
		for _, v := range majors {
			p.major = v
			pm[root] = append(pm[root], *p)
		}
	}
	return pm, nil
}

func walkVulnerabilities(vulns []vex.Vulnerability, pids []vex.ProductID) (map[vex.ProductID]ass, vulnerabilityContentTypes.Content, error) {
	if len(vulns) != 1 {
		return nil, vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected vulnerabilities length. expected: %d, actual: %d", 1, len(vulns))
	}

	assm := make(map[vex.ProductID]ass)

	if err := func() error {
		if len(vulns[0].ProductStatus.FirstAffected) > 0 || len(vulns[0].ProductStatus.FirstFixed) > 0 || len(vulns[0].ProductStatus.LastAffected) > 0 || len(vulns[0].ProductStatus.Recommended) > 0 {
			return errors.Errorf("unexpected product_status method. expected: %q, actual: %+v", []string{"fixed", "known_affected", "known_not_affected", "under_investigation"}, vulns[0].ProductStatus)
		}

		for _, p := range vulns[0].ProductStatus.Fixed {
			base := assm[p]
			base.status = status{product_status: "fixed"}
			assm[p] = base
		}
		for _, p := range vulns[0].ProductStatus.KnownAffected {
			base := assm[p]
			base.status = status{product_status: "affected"}
			assm[p] = base
		}
		for _, p := range vulns[0].ProductStatus.KnownNotAffected {
			base := assm[p]
			base.status = status{product_status: "unaffected"}
			assm[p] = base
		}
		for _, p := range vulns[0].ProductStatus.UnderInvestigation {
			base := assm[p]
			base.status = status{
				product_status:  "affected",
				affected_status: "Under investigation",
			}
			assm[p] = base
		}

		return nil
	}(); err != nil {
		return nil, vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk product_status")
	}

	if err := func() error {
		for _, f := range vulns[0].Flags {
			for _, p := range func() []vex.ProductID {
				if len(f.ProductIDs) > 0 {
					return f.ProductIDs
				}
				return pids
			}() {

				switch base := assm[p]; base.status.product_status {
				case "unaffected":
					if base.status.affected_status != "" {
						return errors.New("already set affected_status")
					}
					base.status.affected_status = f.Label
					assm[p] = base
				default:
					return errors.Errorf("%q is not set for %q", f.Label, base.status.product_status)
				}
			}
		}
		return nil
	}(); err != nil {
		return nil, vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk flags")
	}

	if err := func() error {
		for _, r := range vulns[0].Remediations {
			for _, p := range func() []vex.ProductID {
				if len(r.ProductIDs) > 0 {
					return r.ProductIDs
				}
				return pids
			}() {
				switch r.Category {
				case "mitigation", "workaround":
					// TODO:
				case "no_fix_planned", "none_available":
					base := assm[p]
					if base.status.affected_status != "" {
						return errors.New("already set affected_status")
					}
					base.status.affected_status = r.Details
					assm[p] = base
				case "vendor_fix":
					base := assm[p]
					if base.advisory.id != "" {
						return errors.New("already set advisory id")
					}
					base.advisory = advisory{
						id:   strings.TrimPrefix(r.URL, "https://access.redhat.com/errata/"),
						date: r.Date,
					}
					assm[p] = base
				default:
					return errors.Errorf("unexpected remediation category. expected: %q, actual: %q", []string{"mitigation", "no_fix_planned", "none_available", "vendor_fix", "workaround"}, r.Category)
				}
			}
		}

		return nil
	}(); err != nil {
		return nil, vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk remediations")
	}

	func() {
		for _, s := range vulns[0].Scores {
			for _, p := range s.Products {
				base := assm[p]
				if s.CvssV2 != nil {
					base.severity.cvss2 = s.CvssV2.VectorString
				}
				if s.CvssV3 != nil {
					base.severity.cvss3 = s.CvssV3.VectorString
				}
				assm[p] = base
			}
		}
	}()

	if err := func() error {
		for _, t := range vulns[0].Threats {
			for _, p := range func() []vex.ProductID {
				if len(t.ProductIDs) > 0 {
					return t.ProductIDs
				}
				return pids
			}() {
				switch t.Category {
				case "exploit_status":
				case "impact":
					base := assm[p]
					base.severity.impact = t.Details
					assm[p] = base
				case "target_set":
				default:
					return errors.Errorf("unexpected threat category. expected: %q, actual: %q", []string{"exploit_status", "impact", "target_set"}, t.Category)
				}
			}
		}
		return nil
	}(); err != nil {
		return nil, vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk threats")
	}

	return assm, vulnerabilityContentTypes.Content{
		ID:    vulnerabilityContentTypes.VulnerabilityID(vulns[0].CVE),
		Title: vulns[0].Title,
		Description: func() string {
			if i := slices.IndexFunc(vulns[0].Notes, func(e vex.Note) bool {
				return e.Category == "description"
			}); i >= 0 {
				return vulns[0].Notes[i].Text
			}
			return ""
		}(),
		CWE: func() []cweTypes.CWE {
			if vulns[0].CWE != nil {
				return []cweTypes.CWE{{
					Source: "secalert@redhat.com",
					CWE:    []string{vulns[0].CWE.ID},
				}}
			}
			return nil
		}(),
		References: func() []referenceTypes.Reference {
			rs := make([]referenceTypes.Reference, 0, len(vulns[0].References))
			for _, r := range vulns[0].References {
				rs = append(rs, referenceTypes.Reference{
					Source: "secalert@redhat.com",
					URL:    r.URL,
				})
			}
			return rs
		}(),
		Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, vulns[0].ReleaseDate),
	}, nil
}

type product2 struct {
	name            string
	version         string
	modularitylabel string
	cpe             string
	repositories    []string
	archs           []string
}

type productsWithMaxPid struct {
	maxPid vex.ProductID
	p2s    []product2
}

func buildDataComponents(doc vex.Document, baseVulnerability vulnerabilityContentTypes.Content, pm map[vex.ProductID][]product, assm map[vex.ProductID]ass) ([]advisoryTypes.Advisory, []vulnerabilityTypes.Vulnerability, []detectionTypes.Detection, error) {
	baseVulnerability.Published = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.InitialReleaseDate)
	baseVulnerability.Modified = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.CurrentReleaseDate)
	for pid, ass := range assm {
		if ass.severity.impact == "" && doc.AggregateSeverity != nil {
			ass.severity.impact = doc.AggregateSeverity.Text
			assm[pid] = ass
		}
	}

	// major -> ass -> productWithMaxPid
	apmm := make(map[string]map[ass]productsWithMaxPid)
	for pid, ps := range pm {
		for _, p := range ps {
			if p.name == "" {
				log.Printf("[WARN] package name of %q in %q cannot be found", pid, string(baseVulnerability.ID))
				continue
			}

			apm, found := apmm[p.major]
			if !found {
				apm = map[ass]productsWithMaxPid{}
			}
			ass, found := assm[pid]
			if !found {
				// FIXME: what to do?
				log.Printf("[WARN] advisory/severity/status not found for pid: %s", pid)
				continue
			}

			pmax, found := apm[ass]
			if !found {
				pmax = productsWithMaxPid{
					maxPid: pid,
					p2s: []product2{{
						name:            p.name,
						version:         p.version,
						modularitylabel: p.modularitylabel,
						cpe:             p.cpe,
						archs:           []string{p.arch},
						repositories:    p.repositories,
					}},
				}
			} else {
				added := false
				pmax.maxPid = vex.ProductID(slices.Max([]string{string(pmax.maxPid), string(pid)}))
				for i, p2 := range pmax.p2s {
					if p2.name == p.name && p2.version == p.version && p2.modularitylabel == p.modularitylabel &&
						p2.cpe == p.cpe {
						// && slices.Compare(p2.repositories, p.repositories) == 0 {

						added = true
						if !slices.Contains(p2.archs, p.arch) {
							p2.archs = append(p2.archs, p.arch)
						}
						pmax.p2s[i] = p2
						break
					}
				}
				if !added {
					pmax.p2s = append(pmax.p2s, product2{
						name:            p.name,
						version:         p.version,
						modularitylabel: p.modularitylabel,
						cpe:             p.cpe,
						archs:           []string{p.arch},
						repositories:    p.repositories,
					})
				}
			}
			apm[ass] = pmax
			apmm[p.major] = apm
		}
	}

	var ds []detectionTypes.Detection
	var vs []vulnerabilityTypes.Vulnerability
	var as []advisoryTypes.Advisory

	for major, apm := range apmm {
		var conds []conditionTypes.Condition
		es := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, major))
		for ass, pmax := range apm {
			tag := calculateTag(pmax)
			ss := []segmentTypes.Segment{{
				Ecosystem: es,
				Tag:       tag,
			}}
			ca := criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
			}

			for _, p2 := range pmax.p2s {
				vcs, err := buildVersionCriterion(p2, ass)
				if err != nil {
					return nil, nil, nil, errors.Wrap(err, "build version criterion")
				}
				for _, vc := range vcs {
					ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
						Type:    criterionTypes.CriterionTypeVersion,
						Version: &vc,
					})
				}
			}
			if len(ca.Criterions) > 0 {
				conds = append(conds, conditionTypes.Condition{
					Criteria: ca,
					Tag:      tag,
				})
			}

			v, err := buildVulnerability(baseVulnerability, ass)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "build vulnerability")
			}
			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content:  v,
				Segments: ss,
			})

			a, err := buildAdvisory(ass)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "build advisory")
			}
			if a != nil {
				as = append(as, advisoryTypes.Advisory{
					Content: *a,
					Segments: []segmentTypes.Segment{{
						Ecosystem: es,
						Tag:       tag,
					}},
				})
			}
		}

		if len(conds) == 0 {
			continue
		}

		ds = append(ds, detectionTypes.Detection{
			Ecosystem:  es,
			Conditions: conds,
		})
	}

	return as, vs, ds, nil
}

func buildVersionCriterion(p2 product2, ass ass) ([]vcTypes.Criterion, error) {
	switch ass.status.product_status {
	case "fixed":
		if p2.name == "" && p2.version == "" {
			return nil, nil
		}

		vcs := make([]vcTypes.Criterion, 0, 2)

		if as := slices.DeleteFunc(slices.Clone(p2.archs), func(x string) bool { return x == "src" }); len(as) > 0 {
			vcs = append(vcs, vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: vcPackageTypes.Package{
					Type: vcPackageTypes.PackageTypeBinary,
					Binary: &vcBinaryPackageTypes.Package{
						Name: func() string {
							if p2.modularitylabel != "" {
								return fmt.Sprintf("%s::%s", p2.modularitylabel, p2.name)
							}
							return p2.name
						}(),
						Architectures: as,
						Repositories:  p2.repositories,
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{LessThan: p2.version}},
					Fixed: []string{p2.version},
				},
			})
		}

		if slices.Contains(p2.archs, "src") {
			vcs = append(vcs, vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: vcPackageTypes.Package{
					Type: vcPackageTypes.PackageTypeSource,
					Source: &vcSourcePackageTypes.Package{
						Name: func() string {
							if p2.modularitylabel != "" {
								return fmt.Sprintf("%s::%s", p2.modularitylabel, p2.name)
							}
							return p2.name
						}(),
						Repositories: p2.repositories,
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{LessThan: p2.version}},
					Fixed: []string{p2.version},
				},
			})
		}

		if len(vcs) == 0 {
			return nil, errors.Errorf("No version criterion is built. product: %+v, ass: %+v", p2, ass)
		}
		return vcs, nil
	case "affected":
		if p2.name == "" {
			return nil, nil
		}

		vcs := make([]vcTypes.Criterion, 0, 2)

		if as := slices.DeleteFunc(slices.Clone(p2.archs), func(x string) bool { return x == "src" }); len(as) > 0 {
			vcs = append(vcs, vcTypes.Criterion{
				Vulnerable: true,
				FixStatus: &fixstatusTypes.FixStatus{
					Class:  fixstatusTypes.ClassUnfixed,
					Vendor: ass.status.affected_status,
				},
				Package: vcPackageTypes.Package{
					Type: vcPackageTypes.PackageTypeBinary,
					Binary: &vcBinaryPackageTypes.Package{
						Name: func() string {
							if p2.modularitylabel != "" {
								return fmt.Sprintf("%s::%s", p2.modularitylabel, p2.name)
							}
							return p2.name
						}(),
						Architectures: func() []string {
							if slices.Contains(as, "") {
								return nil
							}
							return as
						}(),
						Repositories: p2.repositories,
					},
				},
			})
		}

		if slices.Contains(p2.archs, "src") {
			vcs = append(vcs, vcTypes.Criterion{
				Vulnerable: true,
				FixStatus: &fixstatusTypes.FixStatus{
					Class:  fixstatusTypes.ClassUnfixed,
					Vendor: ass.status.affected_status,
				},
				Package: vcPackageTypes.Package{
					Type: vcPackageTypes.PackageTypeSource,
					Source: &vcSourcePackageTypes.Package{
						Name: func() string {
							if p2.modularitylabel != "" {
								return fmt.Sprintf("%s::%s", p2.modularitylabel, p2.name)
							}
							return p2.name
						}(),
						Repositories: p2.repositories,
					},
				},
			})
		}

		if len(vcs) == 0 {
			return nil, errors.Errorf("No version criterion is built. product: %+v, ass: %+v", p2, ass)
		}
		return vcs, nil
	case "unaffected":
		return nil, nil
	default:
		return nil, errors.Errorf("unexpected product_status. expected: %q, actual: %q", []string{"fixed", "affected", "unaffected"}, ass.status.product_status)
	}

}

func buildVulnerability(baseVulnerability vulnerabilityContentTypes.Content, ass ass) (vulnerabilityContentTypes.Content, error) {
	ss, err := func() ([]severityTypes.Severity, error) {
		var ss []severityTypes.Severity
		if ass.severity.cvss2 != "" {
			v2, err := cvssV2Types.Parse(ass.severity.cvss2)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss2")
			}
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: "secalert@redhat.com",
				CVSSv2: v2,
			})
		}
		if ass.severity.cvss3 != "" {
			switch {
			case strings.HasPrefix(ass.severity.cvss3, "CVSS:3.0"):
				v30, err := cvssV30Types.Parse(ass.severity.cvss3)
				if err != nil {
					return nil, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv30,
					Source:  "secalert@redhat.com",
					CVSSv30: v30,
				})
			case strings.HasPrefix(ass.severity.cvss3, "CVSS:3.1"):
				v31, err := cvssV31Types.Parse(ass.severity.cvss3)
				if err != nil {
					return nil, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv31,
					Source:  "secalert@redhat.com",
					CVSSv31: v31,
				})
			default:
				return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", ass.severity.cvss3)
			}
		}
		if ass.severity.impact != "" {
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeVendor,
				Source: "secalert@redhat.com",
				Vendor: &ass.severity.impact,
			})
		}
		return ss, nil
	}()
	if err != nil {
		return vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk severity")
	}
	baseVulnerability.Severity = ss
	return baseVulnerability, nil
}

func buildAdvisory(ass ass) (*advisoryContentTypes.Content, error) {
	if ass.advisory.id == "" {
		return nil, nil
	}
	a := advisoryContentTypes.Content{
		ID: advisoryContentTypes.AdvisoryID(ass.advisory.id),
		References: []referenceTypes.Reference{{
			Source: "secalert@redhat.com",
			URL:    fmt.Sprintf("https://access.redhat.com/errata/%s", ass.advisory.id),
		}},
		Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, ass.advisory.date),
	}
	return &a, nil
}

func calculateTag(pmax productsWithMaxPid) segmentTypes.DetectionTag {
	h := fnv.New128()
	h.Write([]byte(pmax.maxPid))
	dst := make([]byte, 36)
	uuid := h.Sum(nil)
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])

	return segmentTypes.DetectionTag(dst)
}
