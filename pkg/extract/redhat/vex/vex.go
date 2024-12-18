package vex

import (
	"fmt"
	"io/fs"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"

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
	pm, err := walkProductTree(vuln.ProductTree, c2r)
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
			ID:   sourceTypes.RedHatCSAF,
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

func walkProductTree(pt vex.ProductTree, c2r map[string][]string) (map[vex.ProductID][]product, error) {
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

						p.name = instance.Name
						p.version = func() string {
							if n, ok := m["epoch"]; ok {
								return fmt.Sprintf("%s:%s", n, instance.Version)
							}
							return fmt.Sprintf("0:%s", instance.Version)
						}()

						switch m["arch"] {
						case "":
							return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", "pkg:rpm/redhat/<name>@<version>?arch=<arch>(&epoch=<epoch>)", fpn.ProductIdentificationHelper.PURL)
						default:
							p.arch = m["arch"]
						}
					case strings.HasPrefix(fpn.ProductIdentificationHelper.PURL, "pkg:rpmmod/"):
						instance, err := packageurl.FromString(fpn.ProductIdentificationHelper.PURL)
						if err != nil {
							return nil, errors.Wrapf(err, "parse %q", fpn.ProductIdentificationHelper.PURL)
						}
						switch instance.Version {
						case "":
							p.name = instance.Name
							p.arch = "src"
							p.modularitylabel = strings.TrimPrefix(instance.Namespace, "redhat/")
						default:
							p.modularitylabel = fmt.Sprintf("%s:%s", instance.Name, strings.Split(instance.Version, ":")[0])
						}
					case strings.HasPrefix(fpn.ProductIdentificationHelper.PURL, "pkg:oci/"), strings.HasPrefix(fpn.ProductIdentificationHelper.PURL, "pkg:maven/"):
						return nil, nil
					default:
						return nil, errors.Errorf("unexpected purl format. expected: %q, actual: %q", []string{"pkg:rpm/...", "pkg:rpmmod/...", "pkg:oci/...", "pkg:maven/..."}, fpn.ProductIdentificationHelper.PURL)
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
									if len(rhs) < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.module+el<major>.*", p.version)
									}
									return []string{rhs[0:1]}, nil
								}
							} else {
								if _, rhs, ok := strings.Cut(p.version, ".el"); ok {
									if len(rhs) < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.el<major>.*", p.version)
									}
									return []string{rhs[0:1]}, nil
								}
								if _, rhs, ok := strings.Cut(p.version, ".RHEL"); ok {
									if len(rhs) < 1 {
										return nil, errors.Errorf("unexpected version format. expected: %q, actual: %q", ".*\\.RHEL<major>.*", p.version)
									}
									return []string{rhs[0:1]}, nil
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
				affected_status: "under investigation",
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
					return errors.Errorf("unexpected remedation category. expected: %q, actual: %q", []string{"mitigation", "no_fix_planned", "none_available", "vendor_fix", "workaround"}, r.Category)
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
					return errors.Errorf("unexpected remedation category. expected: %q, actual: %q", []string{"exploit_status", "impact", "target_set"}, t.Category)
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

func buildDataComponents(doc vex.Document, baseVulnerabilities vulnerabilityContentTypes.Content, pm map[vex.ProductID][]product, assm map[vex.ProductID]ass) ([]advisoryTypes.Advisory, []vulnerabilityTypes.Vulnerability, []detectionTypes.Detection, error) {
	baseVulnerabilities.Published = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.InitialReleaseDate)
	baseVulnerabilities.Modified = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.CurrentReleaseDate)
	for pid, ass := range assm {
		if ass.severity.impact == "" {
			ass.severity.impact = doc.AggregateSeverity.Text
			assm[pid] = ass
		}
	}

	pvm := make(map[vex.ProductID]map[string]vcTypes.Criterion)
	for pid, ps := range pm {
		pvm[pid] = make(map[string]vcTypes.Criterion)

		for _, p := range ps {
			vc, err := func() (*vcTypes.Criterion, error) {
				switch assm[pid].status.product_status {
				case "fixed":
					if p.name == "" && p.version == "" {
						return nil, nil
					}

					switch p.arch {
					case "src":
						return nil, nil
					default:
						return &vcTypes.Criterion{
							Vulnerable: true,
							FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeBinary,
								Binary: &vcBinaryPackageTypes.Package{
									Name: func() string {
										if p.modularitylabel != "" {
											return fmt.Sprintf("%s::%s", p.modularitylabel, p.name)
										}
										return p.name
									}(),
									Architectures: []string{p.arch},
									Repositories:  p.repositories,
								},
							},
							Affected: &affectedTypes.Affected{
								Type:  rangeTypes.RangeTypeRPM,
								Range: []rangeTypes.Range{{LessThan: p.version}},
								Fixed: []string{p.version},
							},
						}, nil
					}
				case "affected":
					if p.name == "" {
						log.Printf("[WARN] package name of %q in %q cannot be found", pid, string(baseVulnerabilities.ID))
						return nil, nil
					}

					switch p.arch {
					case "src":
						return &vcTypes.Criterion{
							Vulnerable: true,
							FixStatus: &fixstatusTypes.FixStatus{
								Class:  fixstatusTypes.ClassUnfixed,
								Vendor: assm[pid].status.affected_status,
							},
							Package: vcPackageTypes.Package{
								Type: vcPackageTypes.PackageTypeSource,
								Source: &vcSourcePackageTypes.Package{
									Name: func() string {
										if p.modularitylabel != "" {
											return fmt.Sprintf("%s::%s", p.modularitylabel, p.name)
										}
										return p.name
									}(),
									Repositories: p.repositories,
								},
							},
						}, nil
					default:
						return nil, errors.Errorf("unexpected affected pkg arch. expected: %q, actual: %q", "src", p.arch)
					}
				case "unaffected":
					return nil, nil
				default:
					return nil, errors.Errorf("unexpected product_status. expected: %q, actual: %q", []string{"fixed", "affected", "unaffected"}, assm[pid].status.product_status)
				}
			}()
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "build version criterion")
			}
			if vc != nil {
				pvm[pid][p.major] = *vc
			}
		}
	}

	cm := make(map[string][]conditionTypes.Condition)
	for pid, vm := range pvm {
		for v, vc := range vm {
			cm[v] = append(cm[v], conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{{
						Type:    criterionTypes.CriterionTypeVersion,
						Version: &vc,
					}},
				},
				Tag: segmentTypes.DetectionTag(fmt.Sprintf("%s:%s", baseVulnerabilities.ID, pid)),
			})
		}
	}

	ds := make([]detectionTypes.Detection, 0, len(cm))
	for v, cs := range cm {
		ds = append(ds, detectionTypes.Detection{
			Ecosystem:  ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, v)),
			Conditions: cs,
		})
	}

	am := make(map[advisory][]vex.ProductID)
	for pid, ass := range assm {
		am[ass.advisory] = append(am[ass.advisory], pid)
	}

	as := make([]advisoryTypes.Advisory, 0, len(am))
	for a, ps := range am {
		if a.id == "" {
			continue
		}
		as = append(as, advisoryTypes.Advisory{
			Content: advisoryContentTypes.Content{
				ID: advisoryContentTypes.AdvisoryID(a.id),
				References: []referenceTypes.Reference{{
					Source: "secalert@redhat.com",
					URL:    fmt.Sprintf("https://access.redhat.com/errata/%s", a.id),
				}},
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, a.date),
			},
			Segments: func() []segmentTypes.Segment {
				ss := make([]segmentTypes.Segment, 0, len(ps))
				for _, pid := range ps {
					for v := range pvm[pid] {
						ss = append(ss, segmentTypes.Segment{
							Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, v)),
							Tag:       segmentTypes.DetectionTag(fmt.Sprintf("%s:%s", baseVulnerabilities.ID, pid)),
						})
					}
				}
				return ss
			}(),
		})
	}

	var vs []vulnerabilityTypes.Vulnerability
	for pid, ass := range assm {
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
			return nil, nil, nil, errors.Wrap(err, "walk severity")
		}
		baseVulnerabilities.Severity = ss

		vs = append(vs, vulnerabilityTypes.Vulnerability{
			Content: baseVulnerabilities,
			Segments: func() []segmentTypes.Segment {
				var ss []segmentTypes.Segment
				for v := range pvm[pid] {
					ss = append(ss, segmentTypes.Segment{
						Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, v)),
						Tag:       segmentTypes.DetectionTag(fmt.Sprintf("%s:%s", baseVulnerabilities.ID, pid)),
					})
				}
				return ss
			}(),
		})

	}

	return as, vs, ds, nil
}
