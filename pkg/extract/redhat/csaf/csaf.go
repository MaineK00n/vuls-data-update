package csaf

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/csaf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
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
	csafDir string
	r       *utiljson.JSONReader
}

func Extract(csafDir, repository2cpeDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "csaf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract RedHat CSAF")

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

	if err := filepath.WalkDir(csafDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		e := extractor{
			csafDir: csafDir,
			r:       br.Copy(),
		}

		var adv csaf.CSAF
		if err := e.r.Read(path, e.csafDir, &adv); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		extracted, err := e.extract(adv, cpe2repository)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		ss, err := util.Split(string(extracted.ID), "-", ":")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(RHSA|RHBA|RHEA)-<year>:<ID>", extracted.ID)
		}

		if err := util.Write(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", csafDir)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RedHatCSAF,
		Name: func() *string { t := "RedHat Enterprise Linux CSAF"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			var rs []repositoryTypes.Repository
			r1, _ := utilgit.GetDataSourceRepository(csafDir)
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

func (e extractor) extract(adv csaf.CSAF, c2r map[string][]string) (dataTypes.Data, error) {
	pm, err := walkProductTree(adv.ProductTree, c2r)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk product_tree")
	}

	vassm, vm, err := walkVulnerabilities(adv.Vulnerabilities, slices.Collect(maps.Keys(pm)))
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk vulnerabilities")
	}

	vassGroupToPids, err := invertVassGroup(vassm, pm)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "inverse pids")
	}

	as, vs, ds, err := buildDataComponents(advisoryContentTypes.Content{
		ID:    advisoryContentTypes.AdvisoryID(adv.Document.Tracking.ID),
		Title: adv.Document.Title,
		Description: func() string {
			if i := slices.IndexFunc(adv.Document.Notes, func(e csaf.Note) bool {
				return e.Category == "general" && e.Title == "Details"
			}); i != -1 {
				return adv.Document.Notes[i].Text
			}
			return ""
		}(),
		Severity: []severityTypes.Severity{{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "secalert@redhat.com",
			Vendor: &adv.Document.AggregateSeverity.Text,
		}},
		References: func() []referenceTypes.Reference {
			rs := make([]referenceTypes.Reference, 0, len(adv.Document.References))
			for _, r := range adv.Document.References {
				rs = append(rs, referenceTypes.Reference{
					Source: "secalert@redhat.com",
					URL:    r.URL,
				})
			}
			return rs
		}(),
		Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, adv.Document.Tracking.InitialReleaseDate),
		Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, adv.Document.Tracking.CurrentReleaseDate),
	}, vm, pm, vassGroupToPids)

	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "build data components")
	}

	return dataTypes.Data{
		ID:              dataTypes.RootID(adv.Document.Tracking.ID),
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
	Advisory string
	Severity severity
	Status   status
}
type severity struct {
	Cvss2  string
	Cvss3  string
	Impact string
}
type status struct {
	ProductStatus  string
	AffectedStatus string
}

func walkProductTree(pt csaf.ProductTree, c2r map[string][]string) (map[csaf.ProductID][]product, error) {
	var f func(m map[csaf.ProductID]csaf.FullProductName, branch csaf.Branch) error
	f = func(m map[csaf.ProductID]csaf.FullProductName, branch csaf.Branch) error {
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

	fpnm := make(map[csaf.ProductID]csaf.FullProductName)
	for _, b := range pt.Branches {
		if err := f(fpnm, b); err != nil {
			return nil, errors.Wrap(err, "walk product_tree")
		}
	}

	rm := make(map[csaf.ProductID][]csaf.ProductID)
	for _, r := range pt.Relationships {
		rm[r.FullProductName.ProductID] = append(rm[r.FullProductName.ProductID], r.ProductReference, r.RelatesToProductReference)
	}

	var f2 func(tree map[csaf.ProductID][]csaf.ProductID, node csaf.ProductID) []csaf.ProductID
	f2 = func(tree map[csaf.ProductID][]csaf.ProductID, node csaf.ProductID) []csaf.ProductID {
		if _, ok := tree[node]; !ok {
			return []csaf.ProductID{node}
		}

		var leaves []csaf.ProductID
		for _, n := range tree[node] {
			leaves = append(leaves, f2(tree, n)...)
		}
		return leaves
	}

	pm := make(map[csaf.ProductID][]product)
	for root := range func() map[csaf.ProductID]struct{} {
		rs := make(map[csaf.ProductID]struct{}, len(rm))
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

func walkVulnerabilities(vulns []csaf.Vulnerability, pids []csaf.ProductID) (map[string]map[csaf.ProductID]ass, map[string]vulnerabilityContentTypes.Content, error) {
	vassm := make(map[string]map[csaf.ProductID]ass)
	vm := make(map[string]vulnerabilityContentTypes.Content)
	for _, v := range vulns {
		vassm[v.CVE] = make(map[csaf.ProductID]ass)

		if err := func() error {
			if len(v.ProductStatus.FirstAffected) > 0 || len(v.ProductStatus.FirstFixed) > 0 || len(v.ProductStatus.LastAffected) > 0 || len(v.ProductStatus.Recommended) > 0 {
				return errors.Errorf("unexpected product_status method. expected: %q, actual: %+v", []string{"fixed", "known_affected", "known_not_affected", "under_investigation"}, v.ProductStatus)
			}

			for _, p := range v.ProductStatus.Fixed {
				base := vassm[v.CVE][p]
				base.Status = status{ProductStatus: "fixed"}
				vassm[v.CVE][p] = base
			}
			for _, p := range v.ProductStatus.KnownAffected {
				base := vassm[v.CVE][p]
				base.Status = status{ProductStatus: "affected"}
				vassm[v.CVE][p] = base
			}
			for _, p := range v.ProductStatus.KnownNotAffected {
				base := vassm[v.CVE][p]
				base.Status = status{ProductStatus: "unaffected"}
				vassm[v.CVE][p] = base
			}
			for _, p := range v.ProductStatus.UnderInvestigation {
				base := vassm[v.CVE][p]
				base.Status = status{
					ProductStatus:  "affected",
					AffectedStatus: "Under investigation",
				}
				vassm[v.CVE][p] = base
			}

			return nil
		}(); err != nil {
			return nil, nil, errors.Wrap(err, "walk product_status")
		}

		if err := func() error {
			for _, f := range v.Flags {
				for _, p := range func() []csaf.ProductID {
					if len(f.ProductIDs) > 0 {
						return f.ProductIDs
					}
					return pids
				}() {

					switch base := vassm[v.CVE][p]; base.Status.ProductStatus {
					case "unaffected":
						if base.Status.AffectedStatus != "" {
							return errors.New("already set affected_status")
						}
						base.Status.AffectedStatus = f.Label
						vassm[v.CVE][p] = base
					default:
						return errors.Errorf("%q is not set for %q", f.Label, base.Status.ProductStatus)
					}
				}
			}
			return nil
		}(); err != nil {
			return nil, nil, errors.Wrap(err, "walk flags")
		}

		if err := func() error {
			for _, r := range v.Remediations {
				for _, p := range func() []csaf.ProductID {
					if len(r.ProductIDs) > 0 {
						return r.ProductIDs
					}
					return pids
				}() {
					switch r.Category {
					case "mitigation", "workaround":
						// TODO:
					case "no_fix_planned", "none_available":
						base := vassm[v.CVE][p]
						if base.Status.AffectedStatus != "" {
							return errors.New("already set affected_status")
						}
						base.Status.AffectedStatus = r.Details
						vassm[v.CVE][p] = base
					case "vendor_fix":
						base := vassm[v.CVE][p]
						if base.Advisory != "" {
							return errors.New("already set advisory id")
						}
						base.Advisory = strings.TrimPrefix(r.URL, "https://access.redhat.com/errata/")
						vassm[v.CVE][p] = base
					default:
						return errors.Errorf("unexpected remediation category. expected: %q, actual: %q", []string{"mitigation", "no_fix_planned", "none_available", "vendor_fix", "workaround"}, r.Category)
					}
				}
			}

			return nil
		}(); err != nil {
			return nil, nil, errors.Wrap(err, "walk remediations")
		}

		func() {
			for _, s := range v.Scores {
				for _, p := range s.Products {
					base := vassm[v.CVE][p]
					if s.CvssV2 != nil {
						base.Severity.Cvss2 = s.CvssV2.VectorString
					}
					if s.CvssV3 != nil {
						base.Severity.Cvss3 = s.CvssV3.VectorString
					}
					vassm[v.CVE][p] = base
				}
			}
		}()

		if err := func() error {
			for _, t := range v.Threats {
				for _, p := range func() []csaf.ProductID {
					if len(t.ProductIDs) > 0 {
						return t.ProductIDs
					}
					return pids
				}() {
					switch t.Category {
					case "exploit_status":
					case "impact":
						base := vassm[v.CVE][p]
						base.Severity.Impact = t.Details
						vassm[v.CVE][p] = base
					case "target_set":
					default:
						return errors.Errorf("unexpected threat category. expected: %q, actual: %q", []string{"exploit_status", "impact", "target_set"}, t.Category)
					}
				}
			}
			return nil
		}(); err != nil {
			return nil, nil, errors.Wrap(err, "walk threats")
		}

		vm[v.CVE] = vulnerabilityContentTypes.Content{
			ID:    vulnerabilityContentTypes.VulnerabilityID(v.CVE),
			Title: v.Title,
			Description: func() string {
				if i := slices.IndexFunc(v.Notes, func(e csaf.Note) bool {
					return e.Category == "description"
				}); i != -1 {
					return v.Notes[i].Text
				}
				return ""
			}(),
			CWE: func() []cweTypes.CWE {
				if v.CWE != nil {
					return []cweTypes.CWE{{
						Source: "secalert@redhat.com",
						CWE:    []string{v.CWE.ID},
					}}
				}
				return nil
			}(),
			References: func() []referenceTypes.Reference {
				rs := make([]referenceTypes.Reference, 0, len(v.References))
				for _, r := range v.References {
					rs = append(rs, referenceTypes.Reference{
						Source: "secalert@redhat.com",
						URL:    r.URL,
					})
				}
				return rs
			}(),
			Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, v.ReleaseDate),
		}
	}
	return vassm, vm, nil
}

func invertVassGroup(vassm map[string]map[csaf.ProductID]ass, pm map[csaf.ProductID][]product) (map[string][]csaf.ProductID, error) {
	pidToVassGroup := make(map[csaf.ProductID]map[string]ass)

	for cveID, assm := range vassm {
		for pid, a := range assm {
			if !slices.ContainsFunc(pm[pid], func(p product) bool { return len(p.arch) > 0 }) {
				// Ignore ass with no arches because it does not included in detections.
				continue
			}

			vassGroup, found := pidToVassGroup[pid]
			if !found {
				vassGroup = make(map[string]ass)
			}
			vassGroup[cveID] = a
			pidToVassGroup[pid] = vassGroup
		}
	}

	vassGroupToPids := make(map[string][]csaf.ProductID)

	for pid, vassGroup := range pidToVassGroup {
		bs, err := json.Marshal(vassGroup)
		if err != nil {
			return nil, errors.Wrap(err, "json marshal")
		}
		vassGroupToPids[string(bs)] = append(vassGroupToPids[string(bs)], pid)
	}

	return vassGroupToPids, nil
}

func buildDataComponents(baseAdvisory advisoryContentTypes.Content, baseVulnerabilities map[string]vulnerabilityContentTypes.Content, pm map[csaf.ProductID][]product, vassGroupToPids map[string][]csaf.ProductID) ([]advisoryTypes.Advisory, []vulnerabilityTypes.Vulnerability, []detectionTypes.Detection, error) {
	adv := advisoryTypes.Advisory{
		Content: baseAdvisory,
	}
	var vs []vulnerabilityTypes.Vulnerability
	cm := make(map[string][]conditionTypes.Condition)

	for vassGroupString, pids := range vassGroupToPids {
		var vassGroup map[string]ass
		if err := json.Unmarshal([]byte(vassGroupString), &vassGroup); err != nil {
			return nil, nil, nil, errors.Wrap(err, "json unmarshal")
		}

		for _, status := range func() []status {
			var ss []status
			for _, a := range vassGroup {
				if !slices.Contains(ss, a.Status) {
					ss = append(ss, a.Status)
				}
			}
			return ss
		}() {
			// To include major in the input of calculateTag(), summarize per major.
			// Including major is not mandatory, but it will be helpful when plain-old-grep'ping by tag string.
			pidsm := make(map[string][]csaf.ProductID)
			for _, pid := range pids {
				for _, p := range pm[pid] {
					if !slices.Contains(pidsm[p.major], pid) {
						pidsm[p.major] = append(pidsm[p.major], pid)
					}
				}
			}

			for major, pidsPerMajor := range pidsm {
				segment := segmentTypes.Segment{
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, major)),
					Tag:       calculateTag(major, pidsPerMajor, status),
				}

				adv.Segments = append(adv.Segments, segment)

				for cveID, a := range vassGroup {
					if a.Status != status {
						continue
					}
					base, found := baseVulnerabilities[cveID]
					if !found {
						return nil, nil, nil, errors.Errorf("no base vulnerability found for %s", cveID)
					}

					sevs, err := buildSeverities(a.Severity)
					if err != nil {
						return nil, nil, nil, errors.Wrap(err, "build severities")
					}
					base.Severity = sevs
					base.Sort()

					index := slices.IndexFunc(vs, func(v vulnerabilityTypes.Vulnerability) bool {
						return vulnerabilityContentTypes.Compare(v.Content, base) == 0
					})
					if index < 0 {
						vs = append(vs, vulnerabilityTypes.Vulnerability{
							Content:  base,
							Segments: []segmentTypes.Segment{segment},
						})
					} else {
						vs[index].Segments = append(vs[index].Segments, segment)
					}
				}

				criterions, err := buildCriterions(pidsPerMajor, status, pm)
				if err != nil {
					return nil, nil, nil, errors.Wrap(err, "build criterions")
				}
				if len(criterions) > 0 {
					cm[major] = append(cm[major], conditionTypes.Condition{
						Criteria: criteriaTypes.Criteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: criterions,
						},
						Tag: segment.Tag,
					})
				}
			}
		}
	}

	ds := make([]detectionTypes.Detection, 0, len(cm))
	for major, conds := range cm {
		ds = append(ds, detectionTypes.Detection{
			Ecosystem:  ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, major)),
			Conditions: conds,
		})
	}

	return []advisoryTypes.Advisory{adv}, vs, ds, nil
}

type productKey struct {
	major           string
	name            string
	version         string
	modularitylabel string
}

type productExtra struct {
	arches       []string
	repositories []string
}

func buildCriterions(pids []csaf.ProductID, status status, pm map[csaf.ProductID][]product) ([]criterionTypes.Criterion, error) {
	// Aggregate architectures by {productKey, repositories} at first
	pkm1 := make(map[productKey][]productExtra)
	for _, pid := range pids {
		for _, p := range pm[pid] {
			pk := productKey{
				major:           p.major,
				name:            p.name,
				version:         p.version,
				modularitylabel: p.modularitylabel,
			}

			slices.Sort(p.repositories)
			index := slices.IndexFunc(pkm1[pk], func(e productExtra) bool {
				return slices.Equal(p.repositories, e.repositories)
			})

			if index == -1 {
				pkm1[pk] = append(pkm1[pk], productExtra{
					arches:       []string{p.arch},
					repositories: p.repositories,
				})
			} else {
				if !slices.Contains(pkm1[pk][index].arches, p.arch) {
					pkm1[pk][index].arches = append(pkm1[pk][index].arches, p.arch)
				}
			}
		}
	}

	// Then, aggregate repositories by {productKey, architectures}
	pkm2 := make(map[productKey][]productExtra)
	for pk, extras := range pkm1 {
		for _, extra := range extras {
			slices.Sort(extra.arches)
			index := slices.IndexFunc(pkm2[pk], func(e productExtra) bool {
				return slices.Equal(extra.arches, e.arches)
			})
			if index == -1 {
				pkm2[pk] = append(pkm2[pk], extra)
			} else {
				for _, repository := range extra.repositories {
					if !slices.Contains(pkm1[pk][index].repositories, repository) {
						pkm2[pk][index].repositories = append(pkm2[pk][index].repositories, repository)
					}
				}
			}
		}
	}

	var cs []criterionTypes.Criterion
	for pk, extras := range pkm2 {
		for _, extra := range extras {
			vc, err := buildVersionCriterion(pk, extra, status)
			if err != nil {
				return nil, errors.Wrap(err, "build version criterion")
			}
			if vc == nil {
				continue
			}

			cs = append(cs, criterionTypes.Criterion{
				Type:    criterionTypes.CriterionTypeVersion,
				Version: vc,
			})
		}
	}

	return cs, nil
}

func buildVersionCriterion(pk productKey, extra productExtra, status status) (*vcTypes.Criterion, error) {
	switch status.ProductStatus {
	case "fixed":
		if pk.name == "" && pk.version == "" {
			return nil, nil
		}

		if slices.Equal(extra.arches, []string{"src"}) {
			return nil, nil
		}

		return &vcTypes.Criterion{
			Vulnerable: true,
			FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
			Package: vcPackageTypes.Package{
				Type: vcPackageTypes.PackageTypeBinary,
				Binary: &vcBinaryPackageTypes.Package{
					Name: func() string {
						if pk.modularitylabel != "" {
							return fmt.Sprintf("%s::%s", pk.modularitylabel, pk.name)
						}
						return pk.name
					}(),
					Architectures: func() []string {
						as := make([]string, 0, len(extra.arches))
						for _, arch := range extra.arches {
							switch arch {
							case "src":
							default:
								as = append(as, arch)
							}
						}
						return as
					}(),
					Repositories: extra.repositories,
				},
			},
			Affected: &affectedTypes.Affected{
				Type:  rangeTypes.RangeTypeRPM,
				Range: []rangeTypes.Range{{LessThan: pk.version}},
				Fixed: []string{pk.version},
			},
		}, nil
	case "affected":
		if pk.name == "" {
			return nil, errors.New("name is empty")
		}

		if !slices.Equal(extra.arches, []string{"src"}) {
			return nil, errors.Errorf("unexpected affected pkg arch. expected: %q, actual: %q", "src", extra.arches)
		}

		return &vcTypes.Criterion{
			Vulnerable: true,
			FixStatus: &fixstatusTypes.FixStatus{
				Class:  fixstatusTypes.ClassUnfixed,
				Vendor: status.AffectedStatus,
			},
			Package: vcPackageTypes.Package{
				Type: vcPackageTypes.PackageTypeSource,
				Source: &vcSourcePackageTypes.Package{
					Name: func() string {
						if pk.modularitylabel != "" {
							return fmt.Sprintf("%s::%s", pk.modularitylabel, pk.name)
						}
						return pk.name
					}(),
					Repositories: extra.repositories,
				},
			},
		}, nil
	case "unaffected":
		return nil, nil
	default:
		return nil, errors.Errorf("unexpected product_status. expected: %q, actual: %q", []string{"fixed", "affected", "unaffected"}, status.ProductStatus)
	}
}

func buildSeverities(sev severity) ([]severityTypes.Severity, error) {
	var ss []severityTypes.Severity
	if sev.Cvss2 != "" {
		v2, err := cvssV2Types.Parse(sev.Cvss2)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss2")
		}
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeCVSSv2,
			Source: "secalert@redhat.com",
			CVSSv2: v2,
		})
	}
	if sev.Cvss3 != "" {
		switch {
		case strings.HasPrefix(sev.Cvss3, "CVSS:3.0"):
			v30, err := cvssV30Types.Parse(sev.Cvss3)
			if err != nil {
				return nil, errors.Wrap(err, "parse cvss3")
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  "secalert@redhat.com",
				CVSSv30: v30,
			})
		case strings.HasPrefix(sev.Cvss3, "CVSS:3.1"):
			v31, err := cvssV31Types.Parse(sev.Cvss3)
			if err != nil {
				return nil, errors.Wrap(err, "parse cvss3")
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  "secalert@redhat.com",
				CVSSv31: v31,
			})
		default:
			return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", sev.Cvss3)
		}
	}
	if sev.Impact != "" {
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "secalert@redhat.com",
			Vendor: &sev.Impact,
		})
	}
	return ss, nil
}

func calculateTag(major string, pids []csaf.ProductID, status status) segmentTypes.DetectionTag {
	maxPid := func() []byte {
		if len(pids) == 0 {
			return nil
		}
		return []byte(slices.Max(pids))
	}()
	h := fnv.New64()
	h.Write(maxPid)
	dst := make([]byte, 18)
	hashed := h.Sum(nil)
	hex.Encode(dst, hashed[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], hashed[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:], hashed[6:])

	return segmentTypes.DetectionTag(fmt.Sprintf("%s-%s-%s-%s", major, status.ProductStatus, status.AffectedStatus, dst))
}
