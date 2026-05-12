package v2

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
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
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
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
	v2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/vex/v2"
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
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "vex", "v2"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract RedHat VEX")

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

		var vuln v2.VEX
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
		ID:   sourceTypes.RedHatVEXv2,
		Name: new("RedHat Enterprise Linux CSAF VEX"),
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

func (e extractor) extract(vuln v2.VEX, c2r map[string][]string) (dataTypes.Data, error) {
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
			ID:   sourceTypes.RedHatVEXv2,
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

type assessment struct {
	// advisories holds every vendor_fix erratum reported for this product.
	// VEX-GA can reference the same fixed pid from multiple RHSAs (e.g. a
	// re-issued advisory or sibling errata for variant streams) — see
	// CVE-2007-6015 / CVE-2023-48022 for examples.
	// Kept sorted-and-deduplicated so two assessments that differ only in
	// insertion order produce the same key.
	advisories []advisory
	severity   severity
	status     status
	mitigation string
	workaround string
}

type advisory struct {
	id   string
	date string
}

// assessmentKey is the comparable summary of an assessment, suitable for use
// as a map key. Only the advisories slice needs encoding; every other field
// is already a comparable value type.
type assessmentKey struct {
	advisoriesKey string
	severity      severity
	status        status
	mitigation    string
	workaround    string
}

func (a assessment) key() assessmentKey {
	var sb strings.Builder
	for i, x := range a.advisories {
		if i > 0 {
			sb.WriteByte('\x01')
		}
		sb.WriteString(x.id)
		sb.WriteByte('\x00')
		sb.WriteString(x.date)
	}
	return assessmentKey{
		advisoriesKey: sb.String(),
		severity:      a.severity,
		status:        a.status,
		mitigation:    a.mitigation,
		workaround:    a.workaround,
	}
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

// walkProductTree converts a CSAF VEX product_tree into a map of product_id ->
// product, ready for buildDataComponents to consume.
//
// The walker recurses through the branch tree as the CSAF spec requires (branches
// can in principle nest to any depth). For VEX-GA the tree is in practice flat
//
//	vendor
//	 ├── product_name      (CPE, e.g. cpe:/a:redhat:enterprise_linux:9::appstream)
//	 ├── product_version   (PURL, e.g. pkg:rpm/redhat/foo@1.2-3.el9?epoch=0)
//	 └── ...
//	relationships: default_component_of joins product_name (env) and product_version (pkg)
//
// but intermediate vendor / product_family / architecture nodes are treated as
// transparent containers so the walker stays spec-conformant if Red Hat reintroduces
// grouping later. See
// https://redhatproductsecurity.github.io/security-data-guidelines/vex-ga-details/
func walkProductTree(trackingID string, pt v2.ProductTree, c2r map[string][]string) (map[v2.ProductID][]product, error) {
	type nameInfo struct {
		cpe   string
		major string
	}
	type versionInfo struct {
		name            string
		version         string
		arch            string
		modularitylabel string
	}

	names := make(map[v2.ProductID]nameInfo)
	versions := make(map[v2.ProductID]versionInfo)

	var walk func(branch v2.Branch) error
	walk = func(branch v2.Branch) error {
		switch branch.Category {
		case "vendor", "product_family", "architecture":
			// transparent container; nothing to collect here
		case "product_name", "product_version":
			if branch.Product == nil {
				return errors.Errorf("branch product is nil. tracking_id: %q, category: %q", trackingID, branch.Category)
			}
			pih := branch.Product.ProductIdentificationHelper
			if pih != nil {
				if pih.Hashes != nil || pih.ModuleNumbers != nil || pih.SBOMURLs != nil || pih.SerialNumbers != nil || pih.SKUs != nil || pih.XGenericURIs != nil {
					return errors.Errorf("unexpected product identification helper method. tracking_id: %q, product_id: %q", trackingID, branch.Product.ProductID)
				}
				switch branch.Category {
				case "product_name":
					if pih.CPE != "" {
						names[branch.Product.ProductID] = nameInfo{
							cpe:   pih.CPE,
							major: majorFromCPE(pih.CPE),
						}
					}
				case "product_version":
					if pih.PURL != "" {
						v, err := parseRPMPurl(pih.PURL)
						if err != nil {
							return errors.Wrapf(err, "parse purl. tracking_id: %q, product_id: %q", trackingID, branch.Product.ProductID)
						}
						if v != nil {
							versions[branch.Product.ProductID] = *v
						}
					}
				}
			}
		default:
			return errors.Errorf("unexpected branch category. tracking_id: %q, expected: %q, actual: %q", trackingID, []string{"vendor", "product_family", "architecture", "product_name", "product_version"}, branch.Category)
		}
		for _, child := range branch.Branches {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, root := range pt.Branches {
		if err := walk(root); err != nil {
			return nil, errors.Wrap(err, "walk product_tree")
		}
	}

	pm := make(map[v2.ProductID][]product)
	for _, rel := range pt.Relationships {
		if rel.Category != "default_component_of" {
			return nil, errors.Errorf("unexpected relationship category. tracking_id: %q, expected: %q, actual: %q", trackingID, "default_component_of", rel.Category)
		}
		ni, ok := names[rel.RelatesToProductReference]
		if !ok || ni.major == "" {
			continue
		}
		vi, ok := versions[rel.ProductReference]
		if !ok {
			continue
		}
		pm[rel.FullProductName.ProductID] = append(pm[rel.FullProductName.ProductID], product{
			major:           ni.major,
			name:            vi.name,
			version:         vi.version,
			arch:            vi.arch,
			modularitylabel: vi.modularitylabel,
			cpe:             ni.cpe,
			repositories:    c2r[ni.cpe],
		})
	}
	return pm, nil
}

// parseRPMPurl decodes a Red Hat RPM PURL. The VEX-GA canonical form is
//
//	pkg:rpm/redhat/<name>[@<version>]?[arch=src&][epoch=<n>][&rpmmod=<module>:<stream>[:<version>:<context>]]
//
// Binary RPMs omit the arch qualifier entirely (only sources carry arch=src).
// Returns (nil, nil) for non-RPM PURLs (oci, maven, generic, koji, npm) which
// the VEX feed exposes but the RPM-based extractor does not handle.
func parseRPMPurl(s string) (*struct {
	name, version, arch, modularitylabel string
}, error) {
	if !strings.HasPrefix(s, "pkg:rpm/") {
		// Skip every non-RPM PURL type observed in the VEX-GA feed. A
		// brand-new type errors out so a human decides whether the new
		// artifact class should be processed or just added to this skip
		// list — silent data loss is worse than a loud failure.
		for _, prefix := range []string{
			"pkg:cargo/", "pkg:gem/", "pkg:generic/", "pkg:golang/",
			"pkg:maven/", "pkg:npm/", "pkg:oci/", "pkg:pypi/",
		} {
			if strings.HasPrefix(s, prefix) {
				return nil, nil
			}
		}
		return nil, errors.Errorf("unexpected purl prefix: %q", s)
	}
	instance, err := packageurl.FromString(s)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %q", s)
	}
	quals := instance.Qualifiers.Map()
	// repository_id (src RPMs only, info also reachable via CPE→repository2cpe)
	// and distro (observed only on non-RHEL "Hummingbird" products that are
	// filtered out downstream) are intentionally parsed-but-ignored. A
	// brand-new key errors out so a human decides whether the new metadata
	// should be processed — silent data loss is worse than a loud failure.
	for k := range quals {
		switch k {
		case "arch", "epoch", "rpmmod", "repository_id", "distro":
		default:
			return nil, errors.Errorf("unexpected purl qualifier %q in %q", k, s)
		}
	}
	out := &struct{ name, version, arch, modularitylabel string }{
		name: instance.Name,
		arch: quals["arch"],
	}
	if instance.Version != "" {
		epoch, ok := quals["epoch"]
		if !ok {
			epoch = "0"
		}
		out.version = fmt.Sprintf("%s:%s", epoch, instance.Version)
	}
	if rpmmod := quals["rpmmod"]; rpmmod != "" {
		parts := strings.Split(rpmmod, ":")
		if len(parts) < 2 {
			return nil, errors.Errorf("unexpected rpmmod format. expected: %q, actual: %q", "<module>:<stream>[:<version>:<context>]", rpmmod)
		}
		out.modularitylabel = fmt.Sprintf("%s:%s", parts[0], parts[1])
	}
	return out, nil
}

// majorFromCPE returns the RHEL major version implied by a VEX-GA CPE, or "" when
// the CPE is not RHEL-related. The channel suffix `::el<N>` takes priority over the
// product version (so e.g. cpe:/a:redhat:rhel_dotnet:6.0::el7 → "7", not "6").
func majorFromCPE(cpe string) string {
	for _, n := range []string{"10", "9", "8", "7", "6", "5", "4", "3"} {
		if strings.HasSuffix(cpe, "::el"+n) {
			return n
		}
	}
	const op, ap = "cpe:/o:redhat:", "cpe:/a:redhat:"
	var rest string
	switch {
	case strings.HasPrefix(cpe, op):
		rest = cpe[len(op):]
	case strings.HasPrefix(cpe, ap):
		rest = cpe[len(ap):]
	default:
		return ""
	}
	product, version, ok := strings.Cut(rest, ":")
	if !ok || !isRHELProduct(product) {
		return ""
	}
	if idx := strings.Index(version, "::"); idx >= 0 {
		version = version[:idx]
	}
	if version == "" {
		return ""
	}
	// RHEL 2.1 is the only release with a non-integer major version.
	if product == "enterprise_linux" && strings.HasPrefix(version, "2.1") {
		return "2.1"
	}
	major, _, _ := strings.Cut(version, ".")
	for _, r := range major {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if major == "" {
		return ""
	}
	return major
}

func isRHELProduct(p string) bool {
	switch p {
	case "enterprise_linux", "enterprise_linux_eus",
		"rhel_eus", "rhel_aus", "rhel_els", "rhel_e4s", "rhel_tus",
		"rhel_extras", "rhel_extras_oracle_java", "rhel_extras_sap", "rhel_extras_rt", "rhel_extras_sap_hana",
		"rhel_software_collections",
		"rhel_atomic",
		"rhel_dotnet", "rhel_dotnet_eus",
		"rhel_cluster", "rhel_cluster_storage",
		"rhel_mission_critical":
		return true
	}
	return false
}

func walkVulnerabilities(vulns []v2.Vulnerability, pids []v2.ProductID) (map[v2.ProductID]assessment, vulnerabilityContentTypes.Content, error) {
	if len(vulns) != 1 {
		return nil, vulnerabilityContentTypes.Content{}, errors.Errorf("unexpected vulnerabilities length. expected: %d, actual: %d", 1, len(vulns))
	}

	assm := make(map[v2.ProductID]assessment)

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
			for _, p := range func() []v2.ProductID {
				if len(f.ProductIDs) > 0 {
					return f.ProductIDs
				}
				return pids
			}() {

				switch base := assm[p]; base.status.product_status {
				case "unaffected":
					if base.status.affected_status != "" {
						return errors.Errorf("already set affected_status. cve: %s, product_id: %s", vulns[0].CVE, p)
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
			for _, p := range func() []v2.ProductID {
				if len(r.ProductIDs) > 0 {
					return r.ProductIDs
				}
				return pids
			}() {
				switch r.Category {
				case "mitigation":
					base := assm[p]
					if base.mitigation != "" {
						return errors.Errorf("already set mitigation. cve: %s, product_id: %s", vulns[0].CVE, p)
					}
					base.mitigation = r.Details
					assm[p] = base
				case "workaround":
					base := assm[p]
					if base.workaround != "" {
						return errors.Errorf("already set workaround. cve: %s, product_id: %s", vulns[0].CVE, p)
					}
					base.workaround = r.Details
					assm[p] = base
				case "no_fix_planned", "none_available":
					base := assm[p]
					if base.status.affected_status != "" {
						return errors.Errorf("already set affected_status. cve: %s, product_id: %s", vulns[0].CVE, p)
					}
					base.status.affected_status = r.Details
					assm[p] = base
				case "vendor_fix":
					base := assm[p]
					ad := advisory{
						id:   strings.TrimPrefix(r.URL, "https://access.redhat.com/errata/"),
						date: r.Date,
					}
					// Skip exact duplicates; otherwise insert in sorted order
					// (by id, then date) so the assessment key is stable
					// regardless of remediation declaration order.
					if i, ok := slices.BinarySearchFunc(base.advisories, ad, compareAdvisory); !ok {
						base.advisories = slices.Insert(base.advisories, i, ad)
						assm[p] = base
					}
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
			for _, p := range func() []v2.ProductID {
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
			if i := slices.IndexFunc(vulns[0].Notes, func(e v2.Note) bool {
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
	maxPid v2.ProductID
	// assessment retained so emission can recover the full assessment
	// (including the advisories slice that the assessmentKey collapses
	// into an opaque string).
	assessment assessment
	p2sm       map[string][]product2 // key: product2.cpe
}

func compareAdvisory(a, b advisory) int {
	if c := cmp.Compare(a.id, b.id); c != 0 {
		return c
	}
	return cmp.Compare(a.date, b.date)
}

func buildDataComponents(doc v2.Document, baseVulnerability vulnerabilityContentTypes.Content, pm map[v2.ProductID][]product, assm map[v2.ProductID]assessment) ([]advisoryTypes.Advisory, []vulnerabilityTypes.Vulnerability, []detectionTypes.Detection, error) {
	baseVulnerability.Published = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.InitialReleaseDate)
	baseVulnerability.Modified = utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, doc.Tracking.CurrentReleaseDate)
	for pid, assessment := range assm {
		if assessment.severity.impact == "" && doc.AggregateSeverity != nil {
			assessment.severity.impact = doc.AggregateSeverity.Text
			assm[pid] = assessment
		}
	}

	// major -> assessmentKey -> productsWithMaxPid (full assessment carried inside).
	apmm := make(map[string]map[assessmentKey]productsWithMaxPid)
	for pid, ps := range pm {
		for _, p := range ps {
			if p.name == "" {
				return nil, nil, nil, errors.Errorf("empty package name for pid. cve: %s, product_id: %s", baseVulnerability.ID, pid)
			}

			apm, found := apmm[p.major]
			if !found {
				apm = map[assessmentKey]productsWithMaxPid{}
			}
			assessment, found := assm[pid]
			if !found {
				return nil, nil, nil, errors.Errorf("no product_status entry for pid that appears in product_tree. cve: %s, product_id: %s", baseVulnerability.ID, pid)
			}

			key := assessment.key()
			pmax, found := apm[key]
			if !found {
				pmax = productsWithMaxPid{
					maxPid:     pid,
					assessment: assessment,
					p2sm: map[string][]product2{
						p.cpe: {{
							name:            p.name,
							version:         p.version,
							modularitylabel: p.modularitylabel,
							cpe:             p.cpe,
							archs:           []string{p.arch},
							repositories:    p.repositories,
						}},
					},
				}
			} else {
				pmax.maxPid = v2.ProductID(slices.Max([]string{string(pmax.maxPid), string(pid)}))
				switch i := slices.IndexFunc(pmax.p2sm[p.cpe], func(p2 product2) bool {
					return p2.name == p.name && p2.version == p.version && p2.modularitylabel == p.modularitylabel
				}); i {
				case -1:
					pmax.p2sm[p.cpe] = append(pmax.p2sm[p.cpe], product2{
						name:            p.name,
						version:         p.version,
						modularitylabel: p.modularitylabel,
						cpe:             p.cpe,
						archs:           []string{p.arch},
						repositories:    p.repositories,
					})
				default:
					if !slices.Contains(pmax.p2sm[p.cpe][i].archs, p.arch) {
						pmax.p2sm[p.cpe][i].archs = append(pmax.p2sm[p.cpe][i].archs, p.arch)
					}
				}
			}
			apm[key] = pmax
			apmm[p.major] = apm
		}
	}

	var ds []detectionTypes.Detection
	var vs []vulnerabilityTypes.Vulnerability
	var as []advisoryTypes.Advisory

	for major, apm := range apmm {
		var conds []conditionTypes.Condition
		es := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, major))
		for _, pmax := range apm {
			assessment := pmax.assessment
			tag := calculateTag(pmax)
			ss := []segmentTypes.Segment{{
				Ecosystem: es,
				Tag:       tag,
			}}
			ca := criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
			}

			for _, p2s := range pmax.p2sm {
				subCa := criteriaTypes.Criteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: p2s[0].repositories,
				}

				for _, p2 := range p2s {
					vcs, err := buildVersionCriterion(p2, assessment)
					if err != nil {
						return nil, nil, nil, errors.Wrap(err, "build version criterion")
					}
					for _, vc := range vcs {
						subCa.Criterions = append(subCa.Criterions, criterionTypes.Criterion{
							Type:    criterionTypes.CriterionTypeVersion,
							Version: &vc,
						})
					}
				}
				if len(subCa.Criterions) > 0 {
					ca.Criterias = append(ca.Criterias, subCa)
				}
			}
			if len(ca.Criterias) > 0 {
				conds = append(conds, conditionTypes.Condition{
					Criteria: ca,
					Tag:      tag,
				})
			}

			v, err := buildVulnerability(baseVulnerability, assessment)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "build vulnerability")
			}
			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content:  v,
				Segments: ss,
			})

			// One Advisory entry per RHSA; same segments shared across them
			// because they all attest to the same (env, pkg) fix combination.
			for _, content := range buildAdvisories(assessment) {
				as = append(as, advisoryTypes.Advisory{
					Content: content,
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

func buildVersionCriterion(p2 product2, assessment assessment) ([]vcTypes.Criterion, error) {
	switch assessment.status.product_status {
	case "fixed":
		if p2.name == "" && p2.version == "" {
			return nil, nil
		}

		vcs := make([]vcTypes.Criterion, 0, 1)

		// VEX-GA binary RPM PURLs do not carry an arch qualifier, so archs
		// may contain "". Treat that as "applies to all archs" (nil).
		if slices.ContainsFunc(p2.archs, func(x string) bool { return x != "src" }) {
			as := slices.DeleteFunc(slices.Clone(p2.archs), func(x string) bool { return x == "src" || x == "" })
			if len(as) == 0 {
				as = nil
			}
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
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{LessThan: p2.version}},
					Fixed: []string{p2.version},
				},
			})
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
					Vendor: assessment.status.affected_status,
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
					},
				},
			})
		}

		if slices.Contains(p2.archs, "src") {
			vcs = append(vcs, vcTypes.Criterion{
				Vulnerable: true,
				FixStatus: &fixstatusTypes.FixStatus{
					Class:  fixstatusTypes.ClassUnfixed,
					Vendor: assessment.status.affected_status,
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
					},
				},
			})
		}

		return vcs, nil
	case "unaffected":
		return nil, nil
	default:
		return nil, errors.Errorf("unexpected product_status. expected: %q, actual: %q", []string{"fixed", "affected", "unaffected"}, assessment.status.product_status)
	}

}

func buildVulnerability(baseVulnerability vulnerabilityContentTypes.Content, assessment assessment) (vulnerabilityContentTypes.Content, error) {
	ss, err := func() ([]severityTypes.Severity, error) {
		var ss []severityTypes.Severity
		if assessment.severity.cvss2 != "" {
			v2, err := cvssV2Types.Parse(assessment.severity.cvss2)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss2")
			}
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: "secalert@redhat.com",
				CVSSv2: v2,
			})
		}
		if assessment.severity.cvss3 != "" {
			switch {
			case strings.HasPrefix(assessment.severity.cvss3, "CVSS:3.0"):
				v30, err := cvssV30Types.Parse(assessment.severity.cvss3)
				if err != nil {
					return nil, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv30,
					Source:  "secalert@redhat.com",
					CVSSv30: v30,
				})
			case strings.HasPrefix(assessment.severity.cvss3, "CVSS:3.1"):
				v31, err := cvssV31Types.Parse(assessment.severity.cvss3)
				if err != nil {
					return nil, errors.Wrap(err, "parse cvss3")
				}
				ss = append(ss, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv31,
					Source:  "secalert@redhat.com",
					CVSSv31: v31,
				})
			default:
				return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", assessment.severity.cvss3)
			}
		}
		if assessment.severity.impact != "" {
			ss = append(ss, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeVendor,
				Source: "secalert@redhat.com",
				Vendor: &assessment.severity.impact,
			})
		}
		return ss, nil
	}()
	if err != nil {
		return vulnerabilityContentTypes.Content{}, errors.Wrap(err, "walk severity")
	}
	baseVulnerability.Severity = ss
	if assessment.mitigation != "" {
		baseVulnerability.Mitigations = []remediationTypes.Remediation{{
			Source:      "secalert@redhat.com",
			Description: assessment.mitigation,
		}}
	}
	if assessment.workaround != "" {
		baseVulnerability.Workarounds = []remediationTypes.Remediation{{
			Source:      "secalert@redhat.com",
			Description: assessment.workaround,
		}}
	}
	return baseVulnerability, nil
}

func buildAdvisories(assessment assessment) []advisoryContentTypes.Content {
	out := make([]advisoryContentTypes.Content, 0, len(assessment.advisories))
	for _, ad := range assessment.advisories {
		out = append(out, advisoryContentTypes.Content{
			ID: advisoryContentTypes.AdvisoryID(ad.id),
			References: []referenceTypes.Reference{{
				Source: "secalert@redhat.com",
				URL:    fmt.Sprintf("https://access.redhat.com/errata/%s", ad.id),
			}},
			Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, ad.date),
		})
	}
	return out
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
