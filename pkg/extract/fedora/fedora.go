package fedora

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora"
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "fedora"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Fedora & EPEL")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()

		var fetched fedora.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		data, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}
		if data == nil {
			return nil
		}

		splitted, err := util.Split(strings.TrimPrefix(fetched.Updateid, fetched.Release.IDPrefix), "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", fmt.Sprintf("%s-yyyy-.+", fetched.Release.IDPrefix), fetched.Updateid)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", fmt.Sprintf("%s-yyyy-.+", fetched.Release.IDPrefix), fetched.Updateid)
		}

		if err := util.Write(filepath.Join(options.dir, "data", fetched.Release.Name, splitted[0], fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fetched.Release.Name, splitted[0], fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Fedora,
		Name: func() *string { t := "Fedora Update System"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
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

func extract(fetched fedora.Advisory, raws []string) (*dataTypes.Data, error) {
	switch ct := func() string {
		if fetched.ContentType == nil {
			switch fetched.Release.IDPrefix {
			case "FEDORA", "FEDORA-EPEL", "FEDORA-EPEL-NEXT":
				return "rpm"
			case "FEDORA-MODULAR", "FEDORA-EPEL-MODULAR", "FEDORA-EPEL-NEXT-MODULAR":
				return "module"
			case "FEDORA-FLATPAK":
				return "flatpak"
			case "FEDORA-CONTAINER":
				return "container"
			default:
				return fetched.Release.IDPrefix
			}
		}
		return *fetched.ContentType
	}(); ct {
	case "rpm", "module":
		eco, err := func() (ecosystemTypes.Ecosystem, error) {
			switch fetched.Release.IDPrefix {
			case "FEDORA", "FEDORA-MODULAR":
				return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeFedora, fetched.Release.Version)), nil
			case "FEDORA-EPEL", "FEDORA-EPEL-MODULAR":
				return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeEPEL, strings.Split(fetched.Release.Version, ".")[0])), nil
			case "FEDORA-EPEL-NEXT", "FEDORA-EPEL-NEXT-MODULAR":
				return ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeEPELNext, strings.Split(fetched.Release.Version, ".")[0])), nil
			default:
				return ecosystemTypes.Ecosystem(""), errors.Errorf("unexpected release.id_prefix. expected: %q, actual: %q", []string{"FEDORA", "FEDORA-EPEL", "FEDORA-EPEL-NEXT", "FEDORA-MODULAR", "FEDORA-EPEL-MODULAR", "FEDORA-EPEL-NEXT-MODULAR"}, fetched.Release.IDPrefix)
			}
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "get ecosystem")
		}

		d, err := func() (detectionTypes.Detection, error) {
			var cs []criterion.Criterion
			for _, build := range fetched.Builds {
				switch build.Type {
				case "rpm":
					nevram := make(map[string]map[string][]string)
					for _, ps := range build.Package {
						for _, p := range ps {
							if nevram[p.Name] == nil {
								nevram[p.Name] = make(map[string][]string)
							}
							evr := fmt.Sprintf("%d:%s-%s", func() int {
								if p.Epoch == nil {
									return 0
								}
								return *p.Epoch
							}(), p.Version, p.Release)
							nevram[p.Name][evr] = append(nevram[p.Name][evr], p.Arch)
						}
					}

					for n, evram := range nevram {
						for evr, as := range evram {
							cs = append(cs, criterion.Criterion{
								Type: criterion.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          n,
											Architectures: util.Unique(as),
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type:  vcAffectedRangeTypes.RangeTypeRPM,
										Range: []vcAffectedRangeTypes.Range{{LessThan: evr}},
										Fixed: []string{evr},
									},
								},
							})
						}
					}
				case "module":
					if build.Module == nil || build.Module.Name == "" || build.Module.Stream == "" {
						return detectionTypes.Detection{}, errors.New("module info is incomplete")
					}

					nevram := make(map[string]map[string][]string)
					for _, ps := range build.Package {
						for _, p := range ps {
							n := fmt.Sprintf("%s:%s::%s", build.Module.Name, build.Module.Stream, p.Name)
							if nevram[n] == nil {
								nevram[n] = make(map[string][]string)
							}
							evr := fmt.Sprintf("%d:%s-%s", func() int {
								if p.Epoch == nil {
									return 0
								}
								return *p.Epoch
							}(), p.Version, p.Release)
							nevram[n][evr] = append(nevram[n][evr], p.Arch)
						}
					}

					for n, evram := range nevram {
						for evr, as := range evram {
							cs = append(cs, criterion.Criterion{
								Type: criterion.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          n,
											Architectures: util.Unique(as),
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type:  vcAffectedRangeTypes.RangeTypeRPM,
										Range: []vcAffectedRangeTypes.Range{{LessThan: evr}},
										Fixed: []string{evr},
									},
								},
							})
						}
					}
				case "flatpak", "container":
				default:
					return detectionTypes.Detection{}, errors.Errorf("unexpected build type. expected: %q, actual: %q", []string{"rpm", "module", "flatpak", "container"}, build.Type)
				}
			}
			return detectionTypes.Detection{
				Ecosystem: eco,
				Conditions: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: cs,
					},
				}},
			}, nil
		}()
		if err != nil {
			return nil, errors.Wrapf(err, "get detections")
		}

		return &dataTypes.Data{
			ID: dataTypes.RootID(fetched.Updateid),
			Advisories: []advisoryTypes.Advisory{{
				Content: advisoryContentTypes.Content{
					ID:          advisoryContentTypes.AdvisoryID(fetched.Updateid),
					Title:       fetched.Title,
					Description: fetched.Notes,
					Severity: []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "fedoraproject.org",
						Vendor: func() *string { return &fetched.Severity }(),
					}},
					References: []referenceTypes.Reference{{
						Source: "fedoraproject.org",
						URL:    fetched.URL,
					}},
					Published: utiltime.Parse([]string{"2006-01-02 15:04:05"}, fetched.DateSubmitted),
					Modified: func() *time.Time {
						if fetched.DateModified == nil {
							return nil
						}
						return utiltime.Parse([]string{"2006-01-02 15:04:05"}, *fetched.DateModified)
					}(),
				},
				Segments: []segmentTypes.Segment{{Ecosystem: eco}},
			}},
			Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
				var vs []vulnerabilityTypes.Vulnerability
				for _, bug := range fetched.Bugs {
					var f func(b fedora.Bugzilla) []fedora.Bugzilla
					f = func(b fedora.Bugzilla) []fedora.Bugzilla {
						var bugs []fedora.Bugzilla
						for _, b := range b.Blocked {
							bugs = append(bugs, f(b)...)
						}
						if strings.HasPrefix(b.Alias, "CVE-") {
							bugs = append(bugs, b)
						}
						return bugs
					}

					for _, b := range f(bug.Bugzilla) {
						vs = append(vs, vulnerabilityTypes.Vulnerability{
							Content: vulnerabilityContentTypes.Content{
								ID:    vulnerabilityContentTypes.VulnerabilityID(b.Alias),
								Title: b.ShortDesc,
								Severity: []severityTypes.Severity{{
									Type:   severityTypes.SeverityTypeVendor,
									Source: "fedoraproject.org",
									Vendor: func() *string { return &b.BugSeverity }(),
								}},
								References: []referenceTypes.Reference{{
									Source: "fedoraproject.org",
									URL:    fmt.Sprintf("https://bugzilla.redhat.com/show_bug.cgi?id=%s", b.BugID),
								}},
								Published: utiltime.Parse([]string{"2006-01-02 15:04:05 -0700"}, b.CreationTs),
								Modified:  utiltime.Parse([]string{"2006-01-02 15:04:05 -0700"}, b.DeltaTs),
							},
							Segments: []segmentTypes.Segment{{Ecosystem: eco}},
						})
					}
				}
				return vs
			}(),
			Detections: []detectionTypes.Detection{d},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.Fedora,
				Raws: raws,
			},
		}, nil
	case "flatpak", "container":
		return nil, nil
	default:
		return nil, errors.Errorf("unexpected content_type. expected: %q, actual: %q", []string{"rpm", "module", "flatpak", "container"}, ct)
	}

}
