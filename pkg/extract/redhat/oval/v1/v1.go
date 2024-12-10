package v1

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	vecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
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
	v1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v1"
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
	ovalDir string
	r       *utiljson.JSONReader
}

func Extract(ovalDir, repository2cpeDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "oval", "v1"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract RedHat OVAL v1")

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

	entries, err := os.ReadDir(ovalDir)
	if err != nil {
		return errors.Wrapf(err, "read %s", ovalDir)
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := filepath.WalkDir(filepath.Join(ovalDir, entry.Name(), "definitions"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			e := extractor{
				ovalDir: ovalDir,
				r:       br.Copy(),
			}

			var def v1.Definition
			if err := e.r.Read(path, e.ovalDir, &def); err != nil {
				return errors.Wrapf(err, "read %s", path)
			}

			extracted, err := e.extract(entry.Name(), def, cpe2repository)
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
			}

			ss, err := util.Split(string(extracted.ID), "-", ":")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(RHSA|RHBA|RHEA)-<year>:<ID>", extracted.ID)
			}

			if _, err := os.Stat(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID))); err == nil {
				f, err := os.Open(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
				}
				defer f.Close()

				var base dataTypes.Data
				if err := json.NewDecoder(f).Decode(&base); err != nil {
					return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
				}

				extracted.Merge(base)
			}

			if err := util.Write(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(ovalDir, entry.Name(), "definitions"))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RedHatOVALv1,
		Name: func() *string { t := "RedHat Enterprise Linux OVALv1"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			var rs []repositoryTypes.Repository
			r1, _ := utilgit.GetDataSourceRepository(ovalDir)
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

func (e extractor) extract(name string, def v1.Definition, c2r map[string][]string) (dataTypes.Data, error) {
	id, err := func() (string, error) {
		lhs, rhs, ok := strings.Cut(strings.TrimPrefix(def.ID, "oval:com.redhat."), ":def:")
		if !ok {
			return "", errors.Errorf("unexpected definition id format. expected: %q, actual: %q", "oval:com.redhat.(rhsa|rhba|rhea):def:<id>", def.ID)
		}

		switch lhs {
		case "rhsa", "rhba", "rhea":
			if len(rhs) < 8 {
				return "", errors.Errorf("unexpected definition id format. expected: %q, actual: %q", "oval:com.redhat.(rhsa|rhba|rhea):def:<year><id>", def.ID)
			}
			if _, err := time.Parse("2006", rhs[:4]); err != nil {
				return "", errors.Errorf("unexpected definition id format. expected: %q, actual: %q", "oval:com.redhat.(rhsa|rhba|rhea):def:<year><id>", def.ID)
			}
			return fmt.Sprintf("%s-%s:%s", strings.ToUpper(lhs), rhs[:4], rhs[4:]), nil
		default:
			return "", errors.Errorf("unexpected definition id format. expected: %q, actual: %q", "oval:com.redhat.(rhsa|rhba|rhea):def:<id>", def.ID)
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "parse definition id")
	}

	var rs []string
	for _, cpe := range def.Metadata.Advisory.AffectedCpeList.Cpe {
		rs = append(rs, c2r[cpe]...)
	}

	ds, err := e.collectPackages(name, def.Criteria, rs)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "collect packages")
	}

	segs := func() []segmentTypes.Segment {
		var ss []segmentTypes.Segment
		for _, d := range ds {
			for _, c := range d.Conditions {
				ss = append(ss, segmentTypes.Segment{
					Ecosystem: d.Ecosystem,
					Tag:       c.Tag,
				})
			}
		}
		return ss
	}()

	vs, err := func() ([]vulnerabilityTypes.Vulnerability, error) {
		m := make(map[string]vulnerabilityContentTypes.Content)
		for _, cve := range def.Metadata.Advisory.Cve {
			ss, err := func() ([]severityTypes.Severity, error) {
				var ss []severityTypes.Severity
				if cve.Impact != "" {
					ss = append(ss, severityTypes.Severity{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "secalert@redhat.com",
						Vendor: &cve.Impact,
					})
				}
				if cve.Cvss2 != "" {
					_, rhs, _ := strings.Cut(cve.Cvss2, "/")
					// 5-ELS/definitions/oval:com.redhat.rhsa:def:20091201.json AV:N/AC:M/Au:N/C:P/I:N/A:N/ -> AV:N/AC:M/Au:N/C:P/I:N/A:N
					// 5-ELS/definitions/oval:com.redhat.rhba:def:20090070.json AV:N/AC:H/AU:N/C:N/I:P/A:N  -> AV:N/AC:H/Au:N/C:N/I:P/A:N
					// 5-ELS/definitions/oval:com.redhat.rhsa:def:20090474.json AV:L/AC:L/AU:N/C:N/I:N/A:P  -> AV:L/AC:L/Au:N/C:N/I:N/A:P
					// 5-ELS/definitions/oval:com.redhat.rhsa:def:20090479.json AV:N/AC:M/AU:N/C:N/I:N/A:P  -> AV:N/AC:M/Au:N/C:N/I:N/A:P
					// 5-ELS/definitions/oval:com.redhat.rhsa:def:20091036.json AV:N/AC:L/AU:N/C:N/I:N/A:P  -> AV:N/AC:L/Au:N/C:N/I:N/A:P
					v2, err := cvssV2Types.Parse(strings.ReplaceAll(strings.TrimSuffix(rhs, "/"), "AU:", "Au:"))
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss2")
					}
					ss = append(ss, severityTypes.Severity{
						Type:   severityTypes.SeverityTypeCVSSv2,
						Source: "secalert@redhat.com",
						CVSSv2: v2,
					})
				}
				if cve.Cvss3 != "" {
					_, rhs, _ := strings.Cut(cve.Cvss3, "/")
					switch {
					case strings.HasPrefix(rhs, "CVSS:3.0"):
						v30, err := cvssV30Types.Parse(rhs)
						if err != nil {
							return nil, errors.Wrap(err, "parse cvss3")
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv30,
							Source:  "secalert@redhat.com",
							CVSSv30: v30,
						})
					case strings.HasPrefix(rhs, "CVSS:3.1"):
						v31, err := cvssV31Types.Parse(rhs)
						if err != nil {
							return nil, errors.Wrap(err, "parse cvss3")
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv31,
							Source:  "secalert@redhat.com",
							CVSSv31: v31,
						})
					default:
						return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.Cvss3)
					}
				}
				return ss, nil
			}()
			if err != nil {
				return nil, errors.Wrap(err, "walk severity")
			}

			m[cve.Text] = vulnerabilityContentTypes.Content{
				ID:       vulnerabilityContentTypes.VulnerabilityID(cve.Text),
				Severity: ss,
				CWE: func() []cweTypes.CWE {
					if cve.Cwe == "" {
						return nil
					}
					return []cweTypes.CWE{{
						Source: "secalert@redhat.com",
						CWE:    []string{cve.Cwe},
					}}
				}(),
				References: []referenceTypes.Reference{{
					Source: "secalert@redhat.com",
					URL:    cve.Href,
				}},
				Published: utiltime.Parse([]string{"20060102"}, cve.Public),
			}
		}

		for _, b := range def.Metadata.Advisory.Bugzilla {
			lhs, _, _ := strings.Cut(b.Text, " ")
			if content, ok := m[lhs]; ok {
				content.References = append(content.References, referenceTypes.Reference{
					Source: "secalert@redhat.com",
					URL:    b.Href,
				})
				m[lhs] = content
			}
		}

		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(m))
		for _, content := range m {
			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content:  content,
				Segments: segs,
			})
		}
		return vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk vulnerability")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(id),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(id),
				Title:       strings.TrimSpace(def.Metadata.Title),
				Description: strings.TrimSpace(def.Metadata.Description),
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "secalert@redhat.com",
					Vendor: &def.Metadata.Advisory.Severity}},
				References: func() []referenceTypes.Reference {
					refs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference)+len(def.Metadata.Advisory.Bugzilla))
					for _, r := range def.Metadata.Reference {
						refs = append(refs, referenceTypes.Reference{
							Source: "secalert@redhat.com",
							URL:    r.RefURL,
						})
					}
					for _, b := range def.Metadata.Advisory.Bugzilla {
						refs = append(refs, referenceTypes.Reference{
							Source: "secalert@redhat.com",
							URL:    b.Href,
						})
					}
					return refs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
				Modified:  utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Updated.Date),
			},
			Segments: segs,
		}},
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.RedHatOVALv1,
			Raws: e.r.Paths(),
		},
	}, nil
}

func (e extractor) collectPackages(name string, criteria v1.Criteria, affectedRepositories []string) ([]detectionTypes.Detection, error) {
	m, err := e.prewalkCriteria(make(map[string]v1.Criteria), name, criteria, criteria)
	if err != nil {
		return nil, errors.Wrap(err, "prewalk criteria")
	}

	ds := make([]detectionTypes.Detection, 0, len(m))
	for major, rootCa := range m {
		ca, err := e.walkCriteria(name, rootCa, affectedRepositories)
		if err != nil {
			return nil, errors.Wrap(err, "walk criteria")
		}
		ds = append(ds, detectionTypes.Detection{
			Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRedHat, major)),
			Conditions: []conditionTypes.Condition{{
				Criteria: e.postWalkCriteria(ca),
				Tag:      segmentTypes.DetectionTag(name),
			}},
		})
	}
	return ds, nil
}

func (e extractor) prewalkCriteria(m map[string]v1.Criteria, name string, parent, criteria v1.Criteria) (map[string]v1.Criteria, error) {
	v, err := e.prewalkCriterion(name, criteria.Criterions)
	if err != nil {
		return nil, errors.Wrap(err, "prewalk criterion")
	}
	if v != "" {
		switch {
		case criteria.Operator == "AND" && parent.Operator == "OR":
			// e.g. 1
			// "criteria": {
			//     "operator": "OR",
			//     "criterias": [
			//         {
			//             "operator": "AND",
			//             "criterions": [
			//                 {
			//                     "comment": "Red Hat Enterprise Linux 4 is installed"
			//                 },
			//                 {
			//                     "comment": "gzip is earlier than 0:1.3.3-16.rhel4"
			//                 },
			//                 {
			//                     "comment": "gzip is signed with Red Hat redhatrelease2 key"
			//                 }
			//             ]
			//         }
			//     ],
			//     "criterions": [
			//         {
			//             "comment": "Red Hat Enterprise Linux must be installed"
			//         }
			//     ]
			// }

			// e.g. 2
			// "criteria": {
			//     "operator": "OR",
			//     "criterias": [
			//         {
			//             "operator": "AND",
			//             "criterias": [
			//                 {
			//                     "operator": "OR",
			//                     "criterias": [
			//                         {
			//                             "operator": "AND",
			//                             "criterions": [
			//                                 {
			//                                     "comment": "bluez-utils is earlier than 0:2.10-2.2"
			//                                 },
			//                             ]
			//                         },
			//                         {
			//                             "operator": "AND",
			//                             "criterions": [
			//                                 {
			//                                     "comment": "bluez-utils-cups is earlier than 0:2.10-2.2"
			//                                 },
			//                             ]
			//                         }
			//                     ]
			//                 }
			//             ],
			//             "criterions": [
			//                 {
			//                     "comment": "Red Hat Enterprise Linux 4 is installed"
			//                 }
			//             ]
			//         }
			//     ],
			//     "criterions": [
			//         {
			//             "comment": "Red Hat Enterprise Linux must be installed"
			//         }
			//     ]
			// }

			m[v] = criteria
			return m, nil
		case criteria.Operator == "OR" && parent.Operator == "AND":
			// e.g. 1
			// "criteria": {
			// 	"operator": "OR",
			// 	"criterias": [
			// 		{
			// 			"operator": "AND",
			// 			"criterias": [
			// 				{
			// 					"operator": "OR",
			// 					"criterions": [
			// 						{
			// 							"comment": "Red Hat Enterprise Linux 8 is installed"
			// 						},
			// 						{
			// 							"comment": "Red Hat CoreOS 4 is installed"
			// 						}
			// 					]
			// 				}
			// 			],
			// 			"criterions": [
			// 				{
			// 					"comment": "WALinuxAgent is earlier than 0:2.2.32-1.el8_0.1"
			// 				},
			// 				{
			// 					"comment": "WALinuxAgent is signed with Red Hat redhatrelease2 key"
			// 				}
			// 			]
			// 		}
			// 	],
			// 	"criterions": [
			// 		{
			// 			"comment": "Red Hat Enterprise Linux must be installed"
			// 		}
			// 	]
			// }

			// e.g. 2
			// "criteria": {
			// 	"operator": "OR",
			// 	"criterias": [
			// 	    {
			// 	        "operator": "AND",
			// 	        "criterias": [
			// 	            {
			// 	                "operator": "OR",
			// 	                "criterions": [
			// 	                    {
			// 	                        "comment": "Red Hat Enterprise Linux 8 is installed"
			// 	                    },
			// 	                    {
			// 	                        "comment": "Red Hat CoreOS 4 is installed"
			// 	                    }
			// 	                ]
			// 	            },
			// 	            {
			// 	                "operator": "OR",
			// 	                "criterias": [
			// 	                    {
			// 	                        "operator": "AND",
			// 	                        "criterias": [
			// 	                            {
			// 	                                "operator": "OR",
			// 	                                "criterias": [
			// 	                                    {
			// 	                                        "operator": "AND",
			// 	                                        "criterions": [
			// 	                                            {
			// 	                                                "comment": "bind-dyndb-ldap is earlier than 0:11.1-14.module+el8.1.0+4098+f286395e"
			// 	                                            },
			// 	                                        ]
			// 	                                    }
			// 	                                ]
			// 	                            }
			// 	                        ],
			// 	                        "criterions": [
			// 	                            {
			// 	                                "comment": "Module idm:DL1 is enabled"
			// 	                            }
			// 	                        ]
			// 	                    }
			// 	                ]
			// 	            }
			// 	        ]
			// 	    }
			// 	],
			// 	"criterions": [
			// 	    {
			// 	        "comment": "Red Hat Enterprise Linux must be installed"
			// 	    }
			// 	]
			// }

			m[v] = parent
			return m, nil
		default:
			return nil, errors.New("unexpected criteria tree")
		}
	}

	for _, ovalCa := range criteria.Criterias {
		if _, err := e.prewalkCriteria(m, name, criteria, ovalCa); err != nil {
			return nil, errors.Wrap(err, "prewalk criteria")
		}
	}

	return m, nil
}

func (e extractor) prewalkCriterion(name string, ovalCns []v1.Criterion) (string, error) {
	var next []v1.Criterion

	for _, ovalCn := range ovalCns {
		var t1 v1.RpminfoTest
		if err := e.read(name, "tests", "rpminfo_test", ovalCn.TestRef, &t1); err != nil {
			next = append(next, ovalCn)
			continue
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t2 v1.UnameTest
		if err := e.read(name, "tests", "uname_test", ovalCn.TestRef, &t2); err != nil {
			next = append(next, ovalCn)
			continue
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t3 v1.Textfilecontent54Test
		if err := e.read(name, "tests", "textfilecontent54_test", ovalCn.TestRef, &t3); err != nil {
			next = append(next, ovalCn)
			continue
		}
	}
	ovalCns = next
	next = nil

	var majors []string
	for _, ovalCn := range ovalCns {
		var t4 v1.RpmverifyfileTest
		if err := e.read(name, "tests", "rpmverifyfile_test", ovalCn.TestRef, &t4); err != nil {
			next = append(next, ovalCn)
			continue
		}

		switch {
		case t4.Comment == "Red Hat Enterprise Linux must be installed":
		case strings.HasSuffix(t4.Comment, " is installed"):
			switch {
			case strings.HasPrefix(t4.Comment, "Red Hat CoreOS "):
			case strings.HasPrefix(t4.Comment, "Red Hat Enterprise Linux "):
				majors = append(majors, strings.TrimPrefix(strings.TrimSuffix(t4.Comment, " is installed"), "Red Hat Enterprise Linux "))
			default:
				return "", errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"Red Hat CoreOS <version> is installed", "Red Hat Enterprise Linux <version> is installed"}, t4.Comment)
			}
		default:
			return "", errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"Red Hat Enterprise Linux must be installed", "Red Hat CoreOS <version> is installed", "Red Hat Enterprise Linux <version> is installed"}, t4.Comment)
		}
	}

	if len(next) > 0 {
		return "", errors.Errorf("%q is not found in %q", func() []string {
			rs := make([]string, 0, len(next))
			for _, ovalCn := range next {
				rs = append(rs, ovalCn.TestRef)
			}
			return rs
		}(), []string{"rpminfo_test", "uname_test", "textfilecontent54_test", "rpmverifyfile_test"})
	}

	switch len(majors) {
	case 0:
		return "", nil
	case 1:
		return majors[0], nil
	default:
		return "", errors.New("unexpected criteria tree. multiple major versions found in criterions")
	}
}

func (e extractor) walkCriteria(name string, criteria v1.Criteria, affectedRepositories []string) (criteriaTypes.Criteria, error) {
	var ca criteriaTypes.Criteria
	switch criteria.Operator {
	case "OR":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("unexpected criteria operator. expected: %q, actual: %q", []string{"OR", "AND"}, criteria.Operator)
	}

	for _, ovalCa := range criteria.Criterias {
		cca, err := e.walkCriteria(name, ovalCa, affectedRepositories)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "walk criteria")
		}
		switch {
		case len(cca.Criterias) == 0 && len(cca.Criterions) == 0:
		default:
			ca.Criterias = append(ca.Criterias, cca)
		}
	}

	cca, err := e.walkCriterions(ca, name, criteria.Criterions, affectedRepositories)
	if err != nil {
		return criteriaTypes.Criteria{}, errors.Wrap(err, "walk criterions")
	}
	return cca, nil
}

func (e extractor) walkCriterions(ca criteriaTypes.Criteria, name string, ovalCns []v1.Criterion, affectedRepositories []string) (criteriaTypes.Criteria, error) {
	var next []v1.Criterion

	for _, ovalCn := range ovalCns {
		var t1 v1.RpminfoTest
		if err := e.read(name, "tests", "rpminfo_test", ovalCn.TestRef, &t1); err != nil {
			next = append(next, ovalCn)
			continue
		}

		switch {
		case strings.Contains(t1.Comment, " is earlier than "):
			var o v1.RpminfoObject
			if err := e.read(name, "objects", "rpminfo_object", t1.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "rpminfo_object", t1.Object.ObjectRef))
			}

			var s v1.RpminfoState
			if err := e.read(name, "states", "rpminfo_state", t1.State.StateRef, &s); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("states", "rpminfo_state", t1.State.StateRef))
			}

			if s.Evr == nil {
				return criteriaTypes.Criteria{}, errors.New("evr is empty")
			}
			switch s.Evr.Operation {
			case "less than":
				ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vecTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
						Package: packageTypes.Package{
							Type: packageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{
								Name: o.Name,
								Architectures: func() []string {
									if s.Arch == nil {
										return nil
									}
									return strings.Split(s.Arch.Text, "|")
								}(),
								Repositories: affectedRepositories,
							},
						},
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Range: []rangeTypes.Range{{LessThan: s.Evr.Text}},
							Fixed: []string{s.Evr.Text},
						},
					},
				})
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("unexpected evr operation. expected: %q, actual: %q", []string{"less than"}, s.Evr.Operation)
			}
		case strings.Contains(t1.Comment, " version equals "):
			var o v1.RpminfoObject
			if err := e.read(name, "objects", "rpminfo_object", t1.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "rpminfo_object", t1.Object.ObjectRef))
			}

			var s v1.RpminfoState
			if err := e.read(name, "states", "rpminfo_state", t1.State.StateRef, &s); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("states", "rpminfo_state", t1.State.StateRef))
			}

			if s.Evr == nil {
				return criteriaTypes.Criteria{}, errors.New("evr is empty")
			}
			switch s.Evr.Operation {
			case "equals":
				ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vecTypes.Criterion{
						Vulnerable: false,
						Package: packageTypes.Package{
							Type: packageTypes.PackageTypeBinary,
							Binary: &vcBinaryPackageTypes.Package{
								Name: o.Name,
								Architectures: func() []string {
									if s.Arch == nil {
										return nil
									}
									return strings.Split(s.Arch.Text, "|")
								}(),
								Repositories: affectedRepositories,
							},
						},
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Range: []rangeTypes.Range{{Equal: s.Evr.Text}},
						},
					},
				})
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("unexpected evr operation. expected: %q, actual: %q", []string{"equals"}, s.Evr.Operation)
			}
		case strings.Contains(t1.Comment, " not installed for "):
			var o v1.RpminfoObject
			if err := e.read(name, "objects", "rpminfo_object", t1.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "rpminfo_object", t1.Object.ObjectRef))
			}

			ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeNoneExist,
				NoneExist: &necTypes.Criterion{
					Type: necTypes.PackageTypeBinary,
					Binary: &necBinaryPackageTypes.Package{
						Name:         o.Name,
						Repositories: affectedRepositories,
					},
				},
			})
		case strings.Contains(t1.Comment, " is signed with Red Hat master key"):
		case strings.Contains(t1.Comment, " is signed with Red Hat redhatrelease key"):
		case strings.Contains(t1.Comment, " is signed with Red Hat redhatrelease2 key"):
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{
				"<package> is earlier than <version>",
				"<package> version equals <version>",
				"<package> not installed for <version>",
				"<package> is signed with Red Hat master key",
				"<package> is signed with Red Hat redhatrelease key",
				"<package> is signed with Red Hat redhatrelease2 key",
			}, t1.Comment)
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t2 v1.UnameTest
		if err := e.read(name, "tests", "uname_test", ovalCn.TestRef, &t2); err != nil {
			next = append(next, ovalCn)
			continue
		}

		switch {
		case strings.Contains(t2.Comment, " is currently running"):
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"<package> (version|earlier than) <version> is currently running"}, t2.Comment)
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t3 v1.Textfilecontent54Test
		if err := e.read(name, "tests", "textfilecontent54_test", ovalCn.TestRef, &t3); err != nil {
			next = append(next, ovalCn)
			continue
		}

		switch {
		case strings.Contains(t3.Comment, " is set to boot up on next boot"):
		case strings.HasPrefix(t3.Comment, "Module ") && strings.HasSuffix(t3.Comment, " is enabled"):
			var o v1.Textfilecontent54Object
			if err := e.read(name, "objects", "textfilecontent54_object", t3.Object.ObjectRef, &o); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("objects", "textfilecontent54_object", t3.Object.ObjectRef))
			}

			// <ind-def:pattern operation="pattern match">\[container\-tools\][\w\W]*</ind-def:pattern>
			remaining, found := strings.CutPrefix(o.Pattern.Text, `\[`)
			if !found {
				return criteriaTypes.Criteria{}, errors.Errorf(`unexpected module pattern at prefix. expected: \[, actual: %s`, o.Pattern.Text)
			}
			remaining, found = strings.CutSuffix(remaining, `\][\w\W]*`)
			if !found {
				return criteriaTypes.Criteria{}, errors.Errorf(`unexpected module pattern at suffix. expected: \][\w\W]*, actual: %s`, remaining)
			}
			module := strings.ReplaceAll(remaining, `\`, "")

			var s v1.Textfilecontent54State
			if err := e.read(name, "states", "textfilecontent54_state", t3.State.StateRef, &s); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "read %s", filepath.Join("states", "textfilecontent54_state", t3.State.StateRef))
			}

			// <ind-def:text operation="pattern match">\nstream\s*=\s*3.0\b[\w\W]*\nstate\s*=\s*(enabled|1|true)|\nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*3.0\b</ind-def:text>
			// To extract "stream" value, the regexp pattern of reversed order ("state" at the beginning) is also considered,
			// e.g. \nstate\s*=\s*(enabled|1|true)[\w\W]*\nstream\s*=\s*3.0\b|\nstream\s*=\s*3.0\b[\w\W]*\nstate\s*=\s*(enabled|1|true)
			var ss []string
			for _, s := range strings.Split(s.Text.Text, `\n`) {
				if s == "" {
					continue
				}

				lhs, rhs, ok := strings.Cut(s, `\s*=\s*`)
				if !ok {
					return criteriaTypes.Criteria{}, errors.Errorf("unexpected pattern. expected: %s, actual: %s", `<entry>\s*=\s*<value>`, s)
				}
				if lhs == "stream" {
					ss = append(ss, strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(rhs, "|"), `[\w\W]*`), `\b`), `\`, ""))
				}
			}

			switch ss := util.Unique(ss); len(ss) {
			case 1:
				var f func(ca criteriaTypes.Criteria, modularitylabel string) error
				f = func(ca criteriaTypes.Criteria, modularitylabel string) error {
					for i := range ca.Criterias {
						if err := f(ca.Criterias[i], modularitylabel); err != nil {
							return errors.Wrap(err, "add modularitylabel in criteria")
						}
					}
					for i := range ca.Criterions {
						switch ca.Criterions[i].Type {
						case criterionTypes.CriterionTypeVersion:
							ca.Criterions[i].Version.Package.Binary.Name = fmt.Sprintf("%s::%s", modularitylabel, ca.Criterions[i].Version.Package.Binary.Name)
						case criterionTypes.CriterionTypeNoneExist:
							ca.Criterions[i].NoneExist.Binary.Name = fmt.Sprintf("%s::%s", modularitylabel, ca.Criterions[i].NoneExist.Binary.Name)
						default:
							return errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, ca.Criterions[i].Type)
						}
					}
					return nil
				}
				if err := f(ca, fmt.Sprintf("%s:%s", module, ss[0])); err != nil {
					return criteriaTypes.Criteria{}, errors.Wrap(err, "add modularitylabel")
				}
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("stream cannot be determined to a single value. values: %v, text: %s", ss, s.Text.Text)
			}
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"<package> (version|earlier than) <version> is set to boot up on next boot", "Module <module name>:<module stream> is enabled"}, t3.Comment)
		}
	}
	ovalCns = next
	next = nil

	for _, ovalCn := range ovalCns {
		var t4 v1.RpmverifyfileTest
		if err := e.read(name, "tests", "rpmverifyfile_test", ovalCn.TestRef, &t4); err != nil {
			next = append(next, ovalCn)
			continue
		}

		switch {
		case t4.Comment == "Red Hat Enterprise Linux must be installed":
		case strings.HasSuffix(t4.Comment, " is installed"):
			switch {
			case strings.HasPrefix(t4.Comment, "Red Hat CoreOS "):
			case strings.HasPrefix(t4.Comment, "Red Hat Enterprise Linux "):
			default:
				return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. exopected: %q, actual: %q", []string{"Red Hat CoreOS <version> is installed", "Red Hat Enterprise Linux <version> is installed"}, t4.Comment)
			}
		default:
			return criteriaTypes.Criteria{}, errors.Errorf("unexpected comment format. expected: %q, actual: %q", []string{"Red Hat Enterprise Linux must be installed", "Red Hat CoreOS <version> is installed", "Red Hat Enterprise Linux <version> is installed"}, t4.Comment)
		}
	}

	if len(next) > 0 {
		return criteriaTypes.Criteria{}, errors.Errorf("%q is not found in %q", func() []string {
			rs := make([]string, 0, len(next))
			for _, ovalCn := range next {
				rs = append(rs, ovalCn.TestRef)
			}
			return rs
		}(), []string{"rpminfo_test", "uname_test", "textfilecontent54_test", "rpmverifyfile_test"})
	}
	return ca, nil
}

func (e extractor) postWalkCriteria(ca criteriaTypes.Criteria) criteriaTypes.Criteria {
	if !(len(ca.Criterias) == 1 && len(ca.Criterions) == 0) {
		return ca
	}
	return e.postWalkCriteria(ca.Criterias[0])
}

func (e extractor) read(osver, class, family, id string, v any) error {
	if err := e.r.Read(filepath.Join(e.ovalDir, osver, class, family, fmt.Sprintf("%s.json", id)), e.ovalDir, v); err != nil {
		return errors.Wrapf(err, "read %s %s", class, family)
	}
	return nil
}
