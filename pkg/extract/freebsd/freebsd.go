package freebsd

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/freebsd"
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
		dir: filepath.Join(util.CacheDir(), "extract", "freebsd"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract FreeBSD")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		jsonReader := utiljson.NewJSONReader()
		var fetched freebsd.Vuln
		if err := jsonReader.Read(path, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}
		extracted := extract(fetched, jsonReader.Paths())
		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.FreeBSD,
		Name: func() *string { t := "FreeBSD VuXML"; return &t }(),
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

func extract(fetched freebsd.Vuln, raws []string) dataTypes.Data {
	if fetched.Cancelled != nil {
		return dataTypes.Data{
			ID: fetched.Vid,
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.FreeBSD,
				Raws: raws,
			},
		}
	}

	return dataTypes.Data{
		ID: fetched.Vid,
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          fetched.Vid,
				Title:       fetched.Topic,
				Description: fetched.Description.Text,
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0,
						1+
							len(fetched.References.URL)+
							len(fetched.References.FreebsdSA)+
							len(fetched.References.FreebsdPR)+
							len(fetched.References.Mlist)+
							len(fetched.References.BID)+
							len(fetched.References.CertSA)+
							len(fetched.References.CertVU)+
							len(fetched.References.USCertSA)+
							len(fetched.References.USCertTA))
					rs = append(rs, referenceTypes.Reference{
						Source: "vuxml.freebsd.org",
						URL:    fmt.Sprintf("https://www.vuxml.org/freebsd/%s.html", fetched.Vid),
					})
					for _, u := range fetched.References.URL {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							URL:    u,
						})
					}
					for _, a := range fetched.References.FreebsdSA {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							URL:    fmt.Sprintf("https://www.freebsd.org/security/advisories/FreeBSD-%s.asc", a),
						},
						)
					}
					for _, a := range fetched.References.FreebsdPR {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							URL:    fmt.Sprintf("https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=%s", strings.TrimPrefix(a, "ports/")),
						})
					}
					for _, m := range fetched.References.Mlist {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							URL:    m.Text,
						})
					}
					for _, b := range fetched.References.BID {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							// The URL i.e. http://www.securityfocus.com/bid/12615 is 503 at 2024-04-21,
							// we should use, for example, WebArchive.org waybackmachine.
							URL: fmt.Sprintf("http://www.securityfocus.com/bid/%s", b),
						})
					}
					for _, c := range fetched.References.CertSA {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							// The URL http://www.cert.org/advisories/CA-2004-01.html is redirected to not very detailed page,
							// Because there is only one certsa tag at 2004, leave it as it is.
							URL: fmt.Sprintf("http://www.cert.org/advisories/%s.html", c),
						})
					}
					for _, c := range fetched.References.CertVU {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							URL:    fmt.Sprintf("https://www.kb.cert.org/vuls/id/%s", c),
						})
					}
					for _, u := range fetched.References.USCertSA {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							// The URL i.e. http://www.uscert.gov/cas/alerts/SA04-028A.html is 503 at 2024-04-21,
							// we should use, for example, WebArchive.org waybackmachine.
							URL: fmt.Sprintf("http://www.uscert.gov/cas/alerts/%s.html", u),
						})
					}
					for _, u := range fetched.References.USCertTA {
						rs = append(rs, referenceTypes.Reference{
							Source: "vuxml.freebsd.org",
							// The URL i.e. http://www.uscert.gov/cas/techalerts/TA07-199A.html is 503 at 2024-04-21,
							// we should use, for example, WebArchive.org waybackmachine.
							URL: fmt.Sprintf("http://www.uscert.gov/cas/techalerts/%s.html", u),
						})
					}
					return rs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02"}, fetched.Dates.Entry),
				Modified:  utiltime.Parse([]string{"2006-01-02"}, fetched.Dates.Modified),
			},
			Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeFreeBSD)},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(fetched.References.Cvename))
			for _, c := range fetched.References.Cvename {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: c,
						References: []referenceTypes.Reference{{
							Source: "vuxml.freebsd.org",
							URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", c),
						}},
					},
					Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeFreeBSD)},
				})
			}
			return vs
		}(),
		Detection: []detectionTypes.Detection{
			{
				Ecosystem: ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeFreeBSD),
				Criteria: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: func() []criterionTypes.Criterion {
						cs := make([]criterionTypes.Criterion, 0, func() int {
							cap := 0
							for _, a := range fetched.Affects {
								cap += len(a.Name)
							}
							return cap
						}())
						for _, a := range fetched.Affects {
							for _, n := range a.Name {
								rs := make([]rangeTypes.Range, 0, len(a.Range))
								for _, r := range a.Range {
									rs = append(rs, rangeTypes.Range{Equal: r.Eq, LessThan: r.Lt, LessEqual: r.Le, GreaterThan: r.Gt, GreaterEqual: r.Ge})
								}
								cs = append(cs, criterionTypes.Criterion{
									Vulnerable: true,
									Package:    packageTypes.Package{Name: n},
									Affected: &affectedTypes.Affected{
										Type:  rangeTypes.RangeTypeFreeBSDPkg,
										Range: rs,
									},
								})
							}
						}
						return cs
					}(),
				},
			},
		},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.FreeBSD,
			Raws: raws,
		},
	}
}
