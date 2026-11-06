package api

type summary struct {
	Notes []string `json:"notes"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// VulnerabilityNote is the content of one output file: the note together
// with the three listings the API serves beside it.
type VulnerabilityNote struct {
	Note       Note        `json:"note,omitzero"`
	Vuls       []Vul       `json:"vuls,omitempty"`
	Vendors    []Vendor    `json:"vendors,omitempty"`
	VendorVuls []VendorVul `json:"vendor_vuls,omitempty"`
}

// Note is served by {id}/.
type Note struct {
	VUID                                string   `json:"vuid,omitempty"`
	IDNumber                            string   `json:"idnumber,omitempty"`
	Name                                string   `json:"name,omitempty"`
	Keywords                            []string `json:"keywords,omitempty"`
	Overview                            string   `json:"overview,omitempty"`
	CleanDesc                           string   `json:"clean_desc,omitempty"`
	Impact                              string   `json:"impact,omitempty"`
	Resolution                          string   `json:"resolution,omitempty"`
	Workarounds                         string   `json:"workarounds,omitempty"`
	SysAffected                         string   `json:"sysaffected,omitempty"`
	Thanks                              string   `json:"thanks,omitempty"`
	Author                              string   `json:"author,omitempty"`
	Public                              []string `json:"public,omitempty"`
	CVEIDs                              []string `json:"cveids,omitempty"`
	CERTAdvisory                        string   `json:"certadvisory,omitempty"`
	USCERTTechnicalAlert                string   `json:"uscerttechnicalalert,omitempty"`
	DateCreated                         string   `json:"datecreated,omitempty"`
	PublicDate                          string   `json:"publicdate,omitempty"`
	DateFirstPublished                  string   `json:"datefirstpublished,omitempty"`
	DateUpdated                         string   `json:"dateupdated,omitempty"`
	Revision                            *int     `json:"revision,omitempty"`
	VRDAD1DirectReport                  string   `json:"vrda_d1_directreport,omitempty"`
	VRDAD1Population                    string   `json:"vrda_d1_population,omitempty"`
	VRDAD1Impact                        string   `json:"vrda_d1_impact,omitempty"`
	CAMWidelyKnown                      string   `json:"cam_widelyknown,omitempty"`
	CAMExploitation                     string   `json:"cam_exploitation,omitempty"`
	CAMInternetInfrastructure           string   `json:"cam_internetinfrastructure,omitempty"`
	CAMPopulation                       string   `json:"cam_population,omitempty"`
	CAMImpact                           string   `json:"cam_impact,omitempty"`
	CAMEaseOfExploitation               string   `json:"cam_easeofexploitation,omitempty"`
	CAMAttackerAccessRequired           string   `json:"cam_attackeraccessrequired,omitempty"`
	CAMScoreCurrent                     string   `json:"cam_scorecurrent,omitempty"`
	CAMScoreCurrentWidelyKnown          string   `json:"cam_scorecurrentwidelyknown,omitempty"`
	CAMScoreCurrentWidelyKnownExploited string   `json:"cam_scorecurrentwidelyknownexploited,omitempty"`
	IPProtocol                          string   `json:"ipprotocol,omitempty"`
	CVSSAccessVector                    string   `json:"cvss_accessvector,omitempty"`
	CVSSAccessComplexity                string   `json:"cvss_accesscomplexity,omitempty"`
	CVSSAuthentication                  string   `json:"cvss_authentication,omitempty"`
	CVSSConfidentialityImpact           string   `json:"cvss_confidentialityimpact,omitempty"`
	CVSSIntegrityImpact                 string   `json:"cvss_integrityimpact,omitempty"`
	CVSSAvailabilityImpact              string   `json:"cvss_availabilityimpact,omitempty"`
	CVSSExploitablity                   string   `json:"cvss_exploitablity,omitempty"`
	CVSSRemediationLevel                string   `json:"cvss_remediationlevel,omitempty"`
	CVSSReportConfidence                string   `json:"cvss_reportconfidence,omitempty"`
	CVSSCollateralDamagePotential       string   `json:"cvss_collateraldamagepotential,omitempty"`
	CVSSTargetDistribution              string   `json:"cvss_targetdistribution,omitempty"`
	CVSSSecurityRequirementsCR          string   `json:"cvss_securityrequirementscr,omitempty"`
	CVSSSecurityRequirementsIR          string   `json:"cvss_securityrequirementsir,omitempty"`
	CVSSSecurityRequirementsAR          string   `json:"cvss_securityrequirementsar,omitempty"`
	CVSSBaseScore                       string   `json:"cvss_basescore,omitempty"`
	CVSSBaseVector                      string   `json:"cvss_basevector,omitempty"`
	CVSSTemporalScore                   string   `json:"cvss_temporalscore,omitempty"`
	CVSSEnvironmentalScore              string   `json:"cvss_environmentalscore,omitempty"`
	CVSSEnvironmentalVector             string   `json:"cvss_environmentalvector,omitempty"`
	Metric                              *float64 `json:"metric,omitempty"`
	VulNote                             *int     `json:"vulnote,omitempty"`
}

// Vul is an element of {id}/vuls/.
type Vul struct {
	Note          string `json:"note,omitempty"`
	CVE           string `json:"cve,omitempty"`
	Description   string `json:"description,omitempty"`
	UID           string `json:"uid,omitempty"`
	CaseIncrement *int   `json:"case_increment,omitempty"`
	DateAdded     string `json:"date_added,omitempty"`
	DateUpdated   string `json:"dateupdated,omitempty"`
}

// Vendor is an element of {id}/vendors/. The API serves two record shapes,
// and no response mixes them:
//   - current records carry note, contact_date, references, dateupdated and
//     statement_date;
//   - records of notes migrated from the legacy database carry vuid,
//     idnumber, vendorrecordid, status, vendorinformation, vendorurls,
//     datenotified, dateresponded, datelastupdated and revision.
//
// vendor, statement and addendum appear in both shapes.
type Vendor struct {
	Note          string `json:"note,omitempty"`
	ContactDate   string `json:"contact_date,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	References    string `json:"references,omitempty"`
	Statement     string `json:"statement,omitempty"`
	DateUpdated   string `json:"dateupdated,omitempty"`
	StatementDate string `json:"statement_date,omitempty"`
	Addendum      string `json:"addendum,omitempty"`

	VUID              string `json:"vuid,omitempty"`
	IDNumber          string `json:"idnumber,omitempty"`
	VendorRecordID    string `json:"vendorrecordid,omitempty"`
	Status            string `json:"status,omitempty"`
	VendorInformation string `json:"vendorinformation,omitempty"`
	VendorURLs        string `json:"vendorurls,omitempty"`
	DateNotified      string `json:"datenotified,omitempty"`
	DateResponded     string `json:"dateresponded,omitempty"`
	DateLastUpdated   string `json:"datelastupdated,omitempty"`
	Revision          *int   `json:"revision,omitempty"`
}

// VendorVul is an element of {id}/vendors/vuls/. It comes in the same two
// shapes as Vendor, and no response mixes them:
//   - current records carry vul, date_added, dateupdated and references;
//   - records of notes migrated from the legacy database carry vuid,
//     idnumber, vendorrecordid, vendorinformation, vendorurls, addendum,
//     datenotified, dateresponded, datelastupdated and revision.
//
// vendor, status and statement appear in both shapes.
type VendorVul struct {
	Vul         string `json:"vul,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Status      string `json:"status,omitempty"`
	DateAdded   string `json:"date_added,omitempty"`
	DateUpdated string `json:"dateupdated,omitempty"`
	References  string `json:"references,omitempty"`
	Statement   string `json:"statement,omitempty"`

	VUID              string `json:"vuid,omitempty"`
	IDNumber          string `json:"idnumber,omitempty"`
	VendorRecordID    string `json:"vendorrecordid,omitempty"`
	VendorInformation string `json:"vendorinformation,omitempty"`
	VendorURLs        string `json:"vendorurls,omitempty"`
	Addendum          string `json:"addendum,omitempty"`
	DateNotified      string `json:"datenotified,omitempty"`
	DateResponded     string `json:"dateresponded,omitempty"`
	DateLastUpdated   string `json:"datelastupdated,omitempty"`
	Revision          *int   `json:"revision,omitempty"`
}
