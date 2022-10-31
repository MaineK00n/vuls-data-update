package oval

import "time"

type root struct {
	Generator   generator   `xml:"generator"`
	Definitions definitions `xml:"definitions"`
	Tests       tests       `xml:"tests"`
	Objects     objects     `xml:"objects"`
	States      states      `xml:"states"`
}

type generator struct {
	ProductName   string `xml:"product_name"`
	SchemaVersion string `xml:"schema_version"`
	Timestamp     string `xml:"timestamp"`
}

type definitions struct {
	Definitions []definition `xml:"definition"`
}

type definition struct {
	ID          string      `xml:"id,attr"`
	Class       string      `xml:"class,attr"`
	Title       string      `xml:"metadata>title"`
	Affected    affected    `xml:"metadata>affected"`
	References  []reference `xml:"metadata>reference"`
	Description string      `xml:"metadata>description"`
	Advisory    advisory    `xml:"metadata>advisory"`
	Criteria    criteria    `xml:"criteria"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []criteria  `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

type affected struct {
	Family   string   `xml:"family,attr"`
	Platform []string `xml:"platform"`
}

type reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
}

type advisory struct {
	Severity        string     `xml:"severity"`
	Cves            []cve      `xml:"cve"`
	Bugzillas       []bugzilla `xml:"bugzilla"`
	AffectedCPEList []string   `xml:"affected_cpe_list>cpe"`
	Issued          struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	Updated struct {
		Date string `xml:"date,attr"`
	} `xml:"updated"`
}

type cve struct {
	CveID  string `xml:",chardata"`
	Cvss3  string `xml:"cvss3,attr"`
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
}

type bugzilla struct {
	URL   string `xml:"href,attr"`
	Title string `xml:",chardata"`
}

type tests struct {
	RpminfoTest []rpminfoTest `xml:"rpminfo_test"`
}

type rpminfoTest struct {
	ID      string    `xml:"id,attr"`
	Comment string    `xml:"comment,attr"`
	Check   string    `xml:"check,attr"`
	Object  objectRef `xml:"object"`
	State   stateRef  `xml:"state"`
}

type objectRef struct {
	Text      string `xml:",chardata"`
	ObjectRef string `xml:"object_ref,attr"`
}

type stateRef struct {
	Text     string `xml:",chardata"`
	StateRef string `xml:"state_ref,attr"`
}

type objects struct {
	RpminfoObject []rpminfoObject `xml:"rpminfo_object"`
}

type rpminfoObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type states struct {
	RpminfoState []rpminfoState `xml:"rpminfo_state"`
}

type rpminfoState struct {
	ID      string `xml:"id,attr"`
	Version struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"version"`
	Arch struct {
		Text      string `xml:",chardata"`
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
	} `xml:"arch"`
	Evr struct {
		Text      string `xml:",chardata"`
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
	} `xml:"evr"`
	SignatureKeyid struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"signature_keyid"`
}

type Definition struct {
	DefinitionID string      `json:"definition_id"`
	Class        string      `json:"class"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	Affected     Affected    `json:"affected"`
	Advisory     Advisory    `json:"advisory"`
	Packages     []Package   `json:"packages"`
	References   []Reference `json:"references"`
}

type Affected struct {
	Family    string   `json:"family"`
	Platforms []string `json:"platforms"`
}

type Advisory struct {
	Severity  string     `json:"severity,omitempty"`
	CVEs      []CVE      `json:"cves,omitempty"`
	Bugzillas []Bugzilla `json:"bugzillas,omitempty"`
	CPEs      []string   `json:"cpes,omitempty"`
	Issued    *time.Time `json:"issued,omitempty"`
	Updated   *time.Time `json:"updated,omitempty"`
}

type CVE struct {
	CVEID  string `json:"cve_id,omitempty"`
	CVSS3  string `json:"cvss3,omitempty"`
	Imapct string `json:"imapct,omitempty"`
	Href   string `json:"href,omitempty"`
}

type Bugzilla struct {
	URL   string `json:"url,omitempty"`
	Title string `json:"title,omitempty"`
}

type Package struct {
	Name                 string `json:"name"`
	Status               string `json:"status"`
	FixedVersion         string `json:"fixed_version,omitempty"`
	KernelDefaultVersion string `json:"kernel_default_version,omitempty"`
	Arch                 string `json:"arch,omitempty"`
	Platform             string `json:"platform"`
}

type Reference struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	URL    string `json:"url"`
}
