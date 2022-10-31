package oracle

import "time"

type root struct {
	Generator   generator   `xml:"generator"`
	Definitions definitions `xml:"definitions"`
	Tests       tests       `xml:"tests"`
	Objects     objects     `xml:"objects"`
	States      states      `xml:"states"`
}

type generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	Timestamp      string `xml:"timestamp"`
}

type definitions struct {
	Definitions []definition `xml:"definition"`
}

type definition struct {
	ID          string      `xml:"id,attr"`
	Class       string      `xml:"class,attr"`
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	Affected    affected    `xml:"metadata>affected"`
	Advisory    advisory    `xml:"metadata>advisory"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
}

type affected struct {
	Family   string `xml:"family,attr"`
	Platform string `xml:"platform"`
}

type advisory struct {
	Severity string `xml:"severity"`
	Rights   string `xml:"rights"`
	Issued   struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	Cves []cve `xml:"cve"`
}

type cve struct {
	Text string `xml:",chardata"`
	Href string `xml:"href,attr"`
}

type reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
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
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Name    string `xml:"name"`
}

type states struct {
	RpminfoState []rpminfoState `xml:"rpminfo_state"`
}

type rpminfoState struct {
	ID             string `xml:"id,attr"`
	SignatureKeyid struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"signature_keyid"`
	Version struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"version"`
	Arch struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"arch"`
	Evr struct {
		Text      string `xml:",chardata"`
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
	} `xml:"evr"`
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

type Advisory struct {
	Severity string     `json:"severity"`
	Rights   string     `json:"rights"`
	Issued   *time.Time `json:"issued,omitempty"`
	Cves     []string   `json:"cves"`
}

type Affected struct {
	Family   string `json:"family"`
	Platform string `json:"platform"`
}

type Package struct {
	Name         string `json:"name"`
	FixedVersion string `json:"fixed_version"`
	Arch         string `json:"arch"`
}

type Reference struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	URL    string `json:"url"`
}
