package oval

import "time"

type root struct {
	Generator   generator   `xml:"generator"`
	Definitions definitions `xml:"definitions"`
	Tests       tests       `xml:"tests"`
	Objects     objects     `xml:"objects"`
	States      states      `xml:"states"`
	Variables   variables   `xml:"variables"`
}

type generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	ContentVersion string `xml:"content_version"`
	Timestamp      string `xml:"timestamp"`
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
	Affected        resolution `xml:"affected>resolution"`
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
	Cvss2  string `xml:"cvss2,attr"`
	Cvss3  string `xml:"cvss3,attr"`
	Cwe    string `xml:"cwe,attr"`
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr"`
}

type bugzilla struct {
	ID    string `xml:"id,attr"`
	URL   string `xml:"href,attr"`
	Title string `xml:",chardata"`
}

type resolution struct {
	State     string   `xml:"state,attr"`
	Component []string `xml:"component"`
}

type tests struct {
	RpminfoTests           []rpminfoTest           `xml:"rpminfo_test"`
	RpmverifyfileTests     []rpmverifyfileTest     `xml:"rpmverifyfile_test"`
	Textfilecontent54Tests []textfilecontent54Test `xml:"textfilecontent54_test"`
	UnameTests             []unameTest             `xml:"uname_test"`
}

type rpminfoTest struct {
	ID      string    `xml:"id,attr"`
	Comment string    `xml:"comment,attr"`
	Check   string    `xml:"check,attr"`
	Object  objectRef `xml:"object"`
	State   stateRef  `xml:"state"`
}

type rpmverifyfileTest struct {
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	ID      string    `xml:"id,attr"`
	Version string    `xml:"version,attr"`
	Object  objectRef `xml:"object"`
	State   stateRef  `xml:"state"`
}

type textfilecontent54Test struct {
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	ID      string    `xml:"id,attr"`
	Version string    `xml:"version,attr"`
	Object  objectRef `xml:"object"`
	State   stateRef  `xml:"state"`
}

type unameTest struct {
	Check   string    `xml:"check,attr"`
	Comment string    `xml:"comment,attr"`
	ID      string    `xml:"id,attr"`
	Version string    `xml:"version,attr"`
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
	RpminfoObject           []rpminfoObject           `xml:"rpminfo_object"`
	RpmverifyfileObject     rpmverifyfileObject       `xml:"rpmverifyfile_object"`
	Textfilecontent54Object []textfilecontent54Object `xml:"textfilecontent54_object"`
	UnameObject             unameObject               `xml:"uname_object"`
}

type rpminfoObject struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Name    string `xml:"name"`
}

type rpmverifyfileObject struct {
	ID          string `xml:"id,attr"`
	AttrVersion string `xml:"version,attr"`
	Behaviors   struct {
		Noconfigfiles string `xml:"noconfigfiles,attr"`
		Noghostfiles  string `xml:"noghostfiles,attr"`
		Nogroup       string `xml:"nogroup,attr"`
		Nolinkto      string `xml:"nolinkto,attr"`
		Nomd5         string `xml:"nomd5,attr"`
		Nomode        string `xml:"nomode,attr"`
		Nomtime       string `xml:"nomtime,attr"`
		Nordev        string `xml:"nordev,attr"`
		Nosize        string `xml:"nosize,attr"`
		Nouser        string `xml:"nouser,attr"`
	} `xml:"behaviors"`
	Name struct {
		Operation string `xml:"operation,attr"`
	} `xml:"name"`
	Epoch struct {
		Operation string `xml:"operation,attr"`
	} `xml:"epoch"`
	Version struct {
		Operation string `xml:"operation,attr"`
	} `xml:"version"`
	Release struct {
		Operation string `xml:"operation,attr"`
	} `xml:"release"`
	Arch struct {
		Operation string `xml:"operation,attr"`
	} `xml:"arch"`
	Filepath string `xml:"filepath"`
}

type textfilecontent54Object struct {
	ID       string `xml:"id,attr"`
	Version  string `xml:"version,attr"`
	Filepath struct {
		Text     string `xml:",chardata"`
		Datatype string `xml:"datatype,attr"`
	} `xml:"filepath"`
	Pattern struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"pattern"`
	Instance struct {
		Text     string `xml:",chardata"`
		Datatype string `xml:"datatype,attr"`
		VarRef   string `xml:"var_ref,attr"`
	} `xml:"instance"`
}

type unameObject struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type states struct {
	RpminfoState           []rpminfoState           `xml:"rpminfo_state"`
	RpmverifyfileState     []rpmverifyfileState     `xml:"rpmverifyfile_state"`
	Textfilecontent54State []textfilecontent54State `xml:"textfilecontent54_state"`
	UnameState             []unameState             `xml:"uname_state"`
}

type rpminfoState struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Arch    struct {
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

type rpmverifyfileState struct {
	ID          string `xml:"id,attr"`
	AttrVersion string `xml:"version,attr"`
	Name        struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"name"`
	Version struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"version"`
}

type textfilecontent54State struct {
	Chardata string `xml:",chardata"`
	ID       string `xml:"id,attr"`
	Version  string `xml:"version,attr"`
	Text     struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"text"`
}

type unameState struct {
	ID        string `xml:"id,attr"`
	Version   string `xml:"version,attr"`
	OsRelease struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"os_release"`
}

type variables struct {
	LocalVariable struct {
		Comment    string `xml:"comment,attr"`
		Datatype   string `xml:"datatype,attr"`
		ID         string `xml:"id,attr"`
		Version    string `xml:"version,attr"`
		Arithmetic struct {
			ArithmeticOperation string `xml:"arithmetic_operation,attr"`
			LiteralComponent    struct {
				Text     string `xml:",chardata"`
				Datatype string `xml:"datatype,attr"`
			} `xml:"literal_component"`
			ObjectComponent struct {
				ItemField string `xml:"item_field,attr"`
				ObjectRef string `xml:"object_ref,attr"`
			} `xml:"object_component"`
		} `xml:"arithmetic"`
	} `xml:"local_variable"`
}

type repositoryToCPE struct {
	Data map[string]struct {
		Cpes []string `json:"cpes"`
	} `json:"data"`
}

type Definition struct {
	DefinitionID string      `json:"definition_id,omitempty"`
	Class        string      `json:"class,omitempty"`
	Title        string      `json:"title,omitempty"`
	Description  string      `json:"description,omitempty"`
	Affected     Affected    `json:"affected,omitempty"`
	Advisory     Advisory    `json:"advisory,omitempty"`
	Packages     []Package   `json:"packages,omitempty"`
	References   []Reference `json:"references,omitempty"`
}

type Affected struct {
	Family    string   `json:"family,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
}

type Advisory struct {
	Severity  string      `json:"severity,omitempty"`
	CVEs      []CVE       `json:"cves,omitempty"`
	Bugzillas []Bugzilla  `json:"bugzillas,omitempty"`
	CPEs      []CPE       `json:"cpes,omitempty"`
	Affected  *Resolution `json:"affected,omitempty"`
	Issued    *time.Time  `json:"issued,omitempty"`
	Updated   *time.Time  `json:"updated,omitempty"`
}

type CVE struct {
	CVEID  string     `json:"cve_id,omitempty"`
	CVSS2  string     `json:"cvss2,omitempty"`
	CVSS3  string     `json:"cvss3,omitempty"`
	CWE    string     `json:"cwe,omitempty"`
	Impact string     `json:"impact,omitempty"`
	Href   string     `json:"href,omitempty"`
	Public *time.Time `json:"public,omitempty"`
}

type Bugzilla struct {
	ID    string `json:"id,omitempty"`
	URL   string `json:"url,omitempty"`
	Title string `json:"title,omitempty"`
}

type CPE struct {
	CPE        string   `json:"cpe,omitempty"`
	Repository []string `json:"repository,omitempty"`
}

type Resolution struct {
	State     string   `json:"state,omitempty"`
	Component []string `json:"component,omitempty"`
}

type Package struct {
	Name            string `json:"name,omitempty"`
	Status          string `json:"status,omitempty"`
	FixedVersion    string `json:"fixed_version,omitempty"`
	Arch            string `json:"arch,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`
}

type Reference struct {
	ID     string `json:"id,omitempty"`
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}
