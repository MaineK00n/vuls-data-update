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
	Note        string      `xml:"notes>note"`
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
	Family   string `xml:"family,attr"`
	Platform string `xml:"platform"`
}

type reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
}

type advisory struct {
	Severity        string `xml:"severity"`
	Rights          string `xml:"rights"`
	AssignedTo      string `xml:"assigned_to"`
	DiscoveredBy    string `xml:"discovered_by"`
	PublicDate      string `xml:"public_date"`
	PublicDateAtUSN string `xml:"public_date_at_usn"`
	CRD             string `xml:"crd"`
	Refs            []struct {
		URL string `xml:",chardata"`
	} `xml:"ref"`
	Bugs []struct {
		URL string `xml:",chardata"`
	} `xml:"bug"`
}

type tests struct {
	FamilyTest            familyTest            `xml:"family_test"`
	Textfilecontent54Test textfilecontent54Test `xml:"textfilecontent54_test"`
	DpkginfoTest          []dpkginfoTest        `xml:"dpkginfo_test"`
}

type familyTest struct {
	ID             string    `xml:"id,attr"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	Object         objectRef `xml:"object"`
	State          stateRef  `xml:"state"`
}

type textfilecontent54Test struct {
	ID             string    `xml:"id,attr"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	Object         objectRef `xml:"object"`
	State          stateRef  `xml:"state"`
}

type dpkginfoTest struct {
	ID             string    `xml:"id,attr"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	Object         objectRef `xml:"object"`
	State          stateRef  `xml:"state"`
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
	FamilyObject            familyObject            `xml:"family_object"`
	Textfilecontent54Object textfilecontent54Object `xml:"textfilecontent54_object"`
	DpkginfoObject          []dpkginfoObject        `xml:"dpkginfo_object"`
}

type familyObject struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
}

type textfilecontent54Object struct {
	ID       string `xml:"id,attr"`
	Comment  string `xml:"comment,attr"`
	Filepath string `xml:"filepath"`
	Pattern  struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"pattern"`
	Instance struct {
		Text     string `xml:",chardata"`
		Datatype string `xml:"datatype,attr"`
	} `xml:"instance"`
}

type dpkginfoObject struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
	Name    struct {
		Text     string `xml:",chardata"`
		VarRef   string `xml:"var_ref,attr"`
		VarCheck string `xml:"var_check,attr"`
	} `xml:"name"`
}

type states struct {
	FamilyState            familyState            `xml:"family_state"`
	Textfilecontent54State textfilecontent54State `xml:"textfilecontent54_state"`
	DpkginfoState          []dpkginfoState        `xml:"dpkginfo_state"`
}

type familyState struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
	Family  string `xml:"family"`
}

type textfilecontent54State struct {
	ID            string `xml:"id,attr"`
	Comment       string `xml:"comment,attr"`
	Subexpression string `xml:"subexpression"`
}

type dpkginfoState struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
	Evr     struct {
		Text      string `xml:",chardata"`
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
	} `xml:"evr"`
}

type variables struct {
	ConstantVariable []constantVariable `xml:"constant_variable"`
}

type constantVariable struct {
	ID       string   `xml:"id,attr"`
	Comment  string   `xml:"comment,attr"`
	Version  string   `xml:"version,attr"`
	Datatype string   `xml:"datatype,attr"`
	Value    []string `xml:"value"`
}

type Advisory struct {
	ID              string      `json:"id"`
	DefinitionID    string      `json:"definition_id"`
	Title           string      `json:"title"`
	Description     string      `json:"description"`
	Note            string      `json:"note"`
	Severity        string      `json:"severity"`
	Affected        Affected    `json:"affected"`
	Packages        []Package   `json:"packages"`
	References      []Reference `json:"references"`
	PublicDate      *time.Time  `json:"public_date,omitempty"`
	PublicDateAtUSN *time.Time  `json:"public_date_at_usn,omitempty"`
	CRD             *time.Time  `json:"crd,omitempty"`
	AssignedTo      string      `json:"assigned_to,omitempty"`
	DiscoveredBy    string      `json:"discovered_by,omitempty"`
	Rights          string      `json:"rights"`
}

type Affected struct {
	Family   string `json:"family"`
	Platform string `json:"platform"`
}

type Package struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Note         string `json:"note,omitempty"`
}

type Reference struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	URL    string `json:"url"`
}
