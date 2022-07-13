package oval

import (
	"encoding/xml"
	"time"
)

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
	Debian      debianInfo  `xml:"metadata>debian"`
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
	Product  string `xml:"product"`
}

type reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
}

type debianInfo struct {
	DSA      string `xml:"dsa"`
	MoreInfo string `xml:"moreinfo"`
	Date     string `xml:"date"`
}

type tests struct {
	Textfilecontent54Test textfilecontent54Test `xml:"textfilecontent54_test"`
	UnameTest             unameTest             `xml:"uname_test"`
	DpkginfoTest          []dpkginfoTest        `xml:"dpkginfo_test"`
}

type textfilecontent54Test struct {
	Text           string    `xml:",chardata"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	ID             string    `xml:"id,attr"`
	Object         objectRef `xml:"object"`
	State          stateRef  `xml:"state"`
}

type unameTest struct {
	Text           string    `xml:",chardata"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	ID             string    `xml:"id,attr"`
	Object         objectRef `xml:"object"`
}

type dpkginfoTest struct {
	Text           string    `xml:",chardata"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Comment        string    `xml:"comment,attr"`
	ID             string    `xml:"id,attr"`
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
	Textfilecontent54Object textfilecontent54Object `xml:"textfilecontent54_object"`
	UnameObject             unameObject             `xml:"uname_object"`
	DpkginfoObject          []dpkginfoObject        `xml:"dpkginfo_object"`
}

type textfilecontent54Object struct {
	ID       string `xml:"id,attr"`
	Path     string `xml:"path"`
	Filename string `xml:"filename"`
	Pattern  struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"pattern"`
	Instance struct {
		Text     string `xml:",chardata"`
		Datatype string `xml:"datatype,attr"`
	} `xml:"instance"`
}

type unameObject struct {
	ID string `xml:"id,attr"`
}

type dpkginfoObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type states struct {
	XMLName                xml.Name               `xml:"states"`
	Textfilecontent54State textfilecontent54State `xml:"textfilecontent54_state"`
	DpkginfoState          []dpkginfoState        `xml:"dpkginfo_state"`
}

type textfilecontent54State struct {
	ID            string `xml:"id,attr"`
	Subexpression struct {
		Text      string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"subexpression"`
}

type dpkginfoState struct {
	ID  string `xml:"id,attr"`
	Evr struct {
		Text      string `xml:",chardata"`
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
	} `xml:"evr"`
}

type Advisory struct {
	ID           string      `json:"id"`
	DSAID        string      `json:"dsa_id,omitempty"`
	DefinitionID string      `json:"definition_id"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	MoreInfo     string      `json:"moreinfo,omitempty"`
	Affected     Affected    `json:"affected"`
	Package      Package     `json:"package"`
	Date         *time.Time  `json:"date,omitempty"`
	References   []Reference `json:"references"`
}

type Affected struct {
	Family   string `json:"family"`
	Platform string `json:"platform"`
	Product  string `json:"product"`
}

type Package struct {
	Name         string `json:"name"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type Reference struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	URL    string `json:"url"`
}
