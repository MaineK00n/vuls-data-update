package v2

import "time"

type feed struct {
	Feed struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Updated string `json:"updated"`
		Entry   []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Link  []struct {
				Href   string `json:"href"`
				Length int    `json:"length"`
			} `json:"link"`
			Updated time.Time `json:"updated"`
			Content struct {
				Type string `json:"type"`
				Src  string `json:"src"`
			} `json:"content"`
			Format struct {
				Schema  string `json:"schema"`
				Version string `json:"version"`
			} `json:"format"`
		} `json:"entry"`
	} `json:"feed"`
}

type root struct {
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
		ContentVersion string `xml:"content_version"`
	} `xml:"generator"`
	Definitions struct {
		Definition []Definition `xml:"definition"`
	} `xml:"definitions"`
	Tests     Tests     `xml:"tests"`
	Objects   Objects   `xml:"objects"`
	States    States    `xml:"states"`
	Variables Variables `xml:"variables"`
}

type Definition struct {
	ID         string `xml:"id,attr" json:"id,omitempty"`
	Version    string `xml:"version,attr" json:"version,omitempty"`
	Class      string `xml:"class,attr" json:"class,omitempty"`
	Deprecated string `xml:"deprecated,attr" json:"deprecated,omitempty"`
	Metadata   struct {
		Title     string `xml:"title" json:"title,omitempty"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity" json:"severity,omitempty"`
			Updated  struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitzero"`
			Cve []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
				Cvss2  string `xml:"cvss2,attr" json:"cvss2,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			Affected struct {
				Resolution []struct {
					State     string   `xml:"state,attr" json:"state,omitempty"`
					Component []string `xml:"component" json:"component,omitempty"`
				} `xml:"resolution" json:"resolution,omitempty"`
			} `xml:"affected" json:"affected,omitzero"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitzero"`
			Rights string `xml:"rights" json:"rights,omitempty"`
			Issued struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitzero"`
			Bugzilla []struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				Href string `xml:"href,attr" json:"href,omitempty"`
				ID   string `xml:"id,attr" json:"id,omitempty"`
			} `xml:"bugzilla" json:"bugzilla,omitempty"`
		} `xml:"advisory" json:"advisory,omitzero"`
		Affected struct {
			Family   string   `xml:"family,attr" json:"family,omitempty"`
			Platform []string `xml:"platform" json:"platform,omitempty"`
		} `xml:"affected" json:"affected,omitzero"`
	} `xml:"metadata" json:"metadata,omitzero"`
	Criteria Criteria `xml:"criteria" json:"criteria,omitzero"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr" json:"operator,omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:"criterias,omitempty"`
	Criterions []Criterion `xml:"criterion" json:"criterions,omitempty"`
}

type Criterion struct {
	TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
}

type Tests struct {
	RpminfoTest           []RpminfoTest           `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	RpmverifyfileTest     []RpmverifyfileTest     `xml:"rpmverifyfile_test" json:"rpmverifyfile_test,omitempty"`
	Textfilecontent54Test []Textfilecontent54Test `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
	UnameTest             []UnameTest             `xml:"uname_test" json:"uname_test,omitempty"`
}

type RpminfoTest struct {
	Check          string `xml:"check,attr" json:"check,omitempty"`
	Comment        string `xml:"comment,attr" json:"comment,omitempty"`
	ID             string `xml:"id,attr" json:"id,omitempty"`
	Version        string `xml:"version,attr" json:"version,omitempty"`
	CheckExistence string `xml:"check_existence,attr" json:"check_existence,omitempty"`
	Object         struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type RpmverifyfileTest struct {
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Textfilecontent54Test struct {
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type UnameTest struct {
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type Objects struct {
	RpminfoObject           []RpminfoObject           `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	RpmverifyfileObject     RpmverifyfileObject       `xml:"rpmverifyfile_object" json:"rpmverifyfile_object,omitzero"`
	Textfilecontent54Object []Textfilecontent54Object `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
	UnameObject             UnameObject               `xml:"uname_object" json:"uname_object,omitzero"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Name    string `xml:"name" json:"Name,omitempty"`
}

type RpmverifyfileObject struct {
	ID          string `xml:"id,attr" json:"id,omitempty"`
	AttrVersion string `xml:"version,attr" json:"attr_version,omitempty"`
	Behaviors   struct {
		Noconfigfiles string `xml:"noconfigfiles,attr" json:"noconfigfiles,omitempty"`
		Noghostfiles  string `xml:"noghostfiles,attr" json:"noghostfiles,omitempty"`
		Nogroup       string `xml:"nogroup,attr" json:"nogroup,omitempty"`
		Nolinkto      string `xml:"nolinkto,attr" json:"nolinkto,omitempty"`
		Nomd5         string `xml:"nomd5,attr" json:"nomd5,omitempty"`
		Nomode        string `xml:"nomode,attr" json:"nomode,omitempty"`
		Nomtime       string `xml:"nomtime,attr" json:"nomtime,omitempty"`
		Nordev        string `xml:"nordev,attr" json:"nordev,omitempty"`
		Nosize        string `xml:"nosize,attr" json:"nosize,omitempty"`
		Nouser        string `xml:"nouser,attr" json:"nouser,omitempty"`
	} `xml:"behaviors" json:"behaviors,omitzero"`
	Name struct {
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"name" json:"name,omitzero"`
	Epoch struct {
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"epoch" json:"epoch,omitzero"`
	Version struct {
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"version" json:"version,omitzero"`
	Release struct {
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"release" json:"release,omitzero"`
	Arch struct {
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"arch" json:"arch,omitzero"`
	Filepath string `xml:"filepath" json:"Filepath,omitempty"`
}

type Textfilecontent54Object struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Filepath struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
	} `xml:"filepath" json:"filepath,omitzero"`
	Pattern struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"pattern" json:"pattern,omitzero"`
	Instance struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		VarRef   string `xml:"var_ref,attr" json:"var_ref,omitempty"`
	} `xml:"instance" json:"instance,omitzero"`
}

type UnameObject struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
}

type States struct {
	RpminfoState           []RpminfoState           `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	RpmverifyfileState     []RpmverifyfileState     `xml:"rpmverifyfile_state" json:"rpmverifyfile_state,omitempty"`
	Textfilecontent54State []Textfilecontent54State `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
	UnameState             []UnameState             `xml:"uname_state" json:"uname_state,omitempty"`
}

type RpminfoState struct {
	ID             string `xml:"id,attr" json:"id,omitempty"`
	Version        string `xml:"version,attr" json:"version,omitempty"`
	SignatureKeyid *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"signature_keyid" json:"signature_keyid,omitempty"`
	Evr *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitempty"`
	Arch *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"arch" json:"arch,omitempty"`
}

type RpmverifyfileState struct {
	ID          string `xml:"id,attr" json:"id,omitempty"`
	AttrVersion string `xml:"version,attr" json:"attr_version,omitempty"`
	Name        struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"name" json:"name,omitzero"`
	Version struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"version" json:"version,omitzero"`
}

type Textfilecontent54State struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Text    struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"text" json:"text,omitzero"`
}

type UnameState struct {
	ID        string `xml:"id,attr" json:"id,omitempty"`
	Version   string `xml:"version,attr" json:"version,omitempty"`
	OsRelease struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"os_release" json:"os_release,omitzero"`
}

type Variables struct {
	LocalVariable LocalVariable `xml:"local_variable" json:"local_variable,omitzero"`
}

type LocalVariable struct {
	Comment    string `xml:"comment,attr" json:"comment,omitempty"`
	Datatype   string `xml:"datatype,attr" json:"datatype,omitempty"`
	ID         string `xml:"id,attr" json:"id,omitempty"`
	Version    string `xml:"version,attr" json:"version,omitempty"`
	Arithmetic struct {
		ArithmeticOperation string `xml:"arithmetic_operation,attr" json:"arithmetic_operation,omitempty"`
		LiteralComponent    struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"literal_component" json:"literal_component,omitzero"`
		ObjectComponent struct {
			ItemField string `xml:"item_field,attr" json:"item_field,omitempty"`
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object_component" json:"object_component,omitzero"`
	} `xml:"arithmetic" json:"arithmetic,omitzero"`
}
