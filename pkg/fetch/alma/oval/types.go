package oval

type root struct {
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
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
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Class    string `xml:"class,attr" json:"class,omitempty"`
	Metadata struct {
		Title     string `xml:"title" json:"Title,omitempty"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"Description,omitempty"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity" json:"Severity,omitempty"`
			Rights   string `xml:"rights" json:"Rights,omitempty"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitzero"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitzero"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"Cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitzero"`
			Bugzilla []struct {
				Href string `xml:"href,attr" json:"href,omitempty"`
				ID   string `xml:"id,attr" json:"id,omitempty"`
			} `xml:"bugzilla" json:"bugzilla,omitempty"`
			Cve []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
		} `xml:"advisory" json:"advisory,omitzero"`
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
	RpmverifyfileTest []struct {
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
	} `xml:"rpmverifyfile_test" json:"rpmverifyfile_test,omitempty"`
	UnameTest []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitzero"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitzero"`
	} `xml:"uname_test" json:"uname_test,omitempty"`
	Textfilecontent54Test []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitzero"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitzero"`
	} `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
	RpminfoTest []struct {
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
	} `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
}

type Objects struct {
	RpmverifyfileObject []struct {
		ID          string `xml:"id,attr" json:"id,omitempty"`
		AttrVersion string `xml:"version,attr" json:"attrversion,omitempty"`
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
	} `xml:"rpmverifyfile_object" json:"rpmverifyfile_object,omitempty"`
	UnameObject struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"uname_object" json:"uname_object,omitzero"`
	Textfilecontent54Object []struct {
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
	} `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
	RpminfoObject []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Name    string `xml:"name" json:"Name,omitempty"`
	} `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
}

type States struct {
	RpmverifyfileState []struct {
		ID          string `xml:"id,attr" json:"id,omitempty"`
		AttrVersion string `xml:"version,attr" json:"attrversion,omitempty"`
		Name        struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"name" json:"name,omitzero"`
		Version struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"version" json:"version,omitzero"`
	} `xml:"rpmverifyfile_state" json:"rpmverifyfile_state,omitempty"`
	UnameState []struct {
		ID        string `xml:"id,attr" json:"id,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		OsRelease struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"os_release" json:"os_release,omitzero"`
	} `xml:"uname_state" json:"uname_state,omitempty"`
	Textfilecontent54State []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Text    struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"text" json:"text,omitzero"`
	} `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
	RpminfoState []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Arch    struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"arch" json:"arch,omitzero"`
		Evr struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"evr" json:"evr,omitzero"`
		SignatureKeyid struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"signature_keyid" json:"signature_keyid,omitzero"`
	} `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
}

type Variables struct {
	LocalVariable struct {
		ID         string `xml:"id,attr" json:"id,omitempty"`
		Version    string `xml:"version,attr" json:"version,omitempty"`
		Comment    string `xml:"comment,attr" json:"comment,omitempty"`
		Datatype   string `xml:"datatype,attr" json:"datatype,omitempty"`
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
	} `xml:"local_variable" json:"local_variable,omitzero"`
}
