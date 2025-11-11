package oval

type root struct {
	Generator struct {
		ProductName   string `xml:"product_name"`
		SchemaVersion string `xml:"schema_version"`
		Timestamp     string `xml:"timestamp"`
	} `xml:"generator" json:"generator,omitzero"`
	Definitions struct {
		Definition []Definition `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitzero"`
	Tests   Tests   `xml:"tests" json:"tests,omitzero"`
	Objects Objects `xml:"objects" json:"objects,omitzero"`
	States  States  `xml:"states" json:"states,omitzero"`
}

type Definition struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Class    string `xml:"class,attr" json:"class,omitempty"`
	Metadata struct {
		Title    string `xml:"title" json:"title,omitempty"`
		Affected struct {
			Family   string   `xml:"family,attr" json:"family,omitempty"`
			Platform []string `xml:"platform" json:"platform,omitempty"`
		} `xml:"affected" json:"affected,omitzero"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity" json:"severity,omitempty"`
			Cve      []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
				Cvss4  string `xml:"cvss4,attr" json:"cvss4,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			Bugzilla []struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				Href string `xml:"href,attr" json:"href,omitempty"`
			} `xml:"bugzilla" json:"bugzilla,omitempty"`
			Issued struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitzero"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitzero"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitzero"`
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
	RpminfoTest []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitzero"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitzero"`
	} `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	UnameTest []struct {
		UnixDef string `xml:"unix-def,attr" json:"unix-def,omitempty"`
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitzero"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitzero"`
	} `xml:"uname_test" json:"uname_test,omitempty"`
}

type Objects struct {
	RpminfoObject []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Name    string `xml:"name" json:"name,omitempty"`
	} `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	UnameObject struct {
		UnixDef string `xml:"unix-def,attr" json:"unix-def,omitempty"`
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
	} `xml:"uname_object" json:"uname_object,omitzero"`
}

type States struct {
	RpminfoState []struct {
		ID          string `xml:"id,attr" json:"id,omitempty"`
		AttrVersion string `xml:"version,attr" json:"attr_version,omitempty"`
		Xmlns       string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Version     struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"version" json:"version,omitzero"`
		Evr struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"evr" json:"evr,omitzero"`
		SignatureKeyid struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"signature_keyid" json:"signature_keyid,omitzero"`
		Arch struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"arch" json:"arch,omitzero"`
	} `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	UnameState []struct {
		UnixDef   string `xml:"unix-def,attr" json:"unix-def,omitempty"`
		ID        string `xml:"id,attr" json:"id,omitempty"`
		Version   string `xml:"version,attr" json:"version,omitempty"`
		OSRelease struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"os_release" json:"os_release,omitzero"`
	} `xml:"uname_state" json:"uname_state,omitempty"`
}
