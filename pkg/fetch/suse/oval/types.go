package oval

type root struct {
	Generator struct {
		ProductName   string `xml:"product_name"`
		SchemaVersion string `xml:"schema_version"`
		Timestamp     string `xml:"timestamp"`
	} `xml:"generator" json:"generator,omitempty"`
	Definitions struct {
		Definition []Definition `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitempty"`
	Tests   Tests   `xml:"tests" json:"tests,omitempty"`
	Objects Objects `xml:"objects" json:"objects,omitempty"`
	States  States  `xml:"states" json:"states,omitempty"`
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
		} `xml:"affected" json:"affected,omitempty"`
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
			} `xml:"cve" json:"cve,omitempty"`
			Bugzilla []struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				Href string `xml:"href,attr" json:"href,omitempty"`
			} `xml:"bugzilla" json:"bugzilla,omitempty"`
			Issued struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitempty"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitempty"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitempty"`
		} `xml:"advisory" json:"advisory,omitempty"`
	} `xml:"metadata" json:"metadata,omitempty"`
	Criteria Criteria `xml:"criteria" json:"criteria,omitempty"`
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
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
}

type Objects struct {
	RpminfoObject []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Name    string `xml:"name" json:"name,omitempty"`
	} `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
}

type States struct {
	RpminfoState []struct {
		ID          string `xml:"id,attr" json:"id,omitempty"`
		AttrVersion string `xml:"version,attr" json:"attr_version,omitempty"`
		Xmlns       string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Version     struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"version" json:"version,omitempty"`
		Evr struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"evr" json:"evr,omitempty"`
		SignatureKeyid struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"signature_keyid" json:"signature_keyid,omitempty"`
		Arch struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"arch" json:"arch,omitempty"`
	} `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
}
