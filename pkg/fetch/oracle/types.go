package oracle

type root struct {
	Generator struct {
		Text           string `xml:",chardata"`
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator"`
	Definitions struct {
		Definition []Definition `xml:"definition"`
	} `xml:"definitions"`
	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
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
			Source string `xml:"source,attr" json:"source,omitempty"`
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Advisory    struct {
			Severity string `xml:"severity" json:"severity,omitempty"`
			Rights   string `xml:"rights" json:"rights,omitempty"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitempty"`
			Cve []struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				Href string `xml:"href,attr" json:"href,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
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

type Test struct {
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
}

type Tests struct {
	RpminfoTest           []Test `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	Textfilecontent54Test []Test `xml:"textfilecontent54_test" json:"textfilecontent_54_test,omitempty"`
}

type RpminfoObject struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Name    string `xml:"name" json:"name,omitempty"`
}

type Textfilecontent54Object struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Filepath struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
	} `xml:"filepath" json:"filepath,omitempty"`
	Pattern struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"pattern" json:"pattern,omitempty"`
	Instance struct {
		Text     string `xml:",chardata" json:"text,omitempty"`
		Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
	} `xml:"instance" json:"instance,omitempty"`
}

type Objects struct {
	RpminfoObject           []RpminfoObject           `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	Textfilecontent54Object []Textfilecontent54Object `xml:"textfilecontent54_object" json:"textfilecontent_54_object,omitempty"`
}

type RpminfoState struct {
	Xmlns          string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	ID             string `xml:"id,attr" json:"id,omitempty"`
	AttrVersion    string `xml:"version,attr" json:"attr_version,omitempty"`
	SignatureKeyid *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"signature_keyid" json:"signature_keyid,omitempty"`
	Version *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"version" json:"version,omitempty"`
	Arch *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"arch" json:"arch,omitempty"`
	Evr *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitempty"`
	Release *struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"release" json:"release,omitempty"`
}

type Textfilecontent54State struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Text    struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"text" json:"text,omitempty"`
}

type States struct {
	RpminfoState           []RpminfoState           `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	Textfilecontent54State []Textfilecontent54State `xml:"textfilecontent54_state" json:"textfilecontent_54_state,omitempty"`
}
