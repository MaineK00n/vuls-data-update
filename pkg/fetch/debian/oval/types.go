package oval

type root struct {
	Definitions struct {
		Definition []Definition `xml:"definition"`
	} `xml:"definitions"`
	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
}

type Definition struct {
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Class    string `xml:"class,attr" json:"class,omitempty"`
	Metadata struct {
		Title    string `xml:"title" json:"title,omitempty"`
		Affected struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform" json:"platform,omitempty"`
			Product  string `xml:"product" json:"product,omitempty"`
		} `xml:"affected" json:"affected,omitempty"`
		Reference []struct {
			Source string `xml:"source,attr" json:"source,omitempty"`
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description" json:"description,omitempty"`
		Debian      struct {
			Moreinfo string `xml:"moreinfo" json:"moreinfo,omitempty"`
			Dsa      string `xml:"dsa" json:"dsa,omitempty"`
			Date     string `xml:"date" json:"date,omitempty"`
		} `xml:"debian" json:"debian,omitempty"`
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
	Textfilecontent54Test struct {
		ID             string `xml:"id,attr" json:"id,omitempty"`
		Version        string `xml:"version,attr" json:"version,omitempty"`
		Check          string `xml:"check,attr" json:"check,omitempty"`
		CheckExistence string `xml:"check_existence,attr" json:"check_existence,omitempty"`
		Comment        string `xml:"comment,attr" json:"comment,omitempty"`
		Xmlns          string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Object         struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"textfilecontent54_test" json:"textfilecontent_54_test,omitempty"`
	UnameTest struct {
		ID             string `xml:"id,attr" json:"id,omitempty"`
		Version        string `xml:"version,attr" json:"version,omitempty"`
		Check          string `xml:"check,attr" json:"check,omitempty"`
		CheckExistence string `xml:"check_existence,attr" json:"check_existence,omitempty"`
		Comment        string `xml:"comment,attr" json:"comment,omitempty"`
		Xmlns          string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Object         struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
	} `xml:"uname_test" json:"uname_test,omitempty"`
	DpkginfoTest []struct {
		ID             string `xml:"id,attr" json:"id,omitempty"`
		Version        string `xml:"version,attr" json:"version,omitempty"`
		Check          string `xml:"check,attr" json:"check,omitempty"`
		CheckExistence string `xml:"check_existence,attr" json:"check_existence,omitempty"`
		Comment        string `xml:"comment,attr" json:"comment,omitempty"`
		Xmlns          string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Object         struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"dpkginfo_test" json:"dpkginfo_test,omitempty"`
}

type Objects struct {
	Textfilecontent54Object struct {
		ID       string `xml:"id,attr" json:"id,omitempty"`
		Version  string `xml:"version,attr" json:"version,omitempty"`
		Xmlns    string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Path     string `xml:"path" json:"path,omitempty"`
		Filename string `xml:"filename" json:"filename,omitempty"`
		Pattern  struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"pattern" json:"pattern,omitempty"`
		Instance struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"instance" json:"instance,omitempty"`
	} `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
	UnameObject struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	} `xml:"uname_object" json:"uname_object,omitempty"`
	DpkginfoObject []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Name    string `xml:"name" json:"name,omitempty"`
	} `xml:"dpkginfo_object" json:"dpkginfo_object,omitempty"`
}

type States struct {
	Textfilecontent54State struct {
		ID            string `xml:"id,attr" json:"id,omitempty"`
		Version       string `xml:"version,attr" json:"version,omitempty"`
		Xmlns         string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Subexpression struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"subexpression" json:"subexpression,omitempty"`
	} `xml:"textfilecontent54_state" json:"textfilecontent_54_state,omitempty"`
	DpkginfoState []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Evr     struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"evr" json:"evr,omitempty"`
	} `xml:"dpkginfo_state" json:"dpkginfo_state,omitempty"`
}
