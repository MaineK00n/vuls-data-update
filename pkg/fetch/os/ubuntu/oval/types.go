package oval

type root struct {
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator" json:"generator,omitempty"`
	Definitions struct {
		Definition []Definition `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitempty"`
	Tests     Tests     `xml:"tests" json:"tests,omitempty"`
	Objects   Objects   `xml:"objects" json:"objects,omitempty"`
	States    States    `xml:"states" json:"states,omitempty"`
	Variables Variables `xml:"variables" json:"variables,omitempty"`
}

type Definition struct {
	Class    string `xml:"class,attr" json:"class,omitempty"`
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Metadata struct {
		Title       string `xml:"title"`
		Description string `xml:"description"`
		Affected    struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform"`
		} `xml:"affected" json:"affected,omitempty"`
		Reference struct {
			Source string `xml:"source,attr" json:"source,omitempty"`
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Advisory struct {
			Severity   string   `xml:"severity"`
			Rights     string   `xml:"rights"`
			PublicDate string   `xml:"public_date"`
			Bug        []string `xml:"bug"`
			Cve        struct {
				Text       string `xml:",chardata" json:"text,omitempty"`
				Href       string `xml:"href,attr" json:"href,omitempty"`
				Severity   string `xml:"severity,attr" json:"severity,omitempty"`
				Public     string `xml:"public,attr" json:"public,omitempty"`
				CvssScore  string `xml:"cvss_score,attr" json:"cvss_score,omitempty"`
				CvssVector string `xml:"cvss_vector,attr" json:"cvss_vector,omitempty"`
				Usns       string `xml:"usns,attr" json:"usns,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			PublicDateAtUsn string   `xml:"public_date_at_usn"`
			AssignedTo      string   `xml:"assigned_to"`
			DiscoveredBy    string   `xml:"discovered_by"`
			Crd             string   `xml:"crd"`
			Ref             []string `xml:"ref"`
		} `xml:"advisory" json:"advisory,omitempty"`
	} `xml:"metadata" json:"metadata,omitempty"`
	Notes struct {
		Note string `xml:"note"`
	} `xml:"notes" json:"notes,omitempty"`
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
	Textfilecontent54Test []struct {
		ID             string `xml:"id,attr" json:"id,omitempty"`
		Version        string `xml:"version,attr" json:"version,omitempty"`
		CheckExistence string `xml:"check_existence,attr" json:"check_existence,omitempty"`
		Check          string `xml:"check,attr" json:"check,omitempty"`
		Comment        string `xml:"comment,attr" json:"comment,omitempty"`
		Object         struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
}

type Objects struct {
	Textfilecontent54Object []struct {
		ID       string `xml:"id,attr" json:"id,omitempty"`
		Version  string `xml:"version,attr" json:"version,omitempty"`
		Comment  string `xml:"comment,attr" json:"comment,omitempty"`
		Path     string `xml:"path"`
		Filename string `xml:"filename"`
		Pattern  struct {
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			VarRef    string `xml:"var_ref,attr" json:"var_ref,omitempty"`
			VarCheck  string `xml:"var_check,attr" json:"var_check,omitempty"`
		} `xml:"pattern" json:"pattern,omitempty"`
		Instance struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"instance" json:"instance,omitempty"`
	} `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
}

type States struct {
	Textfilecontent54State []struct {
		ID            string `xml:"id,attr" json:"id,omitempty"`
		Version       string `xml:"version,attr" json:"version,omitempty"`
		Comment       string `xml:"comment,attr" json:"comment,omitempty"`
		Subexpression struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"subexpression" json:"subexpression,omitempty"`
	} `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
}

type Variables struct {
	ConstantVariable []struct {
		ID       string   `xml:"id,attr" json:"id,omitempty"`
		Version  string   `xml:"version,attr" json:"version,omitempty"`
		Datatype string   `xml:"datatype,attr" json:"datatype,omitempty"`
		Comment  string   `xml:"comment,attr" json:"comment,omitempty"`
		Value    []string `xml:"value"`
	} `xml:"constant_variable" json:"constant_variable,omitempty"`
}
