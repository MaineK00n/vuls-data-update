package oval

type branches struct {
	Length   int      `json:"length"`
	Branches []string `json:"branches"`
}

type root struct {
	Generator struct {
		Timestamp     string `xml:"timestamp"`
		ProductName   string `xml:"product_name"`
		SchemaVersion string `xml:"schema_version"`
	} `xml:"generator" json:"generator,omitempty"`
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
			Platform string   `xml:"platform" json:"platform,omitempty"`
			Product  []string `xml:"product" json:"product,omitempty"`
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
			Rights   string `xml:"rights" json:"rights,omitempty"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitempty"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitempty"`
			Bdu []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Cvss   string `xml:"cvss,attr" json:"cvss,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
			} `xml:"bdu" json:"bdu,omitempty"`
			Cve []struct {
				Text   string `xml:",chardata" json:"text,omitempty"`
				Cvss   string `xml:"cvss,attr" json:"cvss,omitempty"`
				Cwe    string `xml:"cwe,attr" json:"cwe,omitempty"`
				Href   string `xml:"href,attr" json:"href,omitempty"`
				Impact string `xml:"impact,attr" json:"impact,omitempty"`
				Public string `xml:"public,attr" json:"public,omitempty"`
				Cvss3  string `xml:"cvss3,attr" json:"cvss3,omitempty"`
			} `xml:"cve" json:"cve,omitempty"`
			AffectedCpeList struct {
				Cpe []string `xml:"cpe" json:"cpe,omitempty"`
			} `xml:"affected_cpe_list" json:"affected_cpe_list,omitempty"`
			Bugzilla []struct {
				Text string `xml:",chardata" json:"text,omitempty"`
				ID   string `xml:"id,attr" json:"id,omitempty"`
				Href string `xml:"href,attr" json:"href,omitempty"`
			} `xml:"bugzilla" json:"bugzilla,omitempty"`
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
	Textfilecontent54Test []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"textfilecontent54_test" json:"textfilecontent54_test,omitempty"`
	RpminfoTest []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Check   string `xml:"check,attr" json:"check,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Object  struct {
			ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
		} `xml:"object" json:"object,omitempty"`
		State struct {
			StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
		} `xml:"state" json:"state,omitempty"`
	} `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
}

type Objects struct {
	Textfilecontent54Object []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Path    struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"path" json:"path,omitempty"`
		Filepath struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"filepath" json:"filepath,omitempty"`
		Pattern struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"pattern" json:"pattern,omitempty"`
		Instance struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"instance" json:"instance,omitempty"`
	} `xml:"textfilecontent54_object" json:"textfilecontent54_object,omitempty"`
	RpminfoObject []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Name    struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Datatype string `xml:"datatype,attr" json:"datatype,omitempty"`
		} `xml:"name" json:"name,omitempty"`
	} `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
}

type States struct {
	Textfilecontent54State []struct {
		ID            string `xml:"id,attr" json:"id,omitempty"`
		Version       string `xml:"version,attr" json:"version,omitempty"`
		Comment       string `xml:"comment,attr" json:"comment,omitempty"`
		Subexpression struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"subexpression" json:"subexpression,omitempty"`
	} `xml:"textfilecontent54_state" json:"textfilecontent54_state,omitempty"`
	RpminfoState []struct {
		ID      string `xml:"id,attr" json:"id,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Comment string `xml:"comment,attr" json:"comment,omitempty"`
		Evr     struct {
			Text      string `xml:",chardata" json:"text,omitempty"`
			Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
			Operation string `xml:"operation,attr" json:"operation,omitempty"`
		} `xml:"evr" json:"evr,omitempty"`
	} `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
}
