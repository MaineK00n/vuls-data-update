package cvrf

type cvrfdoc struct {
	Xmlns          string `xml:"xmlns,attr"`
	Cvrf           string `xml:"cvrf,attr"`
	Xsi            string `xml:"xsi,attr"`
	SchemaLocation string `xml:"schemaLocation,attr"`
	DocumentTitle  struct {
		Text string `xml:",chardata"`
		Lang string `xml:"lang,attr"`
	} `xml:"DocumentTitle"`
	DocumentType      string `xml:"DocumentType"`
	DocumentPublisher struct {
		Type             string `xml:"Type,attr"`
		ContactDetails   string `xml:"ContactDetails"`
		IssuingAuthority string `xml:"IssuingAuthority"`
	} `xml:"DocumentPublisher"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID"`
		} `xml:"Identification"`
		Status          string `xml:"Status"`
		Version         string `xml:"Version"`
		RevisionHistory struct {
			Revision struct {
				Number      string `xml:"Number"`
				Date        string `xml:"Date"`
				Description string `xml:"Description"`
			} `xml:"Revision"`
		} `xml:"RevisionHistory"`
		InitialReleaseDate []string `xml:"InitialReleaseDate"`
		Generator          struct {
			Engine string `xml:"Engine"`
		} `xml:"Generator"`
	} `xml:"DocumentTracking"`
	DocumentNotes []struct {
		Text     string `xml:",chardata"`
		Audience string `xml:"Audience,attr"`
		Ordinal  string `xml:"Ordinal,attr"`
		Title    string `xml:"Title,attr"`
		Type     string `xml:"Type,attr"`
	} `xml:"DocumentNotes>Note"`
	Vulnerability []struct {
		Title string `xml:"Title"`
		CVE   string `xml:"CVE"`
		Notes []struct {
			Title string `xml:"Title,attr"`
			Type  string `xml:"Type,attr"`
			Text  string `xml:",chardata"`
		} `xml:"Notes>Note"`
		References []Reference `xml:"References>Reference"`
	} `xml:"Vulnerability"`
}

type Vulnerability struct {
	Title string `json:"title,omitempty"`
	CVE   string `json:"cve,omitempty"`
	Notes struct {
		Description string `json:"description,omitempty"`
		Published   string `json:"published,omitempty"`
		Modified    string `json:"modified,omitempty"`
	} `json:"notes,omitempty"`
	References []Reference `json:"references,omitempty"`
}

type Reference struct {
	URL         string `xml:"URL" json:"url,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}
