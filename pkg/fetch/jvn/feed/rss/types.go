package rss

import "encoding/xml"

type checksum struct {
	URL          string `json:"url"`
	Filename     string `json:"filename"`
	Sha256       string `json:"sha256"`
	Size         int    `json:"size"`
	LastModified string `json:"lastModified"`
}

type root struct {
	XMLName        xml.Name `xml:"RDF"`
	Xsi            string   `xml:"xsi,attr"`
	Rdf            string   `xml:"rdf,attr"`
	Xmlns          string   `xml:"xmlns,attr"`
	Dc             string   `xml:"dc,attr"`
	Dcterms        string   `xml:"dcterms,attr"`
	Sec            string   `xml:"sec,attr"`
	Sy             string   `xml:"sy,attr"`
	SchemaLocation string   `xml:"schemaLocation,attr"`
	Lang           string   `xml:"lang,attr"`
	Channel        struct {
		About string `xml:"about,attr"`
		Title struct {
			Text string `xml:",chardata"`
		} `xml:"title"`
		Link struct {
			Text string `xml:",chardata"`
		} `xml:"link"`
		Description struct {
			Text string `xml:",chardata"`
		} `xml:"description"`
		Creator struct {
		} `xml:"creator"`
		Date struct {
			Text string `xml:",chardata"`
		} `xml:"date"`
		Modified struct {
			Text string `xml:",chardata"`
		} `xml:"modified"`
		Items struct {
			Seq struct {
				Li []struct {
					Resource string `xml:"resource,attr"`
				} `xml:"li"`
			} `xml:"Seq"`
		} `xml:"items"`
	} `xml:"channel"`
	Item []Item `xml:"item"`
}

type Item struct {
	About       string `xml:"about,attr" json:"about,omitempty"`
	Title       string `xml:"title" json:"title,omitempty"`
	Link        string `xml:"link" json:"link,omitempty"`
	Description string `xml:"description" json:"description,omitempty"`
	Identifier  string `xml:"identifier" json:"identifier,omitempty"`
	References  []struct {
		Text   string `xml:",chardata" json:"text,omitempty"`
		Source string `xml:"source,attr" json:"source,omitempty"`
		ID     string `xml:"id,attr" json:"id,omitempty"`
		Title  string `xml:"title,attr" json:"title,omitempty"`
	} `xml:"references" json:"references,omitempty"`
	CPE []struct {
		Text    string `xml:",chardata" json:"text,omitempty"`
		Version string `xml:"version,attr" json:"version,omitempty"`
		Vendor  string `xml:"vendor,attr" json:"vendor,omitempty"`
		Product string `xml:"product,attr" json:"product,omitempty"`
	} `xml:"cpe" json:"cpe,omitempty"`
	CVSS []struct {
		Version  string `xml:"version,attr" json:"version,omitempty"`
		Score    string `xml:"score,attr" json:"score,omitempty"`
		Type     string `xml:"type,attr" json:"type,omitempty"`
		Severity string `xml:"severity,attr" json:"severity,omitempty"`
		Vector   string `xml:"vector,attr" json:"vector,omitempty"`
	} `xml:"cvss" json:"cvss,omitempty"`
	Date     string `xml:"date" json:"date,omitempty"`
	Issued   string `xml:"issued" json:"issued,omitempty"`
	Modified string `xml:"modified" json:"modified,omitempty"`
}
