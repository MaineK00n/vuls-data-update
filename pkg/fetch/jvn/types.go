package jvn

type feed struct {
	Vulinfo []Advisory `xml:"Vulinfo"`
}

type Advisory struct {
	VulinfoID          string     `xml:"VulinfoID" json:"vulinfo_id,omitempty"`
	Title              string     `xml:"VulinfoData>Title" json:"title,omitempty"`
	VulinfoDescription string     `xml:"VulinfoData>VulinfoDescription>Overview" json:"vulinfo_description,omitempty"`
	Affected           []Affected `xml:"VulinfoData>Affected>AffectedItem" json:"affected,omitempty"`
	Impact             Impact     `xml:"VulinfoData>Impact" json:"impact,omitempty"`
	Solution           string     `xml:"VulinfoData>Solution>SolutionItem>Description" json:"solution,omitempty"`
	Related            []Related  `xml:"VulinfoData>Related>RelatedItem" json:"related,omitempty"`
	History            []History  `xml:"VulinfoData>History>HistoryItem" json:"history,omitempty"`
	DateFirstPublished string     `xml:"VulinfoData>DateFirstPublished" json:"date_first_published,omitempty"`
	DateLastUpdated    string     `xml:"VulinfoData>DateLastUpdated" json:"date_last_updated,omitempty"`
	DatePublic         string     `xml:"VulinfoData>DatePublic" json:"date_public,omitempty"`
}
type Affected struct {
	Name          string   `xml:"Name" json:"name,omitempty"`
	ProductName   string   `xml:"ProductName" json:"product_name,omitempty"`
	VersionNumber []string `xml:"VersionNumber" json:"version_number,omitempty"`
	CPE           *CPE     `xml:"Cpe" json:"cpe,omitempty"`
}

type CPE struct {
	Version string `xml:"version,attr" json:"version,omitempty"`
	Text    string `xml:",chardata" json:"text,omitempty"`
}

type Impact struct {
	Cvss       []CVSS `xml:"Cvss" json:"cvss,omitempty"`
	ImpactItem string `xml:"ImpactItem>Description" json:"impact_item,omitempty"`
}

type CVSS struct {
	Version  string   `xml:"version,attr" json:"version,omitempty"`
	Severity Severity `xml:"Severity" json:"severity,omitempty"`
	Base     string   `xml:"Base" json:"base,omitempty"`
	Vector   string   `xml:"Vector" json:"vector,omitempty"`
}

type Severity struct {
	Type string `xml:"type,attr" json:"type,omitempty"`
	Text string `xml:",chardata" json:"text,omitempty"`
}

type Related struct {
	Type      string `xml:"type,attr" json:"type,omitempty"`
	Name      string `xml:"Name" json:"name,omitempty"`
	VulinfoID string `xml:"VulinfoID" json:"vulinfo_id,omitempty"`
	URL       string `xml:"URL" json:"url,omitempty"`
	Title     string `xml:"Title" json:"title,omitempty"`
}

type History struct {
	HistoryNo   string `xml:"HistoryNo" json:"history_no,omitempty"`
	DateTime    string `xml:"DateTime" json:"date_time,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}
