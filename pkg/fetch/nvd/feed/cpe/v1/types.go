package v1

type cpeDictItem struct {
	Name            string             `xml:"name,attr"`
	Deprecated      string             `xml:"deprecated,attr"`
	DeprecationDate string             `xml:"deprecation_date,attr"`
	Title           []CPEDictTitle     `xml:"title"`
	References      []CPEDictReference `xml:"references>reference"`
	Cpe23Item       struct {
		Name        string `xml:"name,attr"`
		Deprecation *struct {
			Date         string `xml:"date,attr"`
			DeprecatedBy struct {
				Name string `xml:"name,attr"`
				Type string `xml:"type,attr"`
			} `xml:"deprecated-by"`
		} `xml:"deprecation"`
	} `xml:"cpe23-item"`
}

type CPEDictItem struct {
	Name            string             `json:"name,omitempty"`
	Deprecated      bool               `json:"deprecated,omitempty"`
	DeprecationDate string             `json:"deprecation_date,omitempty"`
	Title           []CPEDictTitle     `json:"title,omitempty"`
	References      []CPEDictReference `json:"references,omitempty"`
	Cpe23Item       CPEDictCpe23Item   `json:"cpe_23_item,omitempty"`
}

type CPEDictTitle struct {
	Text string `xml:",chardata" json:"text,omitempty"`
	Lang string `xml:"lang,attr" json:"lang,omitempty"`
}

type CPEDictReference struct {
	Text string `xml:",chardata" json:"text,omitempty"`
	Href string `xml:"href,attr" json:"href,omitempty"`
}

type CPEDictCpe23Item struct {
	Name        string              `json:"name,omitempty"`
	Deprecation *CPEDictDeprecation `json:"deprecation,omitempty"`
}

type CPEDictDeprecation struct {
	Date         string             `json:"date,omitempty"`
	DeprecatedBy CPEDictDeprectedBy `json:"deprecated_by,omitempty"`
}

type CPEDictDeprectedBy struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}
