package detail

import "encoding/xml"

type checksum struct {
	URL          string `json:"url"`
	Filename     string `json:"filename"`
	Sha256       string `json:"sha256"`
	Size         int    `json:"size"`
	LastModified string `json:"lastModified"`
}

type feed struct {
	XMLName        xml.Name  `xml:"VULDEF-Document"`
	Version        string    `xml:"version,attr"`
	Xsi            string    `xml:"xsi,attr"`
	Xmlns          string    `xml:"xmlns,attr"`
	Vuldef         string    `xml:"vuldef,attr"`
	AttrStatus     string    `xml:"status,attr"`
	Sec            string    `xml:"sec,attr"`
	Marking        string    `xml:"marking,attr"`
	TlpMarking     string    `xml:"tlpMarking,attr"`
	SchemaLocation string    `xml:"schemaLocation,attr"`
	Lang           string    `xml:"lang,attr"`
	Vulinfo        []Vulinfo `xml:"Vulinfo"`
	Handling       struct {
		Marking struct {
			MarkingStructure struct {
				Type             string `xml:"type,attr"`
				MarkingModelName string `xml:"marking_model_name,attr"`
				MarkingModelRef  string `xml:"marking_model_ref,attr"`
				Color            string `xml:"color,attr"`
			} `xml:"Marking_Structure"`
		} `xml:"Marking"`
	} `xml:"handling"`
	Status struct {
		Version     string `xml:"version,attr"`
		Method      string `xml:"method,attr"`
		Lang        string `xml:"lang,attr"`
		RetCd       string `xml:"retCd,attr"`
		RetMax      string `xml:"retMax,attr"`
		ErrCd       string `xml:"errCd,attr"`
		ErrMsg      string `xml:"errMsg,attr"`
		TotalRes    string `xml:"totalRes,attr"`
		TotalResRet string `xml:"totalResRet,attr"`
		FirstRes    string `xml:"firstRes,attr"`
		Feed        string `xml:"feed,attr"`
		Lt          string `xml:"lt,attr"`
	} `xml:"Status"`
}

type Vulinfo struct {
	VulinfoID   string `xml:"VulinfoID" json:"vulinfoid,omitempty"`
	VulinfoData struct {
		Title              string `xml:"Title" json:"title,omitempty"`
		VulinfoDescription struct {
			Overview string `xml:"Overview" json:"overview,omitempty"`
		} `xml:"VulinfoDescription" json:"vulinfodescription,omitzero"`
		Affected struct {
			AffectedItem []struct {
				Name        string `xml:"Name" json:"name,omitempty"`
				ProductName string `xml:"ProductName" json:"productname,omitempty"`
				Cpe         *struct {
					Text    string `xml:",chardata" json:"text,omitempty"`
					Version string `xml:"version,attr" json:"version,omitempty"`
				} `xml:"Cpe" json:"cpe,omitempty"`
				VersionNumber []string `xml:"VersionNumber" json:"versionnumber,omitempty"`
			} `xml:"AffectedItem" json:"affecteditem,omitempty"`
		} `xml:"Affected" json:"affected,omitzero"`
		Impact struct {
			Cvss []struct {
				Version  string `xml:"version,attr" json:"version,omitempty"`
				Severity struct {
					Text string `xml:",chardata" json:"text,omitempty"`
					Type string `xml:"type,attr" json:"type,omitempty"`
				} `xml:"Severity" json:"severity,omitzero"`
				Base   string `xml:"Base" json:"base,omitempty"`
				Vector string `xml:"Vector" json:"vector,omitempty"`
			} `xml:"Cvss" json:"cvss,omitempty"`
			ImpactItem struct {
				Description string `xml:"Description" json:"description,omitempty"`
			} `xml:"ImpactItem" json:"impactitem,omitzero"`
		} `xml:"Impact" json:"impact,omitzero"`
		Solution struct {
			SolutionItem struct {
				Description string `xml:"Description" json:"description,omitempty"`
			} `xml:"SolutionItem" json:"solutionitem,omitzero"`
		} `xml:"Solution" json:"solution,omitzero"`
		Related struct {
			RelatedItem []struct {
				Type      string `xml:"type,attr" json:"type,omitempty"`
				Name      string `xml:"Name" json:"name,omitempty"`
				VulinfoID string `xml:"VulinfoID" json:"vulinfoid,omitempty"`
				URL       string `xml:"URL" json:"url,omitempty"`
				Title     string `xml:"Title" json:"title,omitempty"`
			} `xml:"RelatedItem" json:"relateditem,omitempty"`
		} `xml:"Related" json:"related,omitzero"`
		History struct {
			HistoryItem []struct {
				HistoryNo   string `xml:"HistoryNo" json:"historyno,omitempty"`
				DateTime    string `xml:"DateTime" json:"datetime,omitempty"`
				Description string `xml:"Description" json:"description,omitempty"`
			} `xml:"HistoryItem" json:"historyitem,omitempty"`
		} `xml:"History" json:"history,omitzero"`
		DateFirstPublished string `xml:"DateFirstPublished" json:"datefirstpublished,omitempty"`
		DateLastUpdated    string `xml:"DateLastUpdated" json:"datelastupdated,omitempty"`
		DatePublic         string `xml:"DatePublic" json:"datepublic,omitempty"`
	} `xml:"VulinfoData" json:"vulinfodata,omitzero"`
}
