package product

import "encoding/xml"

type checksum struct {
	URL          string `json:"url"`
	Filename     string `json:"filename"`
	Sha256       string `json:"sha256"`
	Size         int    `json:"size"`
	LastModified string `json:"lastModified"`
}

type feed struct {
	XMLName        xml.Name `xml:"Result"`
	Version        string   `xml:"version,attr"`
	Xsi            string   `xml:"xsi,attr"`
	Xmlns          string   `xml:"xmlns,attr"`
	Mjres          string   `xml:"mjres,attr"`
	AttrStatus     string   `xml:"status,attr"`
	SchemaLocation string   `xml:"schemaLocation,attr"`
	VendorInfo     struct {
		Lang   string `xml:"lang,attr"`
		Vendor []struct {
			Vname   string `xml:"vname,attr"`
			Cpe     string `xml:"cpe,attr"`
			Vid     string `xml:"vid,attr"`
			Product []struct {
				Pname string `xml:"pname,attr"`
				Cpe   string `xml:"cpe,attr"`
				Pid   string `xml:"pid,attr"`
			} `xml:"Product"`
		} `xml:"Vendor"`
	} `xml:"VendorInfo"`
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

type Product struct {
	Vid   string `json:"vid,omitempty"`
	Vname string `json:"vname,omitempty"`
	VCpe  string `json:"vcpe,omitempty"`
	Pid   string `json:"pid,omitempty"`
	Pname string `json:"pname,omitempty"`
	PCpe  string `json:"pcpe,omitempty"`
}
