package freebsd

import "time"

type vuxml struct {
	Vuln []struct {
		Vid     string `xml:"vid,attr"`
		Topic   string `xml:"topic"`
		Affects []struct {
			Name  []string `xml:"name"`
			Range []Range  `xml:"range"`
		} `xml:"affects>package"`
		Description struct {
			Xmlns string `xml:"xmlns,attr"`
			Text  string `xml:",innerxml"`
		} `xml:"description>body"`
		References struct {
			URL       []string `xml:"url"`
			Cvename   []string `xml:"cvename"`
			FreebsdSA []string `xml:"freebsdsa"`
			FreebsdPR []string `xml:"freebsdpr"`
			Mlist     []struct {
				Text  string `xml:",chardata"`
				Msgid string `xml:"msgid,attr"`
			} `xml:"mlist"`
			BID      []string `xml:"bid"`
			CertSA   []string `xml:"certsa"`
			CertVU   []string `xml:"certvu"`
			USCertSA []string `xml:"uscertsa"`
			USCertTA []string `xml:"uscertta"`
		} `xml:"references"`
		Dates struct {
			Discovery string `xml:"discovery"`
			Entry     string `xml:"entry"`
			Modified  string `xml:"modified"`
		} `xml:"dates"`
		Cancelled *struct {
			Superseded string `xml:"superseded,attr"`
		} `xml:"cancelled"`
	} `xml:"vuln"`
}

type Advisory struct {
	Vid         string      `json:"vid,omitempty"`
	Topic       string      `json:"topic,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []Package   `json:"affects,omitempty"`
	Dates       *Dates      `json:"dates,omitempty"`
	References  []Reference `json:"references,omitempty"`
	Cancelled   *Cancelled  `json:"cancelled,omitempty"`
}

type Package struct {
	Name  string  `json:"name,omitempty"`
	Range []Range `json:"range,omitempty"`
}

type Range struct {
	Lt string `xml:"lt" json:"lt,omitempty"`
	Ge string `xml:"ge" json:"ge,omitempty"`
	Gt string `xml:"gt" json:"gt,omitempty"`
	Eq string `xml:"eq" json:"eq,omitempty"`
	Le string `xml:"le" json:"le,omitempty"`
}

type Dates struct {
	Discovery *time.Time `json:"discovery,omitempty"`
	Entry     *time.Time `json:"entry,omitempty"`
	Modified  *time.Time `json:"modified,omitempty"`
}

type Reference struct {
	Source string `json:"source,omitempty"`
	Text   string `json:"text,omitempty"`
}

type Cancelled struct {
	Superseded string `json:"superseded,omitempty"`
}
