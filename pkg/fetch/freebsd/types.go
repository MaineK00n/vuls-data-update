package freebsd

type vuxml struct {
	Vuln []Vuln `xml:"vuln"`
}

type Vuln struct {
	Vid     string `xml:"vid,attr" json:"vid,omitempty"`
	Topic   string `xml:"topic" json:"topic,omitempty"`
	Affects []struct {
		Name  []string `xml:"name" json:"name,omitempty"`
		Range []struct {
			Lt string `xml:"lt" json:"lt,omitempty"`
			Ge string `xml:"ge" json:"ge,omitempty"`
			Gt string `xml:"gt" json:"gt,omitempty"`
			Eq string `xml:"eq" json:"eq,omitempty"`
			Le string `xml:"le" json:"le,omitempty"`
		} `xml:"range" json:"range,omitempty"`
	} `xml:"affects>package" json:"affects,omitempty"`
	Description struct {
		Xmlns string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Text  string `xml:",innerxml" json:"text,omitempty"`
	} `xml:"description>body" json:"description,omitempty"`
	References struct {
		URL       []string `xml:"url" json:"url,omitempty"`
		Cvename   []string `xml:"cvename" json:"cvename,omitempty"`
		FreebsdSA []string `xml:"freebsdsa" json:"freebsd_sa,omitempty"`
		FreebsdPR []string `xml:"freebsdpr" json:"freebsd_pr,omitempty"`
		Mlist     []struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Msgid string `xml:"msgid,attr" json:"msgid,omitempty"`
		} `xml:"mlist" json:"mlist,omitempty"`
		BID    []string `xml:"bid" json:"bid,omitempty"`
		CertSA []string `xml:"certsa" json:"cert_sa,omitempty"`
		CertVU []string `xml:"certvu" json:"cert_vu,omitempty"`
		USCertSA []string `xml:"uscertsa" json:"us_cert_sa,omitempty"` // There is no data with tag "uscertsa" at 2024-04-21
		USCertTA []string `xml:"uscertta" json:"us_cert_ta,omitempty"`
	} `xml:"references" json:"references,omitempty"`
	Dates struct {
		Discovery string `xml:"discovery" json:"discovery,omitempty"`
		Entry     string `xml:"entry" json:"entry,omitempty"`
		Modified  string `xml:"modified" json:"modified,omitempty"`
	} `xml:"dates" json:"dates,omitempty"`
	Cancelled *struct {
		Superseded string `xml:"superseded,attr" json:"superseded,omitempty"`
	} `xml:"cancelled" json:"cancelled,omitempty"`
}
