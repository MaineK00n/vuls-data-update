package cvrf

type CVRF struct {
	DocumentTitle struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Lang string `xml:"lang,attr" json:"lang,omitempty"`
	} `xml:"DocumentTitle" json:"documenttitle,omitempty"`
	DocumentType      string `xml:"DocumentType"`
	DocumentPublisher struct {
		Type             string `xml:"Type,attr" json:"type,omitempty"`
		ContactDetails   string `xml:"ContactDetails"`
		IssuingAuthority string `xml:"IssuingAuthority"`
	} `xml:"DocumentPublisher" json:"documentpublisher,omitempty"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID"`
		} `xml:"Identification" json:"identification,omitempty"`
		Status          string `xml:"Status"`
		Version         string `xml:"Version"`
		RevisionHistory struct {
			Revision struct {
				Number      string `xml:"Number"`
				Date        string `xml:"Date"`
				Description string `xml:"Description"`
			} `xml:"Revision" json:"revision,omitempty"`
		} `xml:"RevisionHistory" json:"revisionhistory,omitempty"`
		InitialReleaseDate string `xml:"InitialReleaseDate"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate"`
		Generator          struct {
			Engine string `xml:"Engine"`
			Date   string `xml:"Date"`
		} `xml:"Generator" json:"generator,omitempty"`
	} `xml:"DocumentTracking" json:"documenttracking,omitempty"`
	DocumentNotes struct {
		Note []struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Title   string `xml:"Title,attr" json:"title,omitempty"`
			Type    string `xml:"Type,attr" json:"type,omitempty"`
			Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
			Lang    string `xml:"lang,attr" json:"lang,omitempty"`
		} `xml:"Note" json:"note,omitempty"`
	} `xml:"DocumentNotes" json:"documentnotes,omitempty"`
	DocumentDistribution struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Lang string `xml:"lang,attr" json:"lang,omitempty"`
	} `xml:"DocumentDistribution" json:"documentdistribution,omitempty"`
	AggregateSeverity struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Namespace string `xml:"Namespace,attr" json:"namespace,omitempty"`
	} `xml:"AggregateSeverity" json:"aggregateseverity,omitempty"`
	DocumentReferences struct {
		Reference []struct {
			Type        string `xml:"Type,attr" json:"type,omitempty"`
			URL         string `xml:"URL"`
			Description string `xml:"Description"`
		} `xml:"Reference" json:"reference,omitempty"`
	} `xml:"DocumentReferences" json:"documentreferences,omitempty"`
	Vulnerability []struct {
		Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
		Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Notes   struct {
			Note struct {
				Text    string `xml:",chardata" json:"text,omitempty"`
				Title   string `xml:"Title,attr" json:"title,omitempty"`
				Type    string `xml:"Type,attr" json:"type,omitempty"`
				Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
				Lang    string `xml:"lang,attr" json:"lang,omitempty"`
			} `xml:"Note" json:"note,omitempty"`
		} `xml:"Notes" json:"notes,omitempty"`
		ReleaseDate  string `xml:"ReleaseDate"`
		Involvements struct {
			Involvement struct {
				Party  string `xml:"Party,attr" json:"party,omitempty"`
				Status string `xml:"Status,attr" json:"status,omitempty"`
			} `xml:"Involvement" json:"involvement,omitempty"`
		} `xml:"Involvements" json:"involvements,omitempty"`
		CVE          string `xml:"CVE"`
		Remediations struct {
			Remediation struct {
				Type        string `xml:"Type,attr" json:"type,omitempty"`
				Description struct {
					Text string `xml:",chardata" json:"text,omitempty"`
					Lang string `xml:"lang,attr" json:"lang,omitempty"`
				} `xml:"Description" json:"description,omitempty"`
				URL string `xml:"URL"`
			} `xml:"Remediation" json:"remediation,omitempty"`
		} `xml:"Remediations" json:"remediations,omitempty"`
		References struct {
			Reference []struct {
				URL         string `xml:"URL"`
				Description string `xml:"Description"`
			} `xml:"Reference" json:"reference,omitempty"`
		} `xml:"References" json:"references,omitempty"`
		Threats struct {
			Threat struct {
				Type        string `xml:"Type,attr" json:"type,omitempty"`
				Description string `xml:"Description"`
			} `xml:"Threat" json:"threat,omitempty"`
		} `xml:"Threats" json:"threats,omitempty"`
		DiscoveryDate   string `xml:"DiscoveryDate"`
		ProductStatuses struct {
			Status struct {
				Type      string   `xml:"Type,attr" json:"type,omitempty"`
				ProductID []string `xml:"ProductID"`
			} `xml:"Status" json:"status,omitempty"`
		} `xml:"ProductStatuses" json:"productstatuses,omitempty"`
		Acknowledgments struct {
			Acknowledgment struct {
				Description string `xml:"Description"`
			} `xml:"Acknowledgment" json:"acknowledgment,omitempty"`
		} `xml:"Acknowledgments" json:"acknowledgments,omitempty"`
		CVSSScoreSets struct {
			ScoreSet struct {
				BaseScore string `xml:"BaseScore"`
				Vector    string `xml:"Vector"`
			} `xml:"ScoreSet" json:"scoreset,omitempty"`
		} `xml:"CVSSScoreSets" json:"cvssscoresets,omitempty"`
	} `xml:"Vulnerability" json:"vulnerability,omitempty"`
	ProductTree struct {
		Xmlns  string `xml:"xmlns,attr" json:"xmlns,omitempty"`
		Branch []struct {
			Type   string `xml:"Type,attr" json:"type,omitempty"`
			Name   string `xml:"Name,attr" json:"name,omitempty"`
			Branch []struct {
				Type            string `xml:"Type,attr" json:"type,omitempty"`
				Name            string `xml:"Name,attr" json:"name,omitempty"`
				FullProductName struct {
					Text      string `xml:",chardata" json:"text,omitempty"`
					ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
					CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
				} `xml:"FullProductName" json:"fullproductname,omitempty"`
			} `xml:"Branch" json:"branch,omitempty"`
			FullProductName struct {
				Text      string `xml:",chardata" json:"text,omitempty"`
				ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
				CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
			} `xml:"FullProductName" json:"fullproductname,omitempty"`
		} `xml:"Branch" json:"branch,omitempty"`
		Relationship []struct {
			ProductReference          string `xml:"ProductReference,attr" json:"productreference,omitempty"`
			RelationType              string `xml:"RelationType,attr" json:"relationtype,omitempty"`
			RelatesToProductReference string `xml:"RelatesToProductReference,attr" json:"relatestoproductreference,omitempty"`
			FullProductName           struct {
				Text      string `xml:",chardata" json:"text,omitempty"`
				ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
				CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
			} `xml:"FullProductName" json:"fullproductname,omitempty"`
		} `xml:"Relationship" json:"relationship,omitempty"`
	} `xml:"ProductTree" json:"producttree,omitempty"`
}
