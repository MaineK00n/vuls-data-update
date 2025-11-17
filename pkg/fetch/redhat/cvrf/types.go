package cvrf

type CVRF struct {
	DocumentTitle struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Lang string `xml:"lang,attr" json:"lang,omitempty"`
	} `xml:"DocumentTitle" json:"documenttitle,omitzero"`
	DocumentType      string `xml:"DocumentType" json:"DocumentType,omitempty"`
	DocumentPublisher struct {
		Type             string `xml:"Type,attr" json:"type,omitempty"`
		ContactDetails   string `xml:"ContactDetails" json:"ContactDetails,omitempty"`
		IssuingAuthority string `xml:"IssuingAuthority" json:"IssuingAuthority,omitempty"`
	} `xml:"DocumentPublisher" json:"documentpublisher,omitzero"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID" json:"ID,omitempty"`
		} `xml:"Identification" json:"identification,omitzero"`
		Status          string `xml:"Status" json:"Status,omitempty"`
		Version         string `xml:"Version" json:"Version,omitempty"`
		RevisionHistory struct {
			Revision struct {
				Number      string `xml:"Number" json:"Number,omitempty"`
				Date        string `xml:"Date" json:"Date,omitempty"`
				Description string `xml:"Description" json:"Description,omitempty"`
			} `xml:"Revision" json:"revision,omitzero"`
		} `xml:"RevisionHistory" json:"revisionhistory,omitzero"`
		InitialReleaseDate string `xml:"InitialReleaseDate" json:"InitialReleaseDate,omitempty"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate" json:"CurrentReleaseDate,omitempty"`
		Generator          struct {
			Engine string `xml:"Engine" json:"Engine,omitempty"`
			Date   string `xml:"Date" json:"Date,omitempty"`
		} `xml:"Generator" json:"generator,omitzero"`
	} `xml:"DocumentTracking" json:"documenttracking,omitzero"`
	DocumentNotes struct {
		Note []struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Title   string `xml:"Title,attr" json:"title,omitempty"`
			Type    string `xml:"Type,attr" json:"type,omitempty"`
			Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
			Lang    string `xml:"lang,attr" json:"lang,omitempty"`
		} `xml:"Note" json:"note,omitempty"`
	} `xml:"DocumentNotes" json:"documentnotes,omitzero"`
	DocumentDistribution struct {
		Text string `xml:",chardata" json:"text,omitempty"`
		Lang string `xml:"lang,attr" json:"lang,omitempty"`
	} `xml:"DocumentDistribution" json:"documentdistribution,omitzero"`
	AggregateSeverity struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Namespace string `xml:"Namespace,attr" json:"namespace,omitempty"`
	} `xml:"AggregateSeverity" json:"aggregateseverity,omitzero"`
	DocumentReferences struct {
		Reference []struct {
			Type        string `xml:"Type,attr" json:"type,omitempty"`
			URL         string `xml:"URL" json:"URL,omitempty"`
			Description string `xml:"Description" json:"Description,omitempty"`
		} `xml:"Reference" json:"reference,omitempty"`
	} `xml:"DocumentReferences" json:"documentreferences,omitzero"`
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
			} `xml:"Note" json:"note,omitzero"`
		} `xml:"Notes" json:"notes,omitzero"`
		ReleaseDate  string `xml:"ReleaseDate" json:"ReleaseDate,omitempty"`
		Involvements struct {
			Involvement struct {
				Party  string `xml:"Party,attr" json:"party,omitempty"`
				Status string `xml:"Status,attr" json:"status,omitempty"`
			} `xml:"Involvement" json:"involvement,omitzero"`
		} `xml:"Involvements" json:"involvements,omitzero"`
		CVE          string `xml:"CVE" json:"CVE,omitempty"`
		Remediations struct {
			Remediation struct {
				Type        string `xml:"Type,attr" json:"type,omitempty"`
				Description struct {
					Text string `xml:",chardata" json:"text,omitempty"`
					Lang string `xml:"lang,attr" json:"lang,omitempty"`
				} `xml:"Description" json:"description,omitzero"`
				URL string `xml:"URL" json:"URL,omitempty"`
			} `xml:"Remediation" json:"remediation,omitzero"`
		} `xml:"Remediations" json:"remediations,omitzero"`
		References struct {
			Reference []struct {
				URL         string `xml:"URL" json:"URL,omitempty"`
				Description string `xml:"Description" json:"Description,omitempty"`
			} `xml:"Reference" json:"reference,omitempty"`
		} `xml:"References" json:"references,omitzero"`
		Threats struct {
			Threat struct {
				Type        string `xml:"Type,attr" json:"type,omitempty"`
				Description string `xml:"Description" json:"Description,omitempty"`
			} `xml:"Threat" json:"threat,omitzero"`
		} `xml:"Threats" json:"threats,omitzero"`
		DiscoveryDate   string `xml:"DiscoveryDate" json:"DiscoveryDate,omitempty"`
		ProductStatuses struct {
			Status struct {
				Type      string   `xml:"Type,attr" json:"type,omitempty"`
				ProductID []string `xml:"ProductID" json:"ProductID,omitempty"`
			} `xml:"Status" json:"status,omitzero"`
		} `xml:"ProductStatuses" json:"productstatuses,omitzero"`
		Acknowledgments struct {
			Acknowledgment struct {
				Description string `xml:"Description" json:"Description,omitempty"`
			} `xml:"Acknowledgment" json:"acknowledgment,omitzero"`
		} `xml:"Acknowledgments" json:"acknowledgments,omitzero"`
		CVSSScoreSets struct {
			ScoreSet struct {
				BaseScore string `xml:"BaseScore" json:"BaseScore,omitempty"`
				Vector    string `xml:"Vector" json:"Vector,omitempty"`
			} `xml:"ScoreSet" json:"scoreset,omitzero"`
		} `xml:"CVSSScoreSets" json:"cvssscoresets,omitzero"`
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
				} `xml:"FullProductName" json:"fullproductname,omitzero"`
			} `xml:"Branch" json:"branch,omitempty"`
			FullProductName struct {
				Text      string `xml:",chardata" json:"text,omitempty"`
				ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
				CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
			} `xml:"FullProductName" json:"fullproductname,omitzero"`
		} `xml:"Branch" json:"branch,omitempty"`
		Relationship []struct {
			ProductReference          string `xml:"ProductReference,attr" json:"productreference,omitempty"`
			RelationType              string `xml:"RelationType,attr" json:"relationtype,omitempty"`
			RelatesToProductReference string `xml:"RelatesToProductReference,attr" json:"relatestoproductreference,omitempty"`
			FullProductName           struct {
				Text      string `xml:",chardata" json:"text,omitempty"`
				ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
				CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
			} `xml:"FullProductName" json:"fullproductname,omitzero"`
		} `xml:"Relationship" json:"relationship,omitempty"`
	} `xml:"ProductTree" json:"producttree,omitzero"`
}
