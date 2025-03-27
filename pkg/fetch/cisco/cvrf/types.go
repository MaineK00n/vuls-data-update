package cvrf

import "encoding/xml"

type CVRF struct {
	XMLName           xml.Name `xml:"cvrfdoc" json:"xml_name,omitempty"`
	DocumentTitle     string   `xml:"DocumentTitle" json:"document_title"`
	DocumentType      string   `xml:"DocumentType" json:"document_type"`
	DocumentPublisher struct {
		Type             string  `xml:"Type,attr" json:"type"` // enum: Vendor, Discoverer, Coordinator, User, Other
		VendorID         *string `xml:"VendorID,attr,omitempty" json:"vendor_id,omitempty"`
		ContactDetails   *string `xml:"ContactDetails,omitempty" json:"contact_details,omitempty"`
		IssuingAuthority *string `xml:"IssuingAuthority,omitempty" json:"issuing_authority,omitempty"`
	} `xml:"DocumentPublisher" json:"document_publisher,omitempty"`
	DocumentTracking struct {
		Identification struct {
			ID    string   `xml:"ID" json:"id"`
			Alias []string `xml:"Alias,omitempty" json:"alias,omitempty"`
		} `xml:"Identification" json:"identification"`
		Status          string  `xml:"Status" json:"status"` // enum: Draft, Interim, Final
		Version         Version `xml:"Version" json:"version"`
		RevisionHistory struct {
			Revision []struct {
				Number      Version `xml:"Number" json:"number"`
				Date        string  `xml:"Date" json:"date"`
				Description string  `xml:"Description" json:"description"`
			} `xml:"Revision" json:"revision"`
		} `xml:"RevisionHistory" json:"revisionhistory"`
		InitialReleaseDate string `xml:"InitialReleaseDate" json:"initial_release_date"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate" json:"current_release_date"`
		Generator          *struct {
			Engine string `xml:"Engine" json:"engine"`
			Date   string `xml:"Date" json:"date"`
		} `xml:"Generator,omitempty" json:"generator,omitempty"`
	} `xml:"DocumentTracking" json:"document_tracking"`
	DocumentNotes *struct {
		Note []Note `xml:"Note" json:"note"`
	} `xml:"DocumentNotes,omitempty" json:"document_notes,omitempty"`
	DocumentDistribution *struct {
		Lang *Lang  `xml:"xml:lang,attr,omitempty" json:"lang,omitempty"`
		Text string `xml:",chardata" json:"text"`
	} `xml:"DocumentDistribution,omitempty" json:"document_distribution,omitempty"`
	AggregateSeverity *struct {
		NameSpace *string `xml:"Namespace,attr,omitempty" json:"name_space,omitempty"`
		Text      string  `xml:",chardata" json:"text"`
	} `xml:"AggregateSeverity,omitempty" json:"aggregate_severity,omitempty"`
	DocumentReferences *struct {
		Reference []Reference `xml:"Reference" json:"reference"`
	} `xml:"DocumentReferences,omitempty" json:"document_references,omitempty"`
	Acknowledgments *struct {
		Acknowledgment []Acknowledgment `xml:"Acknowledgment" json:"acknowledgment"`
	} `xml:"Acknowledgments,omitempty" json:"acknowledgments,omitempty"`
	ProductTree *struct {
		Branch          []Branch          `xml:"Branch,omitempty" json:"branch,omitempty"`
		FullProductName []FullProductName `xml:"FullProductName,omitempty" json:"full_product_name,omitempty"`
		Relationship    []Relationship    `xml:"Relationship,omitempty" json:"relationship,omitempty"`
		ProductGroups   *struct {
			Group []struct {
				GroupID     string   `xml:"GroupID,attr" json:"group_id"`
				Description *string  `xml:"Description,omitempty" json:"description,omitempty"`
				ProductID   []string `xml:"ProductID" json:"product_id"`
			} `xml:"Group" json:"group"`
		} `xml:"ProductGroups,omitempty" json:"product_groups,omitempty"`
	} `xml:"ProductTree,omitempty" json:"product_tree,omitempty"`
	Vulnerabilities []struct {
		Ordinal int     `xml:"Ordinal,attr" json:"ordinal"`
		Title   *string `xml:"Title,omitempty" json:"title,omitempty"`
		ID      *string `xml:"ID,omitempty" json:"id,omitempty"`
		Notes   *struct {
			Note []Note `xml:"Note" json:"note"`
		} `xml:"Notes,omitempty" json:"notes,omitempty"`
		DiscoveryDate *string `xml:"DiscoveryDate,omitempty" json:"discovery_date,omitempty"`
		ReleaseDate   *string `xml:"ReleaseDate,omitempty" json:"release_date,omitempty"`
		Involvements  *struct {
			Involvement []struct {
				Party       string  `xml:"Party,attr" json:"party"`   // enum: Vendor, Discoverer, Coordinator, Other
				Status      string  `xml:"Status,attr" json:"status"` // enum: Completed, Contact Attempted, Disputed, In Progress, Not Contacted, Open
				Description *string `xml:"Description,omitempty" json:"description,omitempty"`
			} `xml:"Involvement" json:"involvement"`
		} `xml:"Involvements,omitempty" json:"involvements,omitempty"`
		CVE *string `xml:"CVE,omitempty" json:"cve,omitempty"` // pattern: CVE-[0-9\-]+
		CWE []struct {
			ID   string `xml:"ID" json:"id"` // pattern: CWE-[1-9]\d{0,5}
			Text string `xml:",chardata" json:"text"`
		} `xml:"CWE,omitempty" json:"cwe,omitempty"`
		ProductStatuses *struct {
			Status []struct {
				Type      string   `xml:"Type,attr" json:"type"` // enum: First Affected, Known Affected,  Known Not Affected, First Fixed, Fixed, Recommended, Last Affected
				ProductID []string `xml:"ProductID" json:"product_id"`
			} `xml:"Status" json:"status"`
		} `xml:"ProductStatuses,omitempty" json:"product_statuses,omitempty"`
		Threats *struct {
			Threat []struct {
				Type        string   `xml:"Type,attr" json:"type"` // enum: Impact, Exploit Status, Target Set
				Date        *string  `xml:"Date,attr,omitempty" json:"date,omitempty"`
				Description string   `xml:"Description" json:"description"`
				ProductID   []string `xml:"ProductID,omitempty" json:"product_id,omitempty"`
				GroupID     []string `xml:"GroupID,omitempty" json:"group_id,omitempty"`
			} `xml:"Threat" json:"threat"`
		} `xml:"Threats,omitempty" json:"threats,omitempty"`
		CVSSScoreSets *struct {
			ScoreSetV2 []struct {
				BaseScoreV2          string   `xml:"BaseScoreV2" json:"base_score_v2"`
				TemporalScoreV2      *string  `xml:"TemporalScoreV2,omitempty" json:"temporal_score_v2,omitempty"`
				EnvironmentalScoreV2 *string  `xml:"EnvironmentalScoreV2,omitempty" json:"environmental_score_v2,omitempty"`
				VectorV2             *string  `xml:"VectorV2,omitempty" json:"vector_v2,omitempty"`
				ProductID            []string `xml:"ProductID,omitempty" json:"product_id,omitempty"`
			} `xml:"ScoreSetV2,omitempty" json:"score_set_v2,omitempty"`
			ScoreSetV3 []struct {
				BaseScoreV3          string   `xml:"BaseScoreV3" json:"base_score_v3"`
				TemporalScoreV3      *string  `xml:"TemporalScoreV3,omitempty" json:"temporal_score_v3,omitempty"`
				EnvironmentalScoreV3 *string  `xml:"EnvironmentalScoreV3,omitempty" json:"environmental_score_v3,omitempty"`
				VectorV3             *string  `xml:"VectorV3,omitempty" json:"vector_v3,omitempty"`
				ProductID            []string `xml:"ProductID,omitempty" json:"product_id,omitempty"`
			} `xml:"ScoreSetV3,omitempty" json:"score_set_v3,omitempty"`
		} `xml:"CVSSScoreSets,omitempty" json:"cvss_score_sets,omitempty"`
		Remediations *struct {
			Remediation []struct {
				Type        string   `xml:"Type,attr" json:"type"` // enum: Workaround, Mitigation, Vendor Fix, None Available, Will Not Fix
				Date        *string  `xml:"Date,attr,omitempty" json:"date,omitempty"`
				Description string   `xml:"Description" json:"description"`
				Entitlement []string `xml:"Entitlement,omitempty" json:"entitlement,omitempty"`
				URL         *string  `xml:"URL,omitempty" json:"url,omitempty"`
				ProductID   []string `xml:"ProductID,omitempty" json:"product_id,omitempty"`
				GroupID     []string `xml:"GroupID,omitempty" json:"group_id,omitempty"`
			} `xml:"Remediation" json:"remediation"`
		} `xml:"Remediations,omitempty" json:"remediations,omitempty"`
		References *struct {
			Reference []Reference `xml:"Reference" json:"reference"`
		} `xml:"References,omitempty" json:"references,omitempty"`
		Acknowledgments *struct {
			Acknowledgment []Acknowledgment `xml:"Acknowledgment" json:"acknowledgment"`
		} `xml:"Acknowledgments,omitempty" json:"acknowledgments,omitempty"`
	} `xml:"Vulnerability,omitempty" json:"vulnerabilities,omitempty"`
}

type Version string // pattern: (0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,3}

type Lang string

type Note struct {
	Type     string  `xml:"Type,attr" json:"type"` // enum: Description, Details, FAQ, General, Legal Disclaimer, Other, Summary
	Ordinal  int     `xml:"Ordinal,attr" json:"ordinal"`
	Title    *string `xml:"Title,attr,omitempty" json:"title,omitempty"`
	Audience *string `xml:"Audience,attr,omitempty" json:"audience,omitempty"`
	Text     string  `xml:",chardata" json:"text"`
}

type Reference struct {
	Type        string `xml:"Type,attr" json:"type"` // enum: External, Self
	URL         string `xml:"URL" json:"url"`
	Description struct {
		Lang *Lang  `xml:"xml:lang,attr,omitempty" json:"lang,omitempty"`
		Text string `xml:",chardata" json:"text"`
	} `xml:"Description" json:"description"`
}

type Acknowledgment struct {
	Name         []string `xml:"Name,omitempty" json:"name,omitempty"`
	Organization []string `xml:"Organization,omitempty" json:"organization,omitempty"`
	Description  *struct {
		Lang *Lang  `xml:"xml:lang,attr,omitempty" json:"lang,omitempty"`
		Text string `xml:",chardata" json:"text"`
	} `xml:"Description,omitempty" json:"description,omitempty"`
	URL []string `xml:"URL,omitempty" json:"url,omitempty"`
}

type Branch struct {
	Type            string           `xml:"Type,attr" json:"type"` // enum: Architecture Host Name Language Legacy Patch Level Product Family Product Name Product Version Service Pack Specification Vendor
	Name            string           `xml:"Name,attr" json:"name"`
	FullProductName *FullProductName `xml:"FullProductName,omitempty" json:"full_product_name,omitempty"`
	Branch          []*Branch        `xml:"Branch,omitempty" json:"branch,omitempty"`
}

type FullProductName struct {
	ProductID string  `xml:"ProductID,attr" json:"product_id"`
	CPE       *string `xml:"CPE,attr,omitempty" json:"cpe,omitempty"`
	Text      string  `xml:",chardata" json:"text"`
}

type Relationship struct {
	ProductReference          string            `xml:"ProductReference,attr" json:"product_reference"`
	RelationType              string            `xml:"RelationType,attr" json:"relation_type"` // enum: Default Component Of, External Component Of, Installed On, Installed With, Optional Component Of
	RelatesToProductReference string            `xml:"RelatesToProductReference,attr" json:"relates_to_product_reference"`
	FullProductName           []FullProductName `xml:"FullProductName" json:"full_product_name"`
}
