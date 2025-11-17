package vex

type VEX struct {
	Document        Document        `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Acknowledgment struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLs         []string `json:"urls,omitempty"`
}

type Branch struct {
	Branches []Branch         `json:"branches,omitempty"`
	Category string           `json:"category"` // enum: architecture, host_name, language, legacy, patch_level, product_family, product_name, product_version, product_version_range, service_pack, specification, vendor
	Name     string           `json:"name"`
	Product  *FullProductName `json:"product,omitempty"`
}

type FullProductName struct {
	Name                        string    `json:"name"`
	ProductID                   ProductID `json:"product_id"`
	ProductIdentificationHelper *struct {
		CPE    string `json:"cpe,omitempty"`
		Hashes []struct {
			FileHashes []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"file_hashes,omitempty"`
			Filename string `json:"filename"`
		} `json:"hashes,omitempty"`
		ModuleNumbers []string `json:"module_numbers,omitempty"`
		PURL          string   `json:"purl,omitempty"`
		SBOMURLs      []string `json:"sbom_urls,omitempty"`
		SerialNumbers []string `json:"serial_numbers,omitempty"`
		SKUs          []string `json:"skus,omitempty"`
		XGenericURIs  []struct {
			Namespace string `json:"namespace"`
			URI       string `json:"uri"`
		} `json:"x_generic_uris,omitempty"`
	} `json:"product_identification_helper,omitempty"`
}

type Lang string // ^(([A-Za-z]{2,3}(-[A-Za-z]{3}(-[A-Za-z]{3}){0,2})?|[A-Za-z]{4,8})(-[A-Za-z]{4})?(-([A-Za-z]{2}|[0-9]{3}))?(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(-[A-WY-Za-wy-z0-9](-[A-Za-z0-9]{2,8})+)*(-[Xx](-[A-Za-z0-9]{1,8})+)?|[Xx](-[A-Za-z0-9]{1,8})+|[Ii]-[Dd][Ee][Ff][Aa][Uu][Ll][Tt]|[Ii]-[Mm][Ii][Nn][Gg][Oo])$

type Note struct {
	Audience string `json:"audience,omitempty"`
	Category string `json:"category"` // enum: description, details, faq, general, legal_disclaimer, other, summary
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type ProductGroupID string

type ProductID string

type Reference struct {
	Category string `json:"category,omitempty"` // enum: external, self
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type Version string // pattern: ^(0|[1-9][0-9]*)$|^((0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?)$

type Document struct {
	Acknowledgments   []Acknowledgment `json:"acknowledgments,omitempty"`
	AggregateSeverity *struct {
		Namespace string `json:"namespace,omitempty"`
		Text      string `json:"text"`
	} `json:"aggregate_severity,omitempty"`
	Category     string `json:"category"` // csaf_base, csaf_security_incident_response, csaf_informational_advisory, csaf_security_advisory, csaf_vex
	CSAFVersion  string `json:"csaf_version"`
	Distribution *struct {
		Text string `json:"text,omitempty"`
		TLP  *struct {
			Label string `json:"label"` // enum: AMBER, GREEN, RED, WHITE
			URL   string `json:"url,omitempty"`
		} `json:"tlp,omitempty"`
	} `json:"distribution,omitempty"`
	Lang      Lang   `json:"lang,omitempty"`
	Notes     []Note `json:"notes,omitempty"`
	Publisher struct {
		Category         string `json:"category"` // enum: coordinator, discoverer, other, translator, user, vendor
		ContactDetails   string `json:"contact_details,omitempty"`
		IssuingAuthority string `json:"issuing_authority,omitempty"`
		Name             string `json:"name"`
		Namespace        string `json:"namespace"`
	} `json:"publisher"`
	References []Reference `json:"references,omitempty"`
	SourceLang Lang        `json:"source_lang,omitempty"`
	Title      string      `json:"title"`
	Tracking   struct {
		Aliases            []string `json:"aliases,omitempty"`
		CurrentReleaseDate string   `json:"current_release_date"`
		Generator          struct {
			Date   string `json:"date,omitempty"`
			Engine struct {
				Name    string `json:"name"`
				Version string `json:"version,omitempty"`
			} `json:"engine"`
		} `json:"generator,omitzero"`
		ID                 string `json:"id"`
		InitialReleaseDate string `json:"initial_release_date"`
		RevisionHistory    []struct {
			Date          string  `json:"date"`
			LegacyVersion string  `json:"legacy_version,omitempty"`
			Number        Version `json:"number"`
			Summary       string  `json:"summary"`
		} `json:"revision_history"`
		Status  string  `json:"status"` // enum: draft, final, interim
		Version Version `json:"version"`
	} `json:"tracking"`
}

type ProductTree struct {
	Branches         []Branch          `json:"branches,omitempty"`
	FullProductNames []FullProductName `json:"full_product_names,omitempty"`
	ProductGroups    []struct {
		GroupID    ProductGroupID `json:"group_id"`
		ProductIDs []ProductID    `json:"product_ids"`
		Summary    string         `json:"summary,omitempty"`
	} `json:"product_groups,omitempty"`
	Relationships []Relationship `json:"relationships,omitempty"`
}

type Relationship struct {
	Category                  string          `json:"category"` // enum: default_component_of, external_component_of, installed_on, installed_with, optional_component_of
	FullProductName           FullProductName `json:"full_product_name"`
	ProductReference          ProductID       `json:"product_reference"`
	RelatesToProductReference ProductID       `json:"relates_to_product_reference"`
}

type Vulnerability struct {
	Acknowledgments []Acknowledgment `json:"acknowledgments,omitempty"`
	CVE             string           `json:"cve,omitempty"`
	CWE             *struct {
		ID   string `json:"id"` // pattern: ^CWE-[1-9]\\d{0,5}$
		Name string `json:"name"`
	} `json:"cwe,omitempty"`
	DiscoveryDate string `json:"discovery_date,omitempty"`
	Flags         []struct {
		Date       string           `json:"date,omitempty"`
		GroupIDs   []ProductGroupID `json:"group_ids,omitempty"`
		Label      string           `json:"label"` // enum: component_not_present, inline_mitigations_already_exist, vulnerable_code_cannot_be_controlled_by_adversary, vulnerable_code_not_in_execute_path, vulnerable_code_not_present
		ProductIDs []ProductID      `json:"product_ids,omitempty"`
	} `json:"flags,omitempty"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids,omitempty"`
	Involvements []struct {
		Date    string `json:"date,omitempty"`
		Party   string `json:"party"`  // enum: coordinator, discoverer, other, user, vendor
		Status  string `json:"status"` // enum: completed, contact_attempted, disputed, in_progress, not_contacted, open
		Summary string `json:"summary,omitempty"`
	} `json:"involvements,omitempty"`
	Notes         []Note `json:"notes,omitempty"`
	ProductStatus struct {
		FirstAffected      []ProductID `json:"first_affected,omitempty"`
		FirstFixed         []ProductID `json:"first_fixed,omitempty"`
		Fixed              []ProductID `json:"fixed,omitempty"`
		KnownAffected      []ProductID `json:"known_affected,omitempty"`
		KnownNotAffected   []ProductID `json:"known_not_affected,omitempty"`
		LastAffected       []ProductID `json:"last_affected,omitempty"`
		Recommended        []ProductID `json:"recommended,omitempty"`
		UnderInvestigation []ProductID `json:"under_investigation,omitempty"`
	} `json:"product_status,omitzero"`
	References []struct {
		Category string `json:"category,omitempty"`
		Summary  string `json:"summary,omitempty"`
		URL      string `json:"url,omitempty"`
	} `json:"references,omitempty"`
	ReleaseDate  string `json:"release_date,omitempty"`
	Remediations []struct {
		Category        string           `json:"category"` // enum: mitigation, no_fix_planned, none_available, vendor_fix, workaround
		Date            string           `json:"date,omitempty"`
		Details         string           `json:"details"`
		Entitlements    []string         `json:"entitlements,omitempty"`
		GroupIDs        []ProductGroupID `json:"group_ids,omitempty"`
		ProductIDs      []ProductID      `json:"product_ids,omitempty"`
		RestartRequired *struct {
			Category string `json:"category"` // enum: connected, dependencies, machine, none, parent, service, system, vulnerable_component, zone
			Details  string `json:"details,omitempty"`
		} `json:"restart_required,omitempty"`
		URL string `json:"url,omitempty"`
	} `json:"remediations,omitempty"`
	Scores []struct {
		CvssV2 *struct {
			AccessComplexity      string  `json:"accessComplexity,omitempty"`
			AccessVector          string  `json:"accessVector,omitempty"`
			Authentication        string  `json:"authentication,omitempty"`
			AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
			BaseScore             float64 `json:"baseScore"`
			ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
			IntegrityImpact       string  `json:"integrityImpact,omitempty"`
			VectorString          string  `json:"vectorString"`
			Version               string  `json:"version"`
		} `json:"cvss_v2,omitempty"`
		CvssV3 *struct {
			AttackComplexity      string  `json:"attackComplexity,omitempty"`
			AttackVector          string  `json:"attackVector,omitempty"`
			AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
			BaseScore             float64 `json:"baseScore"`
			BaseSeverity          string  `json:"baseSeverity"`
			ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
			IntegrityImpact       string  `json:"integrityImpact,omitempty"`
			PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
			Scope                 string  `json:"scope,omitempty"`
			UserInteraction       string  `json:"userInteraction,omitempty"`
			VectorString          string  `json:"vectorString"`
			Version               string  `json:"version"`
		} `json:"cvss_v3,omitempty"`
		Products []ProductID `json:"products"`
	} `json:"scores,omitempty"`
	Threats []struct {
		Category   string           `json:"category"` // enum: exploit_status, impact, target_set
		Date       string           `json:"date,omitempty"`
		Details    string           `json:"details"`
		GroupIDs   []ProductGroupID `json:"group_ids,omitempty"`
		ProductIDs []ProductID      `json:"product_ids,omitempty"`
	} `json:"threats,omitempty"`
	Title string `json:"title,omitempty"`
}
