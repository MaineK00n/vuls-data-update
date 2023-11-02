package v5

type cve struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		AssignerOrgID     string  `json:"assignerOrgId"`
		AssignerShortName *string `json:"assignerShortName,omitempty"`
		CveID             string  `json:"cveId"`
		DatePublished     *string `json:"datePublished,omitempty"`
		DateRejected      *string `json:"dateRejected,omitempty"`
		DateReserved      string  `json:"dateReserved"`
		DateUpdated       *string `json:"dateUpdated,omitempty"`
		RequesterUserID   *string `json:"requesterUserId,omitempty"`
		Serial            *int    `json:"serial,omitempty"`
		State             string  `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			Affected []struct {
				CollectionURL   *string  `json:"collectionURL,omitempty"`
				CollectionURL2  *string  `json:"collection_url,omitempty"`
				Cpe             []string `json:"cpe,omitempty"`
				Cpes            []string `json:"cpes,omitempty"`
				DefaultStatus   *string  `json:"defaultStatus,omitempty"`
				Modules         []string `json:"modules,omitempty"`
				PackageName     *string  `json:"packageName,omitempty"`
				Platforms       []string `json:"platforms,omitempty"`
				Product         *string  `json:"product,omitempty"`
				ProgramFiles    []string `json:"programFiles,omitempty"`
				ProgramRoutines []struct {
					Name string `json:"name"`
				} `json:"programRoutines,omitempty"`
				Repo     *string `json:"repo,omitempty"`
				Vendor   *string `json:"vendor,omitempty"`
				Versions []struct {
					Changes []struct {
						At     string `json:"at"`
						Status string `json:"status"`
					} `json:"changes,omitempty"`
					GreaterThanOrEqual *string `json:"greaterThanOrEqual,omitempty"`
					LessThan           *string `json:"lessThan,omitempty"`
					LessThanOrEqual    *string `json:"lessThanOrEqual,omitempty"`
					Status             string  `json:"status"`
					Version            string  `json:"version"`
					VersionType        *string `json:"versionType,omitempty"`
				} `json:"versions,omitempty"`
				XRedhatStatus *string `json:"x_redhatStatus,omitempty"`
			} `json:"affected,omitempty"`
			Configurations []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"configurations,omitempty"`
			Credits []struct {
				Lang  string  `json:"lang"`
				Type  *string `json:"type,omitempty"`
				User  *string `json:"user,omitempty"`
				Value string  `json:"value"`
			} `json:"credits,omitempty"`
			DateAssigned *string `json:"dateAssigned,omitempty"`
			DatePublic   *string `json:"datePublic,omitempty"`
			Descriptions []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"descriptions,omitempty"`
			Exploits []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"exploits,omitempty"`
			Impacts []struct {
				CapecID      *string `json:"capecId,omitempty"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"impacts,omitempty"`
			Metrics []struct {
				CvssV20 *struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					BaseScore             float64 `json:"baseScore"`
					AccessComplexity      *string `json:"accessComplexity,omitempty"`
					AccessVector          *string `json:"accessVector,omitempty"`
					Authentication        *string `json:"authentication,omitempty"`
					AvailabilityImpact    *string `json:"availabilityImpact,omitempty"`
					ConfidentialityImpact *string `json:"confidentialityImpact,omitempty"`
					IntegrityImpact       *string `json:"integrityImpact,omitempty"`
				} `json:"cvssV2_0,omitempty"`
				CvssV30 *struct {
					Version               string   `json:"version"`
					VectorString          string   `json:"vectorString"`
					BaseScore             float64  `json:"baseScore"`
					BaseSeverity          string   `json:"baseSeverity"`
					AttackComplexity      *string  `json:"attackComplexity,omitempty"`
					AttackVector          *string  `json:"attackVector,omitempty"`
					AvailabilityImpact    *string  `json:"availabilityImpact,omitempty"`
					ConfidentialityImpact *string  `json:"confidentialityImpact,omitempty"`
					ExploitCodeMaturity   *string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact       *string  `json:"integrityImpact,omitempty"`
					PrivilegesRequired    *string  `json:"privilegesRequired,omitempty"`
					RemediationLevel      *string  `json:"remediationLevel,omitempty"`
					ReportConfidence      *string  `json:"reportConfidence,omitempty"`
					Scope                 *string  `json:"scope,omitempty"`
					TemporalScore         *float64 `json:"temporalScore,omitempty"`
					TemporalSeverity      *string  `json:"temporalSeverity,omitempty"`
					UserInteraction       *string  `json:"userInteraction,omitempty"`
				} `json:"cvssV3_0,omitempty"`
				CvssV31 *struct {
					Version                       string   `json:"version"`
					VectorString                  string   `json:"vectorString"`
					BaseScore                     float64  `json:"baseScore"`
					BaseSeverity                  string   `json:"baseSeverity"`
					AttackComplexity              *string  `json:"attackComplexity,omitempty"`
					AttackVector                  *string  `json:"attackVector,omitempty"`
					AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
					AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
					ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
					ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
					EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
					EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
					ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
					IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
					ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
					ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
					ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
					ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
					ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
					ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
					ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
					ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
					PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
					RemediationLevel              *string  `json:"remediationLevel,omitempty"`
					ReportConfidence              *string  `json:"reportConfidence,omitempty"`
					Scope                         *string  `json:"scope,omitempty"`
					TemporalScore                 *float64 `json:"temporalScore,omitempty"`
					TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
					UserInteraction               *string  `json:"userInteraction,omitempty"`
				} `json:"cvssV3_1,omitempty"`
				Format    *string     `json:"format,omitempty"`
				Other     interface{} `json:"other,omitempty"`
				Scenario  *string     `json:"scenario,omitempty"`
				Scenarios []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"scenarios,omitempty"`
			} `json:"metrics,omitempty"`
			ProblemTypes []struct {
				Descriptions []struct {
					CWEID       *string `json:"CWE-ID,omitempty"`
					CweID       *string `json:"cweId,omitempty"`
					Cweid       *string `json:"cweid,omitempty"`
					Description string  `json:"description"`
					Lang        string  `json:"lang"`
					Reference   *struct {
						URL string `json:"url"`
					} `json:"reference,omitempty"`
					Type *string `json:"type,omitempty"`
				} `json:"descriptions"`
			} `json:"problemTypes,omitempty"`
			ProviderMetadata struct {
				DateUpdated *string `json:"dateUpdated,omitempty"`
				OrgID       string  `json:"orgId"`
				ShortName   *string `json:"shortName,omitempty"`
			} `json:"providerMetadata"`
			References []struct {
				Name      *string  `json:"name,omitempty"`
				Refsource *string  `json:"refsource,omitempty"`
				Tags      []string `json:"tags,omitempty"`
				URL       string   `json:"url"`
			} `json:"references,omitempty"`
			RejectedReasons []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"rejectedReasons,omitempty"`
			ReplacedBy []string `json:"replacedBy,omitempty"`
			Solutions  []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"solutions,omitempty"`
			Source           interface{} `json:"source,omitempty"`
			Tags             []string    `json:"tags,omitempty"`
			TaxonomyMappings []struct {
				TaxonomyName      string `json:"taxonomyName"`
				TaxonomyVersion   string `json:"taxonomyVersion"`
				TaxonomyRelations []struct {
					RelationshipName  string `json:"relationshipName"`
					RelationshipValue string `json:"relationshipValue"`
					TaxonomyID        string `json:"taxonomyId"`
				} `json:"taxonomyRelations"`
			} `json:"taxonomyMappings,omitempty"`
			Timeline []struct {
				Lang  string `json:"lang"`
				Time  string `json:"time"`
				Value string `json:"value"`
			} `json:"timeline,omitempty"`
			Title       *string `json:"title,omitempty"`
			Workarounds []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"workarounds,omitempty"`
			XConverterErrors map[string]struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			} `json:"x_ConverterErrors,omitempty"`
			XGenerator      interface{} `json:"x_generator,omitempty"`
			XLegacyV4Record interface{} `json:"x_legacyV4Record,omitempty"`
			XRedHatCweChain *string     `json:"x_redHatCweChain,omitempty"`
			XRedhatCweChain *string     `json:"x_redhatCweChain,omitempty"`
		} `json:"cna"`
	} `json:"containers"`
}

type Vulnerability struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CveMetadata CveMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

type CveMetadata struct {
	AssignerOrgID     string  `json:"assignerOrgId"`
	AssignerShortName *string `json:"assignerShortName,omitempty"`
	CveID             string  `json:"cveId"`
	DatePublished     *string `json:"datePublished,omitempty"`
	DateRejected      *string `json:"dateRejected,omitempty"`
	DateReserved      string  `json:"dateReserved"`
	DateUpdated       *string `json:"dateUpdated,omitempty"`
	RequesterUserID   *string `json:"requesterUserId,omitempty"`
	Serial            *int    `json:"serial,omitempty"`
	State             string  `json:"state"`
}

type Containers struct {
	Cna Cna `json:"cna"`
}

type Cna struct {
	Affected         []Affected                 `json:"affected,omitempty"`
	Configurations   []Configuration            `json:"configurations,omitempty"`
	Credits          []Credit                   `json:"credits,omitempty"`
	DateAssigned     *string                    `json:"dateAssigned,omitempty"`
	DatePublic       *string                    `json:"datePublic,omitempty"`
	Descriptions     []Description              `json:"descriptions,omitempty"`
	Exploits         []Exploit                  `json:"exploits,omitempty"`
	Impacts          []Impact                   `json:"impacts,omitempty"`
	Metrics          []Metric                   `json:"metrics,omitempty"`
	ProblemTypes     []ProblemType              `json:"problemTypes,omitempty"`
	ProviderMetadata ProviderMetadata           `json:"providerMetadata"`
	References       []Reference                `json:"references,omitempty"`
	RejectedReasons  []RejectedReason           `json:"rejectedReasons,omitempty"`
	ReplacedBy       []string                   `json:"replacedBy,omitempty"`
	Solutions        []Solution                 `json:"solutions,omitempty"`
	Source           interface{}                `json:"source,omitempty"`
	Tags             []string                   `json:"tags,omitempty"`
	TaxonomyMappings []TaxonomyMapping          `json:"taxonomyMappings,omitempty"`
	Timeline         []Timeline                 `json:"timeline,omitempty"`
	Title            *string                    `json:"title,omitempty"`
	Workarounds      []Workaround               `json:"workarounds,omitempty"`
	XConverterErrors map[string]XConverterError `json:"x_ConverterErrors,omitempty"`
	XGenerator       interface{}                `json:"x_generator,omitempty"`
	XLegacyV4Record  interface{}                `json:"x_legacyV4Record,omitempty"`
	XRedHatCweChain  *string                    `json:"x_redhatCweChain,omitempty"`
}

type Affected struct {
	CollectionURL   *string  `json:"collectionURL,omitempty"`
	Cpes            []string `json:"cpes,omitempty"`
	DefaultStatus   *string  `json:"defaultStatus,omitempty"`
	Modules         []string `json:"modules,omitempty"`
	PackageName     *string  `json:"packageName,omitempty"`
	Platforms       []string `json:"platforms,omitempty"`
	Product         *string  `json:"product,omitempty"`
	ProgramFiles    []string `json:"programFiles,omitempty"`
	ProgramRoutines []struct {
		Name string `json:"name"`
	} `json:"programRoutines,omitempty"`
	Repo     *string `json:"repo,omitempty"`
	Vendor   *string `json:"vendor,omitempty"`
	Versions []struct {
		Changes []struct {
			At     string `json:"at"`
			Status string `json:"status"`
		} `json:"changes,omitempty"`
		GreaterThanOrEqual *string `json:"greaterThanOrEqual,omitempty"`
		LessThan           *string `json:"lessThan,omitempty"`
		LessThanOrEqual    *string `json:"lessThanOrEqual,omitempty"`
		Status             string  `json:"status"`
		Version            string  `json:"version"`
		VersionType        *string `json:"versionType,omitempty"`
	} `json:"versions,omitempty"`
	XRedhatStatus *string `json:"x_redhatStatus,omitempty"`
}

type Configuration struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type Credit struct {
	Lang  string  `json:"lang"`
	Type  *string `json:"type,omitempty"`
	User  *string `json:"user,omitempty"`
	Value string  `json:"value"`
}

type Description struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type Exploit struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type Impact struct {
	CapecID      *string `json:"capecId,omitempty"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
}

type Metric struct {
	CvssV20 *struct {
		Version               string  `json:"version"`
		VectorString          string  `json:"vectorString"`
		BaseScore             float64 `json:"baseScore"`
		AccessComplexity      *string `json:"accessComplexity,omitempty"`
		AccessVector          *string `json:"accessVector,omitempty"`
		Authentication        *string `json:"authentication,omitempty"`
		AvailabilityImpact    *string `json:"availabilityImpact,omitempty"`
		ConfidentialityImpact *string `json:"confidentialityImpact,omitempty"`
		IntegrityImpact       *string `json:"integrityImpact,omitempty"`
	} `json:"cvssV2_0,omitempty"`
	CvssV30 *struct {
		Version               string   `json:"version"`
		VectorString          string   `json:"vectorString"`
		BaseScore             float64  `json:"baseScore"`
		BaseSeverity          string   `json:"baseSeverity"`
		AttackComplexity      *string  `json:"attackComplexity,omitempty"`
		AttackVector          *string  `json:"attackVector,omitempty"`
		AvailabilityImpact    *string  `json:"availabilityImpact,omitempty"`
		ConfidentialityImpact *string  `json:"confidentialityImpact,omitempty"`
		ExploitCodeMaturity   *string  `json:"exploitCodeMaturity,omitempty"`
		IntegrityImpact       *string  `json:"integrityImpact,omitempty"`
		PrivilegesRequired    *string  `json:"privilegesRequired,omitempty"`
		RemediationLevel      *string  `json:"remediationLevel,omitempty"`
		ReportConfidence      *string  `json:"reportConfidence,omitempty"`
		Scope                 *string  `json:"scope,omitempty"`
		TemporalScore         *float64 `json:"temporalScore,omitempty"`
		TemporalSeverity      *string  `json:"temporalSeverity,omitempty"`
		UserInteraction       *string  `json:"userInteraction,omitempty"`
	} `json:"cvssV3_0,omitempty"`
	CvssV31 *struct {
		Version                       string   `json:"version"`
		VectorString                  string   `json:"vectorString"`
		BaseScore                     float64  `json:"baseScore"`
		BaseSeverity                  string   `json:"baseSeverity"`
		AttackComplexity              *string  `json:"attackComplexity,omitempty"`
		AttackVector                  *string  `json:"attackVector,omitempty"`
		AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
		AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
		ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
		ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
		EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
		EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
		ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
		IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
		IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
		ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
		ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
		ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
		ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
		ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
		ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
		ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
		ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
		PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
		RemediationLevel              *string  `json:"remediationLevel,omitempty"`
		ReportConfidence              *string  `json:"reportConfidence,omitempty"`
		Scope                         *string  `json:"scope,omitempty"`
		TemporalScore                 *float64 `json:"temporalScore,omitempty"`
		TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
		UserInteraction               *string  `json:"userInteraction,omitempty"`
	} `json:"cvssV3_1,omitempty"`
	Format    *string     `json:"format,omitempty"`
	Other     interface{} `json:"other,omitempty"`
	Scenario  *string     `json:"scenario,omitempty"`
	Scenarios []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"scenarios,omitempty"`
}

type ProblemType struct {
	Descriptions []ProblemTypeDescription `json:"descriptions"`
}

type ProblemTypeDescription struct {
	CWEID       *string `json:"cweid,omitempty"`
	Description string  `json:"description"`
	Lang        string  `json:"lang"`
	Reference   *struct {
		URL string `json:"url"`
	} `json:"reference,omitempty"`
	Type *string `json:"type,omitempty"`
}

type ProviderMetadata struct {
	DateUpdated *string `json:"dateUpdated,omitempty"`
	OrgID       string  `json:"orgId"`
	ShortName   *string `json:"shortName,omitempty"`
}

type Reference struct {
	Name      *string  `json:"name,omitempty"`
	Refsource *string  `json:"refsource,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	URL       string   `json:"url"`
}

type RejectedReason struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type Solution struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type TaxonomyMapping struct {
	TaxonomyName      string `json:"taxonomyName"`
	TaxonomyVersion   string `json:"taxonomyVersion"`
	TaxonomyRelations []struct {
		RelationshipName  string `json:"relationshipName"`
		RelationshipValue string `json:"relationshipValue"`
		TaxonomyID        string `json:"taxonomyId"`
	} `json:"taxonomyRelations"`
}

type Timeline struct {
	Lang  string `json:"lang"`
	Time  string `json:"time"`
	Value string `json:"value"`
}

type Workaround struct {
	Lang            string `json:"lang"`
	SupportingMedia []struct {
		Base64 bool   `json:"base64"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
	Value string `json:"value"`
}

type XConverterError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
