package vex

// https://github.com/openvex/go-vex/blob/ed3dcf12b58e9081b143fe0c267bd421ece33ca9/pkg/vex/vex.go

// The VEX type represents a VEX document and all of its contained information.
type VEX struct {
	Metadata   Metadata    `json:"metadata"`
	Statements []Statement `json:"statements"`
}

// The Metadata type represents the metadata associated with a VEX document.
type Metadata struct {
	// Context is the URL pointing to the jsonld context definition
	Context string `json:"@context"`

	// ID is the identifying string for the VEX document. This should be unique per
	// document.
	ID string `json:"@id"`

	// Author is the identifier for the author of the VEX statement, ideally a common
	// name, may be a URI. [author] is an individual or organization. [author]
	// identity SHOULD be cryptographically associated with the signature of the VEX
	// statement or document or transport.
	Author string `json:"author"`

	// AuthorRole describes the role of the document Author.
	AuthorRole string `json:"role,omitempty"`

	// Timestamp defines the time at which the document was issued.
	Timestamp string `json:"timestamp"`

	// LastUpdated marks the time when the document had its last update. When the
	// document changes both version and this field should be updated.
	LastUpdated string `json:"last_updated,omitempty"`

	// Version is the document version. It must be incremented when any content
	// within the VEX document changes, including any VEX statements included within
	// the VEX document.
	Version int `json:"version"`

	// Tooling expresses how the VEX document and contained VEX statements were
	// generated. It's optional. It may specify tools or automated processes used in
	// the document or statement generation.
	Tooling string `json:"tooling,omitempty"`

	// Supplier is an optional field.
	Supplier string `json:"supplier,omitempty"`
}

// A Statement is a declaration conveying a single [status] for a single
// [vul_id] for one or more [product_id]s. A VEX Statement exists within a VEX
// Document.
type Statement struct {
	// ID is an optional identifier for the statement. It takes an IRI and must
	// be unique for each statement in the document.
	ID string `json:"@id,omitempty"`

	// [vul_id] SHOULD use existing and well known identifiers, for example:
	// CVE, the Global Security Database (GSD), or a supplier’s vulnerability
	// tracking system. It is expected that vulnerability identification systems
	// are external to and maintained separately from VEX.
	//
	// [vul_id] MAY be URIs or URLs.
	// [vul_id] MAY be arbitrary and MAY be created by the VEX statement [author].
	Vulnerability Vulnerability `json:"vulnerability,omitempty"`

	// Timestamp is the time at which the information expressed in the Statement
	// was known to be true.
	Timestamp string `json:"timestamp,omitempty"`

	// LastUpdated records the time when the statement last had a modification
	LastUpdated string `json:"last_updated,omitempty"`

	// Product
	// Product details MUST specify what Status applies to.
	// Product details MUST include [product_id] and MAY include [subcomponent_id].
	Products []Product `json:"products,omitempty"`

	// A VEX statement MUST provide Status of the vulnerabilities with respect to the
	// products and components listed in the statement. Status MUST be one of the
	// Status const values, some of which have further options and requirements.
	Status Status `json:"status"`

	// [status_notes] MAY convey information about how [status] was determined
	// and MAY reference other VEX information.
	StatusNotes string `json:"status_notes,omitempty"`

	// For ”not_affected” status, a VEX statement MUST include a status Justification
	// that further explains the status.
	Justification Justification `json:"justification,omitempty"`

	// For ”not_affected” status, a VEX statement MAY include an ImpactStatement
	// that contains a description why the vulnerability cannot be exploited.
	ImpactStatement string `json:"impact_statement,omitempty"`

	// For "affected" status, a VEX statement MUST include an ActionStatement that
	// SHOULD describe actions to remediate or mitigate [vul_id].
	ActionStatement          string `json:"action_statement,omitempty"`
	ActionStatementTimestamp string `json:"action_statement_timestamp,omitempty"`
}

// Vulnerability is a struct that captures the vulnerability identifier and
// its aliases. When defined, the ID field should be an IRI.
type Vulnerability struct {
	//  ID is an IRI to reference the vulnerability in the statement.
	ID string `json:"@id,omitempty"`

	// Name is the main vulnerability identifier.
	Name VulnerabilityID `json:"name,omitempty"`

	// Description is a short free form text description of the vulnerability.
	Description string `json:"description,omitempty"`

	// Aliases is a list of other vulnerability identifier strings that
	// locate the vulnerability in other tracking systems.
	Aliases []VulnerabilityID `json:"aliases,omitempty"`
}

// VulnerabilityID is a string that captures a vulnerability identifier. It is
// a free form string but it is intended to capture the identifiers used by
// tracking systems.
type VulnerabilityID string

// Product abstracts the VEX product into a struct that can identify software
// through various means. The main one is the ID field which contains an IRI
// identifying the product, possibly pointing to another document with more data,
// like an SBOM. The Product struct also supports naming software using its
// identifiers and/or cryptographic hashes.
type Product struct {
	Component
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponents are nested entries that list the product's components that are
// related to the statement's vulnerability. The main difference with Product
// and Subcomponent objects is that a Subcomponent cannot nest components.
type Subcomponent struct {
	Component
}

// Component abstracts the common construct shared by product and subcomponents
// allowing OpenVEX statements to point to a piece of software by referencing it
// by hash or identifier.
//
// The ID should be an IRI uniquely identifying the product. Software can be
// referenced as a VEX product or subcomponent using only its IRI or it may be
// referenced by its crptographic hashes and/or other identifiers but, in no case,
// must an IRI describe two different pieces of software or used to describe
// a range of software.
type Component struct {
	// ID is an IRI identifying the component. It is optional as the component
	// can also be identified using hashes or software identifiers.
	ID string `json:"@id,omitempty"`

	// Hashes is a map of hashes to identify the component using cryptographic
	// hashes.
	Hashes map[Algorithm]Hash `json:"hashes,omitempty"`

	// Identifiers is a list of software identifiers that describe the component.
	Identifiers map[IdentifierType]string `json:"identifiers,omitempty"`

	// Supplier is an optional machine-readable identifier for the supplier of
	// the component. Valid examples include email address or IRIs.
	Supplier string `json:"supplier,omitempty"`
}

type (
	IdentifierLocator string
	IdentifierType    string
)

const (
	PURL  IdentifierType = "purl"
	CPE22 IdentifierType = "cpe22"
	CPE23 IdentifierType = "cpe23"
)

type (
	Algorithm string
	Hash      string
)

// The following list of algorithms follows and expands the IANA list at:
// https://www.iana.org/assignments/named-information/named-information.xhtml
// It expands it, trying to keep the naming pattern.
const (
	MD5        Algorithm = "md5"
	SHA1       Algorithm = "sha1"
	SHA256     Algorithm = "sha-256"
	SHA384     Algorithm = "sha-384"
	SHA512     Algorithm = "sha-512"
	SHA3224    Algorithm = "sha3-224"
	SHA3256    Algorithm = "sha3-256"
	SHA3384    Algorithm = "sha3-384"
	SHA3512    Algorithm = "sha3-512"
	BLAKE2S256 Algorithm = "blake2s-256"
	BLAKE2B256 Algorithm = "blake2b-256"
	BLAKE2B512 Algorithm = "blake2b-512"
	BLAKE3     Algorithm = "blake3"
)

// Status describes the exploitability status of a component with respect to a
// vulnerability.
type Status string

const (
	// StatusNotAffected means no remediation or mitigation is required.
	StatusNotAffected Status = "not_affected"

	// StatusAffected means actions are recommended to remediate or mitigate.
	StatusAffected Status = "affected"

	// StatusFixed means the listed products or components have been remediated (by including fixes).
	StatusFixed Status = "fixed"

	// StatusUnderInvestigation means the author of the VEX statement is investigating.
	StatusUnderInvestigation Status = "under_investigation"
)

// Justification describes why a given component is not affected by a
// vulnerability.
type Justification string

const (
	// ComponentNotPresent means the vulnerable component is not included in the artifact.
	//
	// ComponentNotPresent is a strong justification that the artifact is not affected.
	ComponentNotPresent Justification = "component_not_present"

	// VulnerableCodeNotPresent means the vulnerable component is included in
	// artifact, but the vulnerable code is not present. Typically, this case occurs
	// when source code is configured or built in a way that excluded the vulnerable
	// code.
	//
	// VulnerableCodeNotPresent is a strong justification that the artifact is not affected.
	VulnerableCodeNotPresent Justification = "vulnerable_code_not_present"

	// VulnerableCodeNotInExecutePath means the vulnerable code (likely in
	// [subcomponent_id]) can not be executed as it is used by [product_id].
	// Typically, this case occurs when [product_id] includes the vulnerable
	// [subcomponent_id] and the vulnerable code but does not call or use the
	// vulnerable code.
	VulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"

	// VulnerableCodeCannotBeControlledByAdversary means the vulnerable code cannot
	// be controlled by an attacker to exploit the vulnerability.
	//
	// This justification could be difficult to prove conclusively.
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"

	// InlineMitigationsAlreadyExist means [product_id] includes built-in protections
	// or features that prevent exploitation of the vulnerability. These built-in
	// protections cannot be subverted by the attacker and cannot be configured or
	// disabled by the user. These mitigations completely prevent exploitation based
	// on known attack vectors.
	//
	// This justification could be difficult to prove conclusively. History is
	// littered with examples of mitigation bypasses, typically involving minor
	// modifications of existing exploit code.
	InlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)
