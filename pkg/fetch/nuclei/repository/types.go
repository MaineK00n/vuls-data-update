package repository

// https://github.com/projectdiscovery/nuclei/blob/24311cc28e5cc7bbc7a75aaa4220324b25a31db6/nuclei-jsonschema.json
type Template struct {
	ID   string `yaml:"id" json:"id"`
	Info struct {
		Name           string                  `yaml:"name" json:"name"`
		Authors        interface{}             `yaml:"author" json:"author"`                 // string or slice
		Tags           *interface{}            `yaml:"tags,omitempty" json:"tags,omitempty"` // string or slice
		Description    *string                 `yaml:"description,omitempty" json:"description,omitempty"`
		Impact         *string                 `yaml:"impact,omitempty" json:"impact,omitempty"`
		References     *interface{}            `yaml:"reference,omitempty" json:"reference,omitempty"` // string or slice
		Severity       *string                 `yaml:"severity,omitempty" json:"severity,omitempty"`   // enum: info, low, medium, high, critical, unknown
		Metadata       *map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
		Classification *struct {
			CVEID          *string  `yaml:"cve-id,omitempty" json:"cve-id,omitempty"`
			CWEID          *string  `yaml:"cwe-id,omitempty" json:"cwe-id,omitempty"`
			CVSSMetrics    *string  `yaml:"cvss-metrics,omitempty" json:"cvss-metrics,omitempty"`
			CVSSScore      *float64 `yaml:"cvss-score,omitempty" json:"cvss-score,omitempty"`
			EPSSScore      *float64 `yaml:"epss-score,omitempty" json:"epss-score,omitempty"`
			EPSSPercentile *float64 `yaml:"epss-percentile,omitempty" json:"epss-percentile,omitempty"`
			CPE            *string  `yaml:"cpe,omitempty" json:"cpe,omitempty"`
		} `yaml:"classification,omitempty" json:"classification,omitempty"`
		Remediation *string `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	} `yaml:"info" json:"info"`
	Flow               *string                 `yaml:"flow,omitempty" json:"flow,omitempty"`
	RequestsHTTP       *[]HTTPRequest          `yaml:"requests,omitempty" json:"requests,omitempty"`
	RequestsWithHTTP   *[]HTTPRequest          `yaml:"http,omitempty" json:"http,omitempty"`
	RequestsDNS        *[]DNSRequest           `yaml:"dns,omitempty" json:"dns,omitempty"`
	RequestsFile       *[]FileRequest          `yaml:"file,omitempty" json:"file,omitempty"`
	RequestsNetwork    *[]NetworkRequest       `yaml:"network,omitempty" json:"network,omitempty"`
	RequestsWithTCP    *[]NetworkRequest       `yaml:"tcp,omitempty" json:"tcp,omitempty"`
	RequestsHeadless   *[]HeadlessRequest      `yaml:"headless,omitempty" json:"headless,omitempty"`
	RequestsSSL        *[]SSLRequest           `yaml:"ssl,omitempty" json:"ssl,omitempty"`
	RequestsWebsocket  *[]WebsocketRequest     `yaml:"websocket,omitempty" json:"websocket,omitempty"`
	RequestsWHOIS      *[]WhoisRequest         `yaml:"whois,omitempty" json:"whois,omitempty"`
	RequestsCode       *[]CodeRequest          `yaml:"code,omitempty" json:"code,omitempty"`
	RequestsJavascript *[]JavascriptRequest    `yaml:"javascript,omitempty" json:"javascript,omitempty"`
	Workflows          *[]WorkflowTemplate     `yaml:"workflows,omitempty" json:"workflows,omitempty"`
	SelfContained      *bool                   `yaml:"self-contained,omitempty" json:"self-contained,omitempty"`
	StopAtFirstMatch   *bool                   `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`
	Signature          *string                 `yaml:"signature,omitempty" json:"signature,omitempty"` // enum: AWS
	Variables          *map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`
	Constants          *map[string]interface{} `yaml:"constants,omitempty" json:"constants,omitempty"`
}

type HTTPRequest struct {
	Matchers                      *[]MatchersMatcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors                    *[]ExtractorsExtractor  `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition             *string                 `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	Path                          *[]string               `yaml:"path,omitempty" json:"path,omitempty"`
	Raw                           *[]string               `yaml:"raw,omitempty" json:"raw,omitempty"`
	ID                            *string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name                          *string                 `yaml:"name,omitempty" json:"name,omitempty"`
	Attack                        *string                 `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Method                        *string                 `yaml:"method,omitempty" json:"method,omitempty"` // enum: GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH, PURGE, DEBUG
	Body                          *string                 `yaml:"body,omitempty" json:"body,omitempty"`
	Payloads                      *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	Headers                       *map[string]string      `yaml:"headers,omitempty" json:"headers,omitempty"`
	RaceCount                     *int                    `yaml:"race_count,omitempty" json:"race_count,omitempty"`
	MaxRedirects                  *int                    `yaml:"max-redirects,omitempty" json:"max-redirects,omitempty"`
	PipelineConcurrentConnections *int                    `yaml:"pipeline-concurrent-connections,omitempty" json:"pipeline-concurrent-connections,omitempty"`
	PipelineRequestsPerConnection *int                    `yaml:"pipeline-requests-per-connection,omitempty" json:"pipeline-requests-per-connection,omitempty"`
	Threads                       *int                    `yaml:"threads,omitempty" json:"threads,omitempty"`
	MaxSize                       *int                    `yaml:"max-size,omitempty" json:"max-size,omitempty"`
	Fuzzing                       *[]FuzzRule             `yaml:"fuzzing,omitempty" json:"fuzzing,omitempty"`
	Analyzer                      *struct {
		Name       string                 `yaml:"name" json:"name"`
		Parameters map[string]interface{} `yaml:"parameters" json:"parameters"`
	} `yaml:"analyzer,omitempty" json:"analyzer,omitempty"`
	SelfContained        *bool              `yaml:"self-contained,omitempty" json:"self-contained,omitempty"`
	Signature            *string            `yaml:"signature,omitempty" json:"signature,omitempty"` // enum: AWS
	SkipSecretFile       *bool              `yaml:"skip-secret-file,omitempty" json:"skip-secret-file,omitempty"`
	CookieReuse          *bool              `yaml:"cookie-reuse,omitempty" json:"cookie-reuse,omitempty"`
	DisableCookie        *bool              `yaml:"disable-cookie,omitempty" json:"disable-cookie,omitempty"`
	ReadAll              *bool              `yaml:"read-all,omitempty" json:"read-all,omitempty"`
	Redirects            *bool              `yaml:"redirects,omitempty" json:"redirects,omitempty"`
	HostRedirects        *bool              `yaml:"host-redirects,omitempty" json:"host-redirects,omitempty"`
	Pipeline             *bool              `yaml:"pipeline,omitempty" json:"pipeline,omitempty"`
	Unsafe               *bool              `yaml:"unsafe,omitempty" json:"unsafe,omitempty"`
	Race                 *bool              `yaml:"race,omitempty" json:"race,omitempty"`
	ReqCondition         *bool              `yaml:"req-condition,omitempty" json:"req-condition,omitempty"`
	StopAtFirstMatch     *bool              `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`
	SkipVariablesCheck   *bool              `yaml:"skip-variables-check,omitempty" json:"skip-variables-check,omitempty"`
	IterateAll           *bool              `yaml:"iterate-all,omitempty" json:"iterate-all,omitempty"`
	DigestUsername       *string            `yaml:"digest-username,omitempty" json:"digest-username,omitempty"`
	DigestPassword       *string            `yaml:"digest-password,omitempty" json:"digest-password,omitempty"`
	DisablePathAutomerge *bool              `yaml:"disable-path-automerge,omitempty" json:"disable-path-automerge,omitempty"`
	PreCondition         *[]MatchersMatcher `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty"`
	PreConditionOperator *string            `yaml:"pre-condition-operator,omitempty" json:"pre-condition-operator,omitempty"` // enum: and, or
	GlobalMatchers       *bool              `yaml:"global-matchers,omitempty" json:"global-matchers,omitempty"`
}

type DNSRequest struct {
	Matchers          *[]MatchersMatcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor  `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                 `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name              *string                 `yaml:"name,omitempty" json:"name,omitempty"`
	Type              *string                 `yaml:"type,omitempty" json:"type,omitempty"`   // enum: A, NS, DS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, TLSA, ANY, SRV
	Class             *string                 `yaml:"class,omitempty" json:"class,omitempty"` // enum: inet, csnet, chaos, hesiod, none, any
	Retries           *int                    `yaml:"retries,omitempty" json:"retries,omitempty"`
	Trace             *bool                   `yaml:"trace,omitempty" json:"trace,omitempty"`
	TraceMaxRecursion *int                    `yaml:"trace-max-recursion,omitempty" json:"trace-max-recursion,omitempty"`
	Attack            *string                 `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Payloads          *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	Threads           *int                    `yaml:"threads,omitempty" json:"threads,omitempty"`
	Recursion         *bool                   `yaml:"recursion,omitempty" json:"recursion,omitempty"`
	Resolvers         *[]string               `yaml:"resolvers,omitempty" json:"resolvers,omitempty"`
}

type FileRequest struct {
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	Extensions        *[]string              `yaml:"extensions,omitempty" json:"extensions,omitempty"`
	Denylist          *[]string              `yaml:"denylist,omitempty" json:"denylist,omitempty"`
	ID                *string                `yaml:"id,omitempty" json:"id,omitempty"`
	MaxSize           *string                `yaml:"max-size,omitempty" json:"max-size,omitempty"`
	Archive           *bool                  `yaml:"archive,omitempty" json:"archive,omitempty"`
	MimeType          *bool                  `yaml:"mime-type,omitempty" json:"mime-type,omitempty"`
	NoRecursive       *bool                  `yaml:"no-recursive,omitempty" json:"no-recursive,omitempty"`
}

type NetworkRequest struct {
	ID       *string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Host     *[]string               `yaml:"host,omitempty" json:"host,omitempty"`
	Attack   *string                 `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Payloads *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	Threads  *int                    `yaml:"threads,omitempty" json:"threads,omitempty"`
	Inputs   *[]struct {
		Data *interface{} `yaml:"data,omitempty" json:"data,omitempty"` // string or int
		Type *string      `yaml:"type,omitempty" json:"type,omitempty"` // enum: hex, text
		Read *int         `yaml:"read,omitempty" json:"read,omitempty"`
		Name *string      `yaml:"name,omitempty" json:"name,omitempty"`
	} `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Port              *interface{}           `yaml:"port,omitempty" json:"port,omitempty"` // string or int
	ExcludePorts      *string                `yaml:"exclude-ports,omitempty" json:"exclude-ports,omitempty"`
	ReadSize          *int                   `yaml:"read-size,omitempty" json:"read-size,omitempty"`
	ReadAll           *bool                  `yaml:"read-all,omitempty" json:"read-all,omitempty"`
	StopAtFirstMatch  *bool                  `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
}

type HeadlessRequest struct {
	ID                *string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Attack            *string                 `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Payloads          *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	Steps             *[]EngineAction         `yaml:"steps,omitempty" json:"steps,omitempty"`
	UserAgent         *string                 `yaml:"user_agent,omitempty" json:"user_agent,omitempty"` // enum: off, default, custom
	CustomUserAgent   *string                 `yaml:"custom_user_agent,omitempty" json:"custom_user_agent,omitempty"`
	StopAtFirstMatch  *bool                   `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`
	Matchers          *[]MatchersMatcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor  `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                 `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	Fuzzing           *[]FuzzRule             `yaml:"fuzzing,omitempty" json:"fuzzing,omitempty"`
	CookieReuse       *bool                   `yaml:"cookie-reuse,omitempty" json:"cookie-reuse,omitempty"`
	DisableCookie     *bool                   `yaml:"disable-cookie,omitempty" json:"disable-cookie,omitempty"`
}

type SSLRequest struct {
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                `yaml:"id,omitempty" json:"id,omitempty"`
	Address           *string                `yaml:"address,omitempty" json:"address,omitempty"`
	MinVersion        *string                `yaml:"min_version,omitempty" json:"min_version,omitempty"` // enum: sslv3, tls10, tls11, tls12, tls13
	MaxVersion        *string                `yaml:"max_version,omitempty" json:"max_version,omitempty"` // enum: sslv3, tls10, tls11, tls12, tls13
	CipherSuites      *[]string              `yaml:"cipher_suites,omitempty" json:"cipher_suites,omitempty"`
	ScanMode          *string                `yaml:"scan_mode,omitempty" json:"scan_mode,omitempty"` // enum: ctls, ztls, auto
	TLSVersionEnum    *bool                  `yaml:"tls_version_enum,omitempty" json:"tls_version_enum,omitempty"`
	TLSCipherEnum     *bool                  `yaml:"tls_cipher_enum,omitempty" json:"tls_cipher_enum,omitempty"`
	TLSCipherTypes    *[]string              `yaml:"tls_cipher_types,omitempty" json:"tls_cipher_types,omitempty"` // enum: weak, secure, insecure, all
}

type WebsocketRequest struct {
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                `yaml:"id,omitempty" json:"id,omitempty"`
	Address           *string                `yaml:"address,omitempty" json:"address,omitempty"`
	Inputs            *[]struct {
		Data *string `yaml:"data,omitempty" json:"data,omitempty"`
		Name *string `yaml:"name,omitempty" json:"name,omitempty"`
	} `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Headers  *map[string]string      `yaml:"headers,omitempty" json:"headers,omitempty"`
	Attack   *string                 `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Payloads *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
}

type WhoisRequest struct {
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                `yaml:"id,omitempty" json:"id,omitempty"`
	Query             *string                `yaml:"query,omitempty" json:"query,omitempty"`
	Server            *string                `yaml:"server,omitempty" json:"server,omitempty"`
}

type CodeRequest struct {
	Matchers          *[]MatchersMatcher     `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                `yaml:"id,omitempty" json:"id,omitempty"`
	Engine            *[]string              `yaml:"engine,omitempty" json:"engine,omitempty"`
	PreCondition      *string                `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty"`
	Args              *[]string              `yaml:"args,omitempty" json:"args,omitempty"`
	Pattern           *string                `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Source            *string                `yaml:"source,omitempty" json:"source,omitempty"`
}

type JavascriptRequest struct {
	Matchers          *[]MatchersMatcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Extractors        *[]ExtractorsExtractor  `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	MatchersCondition *string                 `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"` // enum: and, or
	ID                *string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Init              *string                 `yaml:"init,omitempty" json:"init,omitempty"`
	PreCondition      *string                 `yaml:"pre-condition,omitempty" json:"pre-condition,omitempty"`
	Args              *map[string]interface{} `yaml:"args,omitempty" json:"args,omitempty"`
	Code              *string                 `yaml:"code,omitempty" json:"code,omitempty"`
	StopAtFirstMatch  *bool                   `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty"`
	Attack            **string                `yaml:"attack,omitempty" json:"attack,omitempty"` // enum: batteringram, pitchfork, clusterbomb
	Threads           *int                    `yaml:"threads,omitempty" json:"threads,omitempty"`
	Payloads          *map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
}

type MatchersMatcher struct {
	Type            string    `yaml:"type" json:"type"`                               // enum: word, binary, status, size, dsl, xpath
	Condition       *string   `yaml:"condition,omitempty" json:"condition,omitempty"` // enum: and, or
	Part            *string   `yaml:"part,omitempty" json:"part,omitempty"`
	Negative        *bool     `yaml:"negative,omitempty" json:"negative,omitempty"`
	Name            *string   `yaml:"name,omitempty" json:"name,omitempty"`
	Status          *[]int    `yaml:"status,omitempty" json:"status,omitempty"`
	Size            *[]int    `yaml:"size,omitempty" json:"size,omitempty"`
	Words           *[]string `yaml:"words,omitempty" json:"words,omitempty"`
	Regex           *[]string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Binary          *[]string `yaml:"binary,omitempty" json:"binary,omitempty"`
	DSL             *[]string `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	XPath           *[]string `yaml:"xpath,omitempty" json:"xpath,omitempty"`
	Encoding        *string   `yaml:"encoding,omitempty" json:"encoding,omitempty"` // enum: hex
	CaseInsensitive *bool     `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty"`
	MatchAll        *bool     `yaml:"match-all,omitempty" json:"match-all,omitempty"`
	Internal        *bool     `yaml:"internal,omitempty" json:"internal,omitempty"`
}

type ExtractorsExtractor struct {
	Name            *string   `yaml:"name,omitempty" json:"name,omitempty"`
	Type            string    `yaml:"type" json:"type"` // enum: regex, kval, xpath, json, dsl
	Regex           *[]string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Group           *int      `yaml:"group,omitempty" json:"group,omitempty"`
	Kval            *[]string `yaml:"kval,omitempty" json:"kval,omitempty"`
	JSON            *[]string `yaml:"json,omitempty" json:"json,omitempty"`
	XPath           *[]string `yaml:"xpath,omitempty" json:"xpath,omitempty"`
	Attribute       *string   `yaml:"attribute,omitempty" json:"attribute,omitempty"`
	DSL             *[]string `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	Part            *string   `yaml:"part,omitempty" json:"part,omitempty"`
	Internal        *bool     `yaml:"internal,omitempty" json:"internal,omitempty"`
	CaseInsensitive *bool     `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty"`
}

type FuzzRule struct {
	Type         *string        `yaml:"type,omitempty" json:"type,omitempty"`   // enum: replace, prefix, postfix, infix, replace-regex
	Part         *string        `yaml:"part,omitempty" json:"part,omitempty"`   // enum: query, header, path, body, cookie, request
	Parts        *[]string      `yaml:"parts,omitempty" json:"parts,omitempty"` // enum: query, header, path, body, cookie, request
	Mode         *string        `yaml:"mode,omitempty" json:"mode,omitempty"`   // enum: single, multiple
	Keys         *[]string      `yaml:"keys,omitempty" json:"keys,omitempty"`
	KeysRegex    *[]string      `yaml:"keys-regex,omitempty" json:"keys-regex,omitempty"`
	Values       *[]string      `yaml:"values,omitempty" json:"values,omitempty"`
	Fuzz         *[]interface{} `yaml:"fuzz,omitempty" json:"fuzz,omitempty"` // string or object
	ReplaceRegex *string        `yaml:"replace-regex,omitempty" json:"replace-regex,omitempty"`
}

type EngineAction struct {
	Args        *map[string]interface{} `yaml:"args,omitempty" json:"args,omitempty"`
	Name        *string                 `yaml:"name,omitempty" json:"name,omitempty"`
	Description *string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Action      string                  `yaml:"action" json:"action"` // enum: navigate, script, click, rightclick, text, screenshot, time, select, files, waitdom, waitfcp, waitfmp, waitidle, waitload, waitstable, getresource, extract, setmethod, addheader, setheader, deleteheader, setbody, waitevent, waitdialog, keyboard, debug, sleep, waitvisible
}

type WorkflowTemplate struct {
	Template *string      `yaml:"template,omitempty" json:"template,omitempty"`
	Tags     *interface{} `yaml:"tags,omitempty" json:"tags,omitempty"` // string or slice
	Matchers *[]struct {
		Name         *interface{}        `yaml:"name,omitempty" json:"name,omitempty"`           // string or slice
		Condition    *string             `yaml:"condition,omitempty" json:"condition,omitempty"` // enum: and, or
		SubTemplates *[]WorkflowTemplate `yaml:"subtemplates,omitempty" json:"subtemplates,omitempty"`
	} `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	SubTemplates *[]WorkflowTemplate `yaml:"subtemplates,omitempty" json:"subtemplates,omitempty"`
}
