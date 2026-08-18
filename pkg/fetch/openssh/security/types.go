package security

// Advisory is one entry of the list on https://www.openssh.com/security.html.
//
// The page carries no machine-readable structure: every entry is a bare <li>
// of English prose, dated at best, and the CVE ID, the affected versions and
// the release that fixes them are stated in whatever wording that entry's
// author reached for. There is no parser for that, which is why this type is
// not produced by the fetcher. The fetcher stores the page under origin/ and
// the conversion to this shape is a separate, model-driven step (see
// openssh-security-raw/SKILL.md) whose output lands under raw/.
//
// What that arrangement asks of this type is that it stay *transcription*, not
// interpretation. Every field is either read off the entry or absent — nothing
// here is inferred from a release timeline, from NVD, or from what the reader
// knows about OpenSSH. Origin.HTML carries the <li> the rest was read from, so
// any field can be checked against its source without going back to the site,
// and an upstream edit to one entry shows up as a diff on that one file.
type Advisory struct {
	// ID identifies the entry. It is "OPENSSH-<date>-<n>", where <date> is
	// Date and <n> is the 1-based position of the entry among those sharing
	// that date, counted down the page — e.g. "OPENSSH-2025-02-18-1" and
	// "OPENSSH-2025-02-18-2" for the two entries of 2025-02-18. The trailing
	// entries that carry no date at all are "OPENSSH-UNDATED-<n>", numbered
	// the same way.
	//
	// The page states no identifier of its own, so this one is assigned. It is
	// derived rather than sequential so that an entry added upstream — always
	// at the top, under a new date — leaves the IDs of every existing entry
	// alone.
	ID string `json:"id"`

	// Date is the date the entry is filed under, as yyyy-mm-dd. Empty for the
	// undated entries at the foot of the page ("OpenSSH was never vulnerable
	// to ...").
	//
	// It is a publication date for the advisory, and not necessarily the date
	// the fix shipped: the two 2025-02-18 entries were published alongside the
	// 9.9p2 release, while the 2015-08-11 entry describes bugs fixed in 7.0,
	// released later that month.
	Date string `json:"date,omitempty"`

	// Title is the one-line statement of the issue, taken from the entry.
	// Where the entry has a sentence that serves as a summary, that sentence
	// is it ("VerifyHostKeyDNS server impersonation."); where it does not, it
	// is written from the entry's first clause. It is not translated,
	// re-worded for style, or given a severity it does not state.
	Title string `json:"title"`

	// Description is the entry's prose, as text: tags dropped, entities
	// decoded, runs of whitespace collapsed to single spaces, paragraphs
	// separated by a blank line. Nothing is added and nothing is summarized
	// away — the whole entry is here, including the sentences that also feed
	// Fixed, Mitigations and CVEs.
	Description string `json:"description"`

	// Status says which of the two kinds of entry this is. See Status.
	Status Status `json:"status"`

	// CVEs are the CVE IDs the entry itself names, in page order. Entries that
	// name none — the majority, since OpenSSH only began citing CVE IDs
	// inline in the 2010s — have none here. An ID is never supplied from
	// elsewhere, however well known the pairing is: that OpenSSH's page does
	// not name a CVE is itself the fact this field records.
	CVEs []string `json:"cves,omitempty"`

	// Affected are the version ranges the entry states are vulnerable, split
	// by the component or build they are stated against. Empty when
	// Status is StatusUnaffected, and empty when an affected entry gives no
	// version bound at all.
	Affected []Affected `json:"affected,omitempty"`

	// Fixed are the releases the entry names as carrying the fix, e.g.
	// ["9.9p2"] or ["7.2p2"]. Empty when the entry names none.
	//
	// A fixed release is not the complement of Affected: "corrected in OpenSSH
	// 9.6" against an affected range of "8.9 to 9.5 inclusive" states both
	// bounds, and neither is derived from the other here.
	Fixed []string `json:"fixed,omitempty"`

	// Mitigations are the workarounds the entry offers, one per measure, as
	// stated ("Mitigate by setting X11Forwarding=no in sshd_config, or on the
	// commandline."). A sentence that merely observes the feature is off by
	// default is not a mitigation and is left to Description.
	Mitigations []string `json:"mitigations,omitempty"`

	// References are the links in the entry, in page order, with relative
	// hrefs resolved against the page's URL.
	References []Reference `json:"references,omitempty"`

	// Annotations are claims about this entry that the page does not make and
	// the fields above therefore cannot carry: the CVE ID the release notes
	// name where the entry does not, the release a linked advisory says
	// carries the fix. Each one names the document it was read from and quotes
	// the sentence it was read off, so it is checkable the same way every other
	// field is.
	//
	// They are kept apart from CVEs and Fixed rather than merged into them,
	// and that separation is the point. Those fields answer "what does OpenSSH
	// say", which is a question with a fixed answer that this repository can
	// re-derive from Origin.HTML alone; Annotations answer "what can be found
	// out", which is a question whose answer grows as documents are read. Merged,
	// neither could be asked: a CVE ID in CVEs that is not in the entry breaks
	// the check that every field is readable off the stored <li>, and once
	// broken there is no way to tell a transcription error from an annotation.
	// Extraction merges them, because by then the distinction has been
	// recorded and what is wanted is the union.
	Annotations []Annotation `json:"annotations,omitempty"`

	// Origin records where the entry was read from.
	Origin Origin `json:"origin,omitzero"`
}

// Annotation is one claim read from a document the entry links to, rather than
// from the entry itself.
//
// It exists because the page is a poor citation index of its own history: six
// of the 55 entries name a CVE ID, and the other 49 leave it to the release
// notes they link to. Recording the ID without recording where it was read
// would make raw/ unfalsifiable at exactly the point where it stops being a
// transcription, so an annotation is not a value but a value plus its evidence.
//
// One combination extraction refuses: a "cves" annotation that would be folded
// in on an advisory whose Status is StatusUnaffected. Such an entry exists to
// record that no OpenSSH release was ever vulnerable, and a CVE attached to it
// says the opposite. It is also the easiest annotation to reach for wrongly,
// since those are the entries that link notes about SSH at large — which is
// exactly why Inapplicable exists: the reading is recorded, with the ID and the
// quote, and simply not folded.
type Annotation struct {
	// Field is the Advisory field this claim is about: "cves" or "fixed".
	//
	// It is the field name rather than a free-form label so that extraction can
	// dispatch on it, and it is checked there: an unrecognized name fails the
	// extract rather than being skipped, for the same reason a malformed
	// version does. These records are model-produced, and a claim filed under a
	// field nothing reads would be silently lost.
	Field string `json:"field"`

	// Value is what the source states, in the form the field takes: a CVE ID
	// for "cves", a release for "fixed". Always set -- an annotation exists to
	// record a value, including when Inapplicable says it is not this entry's,
	// where it is the whole point of the record.
	Value string `json:"value"`

	// Inapplicable records the second of the two outcomes worth writing down:
	// the source states Value for Field, and it is not this entry's.
	//
	// Omitting the value instead is not the same record. That is the "not
	// looked at yet" this type exists to rule out, and it costs the same
	// document being re-read and the same judgement being made again, with
	// nothing written down either time.
	//
	// It has two occasions on this source. A page entry recording that OpenSSH
	// was never vulnerable links notes about SSH at large, which do name CVE
	// IDs -- against the protocol, not against any release here. And one
	// release note covers several entries at once: three share 2023-02-02 and
	// all three are fixed in 9.2, so a CVE named there may well belong to a
	// sibling. Where it cannot be told which, that is not an Inapplicable
	// either but no annotation at all, since the reading was inconclusive
	// rather than negative.
	//
	// Extraction does not fold it in; it is for whoever reads raw/ next.
	//
	// There is deliberately no counterpart for "the source was read and states
	// nothing". On this page that outcome is a grep over origin/txt/ away --
	// five of the 35 stored documents name a CVE ID and the rest do not -- so
	// recording it caches an answer that is cheaper and more reliable to
	// recompute. It is also the one record that carries no quote, which makes
	// it the only kind nothing can check: were a document revised to name an ID,
	// the record would quietly become false with no verification to catch it.
	Inapplicable bool `json:"inapplicable,omitempty"`

	// Source is the document the claim was read from.
	Source AnnotationSource `json:"source"`
}

// AnnotationSource is where an Annotation was read, in enough detail to check
// it without going back to the network.
type AnnotationSource struct {
	// URL is the document, as the entry links to it.
	URL string `json:"url"`

	// Origin is the path of the stored copy under origin/, e.g.
	// "origin/txt/release-9.8". Set when the fetcher ingested the document,
	// which it does for the same-origin documents the page cites; empty when
	// the claim rests on something not stored here.
	//
	// The difference matters: with a stored copy the claim is offline-checkable
	// and an upstream edit to the evidence shows up as a diff, which is the
	// same guarantee Origin.HTML gives every other field. Without one, the
	// annotation is an assertion about a document that may since have changed
	// and nothing here would notice.
	Origin string `json:"origin,omitempty"`

	// Quote is the sentence the claim was read off, verbatim from the source.
	//
	// A quote rather than a line number or a byte offset: the documents are not
	// pinned, and an offset silently comes to point at the wrong line when one
	// is inserted above it, whereas a quote that no longer appears is a
	// detectable failure -- and a greppable one, when Origin is set.
	Quote string `json:"quote,omitempty"`

	// Retrieved is the date the source was read, as yyyy-mm-dd. It is what
	// dates the claim when the document behind it is revised.
	Retrieved string `json:"retrieved,omitempty"`
}

// Status distinguishes the two kinds of entry the page mixes together. It
// matters because they read almost alike and mean opposite things: the list is
// a security *history*, and roughly a quarter of it exists to record that a
// vulnerability reported against SSH at large never applied to OpenSSH.
type Status string

const (
	// StatusAffected marks an entry describing a vulnerability in OpenSSH
	// itself. This includes the many entries phrased from the fix — "OpenSSH
	// 4.4 and newer is not vulnerable to ...", which states that releases
	// before 4.4 are — since the subject of the sentence is still an OpenSSH
	// defect.
	StatusAffected Status = "affected"

	// StatusUnaffected marks an entry recording that no OpenSSH release was
	// ever vulnerable: "OpenSSH was never vulnerable to the ... SSH-1 Brute
	// Force Password Vulnerability", "OpenSSH was not vulnerable to the RC4
	// cipher ... attacks", and the note that the SSH 1 insertion-attack
	// deficiency is handled by the CORE-SDI deattack mechanism.
	//
	// The test is whether some OpenSSH release was vulnerable, not whether a
	// version is named. An entry that names none but says a fix exists is
	// StatusAffected with an empty Affected.
	StatusUnaffected Status = "unaffected"
)

// Affected is one component's vulnerable version range, as the entry states
// it.
type Affected struct {
	// Product is which build the range is stated against: "OpenSSH" or
	// "Portable OpenSSH". The distinction is the entry's own and is kept —
	// e.g. the 2011-02-02 keysign entry is portable-only, and the 2024-07-01
	// race condition is stated against Portable because the RCE it leads to
	// is on non-OpenBSD systems. Where the entry does not say, this is
	// "OpenSSH".
	Product string `json:"product,omitempty"`

	// Component is the program the entry names, verbatim and with the manual
	// section the page gives it: "sshd(8)", "ssh(1)", "ssh-agent(1)",
	// "ssh-add(1)", "sftp-server". Empty when the entry speaks of OpenSSH as
	// a whole.
	Component string `json:"component,omitempty"`

	// Versions are the bounds, as stated. A range with several bounds is one
	// element ("7.4 to 9.9 (inclusive)" is one {ge, le}); alternatives are
	// several ("versions 3.2.2p1, 3.4p1 and 3.4" is three {eq}).
	Versions []Range `json:"versions,omitempty"`

	// Condition is the configuration the entry says the exposure requires,
	// as stated: "X11Forwarding enabled", "read-only mode (sftp-server -R)",
	// "VerifyHostKeyDNS enabled". Empty when the entry states none.
	//
	// It is recorded but not evaluated: extraction cannot test a remote
	// sshd_config, so a conditional entry still yields a detection on version
	// alone.
	Condition string `json:"condition,omitempty"`
}

// Range is one version bound. Its fields map one-to-one onto the extracted
// range types, and at most one of the two lower bounds and one of the two
// upper bounds is set — "8.9 and 9.5 (inclusive)" is {GreaterEqual: "8.9",
// LessEqual: "9.5"}, "prior to 7.6" is {LessThan: "7.6"}, "9.1 (only)" is
// {Equal: "9.1"}.
//
// Versions are copied as written, p-suffix and all ("9.9p1", "3.7.1p2"). The
// suffix marks a portable release of the base version and is not a
// pre-release of it, so it is left to extraction to decide how to compare
// them; normalizing here would throw away the distinction the page draws
// between "9.9" and "9.9p1".
type Range struct {
	Equal        string `json:"eq,omitempty"`
	GreaterEqual string `json:"ge,omitempty"`
	GreaterThan  string `json:"gt,omitempty"`
	LessEqual    string `json:"le,omitempty"`
	LessThan     string `json:"lt,omitempty"`
}

// Reference is one link from the entry.
type Reference struct {
	// URL is the href, made absolute.
	URL string `json:"url"`

	// Text is the link's anchor text ("release notes", "the advisory",
	// "Qualys Security Advisory Team").
	Text string `json:"text,omitempty"`
}

// Origin records the source of an Advisory: which page it was read from, and
// the fragment of it the entry occupies.
type Origin struct {
	// URL is the page the entry was read from.
	URL string `json:"url,omitempty"`

	// HTML is the entry's <li> element, verbatim from origin/, including the
	// tag itself. It is what makes the rest of the record checkable — and
	// what lets a later run tell an entry upstream has revised from one it has
	// only re-read.
	HTML string `json:"html,omitempty"`
}
