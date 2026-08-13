---
name: openssh-security-raw
description: "Convert the stored OpenSSH security page (origin/security.html) into vuls-data-raw JSON under raw/. Use when asked to update, regenerate, or fill in raw/ in a vuls-data-raw-openssh-security repository, after `vuls-data-update fetch openssh-security` has refreshed origin/. Covers entry segmentation, ID assignment, affected/unaffected classification, and version-range transcription."
---

# OpenSSH security page → vuls-data-raw

## 0. What this is

`https://www.openssh.com/security.html` is OpenSSH's whole security history, and
it is prose. Entries are `<li>` elements of one list, dated at best; the CVE ID,
the affected versions and the release that fixes them are stated in whatever
wording that entry's author reached for, and a quarter of the list exists to
say OpenSSH was *never* vulnerable to something. There is no parser for that.

So the split is: `vuls-data-update fetch openssh-security` stores the page
verbatim under `origin/`, along with the release notes and advisories it links
to, and **you** turn it into `raw/`. `vuls-data-update extract openssh-security`
then reads `raw/` and never looks at the HTML.

Your output is a **transcription**. Every field is read off the entry or left
out. You do not supply a CVE ID the entry does not name, infer a fix release
from the version timeline, or reword prose into something tidier.

There is exactly one exception, and it is fenced off in its own field:
`annotations` (§7) records what a *linked document* says — the CVE ID the
release notes name where the entry does not — with the document and the quoted
sentence attached. Everything else on this page still applies to it: the
evidence has to be in `origin/`, and a claim you cannot point at is a claim you
do not write.

## 1. Prerequisites

Run from the root of a `vuls-data-raw-openssh-security` checkout:

```sh
ls origin/security.html   # the input; if missing, run the fetch first
ls origin/txt/            # the documents the page cites; evidence for §7
ls origin/mitre/          # the CVE records for OpenSSH; evidence for §7
ls raw/                   # your output; may be empty on a first run
```

If `origin/security.html` is absent, stop and tell the user to run
`vuls-data-update fetch openssh-security -d <this directory>`. Do not fetch the
page yourself — the whole point of `origin/` is that raw/ is derived from a
stored, diffable copy, not from whatever the site served you. The same goes for
`origin/txt/`: it is the fetcher's copy of the release notes and advisories the
page links to, and it is the only thing §7 lets you annotate from. A document
that is not there is not citable — not a reason to go and get it.

## 2. Segment the page into entries

Entries are the **top-level** `<li>` elements of the single `<ul>` that follows
the intro paragraphs. As of the page's current state there are **55**: 48 that
open with a bolded date, then 7 undated ones at the foot.

Two traps:

- The 2023-07-19 ssh-agent/PKCS#11 entry contains a **nested `<ul>` with two
  `<li>`** ("Exploitation requires the presence of specific libraries…"). Those
  are exploitation preconditions inside one entry, not two entries. A naive
  count of `<li>` gives 57.
- The list is not closed per item — `<li>` elements are not `</li>`-terminated,
  so an entry runs to the next `<li>` or to `</ul>`.

Count the entries you found before writing anything. If the number differs from
what `raw/` already holds, that difference is the work: say what it is.

## 3. Assign IDs

`OPENSSH-<yyyy>-<mm>-<dd>-<n>` for dated entries, `OPENSSH-UNDATED-<n>` for the
rest. `<n>` is the 1-based position among entries sharing that date, counted
**down the page** (the page is newest-first, so the upper of two entries on one
date is `-1`).

Nine dates carry more than one entry — 2025-02-18, 2024-07-01, 2023-12-18,
2023-02-02 (three), 2006-09-27, 2005-09-01, 2003-09-16, 2001-05-21 and
2000-11-06 (three) — so ordinals are not decoration.

**When `raw/` is not empty, existing IDs win.** Match each entry you segmented
to an existing file by its `origin.html`, and keep that file's `id`. Only
entries with no match are new, and only they get freshly assigned ordinals.
Upstream adds entries at the top under a new date, so in practice existing IDs
never move — but re-deriving ordinals from scratch is what would move them, and
a moved ID silently rewrites history downstream.

## 4. Write one file per entry

Path: `raw/<yyyy>/<ID>.json` for dated entries, `raw/undated/<ID>.json` for the
undated ones. One entry, one file, always — never an array.

The schema is `pkg/fetch/openssh/security/types.go` in vuls-data-update. Its
doc comments are the authority; what follows is the working summary.

```json
{
  "id": "OPENSSH-2025-02-18-1",
  "date": "2025-02-18",
  "title": "VerifyHostKeyDNS server impersonation.",
  "description": "ssh(1) in OpenSSH versions 6.8p1 to 9.9p1 (inclusive).\n\nVerifyHostKeyDNS server impersonation.\n\nA logic error in ssh(1) allowed an on-path attacker to impersonate any server when the VerifyHostKeyDNS option is enabled. This option is disabled by default. This vulnerability has been assigned CVE-2025-26465.\n\nFor more information, please refer to the release notes and the report from the Qualys Security Advisory Team who discovered the bug.",
  "status": "affected",
  "cves": ["CVE-2025-26465"],
  "affected": [
    {
      "product": "OpenSSH",
      "component": "ssh(1)",
      "versions": [{"ge": "6.8p1", "le": "9.9p1"}],
      "condition": "VerifyHostKeyDNS enabled"
    }
  ],
  "fixed": ["9.9p2"],
  "references": [
    {"url": "https://www.openssh.com/txt/release-9.9p2", "text": "release notes"},
    {"url": "https://www.qualys.com/2025/02/18/openssh-mitm-dos.txt", "text": "Qualys Security Advisory Team"}
  ],
  "origin": {
    "url": "https://www.openssh.com/security.html",
    "html": "<li><p><b>February 18, 2025</b><br>\n        ssh(1) in OpenSSH versions 6.8p1 to 9.9p1 (inclusive).\n    <br>\n..."
  }
}
```

Field by field:

- **`date`** — `yyyy-mm-dd`. Some entries end the bolded date with a colon
  ("`<b>November 8, 2013:</b>`"); drop it. Omit for undated entries.
- **`title`** — the entry's own summary sentence where it has one (most
  post-2021 entries put it on its own line between `<br>`s). Where it does not,
  write one from the entry's first clause. Don't invent severity or impact
  wording the entry doesn't use.
- **`description`** — the entry as text: tags dropped, entities decoded,
  whitespace runs collapsed to single spaces, `<br>`/`<p>`-separated blocks
  joined with a blank line. Keep the whole thing, including sentences that also
  feed `cves`, `fixed` and `mitigations`. Link anchor text stays inline as text;
  the href goes to `references`.
- **`status`** — see §5.
- **`cves`** — only IDs written in the entry, page order. Most entries have
  none: OpenSSH only began citing CVE IDs inline in the 2010s, and *that* is a
  fact about this source worth preserving. Never fill one in from memory or
  from NVD, however obvious the pairing — the 2023-12-18 Terrapin entry names
  no CVE ID, so its `cves` is empty, CVE-2023-48795 notwithstanding. If a
  document the entry links to names the ID, that goes in `annotations` (§7),
  which is a different claim: not "the page says this" but "this document does".
- **`affected`** — see §6. Empty for `unaffected` entries, and empty for an
  affected entry that states no version bound.
- **`fixed`** — releases the entry names as carrying the fix. Two forms count,
  and only these two:
  - the sentence, "This bug is corrected in OpenSSH 9.2." → `["9.2"]`;
  - a linked `txt/release-<version>`, whose version *is* the statement —
    `<a href="txt/release-9.9p2">release notes</a>` → `["9.9p2"]`. The entries
    from 2024 on carry no sentence at all and this link is their only fix
    signal, so ignoring it would empty the field exactly where it matters most.

  Both may be present and agree; list the release once. Nothing else counts —
  in particular, do not derive a fix from `affected`'s upper bound, and do not
  reach for a release you happen to know shipped the patch.
- **`mitigations`** — workarounds the entry offers, one string per measure,
  as stated. "Mitigate by setting X11Forwarding=no in sshd_config, or on the
  commandline." is one. A sentence merely noting the feature is off by default
  is not a mitigation — leave it in `description`.
- **`references`** — every link in the entry, page order, hrefs made absolute
  against `https://www.openssh.com/security.html` (so `txt/release-9.9p2` →
  `https://www.openssh.com/txt/release-9.9p2`). Keep the anchor text in `text`.
- **`annotations`** — see §7. The only field that may carry something the entry
  does not state, and only with the document it was read from. Omit it when you
  have annotated nothing.
- **`origin.html`** — the `<li>` **verbatim from `origin/security.html`**,
  opening tag included, byte-for-byte, up to but not including the next `<li>`
  or `</ul>`. Do not reindent, reflow, or strip the trailing newline. This is
  what makes every other field checkable, and what lets the next run tell an
  entry upstream revised from one it merely re-read.

## 5. Classify status — the part that is easy to get backwards

Two values, and the page mixes them without a marker.

**`affected`** — the entry describes a defect in OpenSSH. This *includes* the
many entries phrased from the fix:

> "OpenSSH 4.4 and newer is not vulnerable to the unsafe signal handler
> vulnerability described in the OpenSSH 4.4 release notes."

That says releases **before 4.4 are** vulnerable. `status: "affected"`,
`versions: [{"lt": "4.4"}]`, `fixed: ["4.4"]`.

**`unaffected`** — no OpenSSH release was ever vulnerable. The entry exists to
record that a vulnerability reported against SSH at large did not apply:

> "OpenSSH was never vulnerable to the 'Feb 5, 2001: SSH-1 Brute Force Password
> Vulnerability', Crimelabs Security Note CLABS200101."

> "OpenSSH does not treat localhost as exempt from host key checking, thus
> making it not vulnerable to the host key authentication bypass attack."

`status: "unaffected"`, no `affected`, no `fixed`.

The test is **whether some OpenSSH release was vulnerable** — not whether a
version number appears. Read the sentence's subject: "OpenSSH X and newer are
not vulnerable" is a fix boundary (`affected`); "OpenSSH was not vulnerable" /
"was never vulnerable" / "does not …, thus making it not vulnerable" is a
non-applicability record (`unaffected`).

Three that need deciding rather than pattern-matching:

- **2008-07-22**, "Portable OpenSSH 5.1 and newer are not vulnerable to the
  X11UseLocalhost=no hijacking attack on HP/UX" → `affected`, `{"lt": "5.1"}`,
  Product `Portable OpenSSH`.
- **2002-08-01**, the trojaned distribution tarballs on the OpenBSD FTP server
  → `affected`. It is a supply-chain compromise rather than a code defect, but
  specific releases were affected: three `{"eq"}` entries for 3.2.2p1, 3.4p1
  and 3.4.
- The final undated entry, "OpenSSH has the SSH 1 protocol deficiency that
  might make an insertion attack difficult but possible… the CORE-SDI deattack
  mechanism is used to eliminate the common case" → `unaffected`. It records a
  known protocol limitation that is mitigated, names no vulnerable release and
  no fix.

## 6. Transcribe version ranges

`versions[]` bounds map straight onto the extractor's range fields. At most one
lower bound (`ge`/`gt`) and one upper bound (`le`/`lt`) per element; `eq` stands
alone.

| Entry says | `versions` |
| --- | --- |
| "versions 7.4 to 9.9 (inclusive)" | `[{"ge": "7.4", "le": "9.9"}]` |
| "between 8.9 and 9.5 (inclusive)" | `[{"ge": "8.9", "le": "9.5"}]` |
| "prior to version 9.6" | `[{"lt": "9.6"}]` |
| "9.1 (only)" | `[{"eq": "9.1"}]` |
| "6.7 through 6.9" | `[{"ge": "6.7", "le": "6.9"}]` |
| "3.2.2p1, 3.4p1 and 3.4" | `[{"eq": "3.2.2p1"}, {"eq": "3.4p1"}, {"eq": "3.4"}]` |
| "4.4 and newer is not vulnerable" | `[{"lt": "4.4"}]` |
| "clients between versions 5.4 and 7.1" | `[{"ge": "5.4", "le": "7.1"}]` |

Rules:

- **Copy versions as written, p-suffix and all.** `9.9p1` stays `9.9p1`. The
  suffix marks a *portable* release of the base version, not a pre-release of
  it, and normalizing it away here would throw out the distinction the page
  draws. How to compare them is extraction's problem.
- **One `affected` element per range the entry states separately** — whether
  what separates them is the component or a second bug. Alternative bounds on
  one statement are several `versions` of one element; two statements are two
  elements. The 2015-08-11 entry packs two bugs into one `<li>` — "OpenSSH 6.7
  through 6.9 assign weak permissions to TTY devices" and "Keyboard-interactive
  authentication in OpenSSH prior to 7.0 may allow circumvention of
  MaxAuthTries" — so two elements, `{"ge":"6.7","le":"6.9"}` and `{"lt":"7.0"}`.
- **`product`** is `Portable OpenSSH` only where the entry says so, else
  `OpenSSH`. Portable-only entries: 2024-07-01 (the sshd race / regreSSHion),
  2011-02-02 (keysign), 2008-07-22 (X11UseLocalhost on HP/UX), 2003-09-16 (PAM).
- **`component`** verbatim with the manual section the page gives it —
  `sshd(8)`, `ssh(1)`, `ssh-agent(1)`, `ssh-add(1)`. Some entries write `sshd`
  bare; keep it bare. Omit when the entry speaks of OpenSSH as a whole. Where
  one range is stated against several programs — "ssh(1), sshd(8) in OpenSSH
  prior to version 9.6" — write one element per program, each carrying that
  same range, so that `component` stays one program's name.
- **`condition`** for a stated configuration prerequisite: "X11Forwarding
  enabled", "read-only mode (sftp-server -R)", "UseLogin enabled". It is
  recorded, not evaluated — extraction cannot test a remote `sshd_config`, so
  a conditional entry still yields a version-only detection.
- If an entry gives **no version bound at all** and is still `affected`, leave
  `affected` empty rather than guessing a bound. `fixed` may still be set.

## 7. Annotate from `origin/txt/`

Everything above is transcription: it says what the page says. This section is
the one place you may record something the page does not say — and only under
the same terms, which is that the claim names the document it came from and
quotes the sentence it was read off.

It exists because the page cannot state its own CVE IDs. OpenSSH is not a CNA:
the IDs are assigned by Red Hat or by MITRE, so the project's own documents
mostly predate or ignore them. Six of the 55 entries name an ID; of the other
49, exactly one has a linked release note that names any — and that one,
CVE-2020-14871 in `release-8.5`, is Solaris' PAM bug, not the entry's. So
`origin/txt/` supplies fix releases and detail, and almost no CVE IDs.

The IDs are in `origin/mitre/`, one file per CVE the CVE List has for OpenSSH.
Matching an entry to one is a reading, not a lookup — which is why it is an
annotation, recorded once with its evidence rather than re-derived every time.

**Two sources, two jobs:**

| | holds | annotate from it for |
| --- | --- | --- |
| `origin/txt/` | OpenSSH's release notes and advisories | `fixed`, occasionally detail |
| `origin/mitre/` | CVE records (`CVE-yyyy-nnnn.json`) | `cves` |

**`cves` and `fixed` stay page-only.** An annotation never edits them. That
keeps §8.4 and §8.5 true — every value in those fields is still readable off
the stored `<li>` — and it keeps the two questions apart: what OpenSSH said,
which is fixed and re-derivable, versus what can be found out, which grows as
documents are read. Extraction merges them, so nothing is lost by separating
them here.

```json
"annotations": [
  {
    "field": "cves",
    "value": "CVE-2024-6387",
    "source": {
      "url": "https://www.openssh.com/txt/release-9.8",
      "origin": "origin/txt/release-9.8",
      "quote": "This release contains fixes for ... CVE-2024-6387 ...",
      "retrieved": "2026-08-13"
    }
  }
]
```

- **`field`** is `cves` or `fixed`. Nothing else — extraction fails on an
  unrecognized name rather than dropping the claim.
- **`value`** takes the field's form: a CVE ID, or a release as the source
  writes it (`9.8`, `9.3p2` — §6's rules on version strings apply unchanged).
- **`source.url`** is the document: as the entry links to it for `origin/txt/`,
  or `https://www.cve.org/CVERecord?id=<ID>` for a CVE record.
- **`source.origin`** is the stored copy's path — `origin/txt/release-9.8`,
  `origin/mitre/CVE-2024-6387.json`. Set it always; every document you may read
  is stored, so an annotation without it is one you had no business writing.
- **`source.quote`** is the sentence, verbatim from the stored file. It must
  appear in that file — that is what makes the annotation checkable at all. For
  a CVE record that means a sentence of its **description**, since the file is
  JSON and the description is where the prose lives:
  ```sh
  jq -r '.containers.cna.descriptions[]?.value' origin/mitre/CVE-2024-6387.json
  ```
  Quote from that output, not from the raw JSON, or backslash escaping will put
  characters in your quote that are not in the prose.
- **`source.retrieved`** is the fetch date of `origin/` (`git log -1
  --format=%ad --date=short -- origin/`), not today's date.
- **`"inapplicable": true`**, with the `value`, records that the document states
  something and it is not this entry's. Keep the value and the quote — they are
  the record.

So two outcomes are worth writing down, and a third is not:

| You read the document and it… | write |
| --- | --- |
| names a value that is this entry's | `value` |
| names a value that is **not** this entry's | `value` + `inapplicable: true` |
| names nothing for the field | nothing |

That last row is deliberate. Recording "read it, nothing there" sounds like it
saves the next pass a reading, but on this page it saves a `grep`: five of the
35 documents under `origin/txt/` name a CVE ID and the other thirty do not, and
`grep -l 'CVE-[0-9]' origin/txt/*` answers that faster and more reliably than a
stored record can. It would also be the only annotation with no quote, which
makes it the only one nothing can check — if a document were revised to name an
ID, the record would quietly become false with no verification to catch it.

Every annotation you write therefore carries a `value` and a `quote`, without
exception, which is what makes §8.7 a check on all of them.

In `origin/txt/`, read only what the entry itself links to. A release note for
some other version is not evidence about this entry, however tempting the
version arithmetic.

`origin/mitre/` is different, and has to be: no entry links a CVE record, so
there is nothing to follow. Read them by their description and match on what the
bug *is*. The descriptions are specific enough for this to be a reading rather
than a guess — `DisableForwarding directive does not adhere to the
documentation`, `ssh-add ... without the intended per-hop destination
constraints`, `sshd 9.1 introduced a double-free`. Where two entries could both
fit a record, see the second rule below.

Version bounds are the weakest evidence available here and should not decide a
match on their own. The CVE record's own affected range is empty for most
pre-2020 IDs, and the description's version — `before 9.3p2`, `before 7.1p2` —
is usually the *fixed* release, not the affected range the entry states.

Two things annotation must not do:

- **Don't fold a CVE into an `unaffected` entry.** Those records exist to say
  the vulnerability never applied to OpenSSH, so a CVE ID claimed for one
  inverts its meaning — and the CVE List does carry IDs for SSH-the-protocol
  weaknesses that those entries describe, which is exactly the trap. Extraction
  refuses it, so this fails loudly rather than shipping. It is not a reason to
  leave the record unread: what it names goes in as `inapplicable`, ID and quote
  included, which is the whole reason that outcome exists.
- **Don't resolve an ambiguity by guessing.** Three entries share 2023-02-02 and
  all three are fixed in 9.2; if a document names a CVE without naming which of
  them it is about, there is no annotation to write — not even an
  `inapplicable` one, since that asserts the value is *not* this entry's and you
  do not know that either. Leave it, and say so.

## 8. Verify before you finish

1. `raw/**/*.json` count equals the entry count from §2.
2. Every `id` is unique, and matches its filename and its `date`.
3. Every file's `origin.html` appears verbatim in `origin/security.html`:
   ```sh
   # spot-check one, then loop
   jq -r '.origin.html' raw/2025/OPENSSH-2025-02-18-1.json | head -1
   ```
   Concatenating every `origin.html` in page order should reproduce the list
   body. If two files share an `origin.html`, you split one entry in two.
4. Every `cves[]` entry appears literally in that file's `origin.html`.
5. Every `versions[]` version string appears literally in `origin.html`.
6. `status` is `affected` or `unaffected`, never empty.
7. Every annotation's `source.quote` appears literally in the file named by
   `source.origin`, and that file exists. Every annotation has both, so this
   covers all of them — a missing `quote` or `origin` is itself the failure:
   ```sh
   shopt -s globstar
   jq -r '.annotations[]? | [.source.origin, .source.quote] | @tsv' raw/**/*.json |
     while IFS=$'\t' read -r f q; do
       case "$f" in
         # a CVE record is JSON: check the prose, not the escaped bytes
         */mitre/*) jq -r '.containers.cna.descriptions[]?.value' "$f" ;;
         *)         cat "$f" ;;
       esac | grep -qF -- "$q" || echo "MISSING $f: $q"
     done
   ```
   A quote that no longer appears means the document was revised under you.
   Check `git log origin/txt/` before changing anything: if the evidence moved,
   the annotation has to be re-read, not re-worded.
8. No `unaffected` entry carries a `cves` annotation.
9. `git diff --stat` — on a re-run with an unchanged page, this must be
   **empty**. Any diff means either upstream changed (check `git log origin/`)
   or you re-derived something that should have been stable. Both are worth
   saying out loud; neither should be committed unexplained.

Then run the extractor against the tree to confirm it parses:

```sh
vuls-data-update extract openssh-security . -d /tmp/extract-openssh-security
```

## 9. Don't do this

- **Don't enrich the transcribed fields.** No CVE IDs, CVSS scores, CWEs, or
  affected ranges from NVD, Debian, or your own knowledge — not in `cves`, not
  in `fixed`, not in `affected`. If it isn't in the `<li>`, it isn't in those
  fields. What a linked document says goes in `annotations` under §7, with its
  source, and nowhere else.
- **Don't fetch anything.** Not the page, not the `txt/release-*` notes, not the
  Qualys write-ups. `origin/` is the input, whole and only — including for §7,
  which cites the copies already stored there and nothing beyond them.
- **Don't rewrite `origin/`.** It is the fetcher's output. If it looks wrong,
  re-run the fetch; don't hand-edit it to make conversion easier.
- **Don't renumber existing IDs** because re-deriving them from the page felt
  cleaner. See §3.
- **Don't collapse the undated entries into one file** or drop them because
  they carry no date. They are `unaffected` records and the page's account of
  its own history is incomplete without them.
- **Don't normalize version strings** — no stripping `p1`, no zero-padding, no
  `9.9.1` for `9.9p1`.
- **Don't summarize `description`.** It is the entry's prose in full. A shorter
  paraphrase is a lossy rewrite of the only copy of that text in the dataset.
- **Don't treat the nested `<li>`s of the 2023-07-19 entry as entries.** See §2.
