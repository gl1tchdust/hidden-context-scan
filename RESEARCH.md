# RESEARCH

What was measured, how, and every place the measurement is weak.

Run `python -m hcx.measure` and `python -m hcx.scan census .corpus/spl` to
reproduce any number here. Both read a pinned corpus from local disk.

---

## 1. The question

OWASP published the 2026 LLM Top 10 on 4 August 2026. One entry was re-scoped
rather than renumbered: **LLM07:2025 System Prompt Leakage became LLM08:2026
Hidden Context Exposure**, and the scope widened from "the prompt leaked" to
what the leak reveals. OWASP gives five categories of revealed thing on pages
46 to 47 of that document.

Separately, a CCS 2026 measurement study (arXiv 2606.18673) tested 1,200
applications across six commercial platforms and reported that over 80% leak
their system prompts under realistic adversarial queries.

So extraction is close to solved, and "assume hidden context is public" is an
empirical fact rather than advice. The open question is the one nobody has
measured:

> Given that these prompts are readable, what did the industry put in them?

---

## 2. The corpus

| | |
|---|---|
| Source | `github.com/asgeirtj/system_prompts_leaks` |
| Licence | CC0-1.0, public domain dedication |
| Pinned commit | `bb4c9c5a8bcbe281e2fbe3fd1fa961e514c0a93f`, 14 Nov 2026 |
| Markdown files | 1,710 |
| Analysed | 1,699 at or above 200 bytes |
| Size | 38.2 MiB, which is 40.1 MB |
| Vendors | 17 |

One of those 1,699 files is the corpus repository's own `README.md`, which sits
at the root rather than under a vendor directory. It is not a system prompt,
and it is the single credential-shaped hit in section 4.1, so it is named here
rather than left inside a denominator.

Largest: Meta 512 files, Anthropic 466, OpenAI 432, GLM 90, xAI 76, Google 63.
Median prompt 5,794 characters; largest 987,902.

The corpus is updated daily, which is why the commit is pinned. A census whose
corpus moves under it is not reproducible.

**Selection bias, stated plainly.** This is a corpus of prompts that were
extracted and published. It is not a random sample of deployed systems. Prompts
from systems that resist extraction, or from vendors nobody targeted, are
absent. Every rate below describes this corpus and nothing else.

---

## 3. Method

Six detectors. Five map to OWASP's own Common Examples of Risk for LLM08. The
sixth does not exist in OWASP and is proposed here.

| | Category | Source |
|---|---|---|
| C1 | Exposure of Sensitive Functionality, Tool and Function Schemas | OWASP |
| C2 | Exposure of Behavioral Control Logic | OWASP |
| C3 | Reverse Engineering of Safety and Refusal Mechanisms | OWASP |
| C4 | Disclosure of Permissions and User Roles | OWASP |
| C5 | Exposure of Output Structure and Formatting Rules | OWASP |
| C6 | Capability disclosure | proposed here |
| CRED | Credential or token in hidden context | OWASP's critical tier |

Each detector is a small set of regular expressions. Each pattern carries a
stated reason, and each category carries a caveat describing how it fails.
Both are printed with every finding, because a tool that prints a verdict
teaches nothing and a tool that shows its working produces a better analyst
every time it is wrong.

---

## 4. Results

### 4.1 Credentials: none in a prompt

OWASP's critical tier for LLM08 is credentials in hidden context. Two
independent tools were run over all 1,699 files.

| Tool | Raw hits | Files | After reading the files |
|---|---|---|---|
| gitleaks 8.30.1 | 2 | 2 | 0 live credentials |
| `hcx` credential rule | 3 | 1 | 0 live credentials |

**Across 1,699 published system prompts from 17 vendors, no live credential was
found.** That is the headline, and it is the good-news story this field rarely
gets to report. It is a statement about prompts, not about files: `hcx`'s three
hits are one real token repeated on three lines of the corpus repository's own
`README.md`, which is repository metadata.

The two tools do not overlap, which is the more useful observation. gitleaks
finds the xAI pair described below and misses the `README.md` token. `hcx`
finds the `README.md` token and downgrades the xAI pair after reading the
prose around them. Neither alone would have given the right answer.

The raw hits are worth more than the headline, because of how they failed.

**gitleaks' two.** Both in xAI Grok skill files, both genuinely
API-key-shaped, high-entropy strings in an `Authorization` header and a `key`
parameter. Both are third-party *public* web tokens, and both source files say
so in the prose immediately above the match: "Resy's web app reads a public
JSON API", and "The key is a static public token from Target's JS bundles".

gitleaks was right twice by its own rules and wrong twice about whether a
secret had been exposed. The disambiguating evidence was four lines of English
that a regular expression cannot read. **Precision on the thing that mattered:
0 of 2.**

That is why `hcx`'s credential rule reads a window of surrounding lines before
deciding, and why it always prints which way it decided and why.

**`hcx`'s own two, found later.** Running the census surfaced two different
false positives, both introduced by fixing a false negative:

```
key = normalize_cell_value(ws.cell(row=row).value)      a function call
set_values: [{key: "DATA_APP_OWNER_EMAIL_SHA256", ...}] an env var NAME
```

Adding a bare `key` to the pattern, so that `?key=` in a query string would be
caught, also caught `key` as a programming identifier. Two general checks fixed
it: a value immediately followed by `(` is a call, and a value written in one
case and joined by underscores is a name. Both are regression-tested.

### 4.2 Prevalence, hand-labelled

This is the primary result. 50 files were read in full by a human and labelled
before any detector was run against them.

```
  category                              k/50     rate   95% CI (Wilson)
  ------------------------------------------------------------------------
  C1  tool and function schemas         36/50   72.0%   [58.3%, 82.5%]
  C2  behavioural control logic         36/50   72.0%   [58.3%, 82.5%]
  C3  refusal and safety mechanisms     14/50   28.0%   [17.5%, 41.7%]
  C4  permissions and user roles        11/50   22.0%   [12.8%, 35.2%]
  C5  output structure rules            19/50   38.0%   [25.9%, 51.8%]
  C6  capability disclosure             29/50   58.0%   [44.2%, 70.6%]
  CRED credential in hidden context      0/50    0.0%   [ 0.0%,  7.1%]

  at least one category present:        48/50   96.0%
```

**Hidden context exposure is close to universal and credential exposure is
absent.** 48 of 50 published system prompts disclose at least one LLM08:2026
category. None of the 50 discloses a credential, before or after the
credential rule was widened.

The 45 files beyond the original five were drawn by
`python -m hcx.sample --n 45 --seed 20261115`, proportional by vendor with a
floor of one slot for any vendor holding ten or more files, from files between
200 bytes and 20,000 bytes. The sampler reports a pool of 1,424 files, which
is 83.8% of the corpus; the largest prompts
are under-represented, and since a longer prompt has more chance of carrying any
given category, these rates are if anything conservative.

### 4.3 What the detectors report, and why it is lower

Over all 1,699 files:

```
  C1    874 / 1699   51.4%        C5    415 / 1699   24.4%
  C2    858 / 1699   50.5%        C6    919 / 1699   54.1%
  C3    351 / 1699   20.7%        CRED    1 / 1699    0.1%
  C4    152 / 1699    8.9%
```

The single CRED file is the corpus repository's own `README.md`, carrying a
`sealed_token` in a chart embed URL on three lines.

This cell read `CRED 0 / 1699 0.0%` in an earlier version of this document,
and that was wrong in a specific and instructive way. Section 5.6 below
records the re-scan that took corpus A from 0 to 9 credential findings and
then down to 3 once the kebab-case slugs were excluded. Section 5.8 recorded
the result of that, 0.1%. **This cell was never recomputed, so one document
carried two different answers for the same measurement and nothing noticed.**
`census --expect-cred` and CI now assert the count, which is the only real fix
for a number a human has to remember to refresh.

Every figure sits below the hand-labelled prevalence, which is what recall
below 1.0 predicts. **Quote the n=50 prevalence, not these.** These describe
the detectors.

---

## 5. Detector accuracy, and the result that matters most

The 50 labelled files were split by seed into **30 dev** and **20 holdout**.
The detectors were improved against dev only. The holdout was not looked at
between the baseline and the final run.

### 5.1 The honest number: holdout

```
  cat   tp  fp  fn  tn   precision   n   95% CI         recall   n
  --------------------------------------------------------------------
  C1     8   0   4   8       1.000   8   [0.68, 1.00]    0.667  12
  C2     6   0   9   5       1.000   6   [0.61, 1.00]    0.400  15
  C3     4   1   1  14       0.800   5   [0.38, 0.96]    0.800   5
  C4     2   1   2  15       0.667   3   [0.21, 0.94]    0.500   4
  C5     2   0   6  12       1.000   2   [0.34, 1.00]    0.250   8
  C6     9   2   2   7       0.818  11   [0.52, 0.95]    0.818  11
  CRED   0   0   0  20         n/a   0                     n/a   0
  --------------------------------------------------------------------
  pooled 31  4  24           0.886  35   [0.74, 0.95]    0.564  55
```

`n` is the denominator of the rate beside it, which is `tp+fp` for precision
and `tp+fn` for recall. It is printed because a precision over 3 predictions
and one over 35 format identically and are not the same claim, and because
the minimum-sample guard in `hcx.measure` originally tested the number of
labelled files (20) instead of these denominators. **C4's 0.667 is two
correct calls out of three.** The pooled row is the only one here with a
denominator large enough to carry a usable interval.

### 5.2 The same detectors, scored on the split they were tuned against

```
                DEV (tuned on)        HOLDOUT (sealed)
  cat     precision    recall     precision    recall    delta P
  ----------------------------------------------------------------
  C1          1.000     0.542         1.000     0.667     +0.000
  C2          1.000     0.619         1.000     0.400     +0.000
  C3          1.000     0.667         0.800     0.800     -0.200
  C4          1.000     0.571         0.667     0.500     -0.333
  C5          1.000     0.727         1.000     0.250     +0.000
  C6          1.000     0.833         0.818     0.818     -0.182
```

**Precision is 1.000 on every category on the split the detectors were fitted
to, and falls as far as 0.667 on the split they were not.** Recall moves in
both directions, and C5 collapses from 0.727 to 0.250.

Three of the six do not move at all, which the table above shows and an
earlier version of the README did not: it printed C3, C4 and C6 only.

The dev column also deserves less weight than its 1.000 suggests. The
detectors were improved until no false positive remained on dev, so that
column is a construction rather than a measurement, and part of the gap is
definitional. The claim the data supports is narrower and better stated
without a ratio: **four false positives in thirty-five predictions on files
the detectors had never seen.**

Nothing was done to produce that gap. It is what happens when a detector is
improved against labelled data and then measured somewhere else, and it is the
reason this repository reports the holdout column and treats the dev column as
a development artifact rather than a result.

It is also, at a much smaller scale, the finding of arXiv 2610.03448, which
measured fifteen prompt-injection detectors across three benchmarks and found
that a leader on one caught 2% of another's injections at the same false-positive
rate. A tool that reports its own accuracy without saying which data produced
it is reporting the dev column.

### 5.3 What the measurement caught

Running it was worth more than the numbers.

- **Two detector bugs.** `\s+` under `re.M` spans newlines, so
  `stop[newline]and report` matched across two unrelated sentences. And
  `UNIQUE` matched "what is unique here", because the rules are
  case-insensitive and that is also an English word. Both are fixed and both
  are commented where they happened.
- **One rule deleted rather than patched.** A C4 pattern for "only &lt;someone&gt;
  may &lt;do&gt;" matched "a read-**only** lookup **may** start from a name" and
  "the **only** user update that **may** be longer". It produced every C4 false
  positive on dev. That shape is ordinary English, not a permission model, so
  the rule was removed instead of being given exceptions.
- **Five of my own labels were wrong.** The three xAI site playbooks are the
  same family of file with the same ground-rules block. The first two were
  labelled before the standard had settled and the third after, and they
  disagreed on C1, C3 and C5. Checked by grep, all three carry the captcha and
  stop-and-report rules, the "Secrets never go in the Task text" line and a
  mandated output shape. The detector was right and the labels were not; they
  are corrected in place with the reasoning kept.
- **C4 began at zero recall on dev.** Not conservative, blind: the patterns
  looked for permission words and real permission models are written as tiers,
  rights, consent and ACL fragments.

### 5.4 Declared gaps

One disagreement is known and deliberately not patched.

| File | Category | Why not fixed |
|---|---|---|
| `Anthropic/.../explanatory.md` | C5 | The output template is a fenced block of box-drawing characters with no word like "format" introducing it. A pattern for this one file would be a regex fitted to a single sample. |

It still counts as a false negative. Declared gaps are documentation;
undeclared ones move the confusion matrix and fail CI.

### 5.5 The regression guard

`hcx/labels/sample.yml` records the confusion matrix per split, and
`python -m hcx.measure --strict` fails when any cell moves. It deliberately
does **not** fail on disagreement: the detectors miss a great deal and those
misses are the honest state of the work. Failing on them would only create
pressure to relax the labels. What must never change quietly is the matrix,
because that is the number being quoted.

Verified by disabling a whole category and confirming the build goes red, then
restoring it and confirming it goes green.

## 5.6 Head to head with another tool

[promptsonar](https://github.com/meghal86/promptsonar) is the nearest thing to
prior art: MIT, TypeScript, version 1.6.0 at commit `ac17e984`, with an AISec
2026 evaluation harness and baselines against NVIDIA SkillSpector. It was
missed by the GitHub searches recorded in section 7 because it brands around
prompts and MCP configs rather than the OWASP category name. That was a search
failure here, not a gap in the field.

Each figure below was re-derived from that pinned clone, with the definition
stated, because the first version of this section gave counts with no
definition attached and one of them was wrong:

| | | |
|---|---|---|
| 309 | source files | git-tracked `*.ts`, excluding the 32 `*.tsx` |
| 22 | ground-truthed fixtures | `cases` in `eval/controlled-manifest.json`, and 22 directories in `eval/corpus/controlled` |
| 37 | wild repos | `repos` in `eval/results/wild-results.json` |

It was built from source and run over the same 50 hand-labelled files.

```
  ground truth (human)        48/50 files disclose an LLM08:2026 category

  promptsonar, all 7 pillars  18/50 files, 87 findings
  promptsonar, security only   3/50 files, 11 findings

  security rules that fired:  sec_privileged_sink_access  9
                              sec_owasp_llm02_pii         1
                              sec_mcp_tool_poisoning      1

    xAI/.../site-playbooks-resy.md            llm02_pii
    Meta/.../device-data/SKILL.md             mcp_tool_poisoning, sink_access
    Anthropic/.../claude-api/curl/examples.md sink_access x8
```

**Both rows, because an earlier version of this section printed only the
second one and labelled it "promptsonar 3/50 files flagged".** That is the
security pillar alone. The tool flags 18 of the 50 files across its seven
pillars, six times as many, and 87 findings rather than 11. Quoting the
security subset as though it were the whole tool understates it by a factor of
six in a section whose entire argument is that it should not be understated.

The security subset is still the right row for *this* comparison, because
disclosure is a security question and the other six pillars score prompt
quality. It just has to be labelled as a subset.

**This is not a defeat for promptsonar and it should not be read as one.** It
scores prompt quality and execution risk across seven pillars: injection
patterns, homoglyph evasion, unbounded personas, hardcoded secrets, privileged
sinks. Disclosure is not what it looks for, so finding little on a disclosure
benchmark is the correct behaviour.

The symmetry proves it. Running `hcx` over promptsonar's own 22 controlled
fixtures:

```
  fires on 10 of 22 fixtures, nothing on the other 12
    C6 on 10 fixtures
    C4 on 1, which is also one of those 10 (case-015-mcp-wildcard)

  misses case-007 zero-width-injection, case-016 prompt-injection-llm01,
         case-017 base64-injection, case-008 memory-sensitive
  correctly silent on the three negative controls:
         case-009, case-010, case-020
```

An earlier version of this block said "nothing on the other 11", which made
the three numbers add to 22 and looked right for that reason. The C4 fixture
is also a C6 fixture, so the fired set is 10 and the silent set is 12.

Neither tool can do the other's job. **The LLM08:2026 disclosure lane is
genuinely unoccupied, and that is now measured rather than asserted.**

### What their fixtures found in our detector

Three real bugs, all in the credential rule. The third was found by re-running
their fixtures months later, and it is the worst of the three: this section
previously claimed the first bug was fixed, while the fixture it is named after
still returned nothing.

**`case-021-hardcoded-secret` was missed outright.** The fixture is
`OPENAI_API_KEY="..."`. The rule began `(?:api[_-]?key|...)`, and an
underscore is a word character, so there is no word boundary before `API` and
the pattern could never match. That is the single commonest way a credential is
ever written, and it took a competitor's test suite to find it. The keyword now
allows any number of underscore-separated prefix segments.

**Loosening it then surfaced a second bug.** The corpus re-scan jumped from 0 to
9 high-severity findings. Six were `console_key: contract-tracker-obligations`
in YAML front matter: kebab-case document slugs, not credentials. The
identifier check covered `snake_case` and `SCREAMING_SNAKE` but not
`kebab-case`. It was fixed at the time by treating any single-case
separator-joined value as a name, while leaving unbroken hex and mixed-case
values as credentials. **That fix was too broad and is the third bug below:
it also discards `sk-live-...`.** The rule now keys on segment length
instead.

That sequence is worth stating plainly: fixing a false negative created six
false positives, and only re-running the full corpus caught it. A detector
change is not done when the new case passes.

**The third bug: the first fix was tested with a value the fixture does not
contain.** The regression test asserted on
`OPENAI_API_KEY="8we2hKl3mNp0QrStUvWxYz12AbCd34Ef"`, a mixed-case value
invented for the test. The fixture's real value is
`sk-live-abcdefghijklmnop1234567890`, which is lowercase and hyphen-joined, so
`_looks_like_identifier` discarded it as a name. **The keyword fix was real,
the test passed, and the fixture still produced zero findings**, and it stayed
that way through every later change while this document said otherwise.

The gap had even been written up as a rare declared limit for `glpat-` style
tokens. It is not rare. It covers `sk-`, `glpat-` and every other lowercase
prefixed key, which is most of the formats that matter, and calling it rare
made a bad call look considered.

The fix separates a name from a token by segment length rather than by case. A
name is made of words and words are short: the longest segment in any real
name found across the four corpora is 11 characters
(`contract-tracker-obligations`), while the two missed tokens run 20 and 26.
Any separator-joined value with a segment of 16 or more characters is now a
token, and 16 is also the shortest value the rule accepts at all. The
fixture's own text is the regression test now, verbatim. The census was re-run
over all four corpora afterwards and the credential counts did not move.

The lesson is narrower than "test more": **when someone else's fixture finds
your bug, the regression test is their fixture, not a value of your own that
resembles it.**

### The credential headline, corrected twice

The first claim was "zero credentials across 1,699 files". It was then
restated as "zero credentials across 3,649 prompts, four corpora". The
restatement was false, and the way it became false is the useful part.

**The measurement was done.** The census was run over all four corpora, and
section 5.8 recorded the result correctly as `CRED is 0.1%, 0.1%, 0.0% and
0.0%`. Nothing was skipped. What failed was everything downstream of the
number:

1. **Section 5.8 contradicted itself inside four lines**, putting a bold
   "Zero credentials" directly above the 0.1% figures that refute it.
2. **Section 4.3 still said `CRED 0 / 1699`**, never refreshed after the
   re-scan in 5.6 left corpus A at three findings. Two sections of one
   document, two answers.
3. **The README summarised the bold line and dropped the figures**, so the
   front page of the repository said "None disclose a credential, across four
   corpora" while its own appendix said 0.1% twice.
4. **The hand verdicts were never actually done.** The gloss "every hit
   resolves to a published public token or an identifier on inspection" was
   carried over from the earlier xAI Resy and Target finding. It does not
   describe any of the hits it was attached to: a real `sealed_token`, a
   fabricated `Basic` auth example, and three Windows service names.

So the error was not a missing measurement. It was a rounded percentage that
nobody read, a stale cell nobody refreshed, and a verdict nobody checked. A
0.1% that covers both one file and two files out of 1,691 is a number
engineered to hide a change, and it did: widening the rule to catch
`Authorization: Bearer <token>` took B1 from one file to two, and the printed
percentage did not move.

With that rule fixed and the census re-run, the full result is nine
shape-matches, six distinct values, three files:

| Corpus | File | Hits | Hand verdict |
|---|---|---|---|
| A | the corpus repo's own `README.md` | 3 | One real `sealed_token` in a star-history.com chart embed URL, repeated on three lines. Repository metadata, not hidden context. |
| B1 | `.../knowledge/P0tS3c/testing for command injection (RCE).md` | 2 | One fabricated `Authorization: Basic` example, on two lines, in a penetration-testing cheat sheet. Found only after the rule was widened. |
| B1 | `.../knowledge/P0tS3c/UsingMetasploit.md` | 4 | Pasted lab console output: one LSA hash, and three Windows secret *names* (`aspnet_WP_PASSWORD`, `_SC_aspnet_state`, `_SC_LicenseService`) rather than values. |
| B2, C | nothing | 0 | |

**Seven of those nine were already visible to the version that was
published.** Two needed the new rule. The detector was never the weak link;
the reporting was.

The precise claim is now:

> No system prompt in any of the four corpora contains a live credential.
> Three files out of 3,649 carry a credential-shaped string. One is
> repository metadata and two are third-party penetration-testing cheat
> sheets attached to a custom GPT as knowledge documents.

`python -m hcx.scan census <corpus> --expect-cred N` now asserts the count,
and CI runs it on all four corpora on every push. The gate exists because
both errors above were the same error: a number that nothing re-measured.

The three `Secret : <name>` hits are genuine false positives, and they are
kept rather than patched out. The general fix would be to treat a mixed-case
underscore-joined value as a name, which is also the shape of real tokens, and
writing a pattern to quiet one Metasploit tutorial is fitting a regex to a
sample of three. The tool reports them as shape matches with a note telling
the reader to confirm, which is what it is for. Recorded here, not hidden.

### Three tools, one file

All three were run over `xAI/grok-bot/skills/site-playbooks-resy.md`:

| Tool | Verdict | Reasoning given |
|---|---|---|
| gitleaks 8.30.1 | `generic-api-key`, leak | none |
| promptsonar 1.6.0 | `sec_owasp_llm02_pii`, low | "Hardcoded Assigned Credential Literal" |
| hcx | informational | "the surrounding 3 lines contain 'public'" |

The file's own prose, three lines above the match, reads "Resy's web app reads
a public JSON API". Two tools detect the string. One reads the sentence.
promptsonar is appropriately cautious in rating it low; it simply does not say
why, and a reviewer cannot act on a severity without a reason.

---

## 5.7 Drift: what changes across model generations

The published longitudinal work on LLMs holds the prompt fixed and watches the
model move. This asks the opposite question, which this corpus makes answerable
because it stores each generation as its own file. `python -m hcx.drift` finds
**13 version series with three or more generations** across four vendors.

### System prompts are growing

All thirteen, because an earlier version of this table showed the five
fastest growers under this heading and hid the rest behind an ellipsis. The
largest series grew 1.4x and two shrank.

```
  series                             n     first      last   growth    rho
  --------------------------------------------------------------------------
  xAI/grok                           6     4,259    45,164    10.6x  +0.94
  Anthropic/claude-opus              6    90,351   477,020     5.3x  +0.43
  OpenAI/gpt/-sol                    3   126,855   637,242     5.0x  +0.50
  Anthropic/claude-sonnet            4   101,438   479,742     4.7x  +1.00
  Google/gemini/-flash               4    15,511    57,657     3.7x  +1.00
  OpenAI/gpt/-codex                  4     6,948    10,507     1.5x  +1.00
  OpenAI/gpt/-thinking               4    78,961   115,924     1.5x  +0.80
  OpenAI/gpt                         8    12,915    17,753     1.4x  +0.38
  Anthropic/2026-10-30-claude-opus   3    20,273    26,064     1.3x  +1.00
  Anthropic/claude-fable             3   404,644   452,763     1.1x  +0.50
  Anthropic/claude-code-fable        3   431,746   432,230     1.0x  +0.50
  Anthropic/claude-code-sonnet       3   463,846   427,383     0.9x  -0.50
  Anthropic/claude-code-opus         5   471,057   427,817     0.9x  -0.70

  growing 11, shrinking 2, sign test p = 0.0225
```

The growth is real but uneven. It is driven by the vendor-facing model prompts;
the `claude-code-*` series are already near half a megabyte and are flat or
slightly down.

### Safety language is not growing with them

The density of C3, refusal and safety mechanisms, falls in 11 of 13 series
(p = 0.0225), and it is the only category with a significant trend. The raw
counts say why, and they are more convincing than the density arithmetic:

```
  Anthropic/claude-opus          chars    C3 raw   C3 per 10k
    4.5                         90,351         9          1.0
    4.6                        813,377        23          0.3
    4.7                        181,696         9          0.5
    4.8                        183,109         9          0.5
    5                          223,258         9          0.4
    5.5                        477,020        10          0.2

  OpenAI/gpt                     chars    C3 raw   C3 per 10k
    4.1                         12,915         3          2.3
    4.5                         11,018         3          2.7
    5                           21,118         3          1.4
    5.1                         24,397         3          1.2
    5.2                         21,544         3          1.4
    5.4                         12,896         3          2.3
    5.5                        359,517         3          0.1
    5.6                         17,753         4          2.3
```

**The absolute volume of refusal and safety language is close to constant while
the prompt grows several-fold.** Five of Anthropic's six opus generations sit
at nine or ten matches while the prompt grows 5.3x. OpenAI's main gpt line
sits at exactly three across seven consecutive versions, 4.1 through 5.5,
including the one where the prompt jumps to 359,517 characters.

One generation breaks the pattern and is stated rather than smoothed:
**claude-opus 4.6 has 23 matches**, more than double its neighbours. It is
also by far the largest file in the series at 813,377 characters, so its
density is the lowest of the six at 0.3 per 10k. Whether 4.6 is a genuine
outlier or an artifact of a differently assembled file is not something this
corpus can answer.

Even with 4.6 included the point holds, because it is a point about scaling:
the counts move between 9 and 23 while the character count moves between
90,351 and 813,377. That is a stronger statement than "density falls",
because it does not depend on the division. Safety language is not being
removed. It is not scaling with everything else being added.

The direction is downward at each of the four vendors:

```
  C3 density rising / with a direction
    Anthropic   1/7      Google   0/1      OpenAI   1/4      xAI   0/1
```

Read that with the denominators in view. Anthropic at 1/7 and OpenAI at 1/4
are the only two cells with enough series to mean anything; Google and xAI
contribute one series each, so "0/1" is one file pair, not a vendor trend.
Calling this four independent vendors agreeing, as an earlier version of this
section did, credits two single observations as if they were evidence.

### Why this is exploratory and not a finding

Four reasons, all of which belong next to the result rather than in a footnote.

1. **Multiple comparisons.** Thirteen tests were run: length, plus count and
   density for six categories. A Bonferroni threshold is 0.05/13 = 0.0038.
   Both p = 0.0225 results are an order of magnitude short of it. Expect about
   0.65 significant results by chance alone across thirteen tests; two were
   observed.
2. **The series are not independent.** Seven of thirteen are Anthropic, four
   are OpenAI. Series from one vendor share authorship and templates, so the
   effective n is closer to four than thirteen. At n=4 vendors, a unanimous
   direction is p = 0.125.
3. **The detector could be the cause.** C3's measured holdout recall is 0.800.
   If newer prompts phrase refusals in ways these patterns do not match, a
   constant count would be a detector artifact rather than a fact about
   prompts. Testing that needs hand-labelling stratified by version, which has
   not been done.
4. **Survivorship.** The corpus contains the prompts people chose to extract
   and publish. Nothing guarantees the series are complete or that a missing
   version resembles its neighbours.

The honest status: a hypothesis worth pre-registering and testing on a second
corpus, not a result to announce. It is stated here with its p-values and its
threats because that is the only way it is worth anything.

---

## 5.8 Four corpora: do any of these rates transfer?

Every number above section 5.8 describes one collection assembled by one
curator. Three more were fetched, pinned, and measured with the same detectors
to find out whether any of it generalises.

```
  A   asgeirtj/system_prompts_leaks      CC0      frontier vendor prompts + skills
  B1  0xeb/TheBigPromptLibrary           MIT      third-party custom GPT authors
  B2  0xeb/.../SystemPrompts             MIT      vendor prompts, second curator
  C   x1xhlol/...ai-tools                GPL-3.0  coding agents
```

**Zero exact-content overlap** between A and any of them, by normalised SHA-256
over 3,649 files. These are independently assembled, not forks of each other.
B2 is the control: the same population as A, collected by someone else.

### The rates do not transfer

```
  corpus                     n       C1      C2      C3      C4      C5      C6
  ---------------------------------------------------------------------------
  A   frontier vendors    1699    51.4%   50.5%   20.7%    8.9%   24.4%   54.1%
  B1  custom GPT authors  1691     4.6%   13.5%   33.4%    0.5%    5.4%    7.8%
  B2  vendor, 2nd curator  165    43.6%   58.2%   40.0%    4.2%   17.0%   35.2%
  C   coding agents         94    61.7%   76.6%   61.7%    5.3%   45.7%   76.6%
```

C1 runs from **4.6% to 61.7%** depending on who wrote the prompt, at almost
identical n for A and B1. C6 runs from 7.8% to 76.6%.

B2 behaves as a control should: same population type, independently collected,
rates in the same region as A without matching them. So the swing at B1 and C is
a population difference, not detector noise.

**This is the transfer problem one level up.** Section 5.2 showed a detector's
accuracy is a property of the split it was measured on. This shows a *corpus
statistic* is a property of the population it was measured on. "51.4% of system
prompts disclose tool schemas" is not a fact about system prompts. It is a fact
about frontier vendor prompts, and it is wrong by an order of magnitude for the
prompts most people actually write.

### It is not a length artifact

The obvious objection is that custom GPT instructions are shorter, so every
rate falls mechanically. Length explains a factor of two.

```
  corpus                  median chars    mean per-file    pooled
                                          C1 / 10k chars   C1 / 10k chars
  ------------------------------------------------------------------------
  A   frontier vendors           5,794             15.57             2.70
  B1  custom GPT authors         2,643              0.20             0.44
  B2  vendor, 2nd curator        5,277              1.91             1.60
  C   coding agents             12,443              1.44             1.25

  median length A / B1          2.19x
  density gap A / B1                             77.9x             6.1x
```

**Two density columns, because the choice of definition changes the headline
by an order of magnitude and an earlier version of this section printed only
the flattering one.** The mean of per-file rates gives 77.9x. The pooled rate,
total matches divided by total characters, gives 6.1x. The mean is inflated by
short files: one C1 match in a 300-character file scores 33 per 10k, and B1 is
full of short files that score zero, so the two averages diverge.

The honest reading is the pooled one: **a 6.1x density gap against a 2.2x
length gap.** That is still well clear of the length confound, which is what
this section exists to establish, and it does not need the larger number.

Custom GPT authors do not describe tool schemas because they do not have tools
to describe. The difference is real at either definition.

### One category runs the other way

C3, refusal and safety, is the only category where amateur authors score
**higher** than frontier labs: 33.4% against 20.7%. People building a custom GPT
write more refusal language, proportionally, than the labs do. That is
independent corroboration of the drift result in 5.7 from a completely different
direction.

### A composition bias in our own corpus, found by this comparison

A's C1 density is higher than B2's although both are vendor prompts of similar
median length. Splitting A by what the files actually are explains it. A file
counts as a skill or agent file when its path contains `skill` or `agent`,
case-insensitively, which is crude but stated, so the split can be re-derived:

```
  group                     n    share   median chars      C1      C6      C3
  --------------------------------------------------------------------------
  skill / agent files    1222    71.9%          4,588   53.0%   52.2%    9.7%
  plain model prompts     477    28.1%         12,286   47.4%   58.9%   48.8%
```

**71.9% of the primary corpus is agent skill files, not model system prompts**,
and the two differ by 5.0x on C3. A skill file is a task instruction and
carries almost no refusal language; a model prompt carries a great deal.

So the blended "C3 = 20.7%" in section 4.3 describes neither group. The honest
split is 9.7% for skill files and 48.8% for model prompts. Every A-corpus
figure in this document should be read with that composition in mind, and
future work should report the two separately rather than pooling them.

An earlier version of this table gave 1214/485, medians 4,604 and 12,225, and
a 5.7x C3 gap. Those numbers could not be reproduced from any path rule tried,
so they were replaced with figures computed from the stated classifier. The
conclusion is unchanged and the arithmetic now re-derives.

### What survived

One result transfers, and it is the headline. It is not a zero.

**No system prompt in any of the four corpora contains a live credential.**
Three files out of 3,649 carry a credential-shaped string: 1 in A, 2 in B1, 0
in B2, 0 in C. One is the corpus repository's own README and two are
third-party penetration-testing cheat sheets attached to a custom GPT as
knowledge documents. Each was read by hand and the verdicts are in "The
credential headline, corrected twice" above.

The percentage form of this, `0.1%, 0.1%, 0.0%, 0.0%`, is how an earlier
version of this section stated it, and it is a bad way to state it. At three
files out of 3,649 the rate rounds away the only thing worth knowing, and a
0.1% that covers both one file and two hid a real change when the detector
improved. File counts from here on, and CI asserts each one.

---

## 6. Limits

- **Regular expressions over prose.** Every category over-reports or
  under-reports in ways only hand-labelling can quantify. C2 and C6 are the
  weakest and are flagged as low confidence in every finding they produce.
- **Hit rate is not exposure.** A prompt that mentions a tool is not
  necessarily disclosing an exploitable schema. Severity requires a human.
- **No extractability measurement.** This measures what is *in* published
  prompts. Whether a given deployed system would yield its prompt is a
  different question, answered by arXiv 2606.18673, not by this.
- **Markdown only.** Prompts embedded in code, JSON or binaries are not seen.
- **English-centric patterns.** A non-English prompt will be under-reported.
- **One corpus.** Nothing here transfers to a corpus that was assembled
  differently, and no attempt is made to claim it does.
- **The migration linter reads identifiers, not sentences.** It cannot
  distinguish a classification from a mention, so a document *about* the
  taxonomy trips it, and `--write` on prose produces nonsense. This repository's
  own README and this file both fail their own linter for that reason. The
  behaviour is pinned by a test rather than papered over.

### One self-inflicted failure worth recording

The first version of `.gitleaks.toml` attached an allowlist to the
`generic-api-key` rule by redefining it. Redefining a rule replaces the
built-in one, so the scan went quiet: a planted high-entropy key was no longer
caught, and the repository reported clean because the control was broken rather
than because it was secure.

It was caught by planting a secret and checking the scanner still failed, which
took one command and should be routine for any control anyone depends on. The
fix was a global allowlist that names the fixture values and redefines nothing.
A control that reports clean because it was broken is worse than no control,
and this repository is about precisely that failure mode, so the incident stays
in the record.

---

## 7. Ethics and scope

The corpus is CC0 public-domain text, already published, read from local disk.
Nothing was extracted from any live system, and no third-party service was
contacted at any point in this work.

The scanner has **no network code at all**. Every entry point takes a file
path. Fetching the corpus is a shell script the Python package cannot import,
and CI asserts that `hcx` pulls in no network module. That is a structural
guarantee rather than a policy: a tool that cannot reach a live endpoint cannot
be pointed at somebody else's product, by its author or by anyone who clones
it.

Token values are never printed. Every credential-shaped string found across
the four corpora is described here by length, shape and context only, with one
exception: the fabricated `Authorization: Basic` example from a published
penetration-testing cheat sheet is quoted, because it is a made-up string in a
public tutorial and quoting it is what makes the hand verdict checkable.
`hcx` reports credential findings with the value left in the source line
rather than extracted, so piping output to a log does not create a new copy of
something that might be a secret.

---

## 8. What would change these conclusions

- **A live credential found inside an actual prompt.** The result is specific
  to these four corpora and these pins. Re-run after bumping any pin;
  `census --expect-cred` will fail the build rather than let the claim drift.
- **Precision below roughly 0.6 at n=50.** Then the census is measuring the
  detectors rather than the corpus, and the honest publication is the method
  and the failure, not the rates. Pooled holdout precision is currently 0.886
  over 35 predictions, with a 95% interval of [0.74, 0.95], so the lower bound
  is already within 0.14 of that line.
- **C6 not holding up under labelling.** The proposal that capability
  disclosure deserves its own category rests on a 54.1% detector hit rate over
  corpus A and a 58% hand-labelled prevalence at n=50, against a holdout
  precision of 0.818 over 11 predictions. If a larger labelled sample halves
  it, it is an observation, not a proposal.
- **The composition split in 5.8 holding up under a better classifier.**
  71.9% skill files rests on a path-substring test. A real classifier could
  move it several points and would change every A-corpus figure's
  interpretation, though not its value.
