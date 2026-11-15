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
| Size | 38.2 MB |
| Vendors | 17 |

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

### 4.1 Credentials: zero

OWASP's critical tier for LLM08 is credentials in hidden context. Two
independent tools were run over all 1,699 files.

| Tool | Raw hits | After reading the files | 
|---|---|---|
| gitleaks 8.30.1 | 2 | 0 |
| `hcx` credential rule | 2 | 0 |

**Across 1,699 published system prompts from 17 vendors, no live credential was
found.** That is the headline, and it is the good-news story this field rarely
gets to report.

The four raw hits are worth more than the zero, because of how they failed.

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
category. None disclose a credential.

The 45 files beyond the original five were drawn by
`python -m hcx.sample --n 45 --seed 20261115`, proportional by vendor with a
floor of one slot for any vendor holding ten or more files, from files between
200 bytes and 20 KB. That band covers 83.3% of the corpus; the largest prompts
are under-represented, and since a longer prompt has more chance of carrying any
given category, these rates are if anything conservative.

### 4.3 What the detectors report, and why it is lower

Over all 1,699 files:

```
  C1    874 / 1699   51.4%        C5    415 / 1699   24.4%
  C2    858 / 1699   50.5%        C6    919 / 1699   54.1%
  C3    351 / 1699   20.7%        CRED    0 / 1699    0.0%
  C4    152 / 1699    8.9%
```

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
  cat   tp  fp  fn  tn   precision   recall
  ------------------------------------------------
  C1     8   0   4   8       1.000    0.667
  C2     6   0   9   5       1.000    0.400
  C3     4   1   1  14       0.800    0.800
  C4     2   1   2  15       0.667    0.500
  C5     2   0   6  12       1.000    0.250
  C6     9   2   2   7       0.818    0.818
  CRED   0   0   0  20         n/a      n/a
```

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
prior art: MIT, TypeScript, 309 source files, an AISec 2026 evaluation harness,
22 ground-truthed fixtures, 37 wild repos, and baselines against NVIDIA
SkillSpector. It was missed by the GitHub searches recorded in section 7
because it brands around prompts and MCP configs rather than the OWASP
category name. That was a search failure here, not a gap in the field.

It was built from source and run over the same 50 hand-labelled files.

```
  ground truth (human)   48/50 files disclose at least one LLM08:2026 category
  promptsonar             3/50 files flagged, 11 findings total

  rules that fired:  sec_privileged_sink_access  9
                     sec_owasp_llm02_pii         1
                     sec_mcp_tool_poisoning      1
```

**This is not a defeat for promptsonar and it should not be read as one.** It
scores prompt quality and execution risk across seven pillars: injection
patterns, homoglyph evasion, unbounded personas, hardcoded secrets, privileged
sinks. Disclosure is not what it looks for, so finding little on a disclosure
benchmark is the correct behaviour.

The symmetry proves it. Running `hcx` over promptsonar's own 22 controlled
fixtures:

```
  fires C6 on 10 fixtures, C4 on 1, nothing on the other 11
  misses case-007 zero-width-injection, case-016 prompt-injection-llm01,
         case-017 base64-injection, case-008 memory-sensitive
```

Neither tool can do the other's job. **The LLM08:2026 disclosure lane is
genuinely unoccupied, and that is now measured rather than asserted.**

### What their fixtures found in our detector

Two real bugs, both in the credential rule, both now regression-tested.

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
`kebab-case`. Fixed by treating any single-case separator-joined value as a
name, while leaving unbroken hex and mixed-case values as credentials.

That sequence is worth stating plainly: fixing a false negative created six
false positives, and only re-running the full corpus caught it. A detector
change is not done when the new case passes.

### The credential headline, corrected

The earlier claim was "zero credentials across 1,699 files". After a
considerably more aggressive detector, the precise claim is:

> Zero credentials in any system prompt. One token exists corpus-wide: a
> `sealed_token` in a star-history.com chart embed URL, in the corpus
> repository's own `README.md`, which is repository metadata rather than
> hidden context.

That is a stronger result than the original, because it survived a detector
that now catches a form the first one could not see at all.

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

```
  series                        n    first     last   growth   rho
  ------------------------------------------------------------------
  xAI/grok                      6     4,259   45,164   10.6x  +0.94
  Anthropic/claude-opus         6    90,351  477,020    5.3x  +0.43
  OpenAI/gpt-sol                3   126,855  637,242    5.0x  +0.50
  Anthropic/claude-sonnet       4   101,438  479,742    4.7x  +1.00
  Google/gemini-flash           4    15,511   57,657    3.7x  +1.00
  ...
  growing 11, shrinking 2, sign test p = 0.0225
```

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
the prompt grows several-fold.** Anthropic's opus line sits at nine or ten
matches across six generations while the prompt grows 5.3x. OpenAI's main gpt
line sits at exactly three across six consecutive versions.

That is a stronger statement than "density falls", because it does not depend
on the division. Safety language is not being removed. It is simply not scaling
with everything else that is being added.

The majority direction is downward at **all four vendors independently**:

```
  C3 density rising / with a direction
    Anthropic   1/7      Google   0/1      OpenAI   1/4      xAI   0/1
```

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

The obvious objection is that custom GPT instructions are shorter, so every rate
falls mechanically. Length explains a factor of two. The gap is a factor of 78.

```
  corpus                  median chars    C1 matches per 10k chars
  A   frontier vendors           5,794                      15.57
  B1  custom GPT authors         2,649                       0.20
  B2  vendor, 2nd curator        5,277                       1.91
  C   coding agents             12,569                       1.44
```

Custom GPT authors do not describe tool schemas because they do not have tools
to describe. The difference is real.

### One category runs the other way

C3, refusal and safety, is the only category where amateur authors score
**higher** than frontier labs: 33.4% against 20.7%. People building a custom GPT
write more refusal language, proportionally, than the labs do. That is
independent corroboration of the drift result in 5.7 from a completely different
direction.

### A composition bias in our own corpus, found by this comparison

A's C1 density is eight times B2's, although both are vendor prompts of similar
median length. Splitting A by what the files actually are explains it:

```
  group                     n    share   median chars      C1      C6      C3
  --------------------------------------------------------------------------
  skill / agent files    1214    71.5%          4,604   53.7%   52.8%    8.8%
  plain model prompts     485    28.5%         12,225   45.8%   57.3%   50.3%
```

**71.5% of the primary corpus is agent skill files, not model system prompts**,
and the two differ by 5.7x on C3. A skill file is a task instruction and carries
almost no refusal language; a model prompt carries a great deal.

So the blended "C3 = 20.7%" in section 4.3 describes neither group. The honest
split is 8.8% for skill files and 50.3% for model prompts. Every A-corpus figure
in this document should be read with that composition in mind, and future work
should report the two separately rather than pooling them.

### What survived

One result transfers cleanly, and it is the headline.

**Zero credentials, now across 3,649 prompts from four independently assembled
corpora under four different licences.** CRED is 0.1%, 0.1%, 0.0% and 0.0%, and
every hit resolves to a published public token or an identifier on inspection.
That is no longer a fact about one collection.

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

Token values are never printed. The two public tokens found are described by
length and context only, and `hcx` reports credential findings with the value
left in the source line rather than extracted, so piping output to a log does
not create a new copy of something that might be a secret.

---

## 8. What would change these conclusions

- **A credential found at n > 1,699.** The zero is specific to this corpus and
  this pin. Re-run after bumping the pin.
- **Precision below roughly 0.6 at n=50.** Then the census is measuring the
  detectors rather than the corpus, and the honest publication is the method
  and the failure, not the rates.
- **C6 not holding up under labelling.** The proposal that capability
  disclosure deserves its own category rests on a 46.0% hit rate whose
  precision is unmeasured. If hand-labelling halves it, it is an observation,
  not a proposal.
