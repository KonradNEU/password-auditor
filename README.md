# Password Auditor

A local-first CLI that tells you how weak a password is and whether it has
already leaked — without ever sending the password anywhere.

It does two independent things:

1. **Scores the password offline** on length, character variety, and
   predictable patterns (dictionary words, leetspeak, sequences, keyboard
   walks, repeats, dates).
2. **Checks it against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
   Pwned Passwords corpus** using the **k-anonymity** model, so only the first
   five characters of the password's SHA-1 hash leave your machine.

The password is read from a hidden prompt, never from a command-line argument,
so it cannot end up in your shell history or in the process list.

---

## Install

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS/Linux use `python3 -m venv .venv && source .venv/bin/activate`.

## Usage

### Desktop window

```powershell
py main.py
```

Opens a dark-themed window: a masked entry with a Show/Hide toggle, a switch
for the breach lookup, an animated score meter, character-class badges, a
breach banner, and the findings and suggestions as cards. In PyCharm, this is
what the green ▶ arrow runs. Tkinter ships with the standard Windows and macOS
Python installers; on Linux install `python3-tk`.

The stock Tkinter widgets can't be styled into a flat dark look on Windows, so
the switch, badges, buttons and meter are drawn on canvases in
`widgets.py`, against the palette in `theme.py`. The window also asks Windows
for a dark title bar, and falls back silently if that isn't supported.

The window is only a front end — it calls the same `audit()` as the CLI, so
the scoring and the k-anonymity guarantees are identical.

### Terminal

```powershell
py -m password_auditor
```

You will be prompted; typing is hidden:

```
Password (input hidden):
```

### Options

| Flag | Effect |
| --- | --- |
| `--offline` | Skip the breach lookup entirely; score locally only |
| `--stdin` | Read the password from stdin instead of prompting (for pipelines) |
| `--json` | Emit a machine-readable report instead of the text one |
| `--confirm` | Prompt twice and require the entries to match |
| `--timeout SECONDS` | HTTP timeout for the breach lookup (default 10) |
| `--no-color` | Disable ANSI colour (also honours `NO_COLOR`) |
| `--version` | Print the version |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Score ≥ 60 and not found in any breach |
| `1` | Weak: score < 60 |
| `2` | Found in the Pwned Passwords corpus |
| `3` | Usage error (no password supplied, mismatched confirmation) |
| `130` | Interrupted |

That makes it usable in a script:

```bash
if ! printf '%s' "$candidate" | python -m password_auditor --stdin --json > report.json; then
  echo "rejected"
fi
```

### Sample report

```
==================================================================
  PASSWORD AUDIT REPORT
==================================================================

  Strength   ##............................  7/100  VERY WEAK

  Length     8 characters
  Variety    lowercase x8
  Entropy    5.6 bits effective (of 37.6 raw, pool of 26)
  Crack time instantly at 1e+11 guesses/sec offline

  Predictable patterns
    ! dictionary word (chars 1-8): common word or password base

  Breach check (HIBP, k-anonymity)
    ! FOUND in breach data 10,437,277 time(s)
      sent hash prefix 5BAA6 only; matched locally against 853 candidates

  Suggestions
    1. Stop using this password now: it appears 10,437,277 time(s) in
       known breach corpora, so it is already in attackers' wordlists.
    ...
==================================================================
```

---

## How the k-anonymity breach check works

The naive way to ask "has this password leaked?" is to send the password, or
its hash, to a server. Both are bad: the plaintext is obviously fatal, and a
full unsalted SHA-1 is effectively the password too — it can be looked up in
a rainbow table instantly. Either way the server learns your exact secret.

K-anonymity avoids this by asking a deliberately vague question. The server
answers a *bucket* of candidates, and your machine finds the answer inside it.

```
  password                     (never leaves this process)
     |
     | SHA-1, locally
     v
  5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  \___/ \____________________________________/
   |                      |
   | prefix: 5 hex chars  | suffix: 35 hex chars
   | THIS IS SENT         | THIS STAYS LOCAL
   v                      |
  GET https://api.pwnedpasswords.com/range/5BAA6
     |                    |
     v                    v
  ~800 "suffix:count" rows ---> compared locally
                                 |
                                 v
                          count > 0 ? breached
```

Step by step:

1. **Hash locally.** `hashlib.sha1(password)` → a 40-character hex digest.
   SHA-1 is used because it is the key the Pwned Passwords corpus is indexed
   by; it is a lookup key here, not password storage.
2. **Split the digest.** The first 5 hex characters are the *prefix* (20 bits);
   the remaining 35 are the *suffix*.
3. **Send only the prefix.** The request URL is
   `https://api.pwnedpasswords.com/range/5BAA6`. The password, the full hash,
   and the suffix are not in the request — not in the path, not in a header,
   not in a body.
4. **Receive a bucket.** The API returns every known hash suffix sharing that
   prefix, with its breach count. There are 16^5 = 1,048,576 possible prefixes
   spread over ~850 million known hashes, so a bucket holds roughly 800 rows.
5. **Match locally.** `parse_range()` compares your suffix against the bucket
   on your machine. The answer — the part that is actually sensitive — is
   computed here and never transmitted.

**What the server learns:** that someone at your IP has a password whose hash
starts with `5BAA6`, i.e. one of ~800 candidates. That is the "k" in
k-anonymity: you are hidden in a set of size k ≈ 800. It cannot tell which
candidate you hold, whether you were checking your own password, or whether
the lookup found anything.

**What the server never learns:** the password, the full hash, the suffix, and
the result of the check.

### Response padding

An observer who cannot read the TLS traffic can still see its *size*. Because
different prefixes return different numbers of rows, response size is a
fingerprint that narrows down which prefix was requested. The request
therefore sends `Add-Padding: true`, which asks the API to pad the response
with a random number of filler rows that all have a count of `0`. Genuine
entries always have a count of at least 1, so `parse_range()` drops any
zero-count row locally — padding is invisible in the report and does not
inflate the reported anonymity-set size.

### What the tool never does

- It never sends the password or its full hash anywhere.
- It never accepts the password as a CLI argument (no shell-history leak).
- It never prints the password, or any matched substring of it, back to you —
  the report names the *kind* of pattern and its position, not its contents.
- It never writes the password to disk, a log, or a cache.
- `--offline` skips network access entirely if you would rather not make any
  request at all.

---

## Attack replay: *how* it falls

A score tells you a password is weak. The attack replay shows you **why**, by
reconstructing the stages a real cracker works through — and it is the most
useful part of the report.

```
  WHERE THE ENTROPY IS
  [a][a][a][a][a][a][a][a][9][9][9][9][A][#][a][a]
   └──── red: free ─────┘ └─ amber ─┘  └─ green ─┘

  1. Date and year list          2^2 guesses      ← cheapest first
  2. Wordlist + mangling rules   2^6 guesses
  3. Exhaustive brute force      2^26 guesses
  = 3 stages, 2^34 guesses, 3 minutes.
```

- **The heatmap** shows one block per position, coloured by how much entropy
  survives there. A character inside a detected pattern is nearly free to the
  attacker (red); a character no detector can explain costs full price
  (green). Blocks show the character *class* — `a A 9 #` — never the character,
  so the report still never echoes any part of your password.
- **The stages** are ordered cheapest-first, because that is the order an
  attacker actually tries them: breach corpus, then wordlists and rules, then
  keyboard and sequence generators, then brute force over what is left.
- **If the password is breached**, a lookup stage is prepended and every other
  stage is marked *bypassed*. That contrast is the point: 2^60 guesses of
  nominal strength are worth nothing against one lookup in a sorted list.

Each stage's guess count is `2 ** (bits that stage must resolve)`, so the
stages multiply out to exactly `2 ** effective_bits` — the same number the
score comes from. The replay is a different *view* of the score, not a second,
disagreeing estimate. `test_crack.py` asserts that identity holds.

In the GUI the stages animate in one at a time, with a **Replay** button. The
text report and `--json` include the same data.

---

## How the strength score works

The score is an explainable entropy estimate, not a verdict:

1. **Pool size** from the character classes in use — lowercase (26),
   uppercase (26), digits (10), symbols (33), non-ASCII (100, conservative).
2. **Raw entropy** = `length × log2(pool)`.
3. **Pattern refunds.** Each detector marks a span as predictable with a
   *predictability* factor. A recognised span is refunded that fraction of its
   entropy, because a rule-based cracker does not pay full price for it. A
   dictionary word (0.85) keeps only ~15% of its nominal bits.
4. **Score** = surviving bits mapped onto 0–100, where 75 bits = 100.
5. **Breach override.** If the password appears in the corpus, the score is
   capped at 5 no matter how random it looks. A leaked random password is
   already in a wordlist, and wordlist position beats entropy.

Crack times assume 10^11 guesses/second — a well-funded attacker against a
fast, unsalted hash. That is the pessimistic case on purpose.

### Detectors

| Detector | Catches |
| --- | --- |
| `dictionary_word` | Word-list entries, seen through case and leetspeak (`P@ssw0rd` → `password`) |
| `reversed_word` | Word-list entries spelled backwards |
| `keyboard_walk` | Runs of physically adjacent keys (`qwerty`, `1qaz`), using a staggered US-QWERTY adjacency graph |
| `sequence` | Ascending or descending runs of letters or digits (`abcdef`, `9876`) |
| `repeated_char` | `aaaa` |
| `repeated_block` | `abcabcabc` |
| `year` / `date` | `1998`, `12/25/1990` |

Overlapping findings are resolved in favour of the longest match, so a span is
only ever penalised once.

**The score is an estimate.** A high score is not proof of safety: the tool
cannot know that a password is your pet's name, or that you reused it on a site
that has not disclosed a breach yet. Treat it as a floor, not a guarantee.

---

## Project structure

```
password-auditor/
├── main.py                # click-to-run: opens the desktop window
├── password_auditor/
│   ├── __init__.py
│   ├── __main__.py        # `py -m password_auditor`
│   ├── gui.py             # Tkinter window (front end only)
│   ├── widgets.py         # custom flat widgets: switch, pills, score meter
│   ├── theme.py           # palette, fonts, drawing helpers
│   ├── cli.py             # argument parsing, hidden prompt, exit codes
│   ├── auditor.py         # orchestration, breach cap, remediation advice
│   ├── strength.py        # entropy model and scoring
│   ├── crack.py           # attack replay + per-character entropy
│   ├── patterns.py        # offline pattern detectors
│   ├── hibp.py            # k-anonymity lookup
│   ├── report.py          # text and JSON rendering
│   └── data/
│       └── common_words.txt
├── tests/
│   ├── test_patterns.py
│   ├── test_strength.py
│   ├── test_hibp.py
│   ├── test_auditor.py
│   └── test_cli.py
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

## Tests

```powershell
pip install -r requirements-dev.txt
py -m pytest -q
```

The suite never touches the network: the HIBP tests use a fake session that
records the outgoing request, which is how the "only 5 characters are sent"
property is asserted rather than assumed.

## Word list

`password_auditor/data/common_words.txt` is small and deliberately so — it
exists to catch the obvious bases (`password`, `qwerty`, common names, months).
The long tail of genuinely bad passwords is what the HIBP lookup is for. Add
your own entries, one lowercase word per line; `#` starts a comment.

## Licence

MIT.
