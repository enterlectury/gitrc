# gitrc.sh

> **GitHub Secret Scanner for Bug Bounty Hunters**
> Clone public GitHub repos and scan them for leaked API keys, tokens, credentials, and sensitive data — automatically.

Built by [enterlectury](https://github.com/enterlectury)

---

## What It Does

`gitrc.sh` automates the full recon-to-findings pipeline:

1. **Clones** all public repos from a GitHub org/user (or a single repo)
2. **Scans** every repo with three engines running in parallel:
   - 🔴 **TruffleHog** — deep git history scan + filesystem scan
   - 🟠 **Gitleaks** — git history + current working files
   - 🟡 **Custom Regex** — your own pattern library (`regex.txt`)
3. **Outputs** clean results with clickable `leak-link` URLs pointing to the exact file + line on GitHub
4. **Deduplicates** all findings and **filters out** dummy/sample values automatically
5. Optionally merges everything into a **`MASTER.md`** and extracts all **domains/subdomains** to `DOMAINS.md`

---

## Requirements

| Tool | Install |
|------|---------|
| `trufflehog` | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` |
| `gitleaks` | `https://github.com/gitleaks/gitleaks/releases` |
| `jq` | `sudo apt install jq` |
| `git` | `sudo apt install git` |
| `grep` (PCRE) | included in most distros |

---

## Installation

```bash
git clone https://github.com/enterlectury/gitrc
cd gitrc
chmod +x gitrc.sh
```

Place `regex.txt` in the **same folder** as `gitrc.sh`. The script auto-detects it.

---

## Usage

```bash
gitrc.sh <url-or-path> [options]
```

### Arguments

| Input | Mode |
|-------|------|
| `https://github.com/org` | Clone all public repos → scan |
| `https://github.com/user/repo` | Clone single repo → scan |
| `/local/path/to/org/` | Scan only (auto-detected) |

---

## Options

| Option | Description |
|--------|-------------|
| `--clone-only` | Clone only, skip scanning |
| `--concurrency N` | TruffleHog parallel workers (default: 12) |
| `--no-regex` | Skip custom regex (TH + Gitleaks only) |
| `--regex-only` | Run only custom regex scan |
| `--regex-file <path>` | Use a different regex file |
| `--master` | Build `MASTER.md` (all tools merged, deduplicated) |
| `--extract-domains` | Build `DOMAINS.md` (unique domains + full paths) |
| `-h, --help` | Show help |

---

## Examples

```bash
# Scan entire Google org
gitrc.sh "https://github.com/google"

# Scan a single repo
gitrc.sh "https://github.com/enterlectury/Android"

# Scan with more TruffleHog workers
gitrc.sh "https://github.com/google" --concurrency 20

# Scan a local folder you already cloned
gitrc.sh "~/bb-hunting/google/"

# Run only your custom regex (fast, no TH/GL)
gitrc.sh "https://github.com/target" --regex-only

# Full run + build master report + extract domains
gitrc.sh "https://github.com/target" --master --extract-domains

# Use a custom regex file
gitrc.sh "https://github.com/target" --regex-file ~/my-patterns.txt
```

---

## Output Structure

```
<org>/
├── repo1/                  ← Cloned repo
├── repo2/
├── trf-results/
│   ├── repo1.json          ← TruffleHog findings
│   └── SUMMARY.txt
├── gitleaks-results/
│   ├── repo1.json          ← Gitleaks git history
│   ├── repo1_dir.json      ← Gitleaks current files
│   └── SUMMARY.txt
├── regex-results/
│   ├── repo1.txt           ← Custom regex findings
│   └── SUMMARY.txt
├── MASTER.md               ← All findings merged (--master)
└── DOMAINS.md              ← Domains extracted (--extract-domains)
```

---

## leak-link Format

Every finding across all tools includes a `leak-link` field pointing directly to the leaked line on GitHub:

```
https://github.com/org/repo/blob/<commit>/path/to/file.env#L44
```

Links use the **real commit hash** (not `HEAD`) so they are always valid and clickable.

---

## regex.txt — Custom Pattern Library

Edit `regex.txt` to add, remove, or tune patterns. Format:

```
# This is a comment — ignored
Service Name|||PCRE_REGEX_PATTERN
```

**Example entries:**
```
AWS Access Key|||(?:AKIA)[A-Z0-9]{16}
Slack Webhook URL|||https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}
Keyword: stripe_secret|||(?i)\bstripe_secret\s*[:=]\s*['\"]?[A-Za-z0-9]{16,}['\"]?
```

**Keyword patterns** (underscore-connected variable names):
- ✅ `aws_secret_key = "AKIAIOSFODNN7EXAMPLE"` → **flagged**
- ❌ `authsecret` (standalone word, no underscore) → **ignored**

The tool ships with **150+ patterns** covering AWS, Google, GitHub, GitLab, Slack, Stripe, Twilio, Facebook, Heroku, Shopify, Telegram, Discord, and many more.

---

## Smart Filters

`gitrc.sh` automatically ignores:

| Pattern | Example |
|---------|---------|
| Localhost / loopback | `localhost`, `127.0.0.1` |
| All-zeros / all-ones | `000000000000`, `111111111` |
| Placeholder tokens | `ghp_xjeirbvjanxxxxxxxxxxxxxxx` |
| Common dummy values | `changeme`, `your_api_key`, `password123` |
| Repeated single char | `aaaaaaaaaaaaaaaa` |

---

## MASTER.md

Run with `--master` to generate a single Markdown report combining all tool results, deduplicated by `leak-link`:

```markdown
## 🔴 TruffleHog — `repo_name`

| Field      | Value |
|------------|-------|
| leak-link  | https://github.com/... |
| file       | `config.env` |
| commit     | `abc123...` |
| leak       | `AKIAIOSFODNN7EXAMPLE` |
```

---

## DOMAINS.md

Run with `--extract-domains` to extract all domains and subdomains discovered across all findings:

**Section 1** — Unique domains (one per line):
```
https://api.example.com
https://staging.example.com
```

**Section 2** — Full paths (same domain, different endpoints):
```
https://api.example.com/v1/users
https://api.example.com/auth/token
```

---

## Scanning Logic

Each repo is processed by all three engines **simultaneously** using bash background jobs:

```
For each repo:
    TruffleHog git history scan   &
    TruffleHog filesystem scan    &
    Gitleaks git history scan     &
    Gitleaks dir scan             &
    Custom regex grep scan        &
    wait ← all finish before next repo
```

---

## Contributing

To add new patterns, open `regex.txt` and add a line:
```
My Service Name|||your_regex_here
```

To report issues or contribute improvements, open a PR or issue on GitHub.

---

## Disclaimer

This tool is intended for **authorized security testing and bug bounty research only**. Only use it on targets you have explicit permission to test. The author is not responsible for misuse.
