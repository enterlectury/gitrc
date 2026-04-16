# gitrc.sh — Technical Blueprint

> Internal developer reference. Explains every design decision, function, and data flow in the tool.

---

## Overview

`gitrc.sh` is a Bash-based GitHub secret scanner that:
1. Clones public GitHub org/user/repo targets
2. Runs **TruffleHog**, **Gitleaks**, and a **custom regex engine** in parallel per repo
3. Produces structured JSON and text results with clickable GitHub links (`leak-link`)
4. Deduplicates all findings and filters out dummy/sample data
5. Optionally merges all results into a `MASTER.md` and extracts all domains to `DOMAINS.md`

---

## File Structure

```
gitrc.sh          ← Main script
regex.txt             ← Custom regex pattern library (NAME|||PATTERN)

<org>/
├── repo1/            ← Cloned git repo
├── repo2/
├── trf-results/
│   ├── repo1.json    ← TruffleHog findings (NDJSON, one JSON object per line)
│   └── SUMMARY.txt
├── gitleaks-results/
│   ├── repo1.json    ← Gitleaks git history findings (JSON array)
│   ├── repo1_dir.json← Gitleaks current-file findings (JSON array)
│   └── SUMMARY.txt
├── regex-results/
│   ├── repo1.txt     ← Custom regex findings (human-readable blocks)
│   └── SUMMARY.txt
├── MASTER.md         ← All findings merged, deduplicated by leak-link
└── DOMAINS.md        ← All discovered domains, subdomains, full paths
```

---

## Function Reference

### `show_help()`
Prints full CLI usage, options, regex format, and examples. Triggered by `-h`, `--help`, or no arguments.

---

### `is_dummy_value(value)`
Filters out false positives before writing any finding. Returns true (skip) if value:
- Is fewer than 8 characters
- Consists entirely of `0`, `1`, or `x`
- Contains `localhost` or `127.0.0.1`
- Matches placeholder patterns: `xxxx`, `your_key`, `changeme`, `placeholder`, `password123`, etc.
- Matches `ghp_xjeirbvjanxxxxxxxxxxxxxxx` style (many repeated `x`)
- Is a single character repeated (e.g. `aaaaaaaaaa`)

---

### `check_deps()`
Verifies required binaries exist:
- Always: `curl`, `jq`, `git`, `grep`
- If not `--regex-only`: `trufflehog`, `gitleaks`
- If not `--no-regex`: checks that `regex.txt` exists; loads pattern count

---

### `clone_repos()`
Two modes:
- **Single repo** (`https://github.com/user/repo`): Clones one repo directly
- **Org/user level** (`https://github.com/org`): Paginates GitHub API (`/orgs/` then falls back to `/users/`), clones all public repos, skips already-cloned dirs, `sleep 0.5` between clones to be polite

---

### `get_latest_commit(repo_path)`
Runs `git rev-parse HEAD` to get the actual latest commit hash. Used instead of `HEAD` in all `blob/` URLs to prevent **404 links**.

**Problem it solves:** `HEAD` is not a valid ref in GitHub blob URLs — they require a real commit SHA or branch name. All filesystem/dir scan links previously used `HEAD` and returned 404.

---

### `scan_one_trufflehog(repo_name, repo_path)`
Runs two scans:
1. **Git scan** (`trufflehog git file://...`) — full commit history
2. **Filesystem scan** (`trufflehog filesystem ...`) — current working files

After scanning:
- Injects `leak-link` field into every finding using `jq`
- Git findings use the commit hash already present in the result
- Filesystem findings use `get_latest_commit()` to avoid 404
- **Path deduplication fix**: strips `$REPO_PATH/` prefix properly using `ltrimstr` — prevents double paths like `.../enterlectury/Android/enterlectury/Android/file.txt`
- Deduplicates final output with `sort -u`
- Field name: `"leak-link"` (not `"Link"`)

---

### `scan_one_gitleaks(repo_name, repo_path)`
Runs two scans:
1. **Git scan** (`gitleaks git ...`) — full git history; Gitleaks natively provides `Commit` field
2. **Dir scan** (`gitleaks dir ...`) — current working files; no commit in output

After scanning:
- Injects `leak-link` using `jq` into both result files
- Dir scan uses `get_latest_commit()` instead of `HEAD`
- Supports multi-line ranges: appends `-L<EndLine>` when `StartLine != EndLine`
- Deduplicates with `unique_by(."leak-link")` in jq
- Both result files are kept separate for traceability

**Why two files?**
`Android.json` = git history findings (has commit hash).
`Android_dir.json` = current file findings (no commit, use latest). Kept separate so you know which scan found what.

---

### `scan_one_regex(repo_name, repo_path)`
Reads `regex.txt` line by line. For each `NAME|||PATTERN`:
1. Runs `grep -rn -I -P` on all text file extensions in the repo
2. Parses each match into: `file`, `line_number`, `matched_content`
3. Extracts the actual leaked value using `grep -oP` (the matching portion only, not the whole line)
4. Calls `is_dummy_value()` — skips if dummy
5. Builds `leak-link` using real commit hash
6. Tracks seen `leak-link` values in a temp file — skips duplicates
7. Writes clean output blocks:

```
────────────────────────────────────────
  service  : AWS Access Key
  leak-link: https://github.com/org/repo/blob/abc123/config.env#L44
  file     : config.env:44
  leak     : AKIAIOSFODNN7EXAMPLE
```

Result file is deleted if zero findings (keeps results dir clean).

---

### `build_summary(tool_name, out_dir, total_repos)`
Reads `.counts` tracking file, writes `SUMMARY.txt` with per-repo finding counts and totals.

---

### `build_master()`
Triggered by `--master` flag. Reads all three result directories and merges into `MASTER.md`.

Deduplication: uses a temp file of seen `leak-link` values. Any finding whose `leak-link` already appeared is skipped regardless of which tool found it.

Output format per entry (Markdown table):
```markdown
## 🔴 TruffleHog — `repo_name`

| Field      | Value |
|------------|-------|
| leak-link  | https://... |
| file       | `config.env` |
| commit     | `abc123...` |
| leak       | `AKIAIOSFODNN7EXAMPLE` |
```

Colors: 🔴 TruffleHog, 🟠 Gitleaks, 🟡 Regex

---

### `build_domains()`
Triggered by `--extract-domains` flag.

Extracts all `https://` URLs from every result file using `grep -oP`. Writes `DOMAINS.md` with two sections:
- **Section 1**: Unique domains/subdomains only (no paths), sorted, in a code block
- **Section 2**: All full paths (same domain may appear multiple times with different paths), sorted unique, in a code block

---

## regex.txt Format

```
# Comment line — ignored
NAME|||REGEX_PATTERN
```

- Separator is `|||` (3 pipes)
- Name can contain spaces and colons (e.g. `Keyword: aws_secret_key`)
- Pattern is a PCRE regex passed directly to `grep -P`
- Empty lines and `#` lines are ignored

**Keyword patterns** only match underscore-connected variable names followed by `=` or `:`, for example `aws_secret_key = "..."`. Standalone words like `auth` or `authsecret` without an underscore connector are not matched.

---

## Deduplication Strategy

| Layer | Method |
|-------|--------|
| TruffleHog | `sort -u` on raw NDJSON lines |
| Gitleaks | `jq unique_by(."leak-link")` on JSON array |
| Regex | temp file tracks seen `leak-link` strings per repo |
| MASTER.md | shared temp file tracks seen `leak-link` across all tools |

---

## Dummy Value Filter

Values are dropped if they match any of:
- Length < 8
- All zeros, ones, or x's
- `localhost`, `127.0.0.1`, `0.0.0.0`
- `xxxx`, `your_key`, `changeme`, `placeholder`, `password123`, `abc123`, `test123`
- `ghp_xjeirbvjanxxxxxxxxxxxxxxx` style (repeated `x` >= 6)
- Any string where every character is the same

---

## Parallel Execution Model

```
For each repo:
    scan_one_trufflehog &   ←── background process 1
    scan_one_gitleaks   &   ←── background process 2
    scan_one_regex      &   ←── background process 3
    wait                    ←── wait for all 3 before next repo
```

This keeps memory usage controlled (not all repos at once) while maximising per-repo speed.

---

## URL / Link Construction

All three tools produce a `leak-link` field with this format:
```
https://github.com/<org>/<repo>/blob/<real_commit>/<relative/path/to/file>#L<line>
```

For multi-line Gitleaks findings:
```
...#L<StartLine>-L<EndLine>
```

The `get_latest_commit()` function (`git rev-parse HEAD`) ensures the commit is always a real 40-char SHA, never the string `HEAD`, so all links are valid and clickable on GitHub.

---

## Flags Reference

| Flag | Effect |
|------|--------|
| `--clone-only` | Clone only, no scanning |
| `--concurrency N` | TruffleHog workers per repo (default 12) |
| `--no-regex` | Skip regex scan |
| `--regex-only` | Run only regex (skip TH + GL) |
| `--regex-file <path>` | Use custom regex file |
| `--master` | Build MASTER.md after scanning |
| `--extract-domains` | Build DOMAINS.md after scanning |
| `-h / --help` | Show help |
