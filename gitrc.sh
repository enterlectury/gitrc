#!/bin/bash
# =============================================================================
# gitrc.sh — Clone public GitHub repos + scan for secrets
# Tools: TruffleHog + Gitleaks + Custom Regex (parallel per repo)
# Author: Aditya (enterlectury) | https://github.com/enterlectury
# =============================================================================
# Usage:
#   gitrc.sh "https://github.com/google"
#   gitrc.sh "path/of/repo/google"
#   gitrc.sh "https://github.com/google" --clone-only
#   gitrc.sh "~/bb-hunting/google/" --concurrency 20
#   gitrc.sh "https://github.com/google" --regex-only
#   gitrc.sh "https://github.com/google" --no-regex
#   gitrc.sh "https://github.com/google" --regex-file /custom/path/regex.txt
#   gitrc.sh "https://github.com/google" --master
#   gitrc.sh "https://github.com/google" --extract-domains
#
# Output structure:
#   google/
#   ├── repo1/
#   ├── trf-results/
#   │   ├── repo1.json          ← TruffleHog findings (leak-link field)
#   │   └── SUMMARY.txt
#   ├── gitleaks-results/
#   │   ├── repo1.json          ← Gitleaks git history findings
#   │   ├── repo1_dir.json      ← Gitleaks current-file findings
#   │   └── SUMMARY.txt
#   ├── regex-results/
#   │   ├── repo1.txt           ← Regex findings (clean line-by-line)
#   │   └── SUMMARY.txt
#   ├── MASTER.md               ← All findings merged, deduplicated (--master)
#   └── DOMAINS.md              ← Extracted domains/subdomains (--extract-domains)
# =============================================================================

# -----------------------------------------------------------------------------
# HELP
# -----------------------------------------------------------------------------
show_help() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            gitrc.sh — GitHub Secret Scanner              ║"
    echo "║       TruffleHog + Gitleaks + Custom Regex (parallel)        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "USAGE:"
    echo "  gitrc.sh <url-or-path> [options]"
    echo ""
    echo "ARGUMENTS:"
    echo "  <url>     GitHub org/user URL  → clone all repos + scan"
    echo "            GitHub single repo   → clone one repo + scan"
    echo "  <path>    Local folder path    → scan only (auto-detected)"
    echo ""
    echo "OPTIONS:"
    echo "  --clone-only              Only clone repos, skip scanning"
    echo "  --concurrency N           TruffleHog parallel workers (default: 12)"
    echo "  --no-regex                Skip custom regex (TruffleHog + Gitleaks only)"
    echo "  --regex-only              Custom regex scan only (skip TH + Gitleaks)"
    echo "  --regex-file <path>       Custom regex.txt path (default: next to script)"
    echo "  --master                  Build MASTER.md after scanning (all tools merged)"
    echo "  --extract-domains         Build DOMAINS.md after scanning"
    echo "  -h, --help                Show this help"
    echo ""
    echo "REGEX FILE FORMAT (regex.txt):"
    echo "  NAME|||PATTERN            3-pipe separator"
    echo "  Lines starting with #     are comments (skipped)"
    echo "  Example:"
    echo "    AWS Access Key|||(?:AKIA)[A-Z0-9]{16}"
    echo "    Keyword: aws_secret_key|||(?i)\baws_secret_key\s*[:=]\s*['\"]?[A-Za-z0-9]{16,}['\"]?"
    echo ""
    echo "EXAMPLES:"
    echo "  gitrc.sh \"https://github.com/google\""
    echo "  gitrc.sh \"https://github.com/enterlectury/Android\""
    echo "  gitrc.sh \"~/bb-hunting/google/\" --concurrency 20"
    echo "  gitrc.sh \"https://github.com/google\" --regex-only"
    echo "  gitrc.sh \"https://github.com/google\" --master --extract-domains"
    echo "  gitrc.sh \"https://github.com/google\" --regex-file ~/my-regex.txt"
    echo ""
    echo "OUTPUT:"
    echo "  trf-results/              TruffleHog .json per repo"
    echo "  gitleaks-results/         Gitleaks .json per repo"
    echo "  regex-results/            Custom regex .txt per repo"
    echo "  MASTER.md                 All leaks merged + deduplicated"
    echo "  DOMAINS.md                Unique domains + full paths"
    echo ""
    exit 0
}

# -----------------------------------------------------------------------------
# DEFAULT CONFIG
# -----------------------------------------------------------------------------
INPUT=""
CLONE_ONLY=false
SCAN_ONLY=false
CONCURRENCY=12
NO_REGEX=false
REGEX_ONLY=false
BUILD_MASTER=false
EXTRACT_DOMAINS=false

TH_RESULTS="verified,unverified,unknown"
TRF_RESULTS_DIR="trf-results"
GL_RESULTS_DIR="gitleaks-results"
RX_RESULTS_DIR="regex-results"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGEX_FILE="$SCRIPT_DIR/regex.txt"

# -----------------------------------------------------------------------------
# DUMMY/SAMPLE DATA — values matching these are suppressed as false positives
# Pattern: localhost, 127.0.0.1, all same char repeated, placeholder tokens
# -----------------------------------------------------------------------------
is_dummy_value() {
    local VAL="$1"
    # Too short to be real
    [ "${#VAL}" -lt 8 ] && return 0
    # All zeros, ones, or x's
    echo "$VAL" | grep -qP '^[0x]+$'          && return 0
    echo "$VAL" | grep -qP '^1+$'             && return 0
    echo "$VAL" | grep -qiP '^x+$'            && return 0
    # Localhost / loopback
    echo "$VAL" | grep -qP '(localhost|127\.0\.0\.1|0\.0\.0\.0)' && return 0
    # Placeholder patterns like xxxx, 0000, 1111, your_key, YOUR_KEY, changeme
    echo "$VAL" | grep -qiP '(xxxx|0{6,}|1{6,}|your[_-]?(key|secret|token|password)|changeme|placeholder|example|test123|password123|abc123|insert_here)' && return 0
    # GitHub placeholder tokens like ghp_xjeirbvjanxxxxxxxxxxxxxxx
    echo "$VAL" | grep -qiP 'x{6,}' && return 0
    # All same character repeated
    local FIRST="${VAL:0:1}"
    local REPEATED
    REPEATED=$(printf "%${#VAL}s" | tr ' ' "$FIRST")
    [ "$VAL" = "$REPEATED" ] && return 0
    return 1
}

# -----------------------------------------------------------------------------
# PARSE ARGUMENTS
# -----------------------------------------------------------------------------
if [[ "$1" == "-h" || "$1" == "--help" || -z "$1" ]]; then
    show_help
fi

INPUT="$1"
shift

while [[ "$1" != "" ]]; do
    case $1 in
        --clone-only )      CLONE_ONLY=true ;;
        --concurrency )     shift; CONCURRENCY="$1" ;;
        --no-regex )        NO_REGEX=true ;;
        --regex-only )      REGEX_ONLY=true ;;
        --regex-file )      shift; REGEX_FILE="${1/#\~/$HOME}" ;;
        --master )          BUILD_MASTER=true ;;
        --extract-domains ) EXTRACT_DOMAINS=true ;;
        -h | --help )       show_help ;;
        * ) echo "❌ Unknown option: $1"; show_help ;;
    esac
    shift
done

INPUT="${INPUT%/}"

if [[ "$INPUT" == http* ]]; then
    IS_URL=true
    ORG_URL="$INPUT"
    URL_PATH="${ORG_URL#https://github.com/}"
    SEGMENT_COUNT=$(echo "$URL_PATH" | tr '/' '\n' | grep -c .)
    if [ "$SEGMENT_COUNT" -eq 1 ]; then
        ORG_NAME="$URL_PATH"
        SINGLE_REPO_URL=""
    else
        ORG_NAME=$(echo "$URL_PATH" | cut -d'/' -f1)
        REPO_ONLY=$(echo "$URL_PATH" | cut -d'/' -f2)
        SINGLE_REPO_URL="${ORG_URL}.git"
    fi
    BASE_DIR="./$ORG_NAME"
else
    IS_URL=false
    SCAN_ONLY=true
    BASE_DIR="${INPUT/#\~/$HOME}"
    ORG_NAME=$(basename "$BASE_DIR")
    SINGLE_REPO_URL=""
    echo "📂 Local path detected — switching to scan-only mode automatically."
fi

TRF_OUT="$BASE_DIR/$TRF_RESULTS_DIR"
GL_OUT="$BASE_DIR/$GL_RESULTS_DIR"
RX_OUT="$BASE_DIR/$RX_RESULTS_DIR"

# -----------------------------------------------------------------------------
# DEPENDENCY CHECK
# -----------------------------------------------------------------------------
check_deps() {
    echo "🔍 Checking dependencies..."
    for cmd in curl jq git grep; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "❌ Missing: $cmd — please install it."
            exit 1
        fi
    done
    if [ "$CLONE_ONLY" = false ] && [ "$REGEX_ONLY" = false ]; then
        if ! command -v trufflehog &>/dev/null; then
            echo "❌ Missing: trufflehog"
            echo "   Install: https://github.com/trufflesecurity/trufflehog"
            exit 1
        fi
        if ! command -v gitleaks &>/dev/null; then
            echo "❌ Missing: gitleaks"
            echo "   Install: https://github.com/gitleaks/gitleaks"
            exit 1
        fi
    fi
    if [ "$NO_REGEX" = false ] && [ "$CLONE_ONLY" = false ]; then
        if [ ! -f "$REGEX_FILE" ]; then
            echo "⚠️  Regex file not found: $REGEX_FILE"
            echo "   Place regex.txt next to gitrc.sh or use --regex-file <path>"
            echo "   Skipping custom regex scan."
            NO_REGEX=true
        else
            PATTERN_COUNT=$(grep -c '|||' "$REGEX_FILE" 2>/dev/null || echo 0)
            echo "📋 Regex file: $REGEX_FILE ($PATTERN_COUNT patterns loaded)"
        fi
    fi
    echo "✅ Dependencies OK."
}

# =============================================================================
# [CLONE SECTION]
# =============================================================================
clone_repos() {
    echo ""
    mkdir -p "$BASE_DIR"
    if [ -n "$SINGLE_REPO_URL" ]; then
        echo "📥 Cloning single repo: $REPO_ONLY"
        REPO_PATH="$BASE_DIR/$REPO_ONLY"
        if [ -d "$REPO_PATH" ]; then
            echo "⏭️  Already cloned, skipping: $REPO_ONLY"
        else
            git clone "$SINGLE_REPO_URL" "$REPO_PATH" --quiet
            [ $? -eq 0 ] && echo "✅ Cloned: $REPO_ONLY" || echo "⚠️  Failed: $SINGLE_REPO_URL"
        fi
        return
    fi
    echo "📥 Cloning all public repos for: $ORG_NAME"
    echo "📁 Destination: $BASE_DIR/"
    echo ""
    PER_PAGE=100; PAGE=1; TOTAL_CLONED=0; TOTAL_SKIPPED=0
    while :; do
        REPOS=$(curl -s "https://api.github.com/orgs/$ORG_NAME/repos?per_page=$PER_PAGE&page=$PAGE&type=public" \
            | jq -r '.[].clone_url' 2>/dev/null)
        if [ -z "$REPOS" ]; then
            REPOS=$(curl -s "https://api.github.com/users/$ORG_NAME/repos?per_page=$PER_PAGE&page=$PAGE" \
                | jq -r '.[].clone_url' 2>/dev/null)
        fi
        [ -z "$REPOS" ] && break
        for REPO_URL in $REPOS; do
            REPO_NAME=$(basename "$REPO_URL" .git)
            REPO_PATH="$BASE_DIR/$REPO_NAME"
            if [ -d "$REPO_PATH" ]; then
                echo "⏭️  Already cloned: $REPO_NAME"; ((TOTAL_SKIPPED++)); continue
            fi
            echo "🔗 Cloning: $REPO_NAME"
            git clone "$REPO_URL" "$REPO_PATH" --quiet
            [ $? -eq 0 ] && { echo "   ✅ Done: $REPO_NAME"; ((TOTAL_CLONED++)); } || echo "   ⚠️  Failed: $REPO_NAME"
            sleep 0.5
        done
        ((PAGE++))
    done
    echo ""
    echo "📦 Clone complete: $TOTAL_CLONED cloned, $TOTAL_SKIPPED skipped."
}

# =============================================================================
# [HELPER] Get latest commit hash for HEAD (used in filesystem scan link fix)
# =============================================================================
get_latest_commit() {
    local REPO_PATH="$1"
    git -C "$REPO_PATH" rev-parse HEAD 2>/dev/null || echo "HEAD"
}

# =============================================================================
# [SCAN SECTION — TRUFFLEHOG]
# Unified leak-link field, deduplication, dummy value filter
# =============================================================================
scan_one_trufflehog() {
    local REPO_NAME="$1"
    local REPO_PATH="$2"
    local RESULT_FILE="$TRF_OUT/${REPO_NAME}.json"
    local TMP_GIT="$TRF_OUT/.tmp_trf_git_${REPO_NAME}.json"
    local TMP_FS="$TRF_OUT/.tmp_trf_fs_${REPO_NAME}.json"
    local TMP_ALL="$TRF_OUT/.tmp_trf_all_${REPO_NAME}.json"

    echo "[TruffleHog] 🔎 Starting: $REPO_NAME"

    REMOTE_URL=$(git -C "$REPO_PATH" remote get-url origin 2>/dev/null | sed 's/\.git$//')
    LATEST_COMMIT=$(get_latest_commit "$REPO_PATH")
    [ -z "$REMOTE_URL" ] && echo "[TruffleHog] ⚠️  No remote URL for $REPO_NAME"

    trufflehog git "file://$REPO_PATH" \
        --results="$TH_RESULTS" --json --concurrency="$CONCURRENCY" --no-update \
        2>/dev/null > "$TMP_GIT"

    trufflehog filesystem "$REPO_PATH" \
        --results="$TH_RESULTS" --json --no-update \
        2>/dev/null > "$TMP_FS"

    {
        # Git scan: has real commit hash
        if [ -f "$TMP_GIT" ] && [ -s "$TMP_GIT" ]; then
            jq -c --arg base "$REMOTE_URL" '
                . + {
                    "leak-link": (
                        $base + "/blob/" +
                        (.SourceMetadata.Data.Git.commit // "HEAD") + "/" +
                        (.SourceMetadata.Data.Git.file // "") +
                        "#L" + ((.SourceMetadata.Data.Git.line // 0) | tostring)
                    )
                }
            ' "$TMP_GIT" 2>/dev/null
        fi

        # Filesystem scan: strip double base path, use latest real commit not HEAD
        if [ -f "$TMP_FS" ] && [ -s "$TMP_FS" ]; then
            jq -c --arg base "$REMOTE_URL" --arg repopath "$REPO_PATH" --arg commit "$LATEST_COMMIT" '
                . + {
                    "leak-link": (
                        $base + "/blob/" + $commit + "/" +
                        ((.SourceMetadata.Data.Filesystem.file // "")
                            | ltrimstr($repopath + "/")
                            | ltrimstr($repopath)
                            | ltrimstr("/")
                        ) +
                        "#L" + ((.SourceMetadata.Data.Filesystem.line // 0) | tostring)
                    )
                }
            ' "$TMP_FS" 2>/dev/null
        fi
    } > "$TMP_ALL"

    # Deduplicate by leak-link field
    if [ -f "$TMP_ALL" ] && [ -s "$TMP_ALL" ]; then
        sort -u "$TMP_ALL" > "$RESULT_FILE"
    fi

    rm -f "$TMP_GIT" "$TMP_FS" "$TMP_ALL"

    local COUNT=0
    [ -f "$RESULT_FILE" ] && [ -s "$RESULT_FILE" ] && COUNT=$(grep -c . "$RESULT_FILE" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] \
        && echo "[TruffleHog] 🚨 $REPO_NAME — $COUNT finding(s) → trf-results/${REPO_NAME}.json" \
        || echo "[TruffleHog] ✅ $REPO_NAME — clean"
    echo "$REPO_NAME $COUNT" >> "$TRF_OUT/.counts"
}

# =============================================================================
# [SCAN SECTION — GITLEAKS]
# Adds leak-link field to both git and dir scan results
# Dir scan uses latest real commit instead of HEAD to prevent 404
# =============================================================================
scan_one_gitleaks() {
    local REPO_NAME="$1"
    local REPO_PATH="$2"
    local RESULT_GIT="$GL_OUT/${REPO_NAME}.json"
    local RESULT_DIR="$GL_OUT/${REPO_NAME}_dir.json"
    local TMP_GIT_LINKED="$GL_OUT/.tmp_gl_git_${REPO_NAME}.json"
    local TMP_DIR_LINKED="$GL_OUT/.tmp_gl_dir_${REPO_NAME}.json"

    echo "[Gitleaks]   🔎 Starting: $REPO_NAME"

    REMOTE_URL=$(git -C "$REPO_PATH" remote get-url origin 2>/dev/null | sed 's/\.git$//')
    LATEST_COMMIT=$(get_latest_commit "$REPO_PATH")

    # --- Git history scan ---
    gitleaks git "$REPO_PATH" \
        --report-format=json --report-path="$TMP_GIT_LINKED" \
        --no-banner --exit-code=0 2>/dev/null

    # --- Dir / working-files scan ---
    gitleaks dir "$REPO_PATH" \
        --report-format=json --report-path="$TMP_DIR_LINKED" \
        --no-banner --exit-code=0 2>/dev/null

    # Inject leak-link into git scan results (Commit is already in gitleaks output)
    if [ -f "$TMP_GIT_LINKED" ] && [ -s "$TMP_GIT_LINKED" ]; then
        jq --arg base "$REMOTE_URL" '
            if type == "array" then
                [ .[] | . + {
                    "leak-link": (
                        $base + "/blob/" +
                        (.Commit // "HEAD") + "/" +
                        (.File // "") +
                        "#L" + ((.StartLine // 0) | tostring) +
                        if (.StartLine != .EndLine and .EndLine != null)
                            then "-L" + (.EndLine | tostring)
                            else "" end
                    )
                }]
            else . end
        ' "$TMP_GIT_LINKED" 2>/dev/null \
        | jq 'if type == "array" then unique_by(."leak-link") else . end' \
        > "$RESULT_GIT"
    fi

    # Inject leak-link into dir scan results (no commit — use real latest commit)
    if [ -f "$TMP_DIR_LINKED" ] && [ -s "$TMP_DIR_LINKED" ]; then
        jq --arg base "$REMOTE_URL" --arg repopath "$REPO_PATH" --arg commit "$LATEST_COMMIT" '
            if type == "array" then
                [ .[] | . + {
                    "leak-link": (
                        $base + "/blob/" + $commit + "/" +
                        ((.File // "") | ltrimstr($repopath + "/") | ltrimstr($repopath) | ltrimstr("/")) +
                        "#L" + ((.StartLine // 0) | tostring) +
                        if (.StartLine != .EndLine and .EndLine != null)
                            then "-L" + (.EndLine | tostring)
                            else "" end
                    )
                }]
            else . end
        ' "$TMP_DIR_LINKED" 2>/dev/null \
        | jq 'if type == "array" then unique_by(."leak-link") else . end' \
        > "$RESULT_DIR"
    fi

    rm -f "$TMP_GIT_LINKED" "$TMP_DIR_LINKED"

    local COUNT_GIT=0
    local COUNT_DIR=0
    [ -f "$RESULT_GIT" ] && [ -s "$RESULT_GIT" ] && COUNT_GIT=$(jq 'if type == "array" then length else 0 end' "$RESULT_GIT" 2>/dev/null || echo 0)
    [ -f "$RESULT_DIR" ] && [ -s "$RESULT_DIR" ] && COUNT_DIR=$(jq 'if type == "array" then length else 0 end' "$RESULT_DIR" 2>/dev/null || echo 0)
    local TOTAL_COUNT=$((COUNT_GIT + COUNT_DIR))

    [ "$TOTAL_COUNT" -gt 0 ] \
        && echo "[Gitleaks]   🚨 $REPO_NAME — $TOTAL_COUNT finding(s) (git:$COUNT_GIT dir:$COUNT_DIR) → gitleaks-results/" \
        || echo "[Gitleaks]   ✅ $REPO_NAME — clean"
    echo "$REPO_NAME $TOTAL_COUNT" >> "$GL_OUT/.counts"
}

# =============================================================================
# [SCAN SECTION — CUSTOM REGEX]
# Clean output format per item:
#   service  : <NAME>
#   leak-link: https://github.com/org/repo/blob/<commit>/file.ext#L42
#   file     : relative/path/file.ext:42
#   leak     : the-actual-matched-value
# Dummy values are suppressed. Duplicate leak-links are skipped.
# =============================================================================
scan_one_regex() {
    local REPO_NAME="$1"
    local REPO_PATH="$2"
    local RESULT_FILE="$RX_OUT/${REPO_NAME}.txt"

    echo "[Regex]      🔎 Starting: $REPO_NAME"

    REMOTE_URL=$(git -C "$REPO_PATH" remote get-url origin 2>/dev/null | sed 's/\.git$//')
    LATEST_COMMIT=$(get_latest_commit "$REPO_PATH")

    local COUNT=0
    # Track seen leak-links to deduplicate
    local SEEN_LINKS_FILE
    SEEN_LINKS_FILE=$(mktemp)

    {
        echo "========================================"
        echo " gitrc.sh — Custom Regex Results"
        echo " Repo   : $REPO_NAME"
        echo " Date   : $(date)"
        echo " Remote : ${REMOTE_URL:-local}"
        echo "========================================"
        echo ""

        while IFS= read -r LINE; do
            [[ -z "$LINE" || "$LINE" == \#* ]] && continue
            PATTERN_NAME="${LINE%%|||*}"
            PATTERN_REGEX="${LINE##*|||}"
            [[ -z "$PATTERN_NAME" || -z "$PATTERN_REGEX" ]] && continue

            MATCHES=$(grep -rn -I \
                --include="*.js"  --include="*.ts"   --include="*.jsx"  --include="*.tsx" \
                --include="*.py"  --include="*.rb"   --include="*.php"  --include="*.java" \
                --include="*.go"  --include="*.cs"   --include="*.cpp"  --include="*.c" \
                --include="*.sh"  --include="*.bash" --include="*.env"  --include="*.cfg" \
                --include="*.conf" --include="*.config" --include="*.ini" --include="*.yaml" \
                --include="*.yml" --include="*.json" --include="*.xml"  --include="*.toml" \
                --include="*.properties" --include="*.gradle" --include="*.tf" \
                --include="*.txt" --include="*.md"   --include="*.html" --include="*.htm" \
                --include="*.sql" --include="*.log"  --include="*.pem"  --include="*.key" \
                --include="*.pub" --include="*.cert" --include="*.crt" \
                -P "$PATTERN_REGEX" "$REPO_PATH" 2>/dev/null)

            if [ -n "$MATCHES" ]; then
                while IFS= read -r MATCH_LINE; do
                    # Parse file:line:content
                    REL_PATH="${MATCH_LINE#$REPO_PATH/}"
                    FILE_PART="${REL_PATH%%:*}"
                    REST="${REL_PATH#*:}"
                    LINE_NUM="${REST%%:*}"
                    MATCHED_CONTENT="${REST#*:}"

                    # Extract just the actual leaked value (trim leading whitespace/assignment)
                    LEAK_VALUE=$(echo "$MATCHED_CONTENT" | sed 's/^[[:space:]]*//' \
                        | grep -oP "$PATTERN_REGEX" 2>/dev/null | head -1)
                    [ -z "$LEAK_VALUE" ] && LEAK_VALUE=$(echo "$MATCHED_CONTENT" | sed 's/^[[:space:]]*//')

                    # Skip dummy/sample values
                    is_dummy_value "$LEAK_VALUE" && continue

                    # Build leak-link using real commit
                    LEAK_LINK="${REMOTE_URL}/blob/${LATEST_COMMIT}/${FILE_PART}#L${LINE_NUM}"

                    # Deduplicate by leak-link
                    if grep -qF "$LEAK_LINK" "$SEEN_LINKS_FILE" 2>/dev/null; then
                        continue
                    fi
                    echo "$LEAK_LINK" >> "$SEEN_LINKS_FILE"

                    echo "────────────────────────────────────────"
                    echo "  service  : $PATTERN_NAME"
                    echo "  leak-link: $LEAK_LINK"
                    echo "  file     : $FILE_PART:$LINE_NUM"
                    echo "  leak     : $LEAK_VALUE"
                    echo ""
                    ((COUNT++))
                done <<< "$MATCHES"
            fi
        done < "$REGEX_FILE"

        if [ "$COUNT" -eq 0 ]; then
            echo "✅ No findings."
        fi
        echo "========================================"
        echo " TOTAL FINDINGS: $COUNT"
        echo "========================================"
    } > "$RESULT_FILE"

    rm -f "$SEEN_LINKS_FILE"

    [ "$COUNT" -gt 0 ] \
        && echo "[Regex]      🚨 $REPO_NAME — $COUNT finding(s) → regex-results/${REPO_NAME}.txt" \
        || { echo "[Regex]      ✅ $REPO_NAME — clean"; rm -f "$RESULT_FILE"; }
    echo "$REPO_NAME $COUNT" >> "$RX_OUT/.counts"
}

# =============================================================================
# [PARALLEL SCAN ORCHESTRATOR]
# =============================================================================
scan_repos() {
    echo ""
    if [ "$REGEX_ONLY" = true ]; then
        echo "🔍 Scan mode: Custom Regex only"
        echo "📂 Source       : $BASE_DIR/"
        echo "💾 Regex results: $RX_OUT/"
        echo "📋 Regex file   : $REGEX_FILE"
    elif [ "$NO_REGEX" = true ]; then
        echo "🔍 Scan mode: TruffleHog + Gitleaks"
        echo "📂 Source              : $BASE_DIR/"
        echo "💾 TruffleHog results  : $TRF_OUT/"
        echo "💾 Gitleaks results    : $GL_OUT/"
        echo "🎯 TH filter           : $TH_RESULTS"
        echo "⚙️  TH concurrency     : $CONCURRENCY workers"
    else
        echo "🔍 Scan mode: TruffleHog + Gitleaks + Custom Regex (parallel)"
        echo "📂 Source              : $BASE_DIR/"
        echo "💾 TruffleHog results  : $TRF_OUT/"
        echo "💾 Gitleaks results    : $GL_OUT/"
        echo "💾 Regex results       : $RX_OUT/"
        echo "🎯 TH filter           : $TH_RESULTS"
        echo "⚙️  TH concurrency     : $CONCURRENCY workers"
        echo "📋 Regex file          : $REGEX_FILE"
    fi
    echo ""

    [ "$REGEX_ONLY" = false ] && mkdir -p "$TRF_OUT" && mkdir -p "$GL_OUT"
    [ "$NO_REGEX"   = false ] && mkdir -p "$RX_OUT"
    [ "$REGEX_ONLY" = false ] && rm -f "$TRF_OUT/.counts" && rm -f "$GL_OUT/.counts"
    [ "$NO_REGEX"   = false ] && rm -f "$RX_OUT/.counts"

    TOTAL_REPOS=0
    for REPO_PATH in "$BASE_DIR"/*/; do
        REPO_NAME=$(basename "$REPO_PATH")
        [[ "$REPO_NAME" == "$TRF_RESULTS_DIR" || "$REPO_NAME" == "$GL_RESULTS_DIR" || "$REPO_NAME" == "$RX_RESULTS_DIR" ]] && continue
        if [ ! -d "$REPO_PATH/.git" ]; then
            echo "⚠️  Not a git repo, skipping: $REPO_NAME"
            continue
        fi
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📦 Repo: $REPO_NAME"
        if [ "$REGEX_ONLY" = true ]; then
            scan_one_regex      "$REPO_NAME" "$REPO_PATH" &
        elif [ "$NO_REGEX" = true ]; then
            scan_one_trufflehog "$REPO_NAME" "$REPO_PATH" &
            scan_one_gitleaks   "$REPO_NAME" "$REPO_PATH" &
        else
            scan_one_trufflehog "$REPO_NAME" "$REPO_PATH" &
            scan_one_gitleaks   "$REPO_NAME" "$REPO_PATH" &
            scan_one_regex      "$REPO_NAME" "$REPO_PATH" &
        fi
        wait
        ((TOTAL_REPOS++))
    done

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ "$REGEX_ONLY" = false ] && build_summary "TruffleHog" "$TRF_OUT" "$TOTAL_REPOS"
    [ "$REGEX_ONLY" = false ] && build_summary "Gitleaks"   "$GL_OUT"  "$TOTAL_REPOS"
    [ "$NO_REGEX"   = false ] && build_summary "Regex"      "$RX_OUT"  "$TOTAL_REPOS"
}

# =============================================================================
# [SUMMARY BUILDER]
# =============================================================================
build_summary() {
    local TOOL_NAME="$1"; local OUT_DIR="$2"; local TOTAL_REPOS="$3"
    local SUMMARY_FILE="$OUT_DIR/SUMMARY.txt"
    local COUNTS_FILE="$OUT_DIR/.counts"
    local TOTAL_FINDINGS=0; local REPOS_WITH_FINDINGS=0
    {
        echo "========================================"
        echo " gitrc.sh — $TOOL_NAME Scan SUMMARY"
        echo " Target : $ORG_NAME"
        echo " Date   : $(date)"
        echo "========================================"
        echo ""
        if [ -f "$COUNTS_FILE" ]; then
            while read -r REPO COUNT; do
                if [ "$COUNT" -gt 0 ]; then
                    echo "🚨 $REPO — $COUNT finding(s)"
                    ((REPOS_WITH_FINDINGS++))
                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
                else
                    echo "✅ $REPO — clean"
                fi
            done < "$COUNTS_FILE"
        fi
        echo ""
        echo "========================================"
        echo " TOTAL REPOS SCANNED  : $TOTAL_REPOS"
        echo " REPOS WITH FINDINGS  : $REPOS_WITH_FINDINGS"
        echo " TOTAL FINDINGS       : $TOTAL_FINDINGS"
        echo "========================================"
    } > "$SUMMARY_FILE"
    rm -f "$COUNTS_FILE"
    echo "📄 [$TOOL_NAME] SUMMARY → $SUMMARY_FILE (repos:$TOTAL_REPOS findings:$TOTAL_FINDINGS)"
}

# =============================================================================
# [MASTER.md BUILDER — Task 7]
# Merges TruffleHog + Gitleaks + Regex results into one deduplicated .md file
# Deduplication key: leak-link field
# =============================================================================
build_master() {
    local MASTER_FILE="$BASE_DIR/MASTER.md"
    local SEEN_FILE
    SEEN_FILE=$(mktemp)
    local COUNT=0

    echo "📝 Building MASTER.md..."

    {
        echo "# gitrc.sh — Master Leak Report"
        echo ""
        echo "- **Target** : $ORG_NAME"
        echo "- **Date**   : $(date)"
        echo "- **Source** : TruffleHog + Gitleaks + Custom Regex"
        echo ""
        echo "---"
        echo ""

        # --- TruffleHog findings ---
        if [ -d "$TRF_OUT" ]; then
            for JSON in "$TRF_OUT"/*.json; do
                [ -f "$JSON" ] || continue
                REPO_NAME=$(basename "$JSON" .json)
                while IFS= read -r ENTRY; do
                    LINK=$(echo "$ENTRY" | jq -r '."leak-link" // empty' 2>/dev/null)
                    RAW=$(echo "$ENTRY" | jq -r '.Raw // .RawV2 // empty' 2>/dev/null)
                    COMMIT=$(echo "$ENTRY" | jq -r '.SourceMetadata.Data.Git.commit // empty' 2>/dev/null)
                    FILE=$(echo "$ENTRY" | jq -r '.SourceMetadata.Data.Git.file // .SourceMetadata.Data.Filesystem.file // empty' 2>/dev/null)
                    [ -z "$LINK" ] && continue
                    grep -qF "$LINK" "$SEEN_FILE" && continue
                    echo "$LINK" >> "$SEEN_FILE"
                    echo "## 🔴 TruffleHog — \`$REPO_NAME\`"
                    echo ""
                    echo "| Field      | Value |"
                    echo "|------------|-------|"
                    echo "| leak-link  | $LINK |"
                    echo "| file       | \`$FILE\` |"
                    echo "| commit     | \`$COMMIT\` |"
                    echo "| leak       | \`$RAW\` |"
                    echo ""
                    ((COUNT++))
                done < <(grep -v '^$' "$JSON" 2>/dev/null)
            done
        fi

        # --- Gitleaks findings ---
        if [ -d "$GL_OUT" ]; then
            for JSON in "$GL_OUT"/*.json; do
                [ -f "$JSON" ] || continue
                REPO_NAME=$(basename "$JSON" .json | sed 's/_dir$//')
                while IFS= read -r ENTRY; do
                    LINK=$(echo "$ENTRY" | jq -r '."leak-link" // empty' 2>/dev/null)
                    SECRET=$(echo "$ENTRY" | jq -r '.Secret // empty' 2>/dev/null)
                    COMMIT=$(echo "$ENTRY" | jq -r '.Commit // empty' 2>/dev/null)
                    FILE=$(echo "$ENTRY" | jq -r '.File // empty' 2>/dev/null)
                    [ -z "$LINK" ] && continue
                    grep -qF "$LINK" "$SEEN_FILE" && continue
                    echo "$LINK" >> "$SEEN_FILE"
                    echo "## 🟠 Gitleaks — \`$REPO_NAME\`"
                    echo ""
                    echo "| Field      | Value |"
                    echo "|------------|-------|"
                    echo "| leak-link  | $LINK |"
                    echo "| file       | \`$FILE\` |"
                    echo "| commit     | \`$COMMIT\` |"
                    echo "| leak       | \`$SECRET\` |"
                    echo ""
                    ((COUNT++))
                done < <(jq -c '.[]' "$JSON" 2>/dev/null)
            done
        fi

        # --- Regex findings ---
        if [ -d "$RX_OUT" ]; then
            for TXT in "$RX_OUT"/*.txt; do
                [ -f "$TXT" ] || continue
                REPO_NAME=$(basename "$TXT" .txt)
                # Parse grouped blocks from the txt file
                while IFS= read -r L; do
                    if [[ "$L" =~ ^[[:space:]]*service[[:space:]]*: ]]; then
                        SVC="${L#*: }"
                    elif [[ "$L" =~ ^[[:space:]]*leak-link[[:space:]]*: ]]; then
                        LINK="${L#*: }"
                    elif [[ "$L" =~ ^[[:space:]]*file[[:space:]]*: ]]; then
                        RFILE="${L#*: }"
                    elif [[ "$L" =~ ^[[:space:]]*leak[[:space:]]*: ]]; then
                        LK="${L#*: }"
                        [ -z "$LINK" ] && continue
                        grep -qF "$LINK" "$SEEN_FILE" && { SVC=""; LINK=""; RFILE=""; LK=""; continue; }
                        echo "$LINK" >> "$SEEN_FILE"
                        echo "## 🟡 Regex — \`$REPO_NAME\`"
                        echo ""
                        echo "| Field      | Value |"
                        echo "|------------|-------|"
                        echo "| service    | $SVC |"
                        echo "| leak-link  | $LINK |"
                        echo "| file       | \`$RFILE\` |"
                        echo "| leak       | \`$LK\` |"
                        echo ""
                        SVC=""; LINK=""; RFILE=""; LK=""
                        ((COUNT++))
                    fi
                done < "$TXT"
            done
        fi

        echo "---"
        echo ""
        echo "**Total unique findings: $COUNT**"

    } > "$MASTER_FILE"

    rm -f "$SEEN_FILE"
    echo "📋 MASTER.md → $MASTER_FILE ($COUNT unique findings)"
}

# =============================================================================
# [DOMAINS.md BUILDER — Task 9]
# Extracts all URLs/domains from all result files
# Section 1: Unique domains only
# Section 2: Full paths (may have same domain, different path)
# =============================================================================
build_domains() {
    local DOMAINS_FILE="$BASE_DIR/DOMAINS.md"
    local TMP_ALL_URLS
    TMP_ALL_URLS=$(mktemp)
    local TMP_DOMAINS
    TMP_DOMAINS=$(mktemp)

    echo "🌐 Building DOMAINS.md..."

    # Collect all URLs from all result files
    # From JSON files — pull leak-link
    for JSON in "$TRF_OUT"/*.json "$GL_OUT"/*.json 2>/dev/null; do
        [ -f "$JSON" ] || continue
        grep -oP 'https://[^\s"]+' "$JSON" 2>/dev/null >> "$TMP_ALL_URLS"
    done
    # From Regex .txt files
    for TXT in "$RX_OUT"/*.txt 2>/dev/null; do
        [ -f "$TXT" ] || continue
        grep -oP 'https://[^\s"]+' "$TXT" 2>/dev/null >> "$TMP_ALL_URLS"
    done

    # Extract domain+subdomain (no path)
    grep -oP 'https?://[^/\s]+' "$TMP_ALL_URLS" 2>/dev/null | sort -u > "$TMP_DOMAINS"

    {
        echo "# gitrc.sh — Domains & Subdomains"
        echo ""
        echo "- **Target** : $ORG_NAME"
        echo "- **Date**   : $(date)"
        echo ""
        echo "---"
        echo ""
        echo "## Section 1 — Unique Domains / Subdomains"
        echo ""
        echo "\`\`\`"
        cat "$TMP_DOMAINS"
        echo "\`\`\`"
        echo ""
        echo "---"
        echo ""
        echo "## Section 2 — Full Paths (same domain may appear with different paths)"
        echo ""
        echo "\`\`\`"
        sort -u "$TMP_ALL_URLS"
        echo "\`\`\`"
    } > "$DOMAINS_FILE"

    rm -f "$TMP_ALL_URLS" "$TMP_DOMAINS"
    echo "🌐 DOMAINS.md → $DOMAINS_FILE"
}

# =============================================================================
# [MAIN]
# =============================================================================
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            gitrc.sh — GitHub Secret Scanner              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo " Target : $ORG_NAME"
    if   [ "$SCAN_ONLY"  = true ]; then echo " Mode   : Scan only"
    elif [ "$CLONE_ONLY" = true ]; then echo " Mode   : Clone only"
    else                                echo " Mode   : Clone + Scan"
    fi
    if   [ "$REGEX_ONLY" = true ]; then echo " Tools  : Custom Regex only"
    elif [ "$NO_REGEX"   = true ]; then echo " Tools  : TruffleHog + Gitleaks"
    else                                echo " Tools  : TruffleHog + Gitleaks + Custom Regex"
    fi
    echo "══════════════════════════════════════════════════════════════"

    check_deps

    [ "$SCAN_ONLY"  = false ] && clone_repos
    [ "$CLONE_ONLY" = false ] && scan_repos

    [ "$BUILD_MASTER"      = true ] && build_master
    [ "$EXTRACT_DOMAINS"   = true ] && build_domains

    echo ""
    echo "🏁 All done."
    [ "$REGEX_ONLY" = false ] && echo "   TruffleHog → $TRF_OUT/"
    [ "$REGEX_ONLY" = false ] && echo "   Gitleaks   → $GL_OUT/"
    [ "$NO_REGEX"   = false ] && echo "   Regex      → $RX_OUT/"
    [ "$BUILD_MASTER"    = true ] && echo "   Master     → $BASE_DIR/MASTER.md"
    [ "$EXTRACT_DOMAINS" = true ] && echo "   Domains    → $BASE_DIR/DOMAINS.md"
    echo ""
}

main
