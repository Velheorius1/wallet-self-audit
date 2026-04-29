#!/usr/bin/env bash
# check-hex-leaks.sh — block 64-char hex in newly staged content.
#
# This is a pre-commit hook (and CI step). Lines containing FIXTURE_OK
# are exempt; legitimate Bitcoin txids (also 64-hex) are caught only if
# they appear without a clear context comment. False-positive cost is
# low — annotate the legit case with FIXTURE_OK and rerun.
#
# Why grep on `git diff --cached -U0 ^+`? We block NEW leaks only;
# historical fixtures already in the tree are allowed (they were vetted
# at the time they were added).

set -euo pipefail

# Lines added in the staging area.
ADDED=$(git diff --cached -U0 -- '*.py' '*.md' '*.json' '*.yaml' '*.yml' '*.toml' \
        | grep -E '^\+' \
        | grep -v '^\+\+\+' \
        | grep -v 'FIXTURE_OK' || true)

if [[ -z "$ADDED" ]]; then
    exit 0
fi

# 64-char lowercase or mixed-case hex strings.
if echo "$ADDED" | grep -Eq '\b[0-9a-fA-F]{64}\b'; then
    echo "ERROR: 64-char hex string found in staged content (possible private key)." >&2
    echo "If this is a legitimate test fixture, add a 'FIXTURE_OK' marker on the same line." >&2
    echo "" >&2
    echo "Offending lines:" >&2
    echo "$ADDED" | grep -E '\b[0-9a-fA-F]{64}\b' | head -10 >&2
    exit 1
fi

# Long hex strings (>=128 chars — definitely suspicious).
if echo "$ADDED" | grep -Eq '\b[0-9a-fA-F]{128,}\b'; then
    echo "ERROR: 128+ char hex string found in staged content." >&2
    exit 1
fi

exit 0
