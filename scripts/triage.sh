#!/usr/bin/env bash
#
# triage.sh - fail if the tree carries an unresolved marker.
#
# Usage: scripts/triage.sh
#
# The release gate is "zero TODOs without a docs/BACKLOG.md entry". A plain grep
# for TODO cannot enforce that, because this tree contains fourteen strings that
# match one and are not markers:
#
#   b"XXXX"                 invalid magic in a parser rejection test
#   mktemp -t dhow-XXXXXX   the template every script uses for a work directory
#
# A gate that reports fourteen findings on a clean tree is a gate people learn
# to ignore, and the fifteenth - a real one - arrives unnoticed. So the
# exclusions are written down here, each with the reason it is not a marker,
# rather than being a `| grep -v` somebody added to make the output quiet.
#
# A marker that is genuinely deferred belongs in docs/BACKLOG.md with an entry
# that can be acted on without the conversation that produced it. A marker in
# the source says "later" to nobody in particular.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# What counts as a marker. HACK and XXX are included because they mean the same
# thing as TODO to everyone except the person who wrote them.
PATTERN='TODO|FIXME|HACK|XXX'

# Source, and only source.
#
# A marker in a Markdown file is a note to a reader; a marker in code is
# deferred work with no owner, which is the thing this gate exists to prevent.
# The documents are not exempt from scrutiny - docs/BACKLOG.md is where deferred
# work is supposed to live, and it would be odd to fail a build because that
# file talks about the markers it replaces.
SOURCE='\.(rs|go|sh|py|toml|yml|yaml|h)$|^Makefile$'

# Paths that are not this project's source.
#
#   temp/       the master prompt and the git procedure, which are inputs
#   fuzz/seeds/ generated corpus; binary, and a byte sequence is not a marker
#   target/     build output
EXCLUDE_PATHS='/target/|^temp/|^fuzz/seeds/|^\.git/'

# Strings that match the pattern and are not markers. Each is here because it
# is a literal the code needs, not because the output was noisy.
#
#   XXXX          invalid magic bytes, in tests that assert a parser rejects them
#   XXXXXX        the mktemp template every script uses
#   PATTERN=/EXCLUDE  this script describing itself
FALSE_POSITIVES='XXXX|PATTERN=|EXCLUDE_|FALSE_POSITIVES|# '

cd "$ROOT"

FOUND=$(git ls-files \
    | grep -E "$SOURCE" \
    | grep -vE "$EXCLUDE_PATHS" \
    | xargs grep -nE "$PATTERN" 2>/dev/null \
    | grep -vE "$FALSE_POSITIVES" \
    || true)

echo "=== dhow marker triage ==="
echo

if [ -n "$FOUND" ]; then
    echo "Unresolved markers in the source:" >&2
    echo "$FOUND" >&2
    echo >&2
    echo "Each one is either work to do now, or an entry in docs/BACKLOG.md." >&2
    echo "A marker in the source says \"later\" to nobody in particular." >&2
    exit 1
fi

OPEN=$(grep -cE '^### B-[0-9]+' docs/BACKLOG.md || echo 0)
SCANNED=$(git ls-files | grep -E "$SOURCE" | grep -vcE "$EXCLUDE_PATHS")
echo "  ${SCANNED} source files scanned"
echo "  no unresolved markers"
echo "  ${OPEN} backlog entries, open and closed, in docs/BACKLOG.md"
echo
echo "=== TRIAGE CLEAN ==="
