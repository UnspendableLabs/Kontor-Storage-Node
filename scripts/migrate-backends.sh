#!/usr/bin/env bash
#
# Drive `migrate` through a full up / status / down / up cycle against every
# database the README says the node accepts.
#
# `cargo test` cannot reach this. The migration tests run on SQLite, and the DDL
# test in `m20251217_000001_create_agreements_table` asserts the statement a
# backend *would* be sent — neither asks a real Postgres or MySQL server whether
# it accepts it. That gap is exactly how a JSON column default MySQL rejects at
# parse time ("BLOB, TEXT, GEOMETRY or JSON column can't have a default value")
# sat in a schema the README advertises MySQL for, with a green build.
#
# Each URL is taken through the whole cycle rather than just `up`, because the
# interesting failures are on the way back: a `down` that drops tables in the
# wrong order leaves foreign keys dangling, and only the final `up` — rebuilding
# the schema on a database that has already held it once — notices.
#
# Usage:
#   scripts/migrate-backends.sh <database-url> [<database-url> ...]
#
# The binary defaults to the debug build; override with BIN=... for a release
# one. Assumes each URL points at a database this script may take apart.

set -euo pipefail

BIN=${BIN:-./target/debug/kontor-storage-node}

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <database-url> [<database-url> ...]" >&2
    exit 2
fi

if [ ! -x "$BIN" ]; then
    echo "no binary at $BIN — run \`cargo build\` first, or set BIN" >&2
    exit 2
fi

# `migrate` prints the resolved configuration before anything else, so the
# migration list has to be picked out of the surrounding noise. Every migration
# name starts with the `m<date>` prefix `DeriveMigrationName` builds from the
# module name.
statuses() {
    "$BIN" --database-url "$1" migrate status \
        | sed -n -E 's/^(applied|pending) +(m[0-9].*)$/\1/p'
}

expect() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" != "$expected" ]; then
        echo "  FAIL  $label" >&2
        echo "        expected: $expected" >&2
        echo "        actual:   $actual" >&2
        exit 1
    fi
    echo "  ok    $label"
}

# The count of lines in `statuses` output equal to $2.
count_of() {
    statuses "$1" | { grep -c -x "$2" || true; }
}

check_backend() {
    local url=$1
    # The scheme is all that is worth echoing; the rest carries a password.
    echo "==> ${url%%:*}"

    # Normalise: a re-run against a database that still holds the schema has to
    # start from the same place CI's fresh service does.
    "$BIN" --database-url "$url" migrate down -n 999 >/dev/null

    local total
    total=$(statuses "$url" | wc -l | tr -d ' ')
    if [ "$total" -eq 0 ]; then
        echo "  FAIL  no migrations listed — the status output did not parse" >&2
        exit 1
    fi
    expect "a rolled-back database lists all $total as pending" \
        "$total" "$(count_of "$url" pending)"

    expect "up applies every pending migration" \
        "Applied $total migration(s)." \
        "$("$BIN" --database-url "$url" migrate up | tail -n 1)"
    expect "status now reports all $total as applied" \
        "$total" "$(count_of "$url" applied)"

    expect "a second up has nothing to do" \
        "Applied 0 migration(s)." \
        "$("$BIN" --database-url "$url" migrate up | tail -n 1)"

    expect "down reports what it rolled back, not what was asked for" \
        "Rolled back $total migration(s)." \
        "$("$BIN" --database-url "$url" migrate down -n 999 | tail -n 1)"
    expect "status is back to all $total pending" \
        "$total" "$(count_of "$url" pending)"

    # The one that catches a `down` which only looked like it worked.
    expect "the schema rebuilds on a database that has held it before" \
        "Applied $total migration(s)." \
        "$("$BIN" --database-url "$url" migrate up | tail -n 1)"
}

for url in "$@"; do
    check_backend "$url"
done

echo "all backends migrated cleanly"
