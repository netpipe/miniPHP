#!/bin/sh
# Language-feature regression suite.
#
# Each tests/features/NAME.php has a NAME.out holding the exact output real
# PHP 8.3 printed for it, so a pass means "behaves like PHP", not "behaves the
# way I expected". Regenerate an .out only from real PHP, warnings to stderr (miniPHP does not
# print PHP notices):  php -n -d display_errors=stderr NAME.php > NAME.out
#
#   sh tests/features.sh          (needs gcc)
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
# SQLite is compiled once by make and reused (it is ~270,000 lines)
make -s -C "$ROOT" sqlite/sqlite3.o || { echo "could not build sqlite/sqlite3.o"; exit 1; }
gcc -std=c11 -O1 -g -fsanitize=address,undefined -o "$W/php" "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" -lm || { echo "BUILD FAILED"; exit 1; }
export ASAN_OPTIONS=detect_leaks=0
pass=0; fail=0
for t in "$ROOT"/tests/features/*.php; do
    name=$(basename "$t" .php)
    if [ -f "${t%.php}.qs" ]; then
        # NAME.qs: run as a web request with that query string; the .out was
        # made by real PHP from parse_str(), the code that fills $_GET
        env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 QUERY_STRING="$(cat "${t%.php}.qs")" \
            timeout 10 "$W/php" "$t" 2> "$W/err" | tr -d '\r' | sed '1,/^$/d' > "$W/got"
    else
        timeout 10 "$W/php" "$t" > "$W/got" 2> "$W/err"
    fi
    if cmp -s "$W/got" "${t%.php}.out" && ! grep -qE 'runtime error|AddressSanitizer' "$W/err"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf '  FAIL  %s\n        want: %s\n        got:  %s %s\n' "$name" \
            "$(head -c 120 "${t%.php}.out" | tr '\n' '~')" "$(head -c 120 "$W/got" | tr '\n' '~')" "$(head -c 120 "$W/err")"
    fi
done
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
