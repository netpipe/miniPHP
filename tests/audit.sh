#!/bin/sh
# Re-runs every finding from AUDIT.md against the current main.c.
#
# Each check is the reproduction from the audit with its expected outcome AFTER
# the fix, so a change that reintroduces one of them fails here by name.
# Builds with AddressSanitizer + UBSan, so a memory error or undefined behaviour
# anywhere on these paths fails the check that triggered it, not just a crash.
#
#   sh tests/audit.sh          (needs gcc; about 20 seconds)
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
BIN="$W/php"
export ASAN_OPTIONS=detect_leaks=0

gcc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -o "$BIN" "$ROOT/main.c" -lm || { echo "BUILD FAILED"; exit 1; }

pass=0; fail=0
ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }
sane() { ! printf '%s' "$1" | grep -qE 'runtime error|AddressSanitizer'; }

# run <php-source> -> stdout+stderr of the CLI interpreter
run() { printf '%s' "$1" > "$W/t.php"; timeout 30 "$BIN" "$W/t.php" 2>&1; }
# cgi <php-source> [extra env...] -> the full CGI response
cgi() { src=$1; shift; printf '%s' "$src" > "$W/t.php"
        env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 PHPMINI_SESSION_PATH="$W/sess" "$@" \
            timeout 30 "$BIN" "$W/t.php" 2>&1 | tr -d '\r'; }
expect() {  # expect <name> <output> <grep -E pattern>
    if sane "$2" && printf '%s' "$2" | grep -qE -- "$3"; then ok "$1"
    else bad "$1" "$(printf '%s' "$2" | head -c 160 | tr '\n' ' ')"; fi
}

echo "-- it builds and runs at all --"
expect "smoke: a script runs (buf_reserve NULL write)" "$(run '<?php echo 1 + 2;')" '^3$'
expect "functions and recursion"  "$(run '<?php function f($n){ if ($n<=1) return 1; return $n*f($n-1);} echo f(10);')" '3628800'

echo "-- arithmetic --"
expect "PHP_INT_MAX + 1 becomes a float, no overflow"  "$(run '<?php echo 9223372036854775807 + 1;')" '^9\.2233720368548E\+18$'
expect "PHP_INT_MAX * 3 becomes a float"               "$(run '<?php echo 9223372036854775807 * 3;')" '^2\.7670116110564E\+19$'
expect "PHP_INT_MIN % -1 is 0, not a SIGFPE"           "$(run '<?php echo (0 - 9223372036854775807 - 1) % (0 - 1);')" '^0$'
expect "1 / 0 is an error, not a silent 0"             "$(run '<?php echo 1 / 0;')" 'Division by zero'
expect "5 % 0 is an error, not a silent 0"             "$(run '<?php echo 5 % 0;')" 'Modulo by zero'
expect "intval(1e300) has no undefined cast"           "$(run '<?php echo intval(1e300), 1e300 % 7;')" '^00$'
expect "ordinary arithmetic is unchanged"              "$(run '<?php echo 7 % 3, " ", -7 % 3, " ", 10 / 4;')" '^1 -1 2.5$'

echo "-- recursion and nesting --"
expect "infinite recursion is an error, not a segfault" "$(run '<?php function r($n){ return r($n+1); } r(0);')" 'Maximum call stack size'
deep=$(python3 -c "print('<?php echo ' + '('*200000 + '1' + ')'*200000 + ';')" 2>/dev/null)
[ -n "$deep" ] && expect "200,000 nested brackets is an error, not a segfault" "$(run "$deep")" 'Maximum call stack size'
expect "5,000-deep recursion still works"              "$(run '<?php function d($n){ if ($n <= 0) return 0; return 1 + d($n - 1); } echo d(5000);')" '^5000$'

echo "-- response headers --"
out=$(cgi '<?php header("X-A: 1\r\nX-Injected: yes"); echo "b";')
if printf '%s' "$out" | grep -q '^X-Injected'; then bad "header() refuses CR/LF" "$out"; else ok "header() refuses CR/LF"; fi
out=$(cgi '<?php setcookie("c", "v", array("path" => "/\r\nX-Injected: yes")); echo "b";')
if printf '%s' "$out" | grep -q '^X-Injected'; then bad "setcookie() options refuse CR/LF" "$out"; else ok "setcookie() options refuse CR/LF"; fi

echo "-- input limits --"
body=$(python3 -c "import sys;sys.stdout.write('&'.join('k%d='%i for i in range(50000)))" 2>/dev/null)
if [ -n "$body" ]; then
    printf '%s' "$body" > "$W/body"
    printf '<?php echo count($_POST);' > "$W/t.php"
    out=$(env REQUEST_METHOD=POST GATEWAY_INTERFACE=CGI/1.1 CONTENT_LENGTH=$(wc -c < "$W/body") \
          CONTENT_TYPE=application/x-www-form-urlencoded timeout 10 "$BIN" "$W/t.php" < "$W/body" 2>&1 | tr -d '\r')
    expect "50,000-variable POST is capped at 1000, fast" "$out" '^1000$'
fi
printf '<?php $i = 0; while (1) { $i = $i + 1; }' > "$W/t.php"
# memory limit off for this one: the loop also allocates, and this check is
# about the TIME limit specifically
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 PHPMINI_MAX_EXECUTION_TIME=2 PHPMINI_MEMORY_LIMIT=0 timeout 20 "$BIN" "$W/t.php" 2>&1)
expect "endless loop under CGI stops at max_execution_time" "$out" 'Maximum execution time'

# Memory: built WITHOUT sanitizers on purpose. ASan's own internal mappings
# count against the same kernel limit and it stops with its own message first;
# the shipped binary is a plain build, and that is what has to say it.
gcc -std=c11 -O2 -o "$W/plain" "$ROOT/main.c" -lm
printf '<?php $i = 0; while (1) { $s = "x" . $i; $i = $i + 1; }' > "$W/t.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 PHPMINI_MEMORY_LIMIT=32M timeout 20 "$W/plain" "$W/t.php" 2>&1)
expect "a memory-hungry loop under CGI stops at memory_limit" "$out" 'Allowed memory size of 33554432 bytes exhausted'
printf '<?php $a = []; for ($i = 0; $i < 20000; $i++) { $a[] = "item" . $i; } echo count($a);' > "$W/t.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 timeout 60 "$W/plain" "$W/t.php" 2>&1 | tr -d '\r')
expect "a normal 20,000-item array fits the default limit" "$out" '20000$'
printf '<?php $s = 0; for ($i = 0; $i < 400000; $i++) { $s = $s + $i; } echo $s;' > "$W/t.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 timeout 60 "$W/plain" "$W/t.php" 2>&1 | tr -d '\r')
expect "a 400,000-iteration loop fits the default limit" "$out" '79999800000$'

echo "-- sessions --"
mkdir -p "$W/sess"; chmod 700 "$W/sess"
id=$(cgi '<?php session_start(); $_SESSION["n"] = "kept"; $_SESSION["a"] = [1, "two"]; echo "set";' \
     | sed -n 's/^Set-Cookie: PHPSESSID=\([a-f0-9]*\).*/\1/p')
expect "a session survives to the next request" \
       "$(cgi '<?php session_start(); echo $_SESSION["n"], "/", $_SESSION["a"][1];' HTTP_COOKIE="PHPSESSID=$id")" 'kept/two$'
# Superglobals are one array in every scope: a session written from inside a
# function (where login code lives) must survive to the next request.
id2=$(cgi '<?php session_start(); function login() { $_SESSION["user"] = "alice"; } login(); echo "x";' \
      | sed -n 's/^Set-Cookie: PHPSESSID=\([a-f0-9]*\).*/\1/p')
expect "a session written inside a function survives" \
       "$(cgi '<?php session_start(); echo $_SESSION["user"] ?? "missing";' HTTP_COOKIE="PHPSESSID=$id2")" 'alice$'
mode=$(stat -c '%a' "$W/sess/sess_$id" 2>/dev/null)
[ "$mode" = 600 ] && ok "session files are private (0600)" || bad "session files are private (0600)" "mode $mode"
# Positive check: a FRESH server-issued id must come back. Testing only that
# the attacker's id is not echoed passes on the unfixed code too, because that
# code adopted the id silently without sending any cookie at all.
out=$(cgi '<?php session_start(); echo "x";' HTTP_COOKIE="PHPSESSID=NeverIssuedByThisServer1")
expect "an unknown session id is replaced with a fresh one" "$out" '^Set-Cookie: PHPSESSID=[0-9a-f]{32};'

echo "keep me" > "$W/victim"; ln -s "$W/victim" "$W/sess/sess_PlantedSymlinkSession01"
cgi '<?php session_start(); $_SESSION["x"] = "pwned";' HTTP_COOKIE="PHPSESSID=PlantedSymlinkSession01" >/dev/null
[ "$(cat "$W/victim")" = "keep me" ] && ok "a planted symlink is not written through" \
                                     || bad "a planted symlink is not written through" "$(cat "$W/victim")"
expect "HTTPS requests get a Secure session cookie" "$(cgi '<?php session_start();' HTTPS=on)" 'Secure'
chmod 755 "$W/sess"
expect "a session directory others can read is refused" "$(cgi '<?php session_start();')" 'sessions disabled'
chmod 700 "$W/sess"
# A guard for the bounded array loop. (It also passes on the unfixed code, but
# only because that code failed to parse ANY array -- the bug it guards was
# hidden behind the one that broke sessions.)
printf 'a:999999999999:{' > "$W/sess/sess_CorruptSessionFile00001"
expect "a corrupt session file does not hang or crash" \
       "$(cgi '<?php session_start(); echo "alive";' HTTP_COOKIE="PHPSESSID=CorruptSessionFile00001")" 'alive$'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
