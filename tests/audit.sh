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
# SQLite is compiled once by make and reused (it is ~270,000 lines)
trap 'rm -rf "$W"' EXIT
make -s -C "$ROOT" sqlite/sqlite3.o || { echo "could not build sqlite/sqlite3.o"; exit 1; }
BIN="$W/php"
export ASAN_OPTIONS=detect_leaks=0

gcc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -o "$BIN" "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" -lm || { echo "BUILD FAILED"; exit 1; }

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
gcc -std=c11 -O2 -o "$W/plain" "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" -lm
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

echo "-- uploads (milestone 4) --"
# post <php-source> <body-file> [extra env...] -> CGI response to a multipart POST
B=XyZB0undary
post() { src=$1; bf=$2; shift 2; printf '%s' "$src" > "$W/t.php"
         env REQUEST_METHOD=POST GATEWAY_INTERFACE=CGI/1.1 PHPMINI_SESSION_PATH="$W/sess" \
             CONTENT_TYPE="multipart/form-data; boundary=$B" CONTENT_LENGTH=$(wc -c < "$bf") \
             PHPMINI_UPLOAD_TMP_DIR="$W/tmp" "$@" timeout 30 "$BIN" "$W/t.php" < "$bf" 2>&1 | tr -d '\r'; }
mkdir -p "$W/tmp" "$W/dest"
printf -- '--%s\r\nContent-Disposition: form-data; name="f"; filename="../../evil.php"\r\nContent-Type: text/plain\r\n\r\nUPLOADED-BYTES\r\n--%s--\r\n' $B $B > "$W/up1"

out=$(post '<?php echo $_FILES["f"]["name"], "|", $_FILES["f"]["size"], "|", $_FILES["f"]["error"];' "$W/up1")
expect "an upload arrives in \$_FILES, its name cut to a plain filename" "$out" 'evil\.php\|14\|0$'

out=$(post '<?php echo move_uploaded_file($_FILES["f"]["tmp_name"], "'"$W"'/dest/" . $_FILES["f"]["name"]) ? "moved" : "refused";' "$W/up1")
[ "$(cat "$W/dest/evil.php" 2>/dev/null)" = "UPLOADED-BYTES" ] && ok "move_uploaded_file() moves it, bytes intact, and inside dest/" \
    || bad "move_uploaded_file() moves it, bytes intact, and inside dest/" "$out"
[ ! -e "$W/evil.php" ] && ok "the ../../ in the sent name did not escape dest/" || bad "the ../../ in the sent name did not escape dest/" "found $W/evil.php"

out=$(post '<?php echo move_uploaded_file("/etc/passwd", "'"$W"'/dest/stolen") ? "MOVED" : "refused";' "$W/up1")
if printf '%s' "$out" | tail -1 | grep -qx refused && [ ! -e "$W/dest/stolen" ]; then ok "move_uploaded_file() refuses a path that was not uploaded (/etc/passwd)"
else bad "move_uploaded_file() refuses a path that was not uploaded (/etc/passwd)" "$out"; fi

out=$(post '<?php $t = $_FILES["f"]["tmp_name"]; $a = move_uploaded_file($t, "'"$W"'/dest/one"); $b = move_uploaded_file($t, "'"$W"'/dest/two"); echo $a ? "1" : "0", $b ? "1" : "0", is_uploaded_file($t) ? "1" : "0";' "$W/up1")
expect "a second move of the same upload is refused" "$out" '^100$'

out=$(post '<?php echo is_uploaded_file($_FILES["f"]["tmp_name"]) ? "y" : "n", is_uploaded_file("/etc/passwd") ? "y" : "n";' "$W/up1")
expect "is_uploaded_file() knows its own uploads only" "$out" '^yn$'

rm -rf "$W/tmp"/*
post '<?php $t = $_FILES["f"]["tmp_name"]; echo "listing"; undefined_function_to_die();' "$W/up1" >/dev/null
left=$(ls "$W/tmp" | wc -l)
[ "$left" -eq 0 ] && ok "temp files are deleted even when the script dies with a fatal error" \
                  || bad "temp files are deleted even when the script dies with a fatal error" "$left left in tmp/"

# The temp file only exists while the request runs, so its creation is checked
# at the system call: it must be O_EXCL (never reuses or follows an existing
# path) and 0600 (private), even with a permissive umask.
printf '<?php echo $_FILES["f"]["tmp_name"];' > "$W/t.php"
mode=$(sh -c 'umask 000; env REQUEST_METHOD=POST GATEWAY_INTERFACE=CGI/1.1 CONTENT_TYPE="multipart/form-data; boundary='$B'" CONTENT_LENGTH=$(wc -c < "'"$W/up1"'") PHPMINI_UPLOAD_TMP_DIR="'"$W/tmp"'" strace -f -e trace=openat -o "'"$W/strace"'" "'"$BIN"'" "'"$W/t.php"'" < "'"$W/up1"'" >/dev/null 2>&1; grep -o "php[A-Za-z0-9]\{6\}\", O_RDWR|O_CREAT|O_EXCL, 0600" "'"$W/strace"'" | head -1' 2>/dev/null)
if [ -n "$mode" ]; then ok "temp files are created 0600 with O_EXCL (mkstemp)"
elif ! command -v strace >/dev/null; then ok "temp-file mode check skipped (no strace)"
else bad "temp files are created 0600 with O_EXCL (mkstemp)" "no matching openat in strace"; fi

big=$W/big; : > "$big"
out=$(printf '<?php echo count($_POST), count($_FILES);' > "$W/t.php"; env REQUEST_METHOD=POST GATEWAY_INTERFACE=CGI/1.1 \
      CONTENT_TYPE="multipart/form-data; boundary=$B" CONTENT_LENGTH=104857600 timeout 10 "$BIN" "$W/t.php" < "$big" 2>&1 | tr -d '\r')
expect "a body over post_max_size is not read (100 MB claimed, 8 MB limit)" "$out" 'exceeds the limit'

echo "-- SQLite (milestone 5) --"
q() { printf '<?php %s' "$1" > "$W/t.php"; (cd "$W" && timeout 30 "$BIN" t.php 2>&1); }

expect "\$name parameters bind (SQLite supports them; PHP's SQLite3 class does not)" \
  "$(q '$d = sqlite_open(":memory:"); $r = sqlite_query($d, "SELECT $v + 1 AS x", ["v" => 41]); echo $r[0]["x"];')" '^42$'

out=$(q '$d = sqlite_open(":memory:"); sqlite_exec($d, "CREATE TABLE t (x)"); var_dump(sqlite_query($d, "SELECT 1; DROP TABLE t")); echo "tables=", count(sqlite_query($d, "SELECT name FROM sqlite_master WHERE name = ?", ["t"]));' | tr '\n' ' ')
expect "a second statement smuggled into sqlite_query() is refused, table survives" "$out" 'only one statement.*bool\(false\).*tables=1'

expect "sqlite_exec() without parameters runs a whole multi-statement script" \
  "$(q '$d = sqlite_open(":memory:"); sqlite_exec($d, "CREATE TABLE a (x); CREATE TABLE b (y); INSERT INTO a VALUES (1); INSERT INTO b VALUES (2);"); echo count(sqlite_query($d, "SELECT * FROM a")), count(sqlite_query($d, "SELECT * FROM b"));')" '^11$'

expect "load_extension() does not exist (no native code from SQL)" \
  "$(q '$d = sqlite_open(":memory:"); var_dump(sqlite_query($d, "SELECT load_extension(?)", ["/tmp/x.so"])); echo sqlite_error($d);')" 'no such function: load_extension'

expect "defensive mode: SQL cannot rewrite the schema table" \
  "$(q '$d = sqlite_open(":memory:"); sqlite_exec($d, "CREATE TABLE t (x)"); sqlite_exec($d, "PRAGMA writable_schema = ON"); var_dump(sqlite_exec($d, "UPDATE sqlite_master SET sql = ? WHERE name = ?", ["junk", "t"]));')" 'bool\(false\)'

out=$(q '$d = sqlite_open("p.db"); sqlite_exec($d, "CREATE TABLE IF NOT EXISTS k (v)"); sqlite_exec($d, "INSERT INTO k VALUES (?)", ["first request"]);' ; \
      q '$d = sqlite_open("p.db"); $r = sqlite_query($d, "SELECT v FROM k"); echo $r[0]["v"];')
expect "a file database persists to the next request" "$out" 'first request$'

# another process holds the write lock for 2 s; the busy timeout (5 s) waits it out
if command -v python3 >/dev/null; then
    (cd "$W" && python3 -c '
import sqlite3, time
c = sqlite3.connect("lock.db", isolation_level=None)
c.execute("CREATE TABLE IF NOT EXISTS t (x)"); c.execute("BEGIN IMMEDIATE"); c.execute("INSERT INTO t VALUES (1)")
time.sleep(2); c.execute("COMMIT")' &)
    sleep 0.5
    out=$(q '$d = sqlite_open("lock.db"); var_dump(sqlite_exec($d, "INSERT INTO t VALUES (?)", [2]));')
    wait
    expect "a write waits for another process's lock instead of failing" "$out" 'int\(1\)'
fi

printf '<?php $d = sqlite_open(":memory:"); $r = sqlite_query($d, "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c LIMIT 20000000) SELECT i, ? AS pad FROM c", [str_repeat("x", 50)]); echo count($r);' > "$W/t.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 PHPMINI_MEMORY_LIMIT=64M timeout 60 "$W/plain" "$W/t.php" 2>&1)
expect "a 20-million-row result hits memory_limit cleanly, no crash" "$out" 'Allowed memory size'

echo "-- binary-safe strings (milestone 6) --"
# A zero byte is now ordinary string data, so every place a string becomes a
# C path or header must refuse it -- or "secret.php\0.jpg" opens secret.php.
printf '<?php echo "SECRET-SOURCE";' > "$W/secret.php"
out=$(q 'include "secret.php" . chr(0) . ".jpg"; echo "|done";' | tr '\n' ' ')
case "$out" in *SECRET-SOURCE*) bad "include refuses a path with a zero byte (does not open the part before it)" "$out";;
    *) expect "include refuses a path with a zero byte (does not open the part before it)" "$out" "Failed opening 'secret.php'.*\|done";; esac
expect "require of such a path stops the script, as in PHP" "$(q 'require "secret.php" . chr(0) . "x"; echo "ran-on";')" "Failed opening required"
out=$(cgi '<?php header("X-Test: a" . chr(0) . "Injected: yes"); echo "body";')
case "$out" in *Injected*) bad "header() with a zero byte is dropped with PHP's warning" "$(printf '%s' "$out" | tr '\n' ' ')";;
    *) expect "header() with a zero byte is dropped with PHP's warning" "$out" "Header may not contain NUL bytes";; esac
expect "is_uploaded_file() with a zero byte is PHP's ValueError" \
       "$(q 'is_uploaded_file("/etc/passwd" . chr(0)); echo "ran-on";')" 'ValueError: is_uploaded_file\(\).*null bytes'
expect "move_uploaded_file() to a path with a zero byte is PHP's ValueError" \
       "$(q 'move_uploaded_file("/tmp/x", "/tmp/a" . chr(0) . ".php"); echo "ran-on";')" 'ValueError: move_uploaded_file\(\): Argument #2'
expect "sqlite_open() of a path with a zero byte is refused" \
       "$(q 'sqlite_open("db.sqlite" . chr(0) . ".txt"); echo "ran-on";')" 'null bytes'
[ -e "$W/db.sqlite" ] && bad "the truncated database name was not created" "$W/db.sqlite exists" || ok "the truncated database name was not created"

out=$(cgi '<?php echo bin2hex($_GET["v"]), "|", strlen($_GET["v"]);' QUERY_STRING='v=a%00b%00')
expect "a %00 in the query string arrives as a real zero byte (was cut to \"a\")" "$out" '^61006200\|4$'
id=$(cgi '<?php session_start(); $_SESSION["k"] = "a" . chr(0) . "b"; $_SESSION["z" . chr(0)] = chr(255) . chr(0); echo "set";' \
     | sed -n 's/^Set-Cookie: PHPSESSID=\([a-f0-9]*\).*/\1/p')
expect "a session value and key with zero bytes survive to the next request" \
       "$(cgi '<?php session_start(); foreach ($_SESSION as $k => $v) echo bin2hex($k), "=", bin2hex($v), ";";' HTTP_COOKIE="PHPSESSID=$id")" '6b=610062;7a00=ff00;$'
# Expected values are what PHP's PDO sqlite driver returns for the same calls.
# (PHP's SQLite3 class cuts TEXT at the first zero byte when fetching; the
# stored bytes are the same either way.)
expect "SQLite stores and returns TEXT with zero bytes intact" \
       "$(q '$d = sqlite_open(":memory:"); sqlite_exec($d, "CREATE TABLE t (x TEXT)"); sqlite_query($d, "INSERT INTO t VALUES (?), (?)", ["a", "a" . chr(0) . "b"]); $r = sqlite_query($d, "SELECT x, hex(x) AS h FROM t WHERE x = ?", ["a" . chr(0) . "b"]); echo count($r), " ", bin2hex($r[0]["x"]), " ", $r[0]["h"];')" '^1 610062 610062$'

out=$( (cd "$W" && cp "$ROOT/main.c" . && gcc -std=c11 -DMINIPHP_NO_SQLITE -o nosq main.c -lm 2>&1 && printf '<?php echo strlen("ok"); sqlite_open(":memory:");' > n.php && ./nosq n.php 2>&1) )
out=$(printf '%s' "$out" | tr '\n' ' ')
case "$out" in *"Undefined function sqlite_open"*) case "$out" in *2*) ok "built without SQLite (make nosqlite): still works, sqlite_* undefined";; *) bad "built without SQLite" "$out";; esac;; *) bad "built without SQLite (make nosqlite): still works, sqlite_* undefined" "$out";; esac

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
