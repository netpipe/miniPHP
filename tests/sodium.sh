#!/bin/sh
# libsodium suite (make SODIUM=1).
#
# tests/sodium/NAME.php has a NAME.out holding the exact output real PHP 8.3
# printed for it, with its own ext/sodium. Keys, nonces and seeds are fixed,
# so every byte of every ciphertext, signature and hash must match. Random
# ones (keygen, keypair, seal) are checked by round trip and length.
# Regenerate an .out only from real PHP:  php -n NAME.php > NAME.out
#
# tests/sodium/errors.txt is one bad call per line; errors.out is the
# "Uncaught <Class>: <message>" PHP stopped with, line for line.
#
#   sh tests/sodium.sh          (needs gcc; builds libsodium once, ~15 s)
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
make -s -C "$ROOT" sqlite/sqlite3.o || { echo "could not build sqlite/sqlite3.o"; exit 1; }
make -s -C "$ROOT" SODIUM=1 libsodium/libsodium.a || { echo "could not build libsodium"; exit 1; }
gcc -std=c11 -O1 -g -fsanitize=address,undefined -DMINIPHP_SODIUM -I"$ROOT/libsodium/include" -o "$W/php" \
    "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" "$ROOT/libsodium/libsodium.a" -lm || { echo "BUILD FAILED"; exit 1; }
export ASAN_OPTIONS=detect_leaks=0
pass=0; fail=0
ok()  { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }

for t in "$ROOT"/tests/sodium/*.php; do
    name=$(basename "$t" .php)
    timeout 60 "$W/php" "$t" > "$W/got" 2> "$W/err"
    if cmp -s "$W/got" "${t%.php}.out" && ! grep -qE 'runtime error|AddressSanitizer' "$W/err"; then ok
    else bad "$name" "want: $(head -c 100 "${t%.php}.out" | tr '\n' '~')  got: $(head -c 100 "$W/got" | tr '\n' '~') $(head -c 120 "$W/err")"; fi
done

n=0
while IFS= read -r code; do
    n=$((n + 1))
    want=$(sed -n "${n}p" "$ROOT/tests/sodium/errors.out")
    printf '<?php %s echo "RAN-ON";' "$code" > "$W/e.php"
    got=$(timeout 60 "$W/php" "$W/e.php" 2>&1 | grep -o 'Uncaught .*' | head -1)
    if [ "$got" = "$want" ]; then ok; else bad "error: $code" "want: $want  got: $got"; fi
done < "$ROOT/tests/sodium/errors.txt"

# Argon2's working memory is not counted against memory_limit (PHP does not
# count it either) -- but the limit must still hold for everything else.
gcc -std=c11 -O2 -DMINIPHP_SODIUM -I"$ROOT/libsodium/include" -o "$W/plain" \
    "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" "$ROOT/libsodium/libsodium.a" -lm
printf '<?php $h = sodium_crypto_pwhash_str("pw", SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE); echo sodium_crypto_pwhash_str_verify($h, "pw") ? "verified" : "FAILED";' > "$W/m.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 timeout 120 "$W/plain" "$W/m.php" 2>&1 | tr -d '\r')
case "$out" in *verified) ok;; *) bad "a 256 MB Argon2 hash works under the 256 MB memory_limit" "$(printf '%s' "$out" | tail -1)";; esac
printf '<?php sodium_crypto_pwhash_str("pw", 2, 67108864); $a = str_repeat("x", 209715200); $b = str_repeat("y", 209715200); echo "NOT LIMITED";' > "$W/m.php"
out=$(env REQUEST_METHOD=GET GATEWAY_INTERFACE=CGI/1.1 timeout 120 "$W/plain" "$W/m.php" 2>&1 | tr -d '\r')
case "$out" in *"Allowed memory size"*) ok;; *) bad "memory_limit still holds after an Argon2 call" "$(printf '%s' "$out" | tail -1)";; esac

# without SODIUM=1 the functions do not exist, as in a PHP built without ext/sodium
gcc -std=c11 -O1 -o "$W/nosodium" "$ROOT/main.c" "$ROOT/sqlite/sqlite3.o" -lm
printf '<?php echo strlen(random_bytes(4)); sodium_crypto_secretbox_keygen();' > "$W/n.php"
out=$("$W/nosodium" "$W/n.php" 2>&1 | tr '\n' ' ')
case "$out" in *"Undefined function sodium_crypto_secretbox_keygen"*4*|4*"Undefined function sodium_crypto_secretbox_keygen"*) ok;; *) bad "a build without SODIUM=1 has no sodium_* (random_bytes still works)" "$out";; esac

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
