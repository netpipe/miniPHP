<?php
echo bin2hex(sodium_crypto_pwhash(32, "password", str_repeat("s", 16), SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE)), " ", bin2hex(sodium_crypto_pwhash(16, "pw\0x", str_repeat("t", 16), 3, 8192, SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13)), " ", bin2hex(sodium_crypto_pwhash(16, "pw", str_repeat("t", 16), 1, 8192, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13));
