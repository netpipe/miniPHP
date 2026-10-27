<?php
$h = sodium_crypto_pwhash_str("correct horse", 2, 8192 * 4); echo substr($h, 0, 28), " ", strlen($h), " "; var_dump(sodium_crypto_pwhash_str_verify($h, "correct horse"), sodium_crypto_pwhash_str_verify($h, "wrong"), sodium_crypto_pwhash_str_needs_rehash($h, 2, 8192 * 4), sodium_crypto_pwhash_str_needs_rehash($h, 3, 8192 * 4), sodium_crypto_pwhash_str_verify("garbage", "x"));
