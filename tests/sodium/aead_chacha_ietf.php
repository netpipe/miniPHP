<?php
$k = str_repeat("\x31", 32); $n = str_repeat("\x32", 12); $c = sodium_crypto_aead_chacha20poly1305_ietf_encrypt("m", "", $n, $k); echo bin2hex($c), " ", sodium_crypto_aead_chacha20poly1305_ietf_decrypt($c, "", $n, $k);
