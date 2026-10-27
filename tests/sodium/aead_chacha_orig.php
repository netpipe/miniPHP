<?php
$k = str_repeat("\x41", 32); $n = str_repeat("\x42", 8); $c = sodium_crypto_aead_chacha20poly1305_encrypt("message", "x", $n, $k); echo bin2hex($c), " ", sodium_crypto_aead_chacha20poly1305_decrypt($c, "x", $n, $k);
