<?php
$k = str_repeat("\x21", 32); $n = str_repeat("\x22", 24); $c = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt("plain\0text", "ad", $n, $k); echo bin2hex($c), " ", bin2hex(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($c, "ad", $n, $k)); var_dump(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($c, "AD", $n, $k), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt("", "", $n, $k));
