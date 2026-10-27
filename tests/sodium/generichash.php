<?php
echo bin2hex(sodium_crypto_generichash("")), " ", bin2hex(sodium_crypto_generichash("abc\0")), " ", bin2hex(sodium_crypto_generichash("abc", str_repeat("k", 16))), " ", bin2hex(sodium_crypto_generichash("abc", "", 16)), " ", bin2hex(sodium_crypto_generichash("abc", str_repeat("K", 64), 64));
