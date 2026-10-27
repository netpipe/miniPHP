<?php
$k = str_repeat("\x11", 32); echo bin2hex(sodium_crypto_kdf_derive_from_key(16, 0, "Examples", $k)), " ", bin2hex(sodium_crypto_kdf_derive_from_key(64, 9007199254740991, "ctx_ctx_", $k)), " ", bin2hex(sodium_crypto_kdf_derive_from_key(32, 1, "Examples", $k));
